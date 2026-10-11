package pgstore

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ByronGary/kubesentry/internal/audit"
)

// where translates a query into SQL conditions with the semantics of
// audit.Query.Matches. The default-view clauses are spelled exactly like the
// audit_events_default_view index predicate so the planner can use it.
func where(q audit.Query) (string, []any) {
	var conds []string
	var args []any
	arg := func(v any) string {
		args = append(args, v)
		return "$" + strconv.Itoa(len(args))
	}
	if !q.Since.IsZero() {
		conds = append(conds, "time >= "+arg(q.Since))
	}
	if q.User != "" {
		conds = append(conds, "username = "+arg(q.User))
	}
	if q.Namespace != "" {
		conds = append(conds, "namespace = "+arg(q.Namespace))
	}
	if q.Resource != "" {
		conds = append(conds, "resource = "+arg(q.Resource))
	}
	if q.Name != "" {
		conds = append(conds, "name = "+arg(q.Name))
	}
	if q.Verb != "" {
		conds = append(conds, "verb = "+arg(q.Verb))
	}
	if q.Tag != "" {
		conds = append(conds, "tags @> "+arg([]string{q.Tag})+"::text[]")
	}
	if q.Actors != nil {
		kinds := trueKeys(q.Actors, false)
		if len(kinds) == 0 {
			conds = append(conds, "false")
		} else {
			conds = append(conds, "actor_kind = ANY("+arg(kinds)+"::text[])")
		}
	} else {
		conds = append(conds, "(actor_kind <> 'system' OR tags <> '{}')")
	}
	if !q.IncludeReads && q.Verb == "" {
		conds = append(conds, "(NOT is_read OR tags <> '{}')")
	}
	if q.Namespaces != nil {
		nss := trueKeys(q.Namespaces, true)
		c := "namespace = ANY(" + arg(nss) + "::text[])"
		if q.ClusterScoped {
			c = "(" + c + " OR namespace = '')"
		}
		conds = append(conds, c)
	}
	if !q.Before.Time.IsZero() {
		conds = append(conds, "(time, audit_id) < ("+arg(q.Before.Time)+", "+arg(q.Before.AuditID)+")")
	}
	if len(conds) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

func trueKeys(m map[string]bool, skipEmpty bool) []string {
	out := make([]string, 0, len(m))
	for k, ok := range m {
		if ok && !(skipEmpty && k == "") {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

const selectColumns = `audit_id, time, stage, verb, username, actor_kind, groups, coalesce(arn, ''),
  coalesce(session_name, ''), coalesce(impersonated_user, ''), source_ips, coalesce(user_agent, ''),
  coalesce(api_group, ''), coalesce(resource, ''), coalesce(subresource, ''), namespace, coalesce(name, ''),
  coalesce(request_uri, ''), coalesce(status_code, 0), coalesce(decision, ''), tags`

// Query returns matching events, newest first, with MemoryStore's semantics.
func (s *Store) Query(ctx context.Context, q audit.Query) ([]audit.Event, error) {
	q = q.Canonical()
	cond, args := where(q)
	sql := "SELECT " + selectColumns + " FROM audit_events" + cond + " ORDER BY time DESC, audit_id DESC"
	if q.Limit > 0 {
		sql += " LIMIT " + strconv.Itoa(q.Limit)
	}
	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("pgstore: query: %w", err)
	}
	out := []audit.Event{}
	for rows.Next() {
		var e audit.Event
		var status int32
		if err := rows.Scan(&e.AuditID, &e.Time, &e.Stage, &e.Verb, &e.Username, &e.ActorKind, &e.Groups, &e.ARN,
			&e.SessionName, &e.ImpersonatedUser, &e.SourceIPs, &e.UserAgent, &e.APIGroup, &e.Resource, &e.Subresource,
			&e.Namespace, &e.Name, &e.RequestURI, &status, &e.Decision, &e.Tags); err != nil {
			rows.Close()
			return nil, fmt.Errorf("pgstore: query: %w", err)
		}
		e.StatusCode = int(status)
		e.Time = e.Time.UTC()
		e.Groups = nilIfEmpty(e.Groups)
		e.SourceIPs = nilIfEmpty(e.SourceIPs)
		e.Tags = nilIfEmpty(e.Tags)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("pgstore: query: %w", err)
	}
	return out, nil
}

func nilIfEmpty(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}

type sumEntry struct {
	at  time.Time
	sum audit.Summary
}

type covEntry struct {
	at  time.Time
	cov audit.Coverage
}

// Summarize aggregates matching events (Limit ignored) by user and by tag in
// Postgres. Results are cached for CacheTTL per query; Since is bucketed to
// CacheTTL for the cache key, so the rolling "last 24h" of many dashboard
// users shares one aggregation.
func (s *Store) Summarize(ctx context.Context, q audit.Query) (audit.Summary, error) {
	q = q.Canonical()
	q.Limit = 0
	key := ""
	if s.o.CacheTTL > 0 {
		key = summaryCacheKey(q, s.o.CacheTTL)
		s.cacheMu.Lock()
		e, ok := s.sumCache[key]
		s.cacheMu.Unlock()
		if ok && time.Since(e.at) < s.o.CacheTTL {
			return copySummary(e.sum), nil
		}
	}
	sum, err := s.summarize(ctx, q)
	if err != nil {
		return audit.Summary{}, err
	}
	if key != "" {
		s.cacheMu.Lock()
		if len(s.sumCache) > 1000 {
			for k, e := range s.sumCache {
				if time.Since(e.at) >= s.o.CacheTTL {
					delete(s.sumCache, k)
				}
			}
		}
		if len(s.sumCache) <= 1000 {
			s.sumCache[key] = sumEntry{at: time.Now(), sum: sum}
		}
		s.cacheMu.Unlock()
	}
	return copySummary(sum), nil
}

// summaryKey is everything a summary depends on, spelled out so that two
// queries share a cache entry exactly when where() gives them the same SQL.
// fmt's %+v is not such a key: it prints a nil map (every namespace) and an
// empty one (no namespace) alike. TestSummaryCacheKeyCoversEveryQueryField
// fails when audit.Query gains a field this key does not carry.
type summaryKey struct {
	Since        time.Time `json:"since"`
	User         string    `json:"user"`
	Namespace    string    `json:"namespace"`
	Resource     string    `json:"resource"`
	Name         string    `json:"name"`
	Verb         string    `json:"verb"`
	Tag          string    `json:"tag"`
	AnyActor     bool      `json:"anyActor"` // Actors == nil: the default view's actor rule
	Actors       []string  `json:"actors"`
	IncludeReads bool      `json:"includeReads"`
	Limit        int       `json:"limit"`
	// AllNamespaces is Namespaces == nil: no scope at all. Otherwise only
	// Namespaces (sorted, possibly empty) and, with ClusterScoped, events
	// without a namespace match.
	AllNamespaces bool      `json:"allNamespaces"`
	Namespaces    []string  `json:"namespaces"`
	ClusterScoped bool      `json:"clusterScoped"`
	BeforeTime    time.Time `json:"beforeTime"`
	BeforeID      string    `json:"beforeID"`
}

// summaryCacheKey returns q's Summarize cache key, with Since bucketed to
// ttl so the rolling windows of many dashboards share one aggregation. q
// must be canonical.
func summaryCacheKey(q audit.Query, ttl time.Duration) string {
	k := summaryKey{
		Since: q.Since, User: q.User, Namespace: q.Namespace, Resource: q.Resource, Name: q.Name, Verb: q.Verb, Tag: q.Tag,
		AnyActor: q.Actors == nil, Actors: trueKeys(q.Actors, false), IncludeReads: q.IncludeReads, Limit: q.Limit,
		AllNamespaces: q.Namespaces == nil, Namespaces: trueKeys(q.Namespaces, true), ClusterScoped: q.ClusterScoped,
		BeforeTime: q.Before.Time, BeforeID: q.Before.AuditID,
	}
	if !k.Since.IsZero() && ttl > 0 {
		k.Since = k.Since.Truncate(ttl)
	}
	b, err := json.Marshal(k)
	if err != nil {
		panic("pgstore: summary cache key: " + err.Error()) // strings, bools and times always encode
	}
	return string(b)
}

func copySummary(s audit.Summary) audit.Summary {
	out := audit.Summary{TotalEvents: s.TotalEvents, ByTag: make(map[string]int, len(s.ByTag)), Users: append([]audit.UserSummary{}, s.Users...)}
	for k, v := range s.ByTag {
		out.ByTag[k] = v
	}
	return out
}

func (s *Store) summarize(ctx context.Context, q audit.Query) (audit.Summary, error) {
	cond, args := where(q)
	countTag := func(t string) string {
		return "coalesce(sum(cardinality(array_positions(tags, '" + t + "'))), 0)"
	}
	users := `SELECT username, actor_kind, count(*),
  count(*) FILTER (WHERE verb IN ('create', 'update', 'patch', 'delete', 'deletecollection')),
  ` + countTag(audit.TagExec) + `, ` + countTag(audit.TagSecretAccess) + `, ` + countTag(audit.TagDenied) + `, max(time)
FROM audit_events` + cond + ` GROUP BY username, actor_kind`
	tags := `SELECT tag, count(*) FROM audit_events CROSS JOIN LATERAL unnest(tags) AS tag` + cond + ` GROUP BY tag`

	var b audit.SummaryBuilder
	batch := &pgx.Batch{}
	batch.Queue(users, args...)
	batch.Queue(tags, args...)
	br := s.pool.SendBatch(ctx, batch)
	defer br.Close()

	rows, err := br.Query()
	if err != nil {
		return audit.Summary{}, fmt.Errorf("pgstore: summarize: %w", err)
	}
	for rows.Next() {
		var u audit.UserSummary
		var total, writes, execs, secrets, denied int64
		if err := rows.Scan(&u.Username, &u.ActorKind, &total, &writes, &execs, &secrets, &denied, &u.LastSeen); err != nil {
			rows.Close()
			return audit.Summary{}, fmt.Errorf("pgstore: summarize: %w", err)
		}
		u.Total, u.Writes, u.Execs, u.SecretAccess, u.Denied = int(total), int(writes), int(execs), int(secrets), int(denied)
		u.LastSeen = u.LastSeen.UTC()
		b.AddUser(u)
	}
	if err := rows.Err(); err != nil {
		return audit.Summary{}, fmt.Errorf("pgstore: summarize: %w", err)
	}
	rows, err = br.Query()
	if err != nil {
		return audit.Summary{}, fmt.Errorf("pgstore: summarize: %w", err)
	}
	for rows.Next() {
		var tag string
		var n int64
		if err := rows.Scan(&tag, &n); err != nil {
			rows.Close()
			return audit.Summary{}, fmt.Errorf("pgstore: summarize: %w", err)
		}
		b.AddTag(tag, int(n))
	}
	if err := rows.Err(); err != nil {
		return audit.Summary{}, fmt.Errorf("pgstore: summarize: %w", err)
	}
	return b.Summary(), nil
}

// Coverage reports the span and count of stored events and the retention,
// cached for CacheTTL.
func (s *Store) Coverage(ctx context.Context) (audit.Coverage, error) {
	if s.o.CacheTTL > 0 {
		s.cacheMu.Lock()
		c := s.covCache
		s.cacheMu.Unlock()
		if c != nil && time.Since(c.at) < s.o.CacheTTL {
			return c.cov, nil
		}
	}
	cov := audit.Coverage{Backend: "postgres"}
	if s.o.Retention > 0 {
		cov.Retention = s.o.Retention
	}
	var oldest, newest *time.Time
	if err := s.pool.QueryRow(ctx, "SELECT min(time), max(time), count(*) FROM audit_events").Scan(&oldest, &newest, &cov.Events); err != nil {
		return audit.Coverage{}, fmt.Errorf("pgstore: coverage: %w", err)
	}
	if oldest != nil {
		cov.Oldest = oldest.UTC()
	}
	if newest != nil {
		cov.Newest = newest.UTC()
	}
	if s.o.CacheTTL > 0 {
		s.cacheMu.Lock()
		s.covCache = &covEntry{at: time.Now(), cov: cov}
		s.cacheMu.Unlock()
	}
	return cov, nil
}
