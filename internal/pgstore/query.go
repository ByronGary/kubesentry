package pgstore

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ByronGary/kubesentry/internal/audit"
)

// where translates a query into SQL conditions with the semantics of
// audit.Query.Matches. The default-view clauses are spelled exactly like the
// audit_events_default_view and audit_events_scoped_view index predicates so
// the planner can use them, and known actor kinds are literals so it can
// prove audit_events_summary's predicate (actor_kind <> 'system').
func where(q audit.Query) (string, []any) {
	b := &sqlArgs{}
	conds := b.conditions(q, true)
	if len(conds) == 0 {
		return "", b.args
	}
	return " WHERE " + strings.Join(conds, " AND "), b.args
}

// sqlArgs collects the parameters of one statement.
type sqlArgs struct{ args []any }

func (b *sqlArgs) arg(v any) string {
	b.args = append(b.args, v)
	return "$" + strconv.Itoa(len(b.args))
}

// conditions returns q's conditions, the scope (Namespaces, ClusterScoped)
// included only when withScope is set.
func (b *sqlArgs) conditions(q audit.Query, withScope bool) []string {
	var conds []string
	arg := b.arg
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
		switch {
		case len(kinds) == 0:
			conds = append(conds, "false")
		case knownActorKinds(kinds):
			conds = append(conds, "actor_kind IN ('"+strings.Join(kinds, "', '")+"')")
		default:
			conds = append(conds, "actor_kind = ANY("+arg(kinds)+"::text[])")
		}
	} else {
		conds = append(conds, "(actor_kind <> 'system' OR tags <> '{}')")
	}
	if !q.IncludeReads && q.Verb == "" {
		conds = append(conds, "(NOT is_read OR tags <> '{}')")
	}
	if q.Namespaces != nil && withScope {
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
	return conds
}

// maxScopeBranches is the most namespaces a scoped page is read with one
// index range per namespace (scopedPageSQL); larger scopes use one scan.
const maxScopeBranches = 32

// scopedPageSQL returns the statement for a page of a scoped query: one
// newest-first branch per namespace in the scope (and one for events without
// a namespace when ClusterScoped), each reading at most Limit rows from
// audit_events_scoped_view (namespace, time, audit_id), merged and cut to
// Limit. The single statement with namespace = ANY(...) cannot read that
// index in time order across several namespaces, so it walked the whole
// window's time index filtering by namespace (25,000 rows for 201 at 2 of
// 300 namespaces), or fetched and sorted every event of the scope. The
// union matches exactly the same events. ok is false when q is not a
// scoped page of a few namespaces.
func scopedPageSQL(q audit.Query) (sql string, args []any, ok bool) {
	if q.Namespaces == nil || q.Limit <= 0 {
		return "", nil, false
	}
	nss := trueKeys(q.Namespaces, true)
	if q.ClusterScoped {
		nss = append(nss, "")
	}
	if len(nss) == 0 || len(nss) > maxScopeBranches {
		return "", nil, false
	}
	b := &sqlArgs{}
	common := b.conditions(q, false)
	limit := strconv.Itoa(q.Limit)
	branches := make([]string, len(nss))
	for i, ns := range nss {
		conds := append(append([]string{}, common...), "namespace = "+b.arg(ns))
		branches[i] = "(SELECT * FROM audit_events WHERE " + strings.Join(conds, " AND ") +
			" ORDER BY time DESC, audit_id DESC LIMIT " + limit + ")"
	}
	sql = "SELECT " + selectColumns + " FROM (" + strings.Join(branches, "\nUNION ALL ") +
		") AS audit_events ORDER BY time DESC, audit_id DESC LIMIT " + limit
	return sql, b.args, true
}

// knownActorKinds reports whether every kind is one the ingester assigns,
// and so safe to write into SQL as a literal.
func knownActorKinds(kinds []string) bool {
	for _, k := range kinds {
		switch k {
		case "user", "serviceaccount", "system":
		default:
			return false
		}
	}
	return true
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

// read runs one read against Postgres, bounded twice: it waits at most
// AcquireTimeout for one of the store's read slots (MaxConns-2, so the
// writer and maintenance always find a connection) and gives f at most
// QueryTimeout. Either limit fails it with audit.ErrOverloaded, which the API
// answers with 503 + Retry-After instead of holding the request until the
// route (or the SSO proxy) times out. f must use the context it is given.
func (s *Store) read(ctx context.Context, what string, f func(ctx context.Context) error) error {
	if s.readers != nil {
		t := time.NewTimer(s.o.AcquireTimeout)
		select {
		case s.readers <- struct{}{}:
			t.Stop()
		case <-ctx.Done():
			t.Stop()
			return fmt.Errorf("pgstore: %s: %w", what, ctx.Err())
		case <-t.C:
			return fmt.Errorf("pgstore: %s: %w: all %d read slots stayed busy for %s", what, audit.ErrOverloaded, cap(s.readers), s.o.AcquireTimeout)
		}
		defer func() { <-s.readers }()
	}
	qctx, cancel := context.WithTimeout(ctx, s.o.QueryTimeout)
	defer cancel()
	err := f(qctx)
	switch {
	case err == nil:
		return nil
	case ctx.Err() == nil && errors.Is(qctx.Err(), context.DeadlineExceeded):
		return fmt.Errorf("pgstore: %s: %w: no answer within %s", what, audit.ErrOverloaded, s.o.QueryTimeout)
	}
	return fmt.Errorf("pgstore: %s: %w", what, err)
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
	if s, a, ok := scopedPageSQL(q); ok {
		sql, args = s, a
	}
	var out []audit.Event
	err := s.read(ctx, "query", func(ctx context.Context) error {
		rows, err := s.pool.Query(ctx, sql, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		out = []audit.Event{}
		for rows.Next() {
			var e audit.Event
			var status int32
			if err := rows.Scan(&e.AuditID, &e.Time, &e.Stage, &e.Verb, &e.Username, &e.ActorKind, &e.Groups, &e.ARN,
				&e.SessionName, &e.ImpersonatedUser, &e.SourceIPs, &e.UserAgent, &e.APIGroup, &e.Resource, &e.Subresource,
				&e.Namespace, &e.Name, &e.RequestURI, &status, &e.Decision, &e.Tags); err != nil {
				return err
			}
			e.StatusCode = int(status)
			e.Time = e.Time.UTC()
			e.Groups = nilIfEmpty(e.Groups)
			e.SourceIPs = nilIfEmpty(e.SourceIPs)
			e.Tags = nilIfEmpty(e.Tags)
			out = append(out, e)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func nilIfEmpty(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}

// summarizeNow aggregates matching events by user and by tag in Postgres,
// uncached. Summaries that leave system components out read only the
// audit_events_summary index.
func (s *Store) summarizeNow(ctx context.Context, q audit.Query) (audit.Summary, error) {
	cond, args := where(q)
	countTag := func(t string) string {
		return "coalesce(sum(cardinality(array_positions(tags, '" + t + "'))), 0)"
	}
	users := `SELECT username, actor_kind, count(*),
  count(*) FILTER (WHERE verb IN ('create', 'update', 'patch', 'delete', 'deletecollection')),
  ` + countTag(audit.TagExec) + `, ` + countTag(audit.TagSecretAccess) + `, ` + countTag(audit.TagDenied) + `, max(time)
FROM audit_events` + cond + ` GROUP BY username, actor_kind`
	tags := `SELECT tag, count(*) FROM audit_events CROSS JOIN LATERAL unnest(tags) AS tag` + cond + ` GROUP BY tag`

	var sum audit.Summary
	err := s.read(ctx, "summarize", func(ctx context.Context) error {
		var b audit.SummaryBuilder
		batch := &pgx.Batch{}
		batch.Queue(users, args...)
		batch.Queue(tags, args...)
		br := s.pool.SendBatch(ctx, batch)
		defer br.Close()

		rows, err := br.Query()
		if err != nil {
			return err
		}
		for rows.Next() {
			var u audit.UserSummary
			var total, writes, execs, secrets, denied int64
			if err := rows.Scan(&u.Username, &u.ActorKind, &total, &writes, &execs, &secrets, &denied, &u.LastSeen); err != nil {
				rows.Close()
				return err
			}
			u.Total, u.Writes, u.Execs, u.SecretAccess, u.Denied = int(total), int(writes), int(execs), int(secrets), int(denied)
			u.LastSeen = u.LastSeen.UTC()
			b.AddUser(u)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		rows, err = br.Query()
		if err != nil {
			return err
		}
		for rows.Next() {
			var tag string
			var n int64
			if err := rows.Scan(&tag, &n); err != nil {
				rows.Close()
				return err
			}
			b.AddTag(tag, int(n))
		}
		if err := rows.Err(); err != nil {
			return err
		}
		sum = b.Summary()
		return nil
	})
	return sum, err
}

// exactCountBelow is the estimated store size under which coverageNow counts
// events exactly: a count(*) of up to this many rows takes a few
// milliseconds, and small stores (and the tests) get exact numbers.
const exactCountBelow = 100_000

// exactBelow is exactCountBelow, or the threshold a test set.
func (s *Store) exactBelow() float64 {
	if s.exactCountBelow > 0 {
		return s.exactCountBelow
	}
	return exactCountBelow
}

// coverageNow reads the span and size of the store, uncached. The span is
// exact, from both ends of the time index. The event count is exact below
// exactCountBelow and otherwise estimated from the planner's statistics: each
// partition's rows per page at its last ANALYZE times its pages now, which is
// how the planner sizes it too. Autovacuum keeps that within a few percent;
// count(*) took 0.8-4 s at 3-4M events, for a number that is only displayed.
func (s *Store) coverageNow(ctx context.Context) (audit.Coverage, error) {
	cov := audit.Coverage{Backend: "postgres"}
	if s.o.Retention > 0 {
		cov.Retention = s.o.Retention
	}
	err := s.read(ctx, "coverage", func(ctx context.Context) error {
		var oldest, newest *time.Time
		if err := s.pool.QueryRow(ctx, `SELECT (SELECT time FROM audit_events ORDER BY time LIMIT 1),
  (SELECT time FROM audit_events ORDER BY time DESC LIMIT 1)`).Scan(&oldest, &newest); err != nil {
			return err
		}
		if oldest != nil {
			cov.Oldest = oldest.UTC()
		}
		if newest != nil {
			cov.Newest = newest.UTC()
		}
		n, err := s.countEvents(ctx)
		cov.Events = n
		return err
	})
	if err != nil {
		return audit.Coverage{}, err
	}
	return cov, nil
}

// countEvents estimates the number of stored events (see coverageNow).
func (s *Store) countEvents(ctx context.Context) (int64, error) {
	rows, err := s.pool.Query(ctx, `SELECT c.reltuples::float8, c.relpages::bigint,
  coalesce(pg_relation_size(c.oid), 0) / current_setting('block_size')::bigint
FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
WHERE i.inhparent = 'audit_events'::regclass`)
	if err != nil {
		return 0, err
	}
	type part struct {
		tuples      float64 // at the last VACUUM or ANALYZE; -1 never
		pages, size int64   // pages then, and now
	}
	parts, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (part, error) {
		var p part
		return p, r.Scan(&p.tuples, &p.pages, &p.size)
	})
	if err != nil {
		return 0, err
	}
	var tuples, pages float64 // over the partitions with statistics
	for _, p := range parts {
		if p.pages > 0 && p.tuples >= 0 {
			tuples += p.tuples
			pages += float64(p.pages)
		}
	}
	est := 0.0
	if pages > 0 {
		for _, p := range parts {
			switch {
			case p.size == 0:
			case p.pages > 0 && p.tuples >= 0:
				est += p.tuples / float64(p.pages) * float64(p.size)
			default: // filled since its last ANALYZE: the others' density
				est += tuples / pages * float64(p.size)
			}
		}
	}
	if pages == 0 || est < s.exactBelow() {
		var n int64
		err := s.pool.QueryRow(ctx, "SELECT count(*) FROM audit_events").Scan(&n)
		return n, err
	}
	return int64(math.Round(est)), nil
}
