package pgstore

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ByronGary/kubesentry/internal/audit"
)

// CountTags is the Overview's sensitive-activity aggregate (audit.TagCounter):
// how often each tag occurs since q.Since in a scope, and the newest tagged
// events. Unlike Summarize it never reads the whole window: the tags GIN
// index (tags && ARRAY[...]) finds the tagged rows, the time bound prunes
// every daily partition but the last one or two, and the namespace scope is
// part of the statement. Results go through the same stale-while-revalidate
// cache and single flight as summaries, keyed by the query with Since as a
// window length, so every dashboard of one scope shares one computation.
func (s *Store) CountTags(ctx context.Context, q audit.TagCountQuery) (audit.TagCounts, error) {
	ttl := s.o.CacheTTL
	if ttl <= 0 {
		return s.computeTagCounts(ctx, q)
	}
	key := tagCacheKey(q, ttl, s.o.Now())
	s.cacheMu.Lock()
	if e, ok := s.tagCache[key]; ok {
		if age := time.Since(e.at); age < s.staleFor() {
			if age >= ttl {
				s.refreshTagCounts(key, q)
			}
			c := e.counts
			s.cacheMu.Unlock()
			return copyTagCounts(c), nil
		}
	}
	f := s.refreshTagCounts(key, q)
	s.cacheMu.Unlock()
	select {
	case <-f.done:
		if f.err != nil {
			return audit.TagCounts{}, f.err
		}
		return copyTagCounts(f.val), nil
	case <-ctx.Done():
		return audit.TagCounts{}, fmt.Errorf("pgstore: count tags: %w", ctx.Err())
	}
}

var _ audit.TagCounter = (*Store)(nil)

type tagEntry struct {
	at     time.Time
	counts audit.TagCounts
}

func (s *Store) computeTagCounts(ctx context.Context, q audit.TagCountQuery) (audit.TagCounts, error) {
	if s.countTagsFn != nil {
		return s.countTagsFn(ctx, q)
	}
	return s.countTagsNow(ctx, q)
}

// refreshTagCounts is refreshSummary for tag counts. cacheMu is held.
func (s *Store) refreshTagCounts(key string, q audit.TagCountQuery) *flight[audit.TagCounts] {
	if f, ok := s.tagFlights[key]; ok {
		return f
	}
	if s.tagFlights == nil {
		s.tagFlights = map[string]*flight[audit.TagCounts]{}
	}
	f := &flight[audit.TagCounts]{done: make(chan struct{})}
	s.tagFlights[key] = f
	go func() {
		c, err := s.computeTagCounts(s.background(), q)
		s.cacheMu.Lock()
		delete(s.tagFlights, key)
		if err == nil {
			s.storeTagCounts(key, c)
		}
		s.cacheMu.Unlock()
		f.val, f.err = c, err
		close(f.done)
	}()
	return f
}

// storeTagCounts is storeSummary for tag counts. cacheMu is held.
func (s *Store) storeTagCounts(key string, c audit.TagCounts) {
	if s.tagCache == nil {
		s.tagCache = map[string]*tagEntry{}
	}
	if _, ok := s.tagCache[key]; !ok && len(s.tagCache) >= maxSummaries {
		var oldestKey string
		var oldest time.Time
		for k, e := range s.tagCache {
			if time.Since(e.at) >= s.staleFor() {
				delete(s.tagCache, k)
				continue
			}
			if oldestKey == "" || e.at.Before(oldest) {
				oldestKey, oldest = k, e.at
			}
		}
		if len(s.tagCache) >= maxSummaries {
			delete(s.tagCache, oldestKey)
		}
	}
	s.tagCache[key] = &tagEntry{at: time.Now(), counts: c}
}

// tagKey is everything a tag count depends on (see summaryKey). Sets are
// sorted; a nil scope (every namespace) and an empty one stay apart.
type tagKey struct {
	HasSince      bool     `json:"hasSince"`
	Window        int64    `json:"window"`
	Tags          []string `json:"tags"`
	AnyActor      bool     `json:"anyActor"`
	Actors        []string `json:"actors"`
	AllNamespaces bool     `json:"allNamespaces"`
	Namespaces    []string `json:"namespaces"`
	ClusterScoped bool     `json:"clusterScoped"`
	Subset        []string `json:"subset"`
	Latest        int      `json:"latest"`
	LatestTags    []string `json:"latestTags"`
	DefaultLatest bool     `json:"defaultLatest"`
}

func tagCacheKey(q audit.TagCountQuery, ttl time.Duration, now time.Time) string {
	k := tagKey{
		Tags: sortedSet(q.Tags), AnyActor: q.Actors == nil, Actors: trueKeys(q.Actors, false),
		AllNamespaces: q.Namespaces == nil, Namespaces: trueKeys(q.Namespaces, true), ClusterScoped: q.ClusterScoped,
		Subset: trueKeys(q.Subset, false), Latest: q.Latest, LatestTags: sortedSet(q.LatestTags), DefaultLatest: q.LatestTags == nil,
	}
	if !q.Since.IsZero() {
		k.HasSince = true
		k.Window = int64(math.Round(float64(now.Sub(q.Since)) / float64(max(ttl, time.Nanosecond))))
	}
	b, err := json.Marshal(k)
	if err != nil {
		panic("pgstore: tag count cache key: " + err.Error())
	}
	return string(b)
}

func sortedSet(tags []string) []string {
	m := make(map[string]bool, len(tags))
	for _, t := range tags {
		m[t] = true
	}
	return trueKeys(m, false)
}

func copyTagCounts(c audit.TagCounts) audit.TagCounts {
	out := audit.TagCounts{ByTag: make(map[string]int, len(c.ByTag)), Subset: make(map[string]int, len(c.Subset)),
		Latest: append([]audit.Event{}, c.Latest...)}
	for k, v := range c.ByTag {
		out.ByTag[k] = v
	}
	for k, v := range c.Subset {
		out.Subset[k] = v
	}
	return out
}

// countTagsNow runs the counts, uncached: one statement counting tag
// occurrences (unnest) among the rows the GIN index finds, and one reading
// the newest few.
func (s *Store) countTagsNow(ctx context.Context, q audit.TagCountQuery) (audit.TagCounts, error) {
	out := audit.TagCounts{ByTag: map[string]int{}, Subset: map[string]int{}, Latest: []audit.Event{}}
	tags := sortedSet(q.Tags)
	for _, t := range tags {
		out.ByTag[t], out.Subset[t] = 0, 0
	}
	scope := audit.Query{Since: q.Since, Actors: q.Actors, IncludeReads: true, Namespaces: q.Namespaces, ClusterScoped: q.ClusterScoped}.Canonical()
	latestTags := q.LatestTags
	if latestTags == nil {
		latestTags = q.Tags
	}
	latestTags = sortedSet(latestTags)
	wantLatest := q.Latest > 0 && len(latestTags) > 0
	if len(tags) == 0 && !wantLatest {
		return out, nil
	}

	batch := &pgx.Batch{}
	if len(tags) > 0 {
		b := &sqlArgs{}
		conds := b.conditions(scope, true)
		t := b.arg(tags) + "::text[]"
		conds = append(conds, "tags && "+t, "tag = ANY("+t+")")
		sub := "false"
		if subset := trueKeys(q.Subset, false); len(subset) > 0 {
			sub = "namespace = ANY(" + b.arg(subset) + "::text[])"
		}
		batch.Queue(`SELECT tag, count(*), count(*) FILTER (WHERE `+sub+`)
FROM audit_events CROSS JOIN LATERAL unnest(tags) AS tag
WHERE `+strings.Join(conds, " AND ")+` GROUP BY tag`, b.args...)
	}
	if wantLatest {
		b := &sqlArgs{}
		conds := b.conditions(scope, true)
		conds = append(conds, "tags && "+b.arg(latestTags)+"::text[]")
		batch.Queue("SELECT "+selectColumns+" FROM audit_events WHERE "+strings.Join(conds, " AND ")+
			" ORDER BY time DESC, audit_id DESC LIMIT "+strconv.Itoa(q.Latest), b.args...)
	}

	err := s.read(ctx, "count tags", func(ctx context.Context) error {
		br := s.pool.SendBatch(ctx, batch)
		defer br.Close()
		if len(tags) > 0 {
			rows, err := br.Query()
			if err != nil {
				return err
			}
			for rows.Next() {
				var tag string
				var n, inSubset int64
				if err := rows.Scan(&tag, &n, &inSubset); err != nil {
					rows.Close()
					return err
				}
				out.ByTag[tag], out.Subset[tag] = int(n), int(inSubset)
			}
			if err := rows.Err(); err != nil {
				return err
			}
		}
		if wantLatest {
			rows, err := br.Query()
			if err != nil {
				return err
			}
			for rows.Next() {
				var e audit.Event
				var status int32
				if err := rows.Scan(&e.AuditID, &e.Time, &e.Stage, &e.Verb, &e.Username, &e.ActorKind, &e.Groups, &e.ARN,
					&e.SessionName, &e.ImpersonatedUser, &e.SourceIPs, &e.UserAgent, &e.APIGroup, &e.Resource, &e.Subresource,
					&e.Namespace, &e.Name, &e.RequestURI, &status, &e.Decision, &e.Tags); err != nil {
					rows.Close()
					return err
				}
				e.StatusCode = int(status)
				e.Time = e.Time.UTC()
				e.Groups = nilIfEmpty(e.Groups)
				e.SourceIPs = nilIfEmpty(e.SourceIPs)
				e.Tags = nilIfEmpty(e.Tags)
				out.Latest = append(out.Latest, e)
			}
			if err := rows.Err(); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return audit.TagCounts{}, err
	}
	return out, nil
}
