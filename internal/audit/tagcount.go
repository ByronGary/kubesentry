package audit

import (
	"context"
	"sort"
	"time"
)

// TagCountQuery asks how much sensitive activity a scope saw since Since:
// how often each of Tags occurs, and which events were the newest. It is the
// cheap aggregate behind the Overview's activity tile: unlike Summarize it
// reads only tagged events, never the whole window.
type TagCountQuery struct {
	Since time.Time
	// Tags to count. An event counts once for every time it carries a tag,
	// as Summary.ByTag counts.
	Tags []string
	// Actors restricts actor kinds; nil counts every kind.
	Actors map[string]bool
	// Scope, as in Query: Namespaces nil means every namespace; otherwise
	// only those, plus events without a namespace when ClusterScoped.
	Namespaces    map[string]bool
	ClusterScoped bool
	// Subset names namespaces (e.g. production) whose events are counted
	// again, apart, in TagCounts.Subset. Nil counts nothing apart.
	Subset map[string]bool
	// Latest asks for that many of the newest matching events carrying any
	// of LatestTags (Tags when nil), newest first.
	Latest     int
	LatestTags []string
}

// TagCounts answers a TagCountQuery. ByTag and Subset hold every asked tag,
// zero included.
type TagCounts struct {
	ByTag  map[string]int
	Subset map[string]int
	Latest []Event
}

// TagCounter is implemented by stores that count tags cheaply (MemoryStore
// through AsStore, and the Postgres store). It must agree with
// CountTagsByQuery.
type TagCounter interface {
	CountTags(ctx context.Context, q TagCountQuery) (TagCounts, error)
}

// CountTags answers q with st's own TagCounter, or else with
// CountTagsByQuery.
func CountTags(ctx context.Context, st Store, q TagCountQuery) (TagCounts, error) {
	if tc, ok := st.(TagCounter); ok {
		return tc.CountTags(ctx, q)
	}
	return CountTagsByQuery(ctx, st, q)
}

// scope is the Query that selects q's events by time, actor and namespace
// (every tagged event matches it, reads included).
func (q TagCountQuery) scope() Query {
	return Query{Since: q.Since, Actors: q.Actors, IncludeReads: true, Namespaces: q.Namespaces, ClusterScoped: q.ClusterScoped}.Canonical()
}

func (q TagCountQuery) latestTags() []string {
	if q.LatestTags != nil {
		return q.LatestTags
	}
	return q.Tags
}

func newTagCounts(tags []string) TagCounts {
	c := TagCounts{ByTag: make(map[string]int, len(tags)), Subset: make(map[string]int, len(tags)), Latest: []Event{}}
	for _, t := range tags {
		c.ByTag[t], c.Subset[t] = 0, 0
	}
	return c
}

// countTag returns how often t occurs in tags.
func countTag(tags []string, t string) int {
	n := 0
	for _, x := range tags {
		if x == t {
			n++
		}
	}
	return n
}

// CountTagsByQuery answers q with one Query per tag: the reference every
// TagCounter is tested against, and the fallback for stores without one. It
// reads every tagged event, so it suits small stores only.
func CountTagsByQuery(ctx context.Context, st Store, q TagCountQuery) (TagCounts, error) {
	out := newTagCounts(q.Tags)
	base := q.scope()
	for _, t := range dedupe(q.Tags) {
		qt := base
		qt.Tag = t
		events, err := st.Query(ctx, qt)
		if err != nil {
			return TagCounts{}, err
		}
		for i := range events {
			n := countTag(events[i].Tags, t)
			out.ByTag[t] += n
			if q.Subset[events[i].Namespace] {
				out.Subset[t] += n
			}
		}
	}
	if q.Latest <= 0 {
		return out, nil
	}
	seen := map[Cursor]bool{}
	for _, t := range dedupe(q.latestTags()) {
		qt := base
		qt.Tag, qt.Limit = t, q.Latest
		events, err := st.Query(ctx, qt)
		if err != nil {
			return TagCounts{}, err
		}
		for _, e := range events {
			if c := CursorOf(e); !seen[c] {
				seen[c] = true
				out.Latest = append(out.Latest, e)
			}
		}
	}
	sort.Slice(out.Latest, func(i, j int) bool { return newer(&out.Latest[i], &out.Latest[j]) })
	if len(out.Latest) > q.Latest {
		out.Latest = out.Latest[:q.Latest]
	}
	return out, nil
}

func dedupe(tags []string) []string {
	out := make([]string, 0, len(tags))
	for i, t := range tags {
		if !hasTag(tags[:i], t) {
			out = append(out, t)
		}
	}
	return out
}

// CountTags walks only the per-tag indexes, newest first, down to Since.
func (s *MemoryStore) CountTags(q TagCountQuery) TagCounts {
	out := newTagCounts(q.Tags)
	scope := q.scope()
	since := sinceNanos(&scope)
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, t := range dedupe(q.Tags) {
		l := s.tags[t]
		if l == nil {
			continue
		}
		for nd := l.tail; nd != nil && nd.pmax >= since; nd = nd.prev {
			e := &nd.e.ev
			if !scope.matches(e) {
				continue
			}
			n := countTag(e.Tags, t)
			out.ByTag[t] += n
			if q.Subset[e.Namespace] {
				out.Subset[t] += n
			}
		}
	}
	if q.Latest <= 0 {
		return out
	}
	c := &collector{limit: q.Latest}
	seen := map[*entry]bool{}
	for _, t := range dedupe(q.latestTags()) {
		l := s.tags[t]
		if l == nil {
			continue
		}
		for nd := l.tail; nd != nil && nd.pmax >= since; nd = nd.prev {
			if c.full() && nd.pmax < c.worstT() {
				break
			}
			if !seen[nd.e] && scope.matches(&nd.e.ev) {
				seen[nd.e] = true
				c.add(nd.e)
			}
		}
	}
	out.Latest = c.events()
	return out
}

func (a memoryStore) CountTags(ctx context.Context, q TagCountQuery) (TagCounts, error) {
	if err := ctx.Err(); err != nil {
		return TagCounts{}, err
	}
	return a.m.CountTags(q), nil
}

var _ TagCounter = memoryStore{}
