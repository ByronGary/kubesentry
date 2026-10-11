package pgstore

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"time"

	"github.com/ByronGary/kubesentry/internal/audit"
)

// Summaries and coverage are cached stale-while-revalidate. Every dashboard
// polls them (each /info asks for the coverage, each audit page for a 24h
// summary in the caller's scope), and before this cache each miss queried
// Postgres on its own: at 500 users the misses piled up into seconds-long
// queries (stress checkpoint D). Now:
//
//   - a result younger than CacheTTL is served as is;
//   - an older one is still served, at once, while one refresh per result runs
//     in the background (a summary up to 10 TTLs old; the coverage however
//     old, since it is only displayed and readiness reports Postgres itself);
//   - without a usable result, callers wait for a single computation shared
//     by all of them (singleflight), or until their context ends.
//
// Refreshes run on the store's own context, bounded by QueryTimeout, so a
// caller that gives up does not waste the work for the next one.

// flight is a computation in progress that callers can wait for.
type flight[V any] struct {
	done chan struct{}
	val  V
	err  error
}

type sumEntry struct {
	at  time.Time // when it was computed
	sum audit.Summary
}

type covEntry struct {
	at  time.Time
	cov audit.Coverage
}

// maxSummaries bounds the summary cache: one entry per scope and window.
const maxSummaries = 1000

// staleFor is how old a cached summary may get and still be served while
// it is refreshed.
func (s *Store) staleFor() time.Duration { return 10 * s.o.CacheTTL }

// background is the context refreshes run in: cancelled when the store
// closes.
func (s *Store) background() context.Context {
	if s.abortCtx != nil {
		return s.abortCtx
	}
	return context.Background()
}

// Summarize aggregates matching events (Limit ignored) by user and by tag,
// with MemoryStore's semantics, through the cache above. The cache key is
// the query with Since as a window length (rounded to CacheTTL), so the
// rolling "last 24h" of every dashboard in one scope shares one entry.
func (s *Store) Summarize(ctx context.Context, q audit.Query) (audit.Summary, error) {
	q = q.Canonical()
	q.Limit = 0
	ttl := s.o.CacheTTL
	if ttl <= 0 {
		return s.computeSummary(ctx, q)
	}
	key := summaryCacheKey(q, ttl, s.o.Now())
	s.cacheMu.Lock()
	if e, ok := s.sumCache[key]; ok {
		if age := time.Since(e.at); age < s.staleFor() {
			if age >= ttl {
				s.refreshSummary(key, q)
			}
			sum := e.sum
			s.cacheMu.Unlock()
			return copySummary(sum), nil
		}
	}
	f := s.refreshSummary(key, q)
	s.cacheMu.Unlock()
	select {
	case <-f.done:
		if f.err != nil {
			return audit.Summary{}, f.err
		}
		return copySummary(f.val), nil
	case <-ctx.Done():
		return audit.Summary{}, fmt.Errorf("pgstore: summarize: %w", ctx.Err())
	}
}

func (s *Store) computeSummary(ctx context.Context, q audit.Query) (audit.Summary, error) {
	if s.summarizeFn != nil {
		return s.summarizeFn(ctx, q)
	}
	return s.summarizeNow(ctx, q)
}

// refreshSummary starts computing key's summary in the background, unless
// that is under way already, and returns the computation. cacheMu is held.
func (s *Store) refreshSummary(key string, q audit.Query) *flight[audit.Summary] {
	if f, ok := s.sumFlights[key]; ok {
		return f
	}
	if s.sumFlights == nil {
		s.sumFlights = map[string]*flight[audit.Summary]{}
	}
	f := &flight[audit.Summary]{done: make(chan struct{})}
	s.sumFlights[key] = f
	go func() {
		sum, err := s.computeSummary(s.background(), q)
		s.cacheMu.Lock()
		delete(s.sumFlights, key)
		if err == nil {
			s.storeSummary(key, sum)
		}
		s.cacheMu.Unlock()
		f.val, f.err = sum, err
		close(f.done)
	}()
	return f
}

// storeSummary caches sum under key, making room by forgetting what is too
// old to serve and then the oldest entry. cacheMu is held.
func (s *Store) storeSummary(key string, sum audit.Summary) {
	if s.sumCache == nil {
		s.sumCache = map[string]*sumEntry{}
	}
	if _, ok := s.sumCache[key]; !ok && len(s.sumCache) >= maxSummaries {
		var oldestKey string
		var oldest time.Time
		for k, e := range s.sumCache {
			if time.Since(e.at) >= s.staleFor() {
				delete(s.sumCache, k)
				continue
			}
			if oldestKey == "" || e.at.Before(oldest) {
				oldestKey, oldest = k, e.at
			}
		}
		if len(s.sumCache) >= maxSummaries {
			delete(s.sumCache, oldestKey)
		}
	}
	s.sumCache[key] = &sumEntry{at: time.Now(), sum: sum}
}

// summaryKey is everything a summary depends on, spelled out so that two
// queries share a cache entry exactly when where() gives them the same SQL
// (up to the rolling window's start). fmt's %+v is not such a key: it prints
// a nil map (every namespace) and an empty one (no namespace) alike.
// TestSummaryCacheKeyCoversEveryQueryField fails when audit.Query gains a
// field this key does not carry.
type summaryKey struct {
	// Window is Since as a look-back from now in CacheTTL units, rounded:
	// dashboards asking for "the last 24h" a few seconds apart share it.
	// Without Since, HasSince is false.
	HasSince     bool     `json:"hasSince"`
	Window       int64    `json:"window"`
	User         string   `json:"user"`
	Namespace    string   `json:"namespace"`
	Resource     string   `json:"resource"`
	Name         string   `json:"name"`
	Verb         string   `json:"verb"`
	Tag          string   `json:"tag"`
	AnyActor     bool     `json:"anyActor"` // Actors == nil: the default view's actor rule
	Actors       []string `json:"actors"`
	IncludeReads bool     `json:"includeReads"`
	Limit        int      `json:"limit"`
	// AllNamespaces is Namespaces == nil: no scope at all. Otherwise only
	// Namespaces (sorted, possibly empty) and, with ClusterScoped, events
	// without a namespace match.
	AllNamespaces bool      `json:"allNamespaces"`
	Namespaces    []string  `json:"namespaces"`
	ClusterScoped bool      `json:"clusterScoped"`
	BeforeTime    time.Time `json:"beforeTime"`
	BeforeID      string    `json:"beforeID"`
}

// summaryCacheKey returns q's Summarize cache key at now, with Since as a
// window length in ttl units. q must be canonical.
func summaryCacheKey(q audit.Query, ttl time.Duration, now time.Time) string {
	k := summaryKey{
		User: q.User, Namespace: q.Namespace, Resource: q.Resource, Name: q.Name, Verb: q.Verb, Tag: q.Tag,
		AnyActor: q.Actors == nil, Actors: trueKeys(q.Actors, false), IncludeReads: q.IncludeReads, Limit: q.Limit,
		AllNamespaces: q.Namespaces == nil, Namespaces: trueKeys(q.Namespaces, true), ClusterScoped: q.ClusterScoped,
		BeforeTime: q.Before.Time, BeforeID: q.Before.AuditID,
	}
	if !q.Since.IsZero() {
		k.HasSince = true
		k.Window = int64(math.Round(float64(now.Sub(q.Since)) / float64(max(ttl, time.Nanosecond))))
	}
	b, err := json.Marshal(k)
	if err != nil {
		panic("pgstore: summary cache key: " + err.Error()) // strings, bools, ints and times always encode
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

// Coverage reports the span and approximate size of the stored events and
// the retention (see coverageNow), through the cache above: the last value
// is served while it is refreshed, so a caller waits on Postgres only before
// the first value exists, and then no longer than its context allows (/info
// gives it 50ms).
func (s *Store) Coverage(ctx context.Context) (audit.Coverage, error) {
	if s.o.CacheTTL <= 0 {
		return s.computeCoverage(ctx)
	}
	s.cacheMu.Lock()
	if c := s.covCache; c != nil {
		if time.Since(c.at) >= s.o.CacheTTL {
			s.refreshCoverage()
		}
		cov := c.cov
		s.cacheMu.Unlock()
		return cov, nil
	}
	f := s.refreshCoverage()
	s.cacheMu.Unlock()
	select {
	case <-f.done:
		return f.val, f.err
	case <-ctx.Done():
		return audit.Coverage{}, fmt.Errorf("pgstore: coverage: %w", ctx.Err())
	}
}

func (s *Store) computeCoverage(ctx context.Context) (audit.Coverage, error) {
	if s.coverageFn != nil {
		return s.coverageFn(ctx)
	}
	return s.coverageNow(ctx)
}

// warmCoverage starts computing the coverage, so it is ready for the first
// caller.
func (s *Store) warmCoverage() {
	s.cacheMu.Lock()
	s.refreshCoverage()
	s.cacheMu.Unlock()
}

// refreshCoverage is refreshSummary for the coverage. cacheMu is held.
func (s *Store) refreshCoverage() *flight[audit.Coverage] {
	if s.covFlight != nil {
		return s.covFlight
	}
	f := &flight[audit.Coverage]{done: make(chan struct{})}
	s.covFlight = f
	go func() {
		cov, err := s.computeCoverage(s.background())
		s.cacheMu.Lock()
		s.covFlight = nil
		if err == nil {
			s.covCache = &covEntry{at: time.Now(), cov: cov}
		}
		s.cacheMu.Unlock()
		f.val, f.err = cov, err
		close(f.done)
	}()
	return f
}
