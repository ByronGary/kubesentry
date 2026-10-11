package pgstore

// The Summarize cache must keep callers with different audit scopes apart.
// The API passes Namespaces == nil for a caller who may read every namespace
// (unrestricted, or a cluster-wide grant) and an empty, non-nil map for a
// caller who may read none. fmt's %+v printed both as "map[]", so the two
// once shared one cache key.
//
// The cache is also stale-while-revalidate with one computation per key
// (cache.go); the tests below without Postgres replace the computation.

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/audit/audittest"
)

func TestSummaryCacheKeySeparatesNilAndEmptyNamespaces(t *testing.T) {
	ttl := 30 * time.Second
	now := time.Now()
	since := now.Add(-24 * time.Hour)
	everything := audit.Query{Since: since}.Canonical()                             // auditScope with sc.All
	nothing := audit.Query{Since: since, Namespaces: map[string]bool{}}.Canonical() // no grants
	clusterOnly := audit.Query{Since: since, Namespaces: map[string]bool{}, ClusterScoped: true}.Canonical()
	keys := map[string]string{}
	for name, q := range map[string]audit.Query{"everything": everything, "nothing": nothing, "clusterOnly": clusterOnly} {
		k := summaryCacheKey(q, ttl, now)
		if other, dup := keys[k]; dup {
			t.Errorf("%s and %s share the cache key %s", name, other, k)
		}
		keys[k] = name
	}
	// Map order and false entries do not split keys.
	a := audit.Query{Namespaces: map[string]bool{"a": true, "b": true, "c": false}}
	b := audit.Query{Namespaces: map[string]bool{"b": true, "a": true}}
	if summaryCacheKey(a, ttl, now) != summaryCacheKey(b, ttl, now) {
		t.Error("equal scopes give different keys")
	}
}

// The rolling "last 24h" asked a few seconds apart shares a key; another
// window length does not.
func TestSummaryCacheKeyRollingWindow(t *testing.T) {
	ttl := 30 * time.Second
	now := time.Now()
	q := func(at time.Time, window time.Duration) audit.Query {
		return audit.Query{Since: at.Add(-window), Namespaces: map[string]bool{"a": true}}.Canonical()
	}
	k := summaryCacheKey(q(now, 24*time.Hour), ttl, now)
	for _, later := range []time.Duration{time.Millisecond, 3 * time.Second, 14 * time.Second} {
		at := now.Add(later)
		if got := summaryCacheKey(q(at, 24*time.Hour), ttl, at.Add(time.Millisecond)); got != k {
			t.Errorf("24h window %s later: key %s, want %s", later, got, k)
		}
	}
	if summaryCacheKey(q(now, time.Hour), ttl, now) == k {
		t.Error("a 1h window shares the 24h window's key")
	}
}

// Without Postgres: seed the cache entry an unrestricted caller's Summarize
// leaves behind, then ask as a caller with no audit grants. The caller must
// get its own computation, not the seeded entry.
func TestSummaryCacheDoesNotServeAnotherScope(t *testing.T) {
	ttl := 30 * time.Second
	s := &Store{o: Options{CacheTTL: ttl, Now: time.Now}}
	var asked []audit.Query
	s.summarizeFn = func(_ context.Context, q audit.Query) (audit.Summary, error) {
		asked = append(asked, q)
		return audit.Summary{ByTag: map[string]int{}}, nil
	}
	since := time.Now().Add(-24 * time.Hour)
	everything := audit.Query{Since: since}
	nothing := audit.Query{Since: since, Namespaces: map[string]bool{}}
	s.storeSummary(summaryCacheKey(everything.Canonical(), ttl, time.Now()), audit.Summary{TotalEvents: 42,
		Users: []audit.UserSummary{{Username: "admin@corp", ActorKind: "user", Total: 42}}, ByTag: map[string]int{"exec": 7}})

	got, err := s.Summarize(context.Background(), nothing)
	if err != nil {
		t.Fatal(err)
	}
	if got.TotalEvents != 0 {
		t.Errorf("a caller with no audit grants got the unrestricted caller's cached summary: %+v", got)
	}
	if len(asked) != 1 || asked[0].Namespaces == nil {
		t.Errorf("computed %v, want one summary for the empty scope", asked)
	}
}

// Every field of audit.Query changes the key, so a field added later cannot
// be forgotten silently.
func TestSummaryCacheKeyCoversEveryQueryField(t *testing.T) {
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	base := audit.Query{Since: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), Namespaces: map[string]bool{"a": true}}
	change := map[string]func(*audit.Query){
		"Since":         func(q *audit.Query) { q.Since = q.Since.Add(-time.Hour) },
		"User":          func(q *audit.Query) { q.User = "u" },
		"Namespace":     func(q *audit.Query) { q.Namespace = "a" },
		"Resource":      func(q *audit.Query) { q.Resource = "pods" },
		"Name":          func(q *audit.Query) { q.Name = "x" },
		"Verb":          func(q *audit.Query) { q.Verb = "get" },
		"Tag":           func(q *audit.Query) { q.Tag = "exec" },
		"Actors":        func(q *audit.Query) { q.Actors = map[string]bool{} },
		"IncludeReads":  func(q *audit.Query) { q.IncludeReads = true },
		"Limit":         func(q *audit.Query) { q.Limit = 5 },
		"Namespaces":    func(q *audit.Query) { q.Namespaces = nil },
		"ClusterScoped": func(q *audit.Query) { q.ClusterScoped = true },
		"Before":        func(q *audit.Query) { q.Before = audit.Cursor{Time: q.Since.Add(time.Hour), AuditID: "x"} },
	}
	typ := reflect.TypeOf(audit.Query{})
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		f, ok := change[name]
		if !ok {
			t.Errorf("audit.Query.%s is not covered: add it to summaryKey and to this test", name)
			continue
		}
		q := base
		q.Namespaces = map[string]bool{"a": true}
		f(&q)
		if summaryCacheKey(base, time.Second, now) == summaryCacheKey(q, time.Second, now) {
			t.Errorf("changing %s does not change the cache key", name)
		}
	}
	if summaryCacheKey(base, time.Second, now) == summaryCacheKey(audit.Query{Namespaces: base.Namespaces}, time.Second, now) {
		t.Error("a query without Since shares a key with a windowed one")
	}
}

// gate is a stand-in computation the test releases step by step.
type gate[V any] struct {
	calls   atomic.Int32
	entered chan struct{}
	results chan V
	err     error
}

func newGate[V any]() *gate[V] {
	return &gate[V]{entered: make(chan struct{}, 100), results: make(chan V)}
}

func (g *gate[V]) run(ctx context.Context) (V, error) {
	g.calls.Add(1)
	g.entered <- struct{}{}
	select {
	case v := <-g.results:
		return v, g.err
	case <-ctx.Done():
		var zero V
		return zero, ctx.Err()
	}
}

func waitEntered(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("the computation never started")
	}
}

// Concurrent misses for one summary share a single computation, and a
// caller that gives up does not cancel it for the others.
func TestSummarizeSingleflight(t *testing.T) {
	s := &Store{o: Options{CacheTTL: time.Hour, Now: time.Now}}
	g := newGate[audit.Summary]()
	s.summarizeFn = func(ctx context.Context, _ audit.Query) (audit.Summary, error) { return g.run(ctx) }
	q := audit.Query{Since: time.Now().Add(-24 * time.Hour), Namespaces: map[string]bool{"team-a": true}}

	impatient, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := s.Summarize(impatient, q); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("impatient caller: %v, want its deadline", err)
	}
	waitEntered(t, g.entered)
	var wg sync.WaitGroup
	results := make(chan int, 50)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sum, err := s.Summarize(context.Background(), q)
			if err != nil {
				t.Error(err)
			}
			results <- sum.TotalEvents
		}()
	}
	time.Sleep(20 * time.Millisecond) // let them all join
	g.results <- audit.Summary{TotalEvents: 7}
	wg.Wait()
	close(results)
	for n := range results {
		if n != 7 {
			t.Errorf("a waiter got %d events, want 7", n)
		}
	}
	if n := g.calls.Load(); n != 1 {
		t.Errorf("%d computations, want 1 shared by 51 callers", n)
	}
	// And now it is cached.
	if sum, err := s.Summarize(context.Background(), q); err != nil || sum.TotalEvents != 7 || g.calls.Load() != 1 {
		t.Errorf("cached: %+v, %v after %d computations", sum, err, g.calls.Load())
	}
}

// Past its TTL a summary is still served at once while one refresh runs; a
// failed refresh keeps serving it; past 10 TTLs callers wait for a fresh one.
func TestSummarizeStaleWhileRevalidate(t *testing.T) {
	ttl := 40 * time.Millisecond
	s := &Store{o: Options{CacheTTL: ttl, Now: time.Now}}
	g := newGate[audit.Summary]()
	s.summarizeFn = func(ctx context.Context, _ audit.Query) (audit.Summary, error) { return g.run(ctx) }
	ctx := context.Background()
	// The API asks for "the last 24h": Since moves with the clock.
	last24h := func() audit.Query { return audit.Query{Since: time.Now().Add(-24 * time.Hour)} }

	go func() { waitEntered(t, g.entered); g.results <- audit.Summary{TotalEvents: 1} }()
	if sum, err := s.Summarize(ctx, last24h()); err != nil || sum.TotalEvents != 1 {
		t.Fatalf("first: %+v, %v", sum, err)
	}
	time.Sleep(ttl + 10*time.Millisecond)
	for i := 0; i < 20; i++ { // stale: served at once, one refresh started
		start := time.Now()
		sum, err := s.Summarize(ctx, last24h())
		if err != nil || sum.TotalEvents != 1 || time.Since(start) > 500*time.Millisecond {
			t.Fatalf("stale read %d: %+v, %v after %s", i, sum, err, time.Since(start))
		}
	}
	waitEntered(t, g.entered)
	if n := g.calls.Load(); n != 2 {
		t.Fatalf("%d computations, want the first and one refresh", n)
	}
	g.err = errors.New("postgres is down")
	g.results <- audit.Summary{}
	time.Sleep(10 * time.Millisecond)
	if sum, err := s.Summarize(ctx, last24h()); err != nil || sum.TotalEvents != 1 { // still the old one; another refresh starts
		t.Fatalf("after a failed refresh: %+v, %v", sum, err)
	}
	waitEntered(t, g.entered)
	g.err = nil
	g.results <- audit.Summary{TotalEvents: 2}
	deadline := time.Now().Add(5 * time.Second)
	for {
		sum, _ := s.Summarize(ctx, last24h())
		if sum.TotalEvents == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the refreshed summary never showed")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Too old to serve: the caller waits for the computation.
	time.Sleep(10*ttl + 10*time.Millisecond)
	done := make(chan audit.Summary)
	go func() {
		sum, _ := s.Summarize(ctx, last24h())
		done <- sum
	}()
	waitEntered(t, g.entered)
	select {
	case sum := <-done:
		t.Fatalf("served %+v, more than 10 TTLs old", sum)
	case <-time.After(20 * time.Millisecond):
	}
	g.results <- audit.Summary{TotalEvents: 3}
	if sum := <-done; sum.TotalEvents != 3 {
		t.Errorf("got %+v, want the fresh summary", sum)
	}
}

// Coverage: the first caller waits no longer than its context; later
// callers get the last value at once while it is refreshed, even when the
// refresh fails.
func TestCoverageServesLastValue(t *testing.T) {
	ttl := 30 * time.Millisecond
	s := &Store{o: Options{CacheTTL: ttl, Now: time.Now}}
	g := newGate[audit.Coverage]()
	s.coverageFn = g.run
	short, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := s.Coverage(short); !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatalf("cold coverage: %v after %s; want the caller's deadline", err, time.Since(start))
	}
	waitEntered(t, g.entered)
	g.results <- audit.Coverage{Backend: "postgres", Events: 10}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if c, err := s.Coverage(context.Background()); err == nil && c.Events == 10 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("coverage never cached")
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(ttl + 10*time.Millisecond)
	for i := 0; i < 10; i++ {
		if c, err := s.Coverage(context.Background()); err != nil || c.Events != 10 {
			t.Fatalf("stale coverage: %+v, %v", c, err)
		}
	}
	waitEntered(t, g.entered)
	g.err = errors.New("postgres is down")
	g.results <- audit.Coverage{}
	time.Sleep(10 * time.Millisecond)
	if c, err := s.Coverage(context.Background()); err != nil || c.Events != 10 {
		t.Fatalf("after a failed refresh: %+v, %v", c, err)
	}
	if n := g.calls.Load(); n < 2 || n > 3 {
		t.Errorf("%d computations; want one at a time", n)
	}
}

// With Postgres (KUBESENTRY_TEST_PG_DSN): the same, end to end.
func TestPGSummaryCacheSeparatesScopes(t *testing.T) {
	ctx := context.Background()
	s := openTest(t, Options{CacheTTL: time.Hour})
	e := ev("a", "ResponseComplete", 200, audittest.Base)
	e.Namespace = "secret-team"
	if err := s.Add(ctx, []audit.Event{e}); err != nil {
		t.Fatal(err)
	}
	flush(t, s)
	since := audittest.Base.Add(-time.Hour)
	all, err := s.Summarize(ctx, audit.Query{Since: since})
	if err != nil || all.TotalEvents != 1 {
		t.Fatalf("unrestricted summary = %+v, %v", all, err)
	}
	none, err := s.Summarize(ctx, audit.Query{Since: since, Namespaces: map[string]bool{}})
	if err != nil {
		t.Fatal(err)
	}
	if none.TotalEvents != 0 || len(none.Users) != 0 {
		t.Errorf("caller with no audit grants sees %+v", none)
	}
}
