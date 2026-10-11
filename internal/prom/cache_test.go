package prom

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type countingObserver struct {
	mu      sync.Mutex
	results map[string]int
	queries map[string]int
}

func newCountingObserver() *countingObserver {
	return &countingObserver{results: map[string]int{}, queries: map[string]int{}}
}

func (o *countingObserver) CacheResult(r string) {
	o.mu.Lock()
	o.results[r]++
	o.mu.Unlock()
}

func (o *countingObserver) ObserveQuery(kind string, d time.Duration) {
	o.mu.Lock()
	o.queries[kind]++
	o.mu.Unlock()
}

func (o *countingObserver) get(m map[string]int, k string) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return m[k]
}

// stubProm answers every query with one series and counts requests. release,
// when set, holds each response until it is closed.
type stubProm struct {
	hits    atomic.Int64
	release chan struct{}
	fail    atomic.Bool
	mu      sync.Mutex
	params  []string
}

func (s *stubProm) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.hits.Add(1)
	_ = r.ParseForm()
	s.mu.Lock()
	s.params = append(s.params, r.PostForm.Encode())
	s.mu.Unlock()
	if s.release != nil {
		select {
		case <-s.release:
		case <-r.Context().Done():
			return
		}
	}
	if s.fail.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"status":"error","errorType":"unavailable","error":"down"}`))
		return
	}
	if strings.HasSuffix(r.URL.Path, "query_range") {
		w.Write([]byte(`{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"pod":"a"},"values":[[1760000000,"1"],[1760000060,"2"]]}]}}`))
		return
	}
	w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{"pod":"a"},"value":[1760000000,"1"]}]}}`))
}

func cachedClient(t *testing.T, h http.Handler, opts CacheOptions) (*Client, *countingObserver, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	obs := newCountingObserver()
	c, err := NewClient(srv.URL, Options{Cache: NewCache(opts), Observer: obs})
	if err != nil {
		t.Fatal(err)
	}
	return c, obs, srv
}

func TestCacheInstantTTL(t *testing.T) {
	stub := &stubProm{}
	now := time.Unix(1_760_000_000, 0)
	c, obs, _ := cachedClient(t, stub, CacheOptions{Now: func() time.Time { return now }})
	ctx := context.Background()

	at := time.Unix(1_760_000_010, 0) // within the same 30s bucket as +25s
	for i := range 3 {
		got, err := c.Query(ctx, "up", at.Add(time.Duration(i)*5*time.Second))
		if err != nil || len(got) != 1 {
			t.Fatalf("query %d: %v %v", i, got, err)
		}
	}
	if stub.hits.Load() != 1 {
		t.Fatalf("want 1 request inside one bucket, got %d", stub.hits.Load())
	}
	if obs.get(obs.results, CacheHit) != 2 || obs.get(obs.results, CacheMiss) != 1 || obs.get(obs.queries, KindInstant) != 1 {
		t.Fatalf("observer: %v %v", obs.results, obs.queries)
	}
	// The instant time is aligned down to the TTL.
	if !strings.Contains(stub.params[0], "time=1760000010.000") {
		t.Errorf("time not aligned: %s", stub.params[0])
	}

	// After the TTL the entry expires even for the same key.
	now = now.Add(31 * time.Second)
	if _, err := c.Query(ctx, "up", at); err != nil {
		t.Fatal(err)
	}
	if stub.hits.Load() != 2 {
		t.Fatalf("expired entry served: %d requests", stub.hits.Load())
	}
}

func TestCacheRangeAlignsEndAndUsesStepTTL(t *testing.T) {
	stub := &stubProm{}
	now := time.Unix(1_760_000_000, 0)
	c, _, _ := cachedClient(t, stub, CacheOptions{Now: func() time.Time { return now }})
	ctx := context.Background()
	step := 5 * time.Minute

	// Users a few seconds apart, inside one step, share an entry.
	base := time.Unix(1_760_000_200, 0) // 100s into the 300s step that starts at 1760000100
	for _, off := range []time.Duration{0, 30 * time.Second, 90 * time.Second} {
		end := base.Add(off)
		if _, err := c.QueryRange(ctx, "x", end.Add(-24*time.Hour), end, step); err != nil {
			t.Fatal(err)
		}
	}
	if stub.hits.Load() != 1 {
		t.Fatalf("want 1 request within one step, got %d", stub.hits.Load())
	}
	if p := stub.params[0]; !strings.Contains(p, "end=1760000100.000") || !strings.Contains(p, "start=1759913700.000") {
		t.Errorf("end/start not aligned to the step: %s", p)
	}

	// The TTL is the step (5m), longer than the 30s minimum.
	now = now.Add(4 * time.Minute)
	if _, err := c.QueryRange(ctx, "x", base.Add(-24*time.Hour), base, step); err != nil {
		t.Fatal(err)
	}
	if stub.hits.Load() != 1 {
		t.Fatal("range entry expired before its step")
	}
	now = now.Add(2 * time.Minute)
	if _, err := c.QueryRange(ctx, "x", base.Add(-24*time.Hour), base, step); err != nil {
		t.Fatal(err)
	}
	if stub.hits.Load() != 2 {
		t.Fatal("range entry outlived its step")
	}
}

func TestCacheSingleflight(t *testing.T) {
	stub := &stubProm{release: make(chan struct{})}
	c, obs, _ := cachedClient(t, stub, CacheOptions{})
	ctx := context.Background()
	at := time.Unix(1_760_000_000, 0)

	const n = 50
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := c.Query(ctx, "up", at)
			if err == nil && len(got) != 1 {
				err = fmt.Errorf("got %d series", len(got))
			}
			errs <- err
		}()
	}
	// Wait until everyone is queued behind the one request, then release it.
	deadline := time.Now().Add(5 * time.Second)
	for obs.get(obs.results, CacheShared)+obs.get(obs.results, CacheMiss) < n && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	close(stub.release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if stub.hits.Load() != 1 {
		t.Fatalf("want 1 request for %d identical concurrent queries, got %d", n, stub.hits.Load())
	}
	if obs.get(obs.results, CacheMiss) != 1 || obs.get(obs.results, CacheShared) != n-1 {
		t.Errorf("observer: %v", obs.results)
	}
}

func TestCacheWaiterCancellation(t *testing.T) {
	stub := &stubProm{release: make(chan struct{})}
	c, obs, _ := cachedClient(t, stub, CacheOptions{})
	at := time.Unix(1_760_000_000, 0)

	// One caller gives up; the other still gets the result.
	ctx1, cancel1 := context.WithCancel(context.Background())
	done1 := make(chan error, 1)
	go func() { _, err := c.Query(ctx1, "up", at); done1 <- err }()
	done2 := make(chan error, 1)
	go func() { _, err := c.Query(context.Background(), "up", at); done2 <- err }()
	for obs.get(obs.results, CacheShared) < 1 {
		time.Sleep(time.Millisecond)
	}
	cancel1()
	if err := <-done1; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled caller: %v", err)
	}
	close(stub.release)
	if err := <-done2; err != nil {
		t.Fatalf("remaining caller failed because another gave up: %v", err)
	}

	// When every caller leaves, the request is cancelled and nothing is cached.
	stub2 := &stubProm{release: make(chan struct{})}
	c2, _, _ := cachedClient(t, stub2, CacheOptions{})
	ctx3, cancel3 := context.WithCancel(context.Background())
	done3 := make(chan error, 1)
	go func() { _, err := c2.Query(ctx3, "up", at); done3 <- err }()
	for stub2.hits.Load() < 1 {
		time.Sleep(time.Millisecond)
	}
	cancel3()
	<-done3
	inflight := func() int {
		c2.cache.mu.Lock()
		defer c2.cache.mu.Unlock()
		return len(c2.cache.calls)
	}
	deadline := time.Now().Add(5 * time.Second)
	for inflight() > 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if inflight() != 0 || c2.cache.Len() != 0 {
		t.Fatal("abandoned request was cached")
	}
	// A new caller starts afresh rather than joining the abandoned request.
	close(stub2.release)
	if _, err := c2.Query(context.Background(), "up", at); err != nil {
		t.Fatalf("fresh caller: %v", err)
	}
}

func TestCacheDoesNotCacheErrors(t *testing.T) {
	stub := &stubProm{}
	stub.fail.Store(true)
	c, _, _ := cachedClient(t, stub, CacheOptions{})
	at := time.Unix(1_760_000_000, 0)
	for range 2 {
		if _, err := c.Query(context.Background(), "up", at); err == nil {
			t.Fatal("expected error")
		}
	}
	if stub.hits.Load() != 2 {
		t.Fatalf("error was cached: %d requests", stub.hits.Load())
	}
}

func TestCacheLRUBoundedByBytes(t *testing.T) {
	c := NewCache(CacheOptions{MaxBytes: 1000, MaxEntryBytes: 400})
	fetch := func(size int64) func(context.Context) ([]Series, int64, error) {
		return func(context.Context) ([]Series, int64, error) { return []Series{{}}, size, nil }
	}
	ctx := context.Background()
	for i := range 5 {
		if _, err := c.do(ctx, fmt.Sprint("k", i), time.Minute, nil, fetch(300)); err != nil {
			t.Fatal(err)
		}
	}
	if c.Bytes() > 1000 || c.Len() != 3 {
		t.Fatalf("bytes=%d len=%d", c.Bytes(), c.Len())
	}
	// Oldest entries were evicted; the newest survive.
	c.mu.Lock()
	_, old := c.items["k0"]
	_, recent := c.items["k4"]
	c.mu.Unlock()
	if old || !recent {
		t.Fatal("LRU evicted the wrong entries")
	}
	// An entry over the per-entry cap is returned but not stored.
	if got, err := c.do(ctx, "big", time.Minute, nil, fetch(401)); err != nil || len(got) != 1 {
		t.Fatal(got, err)
	}
	c.mu.Lock()
	_, stored := c.items["big"]
	c.mu.Unlock()
	if stored {
		t.Fatal("oversized entry cached")
	}
}

func TestCacheDefaultsAndRealSizes(t *testing.T) {
	c := NewCache(CacheOptions{})
	if c.opts.MaxBytes != 64<<20 || c.opts.MaxEntryBytes != 8<<20 || c.opts.InstantTTL != 30*time.Second || c.opts.MinRangeTTL != 30*time.Second {
		t.Fatalf("defaults: %+v", c.opts)
	}
	if c.ttl(KindRange, 10*time.Second) != 30*time.Second || c.ttl(KindRange, 5*time.Minute) != 5*time.Minute {
		t.Fatal("range TTL")
	}
	// A real response is accounted with a positive size.
	stub := &stubProm{}
	cl, _, _ := cachedClient(t, stub, CacheOptions{})
	if _, err := cl.QueryRange(context.Background(), "x", time.Unix(1_760_000_000, 0), time.Unix(1_760_003_600, 0), time.Minute); err != nil {
		t.Fatal(err)
	}
	if cl.cache.Bytes() <= 0 || cl.cache.Len() != 1 {
		t.Fatalf("bytes=%d len=%d", cl.cache.Bytes(), cl.cache.Len())
	}
}

func TestResponseCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[` + strings.Repeat(" ", 2000) + `]}}`))
	}))
	defer srv.Close()
	c, _ := NewClient(srv.URL, Options{MaxResponseBytes: 1000})
	if _, err := c.Query(context.Background(), "up", time.Now()); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("want ErrResponseTooLarge, got %v", err)
	}
}

func TestCachedResultsAreIndependentSlices(t *testing.T) {
	stub := &stubProm{}
	c, _, _ := cachedClient(t, stub, CacheOptions{})
	at := time.Unix(1_760_000_000, 0)
	a, _ := c.Query(context.Background(), "up", at)
	a[0] = Series{} // a caller reusing its slice must not corrupt the cache
	b, _ := c.Query(context.Background(), "up", at)
	if len(b) != 1 || b[0].Labels["pod"] != "a" {
		t.Fatalf("cache corrupted by caller: %+v", b)
	}
}
