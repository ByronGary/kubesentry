package prom

import (
	"container/list"
	"context"
	"sync"
	"time"
)

// Cache results reported to an Observer.
const (
	CacheHit    = "hit"    // served from the cache
	CacheShared = "shared" // joined an identical query already in flight
	CacheMiss   = "miss"   // sent to Prometheus
)

// Observer receives the cache and query metrics. The server wires it to
// kubesentry_prometheus_cache_total{result} and
// kubesentry_prometheus_query_seconds{kind}; this package does not import the
// metrics registry.
type Observer interface {
	// CacheResult counts one cached lookup: CacheHit, CacheShared or CacheMiss.
	CacheResult(result string)
	// ObserveQuery records one request to Prometheus: KindInstant or KindRange.
	ObserveQuery(kind string, d time.Duration)
}

// ObserverFuncs adapts two functions to an Observer; nil fields are skipped.
type ObserverFuncs struct {
	Cache func(result string)
	Query func(kind string, d time.Duration)
}

func (o ObserverFuncs) CacheResult(result string) {
	if o.Cache != nil {
		o.Cache(result)
	}
}

func (o ObserverFuncs) ObserveQuery(kind string, d time.Duration) {
	if o.Query != nil {
		o.Query(kind, d)
	}
}

// CacheOptions sizes a Cache. Zero fields take the defaults.
type CacheOptions struct {
	MaxBytes      int64         // total estimated size; default 64 MiB
	MaxEntryBytes int64         // larger results are not cached; default 8 MiB
	InstantTTL    time.Duration // instant queries; default 30s
	MinRangeTTL   time.Duration // a range query lives for its step, at least this; default 30s
	Now           func() time.Time
}

// Cache is a query result cache shared by every caller of a Client: a TTL per
// entry, singleflight so identical concurrent queries reach Prometheus once,
// and an LRU bounded by the estimated size of the parsed results. Errors are
// never cached.
type Cache struct {
	opts  CacheOptions
	mu    sync.Mutex
	lru   *list.List // front is most recently used
	items map[string]*list.Element
	bytes int64
	calls map[string]*call
}

type cacheEntry struct {
	key     string
	series  []Series
	size    int64
	expires time.Time
}

// call is one query in flight. Waiters that give up decrement waiters; the
// last one to leave cancels the request.
type call struct {
	done    chan struct{}
	series  []Series
	err     error
	waiters int
	cancel  context.CancelFunc
}

// NewCache returns an empty cache.
func NewCache(opts CacheOptions) *Cache {
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = 64 << 20
	}
	if opts.MaxEntryBytes <= 0 {
		opts.MaxEntryBytes = 8 << 20
	}
	if opts.MaxEntryBytes > opts.MaxBytes {
		opts.MaxEntryBytes = opts.MaxBytes
	}
	if opts.InstantTTL <= 0 {
		opts.InstantTTL = 30 * time.Second
	}
	if opts.MinRangeTTL <= 0 {
		opts.MinRangeTTL = 30 * time.Second
	}
	return &Cache{opts: opts, lru: list.New(), items: map[string]*list.Element{}, calls: map[string]*call{}}
}

func (c *Cache) now() time.Time {
	if c.opts.Now != nil {
		return c.opts.Now()
	}
	return time.Now()
}

func (c *Cache) ttl(kind string, step time.Duration) time.Duration {
	if kind == KindRange {
		return max(step, c.opts.MinRangeTTL)
	}
	return c.opts.InstantTTL
}

// Len is the number of cached results.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.Len()
}

// Bytes is the estimated size of the cached results.
func (c *Cache) Bytes() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bytes
}

func (c *Cache) do(ctx context.Context, key string, ttl time.Duration, obs Observer, fetch func(context.Context) ([]Series, int64, error)) ([]Series, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	if el, ok := c.items[key]; ok {
		e := el.Value.(*cacheEntry)
		if c.now().Before(e.expires) {
			c.lru.MoveToFront(el)
			c.mu.Unlock()
			count(obs, CacheHit)
			return append([]Series(nil), e.series...), nil
		}
		c.remove(el)
	}
	// Join a query in flight unless everyone already gave up on it.
	if cl, ok := c.calls[key]; ok && cl.waiters > 0 {
		cl.waiters++
		c.mu.Unlock()
		count(obs, CacheShared)
		return c.wait(ctx, cl)
	}
	// The request outlives any one caller: it runs until it finishes or the
	// last waiter leaves. The HTTP client's timeout still bounds it.
	fctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	cl := &call{done: make(chan struct{}), waiters: 1, cancel: cancel}
	c.calls[key] = cl
	c.mu.Unlock()
	count(obs, CacheMiss)

	go func() {
		series, size, err := fetch(fctx)
		cancel()
		c.mu.Lock()
		if c.calls[key] == cl {
			delete(c.calls, key)
		}
		if err == nil {
			c.add(key, series, size, ttl)
		}
		cl.series, cl.err = series, err
		c.mu.Unlock()
		close(cl.done)
	}()
	return c.wait(ctx, cl)
}

func (c *Cache) wait(ctx context.Context, cl *call) ([]Series, error) {
	select {
	case <-cl.done:
		if cl.err != nil {
			return nil, cl.err
		}
		return append([]Series(nil), cl.series...), nil
	case <-ctx.Done():
		c.mu.Lock()
		cl.waiters--
		if cl.waiters == 0 {
			cl.cancel()
		}
		c.mu.Unlock()
		return nil, ctx.Err()
	}
}

// add stores a result; the caller holds c.mu.
func (c *Cache) add(key string, series []Series, size int64, ttl time.Duration) {
	if size > c.opts.MaxEntryBytes {
		return
	}
	if el, ok := c.items[key]; ok {
		c.remove(el)
	}
	c.items[key] = c.lru.PushFront(&cacheEntry{key: key, series: series, size: size, expires: c.now().Add(ttl)})
	c.bytes += size
	for c.bytes > c.opts.MaxBytes {
		c.remove(c.lru.Back())
	}
}

func (c *Cache) remove(el *list.Element) {
	e := c.lru.Remove(el).(*cacheEntry)
	delete(c.items, e.key)
	c.bytes -= e.size
}

func count(obs Observer, result string) {
	if obs != nil {
		obs.CacheResult(result)
	}
}
