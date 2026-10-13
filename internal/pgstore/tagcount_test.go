package pgstore

import (
	"context"
	"fmt"
	"math/rand"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/audit/audittest"
)

// Callers with different audit scopes never share a tag count cache entry;
// equal scopes asked a few seconds apart do.
func TestTagCacheKey(t *testing.T) {
	ttl := 30 * time.Second
	now := time.Now()
	since := now.Add(-24 * time.Hour)
	q := func(nss map[string]bool, cluster bool) audit.TagCountQuery {
		return audit.TagCountQuery{Since: since, Tags: []string{audit.TagExec}, Namespaces: nss, ClusterScoped: cluster, Latest: 5}
	}
	keys := map[string]string{}
	for name, tq := range map[string]audit.TagCountQuery{
		"everything":  q(nil, false),
		"nothing":     q(map[string]bool{}, false),
		"clusterOnly": q(map[string]bool{}, true),
		"a":           q(map[string]bool{"a": true}, false),
	} {
		k := tagCacheKey(tq, ttl, now)
		if other, dup := keys[k]; dup {
			t.Errorf("%s and %s share the cache key %s", name, other, k)
		}
		keys[k] = name
	}
	a := q(map[string]bool{"a": true, "b": true, "c": false}, false)
	b := q(map[string]bool{"b": true, "a": true}, false)
	b.Tags = []string{audit.TagExec, audit.TagExec}
	if tagCacheKey(a, ttl, now) != tagCacheKey(b, ttl, now) {
		t.Error("equal queries give different keys")
	}
	later := now.Add(5 * time.Second)
	moved := a
	moved.Since = later.Add(-24 * time.Hour)
	if tagCacheKey(moved, ttl, later) != tagCacheKey(a, ttl, now) {
		t.Error("the rolling 24h window asked 5s later has another key")
	}
	other := a
	other.Subset = map[string]bool{"a": true}
	if tagCacheKey(other, ttl, now) == tagCacheKey(a, ttl, now) {
		t.Error("another production subset shares the key")
	}
}

// Without Postgres: concurrent callers of one scope share one computation,
// another scope gets its own, and callers cannot change the cached value.
func TestTagCountsCacheSingleFlight(t *testing.T) {
	s := &Store{o: Options{CacheTTL: 30 * time.Second, Now: time.Now}}
	var calls atomic.Int32
	release := make(chan struct{})
	s.countTagsFn = func(_ context.Context, q audit.TagCountQuery) (audit.TagCounts, error) {
		calls.Add(1)
		<-release
		return audit.TagCounts{ByTag: map[string]int{audit.TagExec: len(q.Namespaces)}, Subset: map[string]int{}, Latest: []audit.Event{{AuditID: "x"}}}, nil
	}
	ctx := context.Background()
	since := time.Now().Add(-24 * time.Hour)
	team := audit.TagCountQuery{Since: since, Tags: []string{audit.TagExec}, Namespaces: map[string]bool{"a": true}}
	var wg sync.WaitGroup
	results := make([]audit.TagCounts, 20)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := s.CountTags(ctx, team)
			if err != nil {
				t.Error(err)
			}
			results[i] = c
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	if n := calls.Load(); n != 1 {
		t.Errorf("%d computations for one scope, want 1", n)
	}
	results[0].ByTag[audit.TagExec] = 99
	results[0].Latest[0].AuditID = "changed"
	c, _ := s.CountTags(ctx, team)
	if c.ByTag[audit.TagExec] != 1 || c.Latest[0].AuditID != "x" {
		t.Errorf("a caller changed the cached counts: %+v", c)
	}
	if calls.Load() != 1 {
		t.Error("a fresh entry was computed again")
	}
	everything := team
	everything.Namespaces = nil
	if c, _ := s.CountTags(ctx, everything); c.ByTag[audit.TagExec] != 0 || calls.Load() != 2 {
		t.Errorf("another scope = %+v after %d computations", c, calls.Load())
	}
}

// TestPGCountTagsMatchesMemory is the parity test for tag counts.
func TestPGCountTagsMatchesMemory(t *testing.T) {
	testDSN(t)
	const span = 2 * time.Hour
	ctx := context.Background()
	for seed := int64(1); seed <= 2; seed++ {
		t.Run(fmt.Sprint("seed", seed), func(t *testing.T) {
			rng := rand.New(rand.NewSource(seed))
			events := audittest.Events(rng, 2500, span)
			mem := audit.NewMemoryStore(1 << 20).AsStore()
			pg := openTest(t, Options{BatchSize: 500})
			if err := mem.Add(ctx, events); err != nil {
				t.Fatal(err)
			}
			if err := pg.Add(ctx, events); err != nil {
				t.Fatal(err)
			}
			flush(t, pg)
			for i := 0; i < 150; i++ {
				q := audittest.TagQuery(rng, span)
				want, _ := audit.CountTags(ctx, mem, q)
				got, err := pg.CountTags(ctx, q)
				if err != nil {
					t.Fatalf("%+v: %v", q, err)
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("query %d %+v:\npostgres %+v\nmemory   %+v", i, q, got, want)
				}
			}
		})
	}
}
