package pgstore

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/audit/audittest"
)

// TestPGConcurrentLoad is the dashboard stampede of stress checkpoint D
// against one store: many users at once asking for the audit coverage
// (/info), 24h summaries in their own scopes (about 100 distinct small
// scopes, plus the cluster-wide one admins share), the default event view in
// their scope, and the activity of one pod (the pod page). It reports the
// latency per call kind.
//
// It needs KUBESENTRY_TEST_PG_LOAD=1. The events (schema kst_load, Busy
// events over the last ~26h; KUBESENTRY_TEST_PG_LOAD_EVENTS, default 3.2M)
// are loaded once and kept for later runs. A data set that size does not fit
// a small tmpfs: start Postgres on disk, e.g.
//
//	PG_TEST_VOLUME=kst-load PG_TEST_MEMORY=1536m PG_TEST_CPUS=4 eval "$(hack/pg-test.sh)"
//	KUBESENTRY_TEST_PG_LOAD=1 go test -run TestPGConcurrentLoad -v -timeout 60m ./internal/pgstore/
//
// KUBESENTRY_TEST_PG_LOAD_USERS (200) and KUBESENTRY_TEST_PG_LOAD_DURATION
// (90s) size the run; each call has the API's 30s route timeout. Between calls
// each user waits a random time up to KUBESENTRY_TEST_PG_LOAD_THINK_MS (100):
// the default keeps Postgres saturated; 2000 is about 200 calls a second, 7
// times what 500 users of the stress test sent.
func TestPGConcurrentLoad(t *testing.T) {
	dsn := testDSN(t)
	if os.Getenv("KUBESENTRY_TEST_PG_LOAD") == "" {
		t.Skip("set KUBESENTRY_TEST_PG_LOAD=1 to load millions of events and run the concurrent dashboard load")
	}
	n := envInt(t, "KUBESENTRY_TEST_PG_LOAD_EVENTS", 3_200_000)
	users := envInt(t, "KUBESENTRY_TEST_PG_LOAD_USERS", 200)
	think := time.Duration(envInt(t, "KUBESENTRY_TEST_PG_LOAD_THINK_MS", 100)) * time.Millisecond
	dur := 90 * time.Second
	if v := os.Getenv("KUBESENTRY_TEST_PG_LOAD_DURATION"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			t.Fatal(err)
		}
		dur = d
	}
	ctx := context.Background()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Load (or reuse) the data with caching off, then reopen with the
	// defaults the server runs with.
	loader, err := Open(ctx, dsn, Options{Schema: "kst_load", CacheTTL: -1, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	if have := count(t, loader, "SELECT count(*) FROM audit_events"); have < int64(n) {
		t0 := time.Now()
		span := 26 * time.Hour
		step := span / time.Duration(n)
		start := time.Now().Add(-span)
		rng := rand.New(rand.NewSource(1))
		const chunk = 100_000
		for i := int(have); i < n; i += chunk {
			k := min(chunk, n-i)
			addAll(t, loader, audittest.Busy(rng, k, start.Add(time.Duration(i)*step), step))
		}
		if _, err := loader.Pool().Exec(ctx, "VACUUM ANALYZE audit_events"); err != nil {
			t.Fatal(err)
		}
		t.Logf("loaded %d events in %s", n-int(have), time.Since(t0).Round(time.Second))
	}
	loader.Close(ctx)

	s, err := Open(ctx, dsn, Options{Schema: "kst_load", Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close(ctx)

	// About 100 distinct small scopes (1-3 team namespaces of Busy's 300).
	scopes := make([]map[string]bool, 100)
	for i := range scopes {
		scopes[i] = map[string]bool{}
		for j := 0; j <= i%3; j++ {
			scopes[i][fmt.Sprintf("team-%d", (i*3+j*101)%300)] = true
		}
	}
	all := map[string]bool{"user": true, "serviceaccount": true, "system": true}
	people := map[string]bool{"user": true, "serviceaccount": true}

	type sample struct {
		kind string
		d    time.Duration
		err  error
	}
	results := make(chan sample, 4096)
	var wg sync.WaitGroup
	deadline := time.Now().Add(dur)
	for u := 0; u < users; u++ {
		wg.Add(1)
		go func(u int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(u)))
			var scope map[string]bool // nil: an admin, who sees everything
			if u%10 != 0 {
				scope = scopes[rng.Intn(len(scopes))]
			}
			var nss []string
			for ns := range scope {
				nss = append(nss, ns)
			}
			if len(nss) == 0 {
				nss = []string{fmt.Sprintf("team-%d", rng.Intn(300))}
			}
			for time.Now().Before(deadline) {
				time.Sleep(time.Duration(rng.Int63n(int64(think))))
				now := time.Now()
				rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
				var kind string
				var err error
				switch r := rng.Intn(100); {
				case r < 35:
					kind = "coverage"
					_, err = s.Coverage(rctx)
				case r < 55:
					kind = "summary (scoped)"
					if scope == nil {
						kind = "summary (all)"
					}
					_, err = s.Summarize(rctx, audit.Query{Since: now.Add(-24 * time.Hour), Actors: people, IncludeReads: true, Namespaces: scope})
				case r < 85:
					kind = "events (scoped)"
					limit := 201
					if scope == nil {
						kind, limit = "events (all)", 501
					}
					_, err = s.Query(rctx, audit.Query{Since: now.Add(-24 * time.Hour), Namespaces: scope, Limit: limit})
				default:
					kind = "pod activity"
					_, err = s.Query(rctx, audit.Query{Since: now.Add(-7 * 24 * time.Hour), Namespace: nss[rng.Intn(len(nss))],
						Resource: "pods", Name: fmt.Sprintf("obj-%d", rng.Intn(50)), Actors: all, IncludeReads: true, Limit: 50})
				}
				results <- sample{kind, time.Since(now), err}
				cancel()
			}
		}(u)
	}
	go func() { wg.Wait(); close(results) }()

	byKind := map[string][]time.Duration{}
	errs := map[string]int{}
	firstErr := map[string]error{}
	for r := range results {
		byKind[r.kind] = append(byKind[r.kind], r.d)
		if r.err != nil {
			errs[r.kind]++
			if firstErr[r.kind] == nil {
				firstErr[r.kind] = r.err
			}
		}
	}
	kinds := make([]string, 0, len(byKind))
	for k := range byKind {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	var b strings.Builder
	fmt.Fprintf(&b, "\n%d users (think time up to %s) for %s, %d events\n\n| call | n | p50 | p95 | p99 | max | errors |\n|---|---:|---:|---:|---:|---:|---:|\n", users, think, dur, n)
	for _, k := range kinds {
		ds := byKind[k]
		sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
		q := func(p float64) string { return ms(ds[min(len(ds)-1, int(p*float64(len(ds))))]) }
		fmt.Fprintf(&b, "| %s | %d | %s | %s | %s | %s | %d |\n", k, len(ds), q(0.50), q(0.95), q(0.99), ms(ds[len(ds)-1]), errs[k])
	}
	t.Log(b.String())
	for k, err := range firstErr {
		t.Logf("first %s error: %v", k, err)
	}
}

func ms(d time.Duration) string {
	if d < 10*time.Millisecond {
		return strconv.FormatFloat(float64(d)/float64(time.Millisecond), 'f', 1, 64)
	}
	return strconv.FormatInt(d.Milliseconds(), 10)
}

func envInt(tb testing.TB, name string, def int) int {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		tb.Fatalf("%s=%q: want a positive integer", name, v)
	}
	return n
}
