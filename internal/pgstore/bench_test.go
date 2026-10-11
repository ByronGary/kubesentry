package pgstore

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/audit/audittest"
)

// addAll feeds events the way the webhook does (400 per request), waiting out
// backpressure, then flushes.
func addAll(tb testing.TB, s *Store, events []audit.Event) {
	tb.Helper()
	ctx := context.Background()
	for i := 0; i < len(events); i += 400 {
		chunk := events[i:min(i+400, len(events))]
		deadline := time.Now().Add(time.Minute)
		for {
			err := s.Add(ctx, chunk)
			if err == nil {
				break
			}
			if !errors.Is(err, audit.ErrBackpressure) || time.Now().After(deadline) {
				tb.Fatalf("add: %v (store: %+v)", err, s.Stats())
			}
			time.Sleep(2 * time.Millisecond)
		}
	}
	flush(tb, s)
}

// BenchmarkIngest measures sustained webhook-style ingest through the queue,
// COPY and upsert. Run with -benchtime=200000x for a stable figure.
func BenchmarkIngest(b *testing.B) {
	s := openTest(b, Options{})
	events := audittest.Busy(rand.New(rand.NewSource(int64(b.N))), b.N, audittest.Base.Add(-12*time.Hour), 40*time.Millisecond)
	b.ResetTimer()
	start := time.Now()
	addAll(b, s, events)
	b.ReportMetric(float64(b.N)/time.Since(start).Seconds(), "events/s")
}

// BenchmarkQuery1M measures dashboard queries over a million stored events.
// It needs KUBESENTRY_TEST_PG_BIG=1; the data (schema kst_bench_1m) is loaded
// once and kept for later runs.
func BenchmarkQuery1M(b *testing.B) {
	dsn := testDSN(b)
	if os.Getenv("KUBESENTRY_TEST_PG_BIG") == "" {
		b.Skip("set KUBESENTRY_TEST_PG_BIG=1 to load and query 1M events")
	}
	const n = 1_000_000
	step := 100 * time.Millisecond
	start := audittest.Base.Add(-n * step)
	end := audittest.Base
	ctx := context.Background()
	s, err := Open(ctx, dsn, Options{Schema: "kst_bench_1m", CacheTTL: -1, Now: func() time.Time { return end },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close(ctx)
	if have := count(b, s, "SELECT count(*) FROM audit_events"); have < n {
		t0 := time.Now()
		events := audittest.Busy(rand.New(rand.NewSource(1)), n, start, step)
		addAll(b, s, events)
		if _, err := s.Pool().Exec(ctx, "ANALYZE audit_events"); err != nil {
			b.Fatal(err)
		}
		b.Logf("loaded %d events in %s (%.0f events/s)", n, time.Since(t0).Round(time.Millisecond), float64(n)/time.Since(t0).Seconds())
	}
	deep, err := s.Query(ctx, audit.Query{Limit: 5000})
	if err != nil {
		b.Fatal(err)
	}
	for _, c := range audittest.BenchQueries(end, audit.CursorOf(deep[len(deep)-1])) {
		b.Run(c.Name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				var err error
				if c.Summary {
					_, err = s.Summarize(ctx, c.Q)
				} else {
					_, err = s.Query(ctx, c.Q)
				}
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
	b.Run("coverage", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if _, err := s.Coverage(ctx); err != nil {
				b.Fatal(err)
			}
		}
	})
}
