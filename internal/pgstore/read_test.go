package pgstore

import (
	"context"
	"errors"
	"math"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/audit/audittest"
)

// Reads fail fast with audit.ErrOverloaded instead of hanging: a query past
// QueryTimeout is cancelled in Postgres too (not left running there), and a
// read that finds every read slot busy gives up after AcquireTimeout.
func TestPGReadsFailFastWhenOverloaded(t *testing.T) {
	ctx := context.Background()
	s := openTest(t, Options{MaxConns: 3, QueryTimeout: 300 * time.Millisecond, AcquireTimeout: 100 * time.Millisecond})
	if cap(s.readers) != 1 {
		t.Fatalf("read slots = %d, want MaxConns-2 = 1", cap(s.readers))
	}
	if err := s.Add(ctx, []audit.Event{ev("a", "ResponseComplete", 200, audittest.Base)}); err != nil {
		t.Fatal(err)
	}
	flush(t, s)

	blocker := admin(t)
	tx, err := blocker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, "LOCK TABLE "+pgx.Identifier{s.o.Schema, "audit_events"}.Sanitize()+" IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatal(err)
	}
	slow := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := s.Query(ctx, audit.Query{User: "alice"})
		slow <- err
	}()
	time.Sleep(50 * time.Millisecond) // it holds the only read slot, waiting on the lock
	_, err = s.Query(ctx, audit.Query{User: "alice"})
	if !errors.Is(err, audit.ErrOverloaded) || !strings.Contains(err.Error(), "slots") {
		t.Errorf("read with every slot busy = %v, want ErrOverloaded (slots)", err)
	}
	err = <-slow
	if !errors.Is(err, audit.ErrOverloaded) || time.Since(start) > 5*time.Second {
		t.Errorf("read stuck on a lock = %v after %s, want ErrOverloaded after ~300ms", err, time.Since(start))
	}
	// Postgres was told to cancel it: no lock request of ours is left waiting.
	deadline := time.Now().Add(3 * time.Second)
	for {
		var waiting int
		if err := blocker.QueryRow(ctx, `SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid = l.relation
JOIN pg_namespace n ON n.oid = c.relnamespace WHERE NOT l.granted AND n.nspname = $1`, s.o.Schema).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d lock requests still wait: the timed-out statement was not cancelled", waiting)
		}
		time.Sleep(20 * time.Millisecond)
	}
	tx.Rollback(ctx)
	if got, err := s.Query(ctx, audit.Query{User: "alice"}); err != nil || len(got) != 1 {
		t.Errorf("after the lock: %d events, %v", len(got), err)
	}
}

// Above the exact-count threshold the event count is the planner's
// estimate: each partition's rows per page at its last ANALYZE times its
// pages now, so it follows growth between ANALYZEs.
func TestPGCoverageEstimatesLargeStores(t *testing.T) {
	ctx := context.Background()
	s := openTest(t, Options{})
	s.exactCountBelow = 100
	rng := rand.New(rand.NewSource(3))
	addAll(t, s, audittest.Busy(rng, 3000, audittest.Base, time.Second))
	if _, err := s.pool.Exec(ctx, "ANALYZE audit_events"); err != nil {
		t.Fatal(err)
	}
	near := func(got, want int64, tol float64) bool { return math.Abs(float64(got-want)) <= tol*float64(want) }
	cov, err := s.Coverage(ctx)
	if err != nil || !near(cov.Events, 3000, 0.02) {
		t.Fatalf("after ANALYZE: %d events, %v; want about 3000", cov.Events, err)
	}
	if cov.Oldest.IsZero() || !cov.Newest.After(cov.Oldest) {
		t.Errorf("span = %s .. %s", cov.Oldest, cov.Newest)
	}
	addAll(t, s, audittest.Busy(rng, 3000, audittest.Base.Add(time.Hour), time.Second)) // no ANALYZE
	if cov, err = s.Coverage(ctx); err != nil || !near(cov.Events, 6000, 0.1) {
		t.Errorf("after growth: %d events, %v; want about 6000", cov.Events, err)
	}
	s.exactCountBelow = 1e9
	if cov, err = s.Coverage(ctx); err != nil || cov.Events != 6000 {
		t.Errorf("below the threshold: %d events, %v; want exactly 6000", cov.Events, err)
	}
}

// The scoped reads use the indexes migration 0002 adds: a summary without
// system actors reads audit_events_summary only (index-only; the planner has
// to prove its predicate from where()'s literal actor kinds), and a page of
// a few namespaces reads one audit_events_scoped_view range per namespace.
// Sequential and bitmap scans are off so the plan shows what the indexes
// allow even on this small table.
func TestPGScopedReadsUseTheirIndexes(t *testing.T) {
	ctx := context.Background()
	s := openTest(t, Options{})
	addAll(t, s, audittest.Busy(rand.New(rand.NewSource(5)), 2000, audittest.Base, time.Second))
	if _, err := s.pool.Exec(ctx, "ANALYZE audit_events"); err != nil {
		t.Fatal(err)
	}
	explain := func(sql string, args ...any) string {
		t.Helper()
		var plan []string
		err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, "SET LOCAL enable_seqscan = off; SET LOCAL enable_bitmapscan = off"); err != nil {
				return err
			}
			rows, err := tx.Query(ctx, "EXPLAIN "+sql, args...)
			if err != nil {
				return err
			}
			plan, err = pgx.CollectRows(rows, pgx.RowTo[string])
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(plan, "\n")
	}
	scope := map[string]bool{"team-3": true, "team-7": true}
	since := audittest.Base.Add(-time.Hour)

	cond, args := where(audit.Query{Since: since, Actors: map[string]bool{"user": true, "serviceaccount": true}, IncludeReads: true, Namespaces: scope}.Canonical())
	if plan := explain("SELECT username, actor_kind, count(*), max(time), sum(cardinality(tags)) FROM audit_events"+cond+" GROUP BY 1, 2", args...); !strings.Contains(plan, "Index Only Scan using audit_events_") ||
		!strings.Contains(plan, "_namespace_time_username") {
		t.Errorf("scoped summary does not read audit_events_summary alone:\n%s", plan)
	}

	sql, args, ok := scopedPageSQL(audit.Query{Since: since, Namespaces: scope, ClusterScoped: true, Limit: 201}.Canonical())
	if !ok || strings.Count(sql, "UNION ALL") != 2 {
		t.Fatalf("scoped page: ok %v, sql %s", ok, sql)
	}
	if plan := explain(sql, args...); !strings.Contains(plan, "_namespace_time_audit_id_idx") {
		t.Errorf("scoped page does not read audit_events_scoped_view:\n%s", plan)
	}
	// Too many namespaces, no limit or no scope: one plain statement.
	big := map[string]bool{}
	for i := 0; i < maxScopeBranches+1; i++ {
		big[strings.Repeat("n", i+1)] = true
	}
	for _, q := range []audit.Query{{Namespaces: big, Limit: 10}, {Namespaces: scope}, {Limit: 10}, {Namespaces: map[string]bool{}, Limit: 10}} {
		if _, _, ok := scopedPageSQL(q.Canonical()); ok {
			t.Errorf("scopedPageSQL took %+v", q)
		}
	}
}
