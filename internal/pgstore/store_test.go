package pgstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"os"
	"reflect"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/audit/audittest"
)

// The tests need a Postgres: eval "$(hack/pg-test.sh)" sets the DSN.
const dsnEnv = "KUBESENTRY_TEST_PG_DSN"

func testDSN(tb testing.TB) string {
	dsn := os.Getenv(dsnEnv)
	if dsn == "" {
		tb.Skipf("%s not set; run eval \"$(hack/pg-test.sh)\" to test against Postgres", dsnEnv)
	}
	return dsn
}

var nonIdent = regexp.MustCompile(`[^a-z0-9_]+`)

// openTest opens a store in a fresh schema that is dropped afterwards.
func openTest(tb testing.TB, o Options) *Store {
	tb.Helper()
	dsn := testDSN(tb)
	name := nonIdent.ReplaceAllString(strings.ToLower(tb.Name()), "_")
	if len(name) > 40 {
		name = name[:40]
	}
	o.Schema = fmt.Sprintf("kst_%s_%04d", name, rand.Intn(10000))
	if o.Now == nil {
		o.Now = func() time.Time { return audittest.Base }
	}
	if o.CacheTTL == 0 {
		o.CacheTTL = -1
	}
	if o.Logger == nil && !testing.Verbose() {
		o.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	ctx := context.Background()
	s, err := Open(ctx, dsn, o)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() {
		s.Close(context.Background())
		conn, err := pgx.Connect(context.Background(), dsn)
		if err != nil {
			tb.Logf("cleanup: %v", err)
			return
		}
		defer conn.Close(context.Background())
		if _, err := conn.Exec(context.Background(), "DROP SCHEMA IF EXISTS "+pgx.Identifier{o.Schema}.Sanitize()+" CASCADE"); err != nil {
			tb.Logf("cleanup: %v", err)
		}
	})
	return s
}

func admin(tb testing.TB) *pgx.Conn {
	tb.Helper()
	conn, err := pgx.Connect(context.Background(), testDSN(tb))
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { conn.Close(context.Background()) })
	return conn
}

func flush(tb testing.TB, s *Store) {
	tb.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := s.Flush(ctx); err != nil {
		tb.Fatal(err)
	}
}

func count(tb testing.TB, s *Store, sql string, args ...any) int64 {
	tb.Helper()
	var n int64
	if err := s.pool.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil {
		tb.Fatal(err)
	}
	return n
}

// TestPGMatchesMemory is the parity test: the same random events and queries
// against MemoryStore and the Postgres store give identical results.
func TestPGMatchesMemory(t *testing.T) {
	testDSN(t) // skip visibly at the top level
	const span = 2 * time.Hour
	ctx := context.Background()
	for seed := int64(1); seed <= 3; seed++ {
		t.Run(fmt.Sprint("seed", seed), func(t *testing.T) {
			rng := rand.New(rand.NewSource(seed))
			events := audittest.Events(rng, 2000+rng.Intn(1000), span)
			mem := audit.NewMemoryStore(1 << 20).AsStore()
			pg := openTest(t, Options{BatchSize: 300})
			for i := 0; i < len(events); {
				n := min(1+rng.Intn(120), len(events)-i)
				chunk := events[i : i+n]
				if err := mem.Add(ctx, chunk); err != nil {
					t.Fatal(err)
				}
				if err := pg.Add(ctx, chunk); err != nil {
					t.Fatal(err)
				}
				if rng.Intn(5) == 0 {
					flush(t, pg) // vary how stages split across batches
				}
				i += n
			}
			flush(t, pg)

			mc, _ := mem.Coverage(ctx)
			pc, err := pg.Coverage(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if mc.Events != pc.Events || !mc.Oldest.Equal(pc.Oldest) || !mc.Newest.Equal(pc.Newest) {
				t.Fatalf("coverage: memory %+v, postgres %+v", mc, pc)
			}
			for i := 0; i < 300; i++ {
				q := audittest.Query(rng, span)
				want, _ := mem.Query(ctx, q)
				got, err := pg.Query(ctx, q)
				if err != nil {
					t.Fatalf("%s: %v", audittest.Describe(q), err)
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("query %d %s:\npostgres %d: %s\nmemory   %d: %s", i, audittest.Describe(q), len(got), firstDiff(got, want), len(want), firstDiff(want, got))
				}
				if i%3 == 0 {
					ws, _ := mem.Summarize(ctx, q)
					gs, err := pg.Summarize(ctx, q)
					if err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(gs, ws) {
						t.Fatalf("summary %s:\npostgres %+v\nmemory   %+v", audittest.Describe(q), gs, ws)
					}
				}
				if i%10 == 0 {
					checkPaging(t, pg, mem, q)
				}
			}
		})
	}
}

// checkPaging pages through q with cursors on the Postgres store and compares
// with the memory store's unpaged answer.
func checkPaging(t *testing.T, pg *Store, mem audit.Store, q audit.Query) {
	t.Helper()
	ctx := context.Background()
	q.Limit, q.Before = 0, audit.Cursor{}
	want, _ := mem.Query(ctx, q)
	got := []audit.Event{}
	q.Limit = 7
	for {
		page, err := pg.Query(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, page...)
		if len(page) < q.Limit || len(got) > len(want) {
			break
		}
		q.Before = audit.CursorOf(page[len(page)-1])
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("paged %s: postgres %d events, memory %d", audittest.Describe(q), len(got), len(want))
	}
}

func firstDiff(a, b []audit.Event) string {
	for i := range a {
		if i >= len(b) || !reflect.DeepEqual(a[i], b[i]) {
			return fmt.Sprintf("first difference at %d: %+v", i, a[i])
		}
	}
	return "no difference in the common prefix"
}

func ev(id, stage string, status int, at time.Time) audit.Event {
	e := audit.Event{AuditID: id, Time: at, Stage: stage, Verb: "create", Username: "alice", ActorKind: "user",
		Resource: "pods", Subresource: "exec", Namespace: "prod", Name: "web-0", StatusCode: status}
	e.Tags = audit.Classify(e)
	return e
}

func TestPGUpsertByStageRankAndDuplicates(t *testing.T) {
	ctx := context.Background()
	s := openTest(t, Options{})
	at := audittest.Base.Add(time.Minute)

	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(s.Add(ctx, []audit.Event{ev("x", "ResponseStarted", 101, at)}))
	flush(t, s)
	must(s.Add(ctx, []audit.Event{ev("x", "ResponseComplete", 200, at)}))
	flush(t, s)
	must(s.Add(ctx, []audit.Event{ev("x", "ResponseStarted", 101, at)})) // late, lower rank
	flush(t, s)
	// Within one batch, the higher rank wins regardless of order.
	must(s.Add(ctx, []audit.Event{ev("y", "ResponseComplete", 403, at), ev("y", "ResponseStarted", 101, at)}))
	flush(t, s)

	got, err := s.Query(ctx, audit.Query{Actors: map[string]bool{"user": true}, IncludeReads: true})
	must(err)
	if len(got) != 2 {
		t.Fatalf("got %d records, want 2: %+v", len(got), got)
	}
	for _, e := range got {
		if e.Stage != "ResponseComplete" {
			t.Errorf("%s kept stage %s, want ResponseComplete", e.AuditID, e.Stage)
		}
	}
	if got[0].AuditID != "y" || got[0].StatusCode != 403 || !reflect.DeepEqual(got[0].Tags, []string{audit.TagExec, audit.TagDenied}) {
		t.Errorf("y = %+v", got[0])
	}

	// Ingesting the same payload twice (a webhook retry, a CloudWatch overlap)
	// leaves one record per event.
	rng := rand.New(rand.NewSource(9))
	events := audittest.Events(rng, 1000, time.Hour)
	must(s.Add(ctx, events))
	must(s.Add(ctx, events))
	flush(t, s)
	want := int64(len(audittest.Records(events))) + 2
	if n := count(t, s, "SELECT count(*) FROM audit_events"); n != want {
		t.Errorf("after duplicate ingest: %d rows, want %d", n, want)
	}
	if st := s.Stats(); st.Written != int64(2*len(events)+5) || st.Dropped != 0 || st.Queued != 0 {
		t.Errorf("stats = %+v", st)
	}
}

func TestPGDropsOnlyRowsPostgresRejects(t *testing.T) {
	ctx := context.Background()
	s := openTest(t, Options{BatchSize: 50})
	var events []audit.Event
	for i := 0; i < 40; i++ {
		events = append(events, ev(fmt.Sprint("ok-", i), "ResponseComplete", 200, audittest.Base.Add(time.Duration(i)*time.Second)))
	}
	// A name too long (and too random to compress) for a btree index entry:
	// Postgres rejects that row only.
	noise := func() string {
		b := make([]byte, 6000)
		for i := range b {
			b[i] = "0123456789abcdefghijklmnopqrstuvwxyz"[rand.Intn(36)]
		}
		return string(b)
	}
	bad := ev("bad", "ResponseComplete", 200, audittest.Base)
	bad.Name = noise()
	bad.Username = noise()
	events = append(events[:20], append([]audit.Event{bad}, events[20:]...)...)
	if err := s.Add(ctx, events); err != nil {
		t.Fatal(err)
	}
	flush(t, s)
	if n := count(t, s, "SELECT count(*) FROM audit_events"); n != 40 {
		t.Errorf("rows = %d, want the 40 valid ones", n)
	}
	if st := s.Stats(); st.Dropped != 1 || st.Written != 40 {
		t.Errorf("stats = %+v, want 1 dropped, 40 written", st)
	}
}

func TestPGMaintainPartitions(t *testing.T) {
	ctx := context.Background()
	var now atomic.Pointer[time.Time]
	base := audittest.Base
	now.Store(&base)
	s := openTest(t, Options{Retention: 30 * 24 * time.Hour, Now: func() time.Time { return *now.Load() }})

	day := func(d int) time.Time { return base.Truncate(24*time.Hour).AddDate(0, 0, d) }
	parts := func() []string {
		rows, _ := s.pool.Query(ctx, `SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
JOIN pg_class p ON p.oid = i.inhparent JOIN pg_namespace n ON n.oid = p.relnamespace
WHERE p.relname = 'audit_events' AND n.nspname = $1 ORDER BY 1`, s.o.Schema)
		names, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatal(err)
		}
		return names
	}
	want := []string{partitionName(day(-1)), partitionName(day(0)), partitionName(day(1)), partitionName(day(2)), partitionName(day(3)), "audit_events_default"}
	if got := parts(); !reflect.DeepEqual(got, want) {
		t.Fatalf("after Open: partitions %v, want %v", got, want)
	}

	// A backfill of old events lands in the default partition; Maintain moves
	// it into a partition of its own and purges what is past retention.
	var events []audit.Event
	for i := 0; i < 30; i++ {
		events = append(events, ev(fmt.Sprint("old-", i), "ResponseComplete", 200, day(-10).Add(time.Duration(i)*time.Minute)))
	}
	for i := 0; i < 5; i++ {
		events = append(events, ev(fmt.Sprint("ancient-", i), "ResponseComplete", 200, day(-40).Add(time.Duration(i)*time.Minute)))
	}
	events = append(events, ev("today", "ResponseComplete", 200, base))
	if err := s.Add(ctx, events); err != nil {
		t.Fatal(err)
	}
	flush(t, s)
	if n := count(t, s, "SELECT count(*) FROM audit_events_default"); n != 35 {
		t.Fatalf("default partition holds %d rows, want 35", n)
	}
	res, err := s.MaintainReport(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(res.Created, []string{partitionName(day(-10))}) || res.Moved != 30 || res.PurgedRows != 5 || res.DefaultRows != 0 {
		t.Fatalf("maintain = %+v", res)
	}
	if n := count(t, s, "SELECT count(*) FROM "+partitionName(day(-10))); n != 30 {
		t.Errorf("moved partition holds %d rows, want 30", n)
	}
	if got, _ := s.Query(ctx, audit.Query{User: "alice"}); len(got) != 31 {
		t.Errorf("query after move: %d events, want 31", len(got))
	}
	// Idempotent.
	if res, err := s.MaintainReport(ctx); err != nil || len(res.Created)+len(res.Dropped) != 0 || res.Moved != 0 {
		t.Fatalf("second run = %+v, %v", res, err)
	}

	// 25 days on, the backfilled day is past retention and is dropped; the
	// window of new partitions moves forward.
	later := base.AddDate(0, 0, 25)
	now.Store(&later)
	res, err = s.MaintainReport(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(res.Dropped, []string{partitionName(day(-10))}) {
		t.Errorf("dropped = %v, want the day -10 partition", res.Dropped)
	}
	if len(res.Created) != 5 {
		t.Errorf("created = %v, want days 24..28", res.Created)
	}
	if got, _ := s.Query(ctx, audit.Query{User: "alice"}); len(got) != 1 || got[0].AuditID != "today" {
		t.Errorf("after retention: %d events", len(got))
	}
	cov, err := s.Coverage(ctx)
	if err != nil || cov.Events != 1 || cov.Retention != 30*24*time.Hour || cov.Backend != "postgres" {
		t.Errorf("coverage = %+v, %v", cov, err)
	}
}

func TestPGBackpressure(t *testing.T) {
	ctx := context.Background()
	s := openTest(t, Options{QueueSize: 100, BatchSize: 10, FlushInterval: 10 * time.Millisecond})
	// Block the writer: hold a lock that its INSERT needs.
	blocker := admin(t)
	tx, err := blocker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "LOCK TABLE "+pgx.Identifier{s.o.Schema, "audit_events"}.Sanitize()+" IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatal(err)
	}
	accepted := 0
	var lastErr error
	for i := 0; i < 50 && lastErr == nil; i++ {
		chunk := make([]audit.Event, 10)
		for j := range chunk {
			chunk[j] = ev(fmt.Sprintf("bp-%d-%d", i, j), "ResponseComplete", 200, audittest.Base.Add(time.Duration(i*10+j)*time.Millisecond))
		}
		if lastErr = s.Add(ctx, chunk); lastErr == nil {
			accepted += len(chunk)
		}
		time.Sleep(time.Millisecond)
	}
	if !errors.Is(lastErr, audit.ErrBackpressure) {
		t.Fatalf("Add never pushed back (accepted %d): %v", accepted, lastErr)
	}
	if accepted > 100 || accepted < 90 {
		t.Errorf("accepted %d events before backpressure, want the queue size (100)", accepted)
	}
	if st := s.Stats(); st.Queued != accepted {
		t.Errorf("queued = %d, want %d", st.Queued, accepted)
	}
	tx.Rollback(ctx)
	flush(t, s)
	if n := count(t, s, "SELECT count(*) FROM audit_events"); n != int64(accepted) {
		t.Errorf("rows after release = %d, want %d (nothing accepted may be lost)", n, accepted)
	}
	// And the queue takes events again.
	if err := s.Add(ctx, []audit.Event{ev("after", "ResponseComplete", 200, audittest.Base)}); err != nil {
		t.Errorf("Add after drain: %v", err)
	}
}

func TestPGCloseGivesUpWhenPostgresIsStuck(t *testing.T) {
	ctx := context.Background()
	s := openTest(t, Options{FlushInterval: 5 * time.Millisecond})
	blocker := admin(t)
	tx, err := blocker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, "LOCK TABLE "+pgx.Identifier{s.o.Schema, "audit_events"}.Sanitize()+" IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(ctx, []audit.Event{ev("stuck", "ResponseComplete", 200, audittest.Base)}); err != nil {
		t.Fatal(err)
	}
	cctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = s.Close(cctx)
	if err == nil || time.Since(start) > 10*time.Second {
		t.Fatalf("Close = %v after %s; want a prompt error", err, time.Since(start))
	}
	if st := s.Stats(); st.Dropped != 1 {
		t.Errorf("stats = %+v, want the queued event counted as dropped", st)
	}
	if err := s.Add(ctx, []audit.Event{ev("late", "ResponseComplete", 200, audittest.Base)}); !errors.Is(err, ErrClosed) {
		t.Errorf("Add after Close = %v, want ErrClosed", err)
	}
}

func TestPGLeaderExclusiveAndCommitAtomic(t *testing.T) {
	ctx := context.Background()
	s := openTest(t, Options{})
	l1, ok, err := s.TryLead(ctx, "cloudwatch")
	if err != nil || !ok {
		t.Fatalf("first TryLead = %v, %v", ok, err)
	}
	if _, ok, err := s.TryLead(ctx, "cloudwatch"); err != nil || ok {
		t.Fatalf("second TryLead = %v, %v; want held elsewhere", ok, err)
	}
	other, ok, err := s.TryLead(ctx, "maintenance")
	if err != nil || !ok {
		t.Fatalf("a different name should be free: %v, %v", ok, err)
	}
	other.Release(ctx)

	if pos, err := l1.Checkpoint(ctx, "cw:/aws/eks/x/cluster"); err != nil || pos != nil {
		t.Fatalf("empty checkpoint = %s, %v", pos, err)
	}
	batch := []audit.Event{ev("c1", "ResponseComplete", 200, audittest.Base), ev("c2", "ResponseComplete", 200, audittest.Base)}
	if err := l1.Commit(ctx, batch, "cw:/aws/eks/x/cluster", []byte(`{"windowEnd":"2026-10-10T12:00:00Z"}`)); err != nil {
		t.Fatal(err)
	}
	pos, err := l1.Checkpoint(ctx, "cw:/aws/eks/x/cluster")
	if err != nil || !strings.Contains(string(pos), "2026-10-10T12:00:00Z") {
		t.Fatalf("checkpoint = %s, %v", pos, err)
	}
	// A failing commit (the position is not JSON) writes neither the events
	// nor the checkpoint.
	err = l1.Commit(ctx, []audit.Event{ev("c3", "ResponseComplete", 200, audittest.Base)}, "cw:/aws/eks/x/cluster", []byte(`{not json`))
	if err == nil {
		t.Fatal("commit with an invalid position succeeded")
	}
	if n := count(t, s, "SELECT count(*) FROM audit_events WHERE audit_id = 'c3'"); n != 0 {
		t.Errorf("events of a failed commit were written")
	}
	if pos2, _ := l1.Checkpoint(ctx, "cw:/aws/eks/x/cluster"); string(pos2) != string(pos) {
		t.Errorf("checkpoint moved on a failed commit: %s", pos2)
	}

	// Releasing hands over.
	if err := l1.Release(ctx); err != nil {
		t.Fatal(err)
	}
	if err := l1.Commit(ctx, batch, "x", nil); !errors.Is(err, audit.ErrLeadershipLost) {
		t.Errorf("commit after release = %v, want ErrLeadershipLost", err)
	}
	l2, ok, err := s.TryLead(ctx, "cloudwatch")
	if err != nil || !ok {
		t.Fatalf("TryLead after release = %v, %v", ok, err)
	}
	defer l2.Release(ctx)

	// A leader whose session is killed (failover, network loss) cannot write.
	key := lockKey(s.o.Schema, "lead/cloudwatch")
	var pid int32
	a := admin(t)
	if err := a.QueryRow(ctx, `SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND classid::bigint = $1 AND objid::bigint = $2`,
		int64(uint64(key)>>32), int64(uint64(key)&0xffffffff)).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Exec(ctx, "SELECT pg_terminate_backend($1)", pid); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	err = l2.Commit(ctx, []audit.Event{ev("c4", "ResponseComplete", 200, audittest.Base)}, "cw:/aws/eks/x/cluster", []byte(`{"windowEnd":"later"}`))
	if !errors.Is(err, audit.ErrLeadershipLost) {
		t.Fatalf("commit on a killed session = %v, want ErrLeadershipLost", err)
	}
	select {
	case <-l2.Lost():
	default:
		t.Error("Lost() not closed after the session died")
	}
	if n := count(t, s, "SELECT count(*) FROM audit_events WHERE audit_id = 'c4'"); n != 0 {
		t.Error("a leader without its lock wrote events")
	}
	l3, ok, err := s.TryLead(ctx, "cloudwatch")
	if err != nil || !ok {
		t.Fatalf("lock not free after the holder died: %v, %v", ok, err)
	}
	if pos3, _ := l3.Checkpoint(ctx, "cw:/aws/eks/x/cluster"); string(pos3) != string(pos) {
		t.Errorf("checkpoint = %s, want %s", pos3, pos)
	}
	l3.Release(ctx)
}

func TestPGSummaryCache(t *testing.T) {
	ctx := context.Background()
	s := openTest(t, Options{CacheTTL: time.Hour})
	if err := s.Add(ctx, []audit.Event{ev("a", "ResponseComplete", 200, audittest.Base)}); err != nil {
		t.Fatal(err)
	}
	flush(t, s)
	q := audit.Query{Since: audittest.Base.Add(-time.Hour)}
	first, err := s.Summarize(ctx, q)
	if err != nil || first.TotalEvents != 1 {
		t.Fatalf("summary = %+v, %v", first, err)
	}
	if err := s.Add(ctx, []audit.Event{ev("b", "ResponseComplete", 200, audittest.Base)}); err != nil {
		t.Fatal(err)
	}
	flush(t, s)
	// A rolling window a few seconds later shares the cached aggregation.
	q.Since = q.Since.Add(3 * time.Second)
	if again, _ := s.Summarize(ctx, q); again.TotalEvents != 1 {
		t.Errorf("cached summary = %d events, want the cached 1", again.TotalEvents)
	}
	if other, _ := s.Summarize(ctx, audit.Query{User: "alice"}); other.TotalEvents != 2 {
		t.Errorf("a different query = %d events, want 2", other.TotalEvents)
	}
}

func TestPGOpenIsIdempotentAndConcurrent(t *testing.T) {
	dsn := testDSN(t)
	schema := fmt.Sprintf("kst_concurrent_%04d", rand.Intn(10000))
	t.Cleanup(func() {
		a := admin(t)
		a.Exec(context.Background(), "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
	})
	errs := make(chan error, 4)
	stores := make(chan *Store, 4)
	for i := 0; i < 4; i++ {
		go func() {
			s, err := Open(context.Background(), dsn, Options{Schema: schema, Now: func() time.Time { return audittest.Base }})
			errs <- err
			stores <- s
		}()
	}
	for i := 0; i < 4; i++ {
		if err := <-errs; err != nil {
			t.Error(err)
		}
		if s := <-stores; s != nil {
			s.Close(context.Background())
		}
	}
}
