package pgstore

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/incidents"
	"github.com/ByronGary/kubesentry/internal/incidents/incidentstest"
	"github.com/ByronGary/kubesentry/internal/model"
)

// TestPGIncidentsMatchMemory is the incident store's parity test: the same
// random commits against incidents.MemoryStore and the Postgres store list,
// get and load the same incidents and signals, keep the same checkpoints,
// and prune the same rows.
func TestPGIncidentsMatchMemory(t *testing.T) {
	testDSN(t)
	ctx := context.Background()
	for seed := int64(1); seed <= 3; seed++ {
		t.Run(fmt.Sprint("seed", seed), func(t *testing.T) {
			rng := rand.New(rand.NewSource(seed))
			mem := incidents.NewMemoryStore()
			pg := openTest(t, Options{}).Incidents()
			ids := map[string]bool{}
			nonEmpty := 0
			for step := 0; step < 150; step++ {
				c := incidentstest.Commit(rng, step)
				for _, in := range c.Incidents {
					ids[in.ID] = true
				}
				if err := mem.Commit(ctx, c); err != nil {
					t.Fatal(err)
				}
				if err := pg.Commit(ctx, c); err != nil {
					t.Fatalf("step %d: %v", step, err)
				}
				for k := 0; k < 3; k++ {
					q := incidentstest.Query(rng, step)
					if compareLists(t, mem, pg, q) > 0 {
						nonEmpty++
					}
					if q.Limit > 0 {
						// Page on from the last one, as the API does.
						page, _ := mem.List(ctx, q)
						if len(page) > 0 {
							q.Before = incidents.CursorOf(&page[len(page)-1])
							compareLists(t, mem, pg, q)
						}
					}
				}
				if step%10 != 9 {
					continue
				}
				compareIncidents(t, mem, pg, ids)
				if step%50 == 49 {
					before := incidentstest.Base.Add(time.Duration(rng.Intn(48*60)) * time.Minute)
					mn, _ := mem.Prune(ctx, before)
					pn, err := pg.Prune(ctx, before)
					if err != nil || mn != pn {
						t.Fatalf("prune before %s: memory %d, postgres %d (%v)", before, mn, pn, err)
					}
				}
			}
			compareIncidents(t, mem, pg, ids)
			if nonEmpty < 100 {
				t.Errorf("only %d of 450 queries found anything: the test checks too little", nonEmpty)
			}
		})
	}
}

func compareLists(t *testing.T, mem, pg incidents.Store, q incidents.Query) int {
	t.Helper()
	ctx := context.Background()
	want, _ := mem.List(ctx, q)
	got, err := pg.List(ctx, q)
	if err != nil {
		t.Fatalf("list %+v: %v", q, err)
	}
	if !reflect.DeepEqual(got, want) {
		for i := range want {
			if i >= len(got) || !reflect.DeepEqual(got[i], want[i]) {
				var g any = "nothing"
				if i < len(got) {
					g = got[i]
				}
				t.Fatalf("list %+v: %d vs %d incidents; first difference at %d:\npostgres %+v\nmemory   %+v", q, len(got), len(want), i, g, want[i])
			}
		}
		t.Fatalf("list %+v: postgres has %d incidents, memory %d", q, len(got), len(want))
	}
	return len(got)
}

func compareIncidents(t *testing.T, mem, pg incidents.Store, ids map[string]bool) {
	t.Helper()
	ctx := context.Background()
	keys := make([]string, 0, len(ids))
	for id := range ids {
		keys = append(keys, id)
	}
	sort.Strings(keys)
	for _, id := range keys {
		wi, ws, wok, _ := mem.Get(ctx, id)
		gi, gs, gok, err := pg.Get(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if wok != gok || !reflect.DeepEqual(gi, wi) {
			t.Fatalf("get %s: postgres %v %+v\nmemory %v %+v", id, gok, gi, wok, wi)
		}
		if !reflect.DeepEqual(gs, ws) {
			for i := range ws {
				if i >= len(gs) || !reflect.DeepEqual(gs[i], ws[i]) {
					var g any = "nothing"
					if i < len(gs) {
						g = gs[i]
					}
					t.Fatalf("signals of %s differ at %d:\npostgres %+v\nmemory   %+v", id, i, g, ws[i])
				}
			}
			t.Fatalf("signals of %s: postgres %d, memory %d", id, len(gs), len(ws))
		}
	}
	wo, wsig, _ := mem.LoadOpen(ctx)
	gotOpen, gsig, err := pg.LoadOpen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotOpen, wo) || !reflect.DeepEqual(gsig, wsig) {
		t.Fatalf("load open: postgres %d incidents %d with signals, memory %d %d", len(gotOpen), len(gsig), len(wo), len(wsig))
	}
	for _, src := range []string{"incidents/audit", "incidents/cloudtrail", "none"} {
		w, _ := mem.Checkpoint(ctx, src)
		g, err := pg.Checkpoint(ctx, src)
		if err != nil || string(g) != string(w) || (g == nil) != (w == nil) {
			t.Fatalf("checkpoint %s: postgres %q (%v), memory %q", src, g, err, w)
		}
	}
	if sl, ok := pg.(incidents.SignalsLoader); ok {
		all, err := sl.SignalsOf(ctx, keys)
		if err != nil {
			t.Fatal(err)
		}
		want, _ := mem.(incidents.SignalsLoader).SignalsOf(ctx, keys)
		if !reflect.DeepEqual(all, want) {
			t.Fatalf("signals of: postgres %d, memory %d", len(all), len(want))
		}
	}
}

// TestPGEventsMatchMemory is the event store's parity test: random batches
// upserted into both stores (UIDs repeat, reports arrive out of order) give
// the same answers to random queries, and prune the same rows.
func TestPGEventsMatchMemory(t *testing.T) {
	testDSN(t)
	ctx := context.Background()
	for seed := int64(1); seed <= 3; seed++ {
		t.Run(fmt.Sprint("seed", seed), func(t *testing.T) {
			rng := rand.New(rand.NewSource(seed))
			mem := incidents.NewMemoryEventStore()
			pg := openTest(t, Options{Now: func() time.Time { return incidentstest.Base }}).KubeEvents()
			nonEmpty := 0
			for step := 0; step < 120; step++ {
				var batch []incidents.StoredEvent
				for n := rng.Intn(8); n > 0; n-- {
					// Some reports are older than what is stored: they lose.
					batch = append(batch, incidentstest.Event(rng, step-rng.Intn(30)))
				}
				if err := mem.AddEvents(ctx, batch); err != nil {
					t.Fatal(err)
				}
				if err := pg.AddEvents(ctx, batch); err != nil {
					t.Fatalf("step %d: %v", step, err)
				}
				for k := 0; k < 3; k++ {
					q := incidentstest.EventQuery(rng, step)
					want, _ := mem.Events(ctx, q)
					got, err := pg.Events(ctx, q)
					if err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("step %d, events %+v:\npostgres %d %+v\nmemory   %d %+v", step, q, len(got), got, len(want), want)
					}
					if len(got) > 0 {
						nonEmpty++
					}
				}
				if step%40 == 39 {
					before := incidentstest.Base.Add(time.Duration(step-rng.Intn(60)) * time.Minute)
					mn, _ := mem.PruneEvents(ctx, before)
					pn, err := pg.PruneEvents(ctx, before)
					if err != nil || mn != pn {
						t.Fatalf("prune before %s: memory %d, postgres %d (%v)", before, mn, pn, err)
					}
				}
			}
			want, _ := mem.Events(ctx, incidents.EventQuery{})
			got, _ := pg.Events(ctx, incidents.EventQuery{})
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("all events: postgres %d, memory %d", len(got), len(want))
			}
			if nonEmpty < 60 {
				t.Errorf("only %d of 360 queries found anything: the test checks too little", nonEmpty)
			}
		})
	}
}

// An event series whose first time moved (the producer keeps it within a
// day of the last) moves partitions instead of being stored twice.
func TestPGEventFirstSeenMoves(t *testing.T) {
	ctx := context.Background()
	s := openTest(t, Options{Now: func() time.Time { return incidentstest.Base }})
	ev := func(first, last time.Time, count int32) incidents.StoredEvent {
		return incidents.StoredEvent{KubeEvent: model.KubeEvent{UID: "u", Namespace: "shop", Type: "Warning", Reason: "BackOff", Count: count,
			FirstSeen: first, LastSeen: last, Regarding: model.ObjectRef{Kind: "Pod", Namespace: "shop", Name: "api-1"}}}
	}
	b := incidentstest.Base
	for _, e := range []incidents.StoredEvent{ev(b.Add(-30*time.Hour), b.Add(-6*time.Hour), 10), ev(b.Add(-20*time.Hour), b.Add(4*time.Hour), 90),
		ev(b.Add(-30*time.Hour), b.Add(-time.Hour), 50)} { // the last one is older news
		if err := s.KubeEvents().AddEvents(ctx, []incidents.StoredEvent{e}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.KubeEvents().Events(ctx, incidents.EventQuery{})
	if err != nil || len(got) != 1 || got[0].Count != 90 || !got[0].FirstSeen.Equal(b.Add(-20*time.Hour)) {
		t.Fatalf("events = %+v, %v", got, err)
	}
	if n := count(t, s, "SELECT count(*) FROM k8s_events WHERE uid = 'u'"); n != 1 {
		t.Errorf("%d rows for one uid", n)
	}
}

// Maintain keeps k8s_events partitions as it does audit_events', and
// prunes events and incidents past their retention.
func TestPGMaintainEventsAndIncidents(t *testing.T) {
	ctx := context.Background()
	var now atomic.Pointer[time.Time]
	base := incidentstest.Base
	now.Store(&base)
	s := openTest(t, Options{EventsRetention: 48 * time.Hour, IncidentRetention: 7 * 24 * time.Hour,
		Now: func() time.Time { return *now.Load() }})
	day := func(d int) time.Time { return base.Truncate(24*time.Hour).AddDate(0, 0, d) }
	parts := func() []string {
		rows, _ := s.pool.Query(ctx, `SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
JOIN pg_class p ON p.oid = i.inhparent JOIN pg_namespace n ON n.oid = p.relnamespace
WHERE p.relname = 'k8s_events' AND n.nspname = $1 ORDER BY 1`, s.o.Schema)
		names, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatal(err)
		}
		return names
	}
	ev := func(uid string, first time.Time) incidents.StoredEvent {
		return incidents.StoredEvent{KubeEvent: model.KubeEvent{UID: uid, Type: "Warning", Reason: "BackOff", FirstSeen: first, LastSeen: first.Add(time.Minute)}}
	}
	name := func(d int) string { return "k8s_events_" + day(d).Format("20060102") }
	want := []string{name(-1), name(0), name(1), name(2), name(3), "k8s_events_default"}
	if got := parts(); !reflect.DeepEqual(got, want) {
		t.Fatalf("after Open: %v, want %v", got, want)
	}
	// Events from before the partitions land in the default partition;
	// Maintain moves them into one of their own.
	if err := s.KubeEvents().AddEvents(ctx, []incidents.StoredEvent{ev("old", day(-2).Add(time.Hour)), ev("new", base)}); err != nil {
		t.Fatal(err)
	}
	res, err := s.MaintainReport(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(res.KubeEvents.Created, []string{name(-2)}) || res.KubeEvents.Moved != 1 || res.KubeEvents.DefaultRows != 0 ||
		len(res.Created) != 0 {
		t.Fatalf("maintain = %+v", res)
	}
	// Incidents: one resolved long ago, one open.
	end := base.Add(-8 * 24 * time.Hour)
	old := incidents.Incident{ID: "old", Subject: incidents.Subject{Kind: "Deployment", Namespace: "shop", Name: "api"}, State: incidents.Resolved,
		Start: end.Add(-time.Hour), End: &end, LastSignal: end, Severity: incidents.Warning, PeakSeverity: incidents.Warning}
	open := old
	open.ID, open.State, open.End = "open", incidents.Open, nil
	if err := s.Incidents().Commit(ctx, incidents.Commit{Incidents: []incidents.Incident{old, open},
		Signals: map[string][]incidents.Signal{"old": {{ID: "s", Type: incidents.TypeDeploy, Start: end}}}}); err != nil {
		t.Fatal(err)
	}
	// Four days on: the old events' partitions are past 48h + a day.
	later := base.AddDate(0, 0, 4)
	now.Store(&later)
	res, err = s.MaintainReport(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(res.KubeEvents.Dropped, []string{name(-2), name(-1), name(0)}) || res.IncidentsPruned != 1 || res.EventsPruned != 0 {
		t.Errorf("four days on: %+v", res)
	}
	if n := count(t, s, "SELECT count(*) FROM incident_signals"); n != 0 {
		t.Errorf("signals of the pruned incident left: %d", n)
	}
	if got, _ := s.Incidents().List(ctx, incidents.Query{}); len(got) != 1 || got[0].ID != "open" {
		t.Errorf("incidents left: %+v", got)
	}
}

// A leader's incident store writes only while the lock is held.
func TestPGIncidentsCommitNeedsTheLock(t *testing.T) {
	ctx := context.Background()
	s := openTest(t, Options{})
	lease, ok, err := s.IncidentElector()(ctx)
	if err != nil || !ok {
		t.Fatalf("lead: %v %v", ok, err)
	}
	l := lease.(IncidentLease).Leader
	defer l.Release(ctx)
	rng := rand.New(rand.NewSource(1))
	in := incidentstest.Incident(rng, 0)
	if err := lease.Store().Commit(ctx, incidents.Commit{Incidents: []incidents.Incident{in}}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.IncidentElector()(ctx); ok {
		t.Fatal("a second session took a held lock")
	}
	var pid int
	l.mu.Lock()
	err = l.conn.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pid)
	l.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin(t).Exec(ctx, "SELECT pg_terminate_backend($1)", pid); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	other := incidentstest.Incident(rng, 1)
	other.ID = "written-after-the-lock-was-lost"
	err = lease.Store().Commit(ctx, incidents.Commit{Incidents: []incidents.Incident{other}})
	if !errors.Is(err, audit.ErrLeadershipLost) {
		t.Fatalf("commit after losing the lock = %v, want ErrLeadershipLost", err)
	}
	select {
	case <-lease.Lost():
	default:
		t.Fatal("Lost not closed")
	}
	got, err := s.Incidents().List(ctx, incidents.Query{})
	if err != nil || len(got) != 1 || got[0].ID != in.ID {
		t.Fatalf("store holds %+v (%v), want only the leader's incident", got, err)
	}
}

// The engine and runner work against Postgres as they do in memory: a
// leader commits, a follower's board reads the same.
func TestPGEngineRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := openTest(t, Options{})
	clock := incidentstest.Base
	o := incidents.Options{Now: func() time.Time { return clock }}
	board := incidents.NewBoard(0)
	eng := incidents.NewEngine(s.Incidents(), board, o)
	if err := eng.Load(ctx); err != nil {
		t.Fatal(err)
	}
	subj := incidents.Subject{Kind: "Deployment", Namespace: "shop", Name: "api"}
	eng.Add(incidents.Signal{ID: "req", Type: incidents.TypeRequestSpike, Source: incidents.SourceMetrics, Role: incidents.Trigger,
		Severity: incidents.Critical, Start: clock, Subject: subj, Title: "x4"})
	eng.SetCheckpoint(incidents.CheckpointAudit, []byte(`{"time":"x"}`))
	eng.Tick()
	if err := eng.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	r, err := incidents.NewRunner(incidents.Config{Store: s.Incidents(), Options: o})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Refresh(ctx, s.Incidents(), false); err != nil {
		t.Fatal(err)
	}
	lead, _ := board.Snapshot()
	follow, _ := r.Board().Snapshot()
	if len(lead) != 1 || !reflect.DeepEqual(lead, follow) {
		t.Fatalf("leader board %+v\nfollower board %+v", lead, follow)
	}
	ls, _ := board.Signals(lead[0].ID)
	fs, _ := r.Board().Signals(lead[0].ID)
	if !reflect.DeepEqual(ls, fs) {
		t.Fatalf("signals: leader %+v follower %+v", ls, fs)
	}
	if cp, _ := s.Incidents().Checkpoint(ctx, incidents.CheckpointAudit); string(cp) != `{"time":"x"}` {
		t.Errorf("checkpoint %s", cp)
	}
}
