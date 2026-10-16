package pgstore

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/alerts"
	"github.com/ByronGary/kubesentry/internal/alerts/alertstest"
	"github.com/ByronGary/kubesentry/internal/audit"
)

// TestPGAlertsMatchMemory is the alert store's parity test: the same random
// commits and actions against alerts.MemoryStore and the Postgres store load
// the same findings (link and quiet included), baselines, actions and
// digest runs, and prune the same rows.
func TestPGAlertsMatchMemory(t *testing.T) {
	testDSN(t)
	ctx := context.Background()
	for seed := int64(1); seed <= 3; seed++ {
		t.Run(fmt.Sprint("seed", seed), func(t *testing.T) {
			rng := rand.New(rand.NewSource(seed))
			mem := alerts.NewMemoryStore()
			pg := openTest(t, Options{}).Alerts()
			for step := 0; step < 150; step++ {
				c := alertstest.Commit(rng, step)
				if err := mem.Commit(ctx, c); err != nil {
					t.Fatal(err)
				}
				if err := pg.Commit(ctx, c); err != nil {
					t.Fatalf("step %d: %v", step, err)
				}
				for n := rng.Intn(3); n > 0; n-- {
					a := alertstest.Action(rng, alertstest.Base.Add(time.Duration(step)*time.Minute))
					ma, err := mem.AddAction(ctx, a)
					if err != nil {
						t.Fatal(err)
					}
					pa, err := pg.AddAction(ctx, a)
					if err != nil {
						t.Fatalf("step %d: add action: %v", step, err)
					}
					if !reflect.DeepEqual(pa, ma) {
						t.Fatalf("step %d: added\npostgres %+v\nmemory   %+v", step, pa, ma)
					}
				}
				if step%10 != 9 {
					continue
				}
				since := alertstest.Base.Add(time.Duration(step-rng.Intn(48*60)) * time.Minute)
				compareAlerts(t, mem, pg, since)
				compareActions(t, mem, pg, int64(rng.Intn(step+1)))
				if step%50 == 49 {
					before := alertstest.Base.Add(time.Duration(step-rng.Intn(24*60)) * time.Minute)
					mn, _ := mem.Prune(ctx, before)
					pn, err := pg.Prune(ctx, before)
					if err != nil || mn != pn {
						t.Fatalf("prune before %s: memory %d, postgres %d (%v)", before, mn, pn, err)
					}
				}
			}
			compareAlerts(t, mem, pg, time.Time{})
			compareActions(t, mem, pg, 0)
		})
	}
}

func compareActions(t *testing.T, mem, pg alerts.Store, after int64) {
	t.Helper()
	ctx := context.Background()
	want, _ := mem.Actions(ctx, after)
	got, err := pg.Actions(ctx, after)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("actions after %d:\npostgres %+v\nmemory   %+v", after, got, want)
	}
	wr, _ := mem.DigestRuns(ctx)
	gr, err := pg.DigestRuns(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gr, wr) {
		t.Fatalf("digest runs:\npostgres %v\nmemory   %v", gr, wr)
	}
}

// Actions go through the pool, whoever holds the alerts lock: the leader's
// store adds them without the lock's connection, and a store without the
// lock adds them while another session holds it.
func TestPGAlertActionsAnyReplica(t *testing.T) {
	ctx := context.Background()
	s := openTest(t, Options{})
	l, ok, err := s.TryLead(ctx, "alerts")
	if err != nil || !ok {
		t.Fatalf("lead: %v %v", ok, err)
	}
	defer l.Release(ctx)
	if _, err := l.Alerts().AddAction(ctx, alerts.Action{Key: "a/b/c/d", Action: alerts.ActionAck, Actor: "x", Severity: "warning", At: alertstest.Base}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Alerts().AddAction(ctx, alerts.Action{Key: "a/b/c/d", Action: alerts.ActionUnack, Actor: "y", Severity: "warning"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Alerts().AddAction(ctx, alerts.Action{Key: "a/b/c/d", Action: "delete"}); err == nil {
		t.Fatal("an unknown action was stored")
	}
	got, err := s.Alerts().Actions(ctx, 0)
	if err != nil || len(got) != 2 || got[0].Actor != "x" || got[1].Actor != "y" || got[1].At.IsZero() || got[0].ID >= got[1].ID {
		t.Fatalf("actions = %+v, %v", got, err)
	}
}

func compareAlerts(t *testing.T, mem, pg alerts.Store, since time.Time) {
	t.Helper()
	ctx := context.Background()
	want, _ := mem.Load(ctx, since)
	got, err := pg.Load(ctx, since)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		for i := range want {
			if i >= len(got) || !reflect.DeepEqual(got[i], want[i]) {
				var g any = "nothing"
				if i < len(got) {
					g = got[i]
				}
				t.Fatalf("load since %s: %d vs %d findings; first difference at %d:\npostgres %+v\nmemory   %+v", since, len(got), len(want), i, g, want[i])
			}
		}
		t.Fatalf("load since %s: postgres has %d findings, memory %d", since, len(got), len(want))
	}
	wb, _ := mem.Baselines(ctx)
	gb, err := pg.Baselines(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gb, wb) {
		t.Fatalf("baselines:\npostgres %#v\nmemory   %#v", gb, wb)
	}
}

// A leader's alert store writes only while the lock is held: after another
// session takes the lock over, its commit fails with ErrLeadershipLost and
// writes nothing.
func TestPGAlertsCommitNeedsTheLock(t *testing.T) {
	ctx := context.Background()
	s := openTest(t, Options{})
	l, ok, err := s.TryLead(ctx, "alerts")
	if err != nil || !ok {
		t.Fatalf("lead: %v %v", ok, err)
	}
	defer l.Release(ctx)
	f := alertstest.Finding(rand.New(rand.NewSource(1)), alertstest.Base)
	if err := l.Alerts().Commit(ctx, alerts.Commit{Findings: []alerts.Finding{f}, Baselines: map[string][]string{"cluster-admin": {"x"}}}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.TryLead(ctx, "alerts"); ok {
		t.Fatal("a second session took a held lock")
	}

	// The lock's session ends (as when Postgres fails over or the
	// connection drops): the next commit must notice.
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
	g := f
	g.Key, g.Title = "other", "written by a replica that lost the lock"
	err = l.Alerts().Commit(ctx, alerts.Commit{Findings: []alerts.Finding{g}})
	if !errors.Is(err, audit.ErrLeadershipLost) {
		t.Fatalf("commit after losing the lock = %v, want ErrLeadershipLost", err)
	}
	select {
	case <-l.Lost():
	default:
		t.Fatal("Lost not closed")
	}
	got, err := s.Alerts().Load(ctx, time.Time{})
	if err != nil || len(got) != 1 || got[0].Key != f.Key {
		t.Fatalf("store holds %+v (%v), want only the leader's finding", got, err)
	}
	if b, _ := s.Alerts().Baselines(ctx); !reflect.DeepEqual(b, map[string][]string{"cluster-admin": {"x"}}) {
		t.Fatalf("baselines = %v", b)
	}
}

// The maintenance loop deletes findings resolved more than alerts.Retention
// ago and keeps the rest.
func TestPGMaintainPrunesResolvedAlerts(t *testing.T) {
	ctx := context.Background()
	now := alertstest.Base
	s := openTest(t, Options{Now: func() time.Time { return now }})
	old, recent := now.Add(-alerts.Retention-time.Hour), now.Add(-alerts.Retention+time.Hour)
	fs := []alerts.Finding{
		{Key: "old", Alert: "a", Check: "c", Kind: "k", Name: "n", Severity: "warning", Title: "t", Owner: "o", State: alerts.StateResolved, FirstSeen: old, LastSeen: old, ResolvedAt: &old},
		{Key: "recent", Alert: "a", Check: "c", Kind: "k", Name: "n", Severity: "warning", Title: "t", Owner: "o", State: alerts.StateResolved, FirstSeen: old, LastSeen: recent, ResolvedAt: &recent},
		{Key: "open", Alert: "a", Check: "c", Kind: "k", Name: "n", Severity: "warning", Title: "t", Owner: "o", State: alerts.StateOpen, FirstSeen: old, LastSeen: now},
	}
	if err := s.Alerts().Commit(ctx, alerts.Commit{Findings: fs}); err != nil {
		t.Fatal(err)
	}
	// Actions are kept a day longer than resolved findings.
	for _, at := range []time.Time{now.Add(-alerts.Retention - 25*time.Hour), now.Add(-alerts.Retention - 23*time.Hour)} {
		if _, err := s.Alerts().AddAction(ctx, alerts.Action{Key: "open", Action: alerts.ActionAck, Actor: "a", Severity: "warning", At: at}); err != nil {
			t.Fatal(err)
		}
	}
	res, err := s.MaintainReport(ctx)
	if err != nil || res.AlertsPruned != 2 {
		t.Fatalf("maintain = %+v, %v; want 1 finding and 1 action pruned", res, err)
	}
	got, _ := s.Alerts().Load(ctx, time.Time{})
	if len(got) != 2 || got[0].Key != "open" || got[1].Key != "recent" {
		t.Fatalf("left %+v", got)
	}
	if acts, _ := s.Alerts().Actions(ctx, 0); len(acts) != 1 || acts[0].ID != 2 {
		t.Fatalf("actions left %+v", acts)
	}
}
