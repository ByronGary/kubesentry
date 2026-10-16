package alerts_test

import (
	"context"
	"math/rand"
	"reflect"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/alerts"
	"github.com/ByronGary/kubesentry/internal/alerts/alertstest"
)

func TestMemoryStoreLifecycle(t *testing.T) {
	ctx := context.Background()
	s := alerts.NewMemoryStore()
	at := alertstest.Base
	if b, _ := s.Baselines(ctx); len(b) != 0 {
		t.Fatalf("new store has baselines %v", b)
	}
	f := alerts.Finding{Key: "k1", Check: alerts.CheckWorkloadUnhealthy, State: alerts.StateOpen, FirstSeen: at, LastSeen: at.Add(time.Nanosecond)}
	resolvedAt := at.Add(-48 * time.Hour)
	old := alerts.Finding{Key: "k0", State: alerts.StateResolved, FirstSeen: at.Add(-72 * time.Hour), LastSeen: resolvedAt, ResolvedAt: &resolvedAt}
	if err := s.Commit(ctx, alerts.Commit{Findings: []alerts.Finding{f, old}, Baselines: map[string][]string{"cluster-admin": nil, "wildcard-rbac": {"b", "a", "a"}}}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Load(ctx, at.Add(-24*time.Hour))
	if len(got) != 1 || got[0].Key != "k1" || got[0].Labels == nil || !got[0].LastSeen.Equal(at) {
		t.Fatalf("load = %+v", got)
	}
	got[0].Labels["x"] = "mutated" // a copy: the store keeps its own
	if again, _ := s.Load(ctx, at.Add(-24*time.Hour)); again[0].Labels["x"] != "" {
		t.Fatal("Load shares maps with the store")
	}
	if all, _ := s.Load(ctx, time.Time{}); len(all) != 2 || all[0].Key != "k0" {
		t.Fatalf("load all = %+v", all)
	}
	b, _ := s.Baselines(ctx)
	if want := map[string][]string{"cluster-admin": {}, "wildcard-rbac": {"a", "b"}}; !reflect.DeepEqual(b, want) {
		t.Fatalf("baselines = %#v, want %#v", b, want)
	}
	if n, _ := s.Prune(ctx, at.Add(-24*time.Hour)); n != 1 {
		t.Fatalf("pruned %d, want 1", n)
	}
	if all, _ := s.Load(ctx, time.Time{}); len(all) != 1 {
		t.Fatalf("after prune = %+v", all)
	}
}

// The actions log: IDs in order, times as Postgres keeps them, reads after
// an ID, pruning a day past the findings' cutoff; digest runs by name.
func TestMemoryStoreActionsAndDigestRuns(t *testing.T) {
	ctx := context.Background()
	s := alerts.NewMemoryStore()
	at := alertstest.Base.Add(123 * time.Nanosecond)
	until := at.Add(time.Hour)
	first, err := s.AddAction(ctx, alerts.Action{Key: "k1", FirstSeen: at, Action: alerts.ActionSilence, Actor: "bob", Reason: "r", Until: &until, Severity: "warning", At: at})
	if err != nil || first.ID != 1 || !first.At.Equal(alertstest.Base) || !first.Until.Equal(alertstest.Base.Add(time.Hour)) || !first.FirstSeen.Equal(alertstest.Base) {
		t.Fatalf("first = %+v, %v", first, err)
	}
	if _, err := s.AddAction(ctx, alerts.Action{Key: "k1", Action: "delete"}); err == nil {
		t.Fatal("an unknown action was stored")
	}
	second, _ := s.AddAction(ctx, alerts.Action{Key: "k2", Action: alerts.ActionAck, Actor: "alice", Severity: "critical"})
	if second.ID != 2 || second.At.IsZero() {
		t.Fatalf("second = %+v", second)
	}
	if got, _ := s.Actions(ctx, 1); len(got) != 1 || got[0].Key != "k2" {
		t.Fatalf("after 1 = %+v", got)
	}
	got, _ := s.Actions(ctx, 0)
	*got[0].Until = time.Time{} // a copy: the store keeps its own
	if again, _ := s.Actions(ctx, 0); len(again) != 2 || !again[0].Until.Equal(alertstest.Base.Add(time.Hour)) {
		t.Fatalf("all = %+v", again)
	}
	// Prune(before) deletes actions taken a day before before.
	if n, _ := s.Prune(ctx, alertstest.Base.Add(24*time.Hour)); n != 0 {
		t.Fatalf("pruned %d within the day", n)
	}
	if n, _ := s.Prune(ctx, second.At.Add(25*time.Hour)); n != 2 {
		t.Fatalf("pruned %d, want 2", n)
	}
	if got, _ := s.Actions(ctx, 0); len(got) != 0 {
		t.Fatalf("left %+v", got)
	}
	if third, _ := s.AddAction(ctx, alerts.Action{Key: "k3", Action: alerts.ActionAck}); third.ID != 3 {
		t.Fatalf("IDs are reused: %+v", third)
	}

	if runs, _ := s.DigestRuns(ctx); len(runs) != 0 {
		t.Fatalf("runs = %v", runs)
	}
	if err := s.Commit(ctx, alerts.Commit{DigestRuns: map[string]time.Time{"certificates": at}}); err != nil {
		t.Fatal(err)
	}
	if runs, _ := s.DigestRuns(ctx); !runs["certificates"].Equal(alertstest.Base) || len(runs) != 1 {
		t.Fatalf("runs = %v", runs)
	}
	if (alerts.Commit{DigestRuns: map[string]time.Time{"x": at}}).Empty() {
		t.Error("a commit with digest runs is not empty")
	}
}

// The random operations the Postgres parity test uses run cleanly on the
// memory store, and two memory stores agree (the generator is deterministic).
func TestMemoryStoreRandomOps(t *testing.T) {
	ctx := context.Background()
	a, b := alerts.NewMemoryStore(), alerts.NewMemoryStore()
	r1, r2 := rand.New(rand.NewSource(7)), rand.New(rand.NewSource(7))
	for i := 0; i < 200; i++ {
		if err := a.Commit(ctx, alertstest.Commit(r1, i)); err != nil {
			t.Fatal(err)
		}
		_ = b.Commit(ctx, alertstest.Commit(r2, i))
	}
	la, _ := a.Load(ctx, alertstest.Base)
	lb, _ := b.Load(ctx, alertstest.Base)
	if len(la) == 0 || !reflect.DeepEqual(la, lb) {
		t.Fatalf("stores disagree or are empty: %d vs %d", len(la), len(lb))
	}
}
