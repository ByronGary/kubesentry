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
