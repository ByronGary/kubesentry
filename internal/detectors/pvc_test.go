package detectors

import (
	"math"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
)

func TestFindUnusedPVCs(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	old := now.Add(-72 * time.Hour)
	fresh := now.Add(-1 * time.Hour)
	g := int64(1 << 30)

	pvcs := []model.PVC{
		{Namespace: "app", Name: "data-used", StorageClass: "gp3", Phase: "Bound", CapacityBytes: 10 * g, Created: old},
		{Namespace: "app", Name: "data-orphan", StorageClass: "gp3", Phase: "Bound", CapacityBytes: 100 * g, Created: old},
		{Namespace: "app", Name: "data-fresh", StorageClass: "gp3", Phase: "Bound", CapacityBytes: 50 * g, Created: fresh},
		{Namespace: "app", Name: "waiting", StorageClass: "gp3", Phase: "Pending", Created: old},
		{Namespace: "app", Name: "held-by-done-pod", StorageClass: "io2", Phase: "Bound", CapacityBytes: 20 * g, Created: old},
		{Namespace: "other", Name: "data-used", StorageClass: "gp3", Phase: "Bound", CapacityBytes: 5 * g, Created: old},
	}
	pods := []model.Pod{
		{Namespace: "app", Name: "web-0", Phase: "Running", Claims: []string{"data-used"}},
		{Namespace: "app", Name: "job-1", Phase: "Succeeded", Claims: []string{"held-by-done-pod"}},
	}
	opts := PVCOptions{
		MinAge:                  24 * time.Hour,
		PricePerGiBMonth:        map[string]float64{"gp3": 0.08},
		DefaultPricePerGiBMonth: 0.10,
	}

	got := FindUnusedPVCs(pvcs, pods, now, opts)

	// Expect: data-orphan (100GiB*0.08=8.00), held-by-done-pod (20*0.10=2.00),
	// other/data-used (same name as a used PVC, but different namespace; 5*0.08=0.40).
	want := []struct {
		ns, name string
		cost     float64
	}{
		{"app", "data-orphan", 8.00},
		{"app", "held-by-done-pod", 2.00},
		{"other", "data-used", 0.40},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d results %+v, want %d", len(got), got, len(want))
	}
	for i, w := range want {
		if got[i].Namespace != w.ns || got[i].Name != w.name {
			t.Errorf("result %d = %s/%s, want %s/%s", i, got[i].Namespace, got[i].Name, w.ns, w.name)
		}
		if math.Abs(got[i].EstMonthlyCostUSD-w.cost) > 1e-9 {
			t.Errorf("%s cost = %v, want %v", w.name, got[i].EstMonthlyCostUSD, w.cost)
		}
	}
	if math.Abs(got[0].AgeHours-72) > 1e-9 {
		t.Errorf("age hours = %v, want 72", got[0].AgeHours)
	}
}

func TestFindUnusedPVCsEmptyIsNonNil(t *testing.T) {
	got := FindUnusedPVCs(nil, nil, time.Now(), PVCOptions{})
	if got == nil {
		t.Fatal("want empty non-nil slice so JSON encodes as []")
	}
}
