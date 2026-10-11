package detectors

import (
	"strings"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
)

func TestSummarizeStorageClaims(t *testing.T) {
	g := int64(1 << 30)
	old := podNow.Add(-48 * time.Hour)
	classes := []model.StorageClass{
		{Name: "gp3", BindingMode: "WaitForFirstConsumer", Default: true},
		{Name: "fast", BindingMode: "Immediate"},
	}
	pods := []model.Pod{
		{Namespace: "app", Name: "db-0", Phase: "Running", Claims: []string{"data", "data"}},
		{Namespace: "app", Name: "db-1", Phase: "Running", Claims: []string{"shared"}},
		{Namespace: "app", Name: "db-2", Phase: "Pending", Claims: []string{"shared", "wait-used"}},
		{Namespace: "app", Name: "done", Phase: "Succeeded", Claims: []string{"orphan"}},
	}
	cases := []struct {
		pvc    model.PVC
		status string
		detail string
		users  int
	}{
		{model.PVC{Name: "data", Phase: "Bound", StorageClass: "gp3", CapacityBytes: 10 * g}, StatusOK, "Mounted by db-0.", 1},
		{model.PVC{Name: "shared", Phase: "Bound", StorageClass: "gp3", CapacityBytes: 5 * g}, StatusOK, "Mounted by 2 pods.", 2},
		{model.PVC{Name: "orphan", Phase: "Bound", StorageClass: "fast", CapacityBytes: g}, StatusWarn, "Not mounted by any running pod.", 0},
		{model.PVC{Name: "lost", Phase: "Lost", StorageClass: "gp3", VolumeName: "pv-9"}, StatusCrit, "Lost its volume pv-9; the data may be gone.", 0},
		{model.PVC{Name: "typo", Phase: "Pending", StorageClass: "gp2"}, StatusCrit, "Storage class gp2 does not exist.", 0},
		// Static volumes often name a class that was never created; once bound that is fine.
		{model.PVC{Name: "static", Phase: "Bound", StorageClass: "manual", CapacityBytes: g}, StatusWarn, "Not mounted by any running pod.", 0},
		{model.PVC{Name: "wait", Phase: "Pending", StorageClass: "gp3"}, StatusOK, "Waiting for its first pod (WaitForFirstConsumer).", 0},
		{model.PVC{Name: "wait-used", Phase: "Pending", StorageClass: "gp3"}, StatusWarn, "Pending for 2d.", 1},
		{model.PVC{Name: "slow", Phase: "Pending", StorageClass: "fast"}, StatusWarn, "Pending for 2d.", 0},
		{model.PVC{Name: "new", Phase: "Pending", StorageClass: "fast", Created: podNow.Add(-time.Minute)}, StatusOK, "Being provisioned.", 0},
	}
	for _, c := range cases {
		c.pvc.Namespace = "app"
		if c.pvc.Created.IsZero() {
			c.pvc.Created = old
		}
		claims, _, _ := SummarizeStorage([]model.PVC{c.pvc}, nil, classes, pods, podNow)
		got := claims[0]
		if got.Status != c.status || got.Detail != c.detail || len(got.UsedBy) != c.users || got.UsedBy == nil {
			t.Errorf("%s: got %s %q used by %v, want %s %q used by %d", c.pvc.Name, got.Status, got.Detail, got.UsedBy, c.status, c.detail, c.users)
		}
	}
}

func TestSummarizeStorageVolumesAndClasses(t *testing.T) {
	g := int64(1 << 30)
	pvcs := []model.PVC{
		{Namespace: "app", Name: "a", Phase: "Bound", StorageClass: "gp3", CapacityBytes: 10 * g},
		{Namespace: "app", Name: "b", Phase: "Bound", StorageClass: "gp3", CapacityBytes: 5 * g},
		{Namespace: "app", Name: "c", Phase: "Bound", StorageClass: "io2", CapacityBytes: 100 * g},
	}
	pvs := []model.PV{
		{Name: "pv-a", Phase: "Bound", ReclaimPolicy: "Delete", ClaimNamespace: "app", ClaimName: "a"},
		{Name: "pv-old", Phase: "Released", ReclaimPolicy: "Retain", ClaimNamespace: "app", ClaimName: "gone"},
		{Name: "pv-del", Phase: "Released", ReclaimPolicy: "Delete"},
		{Name: "pv-bad", Phase: "Failed", ReclaimPolicy: "Recycle"},
		{Name: "pv-free", Phase: "Available", ReclaimPolicy: "Retain"},
	}
	classes := []model.StorageClass{{Name: "io2"}, {Name: "zzz"}, {Name: "gp3", Default: true}}

	claims, volumes, cls := SummarizeStorage(pvcs, pvs, classes, nil, podNow)
	if len(claims) != 3 {
		t.Fatalf("claims = %+v", claims)
	}

	var order []string
	for _, v := range volumes {
		order = append(order, v.Name+"="+v.Status)
	}
	if got := strings.Join(order, " "); got != "pv-bad=crit pv-del=warn pv-old=warn pv-a=ok pv-free=ok" {
		t.Errorf("volumes = %s", got)
	}
	by := map[string]VolumeSummary{}
	for _, v := range volumes {
		by[v.Name] = v
	}
	if v := by["pv-old"]; v.Claim != "app/gone" || !strings.Contains(v.Detail, "Retain") || !strings.Contains(v.Detail, "costs money") {
		t.Errorf("released retained volume = %+v", v)
	}
	if v := by["pv-a"]; v.Detail != "Bound to app/a." {
		t.Errorf("bound volume = %+v", v)
	}
	if v := by["pv-free"]; v.Detail != "Available, unclaimed." || v.Claim != "" {
		t.Errorf("available volume = %+v", v)
	}

	if len(cls) != 3 || cls[0].Name != "gp3" || cls[1].Name != "io2" || cls[2].Name != "zzz" {
		t.Fatalf("classes should be default first, then by name: %+v", cls)
	}
	if cls[0].Claims != 2 || cls[0].CapacityBytes != 15*g || cls[1].Claims != 1 || cls[2].Claims != 0 {
		t.Errorf("class totals = %+v", cls)
	}
}

func TestSummarizeStorageEmptyIsNonNil(t *testing.T) {
	claims, volumes, classes := SummarizeStorage(nil, nil, nil, nil, podNow)
	if claims == nil || volumes == nil || classes == nil {
		t.Fatal("want empty non-nil slices so JSON encodes as []")
	}
}
