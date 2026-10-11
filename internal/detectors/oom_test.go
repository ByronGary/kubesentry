package detectors

import (
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
)

func TestFindOOMKills(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	pods := []model.Pod{
		{Namespace: "a", Name: "p1", Containers: []model.ContainerStatus{
			{Name: "c", RestartCount: 4, LastTerminatedReason: "OOMKilled", LastTerminatedAt: now.Add(-2 * time.Hour), LastExitCode: 137},
			{Name: "sidecar", LastTerminatedReason: "Error", LastTerminatedAt: now.Add(-1 * time.Hour)},
		}},
		{Namespace: "b", Name: "p2", Containers: []model.ContainerStatus{
			{Name: "c", RestartCount: 1, LastTerminatedReason: "OOMKilled", LastTerminatedAt: now.Add(-30 * time.Minute), LastExitCode: 137},
		}},
		{Namespace: "c", Name: "p3", Containers: []model.ContainerStatus{
			{Name: "c", LastTerminatedReason: "OOMKilled", LastTerminatedAt: now.Add(-48 * time.Hour)},
		}},
		{Namespace: "d", Name: "healthy", Containers: []model.ContainerStatus{{Name: "c"}}},
	}

	all := FindOOMKills(pods, time.Time{})
	if len(all) != 3 {
		t.Fatalf("got %d events, want 3: %+v", len(all), all)
	}
	if all[0].Namespace != "b" || all[1].Namespace != "a" || all[2].Namespace != "c" {
		t.Errorf("not sorted newest first: %+v", all)
	}

	recent := FindOOMKills(pods, now.Add(-24*time.Hour))
	if len(recent) != 2 {
		t.Errorf("got %d events within 24h, want 2", len(recent))
	}
	if got := FindOOMKills(nil, time.Time{}); got == nil {
		t.Error("want empty non-nil slice")
	}
}
