package detectors

import (
	"strings"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
)

var podNow = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

func f64(v float64) *float64 { return &v }

func byID(t *testing.T, checks []Check) map[string]Check {
	t.Helper()
	m := map[string]Check{}
	for _, c := range checks {
		m[c.ID] = c
	}
	if len(checks) != 7 || len(m) != 7 {
		t.Fatalf("want 7 distinct checks, got %d (%d distinct)", len(checks), len(m))
	}
	return m
}

func TestDiagnosePodHealthy(t *testing.T) {
	checks := DiagnosePod(PodInput{
		Pod:              model.Pod{Phase: "Running", Containers: []model.ContainerStatus{{Name: "web"}}},
		Volumes:          []VolumeState{{Claim: "data", Found: true, Phase: "Bound"}},
		MetricsAvailable: true,
		AuditAvailable:   true,
		Now:              podNow,
	})
	for _, c := range checks {
		if c.Status != StatusOK {
			t.Errorf("%s = %s (%s), want ok", c.ID, c.Status, c.Detail)
		}
	}
	if got := byID(t, checks)["storage"].Detail; got != "1 volume, all bound." {
		t.Errorf("storage detail = %q", got)
	}
}

func TestDiagnosePodUnknownWithoutDataSources(t *testing.T) {
	m := byID(t, DiagnosePod(PodInput{Pod: model.Pod{Phase: "Running"}, Now: podNow}))
	if m["memory"].Status != StatusUnknown || m["activity"].Status != StatusUnknown {
		t.Errorf("memory=%s activity=%s, want unknown for both", m["memory"].Status, m["activity"].Status)
	}
}

func TestDiagnosePodProblems(t *testing.T) {
	m := byID(t, DiagnosePod(PodInput{
		Pod: model.Pod{Phase: "Pending", Containers: []model.ContainerStatus{
			{Name: "web", RestartCount: 7, LastTerminatedReason: "OOMKilled", LastTerminatedAt: podNow.Add(-3 * time.Hour)},
			{Name: "old", RestartCount: 4, LastTerminatedReason: "OOMKilled", LastTerminatedAt: podNow.Add(-72 * time.Hour)},
		}},
		Volumes: []VolumeState{
			{Claim: "data", Found: true, Phase: "Bound"},
			{Claim: "ghost", Found: false},
		},
		Leaks:            []LeakFinding{{ContainerKey: model.ContainerKey{Container: "web"}, SlopeBytesPerHour: 120 << 20, TimeToLimitHours: f64(2.5)}},
		MetricsAvailable: true,
		AuditAvailable:   true,
		ExecCount:        2,
		DeniedCount:      1,
		Now:              podNow,
	}))

	want := map[string]struct {
		status string
		inText string
	}{
		"phase":    {StatusWarn, "Pending"},
		"oom":      {StatusCrit, "web (3h ago)"},
		"restarts": {StatusCrit, "11 restarts across 2 containers"}, // 7+4 reaches the crit threshold of 10
		"memory":   {StatusCrit, "120 MiB/h"},
		"storage":  {StatusCrit, "ghost"},
		"activity": {StatusWarn, "2 exec or attach sessions and 1 denied request"},
	}
	for id, w := range want {
		c := m[id]
		if c.Status != w.status || !strings.Contains(c.Detail, w.inText) {
			t.Errorf("%s = %s %q, want %s containing %q", id, c.Status, c.Detail, w.status, w.inText)
		}
	}
	if strings.Contains(m["oom"].Detail, "old") {
		t.Errorf("an OOM older than a day should not appear in the crit message: %q", m["oom"].Detail)
	}
}

func TestOOMCheckOlderThanADayIsWarning(t *testing.T) {
	c := oomCheck(PodInput{Now: podNow, Pod: model.Pod{Containers: []model.ContainerStatus{
		{Name: "web", LastTerminatedReason: "OOMKilled", LastTerminatedAt: podNow.Add(-72 * time.Hour)},
	}}})
	if c.Status != StatusWarn || !strings.Contains(c.Detail, "web (3d ago)") {
		t.Errorf("got %s %q", c.Status, c.Detail)
	}
}

func TestMemoryCheckVariants(t *testing.T) {
	leak := func(ttl *float64) LeakFinding {
		return LeakFinding{ContainerKey: model.ContainerKey{Container: "web"}, SlopeBytesPerHour: 50 << 20, TimeToLimitHours: ttl}
	}
	cases := []struct {
		name   string
		leaks  []LeakFinding
		status string
		inText string
	}{
		{"far from limit", []LeakFinding{leak(f64(30))}, StatusWarn, "30 hours"},
		{"no limit set", []LeakFinding{leak(nil)}, StatusWarn, "No memory limit is set"},
		{"imminent", []LeakFinding{leak(f64(0.4))}, StatusCrit, "24 minutes"},
		{"singular hour", []LeakFinding{leak(f64(1.0))}, StatusCrit, "about 1 hour."},
		{"picks soonest", []LeakFinding{
			{ContainerKey: model.ContainerKey{Container: "slow"}, SlopeBytesPerHour: 1 << 20, TimeToLimitHours: f64(40)},
			{ContainerKey: model.ContainerKey{Container: "fast"}, SlopeBytesPerHour: 9 << 20, TimeToLimitHours: f64(3)},
		}, StatusCrit, "fast grows"},
	}
	for _, c := range cases {
		got := memoryCheck(PodInput{MetricsAvailable: true, Leaks: c.leaks})
		if got.Status != c.status || !strings.Contains(got.Detail, c.inText) {
			t.Errorf("%s: %s %q, want %s containing %q", c.name, got.Status, got.Detail, c.status, c.inText)
		}
	}
}

func TestStorageCheckVariants(t *testing.T) {
	if c := storageCheck(nil); c.Status != StatusOK {
		t.Errorf("no volumes: %v", c)
	}
	if c := storageCheck([]VolumeState{{Claim: "a", Found: true, Phase: "Pending"}}); c.Status != StatusWarn || !strings.Contains(c.Detail, "a (Pending)") {
		t.Errorf("pending: %v", c)
	}
	if c := storageCheck([]VolumeState{{Claim: "a", Found: true, Phase: "Lost"}}); c.Status != StatusCrit {
		t.Errorf("lost: %v", c)
	}
}
