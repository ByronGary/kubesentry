package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/model"
)

func troubledCluster() fakeCluster {
	return fakeCluster{
		pods: []model.Pod{
			{Namespace: "app", Name: "web-0", Phase: "Running", Claims: []string{"data", "data", "ghost"},
				Containers: []model.ContainerStatus{{Name: "web", RestartCount: 4, LastTerminatedReason: "OOMKilled", LastTerminatedAt: now.Add(-2 * time.Hour), LastExitCode: 137}}},
			{Namespace: "app", Name: "calm-0", Phase: "Running", Containers: []model.ContainerStatus{{Name: "c"}}},
			{Namespace: "app", Name: "flappy-0", Phase: "Running", Containers: []model.ContainerStatus{{Name: "c", RestartCount: 9}}},
			{Namespace: "other", Name: "x-0", Phase: "Running", Containers: []model.ContainerStatus{{Name: "c", RestartCount: 1}}},
		},
		pvcs: []model.PVC{{Namespace: "app", Name: "data", Phase: "Bound", StorageClass: "gp3", CapacityBytes: 10 << 30}},
	}
}

func leakySeries() []model.ContainerSeries {
	var samples []model.Sample
	for i := 0; i < 24; i++ {
		samples = append(samples, model.Sample{T: now.Add(-time.Duration(24-i) * 10 * time.Minute), V: float64(100+10*i) * (1 << 20)})
	}
	return []model.ContainerSeries{{Key: model.ContainerKey{Namespace: "app", Pod: "web-0", Container: "web"}, Samples: samples}}
}

func TestPodsListOrdersMostTroubledFirst(t *testing.T) {
	s := newServer(troubledCluster(), nil)
	var resp podsResponse
	if code := get(t, s, "/api/v1/pods", &resp); code != 200 {
		t.Fatalf("status %d", code)
	}
	var names []string
	for _, p := range resp.Items {
		names = append(names, p.Name)
	}
	if got := names; len(got) != 4 || got[0] != "web-0" || got[1] != "flappy-0" || got[2] != "x-0" || got[3] != "calm-0" {
		// OOMKilled first, then restarts desc (9, 1, 0).
		t.Errorf("order = %v", got)
	}
	if !resp.Items[0].OOMKilled || resp.Items[0].Restarts != 4 {
		t.Errorf("first = %+v", resp.Items[0])
	}

	get(t, s, "/api/v1/pods?namespace=other", &resp)
	if resp.Count != 1 || resp.Items[0].Name != "x-0" {
		t.Errorf("namespace filter = %+v", resp)
	}
	if code := get(t, s, "/api/v1/pods?namespace=Bad_NS", nil); code != 400 {
		t.Errorf("bad namespace status %d, want 400", code)
	}
}

func TestPodDiagnosticsFullReport(t *testing.T) {
	metrics := fakeMetrics{
		series: leakySeries(),
		limits: map[model.ContainerKey]float64{{Namespace: "app", Pod: "web-0", Container: "web"}: 512 << 20},
	}
	s := newServer(troubledCluster(), metrics)
	s.Audit = &audit.Ingester{Store: audit.NewMemoryStore(50)}
	s.Audit.(*audit.Ingester).Store.Add(
		audit.Event{AuditID: "1", Time: now.Add(-time.Hour), Stage: "ResponseStarted", Verb: "create", Username: "alice", ActorKind: "user",
			Resource: "pods", Subresource: "exec", Namespace: "app", Name: "web-0", StatusCode: 101, Tags: []string{audit.TagExec}},
		audit.Event{AuditID: "2", Time: now.Add(-time.Hour), Stage: "ResponseComplete", Verb: "get", Username: "alice", ActorKind: "user",
			Resource: "pods", Namespace: "app", Name: "calm-0"}, // different pod: must not appear
	)

	var resp podDiagnosticsResponse
	if code := get(t, s, "/api/v1/pods/app/web-0/diagnostics", &resp); code != 200 {
		t.Fatalf("status %d", code)
	}
	status := map[string]string{}
	for _, c := range resp.Checks {
		status[c.ID] = c.Status
	}
	want := map[string]string{
		"phase":    detectors.StatusOK,
		"oom":      detectors.StatusCrit,
		"restarts": detectors.StatusWarn, // 4 restarts reaches the warn threshold of 3
		// 60 MiB/h, ending at 330 MiB of a 512 MiB limit: about 3 hours left, under the 6 hour crit line.
		"memory":   detectors.StatusCrit,
		"storage":  detectors.StatusCrit, // "ghost" does not exist
		"activity": detectors.StatusWarn, // one exec session
	}
	for id, w := range want {
		if status[id] != w {
			t.Errorf("check %s = %q, want %q (%+v)", id, status[id], w, resp.Checks)
		}
	}

	if !resp.MetricsAvailable || !resp.AuditAvailable || len(resp.Containers) != 1 {
		t.Fatalf("unexpected response: %+v", resp)
	}
	c := resp.Containers[0]
	if len(c.Series) != 24 || c.Leak == nil || c.LimitBytes != 512<<20 || c.LastTerminatedAt == nil || c.LastExitCode != 137 {
		t.Errorf("container = %+v", c)
	}
	if len(resp.Volumes) != 2 || !resp.Volumes[0].Found || resp.Volumes[1].Found {
		t.Errorf("volumes should be deduplicated, with ghost missing: %+v", resp.Volumes)
	}
	if len(resp.Activity) != 1 || resp.Activity[0].Name != "web-0" {
		t.Errorf("activity should hold only this pod's events: %+v", resp.Activity)
	}
}

func TestPodDiagnosticsDegradesWithoutSources(t *testing.T) {
	s := newServer(troubledCluster(), nil)
	var resp podDiagnosticsResponse
	if code := get(t, s, "/api/v1/pods/app/calm-0/diagnostics", &resp); code != 200 {
		t.Fatalf("status %d", code)
	}
	status := map[string]string{}
	for _, c := range resp.Checks {
		status[c.ID] = c.Status
	}
	if status["memory"] != detectors.StatusUnknown || status["activity"] != detectors.StatusUnknown {
		t.Errorf("statuses = %v", status)
	}
	if resp.Containers[0].Series == nil || resp.Activity == nil || resp.Volumes == nil {
		t.Error("collections must encode as [] not null")
	}

	// A Prometheus failure becomes a warning, not a failed request.
	s = newServer(troubledCluster(), fakeMetrics{err: http.ErrHandlerTimeout})
	get(t, s, "/api/v1/pods/app/calm-0/diagnostics", &resp)
	if resp.MetricsAvailable || len(resp.Warnings) != 1 {
		t.Errorf("want a warning and no metrics: %+v", resp)
	}
}

func TestPodDiagnosticsErrors(t *testing.T) {
	s := newServer(troubledCluster(), nil)
	cases := map[string]int{
		"/api/v1/pods/app/missing-0/diagnostics":             404,
		"/api/v1/pods/app/Bad_Name/diagnostics":              400,
		`/api/v1/pods/app/x%22%7D%20or%20vector/diagnostics`: 400,
		"/api/v1/pods/app/web-0/diagnostics?window=1m":       400,
		"/api/v1/pods/app/web-0/diagnostics?window=nope":     400,
	}
	for path, want := range cases {
		if code := get(t, s, path, nil); code != want {
			t.Errorf("%s = %d, want %d", path, code, want)
		}
	}
}
