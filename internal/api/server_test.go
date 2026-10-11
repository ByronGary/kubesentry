package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/model"
)

type fakeCluster struct {
	pvcs []model.PVC
	pods []model.Pod
}

func (f fakeCluster) ListPVCs(context.Context) ([]model.PVC, error) { return f.pvcs, nil }
func (f fakeCluster) ListPods(context.Context) ([]model.Pod, error) { return f.pods, nil }

func (f fakeCluster) GetPod(_ context.Context, ns, name string) (*model.Pod, error) {
	for i := range f.pods {
		if f.pods[i].Namespace == ns && f.pods[i].Name == name {
			return &f.pods[i], nil
		}
	}
	return nil, model.ErrNotFound
}

func (f fakeCluster) GetPVC(_ context.Context, ns, name string) (*model.PVC, error) {
	for i := range f.pvcs {
		if f.pvcs[i].Namespace == ns && f.pvcs[i].Name == name {
			return &f.pvcs[i], nil
		}
	}
	return nil, model.ErrNotFound
}

type fakeMetrics struct {
	series []model.ContainerSeries
	limits map[model.ContainerKey]float64
	err    error
}

func (f fakeMetrics) ContainerMemory(context.Context, time.Duration, time.Duration) ([]model.ContainerSeries, error) {
	return f.series, f.err
}
func (f fakeMetrics) ContainerMemoryLimits(context.Context) (map[model.ContainerKey]float64, error) {
	return f.limits, f.err
}

func (f fakeMetrics) ContainerMemoryIn(_ context.Context, namespaces []string, _, _ time.Duration) ([]model.ContainerSeries, error) {
	in := map[string]bool{}
	for _, ns := range namespaces {
		in[ns] = true
	}
	var out []model.ContainerSeries
	for _, s := range f.series {
		if in[s.Key.Namespace] {
			out = append(out, s)
		}
	}
	return out, f.err
}

func (f fakeMetrics) ContainerMemoryLimitsIn(context.Context, []string) (map[model.ContainerKey]float64, error) {
	return f.limits, f.err
}

func (f fakeMetrics) PodMemory(_ context.Context, ns, pod string, _, _ time.Duration) ([]model.ContainerSeries, map[model.ContainerKey]float64, error) {
	if f.err != nil {
		return nil, nil, f.err
	}
	var out []model.ContainerSeries
	for _, s := range f.series {
		if s.Key.Namespace == ns && s.Key.Pod == pod {
			out = append(out, s)
		}
	}
	return out, f.limits, nil
}

var now = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

func newServer(c ClusterSource, m MetricsSource) *Server {
	return &Server{
		Cluster:     c,
		Metrics:     m,
		PVCOptions:  detectors.PVCOptions{MinAge: time.Hour, DefaultPricePerGiBMonth: 0.10},
		LeakOptions: detectors.DefaultLeakOptions(),
		Now:         func() time.Time { return now },
	}
}

func get(t *testing.T, s *Server, path string, out any) int {
	t.Helper()
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if out != nil {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			t.Fatalf("decode %q: %v", rec.Body.String(), err)
		}
	}
	return rec.Code
}

func TestUnusedPVCsEndpoint(t *testing.T) {
	s := newServer(fakeCluster{
		pvcs: []model.PVC{{Namespace: "a", Name: "orphan", Phase: "Bound", CapacityBytes: 10 << 30, Created: now.Add(-48 * time.Hour)}},
	}, nil)

	var resp unusedPVCResponse
	if code := get(t, s, "/api/v1/pvcs/unused", &resp); code != 200 {
		t.Fatalf("status %d", code)
	}
	if resp.Count != 1 || resp.TotalEstMonthlyCostUSD != 1.0 {
		t.Errorf("got %+v, want 1 item costing $1.00", resp)
	}

	// minAge override hides it.
	get(t, s, "/api/v1/pvcs/unused?minAge=100h", &resp)
	if resp.Count != 0 {
		t.Errorf("minAge=100h should hide the 48h-old PVC, got %d", resp.Count)
	}
	if code := get(t, s, "/api/v1/pvcs/unused?minAge=banana", nil); code != 400 {
		t.Errorf("bad minAge status = %d, want 400", code)
	}
}

func TestOOMEndpointJoinsEventsAndLeaks(t *testing.T) {
	key := model.ContainerKey{Namespace: "app", Pod: "web-0", Container: "web"}
	var samples []model.Sample
	for i := 0; i < 20; i++ {
		samples = append(samples, model.Sample{T: now.Add(-time.Duration(20-i) * 10 * time.Minute), V: float64(100+10*i) * (1 << 20)})
	}
	cluster := fakeCluster{pods: []model.Pod{{
		Namespace: "app", Name: "web-0",
		Containers: []model.ContainerStatus{{Name: "web", RestartCount: 2, LastTerminatedReason: "OOMKilled", LastTerminatedAt: now.Add(-time.Hour), LastExitCode: 137}},
	}}}
	metrics := fakeMetrics{
		series: []model.ContainerSeries{{Key: key, Samples: samples}},
		limits: map[model.ContainerKey]float64{key: 512 << 20},
	}

	var resp oomResponse
	if code := get(t, newServer(cluster, metrics), "/api/v1/oom", &resp); code != 200 {
		t.Fatalf("status %d", code)
	}
	if len(resp.Events) != 1 || !resp.MetricsAvailable || len(resp.Leaks) != 1 {
		t.Fatalf("unexpected response: %+v", resp)
	}
	l := resp.Leaks[0]
	if !l.OOMKilled || l.LastOOMAt == nil || l.TimeToLimitHours == nil {
		t.Errorf("leak should be joined with the OOM event and have a time-to-limit: %+v", l)
	}
}

func TestOOMEndpointDegradesWhenPrometheusFails(t *testing.T) {
	cluster := fakeCluster{pods: []model.Pod{{
		Namespace: "app", Name: "web-0",
		Containers: []model.ContainerStatus{{Name: "web", LastTerminatedReason: "OOMKilled", LastTerminatedAt: now.Add(-time.Hour)}},
	}}}
	var resp oomResponse
	code := get(t, newServer(cluster, fakeMetrics{err: errors.New("boom")}), "/api/v1/oom", &resp)
	if code != 200 {
		t.Fatalf("status %d, want 200 with a warning", code)
	}
	if len(resp.Events) != 1 || resp.MetricsAvailable || len(resp.Warnings) != 1 {
		t.Errorf("unexpected response: %+v", resp)
	}
}

func TestOOMWindowValidation(t *testing.T) {
	s := newServer(fakeCluster{}, nil)
	for _, q := range []string{"window=1m", "window=999h", "window=xyz"} {
		if code := get(t, s, "/api/v1/oom?"+q, nil); code != 400 {
			t.Errorf("%s status = %d, want 400", q, code)
		}
	}
}
