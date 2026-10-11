package prom

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
)

func TestLimitsFromPodPrefersStatusOverSpec(t *testing.T) {
	p := model.Pod{
		Namespace: "app", Name: "web-0",
		Specs: []model.ContainerSpec{
			{Name: "web", MemoryLimitBytes: 256 << 20},
			{Name: "sidecar", MemoryLimitBytes: 64 << 20},
			{Name: "init", Init: true, MemoryLimitBytes: 32 << 20},
			{Name: "unlimited"},
		},
		// web was resized in place to 512Mi; the kubelet's status says so.
		Containers: []model.ContainerStatus{{Name: "web", MemoryLimitBytes: 512 << 20}, {Name: "sidecar"}},
	}
	got := LimitsFromPod(p)
	want := map[model.ContainerKey]float64{
		{Namespace: "app", Pod: "web-0", Container: "web"}:     512 << 20,
		{Namespace: "app", Pod: "web-0", Container: "sidecar"}: 64 << 20,
		{Namespace: "app", Pod: "web-0", Container: "init"}:    32 << 20,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	other := model.Pod{Namespace: "b", Name: "x", Specs: []model.ContainerSpec{{Name: "c", MemoryLimitBytes: 1}}}
	if all := LimitsFromPods([]model.Pod{p, other}); len(all) != 4 {
		t.Fatalf("LimitsFromPods: %v", all)
	}
}

func TestPodSpecLimitsByDefaultKSMOnlyWhenAsked(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(rec.handler))
	defer srv.Close()
	pod := model.Pod{Namespace: "app", Name: "web-0", Specs: []model.ContainerSpec{{Name: "web", MemoryLimitBytes: 100}}}
	ctx := context.Background()

	c, _ := NewClient(srv.URL, Options{})
	_, limits, err := c.PodMemoryFor(ctx, pod, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if q := rec.all(); len(q) != 1 || strings.Contains(q[0], "kube_pod_container_resource_limits") {
		t.Fatalf("kube-state-metrics queried without KSMLimits: %q", q)
	}
	if limits[model.ContainerKey{Namespace: "app", Pod: "web-0", Container: "web"}] != 100 {
		t.Fatalf("limit not taken from the pod: %v", limits)
	}
	if l, err := c.ContainerMemoryLimits(ctx); err != nil || len(l) != 0 || len(rec.all()) != 1 {
		t.Fatalf("ContainerMemoryLimits without KSMLimits: %v %v", l, err)
	}

	// The legacy constructor keeps kube-state-metrics.
	rec.queries = nil
	if _, _, err := New(srv.URL).PodMemory(ctx, "app", "web-0", time.Hour, time.Minute); err != nil {
		t.Fatal(err)
	}
	if q := rec.all(); len(q) != 2 || !strings.Contains(q[1], "kube_pod_container_resource_limits") {
		t.Fatalf("legacy client should query kube-state-metrics: %q", q)
	}
}

func TestPodMemoryForKSMWinsAndPodFillsGaps(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "query_range") {
			w.Write([]byte(`{"status":"success","data":{"resultType":"matrix","result":[]}}`))
			return
		}
		w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[
			{"metric":{"namespace":"app","pod":"web-0","container":"web"},"value":[1760000000,"999"]}]}}`))
	}))
	defer srv.Close()
	c, _ := NewClient(srv.URL, Options{KSMLimits: true})
	pod := model.Pod{Namespace: "app", Name: "web-0", Specs: []model.ContainerSpec{{Name: "web", MemoryLimitBytes: 100}, {Name: "side", MemoryLimitBytes: 50}}}
	_, limits, err := c.PodMemoryFor(context.Background(), pod, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	web := model.ContainerKey{Namespace: "app", Pod: "web-0", Container: "web"}
	side := model.ContainerKey{Namespace: "app", Pod: "web-0", Container: "side"}
	if limits[web] != 999 || limits[side] != 50 {
		t.Fatalf("limits: %v", limits)
	}
}

func TestPointParsing(t *testing.T) {
	tests := []struct {
		in string
		ok bool
		v  float64
	}{
		{`[1760000000.5,"42"]`, true, 42},
		{`[ 1760000000 , "1e3" ]`, true, 1000},
		{`[1760000000,"NaN"]`, false, 0},
		{`[1760000000,"+Inf"]`, false, 0},
		{`[1760000000,42]`, false, 0},
		{`["x","1"]`, false, 0},
		{`{"a":1}`, false, 0},
		{`[1]`, false, 0},
	}
	for _, tc := range tests {
		var p point
		if err := p.UnmarshalJSON([]byte(tc.in)); err != nil {
			t.Fatalf("%s: %v", tc.in, err)
		}
		if p.ok != tc.ok || (tc.ok && p.s.V != tc.v) {
			t.Errorf("%s: got %+v", tc.in, p)
		}
	}
	var p point
	_ = p.UnmarshalJSON([]byte(`[1760000000.5,"1"]`))
	if p.s.T.UnixMilli() != 1760000000500 {
		t.Errorf("fractional timestamp: %v", p.s.T)
	}
}
