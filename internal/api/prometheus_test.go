package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/model"
	"github.com/ByronGary/kubesentry/internal/procmon"
)

// scannedMetrics is a metrics source with a background leak report, as the
// server's Prometheus source has.
type scannedMetrics struct {
	fakeMetrics
	report    detectors.LeakReport
	window    time.Duration
	available bool
	calls     *int // ContainerMemory calls: the costly path
}

func (s scannedMetrics) LeakReport() (detectors.LeakReport, time.Duration, bool) {
	return s.report, s.window, true
}

func (s scannedMetrics) MetricsAvailable() bool { return s.available }

func (s scannedMetrics) ContainerMemory(ctx context.Context, lookback, step time.Duration) ([]model.ContainerSeries, error) {
	*s.calls++
	return s.fakeMetrics.ContainerMemory(ctx, lookback, step)
}

func (s scannedMetrics) ContainerMemoryIn(ctx context.Context, nss []string, lookback, step time.Duration) ([]model.ContainerSeries, error) {
	*s.calls++
	return s.fakeMetrics.ContainerMemoryIn(ctx, nss, lookback, step)
}

func TestOOMServesTheLeakScan(t *testing.T) {
	scanned := []detectors.LeakFinding{
		{ContainerKey: model.ContainerKey{Namespace: "team-a", Pod: "web-1", Container: "web"}, SlopeBytesPerHour: 1 << 22, Confidence: "high"},
		{ContainerKey: model.ContainerKey{Namespace: "team-b", Pod: "web-1", Container: "web"}, SlopeBytesPerHour: 1 << 21, Confidence: "high"},
	}
	calls := 0
	m := scannedMetrics{
		fakeMetrics: fakeMetrics{series: tenantServer(t).Metrics.(fakeMetrics).series, limits: map[model.ContainerKey]float64{}},
		report: detectors.LeakReport{GeneratedAt: now.Add(-time.Minute), LastAttempt: now.Add(-time.Minute), Window: "24h0m0s",
			Findings: scanned, Warnings: []string{"more than 5000 candidates: analysed the 5000 fastest-growing"}},
		window: 24 * time.Hour, available: true, calls: &calls,
	}
	s := tenantServer(t)
	s.Metrics = m
	h := s.Handler()

	// The default window is the scan's: no query, findings scope-filtered.
	var resp oomResponse
	getAs(t, h, "alice", "/api/v1/oom", &resp)
	if calls != 0 || !resp.MetricsAvailable || len(resp.Leaks) != 1 || resp.Leaks[0].Namespace != "team-a" {
		t.Fatalf("scan path: calls %d, %+v", calls, resp)
	}
	if len(resp.Warnings) != 1 || !strings.Contains(resp.Warnings[0], "more than 5000 candidates") {
		t.Errorf("warnings = %v", resp.Warnings)
	}
	getAs(t, h, "nobody", "/api/v1/oom", &resp)
	if len(resp.Leaks) != 0 {
		t.Errorf("a caller without namespaces sees leaks: %+v", resp.Leaks)
	}

	// Another window falls back to querying now (alice's namespaces only).
	resp = oomResponse{}
	getAs(t, h, "alice", "/api/v1/oom?window=6h", &resp)
	if calls != 1 || !resp.MetricsAvailable || len(resp.Leaks) != 1 || resp.Leaks[0].Namespace != "team-a" {
		t.Errorf("fallback: calls %d, %+v", calls, resp)
	}

	// Before the first scan finishes, the default window falls back too.
	m.report = detectors.LeakReport{Window: "24h0m0s", Findings: []detectors.LeakFinding{}}
	s.Metrics = m
	getAs(t, s.Handler(), "alice", "/api/v1/oom", &resp)
	if calls != 2 || len(resp.Leaks) != 1 {
		t.Errorf("no scan yet: calls %d, %+v", calls, resp)
	}

	// A source that has not found its Prometheus counts as none.
	m.available = false
	s.Metrics = m
	var info infoResponse
	getAs(t, s.Handler(), "alice", "/api/v1/info", &info)
	getAs(t, s.Handler(), "alice", "/api/v1/oom", &resp)
	if info.Metrics || info.Prometheus == nil || info.Prometheus.Source != "none" || resp.MetricsAvailable || calls != 2 {
		t.Errorf("unavailable source: info %+v, oom %+v, calls %d", info, resp, calls)
	}
}

// Memory limits on the pod page come from the pod when Prometheus reports
// none (no kube-state-metrics); one Prometheus reports wins.
func TestPodPageLimitsFromThePod(t *testing.T) {
	c := troubledCluster()
	c.pods[0].Specs = []model.ContainerSpec{{Name: "web", MemoryLimitBytes: 256 << 20}}
	s := newServer(c, fakeMetrics{series: leakySeries(), limits: map[model.ContainerKey]float64{}})
	var resp podDiagnosticsResponse
	get(t, s, "/api/v1/pods/app/web-0/diagnostics", &resp)
	if len(resp.Containers) != 1 || resp.Containers[0].LimitBytes != 256<<20 || resp.ActivityWindow != "168h0m0s" {
		t.Errorf("containers %+v window %q", resp.Containers, resp.ActivityWindow)
	}
	s = newServer(c, fakeMetrics{series: leakySeries(), limits: map[model.ContainerKey]float64{{Namespace: "app", Pod: "web-0", Container: "web"}: 512 << 20}})
	get(t, s, "/api/v1/pods/app/web-0/diagnostics", &resp)
	if resp.Containers[0].LimitBytes != 512<<20 {
		t.Errorf("kube-state-metrics limit should win: %+v", resp.Containers[0])
	}
}

func TestAgentsRoute(t *testing.T) {
	s := tenantServer(t)
	h := s.Handler()
	var agents []procmon.AgentStatus
	rec := getAs(t, h, "alice", "/api/v1/agents", nil)
	if rec.Code != 403 {
		t.Errorf("without ViewAgents = %d, want 403", rec.Code)
	}
	s.Authenticator = nil // everyone unrestricted
	rec = getAs(t, s.Handler(), "", "/api/v1/agents", &agents)
	if rec.Code != 200 || len(agents) != 3 || agents[0].Node != "n-kube-system" || agents[0].Stale {
		t.Errorf("agents = %d %+v", rec.Code, agents)
	}

	// No process store, or one that cannot list agents: no route, so the UI hides it.
	s.Processes = nil
	if rec := getAs(t, s.Handler(), "", "/api/v1/agents", nil); rec.Code != 404 {
		t.Errorf("without a store = %d, want 404", rec.Code)
	}
	s.Processes = forPodOnly{}
	if rec := getAs(t, s.Handler(), "", "/api/v1/agents", nil); rec.Code != 404 {
		t.Errorf("with a store that cannot list agents = %d, want 404", rec.Code)
	}
}

type forPodOnly struct{}

func (forPodOnly) Update(procmon.Report)                 {}
func (forPodOnly) ForPod(string) (procmon.PodView, bool) { return procmon.PodView{}, false }

func TestAgentReportStatusCodes(t *testing.T) {
	s, st := procServer()
	gz := func(body string) []byte {
		var b bytes.Buffer
		w := gzip.NewWriter(&b)
		_, _ = w.Write([]byte(body))
		_ = w.Close()
		return b.Bytes()
	}
	send := func(body []byte, encoding string) int {
		req := httptest.NewRequest(http.MethodPost, "/agent/report", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer agent-secret")
		if encoding != "" {
			req.Header.Set("Content-Encoding", encoding)
		}
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		return rec.Code
	}
	good := `{"node":"n1","processes":[{"pid":1,"podUID":"uid-web"}]}`
	bomb := gz(`{"node":"n1","processes":[` + strings.Repeat(`{"pid":1,"name":"xxxxxxxxxxxxxxxxxxxxxxxx"},`, 400_000) + `{"pid":2}]}`)
	cases := []struct {
		name     string
		body     []byte
		encoding string
		want     int
	}{
		{"plain", []byte(good), "", 204},
		{"gzip", gz(good), "gzip", 204},
		{"compressed beyond the limit", bomb, "gzip", 413},
		{"unknown encoding", []byte(good), "br", 415},
		{"not gzip", []byte(good), "gzip", 400},
		{"not JSON", []byte("nope"), "", 400},
		{"no node", []byte(`{"processes":[]}`), "", 400},
	}
	for _, c := range cases {
		if got := send(c.body, c.encoding); got != c.want {
			t.Errorf("%s = %d, want %d", c.name, got, c.want)
		}
	}
	if len(bomb) >= maxAgentBody {
		t.Fatalf("the gzip bomb should be small on the wire, is %d bytes", len(bomb))
	}
	if a := st.Agents(); len(a) != 1 || a[0].Bytes == 0 {
		t.Errorf("agents after reports = %+v", a)
	}
}

func TestMapStatsAndVisibleNamespaces(t *testing.T) {
	s := tenantServer(t)
	h := s.Handler()
	var m mapResponse
	getAs(t, h, "alice", "/api/v1/map", &m)
	if len(m.NamespaceStats) != 1 || m.NamespaceStats[0] != (namespaceStat{Name: "team-a", Pods: 3}) {
		t.Errorf("alice's namespace stats = %+v", m.NamespaceStats)
	}
	s.Authenticator = nil
	getAs(t, s.Handler(), "", "/api/v1/map", &m)
	stats := map[string]namespaceStat{}
	for _, st := range m.NamespaceStats {
		stats[st.Name] = st
	}
	if len(stats) != 3 || !stats["kube-system"].System || stats["team-b"].System || stats["team-b"].Pods != 3 {
		t.Errorf("namespace stats = %+v", m.NamespaceStats)
	}

	var info infoResponse
	getAs(t, h, "alice", "/api/v1/info", &info)
	if info.Namespaces == nil || *info.Namespaces != 1 {
		t.Errorf("alice sees %v namespaces, want 1", info.Namespaces)
	}
	getAs(t, h, "carol", "/api/v1/info", &info)
	if info.Namespaces == nil || *info.Namespaces != 0 {
		t.Errorf("carol sees %v namespaces, want 0", info.Namespaces)
	}
	getAs(t, s.Handler(), "", "/api/v1/info", &info)
	if info.Namespaces == nil || *info.Namespaces != 3 {
		t.Errorf("unrestricted sees %v namespaces, want 3", info.Namespaces)
	}
	raw, _ := json.Marshal(info)
	if !strings.Contains(string(raw), `"namespaces":3`) {
		t.Errorf("info JSON = %s", raw)
	}
}
