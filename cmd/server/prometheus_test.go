package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
	"github.com/ByronGary/kubesentry/internal/prom"
)

// fakeProm answers like a Prometheus 3 server with empty data.
func fakeProm(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/api/v1/status/buildinfo"):
			_, _ = io.WriteString(w, `{"status":"success","data":{"version":"3.5.0","revision":"abc","goVersion":"go1.24"}}`)
		case strings.HasSuffix(r.URL.Path, "/api/v1/status/runtimeinfo"):
			_, _ = io.WriteString(w, `{"status":"success","data":{"storageRetention":"15d"}}`)
		case strings.HasSuffix(r.URL.Path, "/api/v1/query"), strings.HasSuffix(r.URL.Path, "/api/v1/query_range"):
			_, _ = io.WriteString(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1760000000,"7"]}]}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDiscoveryChoosesTheFirstGoodCandidate(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, "<html>bad gateway</html>")
	}))
	t.Cleanup(bad.Close)
	good, alsoGood := fakeProm(t), fakeProm(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	attempts := 0
	setup := promSetup{
		autodiscover: true,
		scan:         prom.LeakScanOptions{Interval: time.Hour, StartJitter: -1},
		pods:         func(context.Context) ([]model.Pod, error) { return nil, nil },
		retry:        10 * time.Millisecond,
		discover: func(context.Context) ([]string, error) {
			attempts++
			if attempts == 1 {
				return nil, errors.New("services are forbidden")
			}
			return []string{"http://127.0.0.1:1", bad.URL, good.URL, alsoGood.URL}, nil
		},
	}
	p := &promSource{}
	if p.MetricsAvailable() || p.Info().Source != "none" {
		t.Fatal("no Prometheus before discovery")
	}
	if _, err := p.ContainerMemory(ctx, time.Hour, time.Minute); !errors.Is(err, errNoPrometheus) {
		t.Errorf("query before discovery: %v", err)
	}
	if err := setup.start(ctx, p); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for !p.MetricsAvailable() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	info := p.Info()
	if info.Source != "discovered" || info.URL != good.URL || info.Flavor != prom.FlavorPrometheus || info.Version != "3.5.0" || info.RetentionHours != 360 {
		t.Fatalf("chose %+v after %d attempts", info, attempts)
	}
	if attempts != 2 {
		t.Errorf("discovery attempts = %d, want a retry after the failure", attempts)
	}
	if _, err := p.ContainerMemoryLimits(ctx); err != nil {
		t.Errorf("query through the discovered client: %v", err)
	}
	if _, window, ok := p.LeakReport(); !ok || window != 24*time.Hour {
		t.Errorf("leak scanner window = %v %v", window, ok)
	}
}

func TestDiscoverySendsTheBearerToken(t *testing.T) {
	inner := fakeProm(t)
	locked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer s3cret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		r.URL.Host, r.URL.Scheme, r.RequestURI = strings.TrimPrefix(inner.URL, "http://"), "http", ""
		resp, err := http.DefaultTransport.RoundTrip(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	t.Cleanup(locked.Close)
	t.Setenv("PROMETHEUS_TOKEN", "s3cret")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	setup := promSetup{
		autodiscover: true,
		scan:         prom.LeakScanOptions{Interval: time.Hour, StartJitter: -1},
		pods:         func(context.Context) ([]model.Pod, error) { return nil, nil },
		discover:     func(context.Context) ([]string, error) { return []string{locked.URL}, nil },
	}
	st, err := setup.discoverOnce(ctx)
	if err != nil {
		t.Fatalf("a Prometheus behind a bearer token was rejected: %v", err)
	}
	if st.info.Version != "3.5.0" {
		t.Errorf("probe through the token: %+v", st.info)
	}
}

func TestConfiguredPrometheus(t *testing.T) {
	srv := fakeProm(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &promSource{}
	sel, _ := prom.ParseMatchers(`cluster="prod"`)
	err := promSetup{url: srv.URL, selector: sel, scan: prom.LeakScanOptions{Window: 6 * time.Hour, StartJitter: -1}}.start(ctx, p)
	if err != nil || !p.MetricsAvailable() {
		t.Fatalf("start: %v", err)
	}
	if info := p.Info(); info.Source != "flag" || info.URL != srv.URL {
		t.Errorf("info = %+v", info)
	}
	deadline := time.Now().Add(10 * time.Second)
	for p.Info().Flavor == "" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if info := p.Info(); info.Flavor != prom.FlavorPrometheus {
		t.Errorf("probe did not describe the server: %+v", info)
	}
	if _, w, _ := p.LeakReport(); w != 6*time.Hour {
		t.Errorf("scan window = %v", w)
	}
	if err := (promSetup{url: "ftp://nowhere"}).start(ctx, &promSource{}); err == nil {
		t.Error("a bad URL should fail")
	}
	// Neither a URL nor discovery: no source, and no error.
	q := &promSource{}
	if err := (promSetup{}).start(ctx, q); err != nil || q.MetricsAvailable() {
		t.Errorf("no Prometheus: %v %v", err, q.MetricsAvailable())
	}
}

func TestLeakFlags(t *testing.T) {
	for in, want := range map[string]float64{"1MiB": 1 << 20, "512KiB/h": 512 << 10, "1048576": 1 << 20, "2Mi": 2 << 20, "1.5MB": 1.5e6} {
		if got, err := parseBytesPerHour(in); err != nil || got != want {
			t.Errorf("%s = %v %v, want %v", in, got, err, want)
		}
	}
	if _, err := parseBytesPerHour("fast"); err == nil {
		t.Error("nonsense should fail")
	}
	c, err := parseFlags([]string{"-leak-min-slope=2MiB", "-leak-min-r2=0.9", "-leak-drop-ratio=0.6", "-leak-min-points=8", "-leak-crit-hours=12",
		"-leak-scan-window=12h", "-leak-scan-interval=10m", "-prometheus-selector=cluster=\"prod\"", "-agent-interval=30s"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := c.policy()
	if p.Leak.MinSlopeBytesPerHour != 2<<20 || p.Leak.MinR2 != 0.9 || p.Leak.DropRatio != 0.6 || p.Leak.MinSegmentPoints != 8 || p.Thresholds.LeakCritHours != 12 {
		t.Errorf("leak policy = %+v crit %v", p.Leak, p.Thresholds.LeakCritHours)
	}
	if c.leakScanWindow != 12*time.Hour || c.leakScanInterval != 10*time.Minute || c.agentInterval != 30*time.Second || !c.promAutodiscover {
		t.Errorf("config = %+v", c)
	}
	for _, bad := range [][]string{{"-prometheus-selector=cluster"}, {"-leak-min-r2=2"}, {"-leak-drop-ratio=1"}, {"-leak-min-points=1"}} {
		if _, err := parseFlags(bad, io.Discard); err == nil {
			t.Errorf("%v should be refused", bad)
		}
	}
}
