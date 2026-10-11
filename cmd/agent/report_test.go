package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/procmon"
)

func TestJitterBounds(t *testing.T) {
	d := 15 * time.Second
	for _, rnd := range []float64{0, 0.25, 0.5, 0.75, 0.999999} {
		got := jittered(d, 0.2, rnd)
		if got < 12*time.Second || got > 18*time.Second {
			t.Errorf("jittered(15s, 0.2, %v) = %v, outside ±20%%", rnd, got)
		}
		if s := startDelay(d, rnd); s < 0 || s >= d {
			t.Errorf("startDelay(15s, %v) = %v, outside [0, 15s)", rnd, s)
		}
	}
	if jittered(d, 0.2, 0) != 12*time.Second || jittered(d, 0, 0.9) != d {
		t.Error("jitter extremes")
	}
	// Real randomness stays in bounds too.
	for range 1000 {
		if got := jittered(d, 0.2, randFloat()); got < 12*time.Second || got > 18*time.Second {
			t.Fatalf("jittered = %v", got)
		}
	}
}

func TestBackoffIsCappedExponentialWithJitter(t *testing.T) {
	iv, limit := 15*time.Second, 2*time.Minute
	for _, tc := range []struct {
		failures int
		lo, hi   time.Duration
	}{
		{1, 7500 * time.Millisecond, 15 * time.Second},
		{2, 15 * time.Second, 30 * time.Second},
		{3, 30 * time.Second, 60 * time.Second},
		{4, 60 * time.Second, 120 * time.Second},
		{10, 60 * time.Second, 120 * time.Second},
		{1000, 60 * time.Second, 120 * time.Second},
	} {
		for _, rnd := range []float64{0, 0.5, 0.999} {
			if got := backoff(tc.failures, iv, limit, rnd); got < tc.lo || got > tc.hi {
				t.Errorf("backoff(%d, rnd=%v) = %v, want [%v, %v]", tc.failures, rnd, got, tc.lo, tc.hi)
			}
		}
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		in   string
		want time.Duration
		ok   bool
	}{
		{"7", 7 * time.Second, true},
		{" 120 ", 2 * time.Minute, true},
		{"Sun, 11 Oct 2026 12:00:30 GMT", 30 * time.Second, true},
		{"Sun, 11 Oct 2026 11:00:00 GMT", 0, true},
		{"", 0, false},
		{"soon", 0, false},
		{"-5", 0, false},
	} {
		got, ok := parseRetryAfter(tc.in, now)
		if got != tc.want || ok != tc.ok {
			t.Errorf("parseRetryAfter(%q) = %v, %v", tc.in, got, ok)
		}
	}
}

// agentServer decodes reports the way the server does (procmon.DecodeReport).
type agentServer struct {
	mu       sync.Mutex
	reports  []procmon.Report
	encs     []string
	hosts    []string
	sni      []string
	status   atomic.Int64 // answer with this when non-zero
	retry    string       // Retry-After to send with it
	noGzip   bool         // answer 415 to gzip, like a server without support
	requests atomic.Int64
}

func (s *agentServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.requests.Add(1)
	if r.URL.Path != "/agent/report" || r.Header.Get("Authorization") != "Bearer tok" {
		http.Error(w, "bad request line", http.StatusBadRequest)
		return
	}
	if code := s.status.Load(); code != 0 {
		if s.retry != "" {
			w.Header().Set("Retry-After", s.retry)
		}
		w.WriteHeader(int(code))
		return
	}
	if s.noGzip && r.Header.Get("Content-Encoding") != "" {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}
	rep, err := procmon.DecodeReport(r, 8<<20)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.reports = append(s.reports, rep)
	s.encs = append(s.encs, r.Header.Get("Content-Encoding"))
	s.hosts = append(s.hosts, r.Host)
	if r.TLS != nil {
		s.sni = append(s.sni, r.TLS.ServerName)
	}
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (s *agentServer) got() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.reports)
}

func testReport() procmon.Report {
	r := procmon.Report{Node: "node-a", Time: time.Now()}
	for i := range 200 {
		r.Processes = append(r.Processes, procmon.Process{PID: i + 1, Name: "java", Cmdline: "java -jar app.jar --port=8080", PodUID: "6f1c2d3e-1111-4a5b-8c9d-0123456789ab", RSSBytes: 1 << 20})
	}
	return r
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func testReporter(t *testing.T, server, fanout string, client *http.Client) *reporter {
	t.Helper()
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	r := newReporter(client, mustURL(t, server), fanout, "tok", true, 15*time.Second, 2*time.Minute)
	r.rand = func() float64 { return 0.5 }
	return r
}

func TestGzipRoundTripThroughDecodeReport(t *testing.T) {
	as := &agentServer{}
	srv := httptest.NewServer(as)
	defer srv.Close()
	r := testReporter(t, srv.URL, "", nil)
	sent := testReport()
	out := r.report(context.Background(), sent)
	if len(out) != 1 || out[0].err != nil || out[0].status != http.StatusNoContent {
		t.Fatalf("outcome: %+v", out)
	}
	got := as.reports[0]
	if as.encs[0] != "gzip" || got.Node != sent.Node || len(got.Processes) != len(sent.Processes) || got.Processes[199].Cmdline != sent.Processes[199].Cmdline {
		t.Fatalf("decoded %+v (encoding %q)", got.Node, as.encs[0])
	}
	plain, _ := jsonSize(sent)
	if got.Bytes <= 0 || got.Bytes*4 > int64(plain) {
		t.Errorf("compressed %d bytes of %d: gzip not effective", got.Bytes, plain)
	}

	// -gzip=false sends plain JSON.
	r.gzip = false
	r.report(context.Background(), sent)
	if as.encs[1] != "" || as.reports[1].Bytes != int64(plain) {
		t.Errorf("plain: encoding %q, %d bytes", as.encs[1], as.reports[1].Bytes)
	}
}

func jsonSize(r procmon.Report) (int, error) {
	b, err := json.Marshal(r)
	return len(b), err
}

func TestFallsBackToPlainForServersWithoutGzip(t *testing.T) {
	as := &agentServer{noGzip: true}
	srv := httptest.NewServer(as)
	defer srv.Close()
	r := testReporter(t, srv.URL, "", nil)
	if out := r.report(context.Background(), testReport()); out[0].err != nil {
		t.Fatalf("first report: %+v", out[0])
	}
	if as.requests.Load() != 2 || as.encs[0] != "" {
		t.Fatalf("want a gzip attempt then a plain resend, got %d requests, encodings %q", as.requests.Load(), as.encs)
	}
	r.report(context.Background(), testReport())
	if as.requests.Load() != 3 {
		t.Fatalf("plain should be remembered: %d requests", as.requests.Load())
	}
}

func TestBacksOffOn429WithRetryAfter(t *testing.T) {
	as := &agentServer{retry: "7"}
	as.status.Store(http.StatusTooManyRequests)
	srv := httptest.NewServer(as)
	defer srv.Close()
	r := testReporter(t, srv.URL, "", nil)
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	r.now = func() time.Time { return now }
	ctx := context.Background()

	out := r.report(ctx, testReport())
	if out[0].status != http.StatusTooManyRequests || out[0].err == nil {
		t.Fatalf("outcome: %+v", out[0])
	}
	tg := r.targets[r.endpoint]
	// Retry-After 7s plus up to a fifth of it as spread (rand 0.5 → 0.7s).
	if want := now.Add(7*time.Second + 700*time.Millisecond); !tg.notBefore.Equal(want) {
		t.Fatalf("notBefore = %v, want %v", tg.notBefore, want)
	}

	// Inside the pause nothing is sent.
	now = now.Add(5 * time.Second)
	if out := r.report(ctx, testReport()); !out[0].skipped || as.requests.Load() != 1 {
		t.Fatalf("sent during Retry-After: %+v, %d requests", out[0], as.requests.Load())
	}

	// After it, the agent reports again and success clears the backoff.
	now = now.Add(3 * time.Second)
	as.status.Store(0)
	if out := r.report(ctx, testReport()); out[0].err != nil || out[0].skipped {
		t.Fatalf("after Retry-After: %+v", out[0])
	}
	if as.requests.Load() != 2 || tg.failures != 0 || !tg.notBefore.IsZero() {
		t.Fatalf("requests=%d target=%+v", as.requests.Load(), tg)
	}

	// Retry-After is capped by -max-backoff.
	as.retry = "3600"
	as.status.Store(http.StatusServiceUnavailable)
	r.report(ctx, testReport())
	if d := tg.notBefore.Sub(now); d > 2*time.Minute+24*time.Second {
		t.Fatalf("Retry-After not capped: %v", d)
	}

	// Without Retry-After, 503s back off exponentially.
	as.retry = ""
	tg.notBefore = time.Time{}
	tg.failures = 2
	r.report(ctx, testReport())
	if d := tg.notBefore.Sub(now); d != backoff(3, 15*time.Second, 2*time.Minute, 0.5) {
		t.Fatalf("exponential backoff: %v", d)
	}

	// A 401 is not transient: no pause, the next interval tries again.
	as.status.Store(http.StatusUnauthorized)
	tg.notBefore = time.Time{}
	r.report(ctx, testReport())
	if !tg.notBefore.IsZero() {
		t.Fatal("backed off on 401")
	}
}

// replicas starts n servers on 127.0.0.2, 127.0.0.3, ... sharing one port, as
// pods behind a headless Service share the Service's target port.
func replicas(t *testing.T, n int, tlsOn bool) ([]*agentServer, []string, string, []byte) {
	t.Helper()
	first, err := net.Listen("tcp", "127.0.0.2:0")
	if err != nil {
		t.Skipf("cannot listen on 127.0.0.2: %v", err)
	}
	_, port, _ := net.SplitHostPort(first.Addr().String())
	var servers []*agentServer
	var ips []string
	var cert []byte
	for i := range n {
		ip := "127.0.0." + strconv.Itoa(i+2)
		ln := first
		if i > 0 {
			if ln, err = net.Listen("tcp", net.JoinHostPort(ip, port)); err != nil {
				t.Skipf("cannot listen on %s: %v", ip, err)
			}
		}
		as := &agentServer{}
		srv := httptest.NewUnstartedServer(as)
		srv.Listener = ln
		if tlsOn {
			srv.StartTLS()
			cert = srv.Certificate().Raw
		} else {
			srv.Start()
		}
		t.Cleanup(srv.Close)
		servers = append(servers, as)
		ips = append(ips, ip)
	}
	return servers, ips, port, cert
}

func TestFanoutToEveryReplica(t *testing.T) {
	servers, ips, port, _ := replicas(t, 3, false)
	r := testReporter(t, "http://kubesentry-ingest.kubesentry.svc:"+port, "kubesentry-ingest-headless.kubesentry.svc", nil)
	var lookedUp string
	r.resolve = func(_ context.Context, host string) ([]string, error) {
		lookedUp = host
		return append(ips, ips[0]), nil // duplicates are posted to once
	}
	out := r.report(context.Background(), testReport())
	if lookedUp != "kubesentry-ingest-headless.kubesentry.svc" || len(out) != 3 {
		t.Fatalf("lookup %q, outcomes %+v", lookedUp, out)
	}
	for i, as := range servers {
		if as.got() != 1 {
			t.Errorf("replica %s got %d reports", ips[i], as.got())
		}
		if as.hosts[0] != "kubesentry-ingest.kubesentry.svc:"+port {
			t.Errorf("Host header %q", as.hosts[0])
		}
	}
	for _, o := range out {
		if o.err != nil || !strings.HasSuffix(o.url, ":"+port+"/agent/report") || !strings.HasPrefix(o.url, "http://127.0.0.") {
			t.Errorf("outcome %+v", o)
		}
	}

	// One replica failing does not block or fail the others.
	servers[1].status.Store(http.StatusServiceUnavailable)
	out = r.report(context.Background(), testReport())
	failed := 0
	for _, o := range out {
		if o.err != nil {
			failed++
		}
	}
	if failed != 1 || servers[0].got() != 2 || servers[2].got() != 2 {
		t.Fatalf("outcomes %+v", out)
	}
	// The failing replica backs off alone.
	out = r.report(context.Background(), testReport())
	if servers[0].got() != 3 || servers[2].got() != 3 || servers[1].requests.Load() != 2 {
		t.Fatalf("backoff leaked to healthy replicas: %+v", out)
	}

	// A replica that went away is forgotten.
	r.resolve = func(context.Context, string) ([]string, error) { return ips[:2], nil }
	r.report(context.Background(), testReport())
	if len(r.targets) != 2 {
		t.Fatalf("targets = %d", len(r.targets))
	}
}

func TestFanoutFallsBackToServer(t *testing.T) {
	as := &agentServer{}
	srv := httptest.NewServer(as)
	defer srv.Close()
	r := testReporter(t, srv.URL, "kubesentry-ingest-headless.kubesentry.svc", nil)
	for _, resolve := range []func(context.Context, string) ([]string, error){
		func(context.Context, string) ([]string, error) { return nil, errors.New("no such host") },
		func(context.Context, string) ([]string, error) { return nil, nil },
	} {
		r.resolve = resolve
		out := r.report(context.Background(), testReport())
		if len(out) != 1 || out[0].url != srv.URL+"/agent/report" || out[0].err != nil {
			t.Fatalf("fallback: %+v", out)
		}
	}
	if as.got() != 2 {
		t.Fatalf("server got %d reports", as.got())
	}
}

func TestFanoutTLSVerifiesTheServerName(t *testing.T) {
	servers, ips, port, cert := replicas(t, 2, true)
	// httptest's certificate is valid for example.com (and 127.0.0.1), not
	// for 127.0.0.2 or .3, so only verification by the -server name passes.
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}), 0o600); err != nil {
		t.Fatal(err)
	}

	server := mustURL(t, "https://example.com:"+port)
	client, err := newHTTPClient(server, caFile, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	r := testReporter(t, server.String(), "ingest-headless", client)
	r.resolve = func(context.Context, string) ([]string, error) { return ips, nil }
	out := r.report(context.Background(), testReport())
	for _, o := range out {
		if o.err != nil {
			t.Fatalf("TLS to %s: %v", o.url, o.err)
		}
	}
	for _, as := range servers {
		if as.got() != 1 || as.sni[0] != "example.com" {
			t.Fatalf("replica got %d reports, SNI %q", as.got(), as.sni)
		}
	}

	// A -server name the certificate does not cover fails verification.
	wrong := mustURL(t, "https://wrong.example:"+port)
	client, _ = newHTTPClient(wrong, caFile, 5*time.Second)
	r = testReporter(t, wrong.String(), "ingest-headless", client)
	r.resolve = func(context.Context, string) ([]string, error) { return ips, nil }
	for _, o := range r.report(context.Background(), testReport()) {
		if o.err == nil || !strings.Contains(o.err.Error(), "certificate") {
			t.Fatalf("want a certificate error, got %+v", o)
		}
	}

	// Without -ca-file the system roots do not trust httptest's certificate.
	client, _ = newHTTPClient(server, "", 5*time.Second)
	r = testReporter(t, server.String(), "ingest-headless", client)
	r.resolve = func(context.Context, string) ([]string, error) { return ips[:1], nil }
	if out := r.report(context.Background(), testReport()); out[0].err == nil {
		t.Fatal("untrusted certificate accepted")
	}

	if _, err := newHTTPClient(server, filepath.Join(t.TempDir(), "missing.pem"), time.Second); err == nil {
		t.Error("missing CA file accepted")
	}
	empty := filepath.Join(t.TempDir(), "empty.pem")
	_ = os.WriteFile(empty, []byte("not a cert"), 0o600)
	if _, err := newHTTPClient(server, empty, time.Second); err == nil {
		t.Error("CA file without certificates accepted")
	}
}

func TestValidFanoutHost(t *testing.T) {
	for h, ok := range map[string]bool{
		"":                                  true,
		"kubesentry-ingest-headless":        true,
		"kubesentry-ingest-headless.ks.svc": true,
		"10.0.0.1":                          true,
		"fd00::1":                           true,
		"https://kubesentry-ingest":         false,
		"kubesentry-ingest:8081":            false,
		"kubesentry-ingest/agent":           false,
	} {
		if err := validFanoutHost(h); (err == nil) != ok {
			t.Errorf("validFanoutHost(%q) = %v", h, err)
		}
	}
}

func TestEndpointsKeepServerSchemePortAndPath(t *testing.T) {
	r := testReporter(t, "https://ingest.ks.svc/prefix", "h", nil)
	r.resolve = func(context.Context, string) ([]string, error) { return []string{"10.1.2.3", "fd00::7"}, nil }
	got := r.endpoints(context.Background())
	want := []string{"https://10.1.2.3:443/prefix/agent/report", "https://[fd00::7]:443/prefix/agent/report"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("endpoints %q, want %q", got, want)
	}
}

func TestOutcomeLogForgetsGoneReplicas(t *testing.T) {
	l := &outcomeLog{failing: map[string]bool{}}
	l.record([]outcome{{url: "a", err: errors.New("x"), failures: 1}, {url: "b", err: errors.New("x"), failures: 1}})
	l.record([]outcome{{url: "a"}})
	if len(l.failing) != 0 {
		t.Fatalf("failing = %v", l.failing)
	}
}
