package api

// Review probes. Each test states the property it expects; a failure on the
// current code is the finding.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/auth"
	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/model"
	"github.com/ByronGary/kubesentry/internal/procmon"
	"github.com/ByronGary/kubesentry/internal/prom"
	"github.com/ByronGary/kubesentry/internal/snapshot"
)

// growingAuthorizer gives alice team-a on her first Scope lookup and
// team-a+team-b on every later one: what happens when her cached scope
// expires (TTL, or a recheck's Forget) and she has just been granted team-b,
// between the response cache computing its key and the handler computing the
// scope it filters by. bob always holds team-a.
type growingAuthorizer struct {
	mu    sync.Mutex
	calls map[string]int
}

func (g *growingAuthorizer) Scope(_ context.Context, id auth.Identity, c auth.Capability) (auth.Scope, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.calls == nil {
		g.calls = map[string]int{}
	}
	g.calls[id.User]++
	if c != auth.ViewNamespace {
		return auth.Scope{Namespaces: map[string]bool{}}, nil
	}
	if id.User == "alice" && g.calls[id.User] > 1 {
		return auth.Scope{Namespaces: map[string]bool{"team-a": true, "team-b": true}}, nil
	}
	return auth.Scope{Namespaces: map[string]bool{"team-a": true}}, nil
}

func (g *growingAuthorizer) Allowed(context.Context, auth.Identity, auth.Capability, string) (bool, error) {
	return false, nil
}

// The response cache keys a response by the scope it looked up, but the
// handler looks the scope up again. If the two differ, the response is
// stored under a key other callers share.
func TestProbeResponseCacheKeyScopeMatchesHandlerScope(t *testing.T) {
	s := tenantServer(t)
	s.Authorizer = &growingAuthorizer{}
	h := s.Handler()

	getAs(t, h, "alice", "/api/v1/pods", nil) // key from {team-a}, body from {team-a, team-b}
	rec := getAs(t, h, "bob", "/api/v1/pods", nil)
	nss, _ := namespacesIn(rec.Body.Bytes())
	if nss["team-b"] > 0 {
		t.Errorf("bob (team-a only) received team-b pods from the cache (X-Kubesentry-Cache=%s): %v",
			rec.Header().Get("X-Kubesentry-Cache"), nss)
	}
}

// -auth-mode=none (and token mode without a token on loopback) trusts every
// loopback connection. A web page using DNS rebinding reaches the loopback
// listener from the user's browser with its own Host name; nothing checks it.
func TestProbeNoneModeRefusesForeignHost(t *testing.T) {
	s := tenantServer(t)
	s.Authenticator = auth.NoneAuthenticator{}
	h := s.Handler()
	req := httptest.NewRequest(http.MethodGet, "http://rebind.attacker.example:8080/api/v1/pods", nil)
	req.RemoteAddr = "127.0.0.1:51234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		nss, _ := namespacesIn(rec.Body.Bytes())
		t.Errorf("Host rebind.attacker.example from loopback got 200 with namespaces %v; want the Host refused (as kubectl proxy's --accept-hosts does)", nss)
	}
}

// Proxy mode trusts identity headers from any loopback connection. kubectl
// port-forward (and a DNS-rebinding page behind it) arrives from loopback.
func TestProbeProxyModeLoopbackIsNotTheProxy(t *testing.T) {
	a := auth.HeaderAuthenticator{UserHeader: "X-Forwarded-Email", GroupsHeader: "X-Forwarded-Groups",
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}
	req := httptest.NewRequest(http.MethodGet, "http://rebind.attacker.example:8080/api/v1/pods", nil)
	req.RemoteAddr = "127.0.0.1:40000"
	req.Header.Set("X-Forwarded-Email", "platform-admin@corp.example")
	req.Header.Set("X-Forwarded-Groups", "platform-admins")
	if id, ok := a.Authenticate(req); ok {
		t.Logf("loopback caller became %q with groups %v without any secret shared with the proxy", id.User, id.Groups)
		t.Errorf("identity headers accepted from a loopback peer with a foreign Host and no proxy secret")
	}
}

// countingMetrics records cluster-wide memory queries.
type countingMetrics struct {
	fakeMetrics
	clusterWide atomic.Int64
}

func (c *countingMetrics) ContainerMemory(ctx context.Context, lookback, step time.Duration) ([]model.ContainerSeries, error) {
	c.clusterWide.Add(1)
	return c.fakeMetrics.ContainerMemory(ctx, lookback, step)
}

// A caller who may see no namespace at all can still make the server run a
// range query over every container in the cluster, once per distinct window.
func TestProbeOOMWithoutGrantsQueriesNothing(t *testing.T) {
	s := tenantServer(t)
	m := &countingMetrics{fakeMetrics: s.Metrics.(fakeMetrics)}
	s.Metrics = m
	h := s.Handler()
	for i := 0; i < 5; i++ {
		if rec := getAs(t, h, "carol", fmt.Sprintf("/api/v1/oom?window=%dm", 11+i), nil); rec.Code != 200 {
			t.Fatalf("oom as carol = %d", rec.Code)
		}
	}
	if n := m.clusterWide.Load(); n > 0 {
		t.Errorf("carol (no grants) caused %d cluster-wide Prometheus range queries", n)
	}
}

// countingReviewer counts SubjectAccessReviews.
type countingReviewer struct {
	grantReviewer
	n atomic.Int64
}

func (c *countingReviewer) Review(ctx context.Context, user string, groups []string, verb, group, resource, ns string) (bool, error) {
	c.n.Add(1)
	return c.grantReviewer.Review(ctx, user, groups, verb, group, resource, ns)
}

// Every distinct namespace name in a pod path costs a SubjectAccessReview
// and a cache entry, also for namespaces that do not exist.
func TestProbeUnknownNamespacesCostNoReviews(t *testing.T) {
	s := tenantServer(t)
	rv := &countingReviewer{grantReviewer: tenantGrants()}
	s.Authorizer = &auth.SARAuthorizer{Reviewer: rv, Candidates: s.Authorizer.(*auth.SARAuthorizer).Candidates}
	s.RateLimit = 0
	h := s.Handler()
	for i := 0; i < 50; i++ {
		if rec := getAs(t, h, "carol", fmt.Sprintf("/api/v1/pods/nope-%d/x/diagnostics", i), nil); rec.Code != 404 {
			t.Fatalf("status %d", rec.Code)
		}
	}
	if n := rv.n.Load(); n >= 50 {
		t.Errorf("50 lookups of namespaces that do not exist made %d SubjectAccessReviews", n)
	}
}

// The agent route decodes the whole report before it checks the process
// count, so an 8 MiB body of empty objects becomes millions of structs.
func TestProbeAgentReportProcessCountBoundsMemory(t *testing.T) {
	s := &Server{Processes: procmon.NewStore(), AgentToken: "t"}
	h := s.Handler()
	var body bytes.Buffer
	body.WriteString(`{"node":"n","processes":[`)
	const n = 1_000_000 // ~3 MiB, well under the 8 MiB limit
	body.WriteString(strings.Repeat("{},", n-1))
	body.WriteString(`{}]}`)
	req := httptest.NewRequest(http.MethodPost, "/agent/report", &body)
	req.Header.Set("Authorization", "Bearer t")
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	runtime.ReadMemStats(&after)
	alloc := after.TotalAlloc - before.TotalAlloc
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d", rec.Code)
	}
	if alloc > 64<<20 {
		t.Errorf("a %d-process report (limit %d) allocated %d MiB before it was refused", n, maxAgentProcesses, alloc>>20)
	}
}

// recordingStore records the queries the API hands the audit store.
type recordingStore struct {
	mu   sync.Mutex
	sums []audit.Query
}

func (r *recordingStore) Add(context.Context, []audit.Event) error { return nil }
func (r *recordingStore) Query(context.Context, audit.Query) ([]audit.Event, error) {
	return nil, nil
}
func (r *recordingStore) Summarize(_ context.Context, q audit.Query) (audit.Summary, error) {
	r.mu.Lock()
	r.sums = append(r.sums, q)
	r.mu.Unlock()
	return audit.Summary{}, nil
}
func (r *recordingStore) Coverage(context.Context) (audit.Coverage, error) {
	return audit.Coverage{}, nil
}

type activeBackend struct{ st audit.Store }

func (activeBackend) IngestReader(io.Reader) (int, error) { return 0, nil }
func (activeBackend) Query(audit.Query) []audit.Event     { return nil }
func (a activeBackend) Active() audit.Store               { return a.st }

// pgstore caches Summarize results under fmt.Sprintf("%+v", query). The API
// hands it Namespaces == nil for a caller with cluster-wide audit access and
// an empty map for a caller with none: the two queries print alike, so the
// second caller is served the first one's cluster-wide summary.
func TestProbeAuditSummaryQueriesOfDifferentScopesPrintApart(t *testing.T) {
	s := tenantServer(t)
	rec := &recordingStore{}
	s.Audit = activeBackend{rec}
	g := tenantGrants()
	g[grant("erin", auth.ViewAudit, "")] = true
	s.Authorizer = &auth.SARAuthorizer{Reviewer: g, Candidates: s.Authorizer.(*auth.SARAuthorizer).Candidates}
	h := s.Handler()
	for _, user := range []string{"erin", "carol"} {
		if r := getAs(t, h, user, "/api/v1/audit/summary", nil); r.Code != 200 {
			t.Fatalf("summary as %s = %d", user, r.Code)
		}
	}
	if len(rec.sums) != 2 {
		t.Fatalf("store saw %d summaries", len(rec.sums))
	}
	erin, carol := fmt.Sprintf("%+v", rec.sums[0]), fmt.Sprintf("%+v", rec.sums[1])
	if erin == carol {
		t.Errorf("erin (all namespaces) and carol (none) produce the same printed query, pgstore's Summarize cache key:\n%s", carol)
	}
}

// A caller with ViewNodes but only some namespaces gets each node's
// requested CPU and memory summed over every pod on it, hidden namespaces
// included, while pods and podCount are cut to their namespaces.
func TestProbeNodeRequestsCoverOnlyVisiblePods(t *testing.T) {
	inv := tenantInventory()
	for i := range inv.Pods {
		inv.Pods[i].Specs[0].CPURequestMilli = 100
	}
	v := snapshot.Build(inv, detectors.DefaultPolicy(), now)
	s := tenantServer(t)
	s.Views = currentView{v}
	s.Authorizer = &auth.SARAuthorizer{Reviewer: tenantGrants(), Candidates: v.RBAC()}
	var nodes nodesResponse
	getAs(t, s.Handler(), "bob", "/api/v1/nodes", &nodes)
	for _, n := range nodes.Items {
		visible := int64(0)
		for _, p := range n.Pods {
			if p.Namespace == "team-b" {
				visible += 100
			}
		}
		if n.CPURequestedMilli > visible {
			t.Errorf("bob (team-b) sees node %s requesting %dm CPU; his pods there request %dm", n.Name, n.CPURequestedMilli, visible)
		}
	}
}

// Path and method tricks never reach an API handler without an identity.
// (Passes: recorded as coverage.)
func TestProbeNoUnauthenticatedAPIPaths(t *testing.T) {
	s := tenantServer(t)
	s.UI = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(299) })
	h := s.Handler()
	paths := []string{"/api/v1/pods", "//api/v1/pods", "/api/../api/v1/pods", "/api/v1/pods/", "/api/v1//pods",
		"/%61pi/v1/pods", "/api%2Fv1%2Fpods", "/api/v1/pods?x=1", "/./api/v1/pods", "/api/v1/./pods", "/API/v1/pods",
		"/api/v1/pods/team-a/web-0/diagnostics", "/api/v1/info", "/api"}
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodPost} {
		for _, p := range paths {
			req := httptest.NewRequest(method, "http://kubesentry"+p, nil)
			req.RemoteAddr = "198.51.100.7:1234" // not the trusted proxy
			req.Header.Set("X-Forwarded-Email", "erin")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code == http.StatusOK || strings.Contains(rec.Body.String(), "team-") {
				t.Errorf("%s %s without identity = %d %q", method, p, rec.Code, rec.Body.String())
			}
		}
	}
}

// -prometheus-url may carry basic-auth credentials (Go's client sends them);
// /info hands the URL, as cmd/server builds it from Client.BaseURL, to every
// signed-in user, whatever they may see.
func TestProbeInfoHidesPrometheusCredentials(t *testing.T) {
	c, err := prom.NewClient("https://kubesentry:s3cret-pass@mimir.example.com/prometheus", prom.Options{})
	if err != nil {
		t.Fatal(err)
	}
	s := tenantServer(t)
	s.PrometheusInfo = func() *PrometheusInfo { return &PrometheusInfo{Source: "flag", URL: c.BaseURL()} } // as cmd/server/prometheus.go
	rec := getAs(t, s.Handler(), "carol", "/api/v1/info", nil)
	if strings.Contains(rec.Body.String(), "s3cret-pass") {
		t.Errorf("carol (no grants) reads the Prometheus password from /info: %s", rec.Body.String())
	}
}
