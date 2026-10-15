package api

// Regression tests for the findings of the October 2026 security review.
// Each states the property it guards.

import (
	"bytes"
	"context"
	"errors"
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

// The response cache keys a response by the scope it looked up and the
// handler filters by a scope too: both must be the same lookup, or the
// response is stored under a key other callers share.
func TestResponseCacheKeyScopeMatchesHandlerScope(t *testing.T) {
	s := tenantServer(t)
	s.Authorizer = &growingAuthorizer{}
	h := s.Handler()

	getAs(t, h, "alice", "/api/v1/pods", nil) // her first lookup says {team-a}, any later one {team-a, team-b}
	rec := getAs(t, h, "bob", "/api/v1/pods", nil)
	nss, _ := namespacesIn(rec.Body.Bytes())
	if nss["team-b"] > 0 {
		t.Errorf("bob (team-a only) received team-b pods from the cache (X-Kubesentry-Cache=%s): %v",
			rec.Header().Get("X-Kubesentry-Cache"), nss)
	}
}

// flakyAuthorizer fails every lookup while failing is set, then defers to
// the inner authorizer.
type flakyAuthorizer struct {
	inner   auth.Authorizer
	failing atomic.Bool
}

func (f *flakyAuthorizer) Scope(ctx context.Context, id auth.Identity, c auth.Capability) (auth.Scope, error) {
	if f.failing.Load() {
		return auth.Scope{}, errors.New("apiserver unavailable")
	}
	return f.inner.Scope(ctx, id, c)
}

func (f *flakyAuthorizer) Allowed(ctx context.Context, id auth.Identity, c auth.Capability, ns string) (bool, error) {
	if f.failing.Load() {
		return false, errors.New("apiserver unavailable")
	}
	return f.inner.Allowed(ctx, id, c, ns)
}

// A lookup that fails while the response is built leaves the caller with
// less than they may see (fail closed). That response is served, but never
// cached: not under the key it was computed for, nor for anyone else.
func TestResponseCacheSkipsResponsesBuiltOnFailedAuthorization(t *testing.T) {
	s := tenantServer(t)
	fa := &flakyAuthorizer{inner: s.Authorizer}
	s.Authorizer = fa
	h := s.Handler()

	// Every lookup fails: the caller sees nothing, and nothing is cached.
	fa.failing.Store(true)
	rec := getAs(t, h, "alice", "/api/v1/pods", nil)
	if rec.Code != 200 {
		t.Fatalf("pods with failing authorization = %d", rec.Code)
	}
	if nss, _ := namespacesIn(rec.Body.Bytes()); len(nss) > 0 {
		t.Errorf("failed authorization showed %v", nss)
	}
	if n := s.ResponseCache.Len(); n != 0 {
		t.Errorf("a response built on a failed lookup was cached (%d entries)", n)
	}
	// Once lookups work again alice sees her namespace at once.
	fa.failing.Store(false)
	rec = getAs(t, h, "alice", "/api/v1/pods", nil)
	if nss, _ := namespacesIn(rec.Body.Bytes()); nss["team-a"] == 0 {
		t.Errorf("after recovery alice sees %v; the degraded response was replayed", nss)
	}
}

// The same when only the handler's lookup fails, after the key's succeeded
// (a capability missing from cachedRoutes): the response is not kept.
func TestResponseCacheSkipsWhenHandlerLookupFails(t *testing.T) {
	ok := &flakyAuthorizer{inner: denyAll{}}
	bad := &flakyAuthorizer{inner: denyAll{}}
	bad.failing.Store(true)
	c := &ResponseCache{KeyFunc: CacheKeyFunc(ok, func() uint64 { return 1 }, auth.ViewNamespace)}
	h := withAuthzMemo(c.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = scopeOf(r.Context(), bad, auth.ViewNodes) // fails closed
		writeJSON(w, http.StatusOK, map[string]int{"items": 0})
	})))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/x", nil)
	req = req.WithContext(auth.WithIdentity(req.Context(), auth.Identity{User: "alice", Source: "proxy"}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || c.Len() != 0 {
		t.Errorf("status %d, %d cached; want 200 and nothing cached", rec.Code, c.Len())
	}
}

// notYetCurrent serves a view but, like a snapshot.Manager before its first
// build is published, cannot name a current one.
type notYetCurrent struct{ v *snapshot.View }

func (n notYetCurrent) View(context.Context) (*snapshot.View, error) { return n.v, nil }
func (n notYetCurrent) Current() *snapshot.View                      { return nil }

// Before the first view exists nothing is cached: scopes computed then lack
// the RBAC index's candidates.
func TestResponseCacheBypassedBeforeFirstView(t *testing.T) {
	s := tenantServer(t)
	s.Views = notYetCurrent{s.Views.(currentView).v}
	h := s.Handler()
	for i := 0; i < 2; i++ {
		rec := getAs(t, h, "alice", "/api/v1/pods", nil)
		if rec.Code != 200 || rec.Header().Get("X-Kubesentry-Cache") != "" {
			t.Errorf("request %d = %d, cache %q", i, rec.Code, rec.Header().Get("X-Kubesentry-Cache"))
		}
	}
	if n := s.ResponseCache.Len(); n != 0 {
		t.Errorf("%d responses cached before the first view", n)
	}
}

// -auth-mode=none (and token mode without a token on loopback) trusts every
// loopback connection. A web page using DNS rebinding reaches the loopback
// listener from the user's browser with its own Host name, so Host names
// other than the loopback ones are refused, as kubectl proxy's
// --accept-hosts does.
func TestNoneModeRefusesForeignHost(t *testing.T) {
	s := tenantServer(t)
	s.Authenticator = auth.NoneAuthenticator{}
	s.UI = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	h := s.Handler()
	send := func(url string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, url, nil)
		req.RemoteAddr = "127.0.0.1:51234"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	for _, url := range []string{"http://rebind.attacker.example:8080/api/v1/pods", "http://rebind.attacker.example/", "http://127.0.0.1.nip.io:8080/api/v1/pods"} {
		if rec := send(url); rec.Code != http.StatusForbidden {
			nss, _ := namespacesIn(rec.Body.Bytes())
			t.Errorf("%s from loopback = %d with namespaces %v; want 403", url, rec.Code, nss)
		}
	}
	for _, url := range []string{"http://localhost:8080/api/v1/pods", "http://127.0.0.1:9999/api/v1/pods", "http://[::1]:8080/api/v1/pods", "http://localhost/"} {
		if rec := send(url); rec.Code != http.StatusOK {
			t.Errorf("%s = %d, want 200", url, rec.Code)
		}
	}
	// Probes answer whatever the Host (kubelet uses the pod IP).
	if rec := send("http://10.0.0.5:8080/healthz"); rec.Code != http.StatusOK {
		t.Errorf("healthz with a pod IP Host = %d", rec.Code)
	}
	// An explicit allowlist replaces the default, in any mode.
	s.AllowedHosts = []string{"kubesentry.internal"}
	h = s.Handler()
	if rec := send("http://localhost:8080/api/v1/pods"); rec.Code != http.StatusForbidden {
		t.Errorf("localhost with an explicit allowlist = %d, want 403", rec.Code)
	}
	if rec := send("http://kubesentry.internal/api/v1/pods"); rec.Code != http.StatusOK {
		t.Errorf("allowed host = %d", rec.Code)
	}
}

// Proxy mode once trusted identity headers from any loopback connection,
// and kubectl port-forward (and a DNS-rebinding page behind it) arrives
// from loopback. With the web listener on a Unix socket shared with the
// sidecar (TrustProxyConn), loopback TCP is not the proxy.
func TestProxyModeLoopbackIsNotTheProxy(t *testing.T) {
	s := tenantServer(t)
	s.Authenticator = auth.HeaderAuthenticator{UserHeader: "X-Forwarded-Email", GroupsHeader: "X-Forwarded-Groups", TrustProxyConn: true,
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}
	h := s.Handler()
	send := func(viaSocket bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "http://rebind.attacker.example:8080/api/v1/pods", nil)
		req.RemoteAddr = "127.0.0.1:40000"
		if viaSocket {
			req = req.WithContext(auth.WithProxyConn(req.Context()))
			req.RemoteAddr = "@"
		}
		req.Header.Set("X-Forwarded-Email", "alice")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	if rec := send(false); rec.Code != http.StatusUnauthorized {
		t.Errorf("identity headers over loopback TCP = %d, want 401", rec.Code)
	}
	if rec := send(true); rec.Code != http.StatusOK {
		t.Errorf("identity headers over the proxy's socket = %d, want 200", rec.Code)
	}
}

func TestParseAllowedHosts(t *testing.T) {
	hosts, err := ParseAllowedHosts(" Kubesentry.Example.com , *.corp.example:443,[::1]:8080, 10.0.0.5 ")
	if err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]bool{
		"kubesentry.example.com": true, "KUBESENTRY.example.com:8443": true, "kubesentry.example.com.": true,
		"a.corp.example:443": true, "a.b.corp.example:443": true, "corp.example:443": false, "a.corp.example:80": false,
		"[::1]:8080": true, "[::1]:8081": false, "10.0.0.5:1": true, "evil.example": false, "": false,
		"kubesentry.example.com.evil.example": false,
	} {
		if got := hostAllowed(hosts, host); got != want {
			t.Errorf("%q allowed = %v, want %v", host, got, want)
		}
	}
	if hosts, _ := ParseAllowedHosts("*"); !hostAllowed(hosts, "anything.example") {
		t.Error("* should allow every host")
	}
	if hosts, err := ParseAllowedHosts(""); err != nil || hosts != nil {
		t.Errorf("empty = %v, %v", hosts, err)
	}
	for _, bad := range []string{"a/b", "host:port", "a.*.example", "user@host", "*.:x"} {
		if _, err := ParseAllowedHosts(bad); err == nil {
			t.Errorf("%q should be refused", bad)
		}
	}
}

// countingMetrics records cluster-wide and namespace-restricted memory queries.
type countingMetrics struct {
	fakeMetrics
	clusterWide atomic.Int64
	mu          sync.Mutex
	restricted  [][]string
}

func (c *countingMetrics) ContainerMemory(ctx context.Context, lookback, step time.Duration) ([]model.ContainerSeries, error) {
	c.clusterWide.Add(1)
	return c.fakeMetrics.ContainerMemory(ctx, lookback, step)
}

func (c *countingMetrics) ContainerMemoryIn(ctx context.Context, nss []string, lookback, step time.Duration) ([]model.ContainerSeries, error) {
	c.mu.Lock()
	c.restricted = append(c.restricted, nss)
	c.mu.Unlock()
	return c.fakeMetrics.ContainerMemoryIn(ctx, nss, lookback, step)
}

// clusterOnlyMetrics cannot restrict queries to namespaces.
type clusterOnlyMetrics struct{ m *countingMetrics }

func (c clusterOnlyMetrics) ContainerMemory(ctx context.Context, lookback, step time.Duration) ([]model.ContainerSeries, error) {
	return c.m.ContainerMemory(ctx, lookback, step)
}
func (c clusterOnlyMetrics) ContainerMemoryLimits(ctx context.Context) (map[model.ContainerKey]float64, error) {
	return c.m.ContainerMemoryLimits(ctx)
}
func (c clusterOnlyMetrics) PodMemory(ctx context.Context, ns, pod string, lookback, step time.Duration) ([]model.ContainerSeries, map[model.ContainerKey]float64, error) {
	return c.m.PodMemory(ctx, ns, pod, lookback, step)
}

// A caller who may not see every namespace never makes the server run a
// range query over every container in the cluster: with no namespace there
// is no query at all, otherwise the query names their namespaces.
func TestOOMQueriesOnlyTheCallersNamespaces(t *testing.T) {
	s := tenantServer(t)
	m := &countingMetrics{fakeMetrics: s.Metrics.(fakeMetrics)}
	s.Metrics = m
	h := s.Handler()
	for i := 0; i < 5; i++ {
		if rec := getAs(t, h, "carol", fmt.Sprintf("/api/v1/oom?window=%dm", 11+i), nil); rec.Code != 200 {
			t.Fatalf("oom as carol = %d", rec.Code)
		}
	}
	if n := m.clusterWide.Load(); n > 0 || len(m.restricted) > 0 {
		t.Errorf("carol (no grants) caused %d cluster-wide and %d restricted Prometheus range queries", n, len(m.restricted))
	}

	var oom oomResponse
	getAs(t, h, "alice", "/api/v1/oom?window=90m", &oom)
	if n := m.clusterWide.Load(); n > 0 {
		t.Errorf("alice (team-a) caused %d cluster-wide queries", n)
	}
	if len(m.restricted) != 1 || strings.Join(m.restricted[0], ",") != "team-a" {
		t.Errorf("alice's queries named %v, want [[team-a]]", m.restricted)
	}
	if len(oom.Leaks) != 1 || oom.Leaks[0].Namespace != "team-a" || !oom.MetricsAvailable {
		t.Errorf("alice's leaks = %+v", oom)
	}

	// Unrestricted callers still query the cluster.
	s.Authenticator = nil
	getAs(t, s.Handler(), "", "/api/v1/oom?window=90m", nil)
	if m.clusterWide.Load() != 1 {
		t.Errorf("unrestricted caller made %d cluster-wide queries, want 1", m.clusterWide.Load())
	}

	// A source that cannot restrict queries serves restricted callers only
	// the background report, with a warning.
	s = tenantServer(t)
	m2 := &countingMetrics{fakeMetrics: s.Metrics.(fakeMetrics)}
	s.Metrics = clusterOnlyMetrics{m2}
	oom = oomResponse{}
	getAs(t, s.Handler(), "alice", "/api/v1/oom?window=90m", &oom)
	if m2.clusterWide.Load() != 0 || len(oom.Warnings) == 0 || len(oom.Leaks) != 0 {
		t.Errorf("cluster-only source: %d cluster-wide queries, response %+v", m2.clusterWide.Load(), oom)
	}
}

// One identity may hold at most LongInflightPerIdentity requests on the
// expensive routes at once; others are not affected.
func TestExpensiveRoutesCapPerIdentity(t *testing.T) {
	s := tenantServer(t)
	s.LongInflightPerIdentity = 2
	block := make(chan struct{})
	entered := make(chan struct{}, 8)
	s.Metrics = blockingMetrics{fakeMetrics: s.Metrics.(fakeMetrics), block: block, entered: entered}
	s.Authenticator = nil // unrestricted: /oom queries the cluster
	h := s.Handler()
	var wg sync.WaitGroup
	codes := make(chan int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- getAs(t, h, "", fmt.Sprintf("/api/v1/oom?window=%dm", 20+i), nil).Code
		}()
	}
	<-entered
	<-entered
	rec := getAs(t, h, "", "/api/v1/oom?window=30m", nil)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Errorf("third expensive request = %d (Retry-After %q), want 429", rec.Code, rec.Header().Get("Retry-After"))
	}
	if rec := getAs(t, h, "", "/api/v1/pods", nil); rec.Code != 200 {
		t.Errorf("a cheap route while capped = %d", rec.Code)
	}
	close(block)
	wg.Wait()
	close(codes)
	for c := range codes {
		if c != 200 {
			t.Errorf("held request = %d", c)
		}
	}
	if rec := getAs(t, h, "", "/api/v1/oom?window=31m", nil); rec.Code != 200 {
		t.Errorf("after the others finished = %d", rec.Code)
	}
}

// blockingMetrics holds every cluster-wide query until block closes.
type blockingMetrics struct {
	fakeMetrics
	block   chan struct{}
	entered chan struct{}
}

func (b blockingMetrics) ContainerMemory(ctx context.Context, lookback, step time.Duration) ([]model.ContainerSeries, error) {
	b.entered <- struct{}{}
	select {
	case <-b.block:
	case <-ctx.Done():
	}
	return b.fakeMetrics.ContainerMemory(ctx, lookback, step)
}

// countingReviewer counts SubjectAccessReviews.
type countingReviewer struct {
	grantReviewer
	n atomic.Int64
}

func (c *countingReviewer) Review(ctx context.Context, user string, groups []string, verb, group, resource, subresource, ns string) (bool, error) {
	c.n.Add(1)
	return c.grantReviewer.Review(ctx, user, groups, verb, group, resource, subresource, ns)
}

// Every distinct namespace name in a pod path once cost a
// SubjectAccessReview and a cache entry, also for namespaces that do not
// exist. Objects the view does not hold are 404 without any review, with
// the same body as objects the caller may not see.
func TestUnknownObjectsCostNoReviews(t *testing.T) {
	s := tenantServer(t)
	rv := &countingReviewer{grantReviewer: tenantGrants()}
	s.Authorizer = &auth.SARAuthorizer{Reviewer: rv, Candidates: s.Authorizer.(*auth.SARAuthorizer).Candidates}
	s.RateLimit = 0
	h := s.Handler()
	var bodies []string
	for i := 0; i < 50; i++ {
		for _, path := range []string{
			fmt.Sprintf("/api/v1/pods/nope-%d/x/diagnostics", i),
			fmt.Sprintf("/api/v1/pods/nope-%d/x/processes", i),
			fmt.Sprintf("/api/v1/pods/team-b/web-%d/diagnostics", 10+i), // the namespace exists, the pod does not
		} {
			rec := getAs(t, h, "carol", path, nil)
			if rec.Code != 404 {
				t.Fatalf("%s = %d", path, rec.Code)
			}
			bodies = append(bodies, rec.Body.String())
		}
	}
	if n := rv.n.Load(); n != 0 {
		t.Errorf("lookups of objects that do not exist made %d SubjectAccessReviews", n)
	}
	// The map's namespace and a node's name: no review per made-up name.
	before := rv.n.Load()
	getAs(t, h, "carol", "/api/v1/map?namespace=nope-0", nil)
	getAs(t, h, "carol", "/api/v1/nodes/nope-0", nil)
	after := rv.n.Load()
	for i := 1; i < 20; i++ {
		for _, path := range []string{fmt.Sprintf("/api/v1/map?namespace=nope-%d", i), fmt.Sprintf("/api/v1/nodes/nope-%d", i)} {
			if rec := getAs(t, h, "carol", path, nil); rec.Code != 404 {
				t.Fatalf("%s = %d", path, rec.Code)
			}
		}
	}
	if rv.n.Load() != after {
		t.Errorf("made-up map namespaces and node names cost %d more reviews after the first (%d)", rv.n.Load()-after, after-before)
	}
	// Existing but hidden, and missing: the same answer.
	hidden := getAs(t, h, "carol", "/api/v1/pods/team-b/web-0/diagnostics", nil)
	if hidden.Code != 404 || hidden.Body.String() != bodies[0] {
		t.Errorf("hidden pod = %d %q, missing pod = %q", hidden.Code, hidden.Body.String(), bodies[0])
	}
}

// The agent route once decoded the whole report before it checked the
// process count, so an 8 MiB body of empty objects became millions of
// structs. Decoding now stops at the store's per-node cap: 413.
func TestAgentReportProcessCountBoundsMemory(t *testing.T) {
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
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d, want 413", rec.Code)
	}
	if s.Processes.(*procmon.Store).Nodes() != 0 {
		t.Error("the refused report was stored")
	}
	if alloc > 64<<20 {
		t.Errorf("a %d-process report (limit %d) allocated %d MiB before it was refused", n, maxAgentProcesses, alloc>>20)
	}
}

// recordingStore records the queries the API hands the audit store.
type recordingStore struct {
	mu      sync.Mutex
	sums    []audit.Query
	queries []audit.Query
}

func (r *recordingStore) Add(context.Context, []audit.Event) error { return nil }
func (r *recordingStore) Query(_ context.Context, q audit.Query) ([]audit.Event, error) {
	r.mu.Lock()
	r.queries = append(r.queries, q)
	r.mu.Unlock()
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

// The API hands the store Namespaces == nil for a caller with cluster-wide
// audit access and, once, handed it an empty map for a caller with none;
// pgstore's Summarize cache printed both alike and served the second caller
// the first one's cluster-wide summary. A caller who may read no audit
// event at all now gets an empty answer without the store being asked, and
// every query that reaches it says exactly what it covers.
func TestAuditWithoutGrantsSkipsTheStore(t *testing.T) {
	s := tenantServer(t)
	rec := &recordingStore{}
	s.Audit = activeBackend{rec}
	g := tenantGrants()
	g[grant("erin", auth.ViewAudit, "")] = true // cluster-wide: every namespace
	s.Authorizer = &auth.SARAuthorizer{Reviewer: g, Candidates: s.Authorizer.(*auth.SARAuthorizer).Candidates}
	h := s.Handler()
	for _, user := range []string{"erin", "carol", "alice"} {
		var sum auditSummaryResponse
		if r := getAs(t, h, user, "/api/v1/audit/summary", &sum); r.Code != 200 {
			t.Fatalf("summary as %s = %d", user, r.Code)
		}
		var ev auditEventsResponse
		if r := getAs(t, h, user, "/api/v1/audit/events", &ev); r.Code != 200 || ev.Items == nil {
			t.Fatalf("events as %s = %d %+v", user, r.Code, ev)
		}
	}
	if len(rec.sums) != 2 || len(rec.queries) != 2 {
		t.Fatalf("store saw %d summaries and %d queries; carol (no grants) must not reach it", len(rec.sums), len(rec.queries))
	}
	for _, qs := range [][]audit.Query{rec.sums, rec.queries} {
		erin, alice := qs[0], qs[1]
		if erin.Namespaces != nil {
			t.Errorf("erin's query is scoped: %+v", erin.Namespaces)
		}
		if alice.Namespaces == nil || len(alice.Namespaces) != 1 || !alice.Namespaces["team-a"] || alice.ClusterScoped {
			t.Errorf("alice's query = namespaces %v, clusterScoped %v", alice.Namespaces, alice.ClusterScoped)
		}
	}
}

// A caller with ViewNodes but only some namespaces once got each node's
// requested CPU and memory summed over every pod on it, hidden namespaces
// included, while pods and podCount were cut to their namespaces. All of
// them now cover the caller's pods only; unrestricted callers see totals.
func TestNodeRequestsCoverOnlyVisiblePods(t *testing.T) {
	inv := tenantInventory()
	for i := range inv.Pods {
		inv.Pods[i].Specs[0].CPURequestMilli = 100
		inv.Pods[i].Specs[0].MemoryRequestBytes = 1 << 20
	}
	v := snapshot.Build(inv, detectors.DefaultPolicy(), now)
	s := tenantServer(t)
	s.Views = currentView{v}
	s.Authorizer = &auth.SARAuthorizer{Reviewer: tenantGrants(), Candidates: v.RBAC()}
	for _, path := range []string{"/api/v1/nodes", "/api/v1/nodes/n1"} {
		var items []detectors.NodeSummary
		if strings.HasSuffix(path, "/n1") {
			var n detectors.NodeSummary
			getAs(t, s.Handler(), "bob", path, &n)
			items = []detectors.NodeSummary{n}
		} else {
			var nodes nodesResponse
			getAs(t, s.Handler(), "bob", path, &nodes)
			items = nodes.Items
		}
		for _, n := range items {
			mine := 0
			for _, p := range n.Pods {
				if p.Namespace == "team-b" {
					mine++
				}
			}
			if n.CPURequestedMilli != int64(100*mine) || n.MemoryRequestedBytes != int64(mine)<<20 || n.PodCount != mine || mine == 0 {
				t.Errorf("%s: bob (team-b) sees node %s requesting %dm CPU, %d bytes, %d pods; his %d pods there request %dm",
					path, n.Name, n.CPURequestedMilli, n.MemoryRequestedBytes, n.PodCount, mine, 100*mine)
			}
		}
	}
	// Unrestricted: the node's own totals.
	s.Authenticator = nil
	var nodes nodesResponse
	getAs(t, s.Handler(), "", "/api/v1/nodes", &nodes)
	total := int64(0)
	for _, n := range nodes.Items {
		total += n.CPURequestedMilli
	}
	if total != int64(100*len(inv.Pods)) {
		t.Errorf("unrestricted total = %dm, want %dm", total, 100*len(inv.Pods))
	}
}

// Path and method tricks never reach an API handler without an identity.
// (This passed already; kept as coverage.)
func TestNoUnauthenticatedAPIPaths(t *testing.T) {
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

// -prometheus-url may carry basic-auth credentials; /info hands the URL, as
// cmd/server builds it from Client.BaseURL, to every signed-in user,
// whatever they may see. Neither the client's BaseURL nor /info carry them.
func TestInfoHidesPrometheusCredentials(t *testing.T) {
	c, err := prom.NewClient("https://kubesentry:s3cret-pass@mimir.example.com/prometheus", prom.Options{})
	if err != nil {
		t.Fatal(err)
	}
	s := tenantServer(t)
	s.PrometheusInfo = func() *PrometheusInfo { return &PrometheusInfo{Source: "flag", URL: c.BaseURL()} } // as cmd/server/prometheus.go
	rec := getAs(t, s.Handler(), "carol", "/api/v1/info", nil)
	if strings.Contains(rec.Body.String(), "s3cret-pass") || strings.Contains(rec.Body.String(), "kubesentry:") {
		t.Errorf("carol (no grants) reads the Prometheus credentials from /info: %s", rec.Body.String())
	}
	// Even a source that hands /info the raw URL is redacted.
	s.PrometheusInfo = func() *PrometheusInfo {
		return &PrometheusInfo{Source: "flag", URL: "https://kubesentry:s3cret-pass@mimir.example.com/prometheus"}
	}
	var info infoResponse
	getAs(t, s.Handler(), "carol", "/api/v1/info", &info)
	if info.Prometheus == nil || info.Prometheus.URL != "https://mimir.example.com/prometheus" {
		t.Errorf("prometheus info = %+v", info.Prometheus)
	}
}
