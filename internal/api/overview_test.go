package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/auth"
	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/model"
	"github.com/ByronGary/kubesentry/internal/snapshot"
)

// leakMetrics adds the background leak report to fakeMetrics.
type leakMetrics struct {
	fakeMetrics
	rep detectors.LeakReport
}

func (l leakMetrics) LeakReport() (detectors.LeakReport, time.Duration, bool) {
	return l.rep, 24 * time.Hour, true
}

func getOverview(t *testing.T, h http.Handler, user, path string) (overviewResponse, *httptest.ResponseRecorder) {
	t.Helper()
	var o overviewResponse
	rec := getAs(t, h, user, path, &o)
	if rec.Code != 200 {
		t.Fatalf("%s as %q = %d %s", path, user, rec.Code, rec.Body.String())
	}
	return o, rec
}

// sensitiveEvents adds activity the overview counts to the tenant store:
// exec in team-a and in team-b (production), secret reads, an RBAC change
// without a namespace and a denied request.
func sensitiveEvents(t *testing.T, s *Server) {
	t.Helper()
	st := s.Audit.(*audit.Ingester).Store
	add := func(id string, ago time.Duration, user, verb, resource, sub, ns string, code int) {
		e := audit.Event{AuditID: id, Time: now.Add(-ago), Stage: "ResponseComplete", Verb: verb, Username: user,
			ActorKind: audit.ClassifyActor(user, audit.DefaultSystemPrefixes), Resource: resource, Subresource: sub, Namespace: ns, StatusCode: code}
		if resource == "clusterrolebindings" {
			e.APIGroup = "rbac.authorization.k8s.io"
		}
		e.Tags = audit.Classify(e)
		st.Add(e)
	}
	add("x1", time.Minute, "alice", "create", "pods", "exec", "team-a", 101)
	add("x2", 2*time.Minute, "bob", "create", "pods", "exec", "team-b", 101)
	add("x3", 3*time.Minute, "bob", "create", "pods", "exec", "team-b", 101)
	add("s1", 4*time.Minute, "alice", "get", "secrets", "", "team-a", 200)
	add("s2", 5*time.Minute, "system:serviceaccount:team-b:app", "get", "secrets", "", "team-b", 200)
	add("r1", 6*time.Minute, "erin", "create", "clusterrolebindings", "", "", 201)
	add("d1", 7*time.Minute, "mallory", "get", "secrets", "", "team-a", 403)
	add("old", 30*time.Hour, "alice", "create", "pods", "exec", "team-a", 101)
}

// Everything on the overview reflects only what the caller may see; carol,
// who holds nothing, gets zeros and nulls rather than errors; filters
// narrow within the scope; and cached answers never cross callers.
func TestOverviewScoping(t *testing.T) {
	s := tenantServer(t)
	sensitiveEvents(t, s)
	h := s.Handler()

	alice, _ := getOverview(t, h, "alice", "/api/v1/overview")
	if alice.Scope.Namespaces != 1 || alice.Pods.Total != 3 || alice.Workloads.Total != 1 || alice.Certificates == nil || alice.Certificates.Total != 2 {
		t.Errorf("alice's tiles: scope %+v pods %+v workloads %+v certs %+v", alice.Scope, alice.Pods, alice.Workloads, alice.Certificates)
	}
	if alice.Nodes != nil {
		t.Errorf("alice (no nodes capability) sees nodes: %+v", alice.Nodes)
	}
	if strings.Join(alice.Owners, ",") != "team-alpha" {
		t.Errorf("alice's owners = %v", alice.Owners)
	}
	if alice.Waste.UnusedPVCs != 1 {
		t.Errorf("alice's waste = %+v", alice.Waste)
	}
	if alice.Health.Agents != nil || alice.Health.Prometheus != "ok" || alice.Health.AuditStore != "ok" {
		t.Errorf("alice's health = %+v", alice.Health)
	}
	// Security counts agree with /security for every caller.
	for _, user := range []string{"alice", "bob", "carol"} {
		var sec securityResponse
		getAs(t, h, user, "/api/v1/security?view=summary", &sec)
		o, _ := getOverview(t, h, user, "/api/v1/overview")
		if o.Security.Crit != sec.Counts["crit"] || o.Security.Warn != sec.Counts["warn"] {
			t.Errorf("%s: overview security %+v, /security counts %v", user, o.Security, sec.Counts)
		}
		for _, a := range o.Attention {
			if user != "alice" && user != "bob" || a.Namespace == "" {
				t.Errorf("%s sees attention item %+v", user, a)
			}
		}
	}

	// Activity: alice reads audit events in team-a only.
	// The denied secret read counts as a secret read too, as the audit summary counts it.
	if a := alice.Activity; a == nil || a.Exec != 1 || a.SecretReads != 2 || a.Denied != 1 || a.RBACChanges != 0 || a.ExecProduction != 0 || a.WindowHours != 24 {
		t.Errorf("alice's activity = %+v", alice.Activity)
	} else {
		for _, e := range a.Latest {
			if e.Namespace != "team-a" {
				t.Errorf("alice's latest activity includes %+v", e)
			}
		}
		if len(a.Latest) != 2 || a.Latest[0].AuditID != "x1" || a.Latest[1].AuditID != "d1" {
			t.Errorf("alice's latest = %+v", a.Latest)
		}
	}

	bob, _ := getOverview(t, h, "bob", "/api/v1/overview")
	if bob.Nodes == nil || bob.Nodes.Total != 2 || bob.Activity != nil || strings.Join(bob.Owners, ",") != "team-beta" ||
		strings.Join(bob.Namespaces, ",") != "team-b" {
		t.Errorf("bob: nodes %+v activity %+v owners %v namespaces %v", bob.Nodes, bob.Activity, bob.Owners, bob.Namespaces)
	}

	carol, _ := getOverview(t, h, "carol", "/api/v1/overview")
	if carol.Scope.Namespaces != 0 || carol.Pods.Total != 0 || carol.Workloads.Total != 0 || carol.Nodes != nil || carol.Activity != nil ||
		len(carol.Attention) != 0 || len(carol.Owners) != 0 || len(carol.Badges) != 0 || carol.Security != (overviewSecurity{}) ||
		carol.Certificates == nil || carol.Certificates.Total != 0 || carol.Waste != (overviewWaste{}) || carol.Health.Agents != nil {
		t.Errorf("carol = %+v", carol)
	}

	// Unrestricted sees more than alice, including production exec and the
	// cluster-scoped RBAC change.
	u := tenantServer(t)
	sensitiveEvents(t, u)
	u.Authenticator = nil
	all, _ := getOverview(t, u.Handler(), "", "/api/v1/overview")
	if all.Pods.Total != 9 || all.Scope.Namespaces != 3 || all.Security.Crit <= alice.Security.Crit || strings.Join(all.Owners, ",") != "team-alpha,team-beta" {
		t.Errorf("unrestricted: pods %+v scope %+v security %+v owners %v", all.Pods, all.Scope, all.Security, all.Owners)
	}
	if a := all.Activity; a == nil || a.Exec != 3 || a.ExecProduction != 2 || a.RBACChanges != 1 || a.SecretReads != 3 ||
		strings.Join(a.ProductionNamespaces, ",") != "team-b" {
		t.Errorf("unrestricted activity = %+v", all.Activity)
	}
	if strings.Join(all.Namespaces, ",") != "kube-system,team-a,team-b" {
		t.Errorf("unrestricted namespaces = %v", all.Namespaces)
	}
	if all.Health.Agents == nil || all.Health.Agents.Reporting != 3 {
		t.Errorf("unrestricted health = %+v", all.Health)
	}

	// Filters narrow within the scope, never beyond it.
	for _, path := range []string{"/api/v1/overview?namespace=team-a", "/api/v1/overview?owner=team-alpha", "/api/v1/overview?owner=team-alpha&namespace=team-a"} {
		o, _ := getOverview(t, h, "alice", path)
		if o.Scope.Namespaces != 1 || o.Pods.Total != 3 || o.Activity == nil || o.Activity.Exec != 1 {
			t.Errorf("%s as alice: scope %+v pods %+v activity %+v", path, o.Scope, o.Pods, o.Activity)
		}
	}
	for _, path := range []string{"/api/v1/overview?namespace=team-b", "/api/v1/overview?owner=team-beta", "/api/v1/overview?owner=nobody",
		"/api/v1/overview?owner=team-alpha&namespace=team-b"} {
		o, _ := getOverview(t, h, "alice", path)
		if o.Scope.Namespaces != 0 || o.Pods.Total != 0 || len(o.Attention) != 0 || len(o.Badges) != 0 || o.Security != (overviewSecurity{}) ||
			o.Activity == nil || o.Activity.Exec != 0 || len(o.Activity.Latest) != 0 || strings.Join(o.Owners, ",") != "team-alpha" ||
			strings.Join(o.Namespaces, ",") != "team-a" {
			t.Errorf("%s as alice = %+v", path, o)
		}
	}
	// A filter leaves cluster-scoped findings and events out.
	f, _ := getOverview(t, u.Handler(), "", "/api/v1/overview?owner=team-beta")
	if f.Scope.Namespaces != 1 || f.Scope.Owner != "team-beta" || f.Activity == nil || f.Activity.RBACChanges != 0 || f.Activity.ExecProduction != 2 {
		t.Errorf("owner filter: scope %+v activity %+v", f.Scope, f.Activity)
	}
	for _, a := range f.Attention {
		if a.Namespace != "team-b" {
			t.Errorf("owner filter shows %+v", a)
		}
	}

	// Bad parameters.
	for _, path := range []string{"/api/v1/overview?namespace=Team_A", "/api/v1/overview?owner=a%00b"} {
		if rec := getAs(t, h, "alice", path, nil); rec.Code != 400 {
			t.Errorf("%s = %d, want 400", path, rec.Code)
		}
	}
}

// The response cache keys the overview by every capability it depends on:
// alice's cached answer never reaches bob or carol, and a repeat is a hit.
func TestOverviewResponseCacheIsolatesCallers(t *testing.T) {
	s := tenantServer(t)
	h := s.Handler()
	_, rec := getOverview(t, h, "alice", "/api/v1/overview")
	if rec.Header().Get("X-Kubesentry-Cache") != "miss" {
		t.Errorf("first request: cache %q", rec.Header().Get("X-Kubesentry-Cache"))
	}
	if _, rec := getOverview(t, h, "alice", "/api/v1/overview"); rec.Header().Get("X-Kubesentry-Cache") != "hit" {
		t.Error("the second request was not served from the cache")
	}
	for _, user := range []string{"bob", "carol"} {
		_, rec := getOverview(t, h, user, "/api/v1/overview")
		if nss, _ := namespacesIn(rec.Body.Bytes()); nss["team-a"] > 0 {
			t.Errorf("%s got alice's overview: %s", user, rec.Body.String())
		}
	}
	// The capabilities the cache key covers are all the overview reads.
	for _, c := range []auth.Capability{auth.ViewNamespace, auth.ViewNodes, auth.ViewRBAC, auth.ViewClusterRBAC, auth.ViewAudit, auth.ViewClusterAudit, auth.ViewAgents} {
		found := false
		for _, have := range cachedRoutes["GET /api/v1/overview"] {
			found = found || have == c
		}
		if !found {
			t.Errorf("cachedRoutes misses %s/%s", c.Group, c.Resource)
		}
	}
	// A cached overview ages out with its window, so health and activity stay fresh.
	later := now.Add(overviewCacheWindow)
	s.Now = func() time.Time { return later }
	if _, rec := getOverview(t, h, "alice", "/api/v1/overview"); rec.Header().Get("X-Kubesentry-Cache") != "miss" {
		t.Error("an overview from an earlier window was served")
	}
}

// attentionServer serves an unrestricted cluster built to exercise ranking
// and folding: a node down, a crash-looping privileged Deployment that also
// leaks, a healthy one that leaks fast, a certificate expiring and twelve
// half-ready Deployments.
func attentionServer() *Server {
	inv := model.Inventory{Unavailable: map[string]string{}}
	old := now.Add(-72 * time.Hour)
	inv.Nodes = []model.Node{
		{Name: "n-up", Ready: true},
		{Name: "n-down", Ready: false, Conditions: []model.Condition{{Type: "Ready", Status: "Unknown", Message: "Kubelet stopped posting node status.", LastTransition: now.Add(-2 * time.Hour)}}},
	}
	inv.Namespaces = []model.Namespace{{Name: "shop", Annotations: map[string]string{"kubesentry.io/owner": "team-shop"}}}
	dep := func(ns, name string, desired, ready int32) {
		inv.Workloads = append(inv.Workloads, model.Workload{Kind: "Deployment", Namespace: ns, Name: name, Desired: desired, Ready: ready,
			Updated: desired, Available: ready, Selector: &model.LabelSelector{MatchLabels: map[string]string{"app": name}}, Created: old})
	}
	pod := func(ns, name, app string, crash bool) {
		p := model.Pod{UID: ns + "/" + name, Namespace: ns, Name: name, Phase: "Running", NodeName: "n-up", Labels: map[string]string{"app": app}, Created: old,
			Ready: !crash, Specs: []model.ContainerSpec{{Name: "c", RunAsNonRoot: true, MemoryLimitBytes: 1 << 30, AllowPrivilegeEscalation: new(bool)}},
			Containers: []model.ContainerStatus{{Name: "c", State: "running", Ready: !crash}}}
		if crash {
			p.ReadyChanged = now.Add(-30 * time.Minute)
			p.Specs[0].Privileged = true
			p.Containers[0] = model.ContainerStatus{Name: "c", State: "waiting", Reason: "CrashLoopBackOff", RestartCount: 5}
		}
		inv.Pods = append(inv.Pods, p)
	}
	dep("shop", "api", 2, 0)
	pod("shop", "api-1", "api", true)
	pod("shop", "api-2", "api", true)
	dep("shop", "worker", 1, 1)
	pod("shop", "worker-1", "worker", false)
	for i := 0; i < 12; i++ {
		ns := fmt.Sprintf("t%02d", i)
		dep(ns, "web", 2, 1)
		pod(ns, "web-1", "web", false)
	}
	inv.Certs = model.CertManager{Installed: true, Certificates: []model.Certificate{
		{Namespace: "shop", Name: "tls", IssuerKind: "External", Ready: "True", NotAfter: now.Add(20 * 24 * time.Hour), Duration: 90 * 24 * time.Hour},
	}}
	ttl := func(h float64) *float64 { return &h }
	m := leakMetrics{rep: detectors.LeakReport{GeneratedAt: now, Findings: []detectors.LeakFinding{
		{ContainerKey: model.ContainerKey{Namespace: "shop", Pod: "api-1", Container: "c"}, SlopeBytesPerHour: 8 << 20, TimeToLimitHours: ttl(10)},
		{ContainerKey: model.ContainerKey{Namespace: "shop", Pod: "worker-1", Container: "c"}, SlopeBytesPerHour: 64 << 20, TimeToLimitHours: ttl(3)},
	}}}
	return &Server{Views: currentView{snapshot.Build(inv, detectors.DefaultPolicy(), now)}, Metrics: m, Now: func() time.Time { return now },
		ResponseCache: &ResponseCache{}}
}

func TestOverviewAttentionRankingAndFolding(t *testing.T) {
	o, _ := getOverview(t, attentionServer().Handler(), "", "/api/v1/overview")
	if len(o.Attention) != attentionLimit {
		t.Fatalf("attention has %d items: %+v", len(o.Attention), o.Attention)
	}
	got := make([]string, len(o.Attention))
	for i, a := range o.Attention {
		got[i] = a.Severity + " " + a.Kind + " " + a.Namespace + "/" + a.Name
	}
	want := []string{
		"crit node-not-ready /n-down", // a node down first
		"crit crashloop shop/api",     // then workloads; its privileged pods and slow leak fold in
		"crit leak shop/worker",       // a leak reaching its limit within 6h
		"warn not-ready t00/web",      // then the warnings, in order
		"warn not-ready t01/web",
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("attention[%d] = %q, want %q (all: %v)", i, got[i], w, got)
		}
	}
	api := o.Attention[1]
	if api.Title != "CrashLoopBackOff ×2 (+2 more)" || api.Owner != "team-shop" || api.Since == nil || !api.Since.Equal(now.Add(-30*time.Minute)) ||
		api.Href != "#/workloads?namespace=shop&q=api" {
		t.Errorf("folded item = %+v", api)
	}
	if n := o.Attention[0]; n.Since == nil || n.Namespace != "" || n.Href != "#/nodes?node=n-down" || n.Owner != "" {
		t.Errorf("node item = %+v", n)
	}
	if l := o.Attention[2]; !strings.Contains(l.Title, "64 MiB/h") || !strings.Contains(l.Title, "~3h") || l.Href != "#/pods/shop/worker-1" {
		t.Errorf("leak item = %+v", l)
	}
	for _, a := range o.Attention {
		if a.Kind == "cert-expiring" {
			t.Errorf("a certificate warning outranks workload warnings: %v", got)
		}
	}

	// Badges count everything, not just the top 10; zero counts are left out.
	wantBadges := map[string]badge{
		"findings":     {16, "crit"}, // node, api, worker, 12 workloads, the certificate
		"workloads":    {13, "crit"},
		"pods":         {2, "crit"},
		"memory":       {2, "crit"},
		"certificates": {1, "warn"},
	}
	for k, b := range wantBadges {
		if o.Badges[k] != b {
			t.Errorf("badge %s = %+v, want %+v", k, o.Badges[k], b)
		}
	}
	if b, ok := o.Badges["security"]; !ok || b.Severity != "crit" || b.Count != o.Security.Crit+o.Security.Warn {
		t.Errorf("security badge = %+v, counts %+v", b, o.Security)
	}
	if o.Pods.Failing != 2 || o.Pods.ByReason["CrashLoopBackOff"] != 2 || o.Pods.Running != 13 {
		t.Errorf("pods = %+v", o.Pods)
	}
	if o.Certificates == nil || o.Certificates.ExpiringSoon != 0 || o.Certificates.Total != 1 {
		t.Errorf("certificates = %+v", o.Certificates)
	}
	if o.Nodes == nil || o.Nodes.NotReady != 1 || o.Nodes.Ready != 1 {
		t.Errorf("nodes = %+v", o.Nodes)
	}

	// A filter keeps a node only when it runs the selected pods.
	f, _ := getOverview(t, attentionServer().Handler(), "", "/api/v1/overview?namespace=t03")
	if len(f.Attention) != 1 || f.Attention[0].Namespace != "t03" || f.Badges["findings"] != (badge{1, "warn"}) {
		t.Errorf("filtered attention = %+v badges %+v", f.Attention, f.Badges)
	}
}

func TestOverviewBadgesOmitZero(t *testing.T) {
	inv := model.Inventory{Unavailable: map[string]string{}, Namespaces: []model.Namespace{{Name: "calm"}}}
	inv.Workloads = []model.Workload{{Kind: "Deployment", Namespace: "calm", Name: "web", Desired: 1, Ready: 1, Updated: 1, Available: 1,
		Selector: &model.LabelSelector{MatchLabels: map[string]string{"app": "web"}}}}
	no := false
	inv.Pods = []model.Pod{{Namespace: "calm", Name: "web-1", Phase: "Running", Ready: true, Labels: map[string]string{"app": "web"}, Created: now.Add(-time.Hour),
		Specs:      []model.ContainerSpec{{Name: "c", RunAsNonRoot: true, MemoryLimitBytes: 1 << 30, AllowPrivilegeEscalation: &no}},
		Containers: []model.ContainerStatus{{Name: "c", State: "running", Ready: true}}}}
	inv.Namespaces[0].Labels = map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}
	s := &Server{Views: snapshot.Static(snapshot.Build(inv, detectors.DefaultPolicy(), now)), Now: func() time.Time { return now }}
	o, rec := getOverview(t, s.Handler(), "", "/api/v1/overview")
	if len(o.Badges) != 0 || len(o.Attention) != 0 || o.Certificates != nil {
		t.Errorf("a calm cluster: badges %+v attention %+v certificates %+v", o.Badges, o.Attention, o.Certificates)
	}
	if !strings.Contains(rec.Body.String(), `"badges":{}`) || !strings.Contains(rec.Body.String(), `"certificates":null`) ||
		!strings.Contains(rec.Body.String(), `"activity":null`) || !strings.Contains(rec.Body.String(), `"attention":[]`) {
		t.Errorf("empty values must be {} and [], absent ones null: %s", rec.Body.String())
	}
	if o.Health.Prometheus != "none" || o.Health.AuditStore != "none" {
		t.Errorf("health without sources = %+v", o.Health)
	}
}

// The history is the caller's share, and "new since 24h" appears once the
// history reaches back a full day.
func TestOverviewHistory(t *testing.T) {
	s := tenantServer(t)
	h := snapshot.NewHistory(time.Hour, 24)
	start := now.Add(-23 * time.Hour)
	for i := 0; i < 24; i++ {
		h.RecordCounts(start.Add(time.Duration(i)*time.Hour), map[snapshot.CountKey]snapshot.Counts{
			{Namespace: "team-a"}:                   {snapshot.SecurityCrit: 1, snapshot.FailingPods: int32(i % 3)},
			{Namespace: "team-b"}:                   {snapshot.SecurityCrit: 5},
			{Namespace: "team-a", RBAC: true}:       {snapshot.SecurityWarn: 7},
			{Namespace: ""}:                         {snapshot.SecurityCrit: 100},
			{Namespace: "kube-system", RBAC: false}: {snapshot.UnhealthyWorkloads: 2},
		})
	}
	s.History = h
	o, _ := getOverview(t, s.Handler(), "alice", "/api/v1/overview")
	hist := o.History
	if hist.StepSeconds != 3600 || !hist.Start.Equal(start.Truncate(time.Hour)) || len(hist.Series["securityCrit"]) != 24 {
		t.Fatalf("history = %+v", hist)
	}
	for i, v := range hist.Series["securityCrit"] {
		if v != 1 {
			t.Fatalf("alice's securityCrit[%d] = %d, want team-a's 1", i, v)
		}
	}
	for i, v := range hist.Series["securityWarn"] {
		if v != 0 {
			t.Fatalf("alice (no ViewRBAC) sees RBAC warnings in history[%d] = %d", i, v)
		}
	}
	if hist.Series["failingPods"][2] != 2 || hist.Series["unhealthyWorkloads"][0] != 0 {
		t.Errorf("alice's history = %v", hist.Series)
	}
	// 1 crit + 3 warn now against 1 crit a day ago.
	if o.Security.NewSince24h == nil || *o.Security.NewSince24h != o.Security.Crit+o.Security.Warn-1 {
		t.Errorf("newSince24h = %v, security %+v", o.Security.NewSince24h, o.Security)
	}

	// Unrestricted sees everything, from the total ring.
	s.Authenticator = nil
	all, _ := getOverview(t, s.Handler(), "", "/api/v1/overview")
	if got := all.History.Series["securityCrit"][0]; got != 106 {
		t.Errorf("unrestricted securityCrit = %d, want 106", got)
	}
	if got := all.History.Series["securityWarn"][0]; got != 7 {
		t.Errorf("unrestricted securityWarn = %d, want 7", got)
	}

	// Less than a day of history: no "new since 24h".
	short := snapshot.NewHistory(time.Hour, 24)
	short.RecordCounts(now.Add(-2*time.Hour), map[snapshot.CountKey]snapshot.Counts{{Namespace: "team-a"}: {snapshot.SecurityCrit: 1}})
	s = tenantServer(t) // a fresh response cache
	s.Authenticator = nil
	s.History = short
	o, _ = getOverview(t, s.Handler(), "", "/api/v1/overview")
	if o.Security.NewSince24h != nil || len(o.History.Series["securityCrit"]) != 3 {
		t.Errorf("short history: newSince24h %v, series %v", o.Security.NewSince24h, o.History.Series)
	}
}

// An audit store that does not answer leaves activity null, and the answer
// is not cached.
func TestOverviewActivityStoreFailure(t *testing.T) {
	s := tenantServer(t)
	s.Authenticator = nil
	s.Audit = activeBackend{overloadedStore{}}
	o, rec := getOverview(t, s.Handler(), "", "/api/v1/overview")
	if o.Activity != nil || rec.Header().Get("Cache-Control") != "no-store" || s.ResponseCache.Len() != 0 {
		t.Errorf("activity %+v, cache-control %q, cached %d", o.Activity, rec.Header().Get("Cache-Control"), s.ResponseCache.Len())
	}
}

func TestOverviewEncodesTheContract(t *testing.T) {
	s := tenantServer(t)
	s.Authenticator = nil
	sensitiveEvents(t, s)
	s.History = snapshot.NewHistory(0, 0)
	s.History.Record(s.Views.(currentView).v)
	_, rec := getOverview(t, s.Handler(), "", "/api/v1/overview")
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	// Every field of web/src/types.ts OverviewResponse.
	for _, k := range []string{"version", "builtAt", "ageSeconds", "scope", "namespaces", "health", "nodes", "pods", "workloads", "certificates",
		"security", "attention", "activity", "waste", "owners", "badges", "history"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("response lacks %q", k)
		}
	}
	var hist struct {
		StepSeconds int                `json:"stepSeconds"`
		Start       string             `json:"start"`
		Series      map[string][]int64 `json:"series"`
	}
	_ = json.Unmarshal(raw["history"], &hist)
	for _, name := range []string{"unhealthyWorkloads", "failingPods", "securityCrit", "securityWarn", "certsExpiringSoon"} {
		if len(hist.Series[name]) != 1 {
			t.Errorf("history series %s = %v", name, hist.Series[name])
		}
	}
	var act map[string]json.RawMessage
	_ = json.Unmarshal(raw["activity"], &act)
	for _, k := range []string{"windowHours", "exec", "execProduction", "secretReads", "rbacChanges", "denied", "latest", "productionNamespaces"} {
		if _, ok := act[k]; !ok {
			t.Errorf("activity lacks %q", k)
		}
	}
}
