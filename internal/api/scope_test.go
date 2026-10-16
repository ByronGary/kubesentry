package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/auth"
	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/model"
	"github.com/ByronGary/kubesentry/internal/procmon"
	"github.com/ByronGary/kubesentry/internal/snapshot"
)

// grantReviewer answers SubjectAccessReviews from a fixed table of
// "user|verb|group|resource|namespace" grants; everything else is denied. A
// subresource is part of the resource, as "pods/log".
type grantReviewer map[string]bool

func (g grantReviewer) Review(_ context.Context, user string, _ []string, verb, group, resource, subresource, ns string) (bool, error) {
	if subresource != "" {
		resource += "/" + subresource
	}
	return g[user+"|"+verb+"|"+group+"|"+resource+"|"+ns], nil
}

func grant(user string, c auth.Capability, ns string) string {
	resource := c.Resource
	if c.Subresource != "" {
		resource += "/" + c.Subresource
	}
	return user + "|" + c.Verb + "|" + c.Group + "|" + resource + "|" + ns
}

// currentView is a ViewProvider that also reports its view, as
// snapshot.Manager does, so the response cache is enabled.
type currentView struct{ v *snapshot.View }

func (c currentView) View(context.Context) (*snapshot.View, error) { return c.v, nil }
func (c currentView) Current() *snapshot.View                      { return c.v }

var tenants = []string{"team-a", "team-b", "kube-system"}

// tenantInventory has the same objects in every namespace of tenants, so any
// object from a namespace the caller may not see shows up in a list.
func tenantInventory() model.Inventory {
	inv := model.Inventory{Unavailable: map[string]string{}}
	old := now.Add(-72 * time.Hour)
	inv.Nodes = []model.Node{{Name: "n1", Ready: true}, {Name: "n2", Ready: true}}
	inv.StorageClasses = []model.StorageClass{{Name: "gp3", Provisioner: "ebs.csi.aws.com", Parameters: map[string]string{"type": "gp3"}, Default: true}}
	inv.Certs.Installed = true
	inv.Certs.Issuers = append(inv.Certs.Issuers, model.Issuer{Kind: "ClusterIssuer", Name: "le", Type: "acme", Ready: "True"})
	for i, ns := range tenants {
		// team-a and team-b have owners, team-b runs production.
		owners := map[string]string{"team-a": "team-alpha", "team-b": "team-beta"}
		n := model.Namespace{Name: ns}
		if o := owners[ns]; o != "" {
			n.Annotations = map[string]string{"kubesentry.io/owner": o}
		}
		if ns == "team-b" {
			n.Labels = map[string]string{"environment": "production"}
		}
		inv.Namespaces = append(inv.Namespaces, n)
		dep := model.Workload{Kind: "Deployment", Namespace: ns, Name: "web", UID: "dep-" + ns, Desired: 3, Ready: 3, Updated: 3, Available: 3,
			Selector: &model.LabelSelector{MatchLabels: map[string]string{"app": "web"}}}
		inv.Workloads = append(inv.Workloads, dep)
		inv.ReplicaSets = append(inv.ReplicaSets, model.ReplicaSet{Namespace: ns, Name: "web-1", UID: "rs-" + ns,
			Owners: []model.OwnerRef{{Kind: "Deployment", Name: "web", UID: dep.UID, Controller: true}}})
		for j := 0; j < 3; j++ {
			p := model.Pod{UID: fmt.Sprintf("%s-%d", ns, j), Namespace: ns, Name: fmt.Sprintf("web-%d", j), Phase: "Running", Ready: true,
				NodeName: fmt.Sprintf("n%d", 1+(i+j)%2), Labels: map[string]string{"app": "web"}, Created: old,
				Owners:     []model.OwnerRef{{Kind: "ReplicaSet", Name: "web-1", UID: "rs-" + ns, Controller: true}},
				Specs:      []model.ContainerSpec{{Name: "web", Privileged: j == 0}},
				Containers: []model.ContainerStatus{{Name: "web", State: "running", Ready: true, ContainerID: fmt.Sprintf("cid-%s-%d", ns, j)}}}
			if j == 1 {
				p.Containers[0].LastTerminatedReason, p.Containers[0].LastTerminatedAt, p.Containers[0].RestartCount = "OOMKilled", now.Add(-time.Hour), 2
			}
			if j == 2 {
				p.Claims = []string{"data"}
			}
			inv.Pods = append(inv.Pods, p)
		}
		for _, c := range []string{"data", "orphan"} {
			inv.PVCs = append(inv.PVCs, model.PVC{Namespace: ns, Name: c, Phase: "Bound", StorageClass: "gp3", CapacityBytes: 10 << 30,
				VolumeName: "pv-" + ns + "-" + c, Created: old})
			inv.PVs = append(inv.PVs, model.PV{Name: "pv-" + ns + "-" + c, Phase: "Bound", StorageClass: "gp3", ClaimNamespace: ns, ClaimName: c, CapacityBytes: 10 << 30})
		}
		inv.Services = append(inv.Services, model.Service{Namespace: ns, Name: "web", Type: "NodePort", Selector: map[string]string{"app": "web"},
			Ports: []model.ServicePort{{Port: 80, NodePort: int32(30080 + i)}}})
		inv.Certs.Certificates = append(inv.Certs.Certificates,
			model.Certificate{Namespace: ns, Name: "tls", IssuerKind: "ClusterIssuer", IssuerName: "le", Ready: "True", NotAfter: now.Add(80 * 24 * time.Hour)},
			model.Certificate{Namespace: ns, Name: "local", IssuerKind: "Issuer", IssuerName: "self", Ready: "True", NotAfter: now.Add(80 * 24 * time.Hour)})
		inv.Certs.Issuers = append(inv.Certs.Issuers, model.Issuer{Kind: "Issuer", Namespace: ns, Name: "self", Type: "selfSigned", Ready: "True"})
		inv.Certs.Requests = append(inv.Certs.Requests, model.CertificateRequest{Namespace: ns, Name: "tls-1", Certificate: "tls",
			IssuerKind: "ClusterIssuer", IssuerName: "le", Ready: "False", Reason: "Failed", Created: old})
	}
	// alice is bound to view pods in team-a and, by a binding the API server
	// does not honour (the reviewer says no), in team-b; bob views team-b.
	inv.RBAC = model.RBAC{
		Roles: []model.Role{
			{Kind: "ClusterRole", Name: "view", Rules: []model.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list"}}}},
			{Kind: "ClusterRole", Name: "kubesentry-viewer", Rules: []model.PolicyRule{
				{APIGroups: []string{"kubesentry.io"}, Resources: []string{"auditevents", "processes"}, Verbs: []string{"get", "list"}}}},
			{Kind: "ClusterRole", Name: "cluster-admin", Rules: []model.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}}},
			{Kind: "ClusterRole", Name: "rbac-reader", Rules: []model.PolicyRule{
				{APIGroups: []string{"rbac.authorization.k8s.io"}, Resources: []string{"rolebindings"}, Verbs: []string{"list"}}}},
		},
		Bindings: []model.RoleBinding{
			// The reviewer confirms this one only where a test grants it.
			{Kind: "RoleBinding", Namespace: "team-a", Name: "alice-rbac", RoleKind: "ClusterRole", RoleName: "rbac-reader", Subjects: []model.Subject{{Kind: "User", Name: "alice"}}},
			{Kind: "RoleBinding", Namespace: "team-a", Name: "alice-view", RoleKind: "ClusterRole", RoleName: "view", Subjects: []model.Subject{{Kind: "User", Name: "alice"}}},
			{Kind: "RoleBinding", Namespace: "team-a", Name: "alice-ks", RoleKind: "ClusterRole", RoleName: "kubesentry-viewer", Subjects: []model.Subject{{Kind: "User", Name: "alice"}}},
			{Kind: "RoleBinding", Namespace: "team-b", Name: "alice-stale", RoleKind: "ClusterRole", RoleName: "view", Subjects: []model.Subject{{Kind: "User", Name: "alice"}}},
			{Kind: "RoleBinding", Namespace: "team-b", Name: "bob-view", RoleKind: "ClusterRole", RoleName: "view", Subjects: []model.Subject{{Kind: "User", Name: "bob"}}},
			{Kind: "ClusterRoleBinding", Name: "erin-admin", RoleKind: "ClusterRole", RoleName: "cluster-admin", Subjects: []model.Subject{{Kind: "User", Name: "erin"}}},
		},
	}
	// A namespaced RBAC finding in every namespace: cluster-admin bound in it.
	for _, ns := range tenants {
		inv.RBAC.Bindings = append(inv.RBAC.Bindings, model.RoleBinding{Kind: "RoleBinding", Namespace: ns, Name: "ns-admins",
			RoleKind: "ClusterRole", RoleName: "cluster-admin", Subjects: []model.Subject{{Kind: "Group", Name: ns + "-admins"}}})
	}
	return inv
}

func tenantGrants() grantReviewer {
	return grantReviewer{
		grant("alice", auth.ViewNamespace, "team-a"): true,
		grant("alice", auth.ViewAudit, "team-a"):     true,
		grant("alice", auth.ViewProcesses, "team-a"): true,
		grant("bob", auth.ViewNamespace, "team-b"):   true,
		grant("bob", auth.ViewNodes, ""):             true,
	}
}

// tenantServer serves tenantInventory in proxy mode: the identity comes from
// X-Forwarded-Email, trusted from httptest's 192.0.2.1.
func tenantServer(t *testing.T) *Server {
	t.Helper()
	v := snapshot.Build(tenantInventory(), detectors.DefaultPolicy(), now)
	st := audit.NewMemoryStore(100)
	for i, ns := range append([]string{""}, tenants...) {
		for j := 0; j < 3; j++ {
			st.Add(audit.Event{AuditID: fmt.Sprintf("e-%d-%d", i, j), Time: now.Add(-time.Duration(10*i+j) * time.Minute), Stage: "ResponseComplete",
				Verb: "delete", Username: "dave", ActorKind: "user", Resource: "pods", Namespace: ns, Name: "web-0", StatusCode: 200, Tags: []string{audit.TagDelete}})
		}
	}
	procs := procmon.NewStore()
	procs.Now = func() time.Time { return now }
	for _, ns := range tenants {
		procs.Update(procmon.Report{Node: "n-" + ns, Processes: []procmon.Process{{PID: 1, Name: "web", PodUID: ns + "-0"}}})
	}
	var series []model.ContainerSeries
	for _, ns := range tenants {
		series = append(series, model.ContainerSeries{Key: model.ContainerKey{Namespace: ns, Pod: "web-1", Container: "web"}, Samples: leakySeries()[0].Samples})
	}
	return &Server{
		Views:         currentView{v},
		Metrics:       fakeMetrics{series: series, limits: map[model.ContainerKey]float64{}},
		Audit:         &audit.Ingester{Store: st},
		Processes:     procs,
		PVCOptions:    detectors.PVCOptions{MinAge: time.Hour},
		LeakOptions:   detectors.DefaultLeakOptions(),
		Now:           func() time.Time { return now },
		ResponseCache: &ResponseCache{},
		Authenticator: auth.HeaderAuthenticator{UserHeader: "X-Forwarded-Email", GroupsHeader: "X-Forwarded-Groups",
			TrustedProxies: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}},
		Authorizer: &auth.SARAuthorizer{Reviewer: tenantGrants(), Candidates: v.RBAC()},
		Alerts:     newStaticAlerts(tenantFindings()),
	}
}

// getAs sends GET path as user (through the trusted proxy) and decodes the body.
func getAs(t *testing.T, h http.Handler, user, path string, out any) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if user != "" {
		req.Header.Set("X-Forwarded-Email", user)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if out != nil && rec.Code == 200 {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
	}
	return rec
}

// allPages follows continue tokens with limit=1 and returns every page body.
func allPages(t *testing.T, h http.Handler, user, path string) []json.RawMessage {
	t.Helper()
	var pages []json.RawMessage
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	next := path + sep + "limit=1"
	for i := 0; i < 100; i++ {
		rec := getAs(t, h, user, next, nil)
		if rec.Code != 200 {
			t.Fatalf("%s as %s = %d %s", next, user, rec.Code, rec.Body.String())
		}
		pages = append(pages, json.RawMessage(rec.Body.Bytes()))
		var p struct{ Continue string }
		_ = json.Unmarshal(rec.Body.Bytes(), &p)
		if p.Continue == "" {
			return pages
		}
		next = path + sep + "limit=1&continue=" + p.Continue
	}
	t.Fatalf("%s: no end to the pages", path)
	return nil
}

// namespacesIn collects every "namespace" value in a JSON document, and
// counts the objects that carry one.
func namespacesIn(raw json.RawMessage) (map[string]int, int) {
	var v any
	_ = json.Unmarshal(raw, &v)
	out := map[string]int{}
	n := 0
	var walk func(any)
	walk = func(x any) {
		switch x := x.(type) {
		case map[string]any:
			if ns, ok := x["namespace"].(string); ok && ns != "" {
				out[ns]++
				n++
			}
			for _, y := range x {
				walk(y)
			}
		case []any:
			for _, y := range x {
				walk(y)
			}
		}
	}
	walk(v)
	return out, n
}

// The authorization leak matrix: every list route, at every page, shows
// alice only team-a (the reviewer confirms nothing else, even where an RBAC
// binding proposes it), cluster-scoped data degrades without its
// capability, and carol, who holds nothing, gets empty lists.
func TestNoAuthorizationLeaks(t *testing.T) {
	s, _ := withTenantIncidents(t, tenantServer(t))
	h := s.Handler()
	routes := []string{
		"/api/v1/pods", "/api/v1/workloads", "/api/v1/storage", "/api/v1/security", "/api/v1/security?view=summary",
		"/api/v1/map", "/api/v1/map?namespace=team-a", "/api/v1/certificates", "/api/v1/pvcs/unused", "/api/v1/audit/events",
		"/api/v1/nodes", "/api/v1/nodes?summary=true", "/api/v1/nodes/n1", "/api/v1/oom", "/api/v1/audit/summary",
		"/api/v1/overview", "/api/v1/overview?namespace=team-a", "/api/v1/overview?owner=team-alpha",
		"/api/v1/alerts", "/api/v1/alerts?state=open", "/api/v1/alerts?owner=team-alpha", "/api/v1/alerts/actions",
		"/api/v1/incidents", "/api/v1/incidents?state=open", "/api/v1/incidents?state=resolved", "/api/v1/incidents?owner=team-alpha",
		"/api/v1/incidents?namespace=team-a", "/api/v1/incidents?type=oom-kill", "/api/v1/incidents?type=eviction",
		"/api/v1/incidents?window=1h&severity=critical",
	}
	for _, route := range routes {
		seen := 0
		for _, page := range allPages(t, h, "alice", route) {
			nss, n := namespacesIn(page)
			for ns := range nss {
				if ns != "team-a" {
					t.Errorf("%s: alice sees namespace %q: %s", route, ns, page)
				}
			}
			seen += n
		}
		if seen == 0 && !strings.HasPrefix(route, "/api/v1/nodes") && !strings.HasPrefix(route, "/api/v1/audit/summary") &&
			!strings.HasSuffix(route, "type=eviction") {
			t.Errorf("%s: alice sees nothing of team-a either", route)
		}

		// carol holds nothing: empty lists, not errors (a namespace or node
		// she names is not found; the overview answers with zeros, echoing
		// only her own filter).
		if strings.HasPrefix(route, "/api/v1/overview") && strings.Contains(route, "namespace=") {
			var o overviewResponse
			if rec := getAs(t, h, "carol", route, &o); rec.Code != 200 {
				t.Errorf("%s as carol = %d, want 200", route, rec.Code)
			}
			o.Scope.Namespace = ""
			raw, _ := json.Marshal(o)
			if nss, _ := namespacesIn(raw); len(nss) > 0 || o.Scope.Namespaces != 0 || len(o.Namespaces) != 0 {
				t.Errorf("%s: carol sees %v: %s", route, nss, raw)
			}
			continue
		}
		if (strings.Contains(route, "namespace=") && !strings.HasPrefix(route, "/api/v1/incidents")) || strings.HasPrefix(route, "/api/v1/nodes/") {
			if rec := getAs(t, h, "carol", route, nil); rec.Code != 404 {
				t.Errorf("%s as carol = %d, want 404", route, rec.Code)
			}
			continue
		}
		for _, page := range allPages(t, h, "carol", route) {
			if nss, _ := namespacesIn(page); len(nss) > 0 {
				t.Errorf("%s: carol sees %v", route, nss)
			}
		}
	}

	// Cluster-scoped data degrades for alice.
	var nodes nodesResponse
	getAs(t, h, "alice", "/api/v1/nodes", &nodes)
	for _, n := range nodes.Items {
		if n.Status != detectors.StatusUnknown || n.CPUAllocatableMilli != 0 || len(n.Pods) == 0 {
			t.Errorf("alice's view of node %s = %+v", n.Name, n)
		}
	}
	var storage storageResponse
	getAs(t, h, "alice", "/api/v1/storage", &storage)
	for _, v := range storage.Volumes {
		if v.Status != detectors.StatusUnknown || !strings.HasPrefix(v.Claim, "team-a/") {
			t.Errorf("alice's volume = %+v", v)
		}
	}
	if len(storage.Volumes) != 2 || len(storage.Classes) != 1 || storage.Classes[0].Claims != 2 || storage.Classes[0].Provisioner != "" {
		t.Errorf("alice's volumes %+v classes %+v", storage.Volumes, storage.Classes)
	}
	var sec securityResponse
	getAs(t, h, "alice", "/api/v1/security?limit=1000", &sec)
	own := map[string]int{"crit": 0, "warn": 0, "info": 0}
	for _, f := range sec.Findings {
		if f.Namespace == "" {
			t.Errorf("alice sees a cluster-scoped finding: %+v", f)
		}
		if f.Category == "rbac" {
			t.Errorf("alice (pods, not rolebindings, in team-a) sees an RBAC finding: %+v", f)
		}
		if !f.System {
			own[f.Severity]++
		}
	}
	// The summary counts only what alice can see, on every view.
	var summary, all securityResponse
	getAs(t, h, "alice", "/api/v1/security?view=summary", &summary)
	unrestricted := tenantServer(t)
	unrestricted.Authenticator = nil
	getAs(t, unrestricted.Handler(), "", "/api/v1/security?view=summary", &all)
	for sev, n := range own {
		if summary.Counts[sev] != n || sec.Counts[sev] != n {
			t.Errorf("alice's %s count = %d (summary) / %d (list), her findings hold %d", sev, summary.Counts[sev], sec.Counts[sev], n)
		}
	}
	if all.Counts["crit"] <= summary.Counts["crit"] || all.Counts["warn"] <= summary.Counts["warn"] {
		t.Errorf("unrestricted counts %v should exceed alice's %v", all.Counts, summary.Counts)
	}
	var certs certificatesResponse
	getAs(t, h, "alice", "/api/v1/certificates", &certs)
	issuers := map[string]string{}
	for _, is := range certs.Issuers {
		issuers[is.Kind+"/"+is.Namespace+"/"+is.Name] = is.Status
	}
	if len(issuers) != 2 || issuers["ClusterIssuer//le"] != detectors.StatusUnknown || issuers["Issuer/team-a/self"] != detectors.StatusOK {
		t.Errorf("alice's issuers = %v", issuers)
	}
	var m mapResponse
	getAs(t, h, "alice", "/api/v1/map", &m)
	if m.Namespace != "team-a" || strings.Join(m.Namespaces, ",") != "team-a" {
		t.Errorf("alice's map = %s of %v", m.Namespace, m.Namespaces)
	}
	for _, n := range m.Graph.Nodes {
		if n.Kind == "Node" && n.Status != detectors.StatusUnknown {
			t.Errorf("alice's map node = %+v", n)
		}
	}
	var ev auditEventsResponse
	getAs(t, h, "alice", "/api/v1/audit/events?limit=1000", &ev)
	if ev.Count != 3 {
		t.Errorf("alice's audit events = %+v", ev.Items)
	}
	var sum auditSummaryResponse
	getAs(t, h, "alice", "/api/v1/audit/summary", &sum)
	if sum.TotalEvents != 3 {
		t.Errorf("alice's audit summary counts %d events, want team-a's 3", sum.TotalEvents)
	}
	var oom oomResponse
	getAs(t, h, "alice", "/api/v1/oom", &oom)
	if len(oom.Events) != 1 || len(oom.Leaks) != 1 || oom.Leaks[0].Namespace != "team-a" {
		t.Errorf("alice's oom = %+v", oom)
	}

	// The overview's aggregates are alice's own: they equal what her list
	// routes show, and every badge, owner and attention item is team-a's.
	var ov overviewResponse
	getAs(t, h, "alice", "/api/v1/overview", &ov)
	var pods podsResponse
	getAs(t, h, "alice", "/api/v1/pods?limit=1000", &pods)
	var wls workloadsResponse
	getAs(t, h, "alice", "/api/v1/workloads?limit=1000", &wls)
	var unused unusedPVCResponse
	getAs(t, h, "alice", "/api/v1/pvcs/unused", &unused)
	if ov.Scope.Namespaces != 1 || ov.Pods.Total != pods.Count || ov.Workloads.Total != wls.Count || ov.Waste.UnusedPVCs != unused.Count ||
		ov.Certificates == nil || ov.Certificates.Total != len(certs.Certificates) || ov.Nodes != nil {
		t.Errorf("alice's overview tiles %+v disagree with her lists: %d pods, %d workloads, %d unused claims, %d certificates",
			ov, pods.Count, wls.Count, unused.Count, len(certs.Certificates))
	}
	if ov.Security.Crit != sec.Counts["crit"] || ov.Security.Warn != sec.Counts["warn"] ||
		ov.Badges["security"].Count != sec.Counts["crit"]+sec.Counts["warn"] {
		t.Errorf("alice's overview security %+v / badge %+v, her /security counts %v", ov.Security, ov.Badges["security"], sec.Counts)
	}
	if ov.Badges["memory"].Count != len(oom.Events) || ov.Badges["findings"].Count != len(ov.Attention) || strings.Join(ov.Owners, ",") != "team-alpha" {
		t.Errorf("alice's badges %v, owners %v, attention %+v", ov.Badges, ov.Owners, ov.Attention)
	}
	if ov.Activity == nil || ov.Activity.Exec+ov.Activity.SecretReads+ov.Activity.RBACChanges+ov.Activity.Denied != 0 || len(ov.Activity.Latest) != 0 {
		t.Errorf("alice's activity (team-a holds only deletes) = %+v", ov.Activity)
	}
	// The namespace picker and the production marker list only what she
	// may see (team-b is production, and not hers).
	if strings.Join(ov.Namespaces, ",") != "team-a" || ov.Activity == nil || len(ov.Activity.ProductionNamespaces) != 0 {
		t.Errorf("alice's namespaces %v, production namespaces %+v", ov.Namespaces, ov.Activity)
	}
	// Alerts: her namespace's findings (an open one and one resolved within
	// the day), never RBAC drift (no ViewRBAC in team-a, no ViewClusterRBAC);
	// the Overview's widget counts the same.
	var al alertsResponse
	getAs(t, h, "alice", "/api/v1/alerts", &al)
	var keys []string
	for _, f := range al.Items {
		keys = append(keys, f.Key)
	}
	if strings.Join(keys, " ") != "workload-unhealthy/Deployment/team-a/web pod-evicted/Deployment/team-a/web" ||
		al.Counts["open"] != 1 || al.Counts["resolved"] != 1 {
		t.Errorf("alice's alerts = %v, counts %v", keys, al.Counts)
	}
	if ov.Alerts == nil || ov.Alerts.Open != 1 || len(ov.Alerts.ByOwner) != 1 || ov.Alerts.ByOwner["team-alpha"] != 1 {
		t.Errorf("alice's overview alerts = %+v", ov.Alerts)
	}
	var carolOv overviewResponse
	getAs(t, h, "carol", "/api/v1/overview", &carolOv)
	if carolOv.Namespaces == nil || len(carolOv.Namespaces) != 0 {
		t.Errorf("carol's namespaces = %#v, want []", carolOv.Namespaces)
	}
	if carolOv.Alerts == nil || carolOv.Alerts.Open != 0 || len(carolOv.Alerts.ByOwner) != 0 {
		t.Errorf("carol's overview alerts = %+v", carolOv.Alerts)
	}

	// Incidents: team-a's, never the node's (no ViewNodes) and never a
	// CloudTrail change (no ViewCloudTrail); the Overview counts the same.
	var inc incidentsResponse
	getAs(t, h, "alice", "/api/v1/incidents?type=eviction", &inc)
	if len(inc.Items) != 0 {
		t.Errorf("alice sees the node incident: %+v", inc.Items)
	}
	getAs(t, h, "alice", "/api/v1/incidents", &inc)
	for _, in := range inc.Items {
		if in.Subject.Namespace != "team-a" || hasType(in, "cloudtrail-change") {
			t.Errorf("alice's incident %+v", in)
		}
	}
	if ov.Incidents == nil || ov.Incidents.Open.Critical+ov.Incidents.Open.Warning != inc.Counts.Open {
		t.Errorf("alice's overview incidents %+v, her list counts %+v", ov.Incidents, inc.Counts)
	}

	// Single objects elsewhere are not found, rather than forbidden.
	for _, path := range []string{"/api/v1/map?namespace=team-b", "/api/v1/pods/team-b/web-0/diagnostics", "/api/v1/pods/team-b/web-0/processes", "/api/v1/nodes/n9",
		"/api/v1/incidents/" + incidentID("team-b"), "/api/v1/incidents/" + incidentID("team-b") + "/logs", "/api/v1/incidents/" + incidentID("team-b") + "/bundle",
		"/api/v1/incidents/" + nodeIncidentID} {
		if rec := getAs(t, h, "alice", path, nil); rec.Code != 404 {
			t.Errorf("%s as alice = %d, want 404", path, rec.Code)
		}
	}
	if rec := getAs(t, h, "alice", "/api/v1/pods/team-a/web-0/diagnostics", nil); rec.Code != 200 {
		t.Errorf("own pod page = %d", rec.Code)
	}
	var procs processesResponse
	if rec := getAs(t, h, "alice", "/api/v1/pods/team-a/web-0/processes", &procs); rec.Code != 200 || !procs.Available {
		t.Errorf("own processes = %d %+v", rec.Code, procs)
	}
	if rec := getAs(t, h, "bob", "/api/v1/pods/team-b/web-0/processes", nil); rec.Code != 403 {
		t.Errorf("processes without ViewProcesses = %d, want 403", rec.Code)
	}

	// bob holds nodes: he sees them in full, with only his pods listed.
	nodes = nodesResponse{}
	getAs(t, h, "bob", "/api/v1/nodes", &nodes)
	if len(nodes.Items) != 2 {
		t.Fatalf("bob's nodes = %+v", nodes)
	}
	for _, n := range nodes.Items {
		if n.Status != detectors.StatusOK {
			t.Errorf("bob's node = %+v", n)
		}
		for _, p := range n.Pods {
			if p.Namespace != "team-b" {
				t.Errorf("bob sees pod %s/%s on %s", p.Namespace, p.Name, n.Name)
			}
		}
	}

	// Namespaced RBAC findings need ViewRBAC (list rolebindings) in their
	// namespace; the counts follow.
	g := tenantGrants()
	g[grant("alice", auth.ViewRBAC, "team-a")] = true
	s.Authorizer = &auth.SARAuthorizer{Reviewer: g, Candidates: s.Authorizer.(*auth.SARAuthorizer).Candidates}
	h = s.Handler()
	var withRBAC, withRBACSummary securityResponse
	getAs(t, h, "alice", "/api/v1/security?limit=1000", &withRBAC)
	getAs(t, h, "alice", "/api/v1/security?view=summary", &withRBACSummary)
	rbacFindings := 0
	for _, f := range withRBAC.Findings {
		if f.Category == "rbac" {
			rbacFindings++
			if f.Namespace != "team-a" {
				t.Errorf("alice's RBAC finding outside team-a: %+v", f)
			}
		}
	}
	total := func(c map[string]int) int { return c["crit"] + c["warn"] + c["info"] }
	if rbacFindings == 0 || total(withRBAC.Counts) != total(sec.Counts)+rbacFindings || total(withRBACSummary.Counts) != total(withRBAC.Counts) {
		t.Errorf("with ViewRBAC in team-a alice sees %d RBAC findings, counts %v (summary %v), without %v",
			rbacFindings, withRBAC.Counts, withRBACSummary.Counts, sec.Counts)
	}
	// The overview follows the same gate (and the response cache keys on it).
	var ovRBAC overviewResponse
	getAs(t, h, "alice", "/api/v1/overview", &ovRBAC)
	if ovRBAC.Security.Crit != withRBAC.Counts["crit"] || ovRBAC.Security.Warn != withRBAC.Counts["warn"] {
		t.Errorf("with ViewRBAC alice's overview security = %+v, /security counts %v", ovRBAC.Security, withRBAC.Counts)
	}

	// The audit store's cluster-wide counts only for callers who may read
	// audit events.
	var info infoResponse
	getAs(t, h, "carol", "/api/v1/info", &info)
	if info.AuditStore != nil {
		t.Errorf("carol (no audit grant) reads the audit store's coverage: %+v", info.AuditStore)
	}
	info = infoResponse{}
	getAs(t, h, "alice", "/api/v1/info", &info)
	if info.AuditStore == nil || info.AuditStore.Events == 0 {
		t.Errorf("alice (audit in team-a) has no audit store coverage: %+v", info.AuditStore)
	}
}

func TestInfoCapabilities(t *testing.T) {
	s := tenantServer(t)
	h := s.Handler()
	var info infoResponse
	getAs(t, h, "alice", "/api/v1/info", &info)
	want := map[string]bool{"nodes": false, "pvs": false, "storageClasses": false, "clusterRBAC": false, "clusterIssuers": false,
		"agents": false, "clusterAudit": false, "processes": true, "audit": true}
	for k, v := range want {
		if got, ok := info.Capabilities[k]; !ok || got != v {
			t.Errorf("alice capability %s = %v (present %v), want %v", k, got, ok, v)
		}
	}
	if info.Identity == nil || info.Identity.User != "alice" || info.Identity.Source != "proxy" || info.Snapshot == nil || info.Version != "" {
		t.Errorf("info = %+v", info)
	}
	s.Version = "v1.2.3"
	info = infoResponse{}
	getAs(t, s.Handler(), "alice", "/api/v1/info", &info)
	if info.Version != "v1.2.3" {
		t.Errorf("info version = %q", info.Version)
	}
	getAs(t, h, "bob", "/api/v1/info", &info)
	if !info.Capabilities["nodes"] || info.Capabilities["audit"] {
		t.Errorf("bob capabilities = %v", info.Capabilities)
	}
	if rec := getAs(t, h, "", "/api/v1/info", nil); rec.Code != 401 {
		t.Errorf("no identity: %d, want 401", rec.Code)
	}
}

// The response cache keys by scope: alice's cached list never reaches bob.
func TestResponseCacheIsolatesCallers(t *testing.T) {
	s := tenantServer(t)
	h := s.Handler()
	for _, path := range []string{"/api/v1/pods", "/api/v1/workloads", "/api/v1/storage", "/api/v1/security", "/api/v1/nodes", "/api/v1/certificates", "/api/v1/overview"} {
		for i := 0; i < 2; i++ {
			rec := getAs(t, h, "alice", path, nil)
			if i == 1 && rec.Header().Get("X-Kubesentry-Cache") != "hit" {
				t.Errorf("%s: second request was not served from the cache", path)
			}
		}
		rec := getAs(t, h, "bob", path, nil)
		nss, _ := namespacesIn(rec.Body.Bytes())
		if nss["team-a"] > 0 {
			t.Errorf("%s: bob got alice's response: %v", path, nss)
		}
	}
	if s.ResponseCache.Len() == 0 {
		t.Error("nothing was cached")
	}
}

func TestRecheck(t *testing.T) {
	s := tenantServer(t)
	h := s.Handler()
	post := func(user string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/recheck", nil)
		req.Header.Set("X-Forwarded-Email", user)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	rec := post("alice")
	var resp recheckResponse
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &resp) != nil || !resp.Capabilities["audit"] || resp.Capabilities["nodes"] {
		t.Fatalf("recheck = %d %s", rec.Code, rec.Body.String())
	}
	if rec := post("alice"); rec.Code != 429 || rec.Header().Get("Retry-After") == "" {
		t.Errorf("second recheck within a minute = %d, want 429 with Retry-After", rec.Code)
	}
	if rec := post("bob"); rec.Code != 200 {
		t.Errorf("another identity's recheck = %d", rec.Code)
	}
}

// pagedServer serves n pods in one namespace, unrestricted.
func pagedServer(n int) *Server {
	inv := model.Inventory{Unavailable: map[string]string{}}
	for i := 0; i < n; i++ {
		inv.Pods = append(inv.Pods, model.Pod{Namespace: fmt.Sprintf("ns-%d", i%7), Name: fmt.Sprintf("pod-%04d", i), Phase: "Running",
			Containers: []model.ContainerStatus{{Name: "c", RestartCount: int32(i % 5)}}})
	}
	return &Server{Views: snapshot.Static(snapshot.Build(inv, detectors.DefaultPolicy(), now)), Now: func() time.Time { return now }}
}

func TestPaginationVisitsEveryItemOnce(t *testing.T) {
	s := pagedServer(53)
	h := s.Handler()
	seen := map[string]int{}
	var order []string
	for _, page := range allPages(t, h, "", "/api/v1/pods") {
		var p podsResponse
		_ = json.Unmarshal(page, &p)
		if p.Count != len(p.Items) || p.Count > 1 {
			t.Fatalf("page = %+v", p)
		}
		for _, it := range p.Items {
			seen[it.Namespace+"/"+it.Name]++
			order = append(order, it.Name)
		}
	}
	if len(seen) != 53 {
		t.Errorf("saw %d distinct pods, want 53", len(seen))
	}
	for k, n := range seen {
		if n != 1 {
			t.Errorf("%s served %d times", k, n)
		}
	}
	// Pages follow the list's own order: most restarts first.
	var all podsResponse
	get(t, s, "/api/v1/pods?limit=1000", &all)
	for i, it := range all.Items {
		if it.Name != order[i] {
			t.Fatalf("page order differs at %d: %s vs %s", i, it.Name, order[i])
		}
	}

	// A namespace filter pages within the namespace.
	seen = map[string]int{}
	for _, page := range allPages(t, h, "", "/api/v1/pods?namespace=ns-3") {
		var p podsResponse
		_ = json.Unmarshal(page, &p)
		for _, it := range p.Items {
			if it.Namespace != "ns-3" {
				t.Errorf("namespace filter leaked %s", it.Namespace)
			}
			seen[it.Name]++
		}
	}
	if len(seen) != 8 {
		t.Errorf("ns-3 has %d pods, want 8", len(seen))
	}
}

func TestPaginationTokensAndLimits(t *testing.T) {
	s := pagedServer(1100)
	var p podsResponse
	if code := get(t, s, "/api/v1/pods", &p); code != 200 || len(p.Items) != defaultPageLimit || p.Continue == "" {
		t.Fatalf("default page = %d items, continue %q", len(p.Items), p.Continue)
	}
	first := p.Items[defaultPageLimit-1]
	var next podsResponse
	get(t, s, "/api/v1/pods?continue="+p.Continue, &next)
	if next.Items[0].Name == first.Name || len(next.Items) != defaultPageLimit {
		t.Errorf("next page starts at %s after %s", next.Items[0].Name, first.Name)
	}
	if key, err := decodeToken("pods", p.Continue); err != nil || !strings.HasSuffix(key, first.Namespace+"\x00"+first.Name) {
		t.Errorf("token round trip = %q, %v", key, err)
	}
	get(t, s, "/api/v1/pods?limit=5000", &p)
	if len(p.Items) != maxPageLimit || p.Continue == "" {
		t.Errorf("limit=5000 = %d items, want clamped to %d", len(p.Items), maxPageLimit)
	}

	tampered := []byte(p.Continue)
	tampered[3] ^= 0x01
	wrongRoute := encodeToken("workloads", "x")
	for _, q := range []string{"limit=0", "limit=-3", "limit=ten", "continue=!!!", "continue=bm90LWEtdG9rZW4", "continue=" + string(tampered), "continue=" + wrongRoute} {
		if code := get(t, s, "/api/v1/pods?"+q, nil); code != 400 {
			t.Errorf("%s = %d, want 400", q, code)
		}
	}
	for _, path := range []string{"/api/v1/storage?continue=garbage", "/api/v1/security?continue=garbage", "/api/v1/workloads?continue=garbage"} {
		if code := get(t, inventoryServer(), path, nil); code != 400 {
			t.Errorf("%s = %d, want 400", path, code)
		}
	}
}

func TestAuditPagination(t *testing.T) {
	st := audit.NewMemoryStore(100)
	for i := 0; i < 25; i++ {
		// Pairs share a timestamp, so the cursor must break ties by auditID.
		st.Add(audit.Event{AuditID: fmt.Sprintf("id-%02d", i), Time: now.Add(-time.Duration(i/2) * time.Minute), Verb: "delete",
			Username: "dave", ActorKind: "user", Resource: "pods", Namespace: "a", Tags: []string{audit.TagDelete}})
	}
	s := newServer(fakeCluster{}, nil)
	s.Audit = &audit.Ingester{Store: st}
	seen := map[string]bool{}
	for _, page := range allPages(t, s.Handler(), "", "/api/v1/audit/events") {
		var p auditEventsResponse
		_ = json.Unmarshal(page, &p)
		for _, e := range p.Items {
			if seen[e.AuditID] {
				t.Errorf("%s served twice", e.AuditID)
			}
			seen[e.AuditID] = true
		}
	}
	if len(seen) != 25 {
		t.Errorf("saw %d events, want 25", len(seen))
	}
}

func TestReadiness(t *testing.T) {
	ready, pgDown := false, false
	s := newServer(fakeCluster{}, nil)
	s.Ready = func() bool { return ready }
	s.Unavailable = func() map[string]string { return map[string]string{"clusterrolebindings": "forbidden"} }
	s.Checks = []HealthCheck{{Name: "postgres", Check: func(context.Context) error {
		if pgDown {
			return fmt.Errorf("connection refused")
		}
		return nil
	}}}
	ops := s.Serve(Parts{Probes: true, Metrics: true}) // the ops listener
	probe := func(h http.Handler, out *readyResponse) int {
		req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		*out = readyResponse{}
		_ = json.Unmarshal(rec.Body.Bytes(), out)
		return rec.Code
	}
	var r readyResponse
	if code := probe(ops, &r); code != 503 || r.Status != "starting" {
		t.Errorf("before sync = %d %+v", code, r)
	}
	ready = true
	if code := probe(ops, &r); code != 200 || r.Status != "ready" || len(r.Degraded) != 0 || r.Unavailable["clusterrolebindings"] != "forbidden" {
		t.Errorf("after sync = %d %+v", code, r)
	}
	pgDown = true
	if code := probe(ops, &r); code != 200 || r.Degraded["postgres"] != "connection refused" {
		t.Errorf("degraded = %d %+v", code, r)
	}
	if code := get(t, s, "/healthz", nil); code != 200 {
		t.Errorf("healthz = %d", code)
	}

	// On the web listener (no -ops-addr) every UI user can call /readyz: the
	// status only, no dependency errors.
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "connection refused") || strings.Contains(rec.Body.String(), "forbidden") {
		t.Errorf("readyz on the web listener = %d %s", rec.Code, rec.Body.String())
	}
	ready = false
	if probe(s.Handler(), &r) != 503 || r.Status != "starting" {
		t.Errorf("web readyz before sync = %+v", r)
	}
}

func TestListenersServeTheirParts(t *testing.T) {
	s, _ := procServer()
	s.Audit = &audit.Ingester{Store: audit.NewMemoryStore(10)}
	s.AuditToken = "audit-secret"
	report := `{"node":"n1","processes":[]}`
	send := func(h http.Handler, method, path, token, body string) int {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	web := s.Serve(Parts{Web: true})
	ingest := s.Serve(Parts{Ingest: true})
	ops := s.Serve(Parts{Probes: true, Metrics: true})
	if code := send(web, "POST", "/agent/report", "agent-secret", report); code != 404 && code != 405 {
		t.Errorf("agent report on the web listener = %d", code)
	}
	if code := send(web, "POST", "/audit/webhook", "audit-secret", "{}"); code != 404 && code != 405 {
		t.Errorf("audit webhook on the web listener = %d", code)
	}
	if code := send(web, "GET", "/api/v1/pods", "", ""); code != 200 {
		t.Errorf("API on the web listener = %d", code)
	}
	if code := send(web, "GET", "/readyz", "", ""); code != 404 {
		t.Errorf("readyz on the web listener with an ops listener = %d", code)
	}
	if code := send(ingest, "POST", "/agent/report", "agent-secret", report); code != 204 {
		t.Errorf("agent report on the ingest listener = %d", code)
	}
	if code := send(ingest, "GET", "/api/v1/pods", "", ""); code != 404 {
		t.Errorf("API on the ingest listener = %d", code)
	}
	if code := send(ops, "GET", "/metrics", "", ""); code != 200 {
		t.Errorf("metrics on the ops listener = %d", code)
	}
	if code := send(ops, "GET", "/api/v1/pods", "", ""); code != 404 {
		t.Errorf("API on the ops listener = %d", code)
	}
	if code := send(ops, "GET", "/debug/pprof/", "", ""); code != 404 {
		t.Errorf("pprof without -pprof = %d", code)
	}
	if code := send(s.Serve(Parts{Pprof: true}), "GET", "/debug/pprof/", "", ""); code != 200 {
		t.Errorf("pprof with -pprof = %d", code)
	}
	// Everything on one listener when there are no others.
	all := s.Handler()
	if send(all, "POST", "/agent/report", "agent-secret", report) != 204 || send(all, "GET", "/readyz", "", "") != 200 {
		t.Error("the single listener serves ingest and probes")
	}
}

// Proxy mode end to end: identity headers count only from a trusted proxy.
func TestProxyModeTrustsOnlyTheProxy(t *testing.T) {
	s := tenantServer(t)
	h := s.Handler()
	send := func(remote string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/pods", nil)
		req.RemoteAddr = remote
		req.Header.Set("X-Forwarded-Email", "alice")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	rec := send("192.0.2.10:5000")
	var p podsResponse
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &p) != nil || p.Count != 3 {
		t.Errorf("from the proxy = %d %s", rec.Code, rec.Body.String())
	}
	if rec := send("10.1.2.3:5000"); rec.Code != 401 {
		t.Errorf("from elsewhere = %d, want 401", rec.Code)
	}
	// The UI's static files stay open, the probes too.
	s.UI = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	h = s.Handler()
	for _, path := range []string{"/", "/assets/app.js", "/healthz"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = "10.1.2.3:5000"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Errorf("%s from anywhere = %d", path, rec.Code)
		}
	}
}
