package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
)

type fakeInventory struct {
	workloads  []model.Workload
	services   []model.Service
	ingresses  []model.Ingress
	nodes      []model.Node
	pvs        []model.PV
	classes    []model.StorageClass
	namespaces []model.Namespace
	rbac       model.RBAC
	err        error // returned by every method
	rbacErr    error // returned by ListRBAC only
}

func (f fakeInventory) ListWorkloads(context.Context) ([]model.Workload, error) {
	return f.workloads, f.err
}
func (f fakeInventory) ListServices(context.Context) ([]model.Service, error) {
	return f.services, f.err
}
func (f fakeInventory) ListIngresses(context.Context) ([]model.Ingress, error) {
	return f.ingresses, f.err
}
func (f fakeInventory) ListNodes(context.Context) ([]model.Node, error) { return f.nodes, f.err }
func (f fakeInventory) ListPVs(context.Context) ([]model.PV, error)     { return f.pvs, f.err }
func (f fakeInventory) ListStorageClasses(context.Context) ([]model.StorageClass, error) {
	return f.classes, f.err
}
func (f fakeInventory) ListNamespaces(context.Context) ([]model.Namespace, error) {
	return f.namespaces, f.err
}
func (f fakeInventory) ListRBAC(context.Context) (model.RBAC, error) {
	if f.rbacErr != nil {
		return model.RBAC{}, f.rbacErr
	}
	return f.rbac, f.err
}

type fakeCerts struct {
	cm  model.CertManager
	err error
}

func (f fakeCerts) CertManager(context.Context) (model.CertManager, error) { return f.cm, f.err }

func inventoryCluster() fakeCluster {
	app := func(name string) map[string]string { return map[string]string{"app": name} }
	return fakeCluster{
		pods: []model.Pod{
			{Namespace: "shop", Name: "web-1", Phase: "Running", NodeName: "n1", Labels: app("web"), Claims: []string{"data"},
				Specs: []model.ContainerSpec{{Name: "web", Privileged: true, CPURequestMilli: 200, MemoryRequestBytes: 256 << 20}}},
			{Namespace: "shop", Name: "web-2", Phase: "Running", NodeName: "n2", Labels: app("web")},
			{Namespace: "kube-system", Name: "dns-1", Phase: "Running", NodeName: "n1", Labels: app("dns")},
			{Namespace: "a-team", Name: "tool", Phase: "Running", NodeName: "n2"},
		},
		pvcs: []model.PVC{
			{Namespace: "shop", Name: "data", Phase: "Bound", StorageClass: "gp3", CapacityBytes: 10 << 30, Created: now.Add(-48 * time.Hour)},
			{Namespace: "shop", Name: "orphan", Phase: "Bound", StorageClass: "gp3", CapacityBytes: 20 << 30, Created: now.Add(-48 * time.Hour)},
		},
	}
}

func inventory() fakeInventory {
	return fakeInventory{
		workloads: []model.Workload{
			{Kind: "Deployment", Namespace: "shop", Name: "web", Desired: 3, Ready: 2, Updated: 3,
				Selector: &model.LabelSelector{MatchLabels: map[string]string{"app": "web"}}},
			{Kind: "Deployment", Namespace: "kube-system", Name: "dns", Desired: 1, Ready: 1, Updated: 1,
				Selector: &model.LabelSelector{MatchLabels: map[string]string{"app": "dns"}}},
		},
		services:  []model.Service{{Namespace: "shop", Name: "web", Type: "NodePort", Selector: map[string]string{"app": "web"}, Ports: []model.ServicePort{{Port: 80, NodePort: 30080}}}},
		ingresses: []model.Ingress{{Namespace: "shop", Name: "web", Rules: []model.IngressRule{{Host: "shop.example.com", Service: "web"}}}},
		nodes:     []model.Node{{Name: "n2", Ready: true}, {Name: "n1", Ready: true, CPUAllocatableMilli: 2000}},
		pvs: []model.PV{
			{Name: "pv-data", Phase: "Bound", ReclaimPolicy: "Delete", ClaimNamespace: "shop", ClaimName: "data"},
			{Name: "pv-old", Phase: "Released", ReclaimPolicy: "Retain"},
		},
		classes:    []model.StorageClass{{Name: "gp3", Default: true}},
		namespaces: []model.Namespace{{Name: "shop"}, {Name: "kube-system"}, {Name: "a-team", Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}}},
		rbac: model.RBAC{Bindings: []model.RoleBinding{{Kind: "ClusterRoleBinding", Name: "erin", RoleKind: "ClusterRole", RoleName: "cluster-admin",
			Subjects: []model.Subject{{Kind: "User", Name: "erin"}}}}},
	}
}

func inventoryServer() *Server {
	s := newServer(inventoryCluster(), nil)
	s.Inventory = inventory()
	s.Certs = fakeCerts{cm: model.CertManager{
		Installed: true,
		Issuers:   []model.Issuer{{Kind: "ClusterIssuer", Name: "le", Type: "acme", Ready: "True"}},
		Certificates: []model.Certificate{
			{Namespace: "shop", Name: "soon", IssuerKind: "ClusterIssuer", IssuerName: "le", Ready: "True", NotAfter: now.Add(10 * 24 * time.Hour)},
			{Namespace: "shop", Name: "fine", IssuerKind: "ClusterIssuer", IssuerName: "le", Ready: "True", NotAfter: now.Add(80 * 24 * time.Hour)},
		},
	}}
	return s
}

func TestWorkloadsEndpoint(t *testing.T) {
	s := inventoryServer()
	var resp workloadsResponse
	if code := get(t, s, "/api/v1/workloads", &resp); code != 200 {
		t.Fatalf("status %d", code)
	}
	if resp.Count != 2 || resp.Items[0].Name != "web" || resp.Items[0].Status != "warn" || resp.Items[0].Pods != 2 {
		t.Errorf("workloads = %+v", resp)
	}
	get(t, s, "/api/v1/workloads?namespace=kube-system", &resp)
	if resp.Count != 1 || resp.Items[0].Name != "dns" || resp.Items[0].Pods != 1 {
		t.Errorf("namespace filter = %+v", resp)
	}
	if code := get(t, s, "/api/v1/workloads?namespace=Bad_NS", nil); code != 400 {
		t.Errorf("bad namespace status %d, want 400", code)
	}
	if body := raw(t, s, "/api/v1/workloads?namespace=empty"); !strings.Contains(body, `"items":[]`) {
		t.Errorf("empty list must encode as []: %s", body)
	}
}

func TestNodesEndpoint(t *testing.T) {
	var resp nodesResponse
	if code := get(t, inventoryServer(), "/api/v1/nodes", &resp); code != 200 {
		t.Fatalf("status %d", code)
	}
	if resp.Count != 2 || resp.Items[0].Name != "n1" || len(resp.Items[0].Pods) != 2 || resp.Items[0].CPURequestedMilli != 200 {
		t.Errorf("nodes = %+v", resp)
	}
	if resp.Items[0].Pods[1].Workload != "Deployment/web" {
		t.Errorf("pod workload = %+v", resp.Items[0].Pods)
	}
}

func TestStorageEndpoint(t *testing.T) {
	var resp storageResponse
	if code := get(t, inventoryServer(), "/api/v1/storage", &resp); code != 200 {
		t.Fatalf("status %d", code)
	}
	if len(resp.Claims) != 2 || resp.Claims[0].Name != "orphan" || resp.Claims[0].Status != "warn" {
		t.Errorf("claims = %+v", resp.Claims)
	}
	if len(resp.Volumes) != 2 || resp.Volumes[0].Name != "pv-old" || len(resp.Classes) != 1 || resp.Classes[0].Claims != 2 {
		t.Errorf("volumes = %+v classes = %+v", resp.Volumes, resp.Classes)
	}
	// 20 GiB at the $0.10 default.
	if len(resp.Unused) != 1 || resp.Unused[0].Name != "orphan" || resp.UnusedMonthlyCostUSD != 2.0 {
		t.Errorf("unused = %+v cost %v", resp.Unused, resp.UnusedMonthlyCostUSD)
	}

	s := newServer(fakeCluster{}, nil)
	s.Inventory = fakeInventory{}
	body := raw(t, s, "/api/v1/storage")
	for _, k := range []string{`"claims":[]`, `"volumes":[]`, `"classes":[]`, `"unused":[]`} {
		if !strings.Contains(body, k) {
			t.Errorf("want %s in %s", k, body)
		}
	}
}

func TestSecurityEndpoint(t *testing.T) {
	var resp securityResponse
	if code := get(t, inventoryServer(), "/api/v1/security", &resp); code != 200 {
		t.Fatalf("status %d", code)
	}
	ids := map[string]bool{}
	for _, f := range resp.Findings {
		ids[f.ID] = true
	}
	for _, want := range []string{
		"privileged/Deployment/shop/web", "cluster-admin/ClusterRoleBinding/erin", "nodeport/Service/shop/web",
		"ingress-no-tls/Ingress/shop/web", "psa-missing/Namespace/shop", "psa-missing/Namespace/kube-system",
	} {
		if !ids[want] {
			t.Errorf("missing finding %s in %v", want, ids)
		}
	}
	// warn: nodeport, ingress-no-tls, shop's missing label and web running as
	// root; kube-system's missing label is a system finding and is not counted.
	if resp.Counts["crit"] != 2 || resp.Counts["warn"] != 4 || resp.Counts["info"] != 2 || len(resp.Warnings) != 0 || len(resp.Namespaces) != 3 {
		t.Errorf("counts = %v warnings = %v namespaces = %d", resp.Counts, resp.Warnings, len(resp.Namespaces))
	}

	// RBAC is often forbidden: the page still loads, with a warning.
	s := inventoryServer()
	inv := inventory()
	inv.rbacErr = errors.New("forbidden")
	s.Inventory = inv
	resp = securityResponse{}
	if code := get(t, s, "/api/v1/security", &resp); code != 200 {
		t.Fatalf("status %d with RBAC forbidden, want 200", code)
	}
	if len(resp.Warnings) != 1 || !strings.Contains(resp.Warnings[0], "roles and bindings") || resp.Counts["crit"] != 1 {
		t.Errorf("warnings = %v counts = %v", resp.Warnings, resp.Counts)
	}

	// Everything failing still answers, with every severity key present.
	s = newServer(fakeCluster{}, nil)
	s.Inventory = fakeInventory{err: errors.New("down")}
	body := raw(t, s, "/api/v1/security")
	for _, k := range []string{`"crit":0`, `"warn":0`, `"info":0`, `"findings":[]`, `"namespaces":[]`} {
		if !strings.Contains(body, k) {
			t.Errorf("want %s in %s", k, body)
		}
	}
}

func TestMapEndpoint(t *testing.T) {
	s := inventoryServer()
	var resp mapResponse
	if code := get(t, s, "/api/v1/map", &resp); code != 200 {
		t.Fatalf("status %d", code)
	}
	// Default: the first non-system namespace with pods.
	if resp.Namespace != "a-team" || strings.Join(resp.Namespaces, ",") != "a-team,kube-system,shop" {
		t.Errorf("namespace = %q of %v", resp.Namespace, resp.Namespaces)
	}

	get(t, s, "/api/v1/map?namespace=shop", &resp)
	edges := map[string]bool{}
	for _, e := range resp.Graph.Edges {
		edges[e.From+" -> "+e.To] = true
	}
	for _, want := range []string{
		"Ingress/shop/web -> Service/shop/web", "Service/shop/web -> Deployment/shop/web",
		"Deployment/shop/web -> Pod/shop/web-1", "Pod/shop/web-1 -> Node/n1", "Pod/shop/web-1 -> PVC/shop/data",
	} {
		if !edges[want] {
			t.Errorf("missing edge %s in %v", want, edges)
		}
	}

	if code := get(t, s, "/api/v1/map?namespace=nowhere", nil); code != 404 {
		t.Errorf("unknown namespace status %d, want 404", code)
	}
	if code := get(t, s, "/api/v1/map?namespace=Bad_NS", nil); code != 400 {
		t.Errorf("bad namespace status %d, want 400", code)
	}

	// Only system namespaces: fall back to the first one.
	s = newServer(fakeCluster{pods: []model.Pod{{Namespace: "kube-system", Name: "x"}}}, nil)
	s.Inventory = fakeInventory{}
	get(t, s, "/api/v1/map", &resp)
	if resp.Namespace != "kube-system" {
		t.Errorf("namespace = %q", resp.Namespace)
	}

	// No pods at all: an empty map, not an error.
	s = newServer(fakeCluster{}, nil)
	s.Inventory = fakeInventory{}
	body := raw(t, s, "/api/v1/map")
	if !strings.Contains(body, `"namespaces":[]`) || !strings.Contains(body, `"nodes":[]`) || !strings.Contains(body, `"edges":[]`) {
		t.Errorf("empty map = %s", body)
	}
}

func TestCertificatesEndpoint(t *testing.T) {
	var resp certificatesResponse
	if code := get(t, inventoryServer(), "/api/v1/certificates", &resp); code != 200 {
		t.Fatalf("status %d", code)
	}
	if !resp.Installed || len(resp.Certificates) != 2 || resp.Certificates[0].Name != "soon" || resp.Certificates[0].Status != "warn" {
		t.Errorf("certificates = %+v", resp.Certificates)
	}
	if len(resp.Issuers) != 1 || resp.Issuers[0].Certificates != 2 || resp.Requests == nil {
		t.Errorf("issuers = %+v requests = %+v", resp.Issuers, resp.Requests)
	}

	s := newServer(fakeCluster{}, nil)
	s.Certs = fakeCerts{}
	body := raw(t, s, "/api/v1/certificates")
	if !strings.Contains(body, `"installed":false`) || !strings.Contains(body, `"certificates":[]`) {
		t.Errorf("not installed = %s", body)
	}

	s.Certs = fakeCerts{err: errors.New("boom")}
	if code := get(t, s, "/api/v1/certificates", nil); code != 502 {
		t.Errorf("cert-manager failure status %d, want 502", code)
	}
}

func TestInventoryUpstreamErrors(t *testing.T) {
	s := newServer(inventoryCluster(), nil)
	s.Inventory = fakeInventory{err: errors.New("boom")}
	for _, path := range []string{"/api/v1/workloads", "/api/v1/nodes", "/api/v1/storage", "/api/v1/map"} {
		if code := get(t, s, path, nil); code != 502 {
			t.Errorf("%s = %d, want 502", path, code)
		}
	}
}

func TestInventoryRoutesNeedSources(t *testing.T) {
	s := newServer(inventoryCluster(), nil)
	for _, path := range []string{"/api/v1/workloads", "/api/v1/nodes", "/api/v1/storage", "/api/v1/security", "/api/v1/map", "/api/v1/certificates"} {
		if code := get(t, s, path, nil); code != 404 {
			t.Errorf("%s = %d without a source, want 404", path, code)
		}
	}

	var info infoResponse
	get(t, s, "/api/v1/info", &info)
	if info.Inventory || info.Certs {
		t.Errorf("info = %+v", info)
	}
	get(t, inventoryServer(), "/api/v1/info", &info)
	if !info.Inventory || !info.Certs {
		t.Errorf("info = %+v", info)
	}
}

func TestInventoryRoutesRequireToken(t *testing.T) {
	s := inventoryServer()
	s.APIToken = "secret"
	for _, path := range []string{"/api/v1/workloads", "/api/v1/nodes", "/api/v1/storage", "/api/v1/security", "/api/v1/map", "/api/v1/certificates"} {
		if code := get(t, s, path, nil); code != 401 {
			t.Errorf("%s = %d without a token, want 401", path, code)
		}
	}
}

// raw returns the body of a GET that must succeed.
func raw(t *testing.T, s *Server, path string) string {
	t.Helper()
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if rec.Code != 200 {
		t.Fatalf("GET %s = %d %s", path, rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}
