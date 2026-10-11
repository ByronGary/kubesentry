package demo

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ByronGary/kubesentry/internal/detectors"
)

// The demo is only useful if it actually exercises each feature, so these
// tests drive the real API over the synthetic data.

func getJSON(t *testing.T, h http.Handler, path string, out any) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if rec.Code != 200 {
		t.Fatalf("GET %s = %d %s", path, rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
}

func TestDemoExercisesEveryFeature(t *testing.T) {
	srv, err := NewServer(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()

	var info struct{ Demo, Metrics, Audit, Processes bool }
	getJSON(t, h, "/api/v1/info", &info)
	if !info.Demo || !info.Metrics || !info.Audit || !info.Processes {
		t.Errorf("info = %+v", info)
	}

	var procs struct {
		Available bool
		Stale     bool
		Processes []struct {
			Name, Cmdline, Container string
		}
	}
	getJSON(t, h, "/api/v1/pods/prod/checkout-api-7d9f8b6c4-x2k9p/processes", &procs)
	if !procs.Available || procs.Stale || len(procs.Processes) < 5 {
		t.Fatalf("processes = %+v", procs)
	}
	containers := map[string]bool{}
	for _, p := range procs.Processes {
		containers[p.Container] = true
	}
	if !containers["api"] || !containers["envoy"] || !containers["pod sandbox"] {
		t.Errorf("containers not resolved to names: %v", containers)
	}
	var pay struct{ Processes []struct{ Cmdline string } }
	getJSON(t, h, "/api/v1/pods/prod/payments-worker-5c6d7f9b8-q8wzn/processes", &pay)
	for _, p := range pay.Processes {
		if strings.Contains(p.Cmdline, "hunter2") {
			t.Errorf("secret leaked into demo command line: %q", p.Cmdline)
		}
	}

	var pvcs struct {
		Count int
		Items []struct{ Name string }
		Total float64 `json:"totalEstMonthlyCostUSD"`
	}
	getJSON(t, h, "/api/v1/pvcs/unused", &pvcs)
	// old-es-data-0, backup-scratch, ml-cache and test-claim-3; new-claim is under the minimum age.
	if pvcs.Count != 4 || pvcs.Total < 70 {
		t.Errorf("unused PVCs = %+v", pvcs)
	}

	var oom struct {
		Events []struct{ Pod string }
		Leaks  []struct {
			Pod        string
			Container  string
			Confidence string
		}
	}
	getJSON(t, h, "/api/v1/oom", &oom)
	if len(oom.Events) != 1 || oom.Events[0].Pod != "checkout-api-7d9f8b6c4-x2k9p" {
		t.Errorf("oom events = %+v", oom.Events)
	}
	leaky := map[string]bool{}
	for _, l := range oom.Leaks {
		leaky[l.Pod+"/"+l.Container] = true
	}
	for _, want := range []string{"checkout-api-7d9f8b6c4-x2k9p/api", "payments-worker-5c6d7f9b8-q8wzn/worker", "search-indexer-0/indexer"} {
		if !leaky[want] {
			t.Errorf("leak not detected for %s; got %v", want, leaky)
		}
	}
	if len(oom.Leaks) != 3 {
		t.Errorf("steady containers must not be flagged; got %d leaks: %+v", len(oom.Leaks), oom.Leaks)
	}

	var diag struct {
		Checks []detectors.Check
	}
	getJSON(t, h, "/api/v1/pods/prod/checkout-api-7d9f8b6c4-x2k9p/diagnostics", &diag)
	status := map[string]string{}
	for _, c := range diag.Checks {
		status[c.ID] = c.Status
	}
	if status["oom"] != detectors.StatusCrit || status["memory"] != detectors.StatusCrit || status["activity"] != detectors.StatusWarn {
		t.Errorf("checkout-api checks = %v", status)
	}

	getJSON(t, h, "/api/v1/pods/data/etl-batch-0/diagnostics", &diag)
	status = map[string]string{}
	for _, c := range diag.Checks {
		status[c.ID] = c.Status
	}
	if status["phase"] != detectors.StatusWarn || status["storage"] != detectors.StatusCrit {
		t.Errorf("etl-batch checks = %v", status)
	}

	var ev struct {
		Count int
		Items []struct {
			Tags []string
		}
	}
	getJSON(t, h, "/api/v1/audit/events", &ev)
	tags := map[string]bool{}
	for _, e := range ev.Items {
		for _, tg := range e.Tags {
			tags[tg] = true
		}
	}
	for _, want := range []string{"exec", "secret-access", "rbac-change", "delete", "denied", "anonymous", "impersonate", "token-request", "debug-container", "secret-change"} {
		if !tags[want] {
			t.Errorf("default audit view lacks %q events; tags seen: %v", want, tags)
		}
	}
	// The default view hides the 40 background reads and the controller chatter.
	if ev.Count > 30 {
		t.Errorf("default audit view should be mostly signal, got %d events", ev.Count)
	}
}

// The inventory pages each tell part of one story: a rollout short of a
// replica, a failed backup, an over-privileged ML pod, a contractor with
// cluster-admin, a Vault issuer that cannot authenticate and a forgotten disk.
func TestDemoInventoryTellsTheStory(t *testing.T) {
	srv, err := NewServer(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()

	var info struct{ Inventory, Certs bool }
	getJSON(t, h, "/api/v1/info", &info)
	if !info.Inventory || !info.Certs {
		t.Errorf("info = %+v", info)
	}

	var wl struct {
		Items []detectors.WorkloadSummary
	}
	getJSON(t, h, "/api/v1/workloads", &wl)
	workloads := map[string]detectors.WorkloadSummary{}
	for _, w := range wl.Items {
		workloads[w.Kind+"/"+w.Namespace+"/"+w.Name] = w
	}
	for id, want := range map[string]string{
		"Deployment/prod/checkout-api":     "warn 1 of 2 ready.",
		"Job/prod/db-backup-29345678":      "crit Failed: Job has reached the specified backoff limit.",
		"CronJob/prod/db-backup":           "warn Last run did not succeed.",
		"Job/data/etl-batch":               "warn 1 pod pending.",
		"CronJob/data/warehouse-compact":   "warn Suspended.",
		"DaemonSet/monitoring/log-shipper": "ok 3 of 3 ready.",
	} {
		if w := workloads[id]; w.Status+" "+w.Detail != want {
			t.Errorf("%s = %q, want %q", id, w.Status+" "+w.Detail, want)
		}
	}
	if w := workloads["Deployment/prod/checkout-api"]; w.Pods != 2 || !w.OOMKilled {
		t.Errorf("checkout-api = %+v", w)
	}

	var nodes struct {
		Count int
		Items []detectors.NodeSummary
	}
	getJSON(t, h, "/api/v1/nodes", &nodes)
	if nodes.Count != 3 || nodes.Items[0].Name != "ip-10-0-12-34.ec2.internal" || len(nodes.Items[0].Pods) == 0 {
		t.Fatalf("nodes = %+v", nodes)
	}
	if ml := nodes.Items[2]; ml.Status != detectors.StatusWarn || len(ml.Pressure) != 1 || len(ml.Taints) != 1 {
		t.Errorf("the ML node should be under memory pressure: %+v", ml)
	}

	// Processes come from the agent on the pod's own node.
	var procs struct {
		Available bool
		Node      string
	}
	getJSON(t, h, "/api/v1/pods/prod/redis-0/processes", &procs)
	if !procs.Available || procs.Node != "ip-10-0-45-67.ec2.internal" {
		t.Errorf("redis-0 processes = %+v", procs)
	}

	var storage struct {
		Claims  []detectors.ClaimSummary
		Volumes []detectors.VolumeSummary
		Classes []detectors.ClassSummary
		Unused  []detectors.UnusedPVC
	}
	getJSON(t, h, "/api/v1/storage", &storage)
	if v := storage.Volumes[0]; v.Name != "pvc-prod-reports-archive" || v.Status != detectors.StatusWarn || v.ReclaimPolicy != "Retain" {
		t.Errorf("the released volume should come first: %+v", v)
	}
	// Same four as /api/v1/pvcs/unused: the pending feature-store claim is not unused.
	if len(storage.Unused) != 4 || len(storage.Classes) != 2 || !storage.Classes[0].Default {
		t.Errorf("unused = %d classes = %+v", len(storage.Unused), storage.Classes)
	}
	claims := map[string]string{}
	for _, c := range storage.Claims {
		claims[c.Namespace+"/"+c.Name] = c.Status
	}
	if claims["data/feature-store"] != detectors.StatusOK || claims["prod/backup-scratch"] != detectors.StatusWarn {
		t.Errorf("claims = %v", claims)
	}

	var sec struct {
		Counts   map[string]int
		Findings []detectors.SecurityFinding
		Warnings []string
	}
	getJSON(t, h, "/api/v1/security", &sec)
	found := map[string]detectors.SecurityFinding{}
	for _, f := range sec.Findings {
		found[f.ID] = f
	}
	for id, sev := range map[string]string{
		"privileged/Deployment/data/ml-trainer":                      "crit",
		"capabilities/Deployment/data/ml-trainer":                    "crit",
		"cluster-admin/ClusterRoleBinding/erin-cluster-admin":        "crit",
		"anonymous-binding/ClusterRoleBinding/metrics-public":        "crit",
		"wildcard-rbac/Role/prod/ci-deployer":                        "warn",
		"secret-readers/ClusterRoleBinding/developers-secret-reader": "warn",
		"host-path/DaemonSet/monitoring/log-shipper":                 "warn",
		"host-namespaces/DaemonSet/monitoring/log-shipper":           "warn",
		"psa-missing/Namespace/staging":                              "warn",
		"psa-privileged/Namespace/data":                              "warn",
		"nodeport/Service/monitoring/grafana":                        "warn",
		"loadbalancer/Service/prod/checkout-web":                     "warn",
		"ingress-no-tls/Ingress/staging/search":                      "warn",
	} {
		if f, ok := found[id]; !ok || f.Severity != sev || f.System {
			t.Errorf("%s = %+v, want a non-system %s finding", id, f, sev)
		}
	}
	if _, ok := found["cluster-admin/ClusterRoleBinding/cluster-admin"]; ok {
		t.Error("the built-in system:masters binding is not a finding")
	}
	if f := found["privileged/DaemonSet/kube-system/kube-proxy"]; !f.System {
		t.Errorf("kube-proxy is plumbing and should be marked system: %+v", f)
	}
	if sec.Counts["crit"] != 4 || len(sec.Warnings) != 0 {
		t.Errorf("counts = %v warnings = %v", sec.Counts, sec.Warnings)
	}

	var certs struct {
		Installed    bool
		Certificates []detectors.CertSummary
		Issuers      []detectors.IssuerSummary
		Requests     []detectors.RequestSummary
	}
	getJSON(t, h, "/api/v1/certificates", &certs)
	byStatus := map[string]int{}
	for _, c := range certs.Certificates {
		byStatus[c.Status]++
	}
	if !certs.Installed || byStatus["crit"] != 1 || byStatus["warn"] != 1 || byStatus["ok"] != 1 {
		t.Errorf("certificates = %+v", certs.Certificates)
	}
	if c := certs.Certificates[0]; c.Name != "api-internal-tls" || !strings.Contains(c.Detail, "vault-intermediate is not ready") {
		t.Errorf("first certificate = %+v", c)
	}
	if is := certs.Issuers[0]; is.Name != "vault-intermediate" || is.Status != "crit" || !strings.Contains(is.Message, "cdp-release-cert-manager") {
		t.Errorf("first issuer = %+v", is)
	}
	if len(certs.Requests) != 1 || certs.Requests[0].Certificate != "api-internal-tls" || certs.Requests[0].Status != "crit" {
		t.Errorf("requests = %+v", certs.Requests)
	}

	var m struct {
		Namespace  string
		Namespaces []string
		Graph      detectors.Graph
	}
	getJSON(t, h, "/api/v1/map", &m)
	if m.Namespace != "data" || len(m.Namespaces) != 5 {
		t.Errorf("default map = %s of %v", m.Namespace, m.Namespaces)
	}
	getJSON(t, h, "/api/v1/map?namespace=prod", &m)
	edges := map[string]bool{}
	for _, e := range m.Graph.Edges {
		edges[e.From+" -> "+e.To] = true
	}
	for _, want := range []string{
		"Ingress/prod/shop -> Service/prod/checkout-web",
		"Service/prod/checkout-web -> Deployment/prod/checkout-web",
		"Deployment/prod/checkout-web -> Pod/prod/checkout-web-6b8c9d7f5-4tn2m",
		"Pod/prod/checkout-web-6b8c9d7f5-4tn2m -> Node/ip-10-0-12-34.ec2.internal",
		"Pod/prod/postgres-0 -> PVC/prod/data-postgres-0",
	} {
		if !edges[want] {
			t.Errorf("prod map lacks %s", want)
		}
	}
	status := map[string]string{}
	for _, n := range m.Graph.Nodes {
		status[n.ID] = n.Status
	}
	if status["Service/prod/legacy-search"] != "warn" || status["Pod/prod/db-backup-29345678-k8w2p"] != "crit" {
		t.Errorf("prod map statuses = %v", status)
	}
}
