package alerts

import (
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/model"
)

// sentByKey indexes sent alerts by dedupe key.
func sentByKey(as []Alert) map[string]Alert {
	out := map[string]Alert{}
	for _, a := range as {
		if k := a.Annotations["dedupe_key"]; k != "" {
			out[k] = a
		}
	}
	return out
}

func service(ns, name, typ string, ann map[string]string, lb ...string) model.Service {
	return model.Service{Namespace: ns, Name: name, Type: typ, Annotations: ann, LoadBalancerIngress: lb,
		Ports: []model.ServicePort{{Port: 80, NodePort: 30080, Protocol: "TCP"}}}
}

// withExposure adds what the exposure and privileged checks report:
// internet-facing and internal load balancers, NodePorts (one in a system
// namespace), an external IP, an ingress without TLS, and workloads running
// privileged or on the host's namespaces.
func withExposure(inv model.Inventory) model.Inventory {
	internet := map[string]string{"service.beta.kubernetes.io/aws-load-balancer-scheme": "internet-facing"}
	internal := map[string]string{"service.beta.kubernetes.io/aws-load-balancer-scheme": "internal"}
	inv.Services = append(append([]model.Service(nil), inv.Services...),
		service("payments", "new-lb", "LoadBalancer", internet, "a.elb.amazonaws.com"),
		service("payments", "int-lb", "LoadBalancer", internal, "b.elb.amazonaws.com"),
		service("team-a", "np", "NodePort", nil),
		service("kube-system", "sys-np", "NodePort", nil),
	)
	ext := service("team-a", "ext", "ClusterIP", nil)
	ext.ExternalIPs = []string{"203.0.113.7"}
	inv.Services = append(inv.Services, ext)
	inv.Ingresses = append(append([]model.Ingress(nil), inv.Ingresses...),
		model.Ingress{Namespace: "team-a", Name: "web", Rules: []model.IngressRule{{Host: "web.example.com", Service: "web", Port: "80"}}})
	deployment(&inv, "team-a", "priv", 1, 1, 1, func(_ int, p *model.Pod) {
		p.Specs = []model.ContainerSpec{{Name: "priv", Privileged: true}}
	})
	deployment(&inv, "payments", "hostnet", 1, 1, 1, func(_ int, p *model.Pod) { p.HostNetwork = true })
	deployment(&inv, "team-a", "hostnet", 1, 1, 1, func(_ int, p *model.Pod) { p.HostPID = true })
	deployment(&inv, "kube-system", "cni", 1, 1, 1, func(_ int, p *model.Pod) {
		p.HostNetwork, p.Specs = true, []model.ContainerSpec{{Name: "cni", Privileged: true}}
	})
	return inv
}

// Exposure and privileged workloads are change-based: what stands at the
// first evaluation is the baseline and never fires; what appears later
// fires (warning; privileged critical; host namespaces critical only in
// production), per workload root. Internal load balancers and cluster
// plumbing never fire.
func TestExposureAndPrivilegedAreChangeBased(t *testing.T) {
	h := newHarness(t, Options{DriftHold: time.Hour})
	h.inv.Services = []model.Service{service("payments", "old-lb", "LoadBalancer",
		map[string]string{"service.beta.kubernetes.io/aws-load-balancer-scheme": "internet-facing"}, "c.elb.amazonaws.com")}
	res, sent := h.at(0)
	for _, a := range sent {
		if a.Labels["alertname"] == AlertExposureChange || a.Labels["alertname"] == AlertPrivilegedWorkload {
			t.Errorf("first evaluation fired %v (it records the baseline)", a.Annotations["dedupe_key"])
		}
	}
	if !strings.Contains(strings.Join(res.Baselined, ","), "loadbalancer") {
		t.Fatalf("baselined %v", res.Baselined)
	}

	h.inv = withExposure(h.inv)
	_, sent = h.at(time.Minute)
	got := sentByKey(sent)
	want := map[string]string{ // key → severity
		"loadbalancer/Service/payments/new-lb":        SeverityWarning,
		"nodeport/Service/team-a/np":                  SeverityWarning,
		"external-ip/Service/team-a/ext":              SeverityWarning,
		"ingress-no-tls/Ingress/team-a/web":           SeverityWarning,
		"privileged/Deployment/team-a/priv":           SeverityCritical,
		"host-namespaces/Deployment/payments/hostnet": SeverityCritical,
		"host-namespaces/Deployment/team-a/hostnet":   SeverityWarning,
	}
	for k, sev := range want {
		a, ok := got[k]
		if !ok {
			t.Errorf("%s did not fire: %v", k, names(sent))
			continue
		}
		if a.Labels["severity"] != sev {
			t.Errorf("%s: severity %s, want %s", k, a.Labels["severity"], sev)
		}
	}
	for k := range got {
		for _, never := range []string{"int-lb", "old-lb", "sys-np", "kube-system"} {
			if strings.Contains(k, never) {
				t.Errorf("%s fired (internal, standing or plumbing)", k)
			}
		}
	}
	lb := got["loadbalancer/Service/payments/new-lb"]
	if lb.Labels["alertname"] != AlertExposureChange || lb.Labels["object"] != "Service/new-lb" || lb.Labels["check"] != "loadbalancer" ||
		lb.Labels["owner"] != "payments" || lb.Labels["production"] != "true" || !strings.Contains(lb.Annotations["summary"], "internet-facing") {
		t.Errorf("load balancer alert %+v", lb)
	}
	priv := got["privileged/Deployment/team-a/priv"]
	if priv.Labels["alertname"] != AlertPrivilegedWorkload || priv.Labels["workload"] != "Deployment/priv" || priv.Labels["owner"] != "platform" {
		t.Errorf("privileged alert %+v", priv)
	}
	// Exposure findings need only the namespace to be seen.
	if g := GateOf(CheckLoadBalancer, "Service"); g != GateNamespace {
		t.Errorf("gate %s", g)
	}
	// It stays open (re-posted) for the hold while it exists, then resolves
	// and never fires again while it stands.
	_, sent = h.at(30 * time.Minute)
	if got := sentByKey(sent); got["privileged/Deployment/team-a/priv"].Labels == nil {
		t.Errorf("+30m: not re-posted within the hold: %v", names(sent))
	}
	_, sent = h.at(62 * time.Minute)
	gone := sentByKey(resolvedOf(sent, h.clk.t))
	for k := range want {
		if _, ok := gone[k]; !ok {
			t.Errorf("after the hold, %s did not resolve: %v", k, names(resolvedOf(sent, h.clk.t)))
		}
	}
	_, sent = h.at(80 * time.Minute)
	for _, a := range sent {
		if a.Labels["alertname"] == AlertExposureChange || a.Labels["alertname"] == AlertPrivilegedWorkload {
			t.Errorf("standing finding sent again: %s", a.Annotations["dedupe_key"])
		}
	}
}

// With the services unreadable the exposure checks are skipped: their
// findings neither resolve nor does the baseline change.
func TestExposureSkippedWhileUnreadable(t *testing.T) {
	h := newHarness(t, Options{})
	h.at(0)
	h.inv = withExposure(h.inv)
	h.at(time.Minute)
	h.inv.Unavailable = map[string]string{"services": "forbidden"}
	h.inv.Services = nil
	h.at(2 * time.Minute)
	_, sent := h.at(10 * time.Minute)
	for _, a := range resolvedOf(sent, h.clk.t) {
		if strings.HasPrefix(a.Annotations["dedupe_key"], "loadbalancer/") || strings.HasPrefix(a.Annotations["dedupe_key"], "nodeport/") {
			t.Errorf("resolved while unreadable: %s", a.Annotations["dedupe_key"])
		}
	}
	if !strings.Contains(strings.Join(names(sent), " "), "loadbalancer/Service/payments/new-lb") {
		t.Errorf("not re-posted while unreadable: %v", names(sent))
	}
}

// -alerts-disable-checks: a disabled check never fires, its open findings
// resolve, and a change-based check keeps its baseline.
func TestDisabledChecks(t *testing.T) {
	h := newHarness(t, Options{Disabled: map[string]bool{CheckPodEvicted: true, CheckNodePort: true}})
	_, sent := h.at(0)
	if strings.Contains(strings.Join(names(sent), " "), "pod-evicted/") {
		t.Errorf("disabled check fired: %v", names(sent))
	}
	h.inv = withExposure(h.inv)
	_, sent = h.at(time.Minute)
	if strings.Contains(strings.Join(names(sent), " "), "nodeport/") {
		t.Errorf("disabled change-based check fired: %v", names(sent))
	}
	if bl, _ := h.store.Baselines(t.Context()); bl[CheckNodePort] != nil {
		t.Errorf("a disabled check recorded a baseline: %v", bl[CheckNodePort])
	}
}

// Golden payload of the new catalog: one alert of each kind the exposure,
// privileged, audit and agent checks raise (testdata/catalog.golden.json;
// go test -update rewrites it).
func TestCatalogPayloadGolden(t *testing.T) {
	const ds = "kubesentry/kubesentry-agent"
	h, fa := auditHarness(t, Options{ExternalURL: "https://kubesentry.example.com/", Cluster: "prod-eks", AgentDaemonSet: ds,
		Audit: AuditOptions{Redact: func(s string) string { return strings.ReplaceAll(s, "hunter2", "[REDACTED]") }}})
	h.inv, h.agents = agentFixture(fixture(), t0)
	h.at(0)
	h.inv = withExposure(h.inv)
	fa.add(execEv(t0.Add(time.Minute), "alice@example.com", "payments", "api-0", "env+PASSWORD%3Dhunter2"))
	fa.add(audit.Event{Time: t0.Add(time.Minute), Verb: "list", Username: "system:anonymous", Groups: []string{"system:unauthenticated"},
		Resource: "pods", Namespace: "team-a"})
	h.agents.Last["n-ok"] = t0.Add(5 * time.Minute)
	h.at(5 * time.Minute)
	h.agents.Last["n-ok"] = t0.Add(10 * time.Minute)
	_, sent := h.at(10 * time.Minute)
	keep := map[string]bool{
		"loadbalancer/Service/payments/new-lb": true, "host-namespaces/Deployment/payments/hostnet": true,
		"audit-exec/User/payments/alice@example.com": true, "audit-anonymous/User/team-a/system:anonymous": true,
		"agent-missing/DaemonSet//" + ds: true,
	}
	var out []Alert
	for _, a := range sent {
		if keep[a.Annotations["dedupe_key"]] {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Annotations["dedupe_key"] < out[j].Annotations["dedupe_key"] })
	if len(out) != len(keep) {
		t.Fatalf("got %d of %d: %v", len(out), len(keep), names(sent))
	}
	golden(t, "catalog", out)
}

// agentFixture adds the agent DaemonSet kubesentry/kubesentry-agent with a
// pod on each of six nodes: n-ok reports, n-silent stopped 5 minutes ago,
// n-never never did, n-young joined 5 minutes ago, n-notready is NotReady,
// n-fargate is a Fargate node. One more DaemonSet's node never reports
// either but is not the agent's.
func agentFixture(inv model.Inventory, at time.Time) (model.Inventory, *AgentReports) {
	inv.Namespaces = append(inv.Namespaces, model.Namespace{Name: "kubesentry"})
	inv.Workloads = append(inv.Workloads, model.Workload{Kind: "DaemonSet", Namespace: "kubesentry", Name: "kubesentry-agent", UID: "ds-agent"},
		model.Workload{Kind: "DaemonSet", Namespace: "kube-system", Name: "other", UID: "ds-other"})
	node := func(name string, ready bool, age time.Duration, labels map[string]string) model.Node {
		return model.Node{Name: name, Ready: ready, Created: at.Add(-age), Labels: labels}
	}
	inv.Nodes = []model.Node{
		node("n-ok", true, 48*time.Hour, nil), node("n-silent", true, 48*time.Hour, nil), node("n-never", true, 48*time.Hour, nil),
		node("n-young", true, 5*time.Minute, nil), node("n-notready", false, 48*time.Hour, nil),
		node("n-fargate", true, 48*time.Hour, map[string]string{"eks.amazonaws.com/compute-type": "fargate"}),
		node("n-other", true, 48*time.Hour, nil),
	}
	for _, n := range inv.Nodes {
		if n.Name == "n-other" {
			continue
		}
		inv.Pods = append(inv.Pods, model.Pod{UID: "agent-" + n.Name, Namespace: "kubesentry", Name: "kubesentry-agent-" + n.Name, Phase: "Running",
			NodeName: n.Name, Created: at.Add(-time.Hour), Owners: []model.OwnerRef{{Kind: "DaemonSet", Name: "kubesentry-agent", UID: "ds-agent", Controller: true}}})
	}
	inv.Pods = append(inv.Pods, model.Pod{UID: "other-0", Namespace: "kube-system", Name: "other-0", Phase: "Running", NodeName: "n-other",
		Owners: []model.OwnerRef{{Kind: "DaemonSet", Name: "other", UID: "ds-other", Controller: true}}})
	return inv, &AgentReports{Interval: 15 * time.Second, Last: map[string]time.Time{
		"n-ok": at.Add(-20 * time.Second), "n-silent": at.Add(-5 * time.Minute),
	}}
}

// The agent-missing check: nodes running the agent's pod that have not
// reported for 3 intervals, without Fargate, NotReady and young nodes; one
// finding per DaemonSet, cluster-scoped, after 10 minutes pending; skipped
// without reports; nothing when the DaemonSet is gone.
func TestAgentMissing(t *testing.T) {
	inv, rep := agentFixture(fixture(), t0)
	const ds = "kubesentry/kubesentry-agent"
	f := run(Input{View: view(inv, t0), Agents: rep, Now: t0}, runOptions{agentDaemonSet: ds})
	var c *Candidate
	for i := range f.Candidates {
		if f.Candidates[i].Check == CheckAgentMissing {
			c = &f.Candidates[i]
		}
	}
	if c == nil {
		t.Fatalf("no agent-missing candidate: %+v", f.Candidates)
	}
	if c.Key() != "agent-missing/DaemonSet//kubesentry/kubesentry-agent" || c.Extra["nodes"] != "n-never,n-silent" || c.Extra["count"] != "2" ||
		c.Node != "" || c.Namespace != "" || c.Severity != SeverityWarning || c.Link != "#/agents" {
		t.Errorf("candidate %+v", c)
	}
	if g := GateOf(c.Check, c.Kind); g != GateAgents {
		t.Errorf("gate %s", g)
	}

	// One silent node is named in the node label.
	rep.Last["n-never"] = t0
	f = run(Input{View: view(inv, t0), Agents: rep, Now: t0}, runOptions{agentDaemonSet: ds})
	if cs := candidatesByKey(f); cs["agent-missing/DaemonSet//"+ds].Node != "n-silent" {
		t.Errorf("one node: %+v", cs["agent-missing/DaemonSet//"+ds])
	}
	// Without reports: skipped, not resolved.
	f = run(Input{View: view(inv, t0), Now: t0}, runOptions{agentDaemonSet: ds})
	if !f.Skipped[CheckAgentMissing] {
		t.Error("not skipped without reports")
	}
	// The DaemonSet gone: nothing expected (and not skipped, so it resolves).
	gone := inv
	gone.Workloads = inv.Workloads[:len(inv.Workloads)-2]
	f = run(Input{View: view(gone, t0), Agents: rep, Now: t0}, runOptions{agentDaemonSet: ds})
	if _, ok := candidatesByKey(f)["agent-missing/DaemonSet//"+ds]; ok || f.Skipped[CheckAgentMissing] {
		t.Errorf("missing DaemonSet: %+v skipped %v", f.Candidates, f.Skipped)
	}
	// No DaemonSet configured: no check.
	f = run(Input{View: view(inv, t0), Agents: rep, Now: t0}, runOptions{})
	if _, ok := candidatesByKey(f)["agent-missing/DaemonSet//"+ds]; ok || f.Skipped[CheckAgentMissing] {
		t.Error("ran without a DaemonSet")
	}

	// Through the evaluator: 10 minutes pending, then it fires. n-ok keeps
	// reporting; n-young is old enough to be expected from +5m on.
	h := newHarness(t, Options{AgentDaemonSet: ds})
	h.inv, h.agents = agentFixture(fixture(), t0)
	for _, d := range []time.Duration{0, 5 * time.Minute, 9 * time.Minute} {
		h.agents.Last["n-ok"] = t0.Add(d)
		if _, sent := h.at(d); sentByKey(sent)["agent-missing/DaemonSet//"+ds].Labels != nil {
			t.Fatalf("+%s: fired before its pending time", d)
		}
	}
	h.agents.Last["n-ok"] = t0.Add(10 * time.Minute)
	_, sent := h.at(10 * time.Minute)
	a, ok := sentByKey(sent)["agent-missing/DaemonSet//"+ds]
	if !ok || a.Labels["alertname"] != AlertAgentMissing || a.Labels["object"] != "DaemonSet/"+ds || a.Labels["owner"] != "platform" ||
		a.Labels["namespace"] != "" || a.Annotations["count"] != "3" || a.Annotations["nodes"] != "n-never,n-silent,n-young" || !a.StartsAt.Equal(t0) {
		t.Fatalf("after 10m: %+v (sent %v)", a, names(sent))
	}
}
