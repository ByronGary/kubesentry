package detectors

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
)

// ctrl is a controller ownerReference to kind/name, with the UID the fixtures
// give every object ("uid-<name>").
func ctrl(kind, name string) []model.OwnerRef {
	return []model.OwnerRef{{Kind: kind, Name: name, UID: "uid-" + name, Controller: true}}
}

func labels(kv ...string) map[string]string {
	m := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return m
}

func runningPod(ns, name string, owners []model.OwnerRef, lbl map[string]string) model.Pod {
	return model.Pod{UID: "uid-" + name, Namespace: ns, Name: name, Phase: "Running", Ready: true,
		ReadyChanged: podNow.Add(-time.Hour), Owners: owners, Labels: lbl, NodeName: "n1"}
}

func deployment(ns, name string, s *model.LabelSelector) model.Workload {
	return model.Workload{Kind: "Deployment", Namespace: ns, Name: name, UID: "uid-" + name, Selector: s, Desired: 1, Ready: 1, Updated: 1}
}

func replicaSet(ns, name string, owners []model.OwnerRef) model.ReplicaSet {
	return model.ReplicaSet{Namespace: ns, Name: name, UID: "uid-" + name, Owners: owners, Desired: 1, Ready: 1}
}

func ep(pod string, ready, serving, terminating bool) model.Endpoint {
	return model.Endpoint{Addresses: []string{"10.0.0." + fmt.Sprint(len(pod))}, Ready: ready, Serving: serving, Terminating: terminating,
		TargetKind: "Pod", TargetName: pod, TargetUID: "uid-" + pod}
}

func slice(ns, svc, name string, eps ...model.Endpoint) model.EndpointSlice {
	return model.EndpointSlice{Namespace: ns, Name: name, Service: svc, ManagedBy: "endpointslice-controller.k8s.io", Endpoints: eps}
}

func ownerString(a *Assoc, p model.Pod) string {
	r, how, ok := a.OwnerOf(&p)
	if !ok {
		return "-"
	}
	return r.Kind + "/" + r.Name + " " + how
}

func podNames(ps []*model.Pod) string {
	var out []string
	for _, p := range ps {
		out = append(out, p.Name)
	}
	slices.Sort(out)
	return strings.Join(out, " ")
}

func TestAssociateOwners(t *testing.T) {
	inv := model.Inventory{
		ReadAt: podNow,
		Nodes:  []model.Node{{Name: "n1", Ready: true}},
		Workloads: []model.Workload{
			// Overlapping selectors: canary pods match both, owners tell them apart.
			deployment("shop", "web", sel("app", "web")),
			deployment("shop", "web-canary", sel("app", "web", "track", "canary")),
			deployment("shop", "api", sel("app", "api")),
			{Kind: "StatefulSet", Namespace: "shop", Name: "db", UID: "uid-db", Selector: sel("app", "db")},
			{Kind: "Job", Namespace: "shop", Name: "batch-a", UID: "uid-batch-a", Selector: sel("batch", "x")},
			{Kind: "Job", Namespace: "shop", Name: "batch-b", UID: "uid-batch-b", Selector: sel("batch", "x")},
			deployment("shop", "lone-selector", sel("role", "lone")),
		},
		ReplicaSets: []model.ReplicaSet{
			replicaSet("shop", "web-111", ctrl("Deployment", "web")),
			replicaSet("shop", "web-222", ctrl("Deployment", "web")), // mid-rollout: two ReplicaSets
			replicaSet("shop", "web-canary-333", ctrl("Deployment", "web-canary")),
			replicaSet("shop", "orphan-444", nil),
			replicaSet("shop", "gone-555", ctrl("Deployment", "gone")),
			replicaSet("shop", "checkout-666", ctrl("Rollout", "checkout")),
		},
		Pods: []model.Pod{
			runningPod("shop", "web-111-a", ctrl("ReplicaSet", "web-111"), labels("app", "web")),
			runningPod("shop", "web-222-b", ctrl("ReplicaSet", "web-222"), labels("app", "web")),
			runningPod("shop", "web-canary-333-c", ctrl("ReplicaSet", "web-canary-333"), labels("app", "web", "track", "canary")),
			runningPod("shop", "db-0", ctrl("StatefulSet", "db"), labels("app", "db")),
			runningPod("shop", "batch-a-1", ctrl("Job", "batch-a"), labels("batch", "x")),
			runningPod("shop", "batch-b-1", ctrl("Job", "batch-b"), labels("batch", "x")),
			runningPod("shop", "orphan-444-d", ctrl("ReplicaSet", "orphan-444"), labels("app", "web")),
			runningPod("shop", "gone-555-e", ctrl("ReplicaSet", "gone-555"), nil),
			runningPod("shop", "checkout-666-f", ctrl("ReplicaSet", "checkout-666"), nil),
			runningPod("shop", "operated-0", ctrl("MyDatabase", "pg"), nil),
			runningPod("shop", "kube-apiserver-n1", ctrl("Node", "n1"), nil),
			runningPod("shop", "mirror-on-ghost", ctrl("Node", "ghost"), nil),
			runningPod("shop", "bare", nil, labels("x", "y")),
			runningPod("shop", "bare-matched", nil, labels("role", "lone")),
			// The owner is missing and nothing else is tried, even though a selector matches.
			runningPod("shop", "missing-job-1", ctrl("Job", "deleted"), labels("app", "web")),
			// A ReplicaSet the inventory lacks resolves through pod-template-hash.
			runningPod("shop", "api-777-g", ctrl("ReplicaSet", "api-777"), labels("app", "api", "pod-template-hash", "777")),
			runningPod("shop", "nohash-888-h", ctrl("ReplicaSet", "nohash-888"), labels("app", "api")),
			// Same name, different UID: the Deployment was replaced.
			runningPod("shop", "stale-1", []model.OwnerRef{{Kind: "StatefulSet", Name: "db", UID: "uid-old-db", Controller: true}}, nil),
			// A non-controller reference alone is still followed.
			runningPod("shop", "weak-1", []model.OwnerRef{{Kind: "StatefulSet", Name: "db", UID: "uid-db"}}, nil),
		},
	}
	a := Associate(inv, DefaultPolicy())

	want := map[string]string{
		"web-111-a":         "Deployment/web owner",
		"web-222-b":         "Deployment/web owner",
		"web-canary-333-c":  "Deployment/web-canary owner",
		"db-0":              "StatefulSet/db owner",
		"batch-a-1":         "Job/batch-a owner",
		"batch-b-1":         "Job/batch-b owner",
		"orphan-444-d":      "ReplicaSet/orphan-444 owner",
		"gone-555-e":        "ReplicaSet/gone-555 owner",
		"checkout-666-f":    "Controller/checkout owner",
		"operated-0":        "Controller/pg owner",
		"kube-apiserver-n1": "Node/n1 owner",
		"mirror-on-ghost":   "Node/ghost owner",
		"bare":              "-",
		"bare-matched":      "Deployment/lone-selector selector",
		"missing-job-1":     "Job/deleted owner",
		"api-777-g":         "Deployment/api owner",
		"nohash-888-h":      "ReplicaSet/nohash-888 owner",
		"stale-1":           "StatefulSet/db owner",
		"weak-1":            "StatefulSet/db owner",
	}
	for _, p := range inv.Pods {
		if got := ownerString(a, p); got != want[p.Name] {
			t.Errorf("%s: owner %q, want %q", p.Name, got, want[p.Name])
		}
	}

	found := map[string]bool{
		"Deployment/web": true, "ReplicaSet/orphan-444": true, "ReplicaSet/gone-555": true, "Controller/checkout": false,
		"Node/n1": true, "Node/ghost": false, "Job/deleted": false, "ReplicaSet/nohash-888": false,
	}
	for k, w := range found {
		kind, name, _ := strings.Cut(k, "/")
		ns := "shop"
		if kind == "Node" {
			ns = ""
		}
		if got := a.Found(Ref{Kind: kind, Namespace: ns, Name: name}); got != w {
			t.Errorf("Found(%s) = %v, want %v", k, got, w)
		}
	}
	if got := podNames(a.PodsOf(Ref{Kind: "Deployment", Namespace: "shop", Name: "web"})); got != "web-111-a web-222-b" {
		t.Errorf("web pods = %s; canary pods and the orphaned ReplicaSet's must not count", got)
	}
	if got := podNames(a.PodsOf(Ref{Kind: "Deployment", Namespace: "shop", Name: "web-canary"})); got != "web-canary-333-c" {
		t.Errorf("canary pods = %s", got)
	}
	if got := a.ControllerKind(Ref{Kind: KindController, Namespace: "shop", Name: "checkout"}); got != "Rollout" {
		t.Errorf("controller kind = %q", got)
	}
	checkout := inv.Pods[8]
	if got := a.WorkloadOf(&checkout); got != "Rollout/checkout" {
		t.Errorf("workload of a Rollout pod = %q", got)
	}
	bare := inv.Pods[12]
	if got := a.WorkloadOf(&bare); got != "" {
		t.Errorf("bare pod workload = %q", got)
	}

	// A pod read after the inventory (the pod page) resolves the same way.
	fresh := runningPod("shop", "web-111-z", ctrl("ReplicaSet", "web-111"), labels("app", "web"))
	if got := ownerString(a, fresh); got != "Deployment/web owner" {
		t.Errorf("fresh pod owner = %s", got)
	}
}

func TestAssociateStaleUIDIsMissing(t *testing.T) {
	inv := model.Inventory{
		Workloads: []model.Workload{{Kind: "StatefulSet", Namespace: "a", Name: "db", UID: "uid-new"}},
		Pods:      []model.Pod{{Namespace: "a", Name: "db-0", Owners: []model.OwnerRef{{Kind: "StatefulSet", Name: "db", UID: "uid-old", Controller: true}}}},
	}
	a := Associate(inv, DefaultPolicy())
	r, how, ok := a.OwnerOf(&inv.Pods[0])
	if !ok || how != HowOwner || r.UID != "uid-old" {
		t.Fatalf("owner = %+v %s %v", r, how, ok)
	}
	if o := a.ownerOfPod(&inv.Pods[0]); o.found {
		t.Error("an owner replaced under the same name is not the pod's owner")
	}
}

func TestAssociateJobParents(t *testing.T) {
	inv := model.Inventory{Workloads: []model.Workload{
		{Kind: "CronJob", Namespace: "a", Name: "nightly", UID: "uid-nightly"},
		{Kind: "CronJob", Namespace: "a", Name: "report", UID: "uid-report"},
		{Kind: "Job", Namespace: "a", Name: "custom-name", Owners: ctrl("CronJob", "nightly")},
		{Kind: "Job", Namespace: "a", Name: "report-29000000"},                             // no ownerRefs: naming scheme
		{Kind: "Job", Namespace: "a", Name: "nightly-29000001", Owners: ctrl("Argo", "x")}, // has ownerRefs: no guessing
		{Kind: "Job", Namespace: "a", Name: "orphaned", Owners: ctrl("CronJob", "deleted")},
	}}
	a := Associate(inv, DefaultPolicy())
	cases := map[string]string{
		"custom-name":      "nightly owner",
		"report-29000000":  "report name",
		"nightly-29000001": "-",
		"orphaned":         "deleted owner",
	}
	for job, want := range cases {
		got := "-"
		if r, how, ok := a.JobParent("a", job); ok {
			got = r.Name + " " + how
		}
		if got != want {
			t.Errorf("JobParent(%s) = %q, want %q", job, got, want)
		}
	}
}

func TestAssociateServiceEndpoints(t *testing.T) {
	var many []model.Endpoint
	var pods []model.Pod
	for i := range 250 {
		name := fmt.Sprintf("big-%03d", i)
		pods = append(pods, runningPod("shop", name, ctrl("ReplicaSet", "big-1"), labels("app", "big")))
		many = append(many, ep(name, true, true, false))
	}
	pods = append(pods,
		runningPod("shop", "job-a-1", ctrl("Job", "job-a"), labels("batch", "x")),
		runningPod("shop", "job-b-1", ctrl("Job", "job-b"), labels("batch", "x")),
		runningPod("shop", "front-1", ctrl("ReplicaSet", "front-1"), labels("app", "shop")),
		runningPod("shop", "cache-0", ctrl("StatefulSet", "cache"), labels("app", "shop")),
		runningPod("shop", "ext-target", nil, nil),
	)
	inv := model.Inventory{
		ReadAt: podNow,
		Workloads: []model.Workload{
			deployment("shop", "big", sel("app", "big")),
			deployment("shop", "front", sel("app", "shop")),
			{Kind: "StatefulSet", Namespace: "shop", Name: "cache", UID: "uid-cache", Selector: sel("app", "shop")},
			{Kind: "Job", Namespace: "shop", Name: "job-a", UID: "uid-job-a", Selector: sel("batch", "x")},
			{Kind: "Job", Namespace: "shop", Name: "job-b", UID: "uid-job-b", Selector: sel("batch", "x")},
		},
		ReplicaSets: []model.ReplicaSet{replicaSet("shop", "big-1", ctrl("Deployment", "big")), replicaSet("shop", "front-1", ctrl("Deployment", "front"))},
		Services: []model.Service{
			{Namespace: "shop", Name: "big", Selector: labels("app", "big")},
			{Namespace: "shop", Name: "batch", Selector: labels("batch", "x")},
			{Namespace: "shop", Name: "shop", Selector: labels("app", "shop")},
			{Namespace: "shop", Name: "manual"},
			{Namespace: "shop", Name: "no-slices", Selector: labels("app", "shop"), Created: podNow.Add(-time.Hour)},
			{Namespace: "shop", Name: "brand-new", Selector: labels("app", "shop"), Created: podNow.Add(-10 * time.Second)},
		},
		EndpointSlices: []model.EndpointSlice{
			// 250 endpoints split over three slices, plus a dual-stack duplicate.
			slice("shop", "big", "big-a", many[:100]...),
			slice("shop", "big", "big-b", many[100:200]...),
			slice("shop", "big", "big-c", many[200:]...),
			slice("shop", "big", "big-v6", ep("big-000", true, true, false)),
			slice("shop", "batch", "batch-x", ep("job-a-1", true, true, false), ep("job-b-1", false, false, false)),
			slice("shop", "shop", "shop-x", ep("front-1", true, true, false), ep("cache-0", false, true, true)),
			{Namespace: "shop", Name: "manual-1", Service: "manual", ManagedBy: "staff", Endpoints: []model.Endpoint{
				{Addresses: []string{"10.1.0.9"}, Ready: true, Serving: true, TargetKind: "Pod", TargetName: "ext-target"},
				{Addresses: []string{"192.0.2.10"}, Ready: true, Serving: true},
			}},
		},
		Pods: pods,
	}
	a := Associate(inv, DefaultPolicy())

	big := a.ServiceEndpoints("shop", "big")
	if len(big) != 250 || a.ServiceHow("shop", "big") != HowEndpoints {
		t.Fatalf("big service has %d endpoints via %q, want 250 via endpoints", len(big), a.ServiceHow("shop", "big"))
	}
	for _, e := range big {
		if e.Owner.Kind != "Deployment" || e.Owner.Name != "big" {
			t.Fatalf("endpoint %+v not owned by Deployment big", e)
		}
	}

	owners := func(svc string) string {
		var out []string
		for _, e := range a.ServiceEndpoints("shop", svc) {
			s := e.PodName + "=" + e.Owner.Kind + "/" + e.Owner.Name
			if e.Ready {
				s += "+ready"
			}
			if e.Serving {
				s += "+serving"
			}
			if e.Terminating {
				s += "+terminating"
			}
			out = append(out, s)
		}
		return strings.Join(out, " ")
	}
	if got := owners("batch"); got != "job-a-1=Job/job-a+ready+serving job-b-1=Job/job-b" {
		t.Errorf("two Jobs with identical labels: %s", got)
	}
	if got := owners("shop"); got != "cache-0=StatefulSet/cache+serving+terminating front-1=Deployment/front+ready+serving" {
		t.Errorf("multi-workload service: %s", got)
	}
	manual := a.ServiceEndpoints("shop", "manual")
	if len(manual) != 2 || manual[0].PodName != "" || manual[0].Address != "192.0.2.10" || manual[1].PodName != "ext-target" || manual[1].PodUID != "uid-ext-target" {
		t.Errorf("manual slice endpoints = %+v", manual)
	}
	// Slices are available, so an old Service without any is empty, not
	// guessed from its selector; a brand-new one is still being populated.
	if eps, how := a.ServiceEndpoints("shop", "no-slices"), a.ServiceHow("shop", "no-slices"); len(eps) != 0 || how != "" {
		t.Errorf("no-slices = %+v via %q", eps, how)
	}
	if eps, how := a.ServiceEndpoints("shop", "brand-new"), a.ServiceHow("shop", "brand-new"); len(eps) != 2 || how != HowSelector {
		t.Errorf("brand-new = %+v via %q", eps, how)
	}
	if got := a.ServicesOfPod("uid-front-1"); strings.Join(got, ",") != "brand-new,shop" {
		t.Errorf("services of front-1 = %v", got)
	}
	if got := a.ServicesOfPod("uid-job-b-1"); strings.Join(got, ",") != "batch" {
		t.Errorf("services of job-b-1 = %v", got)
	}
}

func TestAssociateSelectorFallbackWithoutSlices(t *testing.T) {
	inv := model.Inventory{
		Unavailable: map[string]string{"EndpointSlices.discovery.k8s.io": "forbidden"},
		Workloads:   []model.Workload{deployment("a", "web", sel("app", "web"))},
		Pods: []model.Pod{
			runningPod("a", "web-1", nil, labels("app", "web")),
			{Namespace: "a", Name: "web-done", Phase: "Succeeded", Labels: labels("app", "web")},
			{Namespace: "a", Name: "web-going", UID: "uid-web-going", Phase: "Running", Labels: labels("app", "web"), DeletedAt: podNow},
		},
		Services: []model.Service{{Namespace: "a", Name: "web", Selector: labels("app", "web")}, {Namespace: "a", Name: "ext", Type: "ExternalName", Selector: labels("app", "web")}},
	}
	a := Associate(inv, DefaultPolicy())
	eps := a.ServiceEndpoints("a", "web")
	if a.ServiceHow("a", "web") != HowSelector || len(eps) != 2 {
		t.Fatalf("fallback endpoints = %+v via %q", eps, a.ServiceHow("a", "web"))
	}
	if !eps[0].Ready || eps[1].Ready || !eps[1].Terminating || eps[0].Owner.Name != "web" {
		t.Errorf("fallback states = %+v", eps)
	}
	if a.ServiceEndpoints("a", "ext") != nil {
		t.Error("an ExternalName service has no endpoints")
	}
}

func TestSystemNamespaceSetLabelOverride(t *testing.T) {
	p := DefaultPolicy()
	set := SystemNamespaceSet(p, []model.Namespace{
		{Name: "kube-system", Labels: labels("kubesentry.io/system", "false")},
		{Name: "platform", Labels: labels("kubesentry.io/system", "true")},
		{Name: "karpenter"},
	})
	if set["kube-system"] || !set["platform"] || !set["karpenter"] {
		t.Errorf("system set = %v", set)
	}
	if !p.IsSystemPrincipal("eks:addon-manager") || p.IsSystemPrincipal("system:authenticated") || p.IsSystemPrincipal("alice") {
		t.Error("system principal prefixes")
	}
	if !p.IsBuiltinRBAC("kubeadm:cluster-admins") || p.IsBuiltinRBAC("team-admin") {
		t.Error("builtin RBAC prefixes")
	}
	if z := (Policy{}).WithDefaults(); z.Thresholds != p.Thresholds || z.SystemNamespaceLabel != p.SystemNamespaceLabel || !z.SystemNamespaces["kube-system"] {
		t.Errorf("zero policy defaults = %+v", z)
	}
	custom := Policy{SystemNamespaces: map[string]bool{"ops": true}}.WithDefaults()
	if !custom.SystemNamespaces["ops"] || custom.SystemNamespaces["kube-system"] || custom.Thresholds.RestartWarn != 3 {
		t.Errorf("partial policy defaults = %+v", custom)
	}
	if !SystemNamespaces["amazon-cloudwatch"] {
		t.Error("the deprecated SystemNamespaces variable follows the default policy")
	}
}
