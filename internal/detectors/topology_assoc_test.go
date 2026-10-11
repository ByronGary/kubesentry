package detectors

import (
	"strings"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
)

func edgeMap(g Graph) map[string]GraphEdge {
	m := map[string]GraphEdge{}
	for _, e := range g.Edges {
		m[e.From+" -> "+e.To] = e
	}
	return m
}

func nodeMap(g Graph) map[string]GraphNode {
	m := map[string]GraphNode{}
	for _, n := range g.Nodes {
		m[n.ID] = n
	}
	return m
}

func TestBuildTopologyWithOwnersAndEndpoints(t *testing.T) {
	notReady := runningPod("shop", "web-222-x", ctrl("ReplicaSet", "web-222"), labels("app", "web"))
	notReady.Ready, notReady.ReadyChanged = false, podNow.Add(-time.Minute)
	going := runningPod("shop", "web-111-y", ctrl("ReplicaSet", "web-111"), labels("app", "web"))
	going.Ready, going.DeletedAt = false, podNow.Add(-time.Minute)
	stuck := runningPod("shop", "db-1", ctrl("StatefulSet", "db"), labels("app", "db"))
	stuck.Ready = false
	stuck.Containers = []model.ContainerStatus{{Name: "db", State: "waiting", Reason: "CrashLoopBackOff", RestartCount: 1}}

	inv := model.Inventory{
		ReadAt: podNow,
		Nodes:  []model.Node{{Name: "n1", Ready: true}},
		Workloads: []model.Workload{
			deployment("shop", "web", sel("app", "web")),
			{Kind: "StatefulSet", Namespace: "shop", Name: "db", UID: "uid-db", Selector: sel("app", "db"), Desired: 2, Ready: 1, Updated: 2},
			{Kind: "CronJob", Namespace: "shop", Name: "nightly", UID: "uid-nightly"},
			{Kind: "Job", Namespace: "shop", Name: "renamed", UID: "uid-renamed", Owners: ctrl("CronJob", "nightly"), Active: 1, Desired: 1},
		},
		ReplicaSets: []model.ReplicaSet{
			replicaSet("shop", "web-111", ctrl("Deployment", "web")),
			replicaSet("shop", "web-222", ctrl("Deployment", "web")),
			{Namespace: "shop", Name: "legacy-9", UID: "uid-legacy-9", Desired: 2, Ready: 1},
			replicaSet("shop", "checkout-5", ctrl("Rollout", "checkout")),
		},
		Pods: []model.Pod{
			runningPod("shop", "web-111-a", ctrl("ReplicaSet", "web-111"), labels("app", "web")),
			runningPod("shop", "web-111-b", ctrl("ReplicaSet", "web-111"), labels("app", "web")),
			going,
			notReady,
			runningPod("shop", "db-0", ctrl("StatefulSet", "db"), labels("app", "db")),
			stuck,
			runningPod("shop", "legacy-9-a", ctrl("ReplicaSet", "legacy-9"), labels("app", "legacy")),
			runningPod("shop", "checkout-5-a", ctrl("ReplicaSet", "checkout-5"), labels("app", "checkout")),
			runningPod("shop", "renamed-a", ctrl("Job", "renamed"), nil),
			runningPod("shop", "ghost-a", ctrl("Deployment", "ghost"), nil),
			runningPod("shop", "static-n1", ctrl("Node", "n1"), labels("tier", "static")),
		},
		Services: []model.Service{
			{Namespace: "shop", Name: "web", Type: "LoadBalancer", Selector: labels("app", "web")},
			{Namespace: "shop", Name: "db", ClusterIP: "None", Selector: labels("app", "db"), PublishNotReady: true},
			{Namespace: "shop", Name: "empty", Selector: labels("app", "none")},
			{Namespace: "shop", Name: "static", Selector: labels("tier", "static")},
			{Namespace: "shop", Name: "dead", Selector: labels("app", "web")},
		},
		EndpointSlices: []model.EndpointSlice{
			slice("shop", "web", "web-1",
				ep("web-111-a", true, true, false), ep("web-111-b", true, true, false), ep("web-111-y", false, false, true), ep("web-222-x", false, false, false)),
			// publishNotReadyAddresses: ready is forced true, serving tells the truth.
			slice("shop", "db", "db-1", ep("db-0", true, true, false), ep("db-1", true, false, false)),
			slice("shop", "empty", "empty-1"),
			slice("shop", "static", "static-1", ep("static-n1", true, true, false)),
			slice("shop", "dead", "dead-1", ep("web-222-x", false, false, false)),
		},
	}
	p := DefaultPolicy()
	g := BuildTopologyWith("shop", Associate(inv, p), p, podNow)
	nodes, edges := nodeMap(g), edgeMap(g)

	wantNodes := map[string]string{
		"Service/shop/web":         "warn LoadBalancer, 2 ready, 1 not ready, 1 terminating.",
		"Service/shop/db":          "warn ClusterIP, 1 ready, 1 not ready. Publishes not-ready addresses.",
		"Service/shop/empty":       "warn ClusterIP, no endpoints.",
		"Service/shop/dead":        "crit ClusterIP, 0 ready, 1 not ready.",
		"ReplicaSet/shop/legacy-9": "warn No Deployment owns it. 1 of 2 ready.",
		"Controller/shop/checkout": "ok Managed by Rollout checkout, which kubesentry does not track; 1 of 1 pods ready.",
		"Deployment/shop/ghost":    "unknown Deployment ghost was not found; it may have just been deleted or not yet been seen.",
		"Pod/shop/db-1":            "crit db: CrashLoopBackOff.",
		"Pod/shop/web-111-y":       "ok Terminating.",
		"StatefulSet/shop/db":      "warn 1 of 2 ready. 1 pod in CrashLoopBackOff.",
	}
	for id, want := range wantNodes {
		n, ok := nodes[id]
		if got := n.Status + " " + n.Detail; !ok || got != want {
			t.Errorf("%s = %q, want %q", id, got, want)
		}
	}
	if nodes["Controller/shop/checkout"].OwnerKind != "Rollout" {
		t.Errorf("controller node = %+v", nodes["Controller/shop/checkout"])
	}
	for _, id := range []string{"ReplicaSet/shop/web-111", "ReplicaSet/shop/web-222", "Node/shop/n1"} {
		if _, ok := nodes[id]; ok {
			t.Errorf("unexpected node %s: a Deployment stands for its ReplicaSets", id)
		}
	}

	type e struct {
		how                         string
		ready, notReady, terminated int
	}
	wantEdges := map[string]e{
		"Service/shop/web -> Deployment/shop/web":             {HowEndpoints, 2, 1, 1},
		"Service/shop/db -> StatefulSet/shop/db":              {HowEndpoints, 1, 1, 0},
		"Service/shop/static -> Pod/shop/static-n1":           {HowEndpoints, 1, 0, 0},
		"Deployment/shop/web -> Pod/shop/web-111-a":           {HowOwner, 0, 0, 0},
		"Deployment/shop/web -> Pod/shop/web-222-x":           {HowOwner, 0, 0, 0},
		"ReplicaSet/shop/legacy-9 -> Pod/shop/legacy-9-a":     {HowOwner, 0, 0, 0},
		"Controller/shop/checkout -> Pod/shop/checkout-5-a":   {HowOwner, 0, 0, 0},
		"CronJob/shop/nightly -> Job/shop/renamed":            {HowOwner, 0, 0, 0},
		"Job/shop/renamed -> Pod/shop/renamed-a":              {HowOwner, 0, 0, 0},
		"Deployment/shop/ghost -> Pod/shop/ghost-a":           {HowOwner, 0, 0, 0},
		"Pod/shop/static-n1 -> Node/n1":                       {"", 0, 0, 0},
		"Service/shop/dead -> Deployment/shop/web":            {HowEndpoints, 0, 1, 0},
		"Service/shop/web -> Pod/shop/web-111-a":              {"absent", 0, 0, 0},
		"Node/n1 -> Pod/shop/static-n1":                       {"absent", 0, 0, 0},
		"Service/shop/empty -> Deployment/shop/web":           {"absent", 0, 0, 0},
		"Service/shop/web -> ReplicaSet/shop/web-111":         {"absent", 0, 0, 0},
		"Service/shop/static -> Node/n1":                      {"absent", 0, 0, 0},
		"ReplicaSet/shop/checkout-5 -> Pod/shop/checkout-5-a": {"absent", 0, 0, 0},
	}
	for k, w := range wantEdges {
		got, ok := edges[k]
		if w.how == "absent" {
			if ok {
				t.Errorf("unexpected edge %s", k)
			}
			continue
		}
		if !ok {
			t.Errorf("missing edge %s", k)
			continue
		}
		if got.How != w.how || got.Ready != w.ready || got.NotReady != w.notReady || got.Terminating != w.terminated {
			t.Errorf("%s = %+v, want %+v", k, got, w)
		}
	}
}

func TestBuildTopologyLegacyCronJobNaming(t *testing.T) {
	// No ownerReferences anywhere: the old fixtures keep working by selector
	// and by the CronJob naming scheme, and edges say so.
	in := TopologyInput{
		Now: podNow,
		Workloads: []model.Workload{
			{Kind: "CronJob", Namespace: "shop", Name: "nightly"},
			{Kind: "Job", Namespace: "shop", Name: "nightly-29123400", Desired: 1, Active: 1, Selector: sel("job", "n")},
		},
		Pods: []model.Pod{{Namespace: "shop", Name: "nightly-29123400-abc", Phase: "Running", Labels: labels("job", "n")}},
	}
	edges := edgeMap(BuildTopology("shop", in))
	if e, ok := edges["CronJob/shop/nightly -> Job/shop/nightly-29123400"]; !ok || e.How != "" {
		t.Errorf("cronjob edge = %+v %v", e, ok)
	}
	if e := edges["Job/shop/nightly-29123400 -> Pod/shop/nightly-29123400-abc"]; e.How != HowSelector {
		t.Errorf("job edge = %+v", e)
	}
}

func TestSummarizeNodesPlacementAndPods(t *testing.T) {
	crash := runningPod("a", "crash", ctrl("ReplicaSet", "web-1"), nil)
	crash.NodeName = "ip-1"
	crash.Ready = false
	crash.Containers = []model.ContainerStatus{{Name: "c", State: "waiting", Reason: "ImagePullBackOff"}}
	done := model.Pod{Namespace: "a", Name: "done", Phase: "Succeeded", NodeName: "ip-1", Created: podNow.Add(-time.Hour)}
	inv := model.Inventory{
		Nodes: []model.Node{
			{Name: "ip-1", Ready: true, ProviderID: "aws:///us-east-1b/i-0abc", Labels: map[string]string{
				"eks.amazonaws.com/nodegroup": "general", "eks.amazonaws.com/capacityType": "SPOT",
				"node.kubernetes.io/instance-type": "m7g.large", "kubernetes.io/arch": "arm64", "kubernetes.io/os": "linux"}},
			{Name: "ip-2", Ready: true, Labels: map[string]string{"karpenter.sh/nodepool": "burst", "karpenter.sh/capacity-type": "on-demand",
				"topology.kubernetes.io/zone": "eu-west-1a", "topology.kubernetes.io/region": "eu-west-1"}},
			{Name: "fargate-ip-3", Ready: true, Labels: map[string]string{"eks.amazonaws.com/compute-type": "fargate"}},
			{Name: "cp", Ready: true, Roles: []string{"control-plane"}},
		},
		Workloads:   []model.Workload{deployment("a", "web", sel("app", "web"))},
		ReplicaSets: []model.ReplicaSet{replicaSet("a", "web-1", ctrl("Deployment", "web"))},
		Pods:        []model.Pod{crash, done},
	}
	p := DefaultPolicy()
	got := SummarizeNodesWith(inv.Nodes, Associate(inv, p), p, podNow)
	by := map[string]NodeSummary{}
	for _, n := range got {
		by[n.Name] = n
	}
	n1 := by["ip-1"]
	wantPl := Placement{Zone: "us-east-1b", Region: "us-east-1", InstanceType: "m7g.large", Arch: "arm64", OS: "linux",
		Pool: "general", PoolKind: PoolNodegroup, CapacityType: "spot", ProviderID: "aws:///us-east-1b/i-0abc"}
	if n1.Placement != wantPl || strings.Join(n1.Roles, ",") != "nodegroup:general" {
		t.Errorf("ip-1 placement %+v roles %v", n1.Placement, n1.Roles)
	}
	if n1.PodCount != 1 || len(n1.Pods) != 2 {
		t.Errorf("ip-1 pod count %d, listed %d", n1.PodCount, len(n1.Pods))
	}
	if cp := n1.Pods[0]; cp.Name != "crash" || cp.Ready || cp.Reason != "ImagePullBackOff" || cp.Status != StatusCrit || cp.Workload != "Deployment/web" {
		t.Errorf("crash pod row = %+v", cp)
	}
	if n2 := by["ip-2"]; n2.Placement.PoolKind != PoolKarpenter || n2.Placement.CapacityType != "on-demand" || strings.Join(n2.Roles, ",") != "nodepool:burst" || n2.Placement.Zone != "eu-west-1a" {
		t.Errorf("ip-2 = %+v %v", n2.Placement, n2.Roles)
	}
	if f := by["fargate-ip-3"]; f.Placement.PoolKind != PoolFargate || strings.Join(f.Roles, ",") != "fargate" {
		t.Errorf("fargate = %+v %v", f.Placement, f.Roles)
	}
	if c := by["cp"]; strings.Join(c.Roles, ",") != "control-plane" || c.Placement.PoolKind != "" {
		t.Errorf("control plane = %+v %v", c.Placement, c.Roles)
	}
}

func TestPlacementOf(t *testing.T) {
	cases := []struct {
		name string
		n    model.Node
		want Placement
	}{
		{"legacy labels", model.Node{Labels: map[string]string{"failure-domain.beta.kubernetes.io/zone": "us-west-2c", "beta.kubernetes.io/instance-type": "t3.small"}},
			Placement{Zone: "us-west-2c", Region: "us-west-2", InstanceType: "t3.small"}},
		{"karpenter v0.x provisioner", model.Node{Labels: map[string]string{"karpenter.sh/provisioner-name": "default", "karpenter.sh/capacity-type": "spot"}},
			Placement{Pool: "default", PoolKind: PoolKarpenter, CapacityType: "spot"}},
		{"on demand", model.Node{Labels: map[string]string{"eks.amazonaws.com/nodegroup": "ng", "eks.amazonaws.com/capacityType": "ON_DEMAND"}},
			Placement{Pool: "ng", PoolKind: PoolNodegroup, CapacityType: "on-demand"}},
		{"kind", model.Node{ProviderID: "kind://docker/kubesentry/kubesentry-worker"}, Placement{ProviderID: "kind://docker/kubesentry/kubesentry-worker"}},
		{"local zone keeps no region guess", model.Node{Labels: map[string]string{"topology.kubernetes.io/zone": "us-east-1-bos-1a"}}, Placement{Zone: "us-east-1-bos-1a"}},
	}
	for _, c := range cases {
		if got := PlacementOf(c.n); got != c.want {
			t.Errorf("%s: %+v, want %+v", c.name, got, c.want)
		}
	}
	if r := NodeRoles(model.Node{Labels: map[string]string{"node-role.kubernetes.io/worker": "", "eks.amazonaws.com/nodegroup": "ng"}}); strings.Join(r, ",") != "worker" {
		t.Errorf("role labels win over the pool: %v", r)
	}
}
