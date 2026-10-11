package detectors

import (
	"strings"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
)

func topologyInput() TopologyInput {
	lbl := func(k, v string) map[string]string { return map[string]string{k: v} }
	return TopologyInput{
		Now: podNow,
		Workloads: []model.Workload{
			{Kind: "Deployment", Namespace: "shop", Name: "web", Desired: 2, Ready: 2, Updated: 2, Selector: sel("app", "web")},
			{Kind: "StatefulSet", Namespace: "shop", Name: "db", Desired: 1, Selector: sel("app", "db")},
			{Kind: "CronJob", Namespace: "shop", Name: "nightly"},
			{Kind: "Job", Namespace: "shop", Name: "old", Desired: 1, Selector: sel("job", "old"),
				Conditions: []model.Condition{{Type: "Complete", Status: "True"}}},
			{Kind: "Deployment", Namespace: "other", Name: "web", Desired: 1, Ready: 1, Updated: 1, Selector: sel("app", "web")},
		},
		Pods: []model.Pod{
			{Namespace: "shop", Name: "web-1", Phase: "Running", NodeName: "n1", Labels: lbl("app", "web"), Claims: []string{"data"}},
			{Namespace: "shop", Name: "web-2", Phase: "Running", NodeName: "n2", Labels: lbl("app", "web"),
				Containers: []model.ContainerStatus{{Name: "web", RestartCount: 1, LastTerminatedReason: "OOMKilled", LastTerminatedAt: podNow.Add(-2 * time.Hour)}}},
			{Namespace: "shop", Name: "db-0", Phase: "Pending", Labels: lbl("app", "db"), Claims: []string{"missing"}},
			{Namespace: "shop", Name: "lone", Phase: "Running", NodeName: "n3", Labels: lbl("app", "lone")},
			{Namespace: "shop", Name: "crashed", Phase: "Failed", NodeName: "n1", Created: podNow.Add(-time.Hour)},
			{Namespace: "shop", Name: "old-x", Phase: "Succeeded", NodeName: "n1", Labels: lbl("job", "old"), Created: podNow.Add(-48 * time.Hour)},
			{Namespace: "other", Name: "web-9", Phase: "Running", NodeName: "n1", Labels: lbl("app", "web")},
		},
		Services: []model.Service{
			{Namespace: "shop", Name: "web", Type: "LoadBalancer", Selector: lbl("app", "web")},
			{Namespace: "shop", Name: "api", Type: "ClusterIP", Selector: lbl("app", "api")},
			{Namespace: "shop", Name: "lone", Selector: lbl("app", "lone")},
			{Namespace: "shop", Name: "ext", Type: "ExternalName"},
			{Namespace: "shop", Name: "manual", Type: "ClusterIP"},
			{Namespace: "other", Name: "web", Selector: lbl("app", "web")},
		},
		Ingresses: []model.Ingress{
			{Namespace: "shop", Name: "main", DefaultBackend: "ghost", TLS: []model.IngressTLS{{Hosts: []string{"shop.example.com"}}},
				Rules: []model.IngressRule{{Host: "shop.example.com", Path: "/", Service: "web"}, {Host: "shop.example.com", Path: "/api", Service: "api"}}},
			{Namespace: "shop", Name: "plain", DefaultBackend: "web"},
		},
		Nodes: []model.Node{
			{Name: "n1", Ready: true},
			{Name: "n2", Conditions: []model.Condition{{Type: "Ready", Status: "Unknown", Message: "Kubelet stopped posting node status."}}},
			{Name: "unused", Ready: true},
		},
		PVCs: []model.PVC{
			{Namespace: "shop", Name: "data", Phase: "Bound", StorageClass: "gp3"},
			{Namespace: "shop", Name: "spare", Phase: "Bound", StorageClass: "gp3"},
		},
		StorageClasses: []model.StorageClass{{Name: "gp3"}},
	}
}

func TestBuildTopology(t *testing.T) {
	g := BuildTopology("shop", topologyInput())

	status := map[string]string{}
	var ids []string
	for _, n := range g.Nodes {
		status[n.ID] = n.Status + " " + n.Detail
		ids = append(ids, n.ID)
	}
	wantIDs := []string{
		"Ingress/shop/main", "Ingress/shop/plain",
		"Service/shop/api", "Service/shop/ext", "Service/shop/lone", "Service/shop/manual", "Service/shop/web",
		"Deployment/shop/web", "StatefulSet/shop/db", "Job/shop/old", "CronJob/shop/nightly",
		"Pod/shop/crashed", "Pod/shop/db-0", "Pod/shop/lone", "Pod/shop/web-1", "Pod/shop/web-2",
		"PVC/shop/data", "PVC/shop/missing",
		"Node/n1", "Node/n2", "Node/n3",
	}
	if strings.Join(ids, " ") != strings.Join(wantIDs, " ") {
		t.Errorf("nodes =\n%v\nwant\n%v", ids, wantIDs)
	}

	wantStatus := map[string]string{
		"Ingress/shop/main":    "warn Backend service ghost does not exist.",
		"Ingress/shop/plain":   "ok Default backend only.",
		"Service/shop/api":     "warn Selects no pods.",
		"Service/shop/web":     "ok LoadBalancer, selects 2 pods.",
		"Service/shop/lone":    "ok ClusterIP, selects 1 pod.",
		"Service/shop/manual":  "ok No selector; its endpoints are managed separately.",
		"StatefulSet/shop/db":  "crit 0 of 1 ready.",
		"Pod/shop/crashed":     "crit Failed.",
		"Pod/shop/db-0":        "warn Pending.",
		"Pod/shop/web-2":       "warn OOMKilled: web (2h ago).",
		"Pod/shop/web-1":       "ok Running.",
		"PVC/shop/data":        "ok Mounted by web-1.",
		"PVC/shop/missing":     "crit Claim does not exist.",
		"Node/n1":              "ok Ready.",
		"Node/n2":              "crit Not ready: Kubelet stopped posting node status.",
		"Node/n3":              "unknown Not in the node list.",
		"CronJob/shop/nightly": "ok Never run.",
	}
	for id, want := range wantStatus {
		if status[id] != want {
			t.Errorf("%s = %q, want %q", id, status[id], want)
		}
	}

	edges := map[string]bool{}
	for _, e := range g.Edges {
		key := e.From + " -> " + e.To
		if edges[key] {
			t.Errorf("duplicate edge %s", key)
		}
		edges[key] = true
		if status[e.From] == "" || status[e.To] == "" {
			t.Errorf("edge %s points at a node not on the map", key)
		}
	}
	for _, want := range []string{
		"Ingress/shop/main -> Service/shop/web",
		"Ingress/shop/main -> Service/shop/api",
		"Ingress/shop/plain -> Service/shop/web",
		"Service/shop/web -> Deployment/shop/web",
		"Service/shop/lone -> Pod/shop/lone", // nothing owns it
		"Deployment/shop/web -> Pod/shop/web-1",
		"Deployment/shop/web -> Pod/shop/web-2",
		"StatefulSet/shop/db -> Pod/shop/db-0",
		"Pod/shop/web-1 -> Node/n1",
		"Pod/shop/web-2 -> Node/n2",
		"Pod/shop/web-1 -> PVC/shop/data",
		"Pod/shop/db-0 -> PVC/shop/missing",
		"Pod/shop/crashed -> Node/n1",
	} {
		if !edges[want] {
			t.Errorf("missing edge %s", want)
		}
	}
	if len(g.Edges) != 14 { // the 13 above plus lone -> n3
		t.Errorf("got %d edges: %v", len(g.Edges), edges)
	}

	empty := BuildTopology("nothing-here", topologyInput())
	if empty.Nodes == nil || empty.Edges == nil || len(empty.Nodes) != 0 {
		t.Errorf("empty graph = %+v, want [] and []", empty)
	}
}

func TestSummarizeNodes(t *testing.T) {
	spec := func(cpu, mem int64, init bool) model.ContainerSpec {
		return model.ContainerSpec{Name: "c", CPURequestMilli: cpu, MemoryRequestBytes: mem, Init: init}
	}
	nodes := []model.Node{
		{Name: "b", Ready: true, Unschedulable: true, Roles: []string{"worker"}, CPUAllocatableMilli: 4000},
		{Name: "a", Ready: true, Conditions: []model.Condition{
			{Type: "MemoryPressure", Status: "True"}, {Type: "DiskPressure", Status: "False"}, {Type: "PIDPressure", Status: "True"},
		}},
		{Name: "c", Ready: false},
		{Name: "d", Ready: true},
	}
	pods := []model.Pod{
		{Namespace: "x", Name: "web-1", Phase: "Running", NodeName: "b", Labels: map[string]string{"app": "web"},
			Specs: []model.ContainerSpec{spec(250, 1<<30, false), spec(100, 1<<20, false), spec(4000, 8<<30, true)}},
		{Namespace: "a", Name: "pending", Phase: "Pending", NodeName: "b", Specs: []model.ContainerSpec{spec(500, 0, false)}},
		{Namespace: "x", Name: "done", Phase: "Succeeded", NodeName: "b", Created: podNow.Add(-time.Hour), Specs: []model.ContainerSpec{spec(9000, 9<<30, false)}},
		{Namespace: "x", Name: "ancient", Phase: "Succeeded", NodeName: "b", Created: podNow.Add(-72 * time.Hour)},
		{Namespace: "x", Name: "unscheduled", Phase: "Pending"},
	}
	ws := []model.Workload{{Kind: "Deployment", Namespace: "x", Name: "web", Selector: sel("app", "web")}}

	got := SummarizeNodes(nodes, pods, ws, podNow)
	var rows []string
	for _, n := range got {
		rows = append(rows, n.Name+"="+n.Status+" "+n.Detail)
	}
	want := "a=warn Reports MemoryPressure, PIDPressure.|b=warn Cordoned: no new pods are scheduled here.|c=crit Not ready.|d=ok Ready."
	if strings.Join(rows, "|") != want {
		t.Errorf("nodes =\n%s\nwant\n%s", strings.Join(rows, "|"), want)
	}

	b := got[1]
	if b.CPURequestedMilli != 850 || b.MemoryRequestedBytes != 1<<30+1<<20 {
		t.Errorf("requests = %dm %d bytes; init containers and finished pods must not count", b.CPURequestedMilli, b.MemoryRequestedBytes)
	}
	var pnames []string
	for _, p := range b.Pods {
		pnames = append(pnames, p.Namespace+"/"+p.Name+":"+p.Status+":"+p.Workload)
	}
	if strings.Join(pnames, " ") != "a/pending:warn: x/done:ok: x/web-1:ok:Deployment/web" {
		t.Errorf("pods = %v", pnames)
	}
	if d := got[3]; d.Pods == nil || d.Pressure == nil || d.Taints == nil || d.Roles == nil {
		t.Errorf("collections must encode as [] not null: %+v", d)
	}
}

func TestBuildTopologyLinksCronJobToItsJobs(t *testing.T) {
	in := TopologyInput{
		Now: podNow,
		Workloads: []model.Workload{
			{Kind: "CronJob", Namespace: "shop", Name: "nightly", Schedule: "0 3 * * *"},
			{Kind: "Job", Namespace: "shop", Name: "nightly-29123400", Desired: 1, Active: 1, Selector: sel("job", "nightly-29123400")},
			{Kind: "Job", Namespace: "shop", Name: "nightly-backfill", Desired: 1, Selector: sel("job", "backfill")}, // not the controller's naming
		},
		Pods: []model.Pod{{Namespace: "shop", Name: "nightly-29123400-abc", Phase: "Running", NodeName: "n1", Labels: map[string]string{"job": "nightly-29123400"}}},
	}
	edges := map[string]bool{}
	for _, e := range BuildTopology("shop", in).Edges {
		edges[e.From+" -> "+e.To] = true
	}
	for _, want := range []string{
		"CronJob/shop/nightly -> Job/shop/nightly-29123400",
		"Job/shop/nightly-29123400 -> Pod/shop/nightly-29123400-abc",
	} {
		if !edges[want] {
			t.Errorf("missing edge %s; got %v", want, edges)
		}
	}
	if edges["CronJob/shop/nightly -> Job/shop/nightly-backfill"] {
		t.Error("a Job not named <cronjob>-<minutes> should not be linked")
	}
}
