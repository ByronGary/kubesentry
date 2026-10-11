package verify

import (
	"strings"
	"testing"

	"github.com/ByronGary/kubesentry/test/stress/internal/ks"
	"github.com/ByronGary/kubesentry/test/stress/internal/truth"
)

func set(keys ...string) map[string]bool {
	m := map[string]bool{}
	for _, k := range keys {
		m[k] = true
	}
	return m
}

func TestCompareScoresAndScopes(t *testing.T) {
	tr := set("D/a/web|Pod/a/w1", "D/a/web|Pod/a/w2", "D/a/canary|Pod/a/c1", "D/b/x|Pod/b/x1")
	ob := set("D/a/web|Pod/a/w1", "D/a/web|Pod/a/w2", "D/a/web|Pod/a/c1", "D/b/x|Pod/b/x1")
	s, missing, extra := Compare("pod-owner", "map", tr, tr, ob, func(e string) bool { return EdgeNamespace(e) == "a" })
	if s.Truth != 3 || s.Observed != 3 || s.Matched != 2 {
		t.Fatalf("%+v", s)
	}
	if s.Precision != 2.0/3 || s.Recall != 2.0/3 {
		t.Errorf("precision %v recall %v", s.Precision, s.Recall)
	}
	if len(missing) != 1 || missing[0] != "D/a/canary|Pod/a/c1" || len(extra) != 1 || extra[0] != "D/a/web|Pod/a/c1" {
		t.Errorf("missing %v extra %v", missing, extra)
	}
	empty, _, _ := Compare("x", "y", map[string]bool{}, map[string]bool{}, map[string]bool{}, nil)
	if empty.Precision != 1 || empty.Recall != 1 {
		t.Errorf("empty sets score %v/%v, want 1/1", empty.Precision, empty.Recall)
	}
}

func TestAddMapCollapsesReplicaSetsAndExpandsServices(t *testing.T) {
	m := &ks.MapResponse{Namespace: "a"}
	m.Graph.Nodes = []ks.GraphNode{{ID: "Pod/a/w1", Kind: "Pod", Status: "ok"}, {ID: "Pod/a/w2", Kind: "Pod", Status: "warn"}}
	m.Graph.Edges = []ks.GraphEdge{
		{From: "Deployment/a/web", To: "ReplicaSet/a/web-1"},
		{From: "ReplicaSet/a/web-1", To: "Pod/a/w1"},
		{From: "StatefulSet/a/db", To: "Pod/a/w2"},
		{From: "Service/a/web", To: "Deployment/a/web"},
		{From: "Service/a/db", To: "Pod/a/w2"},
		{From: "Pod/a/w1", To: "Node/n1"},
		{From: "Pod/a/w1", To: "PVC/a/data"},
		{From: "CronJob/a/c", To: "Job/a/c-1"},
		{From: "Ingress/a/i", To: "Service/a/web"},
	}
	o := newObserved()
	o.AddMap(m)
	want := map[string][]string{
		truth.PodOwner:       {"Deployment/a/web|Pod/a/w1", "StatefulSet/a/db|Pod/a/w2"},
		truth.ServicePods:    {"Service/a/web|Pod/a/w1", "Service/a/db|Pod/a/w2"},
		truth.PodNode:        {"Pod/a/w1|Node/n1"},
		truth.PodPVC:         {"Pod/a/w1|PVC/a/data"},
		truth.CronJobJob:     {"CronJob/a/c|Job/a/c-1"},
		truth.IngressService: {"Ingress/a/i|Service/a/web"},
	}
	for rel, keys := range want {
		got := o.Rel("map", rel)
		if len(got) != len(keys) {
			t.Errorf("%s: got %v want %v", rel, got, keys)
		}
		for _, k := range keys {
			if !got[k] {
				t.Errorf("%s: missing %s (have %v)", rel, k, got)
			}
		}
	}
	if o.PodStatus["Pod/a/w2"] != "warn" {
		t.Errorf("pod status %v", o.PodStatus)
	}
}

func TestAddNodesAndSecurity(t *testing.T) {
	o := newObserved()
	o.AddNodes(&ks.NodesResponse{Items: []ks.NodeSummary{{Name: "n1", Pods: []ks.NodePod{
		{Namespace: "a", Name: "w1", Workload: "Deployment/web"}, {Namespace: "a", Name: "bare"},
	}}}})
	if !o.Rel("nodes", truth.PodOwner)["Deployment/a/web|Pod/a/w1"] || len(o.Rel("nodes", truth.PodOwner)) != 1 {
		t.Errorf("owners %v", o.Rel("nodes", truth.PodOwner))
	}
	if len(o.Rel("nodes", truth.PodNode)) != 2 {
		t.Errorf("nodes %v", o.Rel("nodes", truth.PodNode))
	}
	o.AddSecurity(&ks.SecurityResponse{Findings: []ks.SecurityFinding{
		{Category: "pod", Check: SecurityCheck, SubjectKind: "Deployment", Subject: "a/web"},
		{Category: "pod", Check: "run-as-root", SubjectKind: "Pod", Subject: "a/bare"},
	}})
	if g := o.Rel("security", truth.SecurityGroup); len(g) != 1 || !g["Deployment/a/web|"] {
		t.Errorf("security groups %v", g)
	}
}

func TestCategorizePairsWrongOwners(t *testing.T) {
	tr := &truth.Truth{Pods: map[string]*truth.Pod{
		"t/c1":   {Namespace: "t", Name: "c1", Top: "Deployment/t/canary", Labels: map[string]string{"kubesentry.io/stress-case": "overlap"}},
		"t/o1":   {Namespace: "t", Name: "o1", Top: "ReplicaSet/t/orphan-1", Labels: map[string]string{"kubesentry.io/stress-case": "orphan"}},
		"t/bare": {Namespace: "t", Name: "bare", Labels: map[string]string{"kubesentry.io/stress-case": "bare"}},
	}, Endpoints: map[string][]truth.Endpoint{}}
	missing := []string{"Deployment/t/canary|Pod/t/c1", "ReplicaSet/t/orphan-1|Pod/t/o1"}
	extra := []string{"Deployment/t/web|Pod/t/c1", "Deployment/t/web|Pod/t/bare"}
	ms := Categorize(tr, nil, truth.PodOwner, "map", missing, extra)
	got := map[string]string{}
	for _, m := range ms {
		got[m.Case] = m.Category
	}
	if !strings.Contains(got["overlap"], "wrong owner") || !strings.Contains(got["orphan"], "not reported (ReplicaSet)") || !strings.Contains(got["bare"], "spurious") {
		t.Errorf("categories %v", got)
	}
	groups := GroupMismatches(append(ms, ms...))
	if len(groups) != 3 || groups[0].Count != 2 {
		t.Errorf("groups %+v", groups)
	}
}

func TestCompareCounts(t *testing.T) {
	tr := map[string]int{"Deployment/a/web": 2, "Deployment/a/canary": 1, "ReplicaSet/a/orphan": 2, "Job/a/j": 0}
	ob := map[string]int{"Deployment/a/web": 3, "Deployment/a/canary": 1, "Job/a/j": 0}
	s := CompareCounts(tr, tr, ob, nil)
	if s.Workloads != 3 || s.Exact != 2 || s.TruthPods != 3 || s.Observed != 4 {
		t.Errorf("%+v", s)
	}
	if len(s.Wrong) != 1 || s.Wrong[0].Workload != "Deployment/a/web" {
		t.Errorf("wrong %v", s.Wrong)
	}
}

func TestCompareIgnoresChurnBetweenSnapshots(t *testing.T) {
	before := set("CronJob/a/c|Job/a/c-1", "D/a/web|Pod/a/w1")
	after := set("CronJob/a/c|Job/a/c-2", "D/a/web|Pod/a/w1")
	req, all := Stable(before, after)
	// kubesentry saw the old Job: neither a miss for c-2 nor an error for c-1.
	s, missing, extra := Compare("cronjob-job", "map", req, all, set("CronJob/a/c|Job/a/c-1", "D/a/web|Pod/a/w1"), nil)
	if s.Truth != 1 || s.Volatile != 2 || s.Precision != 1 || s.Recall != 1 || len(missing)+len(extra) != 0 {
		t.Errorf("%+v missing %v extra %v", s, missing, extra)
	}
	c := CompareCounts(map[string]int{"Job/a/c-1": 1, "Deployment/a/web": 2}, map[string]int{"Job/a/c-1": 0, "Deployment/a/web": 2},
		map[string]int{"Job/a/c-1": 1, "Deployment/a/web": 2}, nil)
	if c.Workloads != 1 || c.Volatile != 1 || c.Exact != 1 {
		t.Errorf("%+v", c)
	}
}

func TestGlob(t *testing.T) {
	if !Glob("ReplicaSet/stress-tricky/orphan-src-*", "ReplicaSet/stress-tricky/orphan-src-7f9c") || Glob("Deployment/a/web", "Deployment/a/web-canary") {
		t.Error("glob")
	}
}
