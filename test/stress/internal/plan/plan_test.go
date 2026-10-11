package plan

import (
	"encoding/json"
	"net"
	"reflect"
	"regexp"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func objectsJSON(t *testing.T, p *Plan) string {
	t.Helper()
	var all []any
	for _, n := range p.Nodes {
		all = append(all, n.Object())
	}
	all = append(all, toAny(p.Cluster)...)
	for _, ns := range p.Namespaces {
		all = append(all, ns.Object)
		all = append(all, toAny(ns.Objects)...)
		for _, c := range ns.Certs {
			all = append(all, c.Object)
		}
	}
	b, err := json.Marshal(all)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func toAny(objs []runtime.Object) []any {
	out := make([]any, len(objs))
	for i, o := range objs {
		out[i] = o
	}
	return out
}

func TestBuildIsDeterministic(t *testing.T) {
	for _, l := range Levels()[:3] {
		a, b := Build(l), Build(l)
		if objectsJSON(t, a) != objectsJSON(t, b) {
			t.Fatalf("%s: two builds differ", l.Name)
		}
		if !reflect.DeepEqual(a.Stats, b.Stats) {
			t.Fatalf("%s: stats differ", l.Name)
		}
	}
}

func TestLevelsNest(t *testing.T) {
	l1, _ := Get("L1")
	l2, _ := Get("L2")
	small, big := Build(l1), Build(l2)
	bigNames := map[string]bool{}
	for _, ns := range big.Namespaces {
		for _, n := range ns.Names() {
			bigNames[n] = true
		}
	}
	for _, ns := range small.Namespaces {
		for _, n := range ns.Names() {
			if !bigNames[n] {
				t.Fatalf("%s is in L1 but not in L2", n)
			}
		}
	}
	for i, n := range small.Nodes {
		if !reflect.DeepEqual(n.Object(), big.Nodes[i].Object()) {
			t.Fatalf("node %d differs between levels", i)
		}
	}
}

func TestPodTargets(t *testing.T) {
	for _, l := range Levels()[1:] {
		p := Build(l)
		got := p.Stats.ExpectedPods
		if got < l.Pods*85/100 || got > l.Pods*115/100 {
			t.Errorf("%s: expected pods %d, target %d", l.Name, got, l.Pods)
		}
		if p.Stats.Nodes != l.Nodes {
			t.Errorf("%s: %d nodes, want %d", l.Name, p.Stats.Nodes, l.Nodes)
		}
		t.Logf("%s: %d team namespaces, %d pods expected, %d deployments, services %v, %d PVCs, %d roles, %d bindings, %d certificates",
			l.Name, p.Stats.TeamNamespaces, got, p.Stats.Deployments, p.Stats.Services, p.Stats.PVCs, p.Stats.Roles, p.Stats.RoleBindings, p.Stats.Certificates)
	}
}

var dns1123 = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`)

func TestNodesFollowTheFakeNodeConvention(t *testing.T) {
	_, fake, _ := net.ParseCIDR("172.19.100.0/22")
	seenIP := map[string]bool{}
	pools := map[string]int{}
	arm := 0
	nodes := Nodes(1000)
	for _, n := range nodes {
		o := n.Object()
		if !strings.HasPrefix(o.Name, "ip-172-19-10") || !strings.HasSuffix(o.Name, ".ec2.internal") || !dns1123.MatchString(o.Name) {
			t.Fatalf("bad node name %q", o.Name)
		}
		ip := net.ParseIP(n.IP)
		if !fake.Contains(ip) || seenIP[n.IP] {
			t.Fatalf("node %s: IP %s outside 172.19.100.0/22 or duplicated", o.Name, n.IP)
		}
		seenIP[n.IP] = true
		if o.Status.Addresses[0].Type != corev1.NodeInternalIP || o.Status.Addresses[0].Address != n.IP {
			t.Fatalf("node %s: InternalIP must be set at creation", o.Name)
		}
		if o.Annotations["kwok.x-k8s.io/node"] != "fake" || o.Labels["type"] != "kwok" || o.Labels["kubesentry.io/stress"] != "true" {
			t.Fatalf("node %s: missing KWOK annotation or labels", o.Name)
		}
		if o.Spec.Taints[0] != KwokTaint || !strings.HasPrefix(o.Spec.ProviderID, "aws:///us-east-1") {
			t.Fatalf("node %s: taint or providerID wrong", o.Name)
		}
		if n.Pool.Kind == "fargate" && o.Labels["eks.amazonaws.com/compute-type"] != "fargate" {
			t.Fatalf("fargate node %s lacks compute-type label", o.Name)
		}
		pools[n.Pool.Name]++
		if n.Instance.Arch == "arm64" {
			arm++
		}
	}
	if arm < 250 || arm > 350 {
		t.Errorf("arm64 nodes %d of 1000, want about 30%%", arm)
	}
	if pools[PoolFargate] < 30 || pools[PoolFargate] > 70 || pools[PoolWindows] < 3 || pools[PoolWindows] > 20 {
		t.Errorf("pool mix %v", pools)
	}
	if len(Nodes(5000)) != MaxNodes {
		t.Errorf("Nodes must cap at %d", MaxNodes)
	}
}

func TestNamesAreValid(t *testing.T) {
	l, _ := Get("L1")
	p := Build(l)
	for _, ns := range p.Namespaces {
		for _, n := range ns.Names() {
			parts := strings.Split(n, "/")
			name := parts[len(parts)-1]
			if strings.Contains(n, "rbacv1.ClusterRole") {
				continue
			}
			if !dns1123.MatchString(name) || len(name) > 63 && !strings.Contains(n, "PersistentVolume") {
				t.Errorf("invalid name %q", n)
			}
		}
	}
}
