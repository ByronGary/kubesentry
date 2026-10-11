package snapshot

import (
	"fmt"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/model"
)

var synthNow = time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)

// synthSize is the shape of a synthetic cluster. L4 matches the stress
// plan's largest level.
type synthSize struct {
	namespaces, nodes                              int
	deployments, statefulsets, jobs, cronjobs      int
	podsPerDeployment, podsPerStatefulSet          int
	services, roles, bindings, pvcs, ingresses, cs int
}

var sizeL4 = synthSize{
	namespaces: 300, nodes: 1000,
	deployments: 3800, statefulsets: 600, jobs: 400, cronjobs: 200, // 5,000 workloads
	podsPerDeployment: 4, podsPerStatefulSet: 7, // 15,200 + 4,200 + 400 Job pods + 200 static = 20,000
	services: 2000, roles: 3000, bindings: 6000, pvcs: 2000, ingresses: 500, cs: 500,
}

// synthExpect is the ground truth the generator knows: each pod's owner.
type synthExpect struct {
	owner map[string]string // "ns/pod" → "Kind/name"
}

// synthInventory builds a deterministic cluster of the given size, with
// ownerReferences on every pod (ReplicaSets under Deployments, a tenth of them
// mid-rollout with two ReplicaSets), EndpointSlices of at most 100 endpoints,
// some multi-workload Services, static pods and RBAC.
func synthInventory(s synthSize) (model.Inventory, synthExpect) {
	exp := synthExpect{owner: map[string]string{}}
	inv := model.Inventory{ReadAt: synthNow, Unavailable: map[string]string{}}
	ns := func(i int) string { return fmt.Sprintf("team-%03d", i%s.namespaces) }
	created := synthNow.Add(-30 * 24 * time.Hour)

	zones := []string{"us-east-1a", "us-east-1b", "us-east-1c"}
	for i := range s.nodes {
		labels := map[string]string{
			"topology.kubernetes.io/zone": zones[i%3], "topology.kubernetes.io/region": "us-east-1",
			"node.kubernetes.io/instance-type": "m7g.xlarge", "kubernetes.io/arch": "arm64", "kubernetes.io/os": "linux",
		}
		if i%2 == 0 {
			labels["eks.amazonaws.com/nodegroup"] = fmt.Sprintf("ng-%d", i%5)
			labels["eks.amazonaws.com/capacityType"] = "ON_DEMAND"
		} else {
			labels["karpenter.sh/nodepool"] = "default"
			labels["karpenter.sh/capacity-type"] = "spot"
		}
		inv.Nodes = append(inv.Nodes, model.Node{
			Name: fmt.Sprintf("ip-10-%d-%d-%d.ec2.internal", i/65536, (i/256)%256, i%256), Ready: true,
			ProviderID: fmt.Sprintf("aws:///%s/i-%017x", zones[i%3], i), Labels: labels,
			CPUAllocatableMilli: 3920, MemoryAllocatableBytes: 15 << 30, PodsAllocatable: 58,
			KubeletVersion: "v1.31.4-eks-aeac579", Created: created,
		})
	}
	for i := range s.namespaces {
		inv.Namespaces = append(inv.Namespaces, model.Namespace{Name: ns(i), Phase: "Active",
			Labels: map[string]string{"pod-security.kubernetes.io/enforce": []string{"baseline", "restricted", ""}[i%3]}, Created: created})
	}
	inv.Namespaces = append(inv.Namespaces, model.Namespace{Name: "kube-system", Phase: "Active", Created: created})

	podN := 0
	addPod := func(namespace, name string, owner []model.OwnerRef, labels map[string]string, expect string) {
		node := inv.Nodes[podN%len(inv.Nodes)].Name
		podN++
		p := model.Pod{
			UID: "uid-pod-" + namespace + "-" + name, Namespace: namespace, Name: name, Phase: "Running",
			NodeName: node, Labels: labels, Owners: owner, ServiceAccount: "default", AutomountToken: true,
			Created: created, Ready: true, ReadyChanged: created, PodIP: fmt.Sprintf("10.%d.%d.%d", podN/65536, (podN/256)%256, podN%256),
			QOSClass: "Burstable",
			Specs: []model.ContainerSpec{
				{Name: "app", Image: "registry/app:1", RunAsNonRoot: true, CPURequestMilli: 100, MemoryRequestBytes: 128 << 20, MemoryLimitBytes: 256 << 20},
				{Name: "proxy", Image: "registry/proxy:1", CPURequestMilli: 50, MemoryRequestBytes: 64 << 20},
			},
			Containers: []model.ContainerStatus{
				{Name: "app", State: "running", Ready: true, Started: true},
				{Name: "proxy", State: "running", Ready: true, Started: true},
			},
		}
		switch podN % 97 {
		case 0:
			p.Ready = false
			p.Containers[0] = model.ContainerStatus{Name: "app", State: "waiting", Reason: "CrashLoopBackOff", RestartCount: 12}
		case 1:
			p.DeletedAt = synthNow.Add(-time.Minute)
		}
		if podN%5 == 0 {
			p.Claims = []string{"data-" + name}
		}
		inv.Pods = append(inv.Pods, p)
		exp.owner[namespace+"/"+name] = expect
	}
	ref := func(kind, name string) []model.OwnerRef {
		return []model.OwnerRef{{Kind: kind, Name: name, UID: "uid-" + kind + "-" + name, Controller: true}}
	}

	type svcTarget struct {
		ns     string
		labels map[string]string
	}
	var targets []svcTarget
	for i := range s.deployments {
		namespace, name := ns(i), fmt.Sprintf("dep-%04d", i)
		sel := map[string]string{"app": name}
		inv.Workloads = append(inv.Workloads, model.Workload{
			Kind: "Deployment", Namespace: namespace, Name: name, UID: "uid-Deployment-" + name,
			Selector: &model.LabelSelector{MatchLabels: sel}, Desired: int32(s.podsPerDeployment), Ready: int32(s.podsPerDeployment),
			Updated: int32(s.podsPerDeployment), Available: int32(s.podsPerDeployment), Images: []string{"registry/app:1"}, Created: created,
		})
		hashes := []string{fmt.Sprintf("%x", 0x5f000000+i)}
		if i%10 == 0 { // mid-rollout
			hashes = append(hashes, fmt.Sprintf("%x", 0x6f000000+i))
		}
		for _, h := range hashes {
			inv.ReplicaSets = append(inv.ReplicaSets, model.ReplicaSet{Namespace: namespace, Name: name + "-" + h, UID: "uid-ReplicaSet-" + name + "-" + h,
				Owners: ref("Deployment", name), Desired: int32(s.podsPerDeployment), Ready: int32(s.podsPerDeployment), Created: created})
		}
		for j := range s.podsPerDeployment {
			h := hashes[j%len(hashes)]
			addPod(namespace, fmt.Sprintf("%s-%s-%05d", name, h, j), ref("ReplicaSet", name+"-"+h),
				map[string]string{"app": name, "pod-template-hash": h, "team": namespace}, "Deployment/"+name)
		}
		targets = append(targets, svcTarget{namespace, sel})
	}
	for i := range s.statefulsets {
		namespace, name := ns(i), fmt.Sprintf("sts-%04d", i)
		sel := map[string]string{"app": name}
		inv.Workloads = append(inv.Workloads, model.Workload{Kind: "StatefulSet", Namespace: namespace, Name: name, UID: "uid-StatefulSet-" + name,
			Selector: &model.LabelSelector{MatchLabels: sel}, Desired: int32(s.podsPerStatefulSet), Ready: int32(s.podsPerStatefulSet),
			Updated: int32(s.podsPerStatefulSet), Created: created})
		for j := range s.podsPerStatefulSet {
			addPod(namespace, fmt.Sprintf("%s-%d", name, j), ref("StatefulSet", name), map[string]string{"app": name, "team": namespace}, "StatefulSet/"+name)
		}
		targets = append(targets, svcTarget{namespace, sel})
	}
	for i := range s.cronjobs {
		namespace, name := ns(i), fmt.Sprintf("cron-%04d", i)
		inv.Workloads = append(inv.Workloads, model.Workload{Kind: "CronJob", Namespace: namespace, Name: name, UID: "uid-CronJob-" + name,
			Schedule: "0 * * * *", LastScheduleTime: synthNow.Add(-time.Hour), LastSuccessTime: synthNow.Add(-time.Hour), Created: created})
	}
	for i := range s.jobs {
		namespace, name := ns(i), fmt.Sprintf("cron-%04d-%d", i%s.cronjobs, 29000000+i)
		w := model.Workload{Kind: "Job", Namespace: ns(i % s.cronjobs), Name: name, UID: "uid-Job-" + name, Desired: 1, Active: 1,
			Selector: &model.LabelSelector{MatchLabels: map[string]string{"job-name": name}}, Owners: ref("CronJob", fmt.Sprintf("cron-%04d", i%s.cronjobs)), Created: created}
		namespace = w.Namespace
		inv.Workloads = append(inv.Workloads, w)
		addPod(namespace, name+"-x", ref("Job", name), map[string]string{"job-name": name}, "Job/"+name)
	}
	// Static pods fill up to the 20,000.
	for i := 0; len(inv.Pods) < s.deployments*s.podsPerDeployment+s.statefulsets*s.podsPerStatefulSet+s.jobs+200 && i < len(inv.Nodes); i++ {
		addPod("kube-system", "kube-proxy-"+inv.Nodes[i].Name, ref("Node", inv.Nodes[i].Name), map[string]string{"k8s-app": "kube-proxy"}, "Node/"+inv.Nodes[i].Name)
	}

	// Services: one per target, every tenth spans a whole team (several workloads).
	podsBy := map[string][]int{} // "ns|k=v" → pod indexes
	for i := range inv.Pods {
		p := &inv.Pods[i]
		for k, v := range p.Labels {
			podsBy[p.Namespace+"|"+k+"="+v] = append(podsBy[p.Namespace+"|"+k+"="+v], i)
		}
	}
	for i := 0; i < s.services && i < len(targets); i++ {
		t := targets[i]
		sel := t.labels
		name := fmt.Sprintf("svc-%04d", i)
		if i%10 == 0 {
			sel = map[string]string{"team": t.ns}
		}
		svc := model.Service{Namespace: t.ns, Name: name, Type: "ClusterIP", ClusterIP: "172.20.0.1", Selector: sel,
			Ports: []model.ServicePort{{Name: "http", Protocol: "TCP", Port: 80, TargetPort: "8080"}}, Created: created}
		if i%50 == 0 {
			svc.Type = "LoadBalancer"
			svc.Annotations = map[string]string{"service.beta.kubernetes.io/aws-load-balancer-scheme": "internal"}
		}
		inv.Services = append(inv.Services, svc)
		var key string
		for k, v := range sel {
			key = t.ns + "|" + k + "=" + v
		}
		idx := podsBy[key]
		for start := 0; start == 0 || start < len(idx); start += 100 {
			end := min(start+100, len(idx))
			sl := model.EndpointSlice{Namespace: t.ns, Name: fmt.Sprintf("%s-%d", name, start/100), Service: name, ManagedBy: "endpointslice-controller.k8s.io"}
			for _, pi := range idx[start:end] {
				p := &inv.Pods[pi]
				sl.Endpoints = append(sl.Endpoints, model.Endpoint{Addresses: []string{p.PodIP}, Ready: p.Ready && p.DeletedAt.IsZero(), Serving: p.Ready,
					Terminating: !p.DeletedAt.IsZero(), NodeName: p.NodeName, TargetKind: "Pod", TargetName: p.Name, TargetUID: p.UID})
			}
			inv.EndpointSlices = append(inv.EndpointSlices, sl)
		}
	}
	for i := range s.ingresses {
		svc := inv.Services[i%len(inv.Services)]
		inv.Ingresses = append(inv.Ingresses, model.Ingress{Namespace: svc.Namespace, Name: fmt.Sprintf("ing-%04d", i), Class: "alb",
			Annotations: map[string]string{"alb.ingress.kubernetes.io/scheme": []string{"internal", "internet-facing"}[i%2]},
			Rules:       []model.IngressRule{{Host: fmt.Sprintf("app-%d.example.com", i), Path: "/", Service: svc.Name, Port: "80"}}, Created: created})
	}

	inv.StorageClasses = []model.StorageClass{
		{Name: "gp3", Provisioner: "ebs.csi.aws.com", Parameters: map[string]string{"type": "gp3"}, Default: true, BindingMode: "WaitForFirstConsumer"},
		{Name: "efs", Provisioner: "efs.csi.aws.com"},
	}
	claimed := 0
	for i := range inv.Pods {
		if claimed >= s.pvcs*9/10 { // the rest are unused
			break
		}
		for _, c := range inv.Pods[i].Claims {
			inv.PVCs = append(inv.PVCs, model.PVC{Namespace: inv.Pods[i].Namespace, Name: c, StorageClass: "gp3", Phase: "Bound", CapacityBytes: 20 << 30, Created: created})
			claimed++
		}
	}
	for i := 0; claimed < s.pvcs; i++ {
		inv.PVCs = append(inv.PVCs, model.PVC{Namespace: ns(i), Name: fmt.Sprintf("orphan-%04d", i), StorageClass: []string{"gp3", "efs"}[i%2], Phase: "Bound", CapacityBytes: 50 << 30, Created: created})
		claimed++
	}

	viewPods := model.PolicyRule{Verbs: []string{"get", "list", "watch"}, APIGroups: []string{""}, Resources: []string{"pods", "services"}}
	inv.RBAC.Roles = append(inv.RBAC.Roles,
		model.Role{Kind: "ClusterRole", Name: "view", Rules: []model.PolicyRule{viewPods}},
		model.Role{Kind: "ClusterRole", Name: "cluster-admin", Rules: []model.PolicyRule{{Verbs: []string{"*"}, APIGroups: []string{"*"}, Resources: []string{"*"}}}})
	for i := range s.roles {
		inv.RBAC.Roles = append(inv.RBAC.Roles, model.Role{Kind: "Role", Namespace: ns(i), Name: fmt.Sprintf("role-%04d", i),
			Rules: []model.PolicyRule{viewPods, {Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"secrets"}}}})
	}
	for i := range s.bindings {
		b := model.RoleBinding{Kind: "RoleBinding", Namespace: ns(i), Name: fmt.Sprintf("rb-%04d", i), RoleKind: "Role", RoleName: fmt.Sprintf("role-%04d", i%s.roles),
			Subjects: []model.Subject{{Kind: "Group", Name: "group-" + ns(i)}, {Kind: "User", Name: fmt.Sprintf("user-%d@example.com", i)}}}
		if i%3 == 0 {
			b.RoleKind, b.RoleName = "ClusterRole", "view"
		}
		b.Namespace = ns(i % s.roles)
		inv.RBAC.Bindings = append(inv.RBAC.Bindings, b)
	}
	inv.RBAC.Bindings = append(inv.RBAC.Bindings, model.RoleBinding{Kind: "ClusterRoleBinding", Name: "eks:addon-cluster-admin", RoleKind: "ClusterRole", RoleName: "cluster-admin",
		Subjects: []model.Subject{{Kind: "User", Name: "eks:addon-manager"}}})
	inv.AWSAuth = &model.AWSAuth{MapRoles: []model.AWSAuthMapping{{ARN: "arn:aws:iam::111122223333:role/Admin", Username: "admin", Groups: []string{"system:masters"}}}}

	inv.Certs.Installed = true
	inv.Certs.Issuers = []model.Issuer{{Kind: "ClusterIssuer", Name: "le", Type: "acme", Ready: "True"}}
	for i := range s.cs {
		inv.Certs.Certificates = append(inv.Certs.Certificates, model.Certificate{Namespace: ns(i), Name: fmt.Sprintf("cert-%03d", i),
			IssuerKind: "ClusterIssuer", IssuerName: "le", Ready: "True", NotBefore: synthNow.Add(-time.Duration(i%90) * 24 * time.Hour),
			NotAfter: synthNow.Add(time.Duration(90-i%90) * 24 * time.Hour)})
	}
	return inv, exp
}

// sizeSmall is a twentieth of L4, for tests.
var sizeSmall = synthSize{
	namespaces: 15, nodes: 50, deployments: 190, statefulsets: 30, jobs: 20, cronjobs: 10,
	podsPerDeployment: 4, podsPerStatefulSet: 7, services: 100, roles: 150, bindings: 300, pvcs: 100, ingresses: 25, cs: 25,
}

// TestSynthAssociationIsExact checks the association against the generator's
// ground truth: every pod's owner and every Service endpoint's owner.
func TestSynthAssociationIsExact(t *testing.T) {
	inv, exp := synthInventory(sizeSmall)
	a := detectors.Associate(inv, detectors.DefaultPolicy())
	for i := range inv.Pods {
		p := &inv.Pods[i]
		r, how, ok := a.OwnerOf(p)
		if got := r.Kind + "/" + r.Name; !ok || how != detectors.HowOwner || got != exp.owner[p.Namespace+"/"+p.Name] {
			t.Fatalf("%s/%s: owner %s via %s, want %s", p.Namespace, p.Name, got, how, exp.owner[p.Namespace+"/"+p.Name])
		}
	}
	endpoints := 0
	for _, s := range inv.Services {
		if a.ServiceHow(s.Namespace, s.Name) != detectors.HowEndpoints {
			t.Fatalf("service %s/%s not from EndpointSlices", s.Namespace, s.Name)
		}
		for _, e := range a.ServiceEndpoints(s.Namespace, s.Name) {
			endpoints++
			if want := exp.owner[s.Namespace+"/"+e.PodName]; e.Owner.Kind+"/"+e.Owner.Name != want {
				t.Fatalf("service %s endpoint %s owner %+v, want %s", s.Name, e.PodName, e.Owner, want)
			}
		}
	}
	if endpoints == 0 {
		t.Fatal("no endpoints generated")
	}
}

func BenchmarkAssociate20k(b *testing.B) {
	inv, _ := synthInventory(sizeL4)
	if len(inv.Pods) != 20000 {
		b.Fatalf("generated %d pods", len(inv.Pods))
	}
	p := detectors.DefaultPolicy()
	b.ReportAllocs()
	for b.Loop() {
		detectors.Associate(inv, p)
	}
}

// BenchmarkBuild_L4 is one full view build at the stress plan's largest
// level: 20,000 pods, 5,000 workloads with ReplicaSets, 2,000 Services with
// EndpointSlices, 6,000 RoleBindings. Budget: under 1s and 300 MB per build.
func BenchmarkBuild_L4(b *testing.B) {
	inv, _ := synthInventory(sizeL4)
	b.Logf("pods=%d workloads=%d replicasets=%d services=%d slices=%d rolebindings=%d nodes=%d",
		len(inv.Pods), len(inv.Workloads), len(inv.ReplicaSets), len(inv.Services), len(inv.EndpointSlices), len(inv.RBAC.Bindings), len(inv.Nodes))
	p := detectors.DefaultPolicy()
	b.ReportAllocs()
	for b.Loop() {
		Build(inv, p, synthNow)
	}
}

// BenchmarkTopologyNamespace is one namespace map built from a view.
func BenchmarkTopologyNamespace(b *testing.B) {
	inv, _ := synthInventory(sizeL4)
	v := Build(inv, detectors.DefaultPolicy(), synthNow)
	a := v.Assoc()
	b.ReportAllocs()
	for b.Loop() {
		detectors.BuildTopologyWith("team-007", a, v.Policy, v.Built)
	}
}
