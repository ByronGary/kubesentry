package incidents

import (
	"fmt"
	"time"

	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/model"
	"github.com/ByronGary/kubesentry/internal/snapshot"
)

const mi = 1 << 20

// fixture is a small cluster:
//
//	shop (owner payments, production):
//	  Deployment api (revision 1, image app:v1), ReplicaSet api-7d9f, pods
//	  api-7d9f-a on node-1 and api-7d9f-b on node-2, container app with a
//	  512 MiB limit, labels app.kubernetes.io/name=api, part-of=store,
//	  running as ServiceAccount api-sa (IRSA role api-role);
//	  Service api (EndpointSlice), Ingress api-ing (ALB "shop-alb",
//	  security group sg-0abc) routing to it, TargetGroupBinding api-tgb;
//	  StatefulSet db with pod db-0 (no memory limit), Service db, part-of=store;
//	web: Deployment front with pod front-1-x, Service front.
//	kube-system: DaemonSet aws-node with pod aws-node-x.
func fixture() model.Inventory {
	own := func(kind, name string) []model.OwnerRef {
		return []model.OwnerRef{{Kind: kind, Name: name, UID: "uid-" + name, Controller: true}}
	}
	pod := func(ns, name, node string, owners []model.OwnerRef, labels map[string]string, limit int64) model.Pod {
		return model.Pod{UID: "uid-" + name, Namespace: ns, Name: name, Phase: "Running", Ready: true, NodeName: node, Labels: labels,
			Owners: owners, ServiceAccount: "default", Created: t0.Add(-48 * time.Hour),
			Containers: []model.ContainerStatus{{Name: "app", State: "running", Ready: true}},
			Specs:      []model.ContainerSpec{{Name: "app", Image: "app:v1", MemoryLimitBytes: limit}}}
	}
	apiLabels := map[string]string{"app.kubernetes.io/name": "api", "app.kubernetes.io/part-of": "store", "pod-template-hash": "7d9f"}
	inv := model.Inventory{Unavailable: map[string]string{}, ReadAt: t0}
	inv.Namespaces = []model.Namespace{
		{Name: "shop", Labels: map[string]string{"environment": "production"}, Annotations: map[string]string{"kubesentry.io/owner": "payments"}},
		{Name: "web"}, {Name: "kube-system"},
	}
	inv.Nodes = []model.Node{
		{Name: "node-1", Ready: true, ProviderID: "aws:///us-east-1a/i-0aaa"},
		{Name: "node-2", Ready: true, ProviderID: "aws:///us-east-1b/i-0bbb"},
	}
	inv.Workloads = []model.Workload{
		{Kind: "Deployment", Namespace: "shop", Name: "api", UID: "uid-api", Desired: 2, Ready: 2, Revision: "1", Images: []string{"app:v1"},
			Selector: &model.LabelSelector{MatchLabels: map[string]string{"app.kubernetes.io/name": "api"}},
			Labels:   map[string]string{"app.kubernetes.io/name": "api"}},
		{Kind: "StatefulSet", Namespace: "shop", Name: "db", UID: "uid-db", Desired: 1, Ready: 1, Revision: "db-5c4",
			Selector: &model.LabelSelector{MatchLabels: map[string]string{"app": "db"}}},
		{Kind: "Deployment", Namespace: "web", Name: "front", UID: "uid-front", Desired: 1, Ready: 1, Revision: "3"},
		{Kind: "DaemonSet", Namespace: "kube-system", Name: "aws-node", UID: "uid-aws-node", Desired: 2, Ready: 2},
	}
	inv.ReplicaSets = []model.ReplicaSet{
		{Namespace: "shop", Name: "api-7d9f", UID: "uid-api-7d9f", Owners: own("Deployment", "api"), Revision: "1", Images: []string{"app:v1"},
			Created: t0.Add(-72 * time.Hour)},
		{Namespace: "web", Name: "front-1", UID: "uid-front-1", Owners: own("Deployment", "front"), Revision: "3"},
	}
	a := pod("shop", "api-7d9f-a", "node-1", own("ReplicaSet", "api-7d9f"), apiLabels, 512*mi)
	b := pod("shop", "api-7d9f-b", "node-2", own("ReplicaSet", "api-7d9f"), apiLabels, 512*mi)
	a.ServiceAccount, b.ServiceAccount = "api-sa", "api-sa"
	db := pod("shop", "db-0", "node-1", own("StatefulSet", "db"), map[string]string{"app": "db", "app.kubernetes.io/part-of": "store"}, 0)
	front := pod("web", "front-1-x", "node-2", own("ReplicaSet", "front-1"), map[string]string{"app": "front"}, 256*mi)
	awsNode := pod("kube-system", "aws-node-x", "node-1", own("DaemonSet", "aws-node"), nil, 0)
	inv.Pods = []model.Pod{a, b, db, front, awsNode}
	inv.Services = []model.Service{
		{Namespace: "shop", Name: "api", Selector: map[string]string{"app.kubernetes.io/name": "api"}, Created: t0.Add(-time.Hour)},
		{Namespace: "shop", Name: "db", Selector: map[string]string{"app": "db"}, Created: t0.Add(-time.Hour),
			Annotations: map[string]string{AnnotationNLBName: "db-nlb", AnnotationNLBSecurityGroups: "sg-0db"}},
		{Namespace: "web", Name: "front", Selector: map[string]string{"app": "front"}, Created: t0.Add(-time.Hour)},
	}
	ep := func(p model.Pod) model.Endpoint {
		return model.Endpoint{Addresses: []string{"10.0.0.1"}, Ready: true, Serving: true, TargetKind: "Pod", TargetName: p.Name, TargetUID: p.UID}
	}
	inv.EndpointSlices = []model.EndpointSlice{
		{Namespace: "shop", Name: "api-1", Service: "api", Endpoints: []model.Endpoint{ep(a), ep(b)}},
		{Namespace: "shop", Name: "db-1", Service: "db", Endpoints: []model.Endpoint{ep(db)}},
		{Namespace: "web", Name: "front-1", Service: "front", Endpoints: []model.Endpoint{ep(front)}},
	}
	inv.Ingresses = []model.Ingress{{Namespace: "shop", Name: "api-ing", Rules: []model.IngressRule{{Host: "shop.example", Path: "/", Service: "api"}},
		Annotations: map[string]string{AnnotationALBName: "shop-alb", AnnotationALBSecurityGroups: "sg-0abc, sg-0def"}}}
	inv.ServiceAccounts = []model.ServiceAccount{{Namespace: "shop", Name: "api-sa", RoleARN: "arn:aws:iam::111122223333:role/api-role"}}
	inv.TargetGroupBindings = []model.TargetGroupBinding{{Namespace: "shop", Name: "api-tgb", ServiceName: "api", ServicePort: "80",
		TargetGroupARN: "arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/k8s-shop-api/0123456789abcdef"}}
	inv.Cluster = model.ClusterInfo{Name: "prod", Platform: "eks"}
	return inv
}

// view builds a view of inv at now.
func view(inv model.Inventory, now time.Time) *snapshot.View {
	return snapshot.Build(inv, detectors.DefaultPolicy(), now)
}

// withPod returns inv with the named pod changed by f.
func withPod(inv model.Inventory, name string, f func(p *model.Pod)) model.Inventory {
	pods := make([]model.Pod, len(inv.Pods))
	copy(pods, inv.Pods)
	for i := range pods {
		if pods[i].Name == name {
			pods[i].Containers = append([]model.ContainerStatus(nil), pods[i].Containers...)
			f(&pods[i])
		}
	}
	inv.Pods = pods
	return inv
}

// withWorkload returns inv with the named workload changed by f.
func withWorkload(inv model.Inventory, ns, name string, f func(w *model.Workload)) model.Inventory {
	ws := make([]model.Workload, len(inv.Workloads))
	copy(ws, inv.Workloads)
	for i := range ws {
		if ws[i].Namespace == ns && ws[i].Name == name {
			f(&ws[i])
		}
	}
	inv.Workloads = ws
	return inv
}

var (
	apiSubject   = Subject{Kind: "Deployment", Namespace: "shop", Name: "api"}
	dbSubject    = Subject{Kind: "StatefulSet", Namespace: "shop", Name: "db"}
	frontSubject = Subject{Kind: "Deployment", Namespace: "web", Name: "front"}
)

func sigSummary(ss []Signal) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		sev := ""
		if s.Severity != "" {
			sev = "/" + string(s.Severity)
		}
		end := ""
		if s.End != nil {
			end = " end=" + s.End.Format("15:04:05")
		}
		out[i] = fmt.Sprintf("%s %s%s %s/%s%s", s.Type, s.Role, sev, s.Subject.Kind, s.Subject.Name, end)
	}
	return out
}
