// Package truth computes association ground truth live from the API server:
// controller ownerReference chains, EndpointSlices, node names and volumes.
package truth

import (
	"context"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

// Relation names.
const (
	PodOwner       = "pod-owner"       // Workload → Pod (nearest workload-level controller)
	ServicePods    = "service-pods"    // Service → Pod (EndpointSlices)
	PodNode        = "pod-node"        // Pod → Node
	PodPVC         = "pod-pvc"         // Pod → PVC
	CronJobJob     = "cronjob-job"     // CronJob → Job
	IngressService = "ingress-service" // Ingress → Service (existing backends)
	SecurityGroup  = "security-group"  // pod findings reported per owner: "Kind/ns/name"
)

// Pod is one pod with its resolved relations.
type Pod struct {
	Namespace, Name, UID string
	Node                 string
	Phase                string
	Labels               map[string]string
	Created              time.Time
	Terminating          bool
	Owner                string // direct controller "Kind/ns/name", "" when none
	Top                  string // nearest workload-level owner, "" for bare and mirror pods
	Group                string // security grouping root ("Pod/ns/name" for unowned pods)
	Claims               []string
	Escalation           bool // a container lacks allowPrivilegeEscalation=false
	// Reason explains a pod that is not plainly running: a container waiting
	// reason (CrashLoopBackOff, ImagePullBackOff, ...), "Unschedulable",
	// "NotReady" or "Terminating". Empty when ready or completed.
	Reason string
}

// ID is "Pod/ns/name".
func (p *Pod) ID() string { return "Pod/" + p.Namespace + "/" + p.Name }

// Live mirrors kubesentry's "live": not Succeeded or Failed.
func (p *Pod) Live() bool { return p.Phase != "Succeeded" && p.Phase != "Failed" }

// Shown mirrors which pods kubesentry's map and node view list: live ones and
// those created in the last day.
func (p *Pod) Shown(now time.Time) bool { return p.Live() || now.Sub(p.Created) < 24*time.Hour }

// Endpoint is one EndpointSlice endpoint backed by a pod.
type Endpoint struct {
	Pod         string `json:"pod"`
	Ready       bool   `json:"ready"`
	Serving     bool   `json:"serving"`
	Terminating bool   `json:"terminating"`
}

// Truth is the ground truth for the whole cluster.
type Truth struct {
	Taken time.Time
	Pods  map[string]*Pod // by "ns/name"
	// Relations by name; each a set of "from|to".
	Relations map[string]map[string]bool
	// WorkloadPods counts live, non-terminating pods per workload
	// ("Kind/ns/name") for the kinds kubesentry lists.
	WorkloadPods map[string]int
	Endpoints    map[string][]Endpoint // by Service ID
	Workloads    map[string]bool       // every Deployment, StatefulSet, DaemonSet, Job, CronJob, ReplicaSet
	Namespaces   map[string]bool       // namespaces with pods
	Counts       map[string]int        // objects listed, by kind
}

// Key joins a relation edge.
func Key(from, to string) string { return from + "|" + to }

func (t *Truth) add(rel, from, to string) {
	m := t.Relations[rel]
	if m == nil {
		m = map[string]bool{}
		t.Relations[rel] = m
	}
	m[Key(from, to)] = true
}

func id(kind, ns, name string) string { return kind + "/" + ns + "/" + name }

func controller(refs []metav1.OwnerReference) *metav1.OwnerReference {
	for i := range refs {
		if refs[i].Controller != nil && *refs[i].Controller {
			return &refs[i]
		}
	}
	return nil
}

// Compute lists everything it needs and resolves the relations.
func Compute(ctx context.Context, cs kubernetes.Interface) (*Truth, error) {
	t := &Truth{
		Taken: time.Now(), Pods: map[string]*Pod{}, Relations: map[string]map[string]bool{},
		WorkloadPods: map[string]int{}, Endpoints: map[string][]Endpoint{}, Workloads: map[string]bool{},
		Namespaces: map[string]bool{}, Counts: map[string]int{},
	}
	var (
		pods      []corev1.Pod
		rss       []appsv1.ReplicaSet
		deploys   []appsv1.Deployment
		sts       []appsv1.StatefulSet
		dss       []appsv1.DaemonSet
		jobs      []batchv1.Job
		cjs       []batchv1.CronJob
		slices    []discoveryv1.EndpointSlice
		services  []corev1.Service
		ingresses []networkingv1.Ingress
	)
	if err := list(ctx, "pods", func(o metav1.ListOptions) (string, error) {
		l, err := cs.CoreV1().Pods("").List(ctx, o)
		if err != nil {
			return "", err
		}
		pods = append(pods, l.Items...)
		return l.Continue, nil
	}); err != nil {
		return nil, err
	}
	steps := []struct {
		what string
		f    func(metav1.ListOptions) (string, error)
	}{
		{"replicasets", func(o metav1.ListOptions) (string, error) {
			l, err := cs.AppsV1().ReplicaSets("").List(ctx, o)
			if err != nil {
				return "", err
			}
			rss = append(rss, l.Items...)
			return l.Continue, nil
		}},
		{"deployments", func(o metav1.ListOptions) (string, error) {
			l, err := cs.AppsV1().Deployments("").List(ctx, o)
			if err != nil {
				return "", err
			}
			deploys = append(deploys, l.Items...)
			return l.Continue, nil
		}},
		{"statefulsets", func(o metav1.ListOptions) (string, error) {
			l, err := cs.AppsV1().StatefulSets("").List(ctx, o)
			if err != nil {
				return "", err
			}
			sts = append(sts, l.Items...)
			return l.Continue, nil
		}},
		{"daemonsets", func(o metav1.ListOptions) (string, error) {
			l, err := cs.AppsV1().DaemonSets("").List(ctx, o)
			if err != nil {
				return "", err
			}
			dss = append(dss, l.Items...)
			return l.Continue, nil
		}},
		{"jobs", func(o metav1.ListOptions) (string, error) {
			l, err := cs.BatchV1().Jobs("").List(ctx, o)
			if err != nil {
				return "", err
			}
			jobs = append(jobs, l.Items...)
			return l.Continue, nil
		}},
		{"cronjobs", func(o metav1.ListOptions) (string, error) {
			l, err := cs.BatchV1().CronJobs("").List(ctx, o)
			if err != nil {
				return "", err
			}
			cjs = append(cjs, l.Items...)
			return l.Continue, nil
		}},
		{"endpointslices", func(o metav1.ListOptions) (string, error) {
			l, err := cs.DiscoveryV1().EndpointSlices("").List(ctx, o)
			if err != nil {
				return "", err
			}
			slices = append(slices, l.Items...)
			return l.Continue, nil
		}},
		{"services", func(o metav1.ListOptions) (string, error) {
			l, err := cs.CoreV1().Services("").List(ctx, o)
			if err != nil {
				return "", err
			}
			services = append(services, l.Items...)
			return l.Continue, nil
		}},
		{"ingresses", func(o metav1.ListOptions) (string, error) {
			l, err := cs.NetworkingV1().Ingresses("").List(ctx, o)
			if err != nil {
				return "", err
			}
			ingresses = append(ingresses, l.Items...)
			return l.Continue, nil
		}},
	}
	for _, s := range steps {
		if err := list(ctx, s.what, s.f); err != nil {
			return nil, err
		}
	}
	t.Counts = map[string]int{"pods": len(pods), "replicasets": len(rss), "deployments": len(deploys), "statefulsets": len(sts),
		"daemonsets": len(dss), "jobs": len(jobs), "cronjobs": len(cjs), "endpointslices": len(slices), "services": len(services), "ingresses": len(ingresses)}

	rsByUID := map[types.UID]*appsv1.ReplicaSet{}
	for i := range rss {
		rsByUID[rss[i].UID] = &rss[i]
		t.Workloads[id("ReplicaSet", rss[i].Namespace, rss[i].Name)] = true
	}
	jobByUID := map[types.UID]*batchv1.Job{}
	for i := range jobs {
		j := &jobs[i]
		jobByUID[j.UID] = j
		jid := id("Job", j.Namespace, j.Name)
		t.Workloads[jid] = true
		t.WorkloadPods[jid] += 0
		if c := controller(j.OwnerReferences); c != nil && c.Kind == "CronJob" {
			t.add(CronJobJob, id("CronJob", j.Namespace, c.Name), jid)
		}
	}
	for _, d := range deploys {
		t.Workloads[id("Deployment", d.Namespace, d.Name)] = true
		t.WorkloadPods[id("Deployment", d.Namespace, d.Name)] += 0
	}
	for _, s := range sts {
		t.Workloads[id("StatefulSet", s.Namespace, s.Name)] = true
		t.WorkloadPods[id("StatefulSet", s.Namespace, s.Name)] += 0
	}
	for _, d := range dss {
		t.Workloads[id("DaemonSet", d.Namespace, d.Name)] = true
		t.WorkloadPods[id("DaemonSet", d.Namespace, d.Name)] += 0
	}
	for _, c := range cjs {
		t.Workloads[id("CronJob", c.Namespace, c.Name)] = true
		t.WorkloadPods[id("CronJob", c.Namespace, c.Name)] += 0
	}

	for i := range pods {
		kp := &pods[i]
		p := &Pod{
			Namespace: kp.Namespace, Name: kp.Name, UID: string(kp.UID), Node: kp.Spec.NodeName,
			Phase: string(kp.Status.Phase), Labels: kp.Labels, Created: kp.CreationTimestamp.Time,
			Terminating: kp.DeletionTimestamp != nil,
		}
		t.Namespaces[p.Namespace] = true
		p.Reason = reason(kp)
		p.Group = p.ID()
		var cronParent string
		if c := controller(kp.OwnerReferences); c != nil {
			p.Owner = id(c.Kind, kp.Namespace, c.Name)
			switch c.Kind {
			case "ReplicaSet":
				p.Top = p.Owner
				if rs := rsByUID[c.UID]; rs != nil {
					if rc := controller(rs.OwnerReferences); rc != nil {
						p.Top = id(rc.Kind, kp.Namespace, rc.Name)
					}
				}
				p.Group = p.Top
			case "Job":
				p.Top, p.Group = p.Owner, p.Owner
				if j := jobByUID[c.UID]; j != nil {
					if jc := controller(j.OwnerReferences); jc != nil && jc.Kind == "CronJob" {
						cronParent = id("CronJob", kp.Namespace, jc.Name)
						p.Group = cronParent
					}
				}
			case "Node":
				// Mirror pod of a static pod: no workload.
			default:
				p.Top, p.Group = p.Owner, p.Owner
			}
		}
		for _, v := range kp.Spec.Volumes {
			switch {
			case v.PersistentVolumeClaim != nil:
				p.Claims = append(p.Claims, v.PersistentVolumeClaim.ClaimName)
			case v.Ephemeral != nil:
				p.Claims = append(p.Claims, kp.Name+"-"+v.Name)
			}
		}
		for _, c := range append(append([]corev1.Container{}, kp.Spec.InitContainers...), kp.Spec.Containers...) {
			if c.SecurityContext == nil || c.SecurityContext.AllowPrivilegeEscalation == nil || *c.SecurityContext.AllowPrivilegeEscalation {
				p.Escalation = true
			}
		}
		t.Pods[p.Namespace+"/"+p.Name] = p

		if p.Shown(t.Taken) {
			if p.Top != "" {
				t.add(PodOwner, p.Top, p.ID())
			}
			if p.Node != "" {
				t.add(PodNode, p.ID(), "Node/"+p.Node)
			}
			for _, c := range p.Claims {
				t.add(PodPVC, p.ID(), id("PVC", p.Namespace, c))
			}
		}
		if p.Escalation {
			t.add(SecurityGroup, p.Group, "")
		}
		if p.Live() && !p.Terminating && p.Top != "" {
			t.WorkloadPods[p.Top]++
			if cronParent != "" {
				t.WorkloadPods[cronParent]++
			}
		}
	}

	svcExists := map[string]bool{}
	for _, s := range services {
		sid := id("Service", s.Namespace, s.Name)
		svcExists[sid] = true
		t.Endpoints[sid] = []Endpoint{}
	}
	for _, sl := range slices {
		svc := sl.Labels[discoveryv1.LabelServiceName]
		if svc == "" {
			continue
		}
		sid := id("Service", sl.Namespace, svc)
		for _, ep := range sl.Endpoints {
			if ep.TargetRef == nil || ep.TargetRef.Kind != "Pod" {
				continue
			}
			pid := id("Pod", sl.Namespace, ep.TargetRef.Name)
			t.add(ServicePods, sid, pid)
			t.Endpoints[sid] = append(t.Endpoints[sid], Endpoint{
				Pod: pid, Ready: deref(ep.Conditions.Ready, true), Serving: deref(ep.Conditions.Serving, true), Terminating: deref(ep.Conditions.Terminating, false),
			})
		}
	}
	for _, ing := range ingresses {
		iid := id("Ingress", ing.Namespace, ing.Name)
		var backends []string
		if ing.Spec.DefaultBackend != nil && ing.Spec.DefaultBackend.Service != nil {
			backends = append(backends, ing.Spec.DefaultBackend.Service.Name)
		}
		for _, r := range ing.Spec.Rules {
			if r.HTTP == nil {
				continue
			}
			for _, p := range r.HTTP.Paths {
				if p.Backend.Service != nil {
					backends = append(backends, p.Backend.Service.Name)
				}
			}
		}
		for _, b := range backends {
			if sid := id("Service", ing.Namespace, b); svcExists[sid] {
				t.add(IngressService, iid, sid)
			}
		}
	}
	return t, nil
}

func reason(p *corev1.Pod) string {
	if p.DeletionTimestamp != nil {
		return "Terminating"
	}
	for _, cs := range append(append([]corev1.ContainerStatus{}, p.Status.InitContainerStatuses...), p.Status.ContainerStatuses...) {
		if cs.State.Waiting != nil && cs.State.Waiting.Reason != "" && cs.State.Waiting.Reason != "PodInitializing" && cs.State.Waiting.Reason != "ContainerCreating" {
			return cs.State.Waiting.Reason
		}
		// Between back-offs a crash-looping container briefly runs again.
		if cs.RestartCount >= 2 && !cs.Ready && cs.LastTerminationState.Terminated != nil {
			return "CrashLoopBackOff"
		}
	}
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodScheduled && c.Status == corev1.ConditionFalse && c.Reason != "" {
			return c.Reason
		}
	}
	if p.Status.Phase == corev1.PodRunning {
		for _, c := range p.Status.Conditions {
			if c.Type == corev1.PodReady && c.Status != corev1.ConditionTrue {
				return "NotReady"
			}
		}
	}
	return ""
}

func deref(b *bool, def bool) bool {
	if b == nil {
		return def
	}
	return *b
}

func list(ctx context.Context, what string, f func(metav1.ListOptions) (string, error)) error {
	o := metav1.ListOptions{Limit: 1000}
	for {
		cont, err := f(o)
		if err != nil {
			return fmt.Errorf("list %s: %w", what, err)
		}
		if cont == "" {
			return nil
		}
		o.Continue = cont
	}
}
