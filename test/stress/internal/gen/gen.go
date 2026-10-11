package gen

import (
	"context"
	"fmt"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"

	"github.com/ByronGary/kubesentry/test/stress/internal/kc"
	"github.com/ByronGary/kubesentry/test/stress/internal/out"
	"github.com/ByronGary/kubesentry/test/stress/internal/plan"
)

// Result summarises a gen run (written to gen.json).
type Result struct {
	Level        string         `json:"level"`
	Started      time.Time      `json:"started"`
	Finished     time.Time      `json:"finished"`
	Plan         plan.Stats     `json:"plan"`
	Created      int64          `json:"created"`
	Existed      int64          `json:"existed"`
	Failed       int64          `json:"failed"`
	Errors       []string       `json:"errors,omitempty"`
	PhaseSeconds map[string]int `json:"phaseSeconds"`
	Settle       SettleState    `json:"settle"`
}

// SettleState is the cluster after the generator waited for it to settle.
type SettleState struct {
	Seconds        int            `json:"seconds"`
	Nodes          int            `json:"nodes"`
	FakeNodes      int            `json:"fakeNodes"`
	FakeNodesReady int            `json:"fakeNodesReady"`
	Pods           int            `json:"pods"`
	PodsByPhase    map[string]int `json:"podsByPhase"`
	PendingStress  int            `json:"pendingStress"` // pending pods in generated namespaces
	Timeout        bool           `json:"timeout"`
}

// Options control a run.
type Options struct {
	Level         plan.Level
	Workers       int
	Batch         int
	Pause         time.Duration
	SettleTimeout time.Duration
	SkipSettle    bool
}

// Run creates the plan's objects, then waits for the cluster to settle.
// tricky, when non-nil, creates the association edge cases after the
// generated objects (it lives in its own package to keep this one generic).
func Run(ctx context.Context, c *kc.Clients, o Options, tricky func(*Applier) error) (*Result, error) {
	p := plan.Build(o.Level)
	res := &Result{Level: o.Level.Name, Started: time.Now().UTC(), Plan: p.Stats, PhaseSeconds: map[string]int{}}
	out.Logf("plan %s: %d fake nodes, %d team + %d add-on namespaces, about %d pods",
		o.Level.Name, p.Stats.Nodes, p.Stats.TeamNamespaces, p.Stats.AddonNamespaces, p.Stats.ExpectedPods)
	a := &Applier{CS: c.CS, Dyn: c.Dyn, Workers: o.Workers, Batch: o.Batch, Pause: o.Pause}
	phase := func(name string, f func()) {
		t := time.Now()
		f()
		res.PhaseSeconds[name] = int(time.Since(t).Seconds())
	}

	phase("cleanup-l0", func() { cleanupL0(ctx, c.CS) })
	phase("nodes", func() {
		objs := make([]runtime.Object, 0, len(p.Nodes))
		for _, n := range p.Nodes {
			objs = append(objs, n.Object())
		}
		a.Apply(ctx, "nodes", objs)
		waitNodes(ctx, c.CS, len(p.Nodes), 10*time.Minute)
	})
	byType := func(pred func(runtime.Object) bool) []runtime.Object {
		var objs []runtime.Object
		for _, ns := range p.Namespaces {
			for _, x := range ns.Objects {
				if pred(x) {
					objs = append(objs, x)
				}
			}
		}
		return objs
	}
	is := func(types ...string) func(runtime.Object) bool {
		return func(o runtime.Object) bool {
			t := fmt.Sprintf("%T", o)
			for _, want := range types {
				if t == want {
					return true
				}
			}
			return false
		}
	}
	phase("cluster", func() {
		a.Apply(ctx, "cluster-scoped objects", p.Cluster)
	})
	phase("namespaces", func() {
		objs := make([]runtime.Object, 0, len(p.Namespaces))
		for _, ns := range p.Namespaces {
			objs = append(objs, ns.Object)
		}
		a.Apply(ctx, "namespaces", objs)
	})
	phase("config", func() {
		a.Apply(ctx, "service accounts, config", byType(is("*v1.ServiceAccount", "*v1.ConfigMap")))
		a.Apply(ctx, "roles", byType(func(o runtime.Object) bool { _, ok := o.(*rbacv1.Role); return ok }))
		a.Apply(ctx, "role bindings", byType(func(o runtime.Object) bool { _, ok := o.(*rbacv1.RoleBinding); return ok }))
		a.Apply(ctx, "claims", byType(func(o runtime.Object) bool { _, ok := o.(*corev1.PersistentVolumeClaim); return ok }))
	})
	phase("network", func() {
		a.Apply(ctx, "services", byType(func(o runtime.Object) bool { _, ok := o.(*corev1.Service); return ok }))
		a.Apply(ctx, "endpoint slices", byType(func(o runtime.Object) bool { _, ok := o.(*discoveryv1.EndpointSlice); return ok }))
		a.Apply(ctx, "ingresses", byType(func(o runtime.Object) bool { _, ok := o.(*networkingv1.Ingress); return ok }))
	})
	phase("workloads", func() {
		a.Apply(ctx, "deployments", byType(func(o runtime.Object) bool { _, ok := o.(*appsv1.Deployment); return ok }))
		a.Apply(ctx, "statefulsets, daemonsets", byType(func(o runtime.Object) bool {
			switch o.(type) {
			case *appsv1.StatefulSet, *appsv1.DaemonSet:
				return true
			}
			return false
		}))
		a.Apply(ctx, "jobs, cronjobs, pods", byType(func(o runtime.Object) bool {
			switch o.(type) {
			case *batchv1.Job, *batchv1.CronJob, *corev1.Pod:
				return true
			}
			return false
		}))
	})
	phase("certificates", func() {
		var objs []runtime.Object
		for _, ns := range p.Namespaces {
			for _, cert := range ns.Certs {
				if cert.GetKind() == "Issuer" {
					objs = append(objs, cert)
				}
			}
		}
		for _, ns := range p.Namespaces {
			for _, cert := range ns.Certs {
				if cert.GetKind() == "Certificate" {
					objs = append(objs, cert)
				}
			}
		}
		a.Apply(ctx, "issuers, certificates", objs)
	})
	if tricky != nil {
		phase("tricky", func() {
			if err := tricky(a); err != nil {
				out.Logf("tricky cases: %v", err)
			}
		})
	}
	res.Created, res.Existed, res.Failed = a.Counts()
	res.Errors = a.Errors()
	if !o.SkipSettle {
		phase("settle", func() { res.Settle = Settle(ctx, c.CS, p, o.SettleTimeout) })
	}
	res.Finished = time.Now().UTC()
	return res, nil
}

// cleanupL0 deletes fake nodes and the namespace left by the L0 smoke test,
// which predate the stress label.
func cleanupL0(ctx context.Context, cs kubernetes.Interface) {
	if err := cs.CoreV1().Namespaces().Delete(ctx, "stress-l0", metav1.DeleteOptions{}); err == nil {
		out.Logf("deleted namespace stress-l0 (L0 leftover)")
		// Its fake pods sit on node names the plan reuses; KWOK may never finish them.
		_ = cs.CoreV1().Pods("stress-l0").DeleteCollection(ctx, metav1.DeleteOptions{GracePeriodSeconds: new(int64)}, metav1.ListOptions{})
	}
	nodes, err := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: "type=kwok,!" + kc.StressLabel})
	if err != nil {
		return
	}
	for _, n := range nodes.Items {
		if err := cs.CoreV1().Nodes().Delete(ctx, n.Name, metav1.DeleteOptions{}); err == nil {
			out.Logf("deleted fake node %s (L0 leftover)", n.Name)
		}
	}
	if len(nodes.Items) > 0 {
		// The plan reuses those names; wait until they are gone.
		_ = wait.PollUntilContextTimeout(ctx, 2*time.Second, 2*time.Minute, true, func(ctx context.Context) (bool, error) {
			l, err := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: "type=kwok,!" + kc.StressLabel})
			return err == nil && len(l.Items) == 0, nil
		})
	}
}

func waitNodes(ctx context.Context, cs kubernetes.Interface, want int, timeout time.Duration) {
	start := time.Now()
	_ = wait.PollUntilContextTimeout(ctx, 5*time.Second, timeout, true, func(ctx context.Context) (bool, error) {
		l, err := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: "type=kwok," + kc.StressLabel + "=true"})
		if err != nil {
			return false, nil
		}
		ready := 0
		for _, n := range l.Items {
			if nodeReady(&n) {
				ready++
			}
		}
		out.Logf("fake nodes ready: %d/%d (%s)", ready, want, time.Since(start).Round(time.Second))
		return ready >= want, nil
	})
}

func nodeReady(n *corev1.Node) bool {
	for _, c := range n.Status.Conditions {
		if c.Type == corev1.NodeReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

// Settle waits until no generated pod is Pending and the pod count stops
// growing, or the timeout.
func Settle(ctx context.Context, cs kubernetes.Interface, p *plan.Plan, timeout time.Duration) SettleState {
	start := time.Now()
	generated := map[string]bool{}
	for _, ns := range p.Namespaces {
		generated[ns.Object.Name] = true
	}
	var st SettleState
	last, stableSince := -1, time.Now()
	err := wait.PollUntilContextTimeout(ctx, 10*time.Second, timeout, true, func(ctx context.Context) (bool, error) {
		s, err := Snapshot(ctx, cs, generated)
		if err != nil {
			out.Logf("settle: %v", err)
			return false, nil
		}
		st = s
		if s.Pods != last {
			last, stableSince = s.Pods, time.Now()
		}
		out.Logf("settle: %d pods %v, %d pending in generated namespaces, fake nodes ready %d/%d (%s)",
			s.Pods, s.PodsByPhase, s.PendingStress, s.FakeNodesReady, s.FakeNodes, time.Since(start).Round(time.Second))
		return s.Pods >= p.Stats.GeneratedPods && s.PendingStress == 0 && time.Since(stableSince) > 30*time.Second, nil
	})
	st.Timeout = err != nil
	st.Seconds = int(time.Since(start).Seconds())
	return st
}

// Snapshot counts nodes and pods.
func Snapshot(ctx context.Context, cs kubernetes.Interface, generated map[string]bool) (SettleState, error) {
	s := SettleState{PodsByPhase: map[string]int{}}
	nodes, err := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return s, err
	}
	s.Nodes = len(nodes.Items)
	for _, n := range nodes.Items {
		if n.Labels["type"] == "kwok" {
			s.FakeNodes++
			if nodeReady(&n) {
				s.FakeNodesReady++
			}
		}
	}
	opts := metav1.ListOptions{Limit: 2000, ResourceVersion: "0"}
	for {
		l, err := cs.CoreV1().Pods("").List(ctx, opts)
		if err != nil {
			return s, err
		}
		for _, p := range l.Items {
			s.Pods++
			s.PodsByPhase[string(p.Status.Phase)]++
			if p.Status.Phase == corev1.PodPending && generated[p.Namespace] {
				s.PendingStress++
			}
		}
		if l.Continue == "" {
			break
		}
		opts.Continue, opts.ResourceVersion = l.Continue, ""
	}
	return s, nil
}

// Delete removes everything the harness created.
func Delete(ctx context.Context, cs kubernetes.Interface, deleteDyn func(context.Context) error, removeStatic func(context.Context) error) error {
	sel := metav1.ListOptions{LabelSelector: kc.StressLabel + "=true"}
	bg := metav1.DeletePropagationBackground
	do := metav1.DeleteOptions{PropagationPolicy: &bg}
	if removeStatic != nil {
		if err := removeStatic(ctx); err != nil {
			out.Logf("static pod: %v", err)
		}
	}
	nss, err := cs.CoreV1().Namespaces().List(ctx, sel)
	if err != nil {
		return err
	}
	for _, ns := range nss.Items {
		if err := cs.CoreV1().Namespaces().Delete(ctx, ns.Name, do); err != nil && !apierrors.IsNotFound(err) {
			out.Logf("delete namespace %s: %v", ns.Name, err)
		}
	}
	out.Logf("deleting %d namespaces", len(nss.Items))
	_ = cs.CoreV1().ConfigMaps("kube-system").DeleteCollection(ctx, do, sel)
	_ = cs.CoreV1().PersistentVolumes().DeleteCollection(ctx, do, sel)
	_ = cs.StorageV1().StorageClasses().DeleteCollection(ctx, do, sel)
	_ = cs.StorageV1().CSIDrivers().DeleteCollection(ctx, do, sel)
	_ = cs.NetworkingV1().IngressClasses().DeleteCollection(ctx, do, sel)
	_ = cs.RbacV1().ClusterRoleBindings().DeleteCollection(ctx, do, sel)
	_ = cs.RbacV1().ClusterRoles().DeleteCollection(ctx, do, sel)
	if deleteDyn != nil {
		if err := deleteDyn(ctx); err != nil {
			out.Logf("custom resources: %v", err)
		}
	}
	start := time.Now()
	_ = wait.PollUntilContextTimeout(ctx, 10*time.Second, 20*time.Minute, true, func(ctx context.Context) (bool, error) {
		l, err := cs.CoreV1().Namespaces().List(ctx, sel)
		if err != nil {
			return false, nil
		}
		out.Logf("namespaces left: %d (%s)", len(l.Items), time.Since(start).Round(time.Second))
		return len(l.Items) == 0, nil
	})
	if err := cs.CoreV1().Nodes().DeleteCollection(ctx, do, sel); err != nil {
		out.Logf("delete nodes: %v", err)
	}
	return nil
}

// Summary renders a one-line summary.
func (r *Result) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %d created, %d existed, %d failed; settle %ds: %d pods %v, %d fake nodes ready",
		r.Level, r.Created, r.Existed, r.Failed, r.Settle.Seconds, r.Settle.Pods, r.Settle.PodsByPhase, r.Settle.FakeNodesReady)
	return b.String()
}
