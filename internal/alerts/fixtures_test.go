package alerts

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/model"
	"github.com/ByronGary/kubesentry/internal/snapshot"
)

// t0 is the fixtures' clock.
var t0 = time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)

// deployment adds a Deployment with one ReplicaSet and n pods made by pod.
func deployment(inv *model.Inventory, ns, name string, desired, ready int32, n int, pod func(i int, p *model.Pod)) {
	uid := "dep-" + ns + "-" + name
	inv.Workloads = append(inv.Workloads, model.Workload{Kind: "Deployment", Namespace: ns, Name: name, UID: uid,
		Desired: desired, Ready: ready, Updated: desired, Available: ready,
		Selector: &model.LabelSelector{MatchLabels: map[string]string{"app": name}}})
	rs := name + "-7d9f"
	inv.ReplicaSets = append(inv.ReplicaSets, model.ReplicaSet{Namespace: ns, Name: rs, UID: "rs-" + uid,
		Owners: []model.OwnerRef{{Kind: "Deployment", Name: name, UID: uid, Controller: true}}})
	for i := 0; i < n; i++ {
		p := model.Pod{UID: fmt.Sprintf("%s-%d", uid, i), Namespace: ns, Name: fmt.Sprintf("%s-%d", rs, i), Phase: "Running", Ready: true,
			NodeName: fmt.Sprintf("node-%d", i%2), Labels: map[string]string{"app": name}, Created: t0.Add(-48 * time.Hour),
			Owners:     []model.OwnerRef{{Kind: "ReplicaSet", Name: rs, UID: "rs-" + uid, Controller: true}},
			Containers: []model.ContainerStatus{{Name: name, State: "running", Ready: true}}}
		if pod != nil {
			pod(i, &p)
		}
		inv.Pods = append(inv.Pods, p)
	}
}

func crashLooping(p *model.Pod) {
	p.Ready = false
	p.ReadyChanged = t0.Add(-time.Hour)
	p.Containers[0] = model.ContainerStatus{Name: p.Containers[0].Name, State: "waiting", Reason: "CrashLoopBackOff",
		Message: "back-off 5m0s restarting failed container", RestartCount: 12}
}

// fixture is a small cluster with one of each problem the alerts know:
//
//	payments (owner payments, production, Slack hint): Deployment api
//	  crash-looping on 3 of 4 pods; 2 evicted pods of Deployment batch;
//	  2 pods of Deployment web stuck terminating on node-1; a leaking pod
//	  of Deployment cache; certificate api-tls expiring and not renewed,
//	  certificate fresh-tls renewing on schedule.
//	team-a (no owner): Deployment img with an image pull failure; a pod
//	  unschedulable for 10 minutes; certificate lost-tls whose issuer is
//	  missing.
//	cluster: ClusterRoleBinding erin-admin grants cluster-admin to erin;
//	  the kubeadm binding is plumbing and never alerts.
func fixture() model.Inventory {
	inv := model.Inventory{Unavailable: map[string]string{}}
	inv.Namespaces = []model.Namespace{
		{Name: "payments", Labels: map[string]string{"environment": "production"},
			Annotations: map[string]string{"kubesentry.io/owner": "payments", "kubesentry.io/slack-channel": "#payments-alerts", "kubesentry.io/digest": "true"}},
		{Name: "team-a"},
		{Name: "kube-system"},
	}
	deployment(&inv, "payments", "api", 4, 1, 4, func(i int, p *model.Pod) {
		if i < 3 {
			crashLooping(p)
		}
	})
	deployment(&inv, "payments", "batch", 2, 2, 4, func(i int, p *model.Pod) {
		if i >= 2 {
			p.Phase, p.Ready, p.Reason, p.Message = "Failed", false, "Evicted", "The node was low on resource: memory."
			p.ReadyChanged = t0.Add(-time.Duration(i) * time.Hour)
		}
	})
	deployment(&inv, "payments", "web", 2, 2, 4, func(i int, p *model.Pod) {
		if i >= 2 {
			p.DeletedAt = t0.Add(-time.Duration(10*i) * time.Minute)
			p.NodeName = "node-1"
		}
	})
	deployment(&inv, "payments", "cache", 1, 1, 1, nil)
	deployment(&inv, "team-a", "img", 1, 0, 1, func(_ int, p *model.Pod) {
		p.Ready = false
		p.Containers[0] = model.ContainerStatus{Name: "img", State: "waiting", Reason: "ImagePullBackOff", Message: "Back-off pulling image \"nope:latest\""}
	})
	inv.Pods = append(inv.Pods, model.Pod{UID: "bare", Namespace: "team-a", Name: "huge", Phase: "Pending", Created: t0.Add(-10 * time.Minute),
		Unschedulable: "0/3 nodes are available: 3 Insufficient memory."})

	inv.Certs.Installed = true
	inv.Certs.Issuers = []model.Issuer{{Kind: "ClusterIssuer", Name: "le", Type: "acme", Ready: "True"}}
	inv.Certs.Certificates = []model.Certificate{
		{Namespace: "payments", Name: "api-tls", SecretName: "api-tls", DNSNames: []string{"api.example.com"}, IssuerKind: "ClusterIssuer", IssuerName: "le",
			Ready: "True", NotBefore: t0.Add(-87 * 24 * time.Hour), NotAfter: t0.Add(3 * 24 * time.Hour), RenewalTime: t0.Add(-27 * 24 * time.Hour)},
		{Namespace: "payments", Name: "fresh-tls", SecretName: "fresh-tls", IssuerKind: "ClusterIssuer", IssuerName: "le",
			Ready: "True", NotBefore: t0.Add(-20 * time.Hour), NotAfter: t0.Add(4 * time.Hour), RenewalTime: t0.Add(2 * time.Hour)},
		{Namespace: "payments", Name: "ok-tls", SecretName: "ok-tls", IssuerKind: "ClusterIssuer", IssuerName: "le",
			Ready: "True", NotBefore: t0.Add(-10 * 24 * time.Hour), NotAfter: t0.Add(80 * 24 * time.Hour), RenewalTime: t0.Add(50 * 24 * time.Hour)},
		{Namespace: "team-a", Name: "lost-tls", SecretName: "lost-tls", IssuerKind: "Issuer", IssuerName: "gone", Ready: "False", Created: t0.Add(-time.Hour)},
	}

	inv.RBAC = model.RBAC{
		Roles: []model.Role{{Kind: "ClusterRole", Name: "cluster-admin", Rules: []model.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}}}},
		Bindings: []model.RoleBinding{
			{Kind: "ClusterRoleBinding", Name: "erin-admin", RoleKind: "ClusterRole", RoleName: "cluster-admin", Subjects: []model.Subject{{Kind: "User", Name: "erin"}}},
			{Kind: "ClusterRoleBinding", Name: "kubeadm:cluster-admins", RoleKind: "ClusterRole", RoleName: "cluster-admin", Subjects: []model.Subject{{Kind: "Group", Name: "kubeadm:cluster-admins"}}},
		},
	}
	return inv
}

// withBinding adds a ClusterRoleBinding granting cluster-admin to user.
func withBinding(inv model.Inventory, name, user string) model.Inventory {
	inv.RBAC.Bindings = append(append([]model.RoleBinding(nil), inv.RBAC.Bindings...),
		model.RoleBinding{Kind: "ClusterRoleBinding", Name: name, RoleKind: "ClusterRole", RoleName: "cluster-admin", Subjects: []model.Subject{{Kind: "User", Name: user}}})
	return inv
}

func view(inv model.Inventory, at time.Time) *snapshot.View {
	return snapshot.Build(inv, detectors.DefaultPolicy(), at)
}

// leakReport has one leak in payments/cache, 3h from its limit.
func leakReport(at time.Time) *detectors.LeakReport {
	ttl := 3.0
	return &detectors.LeakReport{GeneratedAt: at, Window: "24h", Findings: []detectors.LeakFinding{{
		ContainerKey: model.ContainerKey{Namespace: "payments", Pod: "cache-7d9f-0", Container: "cache"},
		Segments:     2, LeakySegments: 2, SlopeBytesPerHour: 120 << 20, R2: 0.97, CurrentBytes: 700 << 20, LimitBytes: 1 << 30,
		TimeToLimitHours: &ttl, Confidence: "high",
	}, {
		ContainerKey:      model.ContainerKey{Namespace: "payments", Pod: "gone-pod", Container: "x"},
		SlopeBytesPerHour: 1 << 20, Confidence: "medium",
	}}}
}

// recordSink keeps what was sent, batch by batch.
type recordSink struct {
	mu      sync.Mutex
	batches [][]Alert
	dropped int
}

func (r *recordSink) Send(a []Alert) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.batches = append(r.batches, a)
}
func (r *recordSink) Drop()              { r.mu.Lock(); r.dropped++; r.mu.Unlock() }
func (r *recordSink) Status() SinkStatus { return SinkStatus{Name: "test"} }

// take returns and forgets what was sent since the last call.
func (r *recordSink) take() []Alert {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []Alert
	for _, b := range r.batches {
		out = append(out, b...)
	}
	r.batches = nil
	return out
}

// failStore fails its commits while fail is set.
type failStore struct {
	Store
	fail bool
}

func (f *failStore) Commit(ctx context.Context, c Commit) error {
	if f.fail {
		return fmt.Errorf("lost the lock")
	}
	return f.Store.Commit(ctx, c)
}

// firing and resolved split sent alerts by whether they end in the future.
func firing(as []Alert, now time.Time) map[string]Alert {
	out := map[string]Alert{}
	for _, a := range as {
		if a.EndsAt.After(now) {
			out[a.Annotations["dedupe_key"]+a.Labels["owner"]+a.Labels["alertname"]] = a
		}
	}
	return out
}

func resolvedOf(as []Alert, now time.Time) []Alert {
	var out []Alert
	for _, a := range as {
		if !a.EndsAt.After(now) {
			out = append(out, a)
		}
	}
	return out
}
