package detectors

import (
	"strings"
	"testing"

	"github.com/ByronGary/kubesentry/internal/model"
)

func i64(v int64) *int64 { return &v }
func bptr(v bool) *bool  { return &v }

// hardened is a container spec that trips no pod check.
func hardened(name string) model.ContainerSpec {
	return model.ContainerSpec{Name: name, RunAsNonRoot: true, AllowPrivilegeEscalation: bptr(false), MemoryLimitBytes: 256 << 20}
}

func findingsByID(fs []SecurityFinding) map[string]SecurityFinding {
	m := map[string]SecurityFinding{}
	for _, f := range fs {
		m[f.ID] = f
	}
	return m
}

func TestAuditSecurityPods(t *testing.T) {
	root := hardened("trainer")
	root.RunAsNonRoot, root.Privileged = false, true
	root.CapabilitiesAdd = []string{"SYS_ADMIN", "NET_ADMIN"}
	initC := hardened("setup")
	initC.Init, initC.RunAsNonRoot, initC.RunAsUser = true, false, i64(0)
	netOnly := hardened("proxy")
	netOnly.CapabilitiesAdd = []string{"CAP_NET_ADMIN", "NET_BIND_SERVICE"}
	bindOnly := hardened("web")
	bindOnly.CapabilitiesAdd = []string{"NET_BIND_SERVICE"}
	loose := model.ContainerSpec{Name: "app", RunAsUser: i64(1000)} // non-root uid, but no limit and escalation allowed

	in := SecurityInput{
		Workloads: []model.Workload{
			{Kind: "Deployment", Namespace: "data", Name: "trainer", Selector: sel("app", "trainer")},
			{Kind: "DaemonSet", Namespace: "kube-system", Name: "proxy", Selector: sel("app", "proxy")},
			{Kind: "CronJob", Namespace: "data", Name: "backup"},
			{Kind: "Job", Namespace: "data", Name: "backup-29000000", Selector: sel("job", "b1")},
			{Kind: "Job", Namespace: "data", Name: "backup-29000060", Selector: sel("job", "b2")},
		},
		Pods: []model.Pod{
			// Two replicas of one Deployment become one finding per check.
			{Namespace: "data", Name: "trainer-1", Labels: map[string]string{"app": "trainer"}, Specs: []model.ContainerSpec{root, initC}},
			{Namespace: "data", Name: "trainer-2", Labels: map[string]string{"app": "trainer"}, Specs: []model.ContainerSpec{root, initC}},
			{Namespace: "kube-system", Name: "proxy-x", Labels: map[string]string{"app": "proxy"}, HostNetwork: true, HostPID: true,
				HostPaths: []string{"/run/xtables.lock", "/lib/modules"}, Specs: []model.ContainerSpec{netOnly}},
			{Namespace: "web", Name: "lonely", Specs: []model.ContainerSpec{bindOnly}},
			{Namespace: "web", Name: "loose", AutomountToken: true, Specs: []model.ContainerSpec{loose}},
			// Jobs created by one CronJob are reported once, under the CronJob.
			{Namespace: "data", Name: "backup-29000000-a", Labels: map[string]string{"job": "b1"}, HostIPC: true, Specs: []model.ContainerSpec{hardened("dump")}},
			{Namespace: "data", Name: "backup-29000060-b", Labels: map[string]string{"job": "b2"}, HostIPC: true, Specs: []model.ContainerSpec{hardened("dump")}},
		},
	}
	fs, _ := AuditSecurity(in)
	m := findingsByID(fs)

	want := []struct {
		id, severity, inDetail string
		system                 bool
	}{
		{"privileged/Deployment/data/trainer", "crit", "trainer.", false},
		{"capabilities/Deployment/data/trainer", "crit", "trainer (SYS_ADMIN, NET_ADMIN)", false},
		{"run-as-root/Deployment/data/trainer", "warn", "trainer, setup (init).", false},
		{"host-namespaces/DaemonSet/kube-system/proxy", "warn", "hostPID, hostNetwork", true},
		{"host-path/DaemonSet/kube-system/proxy", "warn", "/run/xtables.lock, /lib/modules", true},
		{"capabilities/DaemonSet/kube-system/proxy", "warn", "proxy (NET_ADMIN)", true},
		{"host-namespaces/CronJob/data/backup", "warn", "hostIPC", false},
		{"privilege-escalation/Pod/web/loose", "info", "app.", false},
		{"no-memory-limit/Pod/web/loose", "info", "app.", false},
		{"token-automount/Pod/web/loose", "info", "service account default", false},
	}
	for _, w := range want {
		f, ok := m[w.id]
		if !ok {
			t.Errorf("missing %s", w.id)
			continue
		}
		if f.Severity != w.severity || !strings.Contains(f.Detail, w.inDetail) || f.System != w.system || f.Category != "pod" {
			t.Errorf("%s = %s system=%v %q, want %s system=%v containing %q", w.id, f.Severity, f.System, f.Detail, w.severity, w.system, w.inDetail)
		}
	}
	for _, absent := range []string{
		"run-as-root/Pod/web/loose",                // runAsUser 1000 is not root
		"capabilities/Pod/web/lonely",              // NET_BIND_SERVICE alone is fine
		"host-namespaces/Job/data/backup-29000000", // grouped under the CronJob
	} {
		if _, ok := m[absent]; ok {
			t.Errorf("unexpected finding %s", absent)
		}
	}
	if len(fs) != len(m) {
		t.Errorf("finding IDs must be unique: %d findings, %d IDs", len(fs), len(m))
	}
}

func TestAuditSecurityRBAC(t *testing.T) {
	all := model.PolicyRule{Verbs: []string{"*"}, APIGroups: []string{"*"}, Resources: []string{"*"}}
	readSecrets := model.PolicyRule{Verbs: []string{"get", "list"}, APIGroups: []string{""}, Resources: []string{"secrets"}}
	rbac := model.RBAC{
		Roles: []model.Role{
			{Kind: "ClusterRole", Name: "cluster-admin", Rules: []model.PolicyRule{all}},
			{Kind: "ClusterRole", Name: "edit", Rules: []model.PolicyRule{readSecrets}},
			{Kind: "ClusterRole", Name: "secret-reader", Rules: []model.PolicyRule{readSecrets}},
			{Kind: "ClusterRole", Name: "system:controller:foo", Rules: []model.PolicyRule{all}},
			{Kind: "ClusterRole", Name: "pod-reader", Rules: []model.PolicyRule{{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}}}},
			{Kind: "ClusterRole", Name: "unused-wildcard", Rules: []model.PolicyRule{all}},
			{Kind: "Role", Namespace: "prod", Name: "deployer", Rules: []model.PolicyRule{{Verbs: []string{"*"}, APIGroups: []string{"apps"}, Resources: []string{"deployments"}}}},
			{Kind: "Role", Namespace: "prod", Name: "everything", Rules: []model.PolicyRule{{Verbs: []string{"get"}, APIGroups: []string{"", "apps"}, Resources: []string{"*"}}}},
		},
		Bindings: []model.RoleBinding{
			{Kind: "ClusterRoleBinding", Name: "cluster-admin", RoleKind: "ClusterRole", RoleName: "cluster-admin",
				Subjects: []model.Subject{{Kind: "Group", Name: "system:masters"}}},
			{Kind: "ClusterRoleBinding", Name: "erin-admin", RoleKind: "ClusterRole", RoleName: "cluster-admin",
				Subjects: []model.Subject{{Kind: "User", Name: "erin"}, {Kind: "ServiceAccount", Namespace: "kube-system", Name: "x"}}},
			{Kind: "ClusterRoleBinding", Name: "everyone-admin", RoleKind: "ClusterRole", RoleName: "cluster-admin",
				Subjects: []model.Subject{{Kind: "Group", Name: "system:authenticated"}}},
			{Kind: "RoleBinding", Namespace: "team", Name: "team-admin", RoleKind: "ClusterRole", RoleName: "cluster-admin",
				Subjects: []model.Subject{{Kind: "Group", Name: "team"}}},
			{Kind: "ClusterRoleBinding", Name: "public-pods", RoleKind: "ClusterRole", RoleName: "pod-reader",
				Subjects: []model.Subject{{Kind: "Group", Name: "system:unauthenticated"}}},
			{Kind: "ClusterRoleBinding", Name: "system:public-info-viewer", RoleKind: "ClusterRole", RoleName: "system:public-info-viewer",
				Subjects: []model.Subject{{Kind: "Group", Name: "system:unauthenticated"}}},
			{Kind: "RoleBinding", Namespace: "kube-public", Name: "kubeadm:bootstrap-signer-clusterinfo", RoleKind: "Role", RoleName: "kubeadm:bootstrap-signer-clusterinfo",
				Subjects: []model.Subject{{Kind: "User", Name: "system:anonymous"}}},
			{Kind: "ClusterRoleBinding", Name: "devs-secrets", RoleKind: "ClusterRole", RoleName: "secret-reader",
				Subjects: []model.Subject{{Kind: "Group", Name: "developers"}}},
			{Kind: "RoleBinding", Namespace: "staging", Name: "devs-edit", RoleKind: "ClusterRole", RoleName: "edit",
				Subjects: []model.Subject{{Kind: "Group", Name: "developers"}}},
			{Kind: "ClusterRoleBinding", Name: "controller-secrets", RoleKind: "ClusterRole", RoleName: "secret-reader",
				Subjects: []model.Subject{{Kind: "ServiceAccount", Namespace: "kube-system", Name: "ctrl"}, {Kind: "User", Name: "system:kube-controller-manager"}}},
			{Kind: "RoleBinding", Namespace: "prod", Name: "ci", RoleKind: "Role", RoleName: "deployer",
				Subjects: []model.Subject{{Kind: "ServiceAccount", Namespace: "ci", Name: "deployer"}}},
			{Kind: "RoleBinding", Namespace: "prod", Name: "auditors", RoleKind: "Role", RoleName: "everything",
				Subjects: []model.Subject{{Kind: "User", Name: "system:serviceaccount:audit:reader"}}},
			{Kind: "ClusterRoleBinding", Name: "ctrl", RoleKind: "ClusterRole", RoleName: "system:controller:foo",
				Subjects: []model.Subject{{Kind: "User", Name: "bob"}}},
			{Kind: "ClusterRoleBinding", Name: "kubeadm:cluster-admins", RoleKind: "ClusterRole", RoleName: "cluster-admin",
				Subjects: []model.Subject{{Kind: "Group", Name: "kubeadm:cluster-admins"}}},
			{Kind: "ClusterRoleBinding", Name: "operator-secrets", RoleKind: "ClusterRole", RoleName: "secret-reader",
				Subjects: []model.Subject{{Kind: "ServiceAccount", Namespace: "monitoring", Name: "operator"}}},
		},
	}
	fs, _ := AuditSecurity(SecurityInput{RBAC: rbac})
	m := findingsByID(fs)

	want := []struct {
		id, severity, inDetail string
		system                 bool
	}{
		{"cluster-admin/ClusterRoleBinding/erin-admin", "crit", "cluster-wide to User erin.", false},
		{"cluster-admin/ClusterRoleBinding/everyone-admin", "crit", "Group system:authenticated", false},
		{"cluster-admin/RoleBinding/team/team-admin", "warn", "in namespace team", false},
		{"anonymous-binding/ClusterRoleBinding/public-pods", "crit", "ClusterRole pod-reader cluster-wide to system:unauthenticated", false},
		{"anonymous-binding/RoleBinding/kube-public/kubeadm:bootstrap-signer-clusterinfo", "crit", "system:anonymous", true},
		{"secret-readers/ClusterRoleBinding/devs-secrets", "warn", "Group developers can read secrets cluster-wide through ClusterRole secret-reader.", false},
		{"secret-readers/RoleBinding/staging/devs-edit", "warn", "in namespace staging through ClusterRole edit", false},
		{"secret-readers/RoleBinding/prod/auditors", "warn", "User system:serviceaccount:audit:reader", false},
		{"wildcard-rbac/Role/prod/deployer", "warn", "in verbs, so it also grants anything added later; bound to ServiceAccount ci/deployer.", false},
		{"wildcard-rbac/Role/prod/everything", "warn", "resources", false},
		// A system: role is not judged as a wildcard role, but who it is granted to still counts.
		{"secret-readers/ClusterRoleBinding/ctrl", "warn", "User bob", false},
		// kubeadm's binding for the admin kubeconfig is real but expected: kept, marked system.
		{"cluster-admin/ClusterRoleBinding/kubeadm:cluster-admins", "crit", "Group kubeadm:cluster-admins", true},
		// Only a controller's service account reads secrets: info, not a warning.
		{"secret-readers/ClusterRoleBinding/operator-secrets", "info", "ServiceAccount monitoring/operator", false},
	}
	for _, w := range want {
		f, ok := m[w.id]
		if !ok {
			t.Errorf("missing %s", w.id)
			continue
		}
		if f.Severity != w.severity || !strings.Contains(f.Detail, w.inDetail) || f.System != w.system || f.Category != "rbac" {
			t.Errorf("%s = %s system=%v %q, want %s system=%v containing %q", w.id, f.Severity, f.System, f.Detail, w.severity, w.system, w.inDetail)
		}
	}
	if f := m["cluster-admin/ClusterRoleBinding/erin-admin"]; strings.Contains(f.Detail, "kube-system") {
		t.Errorf("system subjects should not be listed: %q", f.Detail)
	}
	if len(fs) != len(want) {
		var ids []string
		for _, f := range fs {
			ids = append(ids, f.ID)
		}
		// Not expected: system:masters, the system: binding, the system-only
		// secret readers, secret-readers repeated for a cluster-admin binding,
		// the unbound wildcard role and the built-in or system: roles.
		t.Errorf("got %d findings, want %d: %v", len(fs), len(want), ids)
	}
}

func TestAuditSecurityNamespacesAndExposure(t *testing.T) {
	in := SecurityInput{
		Namespaces: []model.Namespace{
			{Name: "prod", Labels: map[string]string{"pod-security.kubernetes.io/enforce": "baseline", "pod-security.kubernetes.io/warn": "restricted"}},
			{Name: "data", Labels: map[string]string{"pod-security.kubernetes.io/enforce": "privileged"}},
			{Name: "staging"},
			{Name: "kube-system"},
			{Name: "ci", Labels: map[string]string{"pod-security.kubernetes.io/enforce": "restricted"}},
		},
		Services: []model.Service{
			{Namespace: "monitoring", Name: "grafana", Type: "NodePort", Ports: []model.ServicePort{{Port: 80, NodePort: 30300, Protocol: "TCP"}}},
			{Namespace: "prod", Name: "web", Type: "LoadBalancer", LoadBalancerIngress: []string{"lb.example.com"}, Ports: []model.ServicePort{{Port: 80, NodePort: 31000}}},
			{Namespace: "prod", Name: "pending-lb", Type: "LoadBalancer"},
			{Namespace: "prod", Name: "legacy", Type: "ClusterIP", ExternalIPs: []string{"203.0.113.10"}},
			{Namespace: "prod", Name: "internal", Type: "ClusterIP"},
		},
		Ingresses: []model.Ingress{
			{Namespace: "prod", Name: "shop", Rules: []model.IngressRule{{Host: "shop.example.com", Service: "web"}}, TLS: []model.IngressTLS{{Hosts: []string{"shop.example.com"}}}},
			{Namespace: "staging", Name: "search", Rules: []model.IngressRule{{Host: "search.example.com", Service: "s"}, {Host: "search.example.com", Path: "/x", Service: "s"}, {Service: "s"}}},
			{Namespace: "staging", Name: "default-only", DefaultBackend: "s"},
		},
	}
	fs, posture := AuditSecurity(in)
	m := findingsByID(fs)

	want := map[string]string{
		"psa-missing/Namespace/staging":         "No pod-security.kubernetes.io/enforce label",
		"psa-missing/Namespace/kube-system":     "No pod-security.kubernetes.io/enforce label",
		"psa-privileged/Namespace/data":         "privileged level",
		"nodeport/Service/monitoring/grafana":   "Opens port 30300/TCP on every node.",
		"loadbalancer/Service/prod/web":         "at lb.example.com.",
		"loadbalancer/Service/prod/pending-lb":  "no address is assigned yet",
		"external-ip/Service/prod/legacy":       "203.0.113.10",
		"ingress-no-tls/Ingress/staging/search": "Serves search.example.com, * over plain HTTP.",
	}
	for id, inDetail := range want {
		f, ok := m[id]
		if !ok {
			t.Errorf("missing %s", id)
			continue
		}
		if f.Severity != "warn" || !strings.Contains(f.Detail, inDetail) {
			t.Errorf("%s = %s %q, want warn containing %q", id, f.Severity, f.Detail, inDetail)
		}
	}
	if len(fs) != len(want) {
		t.Errorf("got %d findings, want %d: %+v", len(fs), len(want), fs)
	}
	if !m["psa-missing/Namespace/kube-system"].System || m["psa-missing/Namespace/staging"].System {
		t.Error("only system namespaces are marked system")
	}
	// Non-system findings sort before system ones of the same severity.
	if last := fs[len(fs)-1]; last.Subject != "kube-system" {
		t.Errorf("last finding = %s, want the kube-system one", last.ID)
	}

	var rows []string
	for _, p := range posture {
		rows = append(rows, p.Name+"="+p.Enforce+"/"+p.Status)
	}
	if got := strings.Join(rows, " "); got != "ci=restricted/ok data=privileged/warn kube-system=/warn prod=baseline/ok staging=/warn" {
		t.Errorf("posture = %s", got)
	}
	if posture[3].Warn != "restricted" || !posture[2].System {
		t.Errorf("posture details = %+v", posture)
	}
}

func TestAuditSecuritySortAndEmpty(t *testing.T) {
	fs, posture := AuditSecurity(SecurityInput{})
	if fs == nil || posture == nil {
		t.Fatal("want empty non-nil slices so JSON encodes as []")
	}

	fs, _ = AuditSecurity(SecurityInput{
		Namespaces: []model.Namespace{{Name: "kube-system"}, {Name: "app"}},
		Pods: []model.Pod{
			{Namespace: "app", Name: "p", AutomountToken: true, Specs: []model.ContainerSpec{{Name: "c", Privileged: true, RunAsNonRoot: true, AllowPrivilegeEscalation: bptr(false), MemoryLimitBytes: 1}}},
		},
	})
	var order []string
	for _, f := range fs {
		order = append(order, f.Severity+":"+f.Check)
	}
	if got := strings.Join(order, " "); got != "crit:privileged warn:psa-missing warn:psa-missing info:token-automount" {
		t.Errorf("order = %s", got)
	}
	if fs[1].Subject != "app" || fs[2].Subject != "kube-system" {
		t.Errorf("non-system first: %s, %s", fs[1].ID, fs[2].ID)
	}
}
