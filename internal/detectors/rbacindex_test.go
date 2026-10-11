package detectors

import (
	"strings"
	"testing"

	"github.com/ByronGary/kubesentry/internal/auth"
	"github.com/ByronGary/kubesentry/internal/model"
)

func TestRBACIndex(t *testing.T) {
	podsList := model.PolicyRule{Verbs: []string{"get", "list", "watch"}, APIGroups: []string{""}, Resources: []string{"pods", "pods/log"}}
	r := model.RBAC{
		Roles: []model.Role{
			{Kind: "ClusterRole", Name: "view", Rules: []model.PolicyRule{podsList}},
			{Kind: "ClusterRole", Name: "everything", Rules: []model.PolicyRule{{Verbs: []string{"*"}, APIGroups: []string{"*"}, Resources: []string{"*"}}}},
			{Kind: "ClusterRole", Name: "one-pod", Rules: []model.PolicyRule{{Verbs: []string{"list"}, APIGroups: []string{""}, Resources: []string{"pods"}, ResourceNames: []string{"x"}}}},
			{Kind: "ClusterRole", Name: "urls", Rules: []model.PolicyRule{{Verbs: []string{"get"}, NonResourceURLs: []string{"/metrics"}}}},
			{Kind: "ClusterRole", Name: "procs", Rules: []model.PolicyRule{{Verbs: []string{"get"}, APIGroups: []string{"kubesentry.io"}, Resources: []string{"processes"}}}},
			{Kind: "Role", Namespace: "team-a", Name: "lister", Rules: []model.PolicyRule{{Verbs: []string{"list"}, APIGroups: []string{"*"}, Resources: []string{"pods"}}}},
			{Kind: "Role", Namespace: "team-b", Name: "lister", Rules: []model.PolicyRule{{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}}}},
		},
		Bindings: []model.RoleBinding{
			{Kind: "RoleBinding", Namespace: "team-a", Name: "a", RoleKind: "Role", RoleName: "lister", Subjects: []model.Subject{{Kind: "Group", Name: "team-a"}}},
			{Kind: "RoleBinding", Namespace: "team-b", Name: "b", RoleKind: "Role", RoleName: "lister", Subjects: []model.Subject{{Kind: "Group", Name: "team-a"}}}, // get only
			{Kind: "RoleBinding", Namespace: "shared", Name: "v", RoleKind: "ClusterRole", RoleName: "view", Subjects: []model.Subject{{Kind: "User", Name: "alice"}}},
			{Kind: "RoleBinding", Namespace: "ops", Name: "all", RoleKind: "ClusterRole", RoleName: "everything", Subjects: []model.Subject{{Kind: "Group", Name: "ops"}}},
			{Kind: "RoleBinding", Namespace: "x", Name: "named", RoleKind: "ClusterRole", RoleName: "one-pod", Subjects: []model.Subject{{Kind: "User", Name: "alice"}}},
			{Kind: "RoleBinding", Namespace: "y", Name: "urls", RoleKind: "ClusterRole", RoleName: "urls", Subjects: []model.Subject{{Kind: "User", Name: "alice"}}},
			{Kind: "RoleBinding", Namespace: "public", Name: "pub", RoleKind: "ClusterRole", RoleName: "view", Subjects: []model.Subject{{Kind: "Group", Name: "system:authenticated"}}},
			{Kind: "RoleBinding", Namespace: "ci", Name: "sa", RoleKind: "ClusterRole", RoleName: "view", Subjects: []model.Subject{{Kind: "ServiceAccount", Namespace: "ci", Name: "bot"}}},
			{Kind: "RoleBinding", Namespace: "team-a", Name: "p", RoleKind: "ClusterRole", RoleName: "procs", Subjects: []model.Subject{{Kind: "Group", Name: "team-a"}}},
			{Kind: "ClusterRoleBinding", Name: "auditors", RoleKind: "ClusterRole", RoleName: "view", Subjects: []model.Subject{{Kind: "Group", Name: "auditors"}}},
			{Kind: "ClusterRoleBinding", Name: "bad", RoleKind: "Role", RoleName: "lister", Subjects: []model.Subject{{Kind: "Group", Name: "team-a"}}},
		},
	}
	x := NewRBACIndex(r, DefaultPolicy())
	var _ auth.Candidates = x

	cases := []struct {
		user   string
		groups []string
		cap    auth.Capability
		want   string
	}{
		{"bob", []string{"team-a"}, auth.ViewNamespace, "public,team-a"},
		{"alice", nil, auth.ViewNamespace, "public,shared"}, // resourceNames and nonResourceURLs do not count
		{"carol", []string{"ops"}, auth.ViewNamespace, "ops,public"},
		{"carol", []string{"ops"}, auth.ViewProcesses, "ops"},
		{"bob", []string{"team-a"}, auth.ViewProcesses, "team-a"},
		{"system:serviceaccount:ci:bot", nil, auth.ViewNamespace, "ci,public"},
		{"nobody", nil, auth.ViewNamespace, "public"},
		{"nobody", nil, auth.ViewAudit, ""},
	}
	for _, c := range cases {
		if got := strings.Join(x.Namespaces(c.user, c.groups, c.cap), ","); got != c.want {
			t.Errorf("%s %v %s: %q, want %q", c.user, c.groups, c.cap.Resource, got, c.want)
		}
	}

	if !x.ClusterWide("dave", []string{"auditors"}, auth.ViewNamespace) || x.ClusterWide("dave", []string{"auditors"}, auth.ViewNodes) {
		t.Error("auditors list pods cluster-wide, not nodes")
	}
	if x.ClusterWide("bob", []string{"team-a"}, auth.ViewNamespace) {
		t.Error("a ClusterRoleBinding to a Role grants nothing")
	}
	if !x.ClusterWide("root", []string{"system:masters"}, auth.ViewNodes) {
		t.Error("system:masters bypasses RBAC")
	}
}
