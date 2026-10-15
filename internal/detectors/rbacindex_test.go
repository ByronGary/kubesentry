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
		{"alice", nil, auth.ViewPodLogs, "public,shared"},       // view grants pods/log
		{"bob", []string{"team-a"}, auth.ViewPodLogs, "public"}, // the team-a Role lists pods, not their logs
		{"carol", []string{"ops"}, auth.ViewPodLogs, "ops,public"},
	}
	for _, c := range cases {
		if got := strings.Join(x.Namespaces(c.user, c.groups, c.cap), ","); got != c.want {
			t.Errorf("%s %v %s: %q, want %q", c.user, c.groups, c.cap.Resource, got, c.want)
		}
	}

	// Personal bindings, for -authz-share-by-groups: any binding naming the
	// user counts, whatever it grants.
	for user, want := range map[string]bool{"alice": true, "system:serviceaccount:ci:bot": true, "bob": false, "team-a": false, "": false} {
		if got := x.HasUserBindings(user); got != want {
			t.Errorf("HasUserBindings(%q) = %v, want %v", user, got, want)
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

// Subresources match as Kubernetes' RBAC authorizer matches them: "pods"
// does not grant pods/log, "pods/log", "*/log" and "*" do.
func TestRBACIndexSubresources(t *testing.T) {
	clusterRole := func(name string, verbs, resources []string) model.Role {
		return model.Role{Kind: "ClusterRole", Name: name, Rules: []model.PolicyRule{{Verbs: verbs, APIGroups: []string{""}, Resources: resources}}}
	}
	bind := func(ns, role string) model.RoleBinding {
		return model.RoleBinding{Kind: "RoleBinding", Namespace: ns, Name: role, RoleKind: "ClusterRole", RoleName: role,
			Subjects: []model.Subject{{Kind: "Group", Name: "devs"}}}
	}
	r := model.RBAC{
		Roles: []model.Role{
			clusterRole("pods-get", []string{"get", "list"}, []string{"pods"}),
			clusterRole("pod-logs", []string{"get"}, []string{"pods/log"}),
			clusterRole("any-log", []string{"get"}, []string{"*/log"}),
			clusterRole("any-status", []string{"get"}, []string{"*/status"}),
			clusterRole("logs-list-only", []string{"list"}, []string{"pods/log"}),
			clusterRole("svc-logs", []string{"get"}, []string{"services/log"}),
			{Kind: "ClusterRole", Name: "all", Rules: []model.PolicyRule{{Verbs: []string{"*"}, APIGroups: []string{"*"}, Resources: []string{"*"}}}},
			{Kind: "ClusterRole", Name: "named-logs", Rules: []model.PolicyRule{{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods/log"}, ResourceNames: []string{"web-0"}}}},
		},
		Bindings: []model.RoleBinding{
			bind("a", "pods-get"), bind("b", "pod-logs"), bind("c", "any-log"), bind("d", "any-status"),
			bind("e", "logs-list-only"), bind("f", "svc-logs"), bind("g", "all"), bind("h", "named-logs"),
		},
	}
	x := NewRBACIndex(r, DefaultPolicy())
	getPods := auth.Capability{Verb: "get", Resource: "pods", Namespaced: true}
	for _, c := range []struct {
		cap  auth.Capability
		want string
	}{
		{auth.ViewPodLogs, "b,c,g"},
		{getPods, "a,g"},
		{auth.ViewNamespace, "a,g"},
		{auth.Capability{Verb: "get", Resource: "pods", Subresource: "status", Namespaced: true}, "d,g"},
	} {
		if got := strings.Join(x.Namespaces("dana", []string{"devs"}, c.cap), ","); got != c.want {
			t.Errorf("%s %s/%s: %q, want %q", c.cap.Verb, c.cap.Resource, c.cap.Subresource, got, c.want)
		}
	}

	for _, c := range []struct {
		rules    []string
		res, sub string
		want     bool
	}{
		{[]string{"pods"}, "pods", "", true},
		{[]string{"pods"}, "pods", "log", false},
		{[]string{"pods/log"}, "pods", "log", true},
		{[]string{"pods/log"}, "pods", "", false},
		{[]string{"*/log"}, "pods", "log", true},
		{[]string{"*/log"}, "pods", "", false},
		{[]string{"*/log"}, "pods", "exec", false},
		{[]string{"*"}, "pods", "log", true},
		{[]string{"*"}, "pods", "", true},
		{[]string{"services/log"}, "pods", "log", false},
		{[]string{"pods/*"}, "pods", "log", false}, // not a wildcard in RBAC
		{nil, "pods", "", false},
	} {
		if got := resourceMatches(c.rules, c.res, c.sub); got != c.want {
			t.Errorf("resourceMatches(%v, %q, %q) = %v, want %v", c.rules, c.res, c.sub, got, c.want)
		}
	}
}
