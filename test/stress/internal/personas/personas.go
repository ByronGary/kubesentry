// Package personas defines the virtual users of the after run and the RBAC
// that gives each its access: 5% admins (cluster-admin), 15% cluster viewers
// (the built-in view ClusterRole bound cluster-wide, plus kubesentry's audit,
// process and agents viewer roles), 80% team members (view in 1–5 namespaces
// of their team, some with kubesentry's process and audit viewer roles there),
// a user in 300 groups and a user with no grants at all.
package personas

import (
	"fmt"
	"sort"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/ByronGary/kubesentry/test/stress/internal/plan"
)

// Kinds of persona.
const (
	Admin      = "admin"
	Viewer     = "viewer"
	Team       = "team"
	ManyGroups = "many-groups"
	NoGrants   = "no-grants"
)

// Groups bound by the persona RBAC.
const (
	GroupAdmins  = "stress:admins"
	GroupViewers = "stress:viewers"
)

// NamespaceGroup is the group that gets view in one team namespace.
func NamespaceGroup(ns string) string { return "stress:ns:" + ns }

// Persona is one virtual user.
type Persona struct {
	Kind   string   `json:"kind"`
	Email  string   `json:"email"`
	Groups []string `json:"groups"`
	// Namespaces are the team namespaces granted through groups (team personas).
	Namespaces []string `json:"namespaces,omitempty"`
}

// ReleaseRoles are the kubesentry chart's virtual-resource ClusterRoles for
// release name "kubesentry".
var ReleaseRoles = struct{ Audit, Processes, Agents string }{"kubesentry-audit-viewer", "kubesentry-process-viewer", "kubesentry-agents-viewer"}

// Build returns n personas in the 5/15/80 mix, then the two edge cases.
// teamNamespaces is the number of team namespaces of the level.
func Build(teamNamespaces, n int) []Persona {
	byTeam := map[int][]string{}
	for j := 0; j < teamNamespaces; j++ {
		t := j % len(plan.Teams)
		byTeam[t] = append(byTeam[t], plan.NamespaceName(j))
	}
	out := make([]Persona, 0, n+2)
	for i := 0; i < n; i++ {
		switch r := i % 100; {
		case r < 5:
			out = append(out, Persona{Kind: Admin, Email: fmt.Sprintf("admin%d@corp.example", i), Groups: []string{GroupAdmins}})
		case r < 20:
			out = append(out, Persona{Kind: Viewer, Email: fmt.Sprintf("viewer%d@corp.example", i), Groups: []string{GroupViewers}})
		default:
			t := i % len(plan.Teams)
			nss := byTeam[t]
			if len(nss) == 0 {
				nss = []string{plan.NamespaceName(0)}
			}
			k := 1 + (i/len(plan.Teams))%5
			if k > len(nss) {
				k = len(nss)
			}
			start := (i / 7) % len(nss)
			p := Persona{Kind: Team, Email: fmt.Sprintf("%s.dev%d@corp.example", plan.Teams[t], i)}
			for x := 0; x < k; x++ {
				ns := nss[(start+x)%len(nss)]
				p.Namespaces = append(p.Namespaces, ns)
				p.Groups = append(p.Groups, NamespaceGroup(ns))
			}
			sort.Strings(p.Namespaces)
			out = append(out, p)
		}
	}
	mg := Persona{Kind: ManyGroups, Email: "many.groups@corp.example", Namespaces: []string{plan.NamespaceName(0)}}
	for g := 0; g < 299; g++ {
		mg.Groups = append(mg.Groups, fmt.Sprintf("idp:directory-group-%03d", g))
	}
	mg.Groups = append(mg.Groups, NamespaceGroup(plan.NamespaceName(0)))
	out = append(out, mg, Persona{Kind: NoGrants, Email: "nobody@corp.example"})
	return out
}

func labels() map[string]string {
	return map[string]string{"kubesentry.io/stress": "true", "kubesentry.io/stress-personas": "true"}
}

func group(name string) rbacv1.Subject {
	return rbacv1.Subject{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: name}
}

// RBAC returns the bindings the personas need.
func RBAC(teamNamespaces int) []runtime.Object {
	var out []runtime.Object
	crb := func(name, role string, subj rbacv1.Subject) {
		out = append(out, &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels()},
			RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: role},
			Subjects:   []rbacv1.Subject{subj},
		})
	}
	crb("stress-persona-admins", "cluster-admin", group(GroupAdmins))
	crb("stress-persona-viewers", "view", group(GroupViewers))
	crb("stress-persona-viewers-audit", ReleaseRoles.Audit, group(GroupViewers))
	crb("stress-persona-viewers-processes", ReleaseRoles.Processes, group(GroupViewers))
	crb("stress-persona-viewers-agents", ReleaseRoles.Agents, group(GroupViewers))
	for j := 0; j < teamNamespaces; j++ {
		ns := plan.NamespaceName(j)
		rb := func(name, role string) {
			out = append(out, &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: labels()},
				RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: role},
				Subjects:   []rbacv1.Subject{group(NamespaceGroup(ns))},
			})
		}
		rb("stress-persona-view", "view")
		if j%2 == 0 {
			rb("stress-persona-processes", ReleaseRoles.Processes)
			rb("stress-persona-audit", ReleaseRoles.Audit)
		}
	}
	return out
}
