package personas

import (
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
)

func TestMixAndEdgeCases(t *testing.T) {
	ps := Build(156, 100)
	if len(ps) != 102 {
		t.Fatalf("%d personas", len(ps))
	}
	kinds := map[string]int{}
	for _, p := range ps {
		kinds[p.Kind]++
		if p.Kind == Team {
			if len(p.Namespaces) < 1 || len(p.Namespaces) > 5 || len(p.Groups) != len(p.Namespaces) {
				t.Errorf("%s: %d namespaces, %d groups", p.Email, len(p.Namespaces), len(p.Groups))
			}
			team := strings.SplitN(p.Email, ".", 2)[0]
			for _, ns := range p.Namespaces {
				if !strings.HasPrefix(ns, team+"-") {
					t.Errorf("%s has %s outside its team", p.Email, ns)
				}
			}
		}
	}
	if kinds[Admin] != 5 || kinds[Viewer] != 15 || kinds[Team] != 80 || kinds[ManyGroups] != 1 || kinds[NoGrants] != 1 {
		t.Errorf("mix %v", kinds)
	}
	last := ps[len(ps)-2]
	if len(last.Groups) != 300 {
		t.Errorf("many-groups user has %d groups", len(last.Groups))
	}
	if len(ps[len(ps)-1].Groups) != 0 {
		t.Error("the no-grants user must have no groups")
	}
}

func TestRBACBindsEveryGroupThePersonasUse(t *testing.T) {
	objs := RBAC(156)
	bound := map[string]bool{}
	for _, o := range objs {
		switch b := o.(type) {
		case *rbacv1.ClusterRoleBinding:
			for _, s := range b.Subjects {
				bound[s.Name] = true
			}
		case *rbacv1.RoleBinding:
			for _, s := range b.Subjects {
				bound[s.Name] = true
			}
		}
	}
	for _, p := range Build(156, 100) {
		if p.Kind == ManyGroups || p.Kind == NoGrants {
			continue
		}
		for _, g := range p.Groups {
			if !bound[g] {
				t.Errorf("%s: group %s is bound nowhere", p.Email, g)
			}
		}
	}
}
