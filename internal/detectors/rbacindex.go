package detectors

import (
	"slices"
	"sort"
	"sync"

	"github.com/ByronGary/kubesentry/internal/auth"
	"github.com/ByronGary/kubesentry/internal/model"
)

// RBACIndex proposes where an identity may hold a capability, from the
// cluster's roles and bindings. It implements auth.Candidates: it only narrows
// the namespaces worth confirming with a SubjectAccessReview, so it errs
// towards proposing (wildcards count) and never decides access itself.
//
// Only rules that grant on whole resources count: a rule restricted by
// resourceNames does not let anyone list, and nonResourceURLs are ignored.
// Subresources match as the API server's RBAC authorizer matches them.
// Aggregated ClusterRoles are read as the API server stores them, with the
// aggregated rules filled in.
type RBACIndex struct {
	rules   map[string][]model.PolicyRule // role key → resource rules without resourceNames
	ns      map[string][]nsGrant          // subject key → namespaced grants
	cluster map[string][]string           // subject key → ClusterRoles bound cluster-wide
	memo    sync.Map                      // grantKey → bool
}

type nsGrant struct{ ns, role string }

type grantKey struct {
	role string
	cap  auth.Capability
}

// NewRBACIndex indexes r in time linear in its bindings and rules. The policy
// is accepted for symmetry with the other builders; access is never judged by
// it.
func NewRBACIndex(r model.RBAC, _ Policy) *RBACIndex {
	x := &RBACIndex{
		rules:   make(map[string][]model.PolicyRule, len(r.Roles)),
		ns:      map[string][]nsGrant{},
		cluster: map[string][]string{},
	}
	for _, ro := range r.Roles {
		var keep []model.PolicyRule
		for _, rule := range ro.Rules {
			if len(rule.ResourceNames) == 0 && len(rule.Resources) > 0 {
				keep = append(keep, rule)
			}
		}
		x.rules[roleKey(ro.Kind, ro.Namespace, ro.Name)] = keep
	}
	for _, b := range r.Bindings {
		role := roleKey("ClusterRole", "", b.RoleName)
		if b.RoleKind == "Role" {
			if b.Kind != "RoleBinding" {
				continue // a ClusterRoleBinding cannot reference a Role
			}
			role = roleKey("Role", b.Namespace, b.RoleName)
		}
		for _, s := range b.Subjects {
			key := subjectKey(s)
			if key == "" {
				continue
			}
			if b.Kind == "ClusterRoleBinding" {
				x.cluster[key] = append(x.cluster[key], role)
			} else {
				x.ns[key] = append(x.ns[key], nsGrant{ns: b.Namespace, role: role})
			}
		}
	}
	return x
}

// subjectKey names a binding subject as the authorizer sees it: service
// accounts are users named system:serviceaccount:<namespace>:<name>.
func subjectKey(s model.Subject) string {
	switch s.Kind {
	case "User":
		return "u:" + s.Name
	case "Group":
		return "g:" + s.Name
	case "ServiceAccount":
		return "u:system:serviceaccount:" + s.Namespace + ":" + s.Name
	}
	return ""
}

func identityKeys(user string, groups []string) []string {
	keys := make([]string, 0, len(groups)+2)
	if user != "" {
		keys = append(keys, "u:"+user)
	}
	for _, g := range groups {
		keys = append(keys, "g:"+g)
	}
	if !slices.Contains(groups, "system:authenticated") {
		keys = append(keys, "g:system:authenticated")
	}
	return keys
}

// Namespaces returns, sorted, the namespaces where a RoleBinding to the user
// or one of the groups (system:authenticated is always included) grants the
// capability through its Role or ClusterRole.
func (x *RBACIndex) Namespaces(user string, groups []string, c auth.Capability) []string {
	seen := map[string]bool{}
	var out []string
	for _, k := range identityKeys(user, groups) {
		for _, g := range x.ns[k] {
			if seen[g.ns] || !x.grants(g.role, c) {
				continue
			}
			seen[g.ns] = true
			out = append(out, g.ns)
		}
	}
	sort.Strings(out)
	return out
}

// ClusterWide reports whether a ClusterRoleBinding grants the capability to
// the user or one of the groups. Members of system:masters bypass RBAC, so
// they always hold it.
func (x *RBACIndex) ClusterWide(user string, groups []string, c auth.Capability) bool {
	if slices.Contains(groups, "system:masters") {
		return true
	}
	for _, k := range identityKeys(user, groups) {
		for _, role := range x.cluster[k] {
			if x.grants(role, c) {
				return true
			}
		}
	}
	return false
}

// HasUserBindings reports whether any RoleBinding or ClusterRoleBinding names
// the user (service accounts included, as system:serviceaccount:ns:name) as a
// subject. With -authz-share-by-groups such a user's access decisions are
// cached per user, never shared with everyone in the same groups.
func (x *RBACIndex) HasUserBindings(user string) bool {
	if user == "" {
		return false
	}
	k := "u:" + user
	return len(x.ns[k]) > 0 || len(x.cluster[k]) > 0
}

var (
	_ auth.Candidates   = (*RBACIndex)(nil)
	_ auth.UserBindings = (*RBACIndex)(nil)
)

// grants reports whether a role allows the capability, memoised per role.
func (x *RBACIndex) grants(role string, c auth.Capability) bool {
	k := grantKey{role, c}
	if v, ok := x.memo.Load(k); ok {
		return v.(bool)
	}
	ok := false
	for _, r := range x.rules[role] {
		if ruleAllows(r, c) {
			ok = true
			break
		}
	}
	x.memo.Store(k, ok)
	return ok
}

func ruleAllows(r model.PolicyRule, c auth.Capability) bool {
	return matchesOrStar(r.Verbs, c.Verb) && matchesOrStar(r.APIGroups, c.Group) && resourceMatches(r.Resources, c.Resource, c.Subresource)
}

// resourceMatches is Kubernetes' RBAC ResourceMatches: "*" matches
// everything, "pods" only the pods themselves, "pods/log" only their logs,
// and "*/log" the log subresource of any resource.
func resourceMatches(rules []string, resource, subresource string) bool {
	combined := resource
	if subresource != "" {
		combined += "/" + subresource
	}
	for _, r := range rules {
		if r == "*" || r == combined {
			return true
		}
		if subresource != "" && r == "*/"+subresource {
			return true
		}
	}
	return false
}

func matchesOrStar(list []string, v string) bool {
	for _, s := range list {
		if s == "*" || s == v {
			return true
		}
	}
	return false
}
