package detectors

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ByronGary/kubesentry/internal/model"
)

// The policy itself is defined in policy.go (a shared contract file); the
// helpers that apply it live here.

// compatPolicy backs the entry points that predate Policy: the default policy,
// with the deprecated SystemNamespaces variable as its namespace set, so code
// that still adjusts that variable keeps working.
func compatPolicy() Policy {
	p := DefaultPolicy()
	p.SystemNamespaces = SystemNamespaces
	return p
}

// Inventory sources the older list interfaces cannot provide. A source listed
// under one of these names in Inventory.Unavailable is treated as unknown
// rather than empty: Services then fall back to their selectors.
const (
	SourceEndpointSlices = "endpointslices"
	SourceReplicaSets    = "replicasets"
)

// WithDefaults fills the parts of p that were left at their zero value from
// DefaultPolicy, so a partly configured policy still judges sensibly. A
// completely zero policy becomes DefaultPolicy.
func (p Policy) WithDefaults() Policy {
	d := DefaultPolicy()
	zero := p.SystemNamespaces == nil && p.Thresholds == (Thresholds{}) && p.SystemPrincipalPrefixes == nil && p.BuiltinRBACPrefixes == nil
	if zero && p.SystemNamespaceLabel == "" {
		p.SystemNamespaceLabel = d.SystemNamespaceLabel
	}
	if p.SystemNamespaces == nil {
		p.SystemNamespaces = d.SystemNamespaces
	}
	if p.SystemPrincipalPrefixes == nil {
		p.SystemPrincipalPrefixes = d.SystemPrincipalPrefixes
	}
	if p.BuiltinRBACPrefixes == nil {
		p.BuiltinRBACPrefixes = d.BuiltinRBACPrefixes
	}
	if p.Thresholds == (Thresholds{}) {
		p.Thresholds = d.Thresholds
	}
	if p.Pricing.EBSPrices == nil {
		p.Pricing.EBSPrices = d.Pricing.EBSPrices
	}
	if p.Pricing.EBSProvisioners == nil {
		p.Pricing.EBSProvisioners = d.Pricing.EBSProvisioners
	}
	if p.Pricing.UsageBilled == nil {
		p.Pricing.UsageBilled = d.Pricing.UsageBilled
	}
	if p.Leak == (LeakOptions{}) {
		p.Leak = d.Leak
	}
	if p.OwnerAnnotation == "" {
		p.OwnerAnnotation = d.OwnerAnnotation
	}
	if p.ProductionLabel == (LabelMatch{}) {
		p.ProductionLabel = d.ProductionLabel
	}
	return p
}

// OwnerOf is the team that owns ns: its OwnerAnnotation, trimmed; "" when
// it has none.
func (p Policy) OwnerOf(ns model.Namespace) string {
	key := p.OwnerAnnotation
	if key == "" {
		key = DefaultOwnerAnnotation
	}
	return strings.TrimSpace(ns.Annotations[key])
}

// ObjectOwner is the team that owns an object: the owner it names itself
// (object: its owner annotation, which internal/kube keeps in the model's
// Owner field), else its namespace's (OwnerOf; ns is nil for a cluster-scoped
// object), else "" (the caller's default applies).
func (p Policy) ObjectOwner(object string, ns *model.Namespace) string {
	if o := strings.TrimSpace(object); o != "" {
		return o
	}
	if ns == nil {
		return ""
	}
	return p.OwnerOf(*ns)
}

// ObjectRef names one object: its kind (Deployment, Certificate,
// ClusterRoleBinding, ...), namespace ("" when cluster-scoped) and name.
type ObjectRef struct{ Kind, Namespace, Name string }

// ObjectOwners maps every object in inv that names its own owner (the
// owner annotation on Deployments, StatefulSets, DaemonSets, Jobs,
// CronJobs, Services, Ingresses, cert-manager Certificates, Roles,
// RoleBindings, ClusterRoles and ClusterRoleBindings) to that owner. Pods
// carry no annotations: a pod's owner is its workload's or namespace's.
func ObjectOwners(inv *model.Inventory) map[ObjectRef]string {
	out := map[ObjectRef]string{}
	add := func(kind, ns, name, owner string) {
		if o := strings.TrimSpace(owner); o != "" {
			out[ObjectRef{kind, ns, name}] = o
		}
	}
	for _, w := range inv.Workloads {
		add(w.Kind, w.Namespace, w.Name, w.Owner)
	}
	for _, s := range inv.Services {
		add("Service", s.Namespace, s.Name, s.Owner)
	}
	for _, in := range inv.Ingresses {
		add("Ingress", in.Namespace, in.Name, in.Owner)
	}
	for _, c := range inv.Certs.Certificates {
		add("Certificate", c.Namespace, c.Name, c.Owner)
	}
	for _, r := range inv.RBAC.Roles {
		add(r.Kind, r.Namespace, r.Name, r.Owner)
	}
	for _, b := range inv.RBAC.Bindings {
		add(b.Kind, b.Namespace, b.Name, b.Owner)
	}
	return out
}

// IsProduction reports whether ns carries the ProductionLabel.
func (p Policy) IsProduction(ns model.Namespace) bool {
	m := p.ProductionLabel
	if m == (LabelMatch{}) {
		m = DefaultProductionLabel
	}
	return m.Matches(ns.Labels)
}

// Matches reports whether labels hold Key with exactly Value.
func (m LabelMatch) Matches(labels map[string]string) bool {
	v, ok := labels[m.Key]
	return ok && m.Key != "" && v == m.Value
}

func (m LabelMatch) String() string { return m.Key + "=" + m.Value }

var (
	// A label or annotation key: an optional DNS subdomain prefix and a name
	// of up to 63 characters.
	labelKeyRE   = regexp.MustCompile(`^([a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?/)?[A-Za-z0-9]([-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?$`)
	labelValueRE = regexp.MustCompile(`^([A-Za-z0-9]([-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?)?$`)
)

// ValidLabelKey reports whether k is a valid label or annotation key.
func ValidLabelKey(k string) bool { return labelKeyRE.MatchString(k) }

// ParseLabelMatch reads "key=value": a valid label key and label value.
func ParseLabelMatch(s string) (LabelMatch, error) {
	k, v, ok := strings.Cut(strings.TrimSpace(s), "=")
	if !ok || !ValidLabelKey(k) || !labelValueRE.MatchString(v) {
		return LabelMatch{}, fmt.Errorf("%q: want key=value with a valid label key and value", s)
	}
	return LabelMatch{Key: k, Value: v}, nil
}

// SystemNamespaceSet resolves which namespaces are cluster plumbing: the
// policy's SystemNamespaces, adjusted by each namespace's
// SystemNamespaceLabel ("true" adds it, "false" removes it).
func SystemNamespaceSet(p Policy, nss []model.Namespace) map[string]bool {
	out := make(map[string]bool, len(p.SystemNamespaces)+4)
	for ns, v := range p.SystemNamespaces {
		if v {
			out[ns] = true
		}
	}
	if p.SystemNamespaceLabel == "" {
		return out
	}
	for _, ns := range nss {
		switch strings.ToLower(strings.TrimSpace(ns.Labels[p.SystemNamespaceLabel])) {
		case "true":
			out[ns.Name] = true
		case "false":
			delete(out, ns.Name)
		}
	}
	return out
}

// everyone lists the groups that stand for all callers or all service
// accounts. They are never plumbing, whatever the prefixes say.
var everyone = map[string]bool{
	"system:anonymous":       true,
	"system:unauthenticated": true,
	"system:authenticated":   true,
	"system:serviceaccounts": true,
}

// IsSystemPrincipal reports whether a user or group name belongs to a
// Kubernetes or cloud component (system:..., eks:...) rather than a person.
// The groups that stand for everyone are never system. Service account names
// are not judged here; their namespace decides (see systemSubject).
func (p Policy) IsSystemPrincipal(name string) bool {
	if everyone[name] {
		return false
	}
	return hasAnyPrefix(name, p.SystemPrincipalPrefixes)
}

// IsBuiltinRBAC reports whether a Role, ClusterRole or binding name is one the
// platform creates (system:..., eks:..., kubeadm:...).
func (p Policy) IsBuiltinRBAC(name string) bool { return hasAnyPrefix(name, p.BuiltinRBACPrefixes) }

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, pre := range prefixes {
		if pre != "" && strings.HasPrefix(s, pre) {
			return true
		}
	}
	return false
}

// unavailable reports whether the inventory marks a source as unreadable. Keys
// are matched loosely (case and an API group suffix are ignored), so
// "endpointslices", "EndpointSlices" and "endpointslices.discovery.k8s.io" all
// count.
func unavailable(m map[string]string, source string) bool {
	for k := range m {
		k = strings.ToLower(k)
		if k == source || strings.HasPrefix(k, source+".") {
			return true
		}
	}
	return false
}
