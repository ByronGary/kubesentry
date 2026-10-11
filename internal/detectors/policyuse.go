package detectors

import (
	"strings"

	"github.com/ByronGary/kubesentry/internal/model"
)

// The policy itself is defined in policy.go (a shared contract file); the
// helpers that apply it live here.

func init() {
	// SystemNamespaces (inventory.go) is deprecated: it now starts as the
	// default policy's set, so code that still reads it agrees with Policy.
	SystemNamespaces = DefaultPolicy().SystemNamespaces
}

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
	return p
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
