// Package auth decides who is calling kubesentry and what they may see.
//
// Authentication: in proxy mode an SSO proxy (oauth2-proxy) in front of
// kubesentry signs users in and passes their identity in headers, which are
// trusted only from the proxy's address. Token mode keeps the shared API token
// as a break-glass identity with cluster-wide scope.
//
// Authorization: kubesentry never decides access itself. It asks the
// Kubernetes API server with SubjectAccessReviews, so a user sees exactly what
// their RBAC (and, on EKS, access entries mapped to Kubernetes groups) allows
// them to list with kubectl. Results are cached per identity.
//
// This package is stdlib-only; the SubjectAccessReview client lives in
// internal/kube and satisfies Reviewer.
package auth

import (
	"context"
	"net/http"
)

// Identity is an authenticated caller.
type Identity struct {
	User   string   // as Kubernetes RBAC knows it, after any prefix is applied
	Groups []string // likewise; always includes system:authenticated
	// Source is how the caller was authenticated: "proxy", "token" or "none".
	Source string
	// Unrestricted skips authorization (the break-glass API token and -auth-mode=none).
	Unrestricted bool
}

// Key identifies the identity in caches.
func (id Identity) Key() string {
	k := id.Source + "|" + id.User
	for _, g := range id.Groups {
		k += "|" + g
	}
	return k
}

// Capability is one thing a page needs: a verb on a resource. Namespaced
// capabilities are checked per namespace, others cluster-wide.
type Capability struct {
	Verb       string
	Group      string // API group; "" for core
	Resource   string
	Namespaced bool
}

// The capabilities kubesentry checks. The kubesentry.io resources are virtual:
// no such API exists, but RBAC can grant them and SubjectAccessReviews
// evaluate them. The Helm chart ships ClusterRoles for them.
var (
	ViewNamespace     = Capability{Verb: "list", Resource: "pods", Namespaced: true}
	ViewProcesses     = Capability{Verb: "get", Group: "kubesentry.io", Resource: "processes", Namespaced: true}
	ViewAudit         = Capability{Verb: "list", Group: "kubesentry.io", Resource: "auditevents", Namespaced: true}
	ViewClusterAudit  = Capability{Verb: "list", Group: "kubesentry.io", Resource: "auditevents"}
	ViewNodes         = Capability{Verb: "list", Resource: "nodes"}
	ViewPVs           = Capability{Verb: "list", Resource: "persistentvolumes"}
	ViewStorageClass  = Capability{Verb: "list", Group: "storage.k8s.io", Resource: "storageclasses"}
	ViewClusterRBAC   = Capability{Verb: "list", Group: "rbac.authorization.k8s.io", Resource: "clusterrolebindings"}
	ViewRBAC          = Capability{Verb: "list", Group: "rbac.authorization.k8s.io", Resource: "rolebindings", Namespaced: true}
	ViewClusterIssuer = Capability{Verb: "list", Group: "cert-manager.io", Resource: "clusterissuers"}
	ViewAgents        = Capability{Verb: "list", Group: "kubesentry.io", Resource: "agents"}
)

// Scope is the set of namespaces a capability is granted in.
type Scope struct {
	All        bool            // granted cluster-wide
	Namespaces map[string]bool // when !All
}

// Has reports whether the scope includes namespace ns.
func (s Scope) Has(ns string) bool { return s.All || s.Namespaces[ns] }

// Authenticator turns a request into an Identity. ok is false when the request
// carries no acceptable identity; the handler then answers 401.
type Authenticator interface {
	Authenticate(r *http.Request) (id Identity, ok bool)
}

// Authorizer answers what an identity may see. Implementations cache.
type Authorizer interface {
	// Scope returns where the identity holds the capability. For a cluster-wide
	// capability the result is either All or empty.
	Scope(ctx context.Context, id Identity, c Capability) (Scope, error)
	// Allowed checks one namespace ("" for cluster-wide).
	Allowed(ctx context.Context, id Identity, c Capability, namespace string) (bool, error)
}

// Reviewer performs one SubjectAccessReview. internal/kube implements it;
// verb, group, resource and namespace are as in authorization.k8s.io/v1
// ResourceAttributes ("" namespace means cluster-wide).
type Reviewer interface {
	Review(ctx context.Context, user string, groups []string, verb, group, resource, namespace string) (bool, error)
}

// Candidates proposes the namespaces worth checking for an identity, from an
// in-memory index of the cluster's RoleBindings (detectors.RBACIndex). Every
// candidate is still confirmed with a SubjectAccessReview; the index only
// keeps the number of reviews proportional to what a user actually holds.
type Candidates interface {
	Namespaces(user string, groups []string, c Capability) []string
}

type ctxKey struct{}

// WithIdentity stores the caller's identity in a context.
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// FromContext returns the identity stored by WithIdentity.
func FromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(ctxKey{}).(Identity)
	return id, ok
}
