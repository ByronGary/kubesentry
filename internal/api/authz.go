package api

// Authorization helpers for handlers. The caller's identity comes from the
// request context (WithAuthentication); every lookup fails closed: no
// identity or no authorizer means no access.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"sort"
	"strconv"

	"github.com/ByronGary/kubesentry/internal/auth"
)

var (
	errNoIdentity   = errors.New("no authenticated identity in request context")
	errNoAuthorizer = errors.New("no authorizer configured")
)

// scopeOf returns where the caller holds c. Unrestricted identities hold
// everything without asking a.
func scopeOf(ctx context.Context, a auth.Authorizer, c auth.Capability) (auth.Scope, error) {
	id, ok := auth.FromContext(ctx)
	if !ok {
		return auth.Scope{}, errNoIdentity
	}
	if id.Unrestricted {
		return auth.Scope{All: true}, nil
	}
	if a == nil {
		return auth.Scope{}, errNoAuthorizer
	}
	return a.Scope(ctx, id, c)
}

// allowed reports whether the caller holds c in namespace ns ("" for
// cluster-wide). Errors deny.
func allowed(ctx context.Context, a auth.Authorizer, c auth.Capability, ns string) bool {
	ok, err := allowedErr(ctx, a, c, ns)
	if err != nil {
		slog.Warn("authorization check failed", "resource", c.Resource, "namespace", ns, "err", err)
	}
	return ok && err == nil
}

func allowedErr(ctx context.Context, a auth.Authorizer, c auth.Capability, ns string) (bool, error) {
	id, ok := auth.FromContext(ctx)
	if !ok {
		return false, errNoIdentity
	}
	if id.Unrestricted {
		return true, nil
	}
	if a == nil {
		return false, errNoAuthorizer
	}
	return a.Allowed(ctx, id, c, ns)
}

// filterByNamespace keeps the items whose namespace is in s. With s.All it
// returns items itself (do not modify it); otherwise a new, non-nil slice.
// Items without a namespace ("") are kept only with s.All.
func filterByNamespace[T any](items []T, ns func(T) string, s auth.Scope) []T {
	if s.All {
		return items
	}
	out := make([]T, 0, min(len(items), 64))
	for _, it := range items {
		if s.Namespaces[ns(it)] {
			out = append(out, it)
		}
	}
	return out
}

// ScopeKey returns a short key that is equal for two callers exactly when
// they hold the same scope for every capability in caps (ViewNamespace when
// none are given), for keying cached responses. Pass every capability the
// response depends on. All unrestricted callers share the key "all".
func ScopeKey(ctx context.Context, a auth.Authorizer, caps ...auth.Capability) (string, error) {
	id, ok := auth.FromContext(ctx)
	if !ok {
		return "", errNoIdentity
	}
	if id.Unrestricted {
		return "all", nil
	}
	if len(caps) == 0 {
		caps = []auth.Capability{auth.ViewNamespace}
	}
	h := sha256.New()
	var names []string
	for _, c := range caps {
		h.Write([]byte(c.Verb + "/" + c.Group + "/" + c.Resource + "="))
		if !c.Namespaced {
			ok, err := allowedErr(ctx, a, c, "")
			if err != nil {
				return "", err
			}
			h.Write([]byte(strconv.FormatBool(ok) + "\n"))
			continue
		}
		s, err := scopeOf(ctx, a, c)
		if err != nil {
			return "", err
		}
		if s.All {
			h.Write([]byte("*\n"))
			continue
		}
		names = names[:0]
		for ns, held := range s.Namespaces {
			if held {
				names = append(names, ns)
			}
		}
		sort.Strings(names)
		for _, ns := range names {
			h.Write([]byte(ns))
			h.Write([]byte{0})
		}
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil)[:16]), nil
}

// CacheKeyFunc builds a ResponseCache.KeyFunc that keys a request by its path
// and sorted query, the caller's ScopeKey over caps, and version() (the
// snapshot view version, so a new view never serves an old response).
// Requests without an identity, or whose scope cannot be determined, are not
// cached.
func CacheKeyFunc(a auth.Authorizer, version func() uint64, caps ...auth.Capability) func(*http.Request) (string, bool) {
	return func(r *http.Request) (string, bool) {
		sk, err := ScopeKey(r.Context(), a, caps...)
		if err != nil {
			return "", false
		}
		var v uint64
		if version != nil {
			v = version()
		}
		return r.URL.Path + "?" + r.URL.Query().Encode() + "\x00" + sk + "\x00" + strconv.FormatUint(v, 10), true
	}
}
