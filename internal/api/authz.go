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
	"sync"

	"github.com/ByronGary/kubesentry/internal/auth"
)

var (
	errNoIdentity   = errors.New("no authenticated identity in request context")
	errNoAuthorizer = errors.New("no authorizer configured")
)

// authzMemo is one request's authorization answers. Every lookup of a
// request goes through it, so the response cache's key and the handler's
// filter see the same scope even when the authorizer's own cache changes
// in between (an entry expires, a recheck forgets it, a grant lands). It
// also records whether any lookup failed: such a response is degraded
// (fail closed) and must not be cached.
type authzMemo struct {
	mu      sync.Mutex
	scopes  map[auth.Capability]scopeAnswer
	allowed map[allowedKey]allowedAnswer
	failed  bool
}

type scopeAnswer struct {
	s   auth.Scope
	err error
}

type allowedKey struct {
	c  auth.Capability
	ns string
}

type allowedAnswer struct {
	ok  bool
	err error
}

type authzMemoKey struct{}

// withAuthzMemo gives each request its own authzMemo. It goes inside
// WithAuthentication and outside the routes (and so the response cache).
func withAuthzMemo(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if authzMemoFrom(r.Context()) == nil {
			r = r.WithContext(context.WithValue(r.Context(), authzMemoKey{}, &authzMemo{}))
		}
		next.ServeHTTP(w, r)
	})
}

func authzMemoFrom(ctx context.Context) *authzMemo {
	m, _ := ctx.Value(authzMemoKey{}).(*authzMemo)
	return m
}

// authzFailed reports whether an authorization lookup of this request
// failed, so its response reflects a denial that may not be real.
func authzFailed(ctx context.Context) bool {
	m := authzMemoFrom(ctx)
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.failed
}

// scopeOf returns where the caller holds c. Unrestricted identities hold
// everything without asking a. Within one request the first answer for c
// is the answer.
func scopeOf(ctx context.Context, a auth.Authorizer, c auth.Capability) (auth.Scope, error) {
	id, ok := auth.FromContext(ctx)
	if !ok {
		return auth.Scope{}, errNoIdentity
	}
	if id.Unrestricted {
		return auth.Scope{All: true}, nil
	}
	m := authzMemoFrom(ctx)
	if m != nil {
		m.mu.Lock()
		ans, hit := m.scopes[c]
		m.mu.Unlock()
		if hit {
			return ans.s, ans.err
		}
	}
	var ans scopeAnswer
	if a == nil {
		ans.err = errNoAuthorizer
	} else {
		ans.s, ans.err = a.Scope(ctx, id, c)
	}
	if m == nil {
		return ans.s, ans.err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if prev, hit := m.scopes[c]; hit { // a concurrent lookup answered first
		return prev.s, prev.err
	}
	if m.scopes == nil {
		m.scopes = map[auth.Capability]scopeAnswer{}
	}
	m.scopes[c] = ans
	m.failed = m.failed || ans.err != nil
	return ans.s, ans.err
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
	if !c.Namespaced {
		ns = ""
	}
	key := allowedKey{c, ns}
	m := authzMemoFrom(ctx)
	if m != nil {
		m.mu.Lock()
		ans, hit := m.allowed[key]
		m.mu.Unlock()
		if hit {
			return ans.ok, ans.err
		}
	}
	var ans allowedAnswer
	if a == nil {
		ans.err = errNoAuthorizer
	} else {
		ans.ok, ans.err = a.Allowed(ctx, id, c, ns)
	}
	if m == nil {
		return ans.ok, ans.err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if prev, hit := m.allowed[key]; hit {
		return prev.ok, prev.err
	}
	if m.allowed == nil {
		m.allowed = map[allowedKey]allowedAnswer{}
	}
	m.allowed[key] = ans
	m.failed = m.failed || ans.err != nil
	return ans.ok, ans.err
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
		h.Write([]byte(c.Verb + "/" + c.Group + "/" + c.Resource + "/" + strconv.FormatBool(c.Namespaced) + "="))
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
		// The escaped path and the encoded query hold no raw "?" or NUL, so
		// the parts cannot run into each other.
		return r.URL.EscapedPath() + "?" + r.URL.Query().Encode() + "\x00" + sk + "\x00" + strconv.FormatUint(v, 10), true
	}
}
