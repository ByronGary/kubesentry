package api

// Handlers serve the precomputed snapshot view, filtered by the caller's
// scope. Nothing here lists the cluster or runs a detector per request:
// derived data (sorted indexes, summaries) is computed once per view with
// View.Memo and shared by every request that view serves. Views are shared
// and immutable, so handlers copy before they change anything.

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sort"

	"github.com/ByronGary/kubesentry/internal/auth"
	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/snapshot"
)

// viewProvider returns s.Views or, without one, a provider that builds a view
// per request from the older list sources, so tests, the demo and old wiring
// take the same code path as the informer cache.
func (s *Server) viewProvider() snapshot.ViewProvider {
	if s.Views != nil {
		return s.Views
	}
	// A nil interface converts to a nil interface, so absent sources stay absent.
	return snapshot.OnDemand{Source: snapshot.FromLists(s.Cluster, s.Inventory, s.Certs), Policy: s.policy(), Now: s.Now}
}

// policy is the policy views are built with when Views is nil: Policy, or for
// older wiring that leaves it zero, the defaults priced by PVCOptions and
// judging leaks by LeakOptions.
func (s *Server) policy() detectors.Policy {
	p := s.Policy
	if p.SystemNamespaces != nil || p.Thresholds != (detectors.Thresholds{}) || p.SystemPrincipalPrefixes != nil ||
		p.Pricing.ClassPrices != nil || p.Pricing.EBSPrices != nil || p.Pricing.DefaultPrice != nil {
		return p.WithDefaults()
	}
	p = detectors.DefaultPolicy()
	if s.PVCOptions.PricePerGiBMonth != nil {
		p.Pricing.ClassPrices = s.PVCOptions.PricePerGiBMonth
	}
	if d := s.PVCOptions.DefaultPricePerGiBMonth; d > 0 {
		p.Pricing.DefaultPrice = &d
	}
	if s.LeakOptions != (detectors.LeakOptions{}) {
		p.Leak = s.LeakOptions
	}
	return p
}

// view returns the view to serve. Without one it answers 503 while the first
// view is still being built (or the request gave up waiting) and 502 when
// the cluster could not be read, and returns false.
func (s *Server) view(w http.ResponseWriter, r *http.Request) (*snapshot.View, bool) {
	v, err := s.viewProvider().View(r.Context())
	if err == nil && v != nil {
		return v, true
	}
	if err == nil || r.Context().Err() != nil || errors.Is(err, context.DeadlineExceeded) {
		w.Header().Set("Retry-After", "5")
		writeError(w, http.StatusServiceUnavailable, "the cluster view is not ready yet")
		return nil, false
	}
	upstreamError(w, "kubernetes", err)
	return nil, false
}

// prepareAuthz makes sure a view exists before a restricted caller's scope
// is computed: the view's RBAC index proposes the namespaces the authorizer
// confirms, and a scope computed without it would be cached too narrow.
// Unrestricted callers need no view for that.
func (s *Server) prepareAuthz(r *http.Request) {
	if id, ok := auth.FromContext(r.Context()); !ok || id.Unrestricted {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), infoViewWait)
	defer cancel()
	_, _ = s.viewProvider().View(ctx)
}

// reportsCurrent reports whether the view provider can name its current
// view without building one (snapshot.Manager); only then are responses
// cached.
func (s *Server) reportsCurrent() bool {
	_, ok := s.Views.(interface{ Current() *snapshot.View })
	return ok
}

// currentVersion is the version of the view being served, for response cache
// keys; ok is false when the provider cannot say without building one, and
// before the first view exists (scopes computed then lack the RBAC index's
// candidates, so nothing is cached).
func (s *Server) currentVersion() (uint64, bool) {
	c, ok := s.Views.(interface{ Current() *snapshot.View })
	if !ok {
		return 0, false
	}
	if v := c.Current(); v != nil {
		return v.Version, true
	}
	return 0, false
}

// scope returns where the caller holds c, as resolved once for this request
// (see authzMemo). A failed check denies: the caller sees nothing rather
// than an error, and the response is not cached.
func (s *Server) scope(r *http.Request, c auth.Capability) auth.Scope {
	sc, err := scopeOf(r.Context(), s.Authorizer, c)
	if err != nil {
		slog.Warn("authorization scope failed", "resource", c.Resource, "err", err)
		return auth.Scope{Namespaces: map[string]bool{}}
	}
	if !sc.All && sc.Namespaces == nil {
		sc.Namespaces = map[string]bool{}
	}
	return sc
}

// can reports whether the caller holds the cluster-wide capability c.
func (s *Server) can(r *http.Request, c auth.Capability) bool {
	return allowed(r.Context(), s.Authorizer, c, "")
}

// keyed is one row of a list in page order: key sorts the rows and is what a
// continue token carries.
type keyed[T any] struct {
	key string
	ns  string
	v   T
}

// memoRows returns rows built by build and sorted by key, once per view.
func memoRows[T any](v *snapshot.View, name string, build func() []keyed[T]) []keyed[T] {
	return v.Memo("api/"+name, func() any {
		rows := build()
		sort.Slice(rows, func(i, j int) bool { return rows[i].key < rows[j].key })
		return rows
	}).([]keyed[T])
}

// pageRows returns up to limit rows after the key `after` that keep accepts,
// and the key to continue from when more such rows follow. The rows must be
// sorted by key. Rows before `after` cost a binary search, not a scan.
func pageRows[T any](rows []keyed[T], after string, limit int, keep func(*keyed[T]) bool) (out []T, next string) {
	out = make([]T, 0, min(limit, len(rows)))
	i := 0
	if after != "" {
		i = sort.Search(len(rows), func(i int) bool { return rows[i].key > after })
	}
	last := ""
	for ; i < len(rows); i++ {
		if !keep(&rows[i]) {
			continue
		}
		if len(out) == limit {
			return out, last
		}
		out = append(out, rows[i].v)
		last = rows[i].key
	}
	return out, ""
}

// inScope keeps rows whose namespace the scope holds, and when ns is set,
// only that namespace.
func inScope[T any](sc auth.Scope, ns string) func(*keyed[T]) bool {
	return func(row *keyed[T]) bool {
		return (ns == "" || row.ns == ns) && sc.Has(row.ns)
	}
}
