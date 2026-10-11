// Package api exposes the detectors over a small JSON HTTP API.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/ByronGary/kubesentry/internal/auth"
	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/model"
	"github.com/ByronGary/kubesentry/internal/snapshot"
)

// ClusterSource lists Kubernetes objects.
type ClusterSource interface {
	ListPVCs(ctx context.Context) ([]model.PVC, error)
	ListPods(ctx context.Context) ([]model.Pod, error)
	// GetPod and GetPVC return model.ErrNotFound for a missing object.
	GetPod(ctx context.Context, namespace, name string) (*model.Pod, error)
	GetPVC(ctx context.Context, namespace, name string) (*model.PVC, error)
}

// MetricsSource provides container memory history. It is optional.
type MetricsSource interface {
	ContainerMemory(ctx context.Context, lookback, step time.Duration) ([]model.ContainerSeries, error)
	ContainerMemoryLimits(ctx context.Context) (map[model.ContainerKey]float64, error)
	// PodMemory returns history and limits for one pod's containers.
	PodMemory(ctx context.Context, namespace, pod string, lookback, step time.Duration) ([]model.ContainerSeries, map[model.ContainerKey]float64, error)
}

type Server struct {
	// Cluster looks single pods and claims up for the pod page (and, without
	// Views, is listed to build views).
	Cluster     ClusterSource
	Metrics     MetricsSource // nil disables leak detection
	Audit       AuditBackend  // nil disables the audit endpoints
	PVCOptions  detectors.PVCOptions
	LeakOptions detectors.LeakOptions
	// APIToken, if set and Authenticator is nil, is required as a bearer
	// token on every /api/ route. Leave it empty only when the listener is not
	// reachable by others.
	APIToken string
	// AuditToken is the bearer token the audit webhook requires. The webhook
	// refuses all requests while it is empty.
	AuditToken string
	// Processes, if set, enables process monitoring: the agent endpoint and per-pod process lists.
	Processes ProcessBackend
	// AgentToken is the bearer token node agents must send. The agent endpoint
	// refuses all requests while it is empty.
	AgentToken string
	// Inventory, if set, enables the map, workloads, nodes, storage and security routes.
	Inventory InventorySource
	// Certs, if set, enables the certificates route.
	Certs CertSource
	// UI, if set, serves the web interface for every path the API does not claim.
	UI http.Handler
	// Demo marks the data as synthetic so the UI can say so.
	Demo bool
	Now  func() time.Time // defaults to time.Now

	// Views hands out the precomputed view every inventory, pod and storage
	// route is served from (a snapshot.Manager over the informer cache). It
	// also enables the inventory and certificates routes. Nil builds a view
	// per request from Cluster, Inventory and Certs (snapshot.OnDemand over
	// snapshot.FromLists), so tests and older wiring take the same path.
	Views snapshot.ViewProvider
	// Policy builds views when Views is nil. Zero means the default policy
	// priced by PVCOptions.
	Policy detectors.Policy

	// Authenticator decides who calls /api/. Nil accepts APIToken as the
	// unrestricted break-glass identity when it is set, and otherwise lets
	// every caller in unrestricted, as before per-user access existed.
	Authenticator auth.Authenticator
	// Authorizer answers what restricted identities (proxy mode) may see. Nil
	// denies them everything; unrestricted identities never consult it.
	Authorizer auth.Authorizer
	// SignOutURL is where the UI's "Sign out" goes (proxy mode).
	SignOutURL string
	// AllowedHosts, if set, are the Host header patterns (ParseAllowedHosts)
	// the web listener answers; other Hosts get 403. Nil means
	// LoopbackHosts when Authenticator is auth.NoneAuthenticator (every
	// local caller is trusted, so DNS rebinding must not reach it), else
	// any Host.
	AllowedHosts []string
	// LongInflightPerIdentity caps the requests one identity may have in
	// flight at once on the expensive routes (/oom, pod diagnostics, audit
	// summary); more get 429 with Retry-After. Zero disables it.
	LongInflightPerIdentity int

	// ClusterInfo overrides what /info says about the cluster: a non-empty
	// Name always wins, the rest fills in when the view knows nothing.
	ClusterInfo model.ClusterInfo
	// PrometheusInfo describes the metrics source for /info (it may change as
	// discovery finds one); nil derives it from Metrics.
	PrometheusInfo func() *PrometheusInfo
	// Unavailable, if set, adds live unreadable sources (the informer cache's)
	// to those the view recorded, for /info and /readyz.
	Unavailable func() map[string]string
	// Ready gates /readyz: 503 until it reports true (caches synced and the
	// first view built). Nil is always ready.
	Ready func() bool
	// Checks are dependencies /readyz reports as degraded when they fail,
	// without failing readiness.
	Checks []HealthCheck

	// ResponseCache, if set, caches GET responses of the view-backed routes,
	// keyed by path, query, the caller's scope and the view version (leave
	// its KeyFunc nil: the server sets it). It needs a Views provider that
	// reports its current view (snapshot.Manager).
	ResponseCache *ResponseCache
	// RateLimit and RateBurst limit each identity's /api/ requests per second;
	// MaxInflight caps concurrent /api/ requests. Zero disables each.
	RateLimit   float64
	RateBurst   int
	MaxInflight int
	// RouteTimeout bounds each API request (the pod page and /oom get twice
	// as long). Zero means 30s; negative disables.
	RouteTimeout time.Duration
	// AccessLog, if set, gets one line per web request: who viewed what.
	AccessLog *slog.Logger

	cacheOnce sync.Once
	recheckMu sync.Mutex
	rechecks  map[string]time.Time // identity key → last recheck
}

// HealthCheck is one dependency /readyz reports on.
type HealthCheck struct {
	Name  string
	Check func(ctx context.Context) error
}

// PrometheusInfo is /info's prometheus field.
type PrometheusInfo struct {
	Source         string  `json:"source"` // flag, discovered, amp or none
	URL            string  `json:"url,omitempty"`
	RetentionHours float64 `json:"retentionHours,omitempty"`
	Flavor         string  `json:"flavor,omitempty"` // prometheus, thanos, mimir, victoriametrics, amp, unknown
	Version        string  `json:"version,omitempty"`
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) hasInventory() bool { return s.Inventory != nil || s.Views != nil }
func (s *Server) hasCerts() bool     { return s.Certs != nil || s.Views != nil }

// Parts selects what one listener serves.
type Parts struct {
	Web     bool // the UI and /api/
	Ingest  bool // POST /agent/report and POST /audit/webhook
	Probes  bool // /healthz and /readyz
	Metrics bool // /metrics
	Pprof   bool // /debug/pprof/
}

// Handler serves everything on one listener: the UI, the API, the ingest
// routes and the probes.
func (s *Server) Handler() http.Handler {
	return s.Serve(Parts{Web: true, Ingest: true, Probes: true})
}

// Serve returns the handler for a listener serving parts.
//
// Web requests pass request ids, the access log and security headers; /api/
// requests then authentication, the per-identity rate limit and the
// in-flight cap, and each route its metrics, timeout, ETag, response cache
// and gzip. The UI's static files stay unauthenticated. Ingest routes keep
// their own token guards and body limits and are not rate limited per user;
// probes and metrics are plain.
func (s *Server) Serve(p Parts) http.Handler {
	mux := http.NewServeMux()
	if p.Probes {
		mux.HandleFunc("GET /healthz", s.healthz)
		mux.HandleFunc("GET /readyz", s.readyz)
	}
	if p.Metrics {
		mux.Handle("GET /metrics", metricsHandler())
	}
	if p.Pprof {
		registerPprof(mux)
	}
	if p.Ingest {
		s.ingestRoutes(mux)
	}
	if p.Web {
		if s.ResponseCache != nil {
			s.cacheOnce.Do(func() {
				if s.ResponseCache.KeyFunc == nil {
					s.ResponseCache.KeyFunc = s.cacheKey
				}
			})
		}
		web := http.NewServeMux()
		web.Handle("/api/", Compose(
			WithAuthentication(s.authenticator()),
			WithRateLimit(s.RateLimit, s.RateBurst),
			WithMaxInflight(s.MaxInflight),
		)(s.apiRoutes()))
		if s.UI != nil {
			web.Handle("/", s.UI)
		}
		var accessLog func(http.Handler) http.Handler
		if s.AccessLog != nil {
			accessLog = WithAccessLog(s.AccessLog)
		}
		mux.Handle("/", Compose(WithRequestID(), accessLog, WithSecurityHeaders(), WithAllowedHosts(s.allowedHosts()))(web))
	}
	return mux
}

// authenticator is Authenticator, or the behaviour before per-user access:
// the API token when set, else everyone, unrestricted.
func (s *Server) authenticator() auth.Authenticator {
	switch {
	case s.Authenticator != nil:
		return s.Authenticator
	case s.APIToken != "":
		return auth.TokenAuthenticator{Token: s.APIToken}
	}
	return openAuthenticator{}
}

// openAuthenticator lets every caller in, unrestricted: an api.Server with
// neither an Authenticator nor an APIToken, as tests and loopback use it.
type openAuthenticator struct{}

func (openAuthenticator) Authenticate(*http.Request) (auth.Identity, bool) {
	return auth.Identity{User: auth.AnonymousUser, Groups: []string{auth.GroupAuthenticated}, Source: "none", Unrestricted: true}, true
}

// cachedRoutes lists the routes whose responses depend only on the view and
// the caller's scope, with every capability that scope covers. Only these are
// cached; a capability missing here would let one caller's response reach
// another, so list them all.
var cachedRoutes = map[string][]auth.Capability{
	"GET /api/v1/pvcs/unused":  {auth.ViewNamespace},
	"GET /api/v1/pods":         {auth.ViewNamespace},
	"GET /api/v1/workloads":    {auth.ViewNamespace},
	"GET /api/v1/nodes":        {auth.ViewNamespace, auth.ViewNodes},
	"GET /api/v1/nodes/{name}": {auth.ViewNamespace, auth.ViewNodes},
	"GET /api/v1/storage":      {auth.ViewNamespace, auth.ViewPVs, auth.ViewStorageClass},
	"GET /api/v1/security":     {auth.ViewNamespace, auth.ViewClusterRBAC},
	"GET /api/v1/map":          {auth.ViewNamespace, auth.ViewNodes},
	"GET /api/v1/certificates": {auth.ViewNamespace, auth.ViewClusterIssuer},
}

// cacheKey keys a cached route's response by path, query, the caller's scope
// over the route's capabilities and the view version. Other requests, and
// every request while the provider cannot name its current view (before the
// first view exists, too), are not cached. The scope is looked up through
// the request's authzMemo, so the handler filters by exactly the scope the
// key names.
func (s *Server) cacheKey(r *http.Request) (string, bool) {
	caps := cachedRoutes[r.Pattern]
	v, ok := s.currentVersion()
	if len(caps) == 0 || !ok {
		return "", false
	}
	return CacheKeyFunc(s.Authorizer, func() uint64 { return v }, caps...)(r)
}

// route registers one API route with its per-route middleware: metrics,
// timeout, the per-identity cap on expensive routes, ETag, the response
// cache (cachedRoutes only) and gzip.
func (s *Server) route(mux *http.ServeMux, pattern, name string, timeout time.Duration, h http.HandlerFunc) {
	var cache func(http.Handler) http.Handler
	if s.ResponseCache != nil && len(cachedRoutes[pattern]) > 0 && s.reportsCurrent() {
		cache = s.ResponseCache.Middleware
	}
	mux.Handle(pattern, Compose(WithMetrics(name), WithTimeout(timeout), WithETag(), cache, WithGzip())(h))
}

func (s *Server) timeouts() (normal, long time.Duration) {
	d := s.RouteTimeout
	if d == 0 {
		d = 30 * time.Second
	}
	return d, 2 * d
}

func (s *Server) apiRoutes() http.Handler {
	mux := http.NewServeMux()
	t, long := s.timeouts()
	s.route(mux, "GET /api/v1/info", "info", t, s.info)
	mux.Handle("POST /api/v1/auth/recheck", Compose(WithMetrics("auth_recheck"), WithTimeout(t))(http.HandlerFunc(s.recheck)))
	s.route(mux, "GET /api/v1/pvcs/unused", "pvcs_unused", t, s.unusedPVCs)
	s.route(mux, "GET /api/v1/oom", "oom", long, s.oom)
	s.route(mux, "GET /api/v1/pods", "pods", t, s.pods)
	s.route(mux, "GET /api/v1/pods/{namespace}/{name}/diagnostics", "pod_diagnostics", long, s.podDiagnostics)
	if s.Audit != nil {
		s.route(mux, "GET /api/v1/audit/events", "audit_events", t, s.auditEvents)
		s.route(mux, "GET /api/v1/audit/summary", "audit_summary", t, s.auditSummary)
	}
	if s.Processes != nil {
		s.route(mux, "GET /api/v1/pods/{namespace}/{name}/processes", "pod_processes", t, s.podProcesses)
		if _, ok := s.Processes.(agentLister); ok {
			s.route(mux, "GET /api/v1/agents", "agents", t, s.agents)
		}
	}
	if s.hasInventory() {
		s.route(mux, "GET /api/v1/workloads", "workloads", t, s.workloads)
		s.route(mux, "GET /api/v1/nodes", "nodes", t, s.nodes)
		s.route(mux, "GET /api/v1/nodes/{name}", "node", t, s.node)
		s.route(mux, "GET /api/v1/storage", "storage", t, s.storage)
		s.route(mux, "GET /api/v1/security", "security", t, s.security)
		s.route(mux, "GET /api/v1/map", "map", t, s.topology)
	}
	if s.hasCerts() {
		s.route(mux, "GET /api/v1/certificates", "certificates", t, s.certificates)
	}
	return withAuthzMemo(mux)
}

// ingestRoutes registers the routes that accept pushed data. Each keeps its
// own token guard (fail closed without a token) and body limit.
func (s *Server) ingestRoutes(mux *http.ServeMux) {
	if s.Audit != nil {
		mux.Handle("POST /audit/webhook", Compose(WithRequestID(), WithMetrics("ingest_audit_webhook"))(guard(s.AuditToken, s.auditWebhook)))
	}
	if s.Processes != nil {
		mux.Handle("POST /agent/report", Compose(WithRequestID(), WithMetrics("ingest_agent_report"), countReports)(guard(s.AgentToken, s.agentReport)))
	}
}

type unusedPVCResponse struct {
	Count                  int                   `json:"count"`
	TotalEstMonthlyCostUSD float64               `json:"totalEstMonthlyCostUSD"`
	Items                  []detectors.UnusedPVC `json:"items"`
}

// unusedPVCs lists the claims no live pod mounts that are at least minAge
// old, most expensive first, in the caller's namespaces.
func (s *Server) unusedPVCs(w http.ResponseWriter, r *http.Request) {
	minAge, err := durationParam(r, "minAge", s.PVCOptions.MinAge, 0, 10*365*24*time.Hour)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	v, ok := s.view(w, r)
	if !ok {
		return
	}
	items, total := visibleUnused(v, s.scope(r, auth.ViewNamespace), minAge)
	writeJSON(w, http.StatusOK, unusedPVCResponse{Count: len(items), TotalEstMonthlyCostUSD: total, Items: items})
}

// durationParam reads a Go-style duration query parameter such as "24h".
func durationParam(r *http.Request, name string, def, min, max time.Duration) (time.Duration, error) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return def, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q: use a duration like 24h or 90m", name, raw)
	}
	if d < min || d > max {
		return 0, fmt.Errorf("%s must be between %s and %s", name, min, max)
	}
	return d, nil
}

func upstreamError(w http.ResponseWriter, what string, err error) {
	slog.Error("upstream query failed", "upstream", what, "err", err)
	writeError(w, http.StatusBadGateway, "failed to query "+what)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("write response", "err", err)
	}
}
