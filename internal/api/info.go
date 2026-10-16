package api

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/ByronGary/kubesentry/internal/auth"
	"github.com/ByronGary/kubesentry/internal/model"
)

// infoResponse mirrors web/src/types.ts Info.
type infoResponse struct {
	Demo      bool `json:"demo"`      // serving synthetic data, not a real cluster
	Metrics   bool `json:"metrics"`   // Prometheus is configured
	Audit     bool `json:"audit"`     // audit ingestion is enabled
	Processes bool `json:"processes"` // process monitoring is enabled
	Inventory bool `json:"inventory"` // map, workloads, nodes, storage and security routes exist
	Certs     bool `json:"certs"`     // the certificates route exists (cert-manager may still be absent)
	// Version is the server's build version (cmd/server's main.version).
	Version string `json:"version,omitempty"`

	Identity     *infoIdentity   `json:"identity,omitempty"`
	SignOutURL   string          `json:"signOutURL,omitempty"`
	Capabilities map[string]bool `json:"capabilities,omitempty"`
	Cluster      *infoCluster    `json:"cluster,omitempty"`
	Snapshot     *infoSnapshot   `json:"snapshot,omitempty"`
	AuditStore   *infoAuditStore `json:"auditStore,omitempty"`
	Prometheus   *PrometheusInfo `json:"prometheus,omitempty"`
	// Namespaces is how many namespaces the caller can see (ViewNamespace).
	Namespaces  *int              `json:"namespaces,omitempty"`
	Unavailable map[string]string `json:"unavailable,omitempty"`
	Alerts      *infoAlerts       `json:"alerts"`
	// Incidents is left out when incidents are off.
	Incidents *infoIncidents `json:"incidents,omitempty"`
}

type infoIdentity struct {
	User   string   `json:"user"`
	Groups []string `json:"groups"`
	Source string   `json:"source"`
}

type infoCluster struct {
	Name     string `json:"name,omitempty"`
	Version  string `json:"version"`
	Platform string `json:"platform"`
	Provider string `json:"provider,omitempty"`
	Region   string `json:"region,omitempty"`
}

type infoSnapshot struct {
	Version    uint64    `json:"version"`
	BuiltAt    time.Time `json:"builtAt"`
	AgeSeconds float64   `json:"ageSeconds"`
	Stale      bool      `json:"stale"`
	Error      string    `json:"error,omitempty"`
}

type infoAuditStore struct {
	Backend        string     `json:"backend"`
	Oldest         *time.Time `json:"oldest,omitempty"`
	Newest         *time.Time `json:"newest,omitempty"`
	Events         int64      `json:"events"`
	RetentionHours float64    `json:"retentionHours,omitempty"`
	MaxEvents      int        `json:"maxEvents,omitempty"`
}

// infoViewWait bounds how long /info waits for the first view: it answers
// without the cluster and snapshot fields rather than hang while a large
// cluster is still being read.
const infoViewWait = 5 * time.Second

// infoCoverageWait bounds how long /info waits for the audit store's
// coverage; past it, auditStore is left out of this answer.
const infoCoverageWait = 50 * time.Millisecond

// info tells the UI which features this server has, who the caller is and
// what they may see, so it can hide what is empty or out of reach.
func (s *Server) info(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	resp := infoResponse{
		Demo: s.Demo, Metrics: s.metrics() != nil, Audit: s.Audit != nil, Processes: s.Processes != nil,
		Inventory: s.hasInventory(), Certs: s.hasCerts(), SignOutURL: s.SignOutURL, Version: s.Version,
		Alerts: s.infoAlerts(),
	}

	// The view comes first: its RBAC index proposes the namespaces the
	// capability checks below confirm.
	vctx, cancel := context.WithTimeout(ctx, infoViewWait)
	v, err := s.viewProvider().View(vctx)
	cancel()
	if err != nil {
		v = nil
		slog.Debug("info without a view", "err", err)
	}

	if id, ok := auth.FromContext(ctx); ok {
		groups := id.Groups
		if groups == nil {
			groups = []string{}
		}
		resp.Identity = &infoIdentity{User: id.User, Groups: groups, Source: id.Source}
		resp.Capabilities = s.capabilities(ctx, id)
		if sc := s.scope(r, auth.ViewNamespace); !sc.All {
			n := 0
			for _, held := range sc.Namespaces {
				if held {
					n++
				}
			}
			resp.Namespaces = &n
		} else if v != nil {
			n := len(v.Inv.Namespaces)
			if n == 0 {
				n = len(v.Assoc().Namespaces()) // namespaces unreadable: those holding objects
			}
			resp.Namespaces = &n
		}
	}

	ci := s.ClusterInfo
	if v != nil {
		ci = mergeCluster(v.Inv.Cluster, s.ClusterInfo)
		age := s.now().Sub(v.Built).Seconds()
		resp.Snapshot = &infoSnapshot{Version: v.Version, BuiltAt: v.Built, AgeSeconds: math.Max(0, math.Round(age*10)/10), Stale: v.Stale, Error: v.Err}
	}
	if ci.Version != "" || ci.Platform != "" || ci.Name != "" {
		resp.Cluster = &infoCluster{Name: ci.Name, Version: ci.Version, Platform: ci.Platform, Provider: ci.Provider, Region: ci.Region}
	}

	// The store's event count and span describe the whole cluster's
	// activity: only for callers who may read audit events somewhere.
	// The Postgres store serves it from a cache it refreshes in the
	// background; /info waits only briefly for a first value and otherwise
	// leaves it out, so it never queues behind a busy database.
	if s.Audit != nil && (resp.Capabilities["audit"] || resp.Capabilities["clusterAudit"]) {
		cctx, cancel := context.WithTimeout(ctx, infoCoverageWait)
		c, err := s.auditStore().Coverage(cctx)
		cancel()
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			slog.Debug("audit coverage not ready; /info leaves it out", "err", err)
		} else if err != nil {
			slog.Warn("audit coverage", "err", err)
		} else {
			as := &infoAuditStore{Backend: c.Backend, Events: c.Events, MaxEvents: c.MaxEvents}
			if !c.Oldest.IsZero() {
				as.Oldest, as.Newest = &c.Oldest, &c.Newest
			}
			if c.Retention > 0 {
				as.RetentionHours = c.Retention.Hours()
			}
			resp.AuditStore = as
		}
	}

	resp.Prometheus = s.prometheusInfo()
	resp.Incidents = s.infoIncidents(resp.Capabilities)

	var fromView map[string]string
	if v != nil {
		for src, reason := range v.Inv.Unavailable {
			// The list adapters record what this server was not given; that
			// is configuration, not something wrong with the cluster.
			if reason == "not configured" || reason == "not available from list sources" {
				continue
			}
			if fromView == nil {
				fromView = map[string]string{}
			}
			fromView[src] = reason
		}
	}
	var live map[string]string
	if s.Unavailable != nil {
		live = s.Unavailable()
	}
	var prom map[string]string
	if err := s.prometheusDown(); err != nil {
		prom = map[string]string{"prometheus": err.Error()}
	}
	resp.Unavailable = mergeUnavailable(fromView, live, prom)
	writeJSON(w, http.StatusOK, resp)
}

// mergeCluster is what the view knows about the cluster, with the
// configured name and anything the view lacks taken from override.
func mergeCluster(fromView, override model.ClusterInfo) model.ClusterInfo {
	out := fromView
	if override.Name != "" {
		out.Name = override.Name
	}
	if out.Version == "" && out.Platform == "" {
		n := out.Name
		out = override
		out.Name = n
	}
	return out
}

// capabilities returns the flags the UI gates on for id. Without an
// authorizer a restricted identity holds nothing.
func (s *Server) capabilities(ctx context.Context, id auth.Identity) map[string]bool {
	if s.Authorizer == nil && !id.Unrestricted {
		return auth.Capabilities(ctx, denyAll{}, id)
	}
	return auth.Capabilities(ctx, s.Authorizer, id)
}

// denyAll is the authorizer of a server that has none.
type denyAll struct{}

func (denyAll) Scope(context.Context, auth.Identity, auth.Capability) (auth.Scope, error) {
	return auth.Scope{Namespaces: map[string]bool{}}, nil
}

func (denyAll) Allowed(context.Context, auth.Identity, auth.Capability, string) (bool, error) {
	return false, nil
}

type recheckResponse struct {
	Capabilities map[string]bool `json:"capabilities"`
}

// recheckEvery is how often one identity may force its access to be re-read.
const recheckEvery = time.Minute

// recheck drops the caller's cached authorization decisions, so a grant or
// revocation shows without waiting for the cache TTL, and returns the
// capabilities as they are now. At most once a minute per identity.
func (s *Server) recheck(w http.ResponseWriter, r *http.Request) {
	id, ok := auth.FromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if wait := s.recheckWait(id.Key()); wait > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
		writeError(w, http.StatusTooManyRequests, "access was rechecked less than a minute ago")
		return
	}
	if f, ok := s.Authorizer.(interface{ Forget(auth.Identity) }); ok {
		f.Forget(id)
	}
	s.prepareAuthz(r)
	writeJSON(w, http.StatusOK, recheckResponse{Capabilities: s.capabilities(r.Context(), id)})
}

// recheckWait returns how long key must wait before its next recheck, and
// records this one when it may go ahead.
func (s *Server) recheckWait(key string) time.Duration {
	now := s.now()
	s.recheckMu.Lock()
	defer s.recheckMu.Unlock()
	if s.rechecks == nil {
		s.rechecks = map[string]time.Time{}
	}
	if last, ok := s.rechecks[key]; ok && now.Sub(last) < recheckEvery {
		return recheckEvery - now.Sub(last)
	}
	for k, t := range s.rechecks {
		if now.Sub(t) >= recheckEvery {
			delete(s.rechecks, k)
		}
	}
	s.rechecks[key] = now
	return 0
}
