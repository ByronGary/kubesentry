package api

import (
	"context"
	"log/slog"
	"math"
	"net/http"
	"time"

	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/auth"
)

// overviewActivity mirrors the activity tile of web/src/types.ts
// OverviewResponse.
type overviewActivity struct {
	WindowHours    int           `json:"windowHours"`
	Exec           int           `json:"exec"`
	ExecProduction int           `json:"execProduction"`
	SecretReads    int           `json:"secretReads"`
	RBACChanges    int           `json:"rbacChanges"`
	Denied         int           `json:"denied"`
	Latest         []audit.Event `json:"latest"`
}

const (
	// activityWindow is the sensitive-activity tile's look-back.
	activityWindow = 24 * time.Hour
	// activityLatest is how many of the newest sensitive events it lists.
	activityLatest = 5
	// activityWait bounds how long the overview waits for the counts: a
	// busy audit store must not hold the whole dashboard. The computation
	// carries on (the Postgres store caches it) for the next poll.
	activityWait = 3 * time.Second
)

var (
	// activityTags are counted, by users and service accounts (as the
	// Activity page's summary counts them by default).
	activityTags = []string{audit.TagExec, audit.TagSecretAccess, audit.TagRBACChange, audit.TagDenied}
	// activityLatestTags pick the events listed: actions on the cluster
	// and refusals. Secret reads are counted, not listed: service accounts
	// make them all day.
	activityLatestTags = []string{audit.TagExec, audit.TagRBACChange, audit.TagDenied, audit.TagImpersonate}
	activityActors     = map[string]bool{"user": true, "serviceaccount": true}
)

// overviewActivity counts sensitive audit activity over the last day where
// the caller may read audit events (and in the selected namespaces when a
// filter is given; a filter leaves cluster-scoped events out). It is nil
// without audit, or for a caller who may read no audit event at all. It
// never summarizes the whole window: it asks the store's cheap tag counts
// (audit.TagCounter). failed is true when the store did not answer, and the
// activity is then nil too.
func (s *Server) overviewActivity(r *http.Request, idx *ovIndex, sel *ovSel, now time.Time) (act *overviewActivity, failed bool) {
	if s.Audit == nil {
		return nil, false
	}
	var q audit.Query
	if !s.auditScope(r, &q) {
		return nil, false
	}
	act = &overviewActivity{WindowHours: int(activityWindow / time.Hour), Latest: []audit.Event{}}
	tq := audit.TagCountQuery{
		Since: now.Add(-activityWindow), Tags: activityTags, Actors: activityActors,
		Namespaces: q.Namespaces, ClusterScoped: q.ClusterScoped, Subset: idx.production,
		Latest: activityLatest, LatestTags: activityLatestTags,
	}
	if sel.filtered {
		nss := map[string]bool{}
		for ns := range sel.set {
			if q.Namespaces == nil || q.Namespaces[ns] {
				nss[ns] = true
			}
		}
		if len(nss) == 0 {
			return act, false
		}
		tq.Namespaces, tq.ClusterScoped = nss, false
	}
	ctx, cancel := context.WithTimeout(r.Context(), activityWait)
	defer cancel()
	c, err := audit.CountTags(ctx, s.auditStore(), tq)
	if err != nil {
		slog.Warn("overview: audit tag counts unavailable", "err", err)
		return nil, true
	}
	act.Exec = c.ByTag[audit.TagExec]
	act.ExecProduction = c.Subset[audit.TagExec]
	act.SecretReads = c.ByTag[audit.TagSecretAccess]
	act.RBACChanges = c.ByTag[audit.TagRBACChange]
	act.Denied = c.ByTag[audit.TagDenied]
	if c.Latest != nil {
		act.Latest = c.Latest
	}
	return act, false
}

// overviewHealth is the health strip: Prometheus, the audit store and its
// CloudWatch reader (lag only for callers who may read audit events), and
// the node agents with the agents capability.
func (s *Server) overviewHealth(r *http.Request) overviewHealth {
	h := overviewHealth{Prometheus: "none", AuditStore: "none"}
	switch {
	case s.prometheusDown() != nil:
		h.Prometheus = "unavailable"
	case s.metrics() != nil:
		h.Prometheus = "ok"
	}
	if s.Audit != nil {
		h.AuditStore = "ok"
		if s.AuditHealth != nil && s.AuditHealth() != nil {
			h.AuditStore = "degraded"
		}
		if s.CloudWatchLag != nil && s.readsAudit(r) {
			if lag, ok := s.CloudWatchLag(); ok {
				v := math.Round(lag.Seconds())
				h.CloudWatchLagSeconds = &v
			}
		}
	}
	if l, ok := s.Processes.(agentLister); ok && s.can(r, auth.ViewAgents) {
		a := &overviewAgents{}
		for _, st := range l.Agents() {
			if st.Stale {
				a.Stale++
			} else {
				a.Reporting++
			}
		}
		h.Agents = a
	}
	return h
}

// readsAudit reports whether the caller may read audit events anywhere.
func (s *Server) readsAudit(r *http.Request) bool {
	sc := s.scope(r, auth.ViewAudit)
	if sc.All || s.can(r, auth.ViewClusterAudit) {
		return true
	}
	for ns, held := range sc.Namespaces {
		if held && ns != "" {
			return true
		}
	}
	return false
}
