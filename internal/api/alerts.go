package api

// GET /api/v1/alerts: the findings kubesentry alerts on, as the alerting
// runner last saw them (its board: the leader's own state, or what another
// replica last read from the store), filtered by the caller's scope like
// every other route. Nothing here evaluates or reads the store.

import (
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/ByronGary/kubesentry/internal/alerts"
	"github.com/ByronGary/kubesentry/internal/auth"
	"github.com/ByronGary/kubesentry/internal/incidents"
)

// AlertsSource is the alerting runner (alerts.Runner).
type AlertsSource interface {
	// Board is the latest board; nil before the first evaluation or read.
	Board() *alerts.Board
	Status() alerts.Status
}

// alertsRoute is the route's pattern, as cachedRoutes keys it.
const alertsRoute = "GET /api/v1/alerts"

// alertsCaps is every capability /alerts depends on.
var alertsCaps = []auth.Capability{auth.ViewNamespace, auth.ViewRBAC, auth.ViewClusterRBAC}

// alertItem mirrors web/src/types.ts AlertFinding: a finding, and the
// incident its current episode joined.
type alertItem struct {
	alerts.Finding
	IncidentID string `json:"incidentId,omitempty"`
}

// alertsResponse mirrors web/src/types.ts AlertsResponse.
type alertsResponse struct {
	Count int         `json:"count"`
	Items []alertItem `json:"items"`
	// Counts covers every finding the caller can see, before the filters.
	Counts    map[string]int `json:"counts"`
	UpdatedAt *time.Time     `json:"updatedAt,omitempty"`
	Continue  string         `json:"continue,omitempty"`
}

// alertScope is what one caller may see of the findings: namespaced ones
// need ViewNamespace there (RBAC ones also ViewRBAC, as on /security),
// cluster-scoped ones (RBAC drift) need ViewClusterRBAC.
type alertScope struct {
	sc, rbac    auth.Scope
	clusterRBAC bool
}

func (s *Server) alertScope(r *http.Request) alertScope {
	return alertScope{sc: s.scope(r, auth.ViewNamespace), rbac: s.scope(r, auth.ViewRBAC), clusterRBAC: s.can(r, auth.ViewClusterRBAC)}
}

func (a alertScope) visible(f *alerts.Finding) bool {
	if f.Namespace == "" {
		return a.clusterRBAC
	}
	return a.sc.Has(f.Namespace) && (!f.RBAC() || a.rbac.Has(f.Namespace))
}

// stateParam reads ?state=: one of the lifecycle states, or "" for all.
func stateParam(w http.ResponseWriter, r *http.Request) (alerts.State, bool) {
	switch st := alerts.State(r.URL.Query().Get("state")); st {
	case "", alerts.StateOpen, alerts.StateAcknowledged, alerts.StateSilenced, alerts.StateResolved:
		return st, true
	}
	writeError(w, http.StatusBadRequest, "state must be open, acknowledged, silenced or resolved")
	return "", false
}

// alertsList answers GET /api/v1/alerts?namespace=&owner=&state=&limit=&continue=:
// the caller's findings that are open, acknowledged or silenced, and those
// resolved in the last 24 hours, most troubled first.
func (s *Server) alertsList(w http.ResponseWriter, r *http.Request) {
	ns, ok := namespaceParam(w, r)
	if !ok {
		return
	}
	owner, ok := ownerParam(w, r)
	if !ok {
		return
	}
	state, ok := stateParam(w, r)
	if !ok {
		return
	}
	pg, ok := pageParams(w, r, "alerts")
	if !ok {
		return
	}
	s.prepareAuthz(r)
	as := s.alertScope(r)
	resp := alertsResponse{Items: []alertItem{}, Counts: map[string]int{
		string(alerts.StateOpen): 0, string(alerts.StateAcknowledged): 0, string(alerts.StateSilenced): 0, string(alerts.StateResolved): 0,
	}}
	b := s.Alerts.Board()
	if b == nil {
		writeJSON(w, http.StatusOK, resp)
		return
	}
	at := b.At
	resp.UpdatedAt = &at
	since := s.now().Add(-alerts.BoardWindow)
	keep := func(f *alerts.Finding) bool {
		return as.visible(f) && (!f.Resolved() || f.ResolvedAt == nil || !f.ResolvedAt.Before(since))
	}
	for i := range b.Findings {
		if f := &b.Findings[i]; keep(f) {
			resp.Counts[string(f.State)]++
		}
	}
	i := 0
	if pg.after != "" {
		i = sort.SearchStrings(b.Keys, pg.after)
		if i < len(b.Keys) && b.Keys[i] == pg.after {
			i++
		}
	}
	last := ""
	for ; i < len(b.Findings); i++ {
		f := &b.Findings[i]
		if !keep(f) || (ns != "" && f.Namespace != ns) || (owner != "" && f.Owner != owner) || (state != "" && f.State != state) {
			continue
		}
		if len(resp.Items) == pg.limit {
			resp.Continue = encodeToken("alerts", last)
			break
		}
		resp.Items = append(resp.Items, alertItem{Finding: *f, IncidentID: s.incidentOfFinding(f)})
		last = b.Keys[i]
	}
	resp.Count = len(resp.Items)
	writeJSON(w, http.StatusOK, resp)
}

// incidentOfFinding is the incident on this replica's board that the
// finding's current episode joined, when it is in the finding's own
// namespace: whoever may see the finding may then see the incident too
// (both need ViewNamespace there), so the ID reveals nothing new.
func (s *Server) incidentOfFinding(f *alerts.Finding) string {
	if s.Incidents == nil || f.Namespace == "" {
		return ""
	}
	b := s.Incidents.Board()
	id, ok := b.IncidentOf(incidents.EpisodeID(f))
	if !ok {
		return ""
	}
	if in, ok := b.Get(id); !ok || in.Subject.Namespace != f.Namespace {
		return ""
	}
	return id
}

// alertsCacheKey adds the board's version to /alerts' response cache key,
// so a cached list never outlives the board it shows; and the incidents
// board's version, since items name the incident their episode joined.
func (s *Server) alertsCacheKey() string {
	if s.Alerts == nil {
		return ""
	}
	key := "a0"
	if b := s.Alerts.Board(); b != nil {
		key = "a" + strconv.FormatUint(b.Version, 10)
	}
	return key + s.incidentsCacheKey()
}

// infoAlerts is /info's alerts field (web/src/types.ts Info.alerts). The
// delivery fields come from this replica: only the leader sends.
type infoAlerts struct {
	Enabled    bool       `json:"enabled"`
	Sink       string     `json:"sink"` // alertmanager or none
	Leader     bool       `json:"leader,omitempty"`
	LastSentAt *time.Time `json:"lastSentAt,omitempty"`
	LastError  string     `json:"lastError,omitempty"`
}

func (s *Server) infoAlerts() *infoAlerts {
	if s.Alerts == nil {
		return &infoAlerts{Sink: "none"}
	}
	st := s.Alerts.Status()
	out := &infoAlerts{Enabled: true, Sink: st.Sink, Leader: st.Leader, LastError: st.LastError}
	if out.Sink == "" {
		out.Sink = "none"
	}
	if !st.LastSentAt.IsZero() {
		t := st.LastSentAt
		out.LastSentAt = &t
	}
	return out
}

// overviewAlerts is the Overview's alerts widget (web/src/types.ts
// OverviewResponse.alerts): findings not resolved, in the selection.
type overviewAlerts struct {
	Open         int            `json:"open"`
	Acknowledged int            `json:"acknowledged"`
	Silenced     int            `json:"silenced"`
	ByOwner      map[string]int `json:"byOwner"`
}

// overviewAlerts counts the board's unresolved findings the caller may see
// in the selection: a filter leaves cluster-scoped findings out, as it
// does their security counts.
func (s *Server) overviewAlerts(sel *ovSel) *overviewAlerts {
	if s.Alerts == nil {
		return nil
	}
	out := &overviewAlerts{ByOwner: map[string]int{}}
	b := s.Alerts.Board()
	if b == nil {
		return out
	}
	for i := range b.Findings {
		f := &b.Findings[i]
		if f.Resolved() {
			continue
		}
		if f.Namespace == "" {
			if sel.filtered || !sel.clusterRBAC {
				continue
			}
		} else if !sel.has(f.Namespace) || (f.RBAC() && !sel.rbac.Has(f.Namespace)) {
			continue
		}
		switch f.State {
		case alerts.StateOpen:
			out.Open++
		case alerts.StateAcknowledged:
			out.Acknowledged++
		case alerts.StateSilenced:
			out.Silenced++
		}
		out.ByOwner[f.Owner]++
	}
	return out
}
