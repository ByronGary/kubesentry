package api

// GET /api/v1/alerts: the findings kubesentry alerts on, as the alerting
// runner last saw them (its board: the leader's own state, or what another
// replica last read from the store), filtered by the caller's scope like
// every other route. Nothing here evaluates or reads the store.
//
// POST /api/v1/alerts/actions acknowledges and silences findings (and lifts
// either); GET /api/v1/alerts/actions lists what people did. Who may see a
// finding depends on its kind (alerts.Gate, alertGates); who may act on it
// needs UpdateAlerts there as well.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ByronGary/kubesentry/internal/alerts"
	"github.com/ByronGary/kubesentry/internal/auth"
	"github.com/ByronGary/kubesentry/internal/incidents"
	"github.com/ByronGary/kubesentry/internal/metrics"
)

// AlertsSource is the alerting runner (alerts.Runner).
type AlertsSource interface {
	// Board is the latest board; nil before the first evaluation or read.
	Board() *alerts.Board
	Status() alerts.Status
	// Act records actions on findings of the board and applies them at once
	// (alerts.Runner.Act); the error is the store's.
	Act(ctx context.Context, acts ...alerts.Action) ([]alerts.ActResult, error)
	// Actions lists recorded actions newest first: on key (every key for
	// ""), at most limit, those keep accepts.
	Actions(key string, limit int, keep func(*alerts.Action) bool) []alerts.Action
	// MaxSilence is the longest silence a request may ask for.
	MaxSilence() time.Duration
}

// alertsRoute is the route's pattern, as cachedRoutes keys it.
const alertsRoute = "GET /api/v1/alerts"

// alertsCaps is every capability /alerts depends on: what the findings'
// gates need, and UpdateAlerts for each item's actionable.
var alertsCaps = []auth.Capability{auth.ViewNamespace, auth.ViewRBAC, auth.ViewClusterRBAC, auth.ViewAudit, auth.ViewClusterAudit,
	auth.ViewNodes, auth.ViewAgents, auth.UpdateAlerts}

// alertItem mirrors web/src/types.ts AlertFinding: a finding, the incident
// its current episode joined, and whether the caller may act on it.
type alertItem struct {
	alerts.Finding
	IncidentID string `json:"incidentId,omitempty"`
	Actionable bool   `json:"actionable,omitempty"`
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

// alertGates is what one caller holds of every capability a finding's gate
// (alerts.Gate) may need. /alerts, /alerts/actions and the Overview's
// counter all decide visibility with allows:
//
//	gate       namespaced finding           cluster-scoped finding
//	namespace  ViewNamespace                ViewNamespace in every namespace
//	rbac       ViewNamespace + ViewRBAC     ViewClusterRBAC
//	audit      ViewNamespace + ViewAudit    ViewClusterAudit
//	node       ViewNamespace + ViewNodes    ViewNodes
//	agents     ViewNamespace + ViewAgents   ViewAgents
//
// A cluster-scoped namespace finding and namespaced node and agent findings
// do not occur; they fail closed as shown.
type alertGates struct {
	ns, rbac, audit                      auth.Scope
	clusterRBAC, clusterAudit, nodes, ag bool
	// update is where the caller may act (UpdateAlerts); only the routes
	// that report or take actions read it.
	update auth.Scope
}

func (s *Server) alertGates(r *http.Request) alertGates {
	return alertGates{
		ns: s.scope(r, auth.ViewNamespace), rbac: s.scope(r, auth.ViewRBAC), audit: s.scope(r, auth.ViewAudit),
		clusterRBAC: s.can(r, auth.ViewClusterRBAC), clusterAudit: s.can(r, auth.ViewClusterAudit),
		nodes: s.can(r, auth.ViewNodes), ag: s.can(r, auth.ViewAgents),
	}
}

// allows reports whether a finding with gate g in namespace ns may be seen.
// inNS says whether a namespace is selected (ViewNamespace there, narrowed
// by the Overview's filter); cluster is false when cluster-scoped findings
// are left out (a filtered Overview).
func (a *alertGates) allows(g alerts.Gate, ns string, inNS func(string) bool, cluster bool) bool {
	if ns == "" {
		if !cluster {
			return false
		}
		switch g {
		case alerts.GateRBAC:
			return a.clusterRBAC
		case alerts.GateAudit:
			return a.clusterAudit
		case alerts.GateNode:
			return a.nodes
		case alerts.GateAgents:
			return a.ag
		}
		return a.ns.All
	}
	if !inNS(ns) {
		return false
	}
	switch g {
	case alerts.GateNamespace:
		return true
	case alerts.GateRBAC:
		return a.rbac.Has(ns)
	case alerts.GateAudit:
		return a.audit.Has(ns)
	case alerts.GateNode:
		return a.nodes
	case alerts.GateAgents:
		return a.ag
	}
	return false
}

// visible reports whether the caller may see f.
func (a *alertGates) visible(f *alerts.Finding) bool {
	return a.allows(f.Gate(), f.Namespace, a.ns.Has, true)
}

// visibleKey reports whether the caller may see the finding with key key,
// from the board when it holds the finding, else from the key itself.
func (a *alertGates) visibleKey(b *alerts.Board, key string) bool {
	if f, ok := b.Find(key); ok {
		return a.visible(f)
	}
	check, kind, ns, _, ok := alerts.ParseKey(key)
	return ok && a.allows(alerts.GateOf(check, kind), ns, a.ns.Has, true)
}

// actionable reports whether the caller may act on f, which they can see:
// UpdateAlerts in its namespace, or cluster-wide for a cluster-scoped one.
func (a *alertGates) actionable(f *alerts.Finding) bool {
	if f.Namespace == "" {
		return a.update.All
	}
	return a.update.Has(f.Namespace)
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
	as := s.alertGates(r)
	as.update = s.scope(r, auth.UpdateAlerts)
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
		resp.Items = append(resp.Items, alertItem{Finding: *f, IncidentID: s.incidentOfFinding(f), Actionable: as.actionable(f)})
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
	// Standing-state digests (-alerts-digest-at): when one was last sent
	// (absent before the first), and the next scheduled time (absent while
	// they are off).
	LastDigestAt *time.Time `json:"lastDigestAt,omitempty"`
	NextDigestAt *time.Time `json:"nextDigestAt,omitempty"`
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
	if !st.LastDigestAt.IsZero() {
		t := st.LastDigestAt
		out.LastDigestAt = &t
	}
	if !st.NextDigestAt.IsZero() {
		t := st.NextDigestAt
		out.NextDigestAt = &t
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
// in the selection (the /alerts gates): a filter leaves cluster-scoped
// findings out, as it does their security counts.
func (s *Server) overviewAlerts(r *http.Request, sel *ovSel) *overviewAlerts {
	if s.Alerts == nil {
		return nil
	}
	out := &overviewAlerts{ByOwner: map[string]int{}}
	b := s.Alerts.Board()
	if b == nil {
		return out
	}
	g := alertGates{ns: sel.sc, rbac: sel.rbac, clusterRBAC: sel.clusterRBAC, nodes: sel.nodes}
	needs := map[alerts.Gate]bool{}
	for i := range b.Findings {
		needs[b.Findings[i].Gate()] = true
	}
	if needs[alerts.GateAudit] {
		g.audit, g.clusterAudit = s.scope(r, auth.ViewAudit), s.can(r, auth.ViewClusterAudit)
	}
	if needs[alerts.GateAgents] {
		g.ag = s.can(r, auth.ViewAgents)
	}
	for i := range b.Findings {
		f := &b.Findings[i]
		if f.Resolved() || !g.allows(f.Gate(), f.Namespace, sel.has, !sel.filtered) {
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

// Limits of the actions routes.
const (
	maxActionKeys       = 100
	minSilenceReason    = 3
	maxSilenceReason    = 500
	defaultActionsLimit = 50
	maxActionsLimit     = 200
)

// alertActionRequest mirrors web/src/types.ts AlertActionRequest.
type alertActionRequest struct {
	Keys   []string `json:"keys"`
	Action string   `json:"action"`
	For    string   `json:"for,omitempty"`
	Reason string   `json:"reason,omitempty"`
}

// alertActionResult mirrors web/src/types.ts AlertActionResult.
type alertActionResult struct {
	Key     string     `json:"key"`
	OK      bool       `json:"ok"`
	Error   string     `json:"error,omitempty"` // not found, forbidden, resolved, invalid
	Finding *alertItem `json:"finding,omitempty"`
}

// alertActionResponse mirrors web/src/types.ts AlertActionResponse.
type alertActionResponse struct {
	Results []alertActionResult `json:"results"`
}

// Per-key results of POST /api/v1/alerts/actions.
const (
	actionNotFound  = "not found"
	actionForbidden = "forbidden"
	actionResolved  = "resolved"
	actionInvalid   = "invalid"
)

// alertActions answers POST /api/v1/alerts/actions: acknowledge, silence,
// or lift either, on up to 100 findings. The request as a whole is 400
// (malformed), 413, 415, or 403 when the caller may act nowhere; otherwise
// each key gets a result. A key the caller cannot see is "not found", as an
// unknown one is; one they see without UpdateAlerts there is "forbidden".
func (s *Server) alertActions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var req alertActionRequest
	if !decodeJSON(w, r, maxJSONBody, &req) {
		return
	}
	kind := alerts.ActionKind(req.Action)
	reason := strings.TrimSpace(req.Reason)
	switch {
	case !kind.Valid():
		writeError(w, http.StatusBadRequest, "action must be ack, unack, silence or unsilence")
		return
	case len(req.Keys) == 0:
		writeError(w, http.StatusBadRequest, "keys must name at least one finding")
		return
	case len(req.Keys) > maxActionKeys:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("keys: at most %d findings per request", maxActionKeys))
		return
	case kind != alerts.ActionSilence && (req.For != "" || req.Reason != ""):
		writeError(w, http.StatusBadRequest, "for and reason apply to silence only")
		return
	}
	var until *time.Time
	if kind == alerts.ActionSilence {
		maxSilence := s.Alerts.MaxSilence()
		d, err := parseDays(req.For)
		if err != nil || d < alerts.MinSilence || d > maxSilence {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("for must be a duration from %s to %s, e.g. 4h or 1d", alerts.MinSilence, formatDays(maxSilence)))
			return
		}
		if n := utf8.RuneCountInString(reason); n < minSilenceReason || n > maxSilenceReason {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("reason must be %d to %d characters", minSilenceReason, maxSilenceReason))
			return
		}
		u := s.now().Add(d)
		until = &u
	}
	s.prepareAuthz(r)
	g := s.alertGates(r)
	g.update = s.scope(r, auth.UpdateAlerts)
	if !g.update.All && len(g.update.Namespaces) == 0 {
		writeError(w, http.StatusForbidden, "acknowledging and silencing alerts needs update on alerts.kubesentry.io")
		return
	}
	actor := ""
	if id, ok := auth.FromContext(r.Context()); ok {
		actor = id.User
	}
	b := s.Alerts.Board()
	results := make([]alertActionResult, 0, len(req.Keys))
	var acts []alerts.Action
	var at []int // results index of each action
	seen := make(map[string]bool, len(req.Keys))
	for _, k := range req.Keys {
		if seen[k] {
			continue
		}
		seen[k] = true
		res := alertActionResult{Key: k}
		f, ok := b.Find(k)
		switch {
		case !ok || !g.visible(f):
			res.Error = actionNotFound
		case !g.actionable(f):
			res.Error = actionForbidden
		default:
			acts = append(acts, alerts.Action{Key: k, Action: kind, Actor: actor, Reason: reason, Until: until})
			at = append(at, len(results))
		}
		results = append(results, res)
	}
	if len(acts) > 0 {
		out, err := s.Alerts.Act(r.Context(), acts...)
		if err != nil {
			slog.Error("recording alert actions failed", "user", actor, "action", kind, "err", err)
			w.Header().Set("Retry-After", "5")
			writeError(w, http.StatusServiceUnavailable, "the actions could not be recorded; try again")
			return
		}
		for i, o := range out {
			res := &results[at[i]]
			switch {
			case o.Err == nil:
				f := o.Finding
				res.OK, res.Finding = true, &alertItem{Finding: f, IncidentID: s.incidentOfFinding(&f), Actionable: true}
			case errors.Is(o.Err, alerts.ErrNotFound):
				res.Error = actionNotFound
			case errors.Is(o.Err, alerts.ErrResolved):
				res.Error = actionResolved
			default:
				res.Error = actionInvalid
			}
		}
	}
	done := 0
	for _, res := range results {
		label := "ok"
		if !res.OK {
			label = strings.ReplaceAll(res.Error, " ", "_")
		} else {
			done++
		}
		metrics.AlertActions.With(string(kind), label).Inc()
	}
	slog.Info("alert action", "user", actor, "action", kind, "keys", len(results), "done", done)
	writeJSON(w, http.StatusOK, alertActionResponse{Results: results})
}

// alertActionItem mirrors web/src/types.ts AlertAction, with the namespace
// of the finding acted on.
type alertActionItem struct {
	alerts.Action
	Namespace string `json:"namespace,omitempty"`
}

// alertActionsResponse mirrors web/src/types.ts AlertActionsResponse.
type alertActionsResponse struct {
	Items []alertActionItem `json:"items"`
}

// alertActionsList answers GET /api/v1/alerts/actions?key=&limit=: the
// actions taken on findings the caller can see (on one finding with key),
// newest first, at most limit (default 50, at most 200). Never cached.
func (s *Server) alertActionsList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	q := r.URL.Query()
	limit := defaultActionsLimit
	if raw := q.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "limit must be a positive number")
			return
		}
		limit = min(n, maxActionsLimit)
	}
	s.prepareAuthz(r)
	g := s.alertGates(r)
	b := s.Alerts.Board()
	acts := s.Alerts.Actions(q.Get("key"), limit, func(a *alerts.Action) bool { return g.visibleKey(b, a.Key) })
	resp := alertActionsResponse{Items: make([]alertActionItem, 0, len(acts))}
	for _, a := range acts {
		_, _, ns, _, _ := alerts.ParseKey(a.Key)
		resp.Items = append(resp.Items, alertActionItem{Action: a, Namespace: ns})
	}
	writeJSON(w, http.StatusOK, resp)
}

// parseDays is time.ParseDuration that also takes days: "7d", "1d12h".
func parseDays(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	var days time.Duration
	if i := strings.IndexByte(s, 'd'); i >= 0 {
		n, err := strconv.ParseFloat(s[:i], 64)
		if err != nil || n < 0 || n > 3650 {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		days, s = time.Duration(n*float64(24*time.Hour)), s[i+1:]
		if s == "" {
			return days, nil
		}
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	return days + d, nil
}

// formatDays prints whole days as "7d", anything else as Go does.
func formatDays(d time.Duration) string {
	if d > 0 && d%(24*time.Hour) == 0 {
		return strconv.FormatInt(int64(d/(24*time.Hour)), 10) + "d"
	}
	return d.String()
}
