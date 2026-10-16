package api

// The incidents routes: GET /api/v1/incidents (the list), /incidents/{id}
// (one incident with its signals, events, audit and charts), /{id}/logs
// (container logs of its window, read when asked) and /{id}/bundle (all of
// it for an agent to read). The list is served from the incidents board
// (the last 24 hours, the leader's own state or what another replica last
// read) and older ranges from the store, filtered by the caller's scope
// like every other route.
//
// Who sees what: a namespaced incident needs ViewNamespace in its
// namespace, a node or cluster one ViewNodes. Inside one, audit changes and
// audit events need ViewAudit there (ViewClusterAudit for a node), CloudTrail
// changes ViewCloudTrail, events about nodes ViewNodes, and logs ViewPodLogs.
// An incident the caller may not see is not found, with the same answer as
// an unknown ID, and an unknown ID is answered before any authorization
// review.

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
	"unicode"

	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/auth"
	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/incidents"
	"github.com/ByronGary/kubesentry/internal/snapshot"
	"github.com/ByronGary/kubesentry/internal/uilink"
)

// IncidentsSource is the incidents runner (incidents.Runner): its board,
// and the reads behind the detail, logs and bundle routes.
type IncidentsSource interface {
	// Board is what the list serves for the last BoardWindow.
	Board() *incidents.MemBoard
	// Options are the options in force, defaults applied.
	Options() incidents.Options
	// Leader reports whether this replica runs the engine.
	Leader() bool
	// Sources is each signal source's state ("ok", "absent", "error: …").
	Sources() map[string]string
	Redactor() *incidents.Redactor
	Get(ctx context.Context, id string) (incidents.Incident, []incidents.Signal, bool, error)
	Detail(ctx context.Context, id string, o incidents.DetailOptions) (incidents.Detail, bool, error)
	AuditEvents(ctx context.Context, in *incidents.Incident, limit int) ([]audit.Event, error)
	Logs(ctx context.Context, id string, req incidents.LogRequest) (incidents.LogResponse, error)
	Bundle(ctx context.Context, id string, req incidents.BundleRequest) (*incidents.Bundle, error)
}

var _ IncidentsSource = (*incidents.Runner)(nil)

// The routes' patterns, as cachedRoutes keys them.
const (
	incidentsRoute      = "GET /api/v1/incidents"
	incidentRoute       = "GET /api/v1/incidents/{id}"
	incidentLogsRoute   = "GET /api/v1/incidents/{id}/logs"
	incidentBundleRoute = "GET /api/v1/incidents/{id}/bundle"
)

// incidentsCaps is every capability the list depends on: the scope, and
// the gates on audit and CloudTrail changes in each incident's types.
var incidentsCaps = []auth.Capability{auth.ViewNamespace, auth.ViewNodes, auth.ViewAudit, auth.ViewClusterAudit, auth.ViewCloudTrail}

// incidentsCacheWindow is how long a cached list is served: a "last hour"
// window moves with the clock, and the board with the engine.
const incidentsCacheWindow = 10 * time.Second

// Limits of the routes.
const (
	// incidentsStoreScan bounds the incidents one store read returns for a
	// range older than the board (one day at most).
	incidentsStoreScan = incidents.MemoryMaxIncidents
	// incidentEventLimit and incidentAuditLimit bound the detail's events
	// and audit events.
	incidentEventLimit = 500
	incidentAuditLimit = 500
	// incidentPodRefs bounds the incidents a pod page lists.
	incidentPodRefs = 20
	maxTagFilters   = 10
)

// incidentRef mirrors web/src/types.ts IncidentRef. Severity is the peak.
type incidentRef struct {
	ID       string    `json:"id"`
	Severity string    `json:"severity"`
	State    string    `json:"state"`
	Title    string    `json:"title"`
	Start    time.Time `json:"start"`
}

func refOf(in *incidents.Incident) incidentRef {
	return incidentRef{ID: in.ID, Severity: string(in.PeakSeverity), State: string(in.State), Title: in.Title, Start: in.Start}
}

// incidentsCounts mirrors IncidentsResponse.counts: the range before the
// severity, type and state filters. Critical and warning count the peak
// severity, byType the incidents holding each type.
type incidentsCounts struct {
	Open     int            `json:"open"`
	Resolved int            `json:"resolved"`
	Critical int            `json:"critical"`
	Warning  int            `json:"warning"`
	ByType   map[string]int `json:"byType"`
}

// incidentsResponse mirrors web/src/types.ts IncidentsResponse.
type incidentsResponse struct {
	Counts   incidentsCounts      `json:"counts"`
	Items    []incidents.Incident `json:"items"`
	Continue string               `json:"continue,omitempty"`
}

// incidentWindow is the padded window logs and events are read in.
type incidentWindow struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

// incidentDetailResponse mirrors web/src/types.ts IncidentDetail.
type incidentDetailResponse struct {
	Incident   incidents.Incident       `json:"incident"`
	Window     incidentWindow           `json:"window"`
	Signals    []incidents.BundleSignal `json:"signals"`
	Events     []incidents.BundleEvent  `json:"events"`
	Audit      []audit.Event            `json:"audit,omitempty"`
	Series     []incidents.Series       `json:"series"`
	Thresholds []incidents.Threshold    `json:"thresholds,omitempty"`
	Related    []incidentRef            `json:"related"`
	Sources    map[string]string        `json:"sources"`
	Warnings   []string                 `json:"warnings,omitempty"`
}

// incidentLogsResponse mirrors web/src/types.ts IncidentLogsResponse.
type incidentLogsResponse struct {
	From      time.Time           `json:"from"`
	To        time.Time           `json:"to"`
	Source    string              `json:"source"`
	Lines     []incidents.LogLine `json:"lines"`
	Truncated bool                `json:"truncated"`
	Warnings  []string            `json:"warnings,omitempty"`
}

// incidentScope is what one caller may see of the incidents in a list.
type incidentScope struct {
	ns, audit                       auth.Scope
	nodes, clusterAudit, cloudtrail bool
}

func (s *Server) incidentScope(r *http.Request) incidentScope {
	return incidentScope{
		ns: s.scope(r, auth.ViewNamespace), audit: s.scope(r, auth.ViewAudit),
		nodes: s.can(r, auth.ViewNodes), clusterAudit: s.can(r, auth.ViewClusterAudit), cloudtrail: s.can(r, auth.ViewCloudTrail),
	}
}

// visible: a namespaced incident needs its namespace, a node or cluster
// one ViewNodes.
func (sc *incidentScope) visible(in *incidents.Incident) bool {
	if ns := in.Subject.Namespace; ns != "" {
		return sc.ns.Has(ns)
	}
	return sc.nodes
}

func (sc *incidentScope) auditOK(in *incidents.Incident) bool {
	if ns := in.Subject.Namespace; ns != "" {
		return sc.audit.Has(ns)
	}
	return sc.clusterAudit
}

// gateIncident leaves the signal types the caller may not see out of an
// incident's types and counts: audit changes without audit access, CloudTrail
// changes without ViewCloudTrail. It returns in itself when nothing is left
// out, sharing its slices and maps: never modify the result.
func gateIncident(in incidents.Incident, audit, cloudtrail bool) incidents.Incident {
	hide := func(t string) bool {
		return (t == incidents.TypeAuditChange && !audit) || (t == incidents.TypeCloudTrailChange && !cloudtrail)
	}
	if !hidesAny(in.Types, hide) && !hidesAnyKey(in.Counts, hide) {
		return in
	}
	out := in
	out.Types = make([]string, 0, len(in.Types))
	for _, t := range in.Types {
		if !hide(t) {
			out.Types = append(out.Types, t)
		}
	}
	out.Counts = make(map[string]int, len(in.Counts))
	for t, n := range in.Counts {
		if !hide(t) {
			out.Counts[t] = n
		}
	}
	return out
}

func hidesAny(l []string, hide func(string) bool) bool {
	for _, t := range l {
		if hide(t) {
			return true
		}
	}
	return false
}

func hidesAnyKey(m map[string]int, hide func(string) bool) bool {
	for t := range m {
		if hide(t) {
			return true
		}
	}
	return false
}

// incidentsFilter is a parsed list request.
type incidentsFilter struct {
	from, to  time.Time
	namespace string
	base      incidents.Query // owner, app, service, tags: before the counts
	severity  incidents.Severity
	types     []string
	state     incidents.State
	limit     int
	after     *incidents.Cursor
}

// incidentTypes are the signal types a type filter may name.
var incidentTypes = map[string]bool{
	incidents.TypeRequestSpike: true, incidents.TypeErrorRate: true, incidents.TypeMemorySpike: true, incidents.TypeOOMKill: true,
	incidents.TypeRestart: true, incidents.TypeCrashLoop: true, incidents.TypeEviction: true, incidents.TypeKubeEvent: true,
	incidents.TypeAlert: true, incidents.TypeDeploy: true, incidents.TypeScale: true, incidents.TypeAuditChange: true,
	incidents.TypeCloudTrailChange: true, incidents.TypeLogErrors: true,
}

// printable reports whether s is at most max bytes of printable text.
func printable(s string, max int) bool {
	return len(s) <= max && strings.IndexFunc(s, func(c rune) bool { return !unicode.IsPrint(c) }) < 0
}

// parseIncidentsFilter reads the list's query; it answers 400 and returns
// false when something is invalid.
func (s *Server) parseIncidentsFilter(w http.ResponseWriter, r *http.Request) (incidentsFilter, bool) {
	bad := func(msg string) (incidentsFilter, bool) {
		writeError(w, http.StatusBadRequest, msg)
		return incidentsFilter{}, false
	}
	q := r.URL.Query()
	o := s.Incidents.Options()
	now := s.now()
	var f incidentsFilter
	switch from, to := q.Get("from"), q.Get("to"); {
	case from != "" || to != "":
		if q.Get("window") != "" {
			return bad("use window, or from and to, not both")
		}
		if from == "" {
			return bad("to needs from")
		}
		t, err := time.Parse(time.RFC3339, from)
		if err != nil {
			return bad("from must be an RFC 3339 time, e.g. 2026-10-15T08:00:00Z")
		}
		f.from, f.to = t, now
		if to != "" {
			if f.to, err = time.Parse(time.RFC3339, to); err != nil {
				return bad("to must be an RFC 3339 time, e.g. 2026-10-15T09:00:00Z")
			}
		}
		if f.from.After(now) {
			return bad("from is in the future")
		}
		if f.to.After(now) {
			f.to = now
		}
		switch {
		case !f.to.After(f.from):
			return bad("to must be after from")
		case f.to.Sub(f.from) > incidents.MaxRange:
			return bad(fmt.Sprintf("the range is at most %s", formatHours(incidents.MaxRange)))
		case f.from.Before(now.Add(-o.Retention)):
			return bad(fmt.Sprintf("from is older than the incident retention (%s)", formatHours(o.Retention)))
		}
	default:
		d, err := durationParam(r, "window", incidents.MaxRange, time.Hour, incidents.MaxRange)
		if err != nil {
			return bad(err.Error())
		}
		f.from, f.to = now.Add(-d), now
	}
	var ok bool
	if f.namespace, ok = namespaceParam(w, r); !ok {
		return f, false
	}
	if f.base.Owner, ok = ownerParam(w, r); !ok {
		return f, false
	}
	if f.base.App = strings.TrimSpace(q.Get("app")); !printable(f.base.App, 253) {
		return bad("invalid app")
	}
	if f.base.Service = q.Get("service"); f.base.Service != "" && !validName(f.base.Service) {
		return bad("invalid service")
	}
	tags := q["tag"]
	if len(tags) > maxTagFilters {
		return bad(fmt.Sprintf("at most %d tag filters", maxTagFilters))
	}
	for _, kv := range tags {
		k, v, found := strings.Cut(kv, "=")
		if !found || !detectors.ValidLabelKey(k) || !printable(v, incidents.MaxAttrLen) {
			return bad("tag must be key=value with a label key, e.g. tag=app.kubernetes.io/part-of=shop")
		}
		if f.base.Tags == nil {
			f.base.Tags = map[string]string{}
		}
		f.base.Tags[k] = v
	}
	switch sev := incidents.Severity(q.Get("severity")); sev {
	case "", incidents.Critical, incidents.Warning:
		f.severity = sev
	default:
		return bad("severity must be critical or warning")
	}
	for _, v := range q["type"] {
		for _, t := range strings.Split(v, ",") {
			if t = strings.TrimSpace(t); t == "" {
				continue
			}
			if !incidentTypes[t] {
				return bad(fmt.Sprintf("unknown signal type %q", t))
			}
			f.types = append(f.types, t)
		}
	}
	switch st := incidents.State(q.Get("state")); st {
	case "", incidents.Open, incidents.Resolved:
		f.state = st
	default:
		return bad("state must be open or resolved")
	}
	pg, ok := pageParams(w, r, "incidents")
	if !ok {
		return f, false
	}
	f.limit = pg.limit
	if pg.after != "" {
		c, err := decodeIncidentCursor(pg.after)
		if err != nil {
			return bad(errBadToken.Error())
		}
		f.after = c
	}
	return f, true
}

// formatHours prints a duration in hours ("24h", "168h").
func formatHours(d time.Duration) string {
	return strconv.FormatFloat(d.Hours(), 'f', -1, 64) + "h"
}

// The continue token carries the last incident's start (Unix microseconds,
// as stores keep it) and ID.
func encodeIncidentCursor(in *incidents.Incident) string {
	c := incidents.CursorOf(in)
	return encodeToken("incidents", strconv.FormatInt(c.Start.UnixMicro(), 10)+"\x00"+c.ID)
}

func decodeIncidentCursor(key string) (*incidents.Cursor, error) {
	us, id, ok := strings.Cut(key, "\x00")
	n, err := strconv.ParseInt(us, 10, 64)
	if !ok || err != nil || id == "" {
		return nil, errBadToken
	}
	return &incidents.Cursor{Start: time.UnixMicro(n).UTC(), ID: id}, nil
}

// incidentsList answers GET /api/v1/incidents: the caller's incidents
// overlapping the range, newest first, a page at a time.
func (s *Server) incidentsList(w http.ResponseWriter, r *http.Request) {
	f, ok := s.parseIncidentsFilter(w, r)
	if !ok {
		return
	}
	s.prepareAuthz(r)
	sc := s.incidentScope(r)
	o := s.Incidents.Options()
	base := f.base
	base.From, base.To = f.from, f.to

	var list []incidents.Incident
	if f.from.Before(s.now().Add(-o.BoardWindow)) && s.IncidentStore != nil {
		// Older than the board: the store, with the scope pushed down.
		sq := base
		sq.Limit = incidentsStoreScan
		switch {
		case f.namespace != "":
			sq.Namespaces = map[string]bool{f.namespace: true}
		case !sc.ns.All:
			sq.Namespaces = map[string]bool{}
			for ns, held := range sc.ns.Namespaces {
				if held {
					sq.Namespaces[ns] = true
				}
			}
			sq.ClusterScoped = sc.nodes
		}
		var err error
		if list, err = s.IncidentStore.List(r.Context(), sq); err != nil {
			upstreamError(w, "the incident store", err)
			return
		}
	} else {
		list, _ = s.Incidents.Board().Snapshot()
	}

	resp := incidentsResponse{Items: []incidents.Incident{}, Counts: incidentsCounts{ByType: map[string]int{}}}
	page := incidents.Query{Severity: f.severity, Types: f.types, State: f.state, Before: f.after}
	var last *incidents.Incident
	for i := range list {
		in := &list[i]
		if !sc.visible(in) || (f.namespace != "" && in.Subject.Namespace != f.namespace) || !base.Matches(in) {
			continue
		}
		g := gateIncident(*in, sc.auditOK(in), sc.cloudtrail)
		countIncident(&resp.Counts, &g)
		if !page.Matches(&g) {
			continue
		}
		if len(resp.Items) == f.limit {
			if resp.Continue == "" && last != nil {
				resp.Continue = encodeIncidentCursor(last)
			}
			continue // keep counting
		}
		resp.Items = append(resp.Items, g)
		last = &resp.Items[len(resp.Items)-1]
	}
	writeJSON(w, http.StatusOK, resp)
}

func countIncident(c *incidentsCounts, in *incidents.Incident) {
	if in.State == incidents.Open {
		c.Open++
	} else {
		c.Resolved++
	}
	if in.PeakSeverity == incidents.Critical {
		c.Critical++
	} else {
		c.Warning++
	}
	for _, t := range in.Types {
		c.ByType[t]++
	}
}

// incidentsCacheKey adds the board's version to the list's response cache
// key, so a cached list never outlives the board it shows.
func (s *Server) incidentsCacheKey() string {
	if s.Incidents == nil {
		return ""
	}
	_, v := s.Incidents.Board().Snapshot()
	return "i" + strconv.FormatUint(v, 10)
}

// validIncidentID accepts what incidents.IncidentID makes (and a little
// more): letters, digits and dashes, at most 64 bytes.
func validIncidentID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '-') {
			return false
		}
	}
	return true
}

// errIncidentNotFound is the one answer for an unknown incident and one the
// caller may not see.
const errIncidentNotFound = "incident not found"

// visibleIncident resolves the incident the path names for a caller who
// may see it, and answers 404 (the same for an unknown ID and one out of
// scope) or 502 and returns false otherwise. An unknown ID is answered
// before any authorization review.
func (s *Server) visibleIncident(w http.ResponseWriter, r *http.Request) (incidents.Incident, bool) {
	id := r.PathValue("id")
	if !validIncidentID(id) {
		writeError(w, http.StatusNotFound, errIncidentNotFound)
		return incidents.Incident{}, false
	}
	in, _, ok, err := s.Incidents.Get(r.Context(), id)
	if err != nil {
		upstreamError(w, "the incident store", err)
		return incidents.Incident{}, false
	}
	if !ok || !s.incidentVisible(r, &in) {
		writeError(w, http.StatusNotFound, errIncidentNotFound)
		return incidents.Incident{}, false
	}
	return in, true
}

// incidentVisible checks one incident with one review: its namespace, or
// ViewNodes for a node or cluster subject.
func (s *Server) incidentVisible(r *http.Request, in *incidents.Incident) bool {
	if ns := in.Subject.Namespace; ns != "" {
		return allowed(r.Context(), s.Authorizer, auth.ViewNamespace, ns)
	}
	return s.can(r, auth.ViewNodes)
}

// incidentAccess is what a caller who may see an incident may see inside it.
type incidentAccess struct {
	audit, cloudtrail, nodes, logs bool
}

func (s *Server) incidentAccess(r *http.Request, in *incidents.Incident) incidentAccess {
	ctx, ns := r.Context(), in.Subject.Namespace
	a := incidentAccess{cloudtrail: s.can(r, auth.ViewCloudTrail), nodes: s.can(r, auth.ViewNodes)}
	if ns != "" {
		a.audit = allowed(ctx, s.Authorizer, auth.ViewAudit, ns)
		a.logs = allowed(ctx, s.Authorizer, auth.ViewPodLogs, ns)
	} else {
		a.audit = s.can(r, auth.ViewClusterAudit)
	}
	return a
}

// signalVisible gates one signal by its source.
func (a incidentAccess) signalVisible(sg *incidents.Signal) bool {
	switch sg.Type {
	case incidents.TypeAuditChange:
		return a.audit
	case incidents.TypeCloudTrailChange:
		return a.cloudtrail
	}
	return true
}

// gateSources reports the sources the caller may not see as forbidden.
func (a incidentAccess) gateSources(src map[string]string) map[string]string {
	out := make(map[string]string, len(src)+2)
	for k, v := range src {
		out[k] = v
	}
	if !a.audit {
		out["audit"] = "forbidden"
	}
	if !a.cloudtrail {
		out["cloudtrail"] = "forbidden"
	}
	if !a.logs {
		for k := range out {
			if k == "logs" || strings.HasPrefix(k, "logs:") {
				out[k] = "forbidden"
			}
		}
	}
	return out
}

// incidentDetail answers GET /api/v1/incidents/{id}.
func (s *Server) incidentDetail(w http.ResponseWriter, r *http.Request) {
	in, ok := s.visibleIncident(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	acc := s.incidentAccess(r, &in)
	d, ok, err := s.Incidents.Detail(ctx, in.ID, incidents.DetailOptions{EventLimit: incidentEventLimit})
	if err != nil {
		upstreamError(w, "the incident store", err)
		return
	}
	if !ok { // gone between the two reads (pruned)
		writeError(w, http.StatusNotFound, errIncidentNotFound)
		return
	}
	red := s.Incidents.Redactor()
	resp := incidentDetailResponse{
		Incident: gateIncident(d.Incident, acc.audit, acc.cloudtrail),
		Window:   incidentWindow{From: incidents.NormalTime(d.From), To: incidents.NormalTime(d.To)},
		Signals:  []incidents.BundleSignal{}, Events: []incidents.BundleEvent{}, Series: d.Series, Thresholds: d.Thresholds,
		Related: []incidentRef{}, Sources: acc.gateSources(d.Sources), Warnings: d.Warnings,
	}
	if resp.Series == nil {
		resp.Series = []incidents.Series{}
	}
	for i := range d.Signals {
		if sg := &d.Signals[i]; acc.signalVisible(sg) {
			resp.Signals = append(resp.Signals, incidents.BundleSignalOf(red.Signal(*sg)))
		}
	}
	for _, e := range d.Events {
		if !s.incidentEventVisible(r, &in, acc, &e) {
			continue
		}
		e.Message = red.String(e.Message)
		resp.Events = append(resp.Events, incidents.BundleEventOf(e))
	}
	if acc.audit {
		evs, err := s.Incidents.AuditEvents(ctx, &d.Incident, incidentAuditLimit)
		switch {
		case err != nil:
			slog.Warn("incident audit events", "incident", in.ID, "err", err)
			resp.Warnings = append(resp.Warnings, "Audit events are unavailable: could not query the audit store.")
		case evs != nil:
			resp.Audit = evs
		default:
			resp.Audit = []audit.Event{}
		}
	}
	for i := range d.Related {
		if rel := &d.Related[i]; s.incidentVisible(r, rel) {
			resp.Related = append(resp.Related, refOf(rel))
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// incidentEventVisible gates one Kubernetes event: an event about a node
// needs ViewNodes, one in another namespace than the incident's needs that
// namespace.
func (s *Server) incidentEventVisible(r *http.Request, in *incidents.Incident, acc incidentAccess, e *incidents.StoredEvent) bool {
	if e.Regarding.Kind == "Node" && !acc.nodes {
		return false
	}
	if e.Namespace != "" && e.Namespace != in.Subject.Namespace {
		return allowed(r.Context(), s.Authorizer, auth.ViewNamespace, e.Namespace)
	}
	return true
}

// incidentLogs answers GET /api/v1/incidents/{id}/logs?from&to&pod&container&level&q&source&limit:
// the incident's container logs in its padded window, redacted. They are
// read when asked and never kept, here or by any cache.
func (s *Server) incidentLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	in, ok := s.visibleIncident(w, r)
	if !ok {
		return
	}
	ns := in.Subject.Namespace
	if !allowed(r.Context(), s.Authorizer, auth.ViewPodLogs, ns) {
		writeError(w, http.StatusForbidden, "you may not read pod logs (get pods/log) in this namespace")
		return
	}
	req, ok := logRequestParams(w, r)
	if !ok {
		return
	}
	if ns == "" {
		writeJSON(w, http.StatusOK, incidentLogsResponse{Lines: []incidents.LogLine{}, Warnings: []string{"A node incident has no container logs of its own."}})
		return
	}
	res, err := s.Incidents.Logs(r.Context(), in.ID, req)
	switch {
	case errors.Is(err, incidents.ErrNotFound):
		writeError(w, http.StatusNotFound, errIncidentNotFound)
		return
	case errors.Is(err, incidents.ErrNoLogSource):
		if req.Source != "" && req.Source != "auto" {
			writeError(w, http.StatusBadRequest, "log source "+req.Source+" is not configured")
			return
		}
		writeJSON(w, http.StatusOK, incidentLogsResponse{Lines: []incidents.LogLine{}, Warnings: []string{"Logs are off: no log source is configured."}})
		return
	case err != nil:
		upstreamError(w, "logs", err)
		return
	}
	resp := incidentLogsResponse{From: incidents.NormalTime(res.From), To: incidents.NormalTime(res.To), Source: res.Source, Lines: res.Lines, Truncated: res.Truncated, Warnings: res.Warnings}
	if resp.Lines == nil {
		resp.Lines = []incidents.LogLine{}
	}
	writeJSON(w, http.StatusOK, resp)
}

// logLevels are the levels a log request may ask for (that level and more
// severe).
var logLevels = map[string]bool{"": true, "error": true, "warn": true, "info": true, "debug": true}

// logRequestParams parses the logs route's query; 400 and false when invalid.
func logRequestParams(w http.ResponseWriter, r *http.Request) (incidents.LogRequest, bool) {
	bad := func(msg string) (incidents.LogRequest, bool) {
		writeError(w, http.StatusBadRequest, msg)
		return incidents.LogRequest{}, false
	}
	q := r.URL.Query()
	var req incidents.LogRequest
	for _, p := range []struct {
		name string
		dst  *time.Time
	}{{"from", &req.From}, {"to", &req.To}} {
		if v := q.Get(p.name); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				return bad(p.name + " must be an RFC 3339 time")
			}
			*p.dst = t
		}
	}
	names := func(key string) ([]string, bool) {
		var out []string
		for _, v := range q[key] {
			for _, n := range strings.Split(v, ",") {
				if n = strings.TrimSpace(n); n == "" {
					continue
				}
				if !validName(n) {
					return nil, false
				}
				out = append(out, n)
			}
		}
		return out, len(out) <= 50
	}
	var ok bool
	if req.Pods, ok = names("pod"); !ok {
		return bad("invalid pod")
	}
	if req.Containers, ok = names("container"); !ok {
		return bad("invalid container")
	}
	if req.Level = q.Get("level"); !logLevels[req.Level] {
		return bad("level must be error, warn, info or debug")
	}
	if req.Text = q.Get("q"); !printable(req.Text, 256) {
		return bad("q must be printable text, at most 256 bytes")
	}
	switch req.Source = q.Get("source"); req.Source {
	case "", "auto", "kubernetes", "cloudwatch":
	default:
		return bad("source must be auto, kubernetes or cloudwatch")
	}
	limit, err := limitParam(r, 0)
	if err != nil {
		return bad(err.Error())
	}
	req.Limit = limit
	return req, true
}

// incidentBundle answers GET /api/v1/incidents/{id}/bundle?format=json|ndjson&require=all:
// everything about the incident for an agent to read. The sections the
// caller may not see are left out and named in omitted; with require=all
// that is a 403 instead.
func (s *Server) incidentBundle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	q := r.URL.Query()
	format := q.Get("format")
	if format != "" && format != "json" && format != "ndjson" {
		writeError(w, http.StatusBadRequest, "format must be json or ndjson")
		return
	}
	require := q.Get("require")
	if require != "" && require != "all" {
		writeError(w, http.StatusBadRequest, "require must be all")
		return
	}
	in, ok := s.visibleIncident(w, r)
	if !ok {
		return
	}
	acc := s.incidentAccess(r, &in)
	omitted := map[string]string{}
	if !acc.logs {
		omitted[incidents.SectionLogs] = "forbidden"
	}
	if !acc.audit {
		omitted[incidents.SectionAudit] = "forbidden"
	}
	if !acc.cloudtrail {
		omitted[incidents.SectionCloudTrail] = "forbidden"
	}
	if require == "all" && len(omitted) > 0 {
		names := make([]string, 0, len(omitted))
		for k := range omitted {
			names = append(names, k)
		}
		sort.Strings(names)
		writeError(w, http.StatusForbidden, "require=all, but you may not see: "+strings.Join(names, ", "))
		return
	}
	b, err := s.Incidents.Bundle(r.Context(), in.ID, incidents.BundleRequest{Omitted: omitted, Cluster: s.ClusterInfo.Name})
	switch {
	case errors.Is(err, incidents.ErrNotFound):
		writeError(w, http.StatusNotFound, errIncidentNotFound)
		return
	case err != nil:
		upstreamError(w, "the incident store", err)
		return
	}
	b.Incident = gateIncident(b.Incident, acc.audit, acc.cloudtrail)
	b.Window = incidents.BundleWindow{From: incidents.NormalTime(b.Window.From), To: incidents.NormalTime(b.Window.To)}
	if !acc.nodes || in.Subject.Namespace != "" {
		evs := b.Events[:0]
		for _, e := range b.Events {
			if (e.Regarding.Kind == "Node" && !acc.nodes) ||
				(e.Namespace != "" && e.Namespace != in.Subject.Namespace && !allowed(r.Context(), s.Authorizer, auth.ViewNamespace, e.Namespace)) {
				b.Truncated = withFlag(b.Truncated, incidents.SectionEvents)
				continue
			}
			evs = append(evs, e)
		}
		b.Events = evs
	}
	name := "incident-" + in.ID
	if format == "ndjson" {
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.ndjson"`)
		w.WriteHeader(http.StatusOK)
		if err := b.WriteNDJSON(w); err != nil {
			slog.Error("write incident bundle", "err", err)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.json"`)
	w.WriteHeader(http.StatusOK)
	if err := b.WriteJSON(w); err != nil {
		slog.Error("write incident bundle", "err", err)
	}
}

// withFlag sets m[k], making m when it is nil.
func withFlag(m map[string]bool, k string) map[string]bool {
	if m == nil {
		m = map[string]bool{}
	}
	m[k] = true
	return m
}

// infoIncidents is /info's incidents field (web/src/types.ts Info.incidents).
type infoIncidents struct {
	Enabled        bool              `json:"enabled"`
	Leader         bool              `json:"leader,omitempty"`
	Sources        map[string]string `json:"sources"`
	MaxRangeHours  float64           `json:"maxRangeHours"`
	LogLeadSeconds float64           `json:"logLeadSeconds"`
	LogLagSeconds  float64           `json:"logLagSeconds"`
}

// infoIncidents describes the incidents for /info; nil when they are off.
// A source's error is shown in full only to callers who may see what it
// reads (CloudTrail).
func (s *Server) infoIncidents(caps map[string]bool) *infoIncidents {
	if s.Incidents == nil {
		return nil
	}
	o := s.Incidents.Options()
	src := s.Incidents.Sources()
	if v := src["cloudtrail"]; strings.HasPrefix(v, "error") && !caps["cloudtrail"] {
		src["cloudtrail"] = "error"
	}
	return &infoIncidents{Enabled: true, Leader: s.Incidents.Leader(), Sources: src, MaxRangeHours: o.MaxRange.Hours(),
		LogLeadSeconds: o.LogLead.Seconds(), LogLagSeconds: o.LogLag.Seconds()}
}

// overviewIncidents is the Overview's incidents field: open incidents in
// the selection by (peak) severity.
type overviewIncidents struct {
	Open struct {
		Critical int `json:"critical"`
		Warning  int `json:"warning"`
	} `json:"open"`
}

// attnExtra is an item that joins the Overview's attention groups per
// request: a leak finding, an open incident.
type attnExtra struct {
	key  groupKey
	name string
	item attnItem
}

// selectedIncidents returns the board's open incidents in the Overview's
// selection, as attention items, with their counts. A node incident needs
// ViewNodes and, with a filter, a selected pod on the node; a cluster one
// ViewNodes and no filter. Nil counts mean incidents are off.
func (s *Server) selectedIncidents(v *snapshot.View, sel *ovSel) ([]attnExtra, *overviewIncidents) {
	if s.Incidents == nil {
		return nil, nil
	}
	out := &overviewIncidents{}
	list, _ := s.Incidents.Board().Snapshot()
	var extras []attnExtra
	for i := range list {
		in := &list[i]
		if in.State != incidents.Open {
			continue
		}
		sub := in.Subject
		switch {
		case sub.Namespace != "":
			if !sel.has(sub.Namespace) {
				continue
			}
		case !sel.nodes:
			continue
		case sub.Kind == incidents.KindNode:
			if sel.filtered && !runsSelectedPods(v, sub.Name, sel) {
				continue
			}
		case sel.filtered:
			continue
		}
		sev := detectors.StatusWarn
		if in.PeakSeverity == incidents.Critical {
			sev = detectors.StatusCrit
			out.Open.Critical++
		} else {
			out.Open.Warning++
		}
		extras = append(extras, attnExtra{key: groupKey{sub.Namespace, sub.Kind, sub.Name}, name: sub.Name, item: attnItem{
			severity: sev, category: catIncident, order: -float64(in.Start.Unix()), kind: "incident", title: clip(in.Title),
			href: uilink.Incident(in.ID), since: in.Start,
		}})
	}
	return extras, out
}

// podIncidents are the board's incidents (open, or resolved within its
// window) whose subject owns the pod, or that name it, newest first.
func (s *Server) podIncidents(v *snapshot.View, ns, pod string) []incidentRef {
	if s.Incidents == nil {
		return nil
	}
	var root incidents.Subject
	if p, ok := v.Assoc().PodNamed(ns, pod); ok {
		kind, name := v.Assoc().RootOf(p)
		root = incidents.Subject{Kind: kind, Namespace: ns, Name: name}
	}
	list, _ := s.Incidents.Board().Snapshot()
	out := []incidentRef{}
	for i := range list {
		in := &list[i]
		if in.Subject.Namespace != ns {
			continue
		}
		if (root.Name != "" && in.Subject == root) || containsString(in.Pods, pod) {
			out = append(out, refOf(in))
			if len(out) == incidentPodRefs {
				break
			}
		}
	}
	return out
}

func containsString(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
