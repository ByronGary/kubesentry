package api

// The AI investigator's routes (docs/contracts.md "AI investigator"):
// POST /api/v1/incidents/{id}/investigations starts a run, GET lists the
// incident's runs and reads one, POST …/{iid}/cancel stops one. Runs are
// asynchronous: a start answers 202 at once and the UI polls the run.
//
// Who may do what: an unknown incident, or one the caller may not see, is
// not found before any other authorization review. Starting needs
// InvestigateIncidents in the incident's namespace (cluster-wide for a node
// or cluster incident). What the run may read inside the incident is the
// starter's access (logs, audit, CloudTrail, nodes), frozen at start;
// reading a run needs every part of it the run held, otherwise the run is
// not found (and lists count it as hidden). Only the starter may cancel.
// None of these responses is cached.

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/ByronGary/kubesentry/internal/auth"
	"github.com/ByronGary/kubesentry/internal/incidents"
	"github.com/ByronGary/kubesentry/internal/investigate"
)

// InvestigationsService runs investigations (*investigate.Service).
type InvestigationsService interface {
	Start(ctx context.Context, req investigate.StartRequest) (*investigate.Investigation, bool, error)
	Get(ctx context.Context, incidentID, id string, reader investigate.Access) (*investigate.Investigation, error)
	List(ctx context.Context, incidentID string, reader investigate.Access) ([]investigate.Summary, int, error)
	Cancel(ctx context.Context, incidentID, id, identity string) (*investigate.Investigation, error)
	Provider() string
	Options() investigate.Options
	PerHour() int
}

var _ InvestigationsService = (*investigate.Service)(nil)

// The routes' patterns.
const (
	investigationsRoute      = "GET /api/v1/incidents/{id}/investigations"
	investigationStartRoute  = "POST /api/v1/incidents/{id}/investigations"
	investigationRoute       = "GET /api/v1/incidents/{id}/investigations/{iid}"
	investigationCancelRoute = "POST /api/v1/incidents/{id}/investigations/{iid}/cancel"
)

const errInvestigationNotFound = "investigation not found"

// investigationStartResponse mirrors web/src/types.ts
// InvestigationStartResponse.
type investigationStartResponse struct {
	Investigation *investigate.Investigation `json:"investigation"`
	Cached        bool                       `json:"cached,omitempty"`
}

// investigationsResponse mirrors web/src/types.ts InvestigationsResponse.
type investigationsResponse struct {
	Items  []investigate.Summary `json:"items"`
	Hidden int                   `json:"hidden"`
}

// infoInvestigator is /info's investigator field (web/src/types.ts
// Info.investigator).
type infoInvestigator struct {
	Enabled  bool   `json:"enabled"`
	Provider string `json:"provider"`
	Model    string `json:"model"`
	Effort   string `json:"effort"`
	PerHour  int    `json:"perHour"`
}

// infoInvestigator describes the investigator; nil when it is off.
func (s *Server) infoInvestigator() *infoInvestigator {
	if s.Investigations == nil || s.Incidents == nil {
		return nil
	}
	o := s.Investigations.Options()
	return &infoInvestigator{Enabled: true, Provider: s.Investigations.Provider(), Model: o.Model, Effort: o.Effort,
		PerHour: s.Investigations.PerHour()}
}

// investigationRoutes registers the routes; the caller checked that
// incidents and the investigator are on.
func (s *Server) investigationRoutes(mux *http.ServeMux, t, long time.Duration) {
	s.route(mux, investigationsRoute, "incident_investigations", t, s.investigationsList)
	s.route(mux, investigationRoute, "incident_investigation", t, s.investigationDetail)
	// A start assembles the incident's digest (its logs too) before it
	// answers.
	mux.Handle(investigationStartRoute, Compose(WithMetrics("incident_investigate"), WithTimeout(long))(http.HandlerFunc(s.investigationStart)))
	mux.Handle(investigationCancelRoute, Compose(WithMetrics("incident_investigation_cancel"), WithTimeout(t))(http.HandlerFunc(s.investigationCancel)))
}

// investigationAccess is what the caller may read inside the incident, as
// a run records it.
func (s *Server) investigationAccess(r *http.Request, in *incidents.Incident) investigate.Access {
	a := s.incidentAccess(r, in)
	return investigate.Access{Logs: a.logs, Audit: a.audit, CloudTrail: a.cloudtrail, Nodes: a.nodes}
}

// mayInvestigate: InvestigateIncidents in the incident's namespace, or
// cluster-wide for a node or cluster incident.
func (s *Server) mayInvestigate(r *http.Request, in *incidents.Incident) bool {
	if ns := in.Subject.Namespace; ns != "" {
		return allowed(r.Context(), s.Authorizer, auth.InvestigateIncidents, ns)
	}
	return s.can(r, auth.InvestigateIncidents)
}

// identityName is who the caller is, as runs record it.
func identityName(r *http.Request) string {
	if id, ok := auth.FromContext(r.Context()); ok && id.User != "" {
		return id.User
	}
	return auth.AnonymousUser
}

// optionalJSON reads an optional JSON body: none at all is fine, anything
// else follows decodeJSON (415, 413, 400).
func optionalJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.ContentLength == 0 {
		return true
	}
	return decodeJSON(w, r, maxJSONBody, v)
}

// retryAfter sets Retry-After in whole seconds, at least one.
func retryAfter(w http.ResponseWriter, d time.Duration) {
	sec := int((d + time.Second - 1) / time.Second)
	if sec < 1 {
		sec = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(sec))
}

// investigationStart answers POST /api/v1/incidents/{id}/investigations
// with {fresh?}: 202 with the new run, or 200 with a completed run of the
// same input (cached, no model call, no quota used).
func (s *Server) investigationStart(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var req struct {
		Fresh bool `json:"fresh"`
	}
	if !optionalJSON(w, r, &req) {
		return
	}
	in, ok := s.visibleIncident(w, r)
	if !ok {
		return
	}
	if !s.mayInvestigate(r, &in) {
		msg := "investigating incidents needs create on investigations.kubesentry.io in this namespace"
		if in.Subject.Namespace == "" {
			msg = "investigating a node or cluster incident needs create on investigations.kubesentry.io cluster-wide"
		}
		writeError(w, http.StatusForbidden, msg)
		return
	}
	inv, cached, err := s.Investigations.Start(r.Context(), investigate.StartRequest{IncidentID: in.ID, RequestedBy: identityName(r),
		Access: s.investigationAccess(r, &in), Fresh: req.Fresh})
	var conflict *investigate.ConflictError
	var quota *investigate.QuotaError
	var busy *investigate.BusyError
	switch {
	case err == nil:
	case errors.Is(err, investigate.ErrIncidentNotFound), errors.Is(err, investigate.ErrNotFound):
		writeError(w, http.StatusNotFound, errIncidentNotFound)
		return
	case errors.As(err, &conflict):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "an investigation of this incident is already running",
			"runningId": conflict.RunningID})
		return
	case errors.As(err, &quota):
		retryAfter(w, quota.RetryAfter)
		writeError(w, http.StatusTooManyRequests, quota.Error())
		return
	case errors.As(err, &busy):
		retryAfter(w, busy.RetryAfter)
		writeError(w, http.StatusServiceUnavailable, busy.Error())
		return
	default:
		upstreamError(w, "the investigator", err)
		return
	}
	status := http.StatusAccepted
	if cached {
		status = http.StatusOK
	}
	writeJSON(w, status, investigationStartResponse{Investigation: inv, Cached: cached})
}

// investigationsList answers GET /api/v1/incidents/{id}/investigations:
// the runs the caller may read, newest first, and how many others.
func (s *Server) investigationsList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	in, ok := s.visibleIncident(w, r)
	if !ok {
		return
	}
	items, hidden, err := s.Investigations.List(r.Context(), in.ID, s.investigationAccess(r, &in))
	if err != nil {
		upstreamError(w, "the investigation store", err)
		return
	}
	if items == nil {
		items = []investigate.Summary{}
	}
	writeJSON(w, http.StatusOK, investigationsResponse{Items: items, Hidden: hidden})
}

// investigationDetail answers GET /api/v1/incidents/{id}/investigations/{iid}.
func (s *Server) investigationDetail(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	_, inv, ok := s.readableInvestigation(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, inv)
}

// readableInvestigation resolves the run the path names for a caller who
// may read it, answering 404 (an unknown incident or run, one out of scope,
// or one that used access the caller lacks) or 502 otherwise.
func (s *Server) readableInvestigation(w http.ResponseWriter, r *http.Request) (incidents.Incident, *investigate.Investigation, bool) {
	in, ok := s.visibleIncident(w, r)
	if !ok {
		return in, nil, false
	}
	iid := r.PathValue("iid")
	if !validIncidentID(iid) {
		writeError(w, http.StatusNotFound, errInvestigationNotFound)
		return in, nil, false
	}
	inv, err := s.Investigations.Get(r.Context(), in.ID, iid, s.investigationAccess(r, &in))
	switch {
	case errors.Is(err, investigate.ErrNotFound):
		writeError(w, http.StatusNotFound, errInvestigationNotFound)
		return in, nil, false
	case err != nil:
		upstreamError(w, "the investigation store", err)
		return in, nil, false
	}
	return in, inv, true
}

// investigationCancel answers POST …/investigations/{iid}/cancel: the
// starter stops their running run (403 for anyone else, 409 once it has
// finished).
func (s *Server) investigationCancel(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var req struct{}
	if !optionalJSON(w, r, &req) {
		return
	}
	in, inv, ok := s.readableInvestigation(w, r)
	if !ok {
		return
	}
	who := identityName(r)
	got, err := s.Investigations.Cancel(r.Context(), in.ID, inv.ID, who)
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, investigationStartResponse{Investigation: got})
	case errors.Is(err, investigate.ErrNotFound):
		writeError(w, http.StatusNotFound, errInvestigationNotFound)
	case errors.Is(err, investigate.ErrForbidden):
		writeError(w, http.StatusForbidden, "only the person who started an investigation may cancel it")
	case errors.Is(err, investigate.ErrNotRunning):
		writeError(w, http.StatusConflict, "the investigation is not running")
	default:
		upstreamError(w, "the investigation store", err)
	}
}
