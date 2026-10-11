package api

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/auth"
	"github.com/ByronGary/kubesentry/internal/metrics"
)

// AuditBackend ingests audit payloads and serves queries over them.
// *audit.Ingester implements it; its Active store (memory or Postgres) is
// then queried directly, with paging, scope and error reporting.
type AuditBackend interface {
	IngestReader(r io.Reader) (int, error)
	Query(q audit.Query) []audit.Event
}

const (
	maxAuditBody    = 32 << 20
	defaultAuditWin = 24 * time.Hour
)

var allActors = map[string]bool{"user": true, "serviceaccount": true, "system": true}

// guard requires "Authorization: Bearer <token>" when token is non-empty.
func guard(token string, next http.HandlerFunc) http.HandlerFunc {
	if token == "" {
		return next
	}
	want := []byte("Bearer " + token)
	return func(w http.ResponseWriter, r *http.Request) {
		got := []byte(r.Header.Get("Authorization"))
		if subtle.ConstantTimeCompare(got, want) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r)
	}
}

// auditStore is the store queries read: the ingester's active store, or an
// adapter over an older AuditBackend.
func (s *Server) auditStore() audit.Store {
	if a, ok := s.Audit.(interface{ Active() audit.Store }); ok {
		if st := a.Active(); st != nil {
			return st
		}
	}
	return backendStore{s.Audit}
}

// backendStore adapts an AuditBackend that is not an Ingester to audit.Store.
type backendStore struct{ b AuditBackend }

func (b backendStore) Add(context.Context, []audit.Event) error {
	return errors.New("audit backend is read-only here")
}

func (b backendStore) Query(_ context.Context, q audit.Query) ([]audit.Event, error) {
	return b.b.Query(q), nil
}

func (b backendStore) Summarize(_ context.Context, q audit.Query) (audit.Summary, error) {
	q.Limit = 0
	return audit.Summarize(b.b.Query(q)), nil
}

func (b backendStore) Coverage(context.Context) (audit.Coverage, error) {
	return audit.Coverage{Backend: "memory"}, nil
}

// auditWebhook receives events from the kube-apiserver audit webhook backend,
// or from a script posting newline-delimited events. It fails closed: without
// a configured token anyone could inject fake audit records, so it refuses.
// A store that is busy (Postgres queue full) answers 503 with Retry-After,
// which the API server's webhook backend retries.
func (s *Server) auditWebhook(w http.ResponseWriter, r *http.Request) {
	if s.AuditToken == "" {
		writeError(w, http.StatusServiceUnavailable, "audit webhook disabled: no audit token configured")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAuditBody)
	var n int
	var err error
	if in, ok := s.Audit.(interface {
		Ingest(context.Context, io.Reader) (int, error)
	}); ok {
		n, err = in.Ingest(r.Context(), r.Body)
	} else {
		n, err = s.Audit.IngestReader(r.Body)
	}
	if err != nil {
		var tooBig *http.MaxBytesError
		switch {
		case errors.As(err, &tooBig):
			writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("payload exceeds %d MiB; send smaller batches", maxAuditBody>>20))
		case errors.Is(err, audit.ErrBackpressure):
			w.Header().Set("Retry-After", "5")
			writeError(w, http.StatusServiceUnavailable, "audit store is busy; retry later")
		default:
			writeError(w, http.StatusBadRequest, "invalid audit payload")
		}
		return
	}
	metrics.AuditIngested.With("webhook").Add(float64(n))
	writeJSON(w, http.StatusOK, map[string]int{"accepted": n})
}

type auditEventsResponse struct {
	Count    int           `json:"count"`
	Items    []audit.Event `json:"items"`
	Continue string        `json:"continue,omitempty"`
}

// auditEvents lists events, newest first, a page at a time, in the
// namespaces where the caller may read audit events (and cluster-scoped
// events with ViewClusterAudit). By default it shows the signal: it hides
// system components and untagged reads. See audit.Query.
func (s *Server) auditEvents(w http.ResponseWriter, r *http.Request) {
	q, err := s.parseAuditQuery(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	limit, err := limitParam(r, defaultPageLimit)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	q.Before, err = audit.DecodeCursor(r.URL.Query().Get("continue"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var items []audit.Event
	if s.auditScope(r, &q) {
		q.Limit = limit + 1 // one more tells whether there is a next page
		items, err = s.auditStore().Query(r.Context(), q)
		if err != nil {
			upstreamError(w, "audit store", err)
			return
		}
	}
	resp := auditEventsResponse{Items: items}
	if len(items) > limit {
		resp.Items = items[:limit]
		resp.Continue = audit.CursorOf(resp.Items[limit-1]).Encode()
	}
	if resp.Items == nil {
		resp.Items = []audit.Event{}
	}
	resp.Count = len(resp.Items)
	writeJSON(w, http.StatusOK, resp)
}

// auditScope narrows q to what the caller may read. It returns false when
// that is nothing at all (no namespace and no cluster-scoped events): the
// caller then answers empty without asking the store, so a query scoped to
// nothing never reaches a store (or its cache) at all.
func (s *Server) auditScope(r *http.Request, q *audit.Query) bool {
	s.prepareAuthz(r)
	sc := s.scope(r, auth.ViewAudit)
	if sc.All {
		q.Namespaces, q.ClusterScoped = nil, false
		return true
	}
	held := make(map[string]bool, len(sc.Namespaces))
	for ns, ok := range sc.Namespaces {
		if ok && ns != "" {
			held[ns] = true
		}
	}
	q.Namespaces = held // never nil: nil would mean every namespace
	q.ClusterScoped = s.can(r, auth.ViewClusterAudit)
	return len(held) > 0 || q.ClusterScoped
}

type auditSummaryResponse struct {
	Window string `json:"window"`
	audit.Summary
}

// auditSummary aggregates activity per user and per tag. Unlike /events it
// counts reads by default, and covers humans and service accounts but not
// system components, unless the actors parameter says otherwise.
func (s *Server) auditSummary(w http.ResponseWriter, r *http.Request) {
	q, err := s.parseAuditQuery(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	params := r.URL.Query()
	if params.Get("actors") == "" {
		q.Actors = map[string]bool{"user": true, "serviceaccount": true}
	}
	if params.Get("includeReads") == "" {
		q.IncludeReads = true
	}
	sum := audit.Summarize(nil)
	if s.auditScope(r, &q) {
		sum, err = s.auditStore().Summarize(r.Context(), q)
		if err != nil {
			upstreamError(w, "audit store", err)
			return
		}
	}
	window, _ := durationParam(r, "since", defaultAuditWin, time.Minute, 365*24*time.Hour) // already validated
	writeJSON(w, http.StatusOK, auditSummaryResponse{Window: window.String(), Summary: sum})
}

func (s *Server) parseAuditQuery(r *http.Request) (audit.Query, error) {
	p := r.URL.Query()
	since, err := durationParam(r, "since", defaultAuditWin, time.Minute, 365*24*time.Hour)
	if err != nil {
		return audit.Query{}, err
	}
	q := audit.Query{
		Since:     s.now().Add(-since),
		User:      p.Get("user"),
		Namespace: p.Get("namespace"),
		Resource:  p.Get("resource"),
		Verb:      p.Get("verb"),
		Tag:       p.Get("tag"),
	}
	if raw := p.Get("actors"); raw != "" {
		q.Actors = map[string]bool{}
		for _, a := range strings.Split(raw, ",") {
			a = strings.TrimSpace(a)
			if !allActors[a] {
				return audit.Query{}, fmt.Errorf("invalid actors value %q: use user, serviceaccount, system", a)
			}
			q.Actors[a] = true
		}
	}
	if raw := p.Get("includeReads"); raw != "" {
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return audit.Query{}, fmt.Errorf("invalid includeReads %q: use true or false", raw)
		}
		q.IncludeReads = b
	}
	return q, nil
}
