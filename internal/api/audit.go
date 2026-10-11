package api

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ByronGary/kubesentry/internal/audit"
)

// AuditBackend ingests audit payloads and serves queries over them.
type AuditBackend interface {
	IngestReader(r io.Reader) (int, error)
	Query(q audit.Query) []audit.Event
}

const (
	maxAuditBody    = 32 << 20
	defaultAuditWin = 24 * time.Hour
	maxAuditLimit   = 1000
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

// auditWebhook receives events from the kube-apiserver audit webhook backend,
// or from a script posting newline-delimited events. It fails closed: without
// a configured token anyone could inject fake audit records, so it refuses.
func (s *Server) auditWebhook(w http.ResponseWriter, r *http.Request) {
	if s.AuditToken == "" {
		writeError(w, http.StatusServiceUnavailable, "audit webhook disabled: no audit token configured")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAuditBody)
	n, err := s.Audit.IngestReader(r.Body)
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("payload exceeds %d MiB; send smaller batches", maxAuditBody>>20))
			return
		}
		writeError(w, http.StatusBadRequest, "invalid audit payload")
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"accepted": n})
}

type auditEventsResponse struct {
	Count int           `json:"count"`
	Items []audit.Event `json:"items"`
}

// auditEvents lists events, newest first. By default it shows the signal: it
// hides system components and untagged reads. See audit.Query.
func (s *Server) auditEvents(w http.ResponseWriter, r *http.Request) {
	q, err := s.parseAuditQuery(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	q.Limit, err = limitParam(r, 100)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	items := s.Audit.Query(q)
	writeJSON(w, http.StatusOK, auditEventsResponse{Count: len(items), Items: items})
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
	window, _ := durationParam(r, "since", defaultAuditWin, time.Minute, 365*24*time.Hour) // already validated
	writeJSON(w, http.StatusOK, auditSummaryResponse{Window: window.String(), Summary: audit.Summarize(s.Audit.Query(q))})
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

func limitParam(r *http.Request, def int) (int, error) {
	raw := r.URL.Query().Get("limit")
	if raw == "" {
		return def, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > maxAuditLimit {
		return 0, fmt.Errorf("limit must be an integer between 1 and %d", maxAuditLimit)
	}
	return n, nil
}
