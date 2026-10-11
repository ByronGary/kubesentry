package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/ByronGary/kubesentry/internal/auth"
	"github.com/ByronGary/kubesentry/internal/metrics"
	"github.com/ByronGary/kubesentry/internal/procmon"
)

// ProcessBackend stores reports from node agents and answers per-pod queries.
// procmon.Store implements it, and agentLister and storeOptions too.
type ProcessBackend interface {
	Update(r procmon.Report)
	ForPod(uid string) (procmon.PodView, bool)
}

type (
	// agentLister lists the node agents; with it, GET /api/v1/agents exists.
	agentLister interface{ Agents() []procmon.AgentStatus }
	// storeOptions tells how old process data is stale.
	storeOptions interface{ Options() procmon.StoreOptions }
)

const (
	maxAgentBody      = 8 << 20
	maxAgentProcesses = 20000
	// Agents report every 15s by default; data older than this is flagged.
	processStaleAfter = 2 * time.Minute
)

// agentReport receives a node snapshot, plain or gzipped. Like the audit
// webhook it fails closed without a token: anyone who could post here could
// invent process data.
func (s *Server) agentReport(w http.ResponseWriter, r *http.Request) {
	if s.AgentToken == "" {
		writeError(w, http.StatusServiceUnavailable, "agent endpoint disabled: no agent token configured")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAgentBody)
	rep, err := procmon.DecodeReport(r, maxAgentBody)
	switch {
	case errors.Is(err, procmon.ErrTooLarge):
		writeError(w, http.StatusRequestEntityTooLarge, "report too large")
		return
	case errors.Is(err, procmon.ErrUnsupportedEncoding):
		writeError(w, http.StatusUnsupportedMediaType, "unsupported content encoding: send plain or gzip JSON")
		return
	case err != nil:
		writeError(w, http.StatusBadRequest, "invalid report")
		return
	}
	if rep.Node == "" || len(rep.Node) > 253 || len(rep.Processes) > maxAgentProcesses {
		writeError(w, http.StatusBadRequest, "report needs a node name and at most 20000 processes")
		return
	}
	s.Processes.Update(rep)
	w.WriteHeader(http.StatusNoContent)
}

type processItem struct {
	PID       int     `json:"pid"`
	PPID      int     `json:"ppid"`
	Name      string  `json:"name"`
	Cmdline   string  `json:"cmdline"`
	Container string  `json:"container"`
	RSSBytes  int64   `json:"rssBytes"`
	Threads   int     `json:"threads"`
	CPUMillis float64 `json:"cpuMillicores"`
}

type processesResponse struct {
	Available  bool          `json:"available"`
	Node       string        `json:"node,omitempty"`
	ObservedAt *time.Time    `json:"observedAt,omitempty"`
	Stale      bool          `json:"stale"`
	Processes  []processItem `json:"processes"`
}

// podProcesses lists the processes running in one pod, as last reported by the
// agent on its node. "available: false" means no agent has seen the pod.
//
// The caller needs ViewNamespace to see the pod at all (404 otherwise) and
// ViewProcesses in its namespace for its processes (403 otherwise).
func (s *Server) podProcesses(w http.ResponseWriter, r *http.Request) {
	pod, _, ok := s.visiblePod(w, r)
	if !ok {
		return
	}
	if !allowed(r.Context(), s.Authorizer, auth.ViewProcesses, pod.Namespace) {
		writeError(w, http.StatusForbidden, "you may not see processes in this namespace")
		return
	}
	resp := processesResponse{Processes: []processItem{}}
	view, ok := s.Processes.ForPod(pod.UID)
	if pod.UID == "" || !ok {
		writeJSON(w, http.StatusOK, resp)
		return
	}
	names := map[string]string{}
	for _, c := range pod.Containers {
		if c.ContainerID != "" {
			names[c.ContainerID] = c.Name
		}
	}
	resp.Available, resp.Node = true, view.Node
	obs := view.ObservedAt
	resp.ObservedAt = &obs
	staleAfter := processStaleAfter
	if o, ok := s.Processes.(storeOptions); ok {
		staleAfter = o.Options().StaleAfter
	}
	resp.Stale = s.now().Sub(obs) > staleAfter
	for _, p := range view.Processes {
		c := names[p.ContainerID]
		switch {
		case c != "":
		case p.ContainerID == "":
			c = "pod sandbox"
		default:
			c = p.ContainerID[:min(12, len(p.ContainerID))]
		}
		resp.Processes = append(resp.Processes, processItem{
			PID: p.PID, PPID: p.PPID, Name: p.Name, Cmdline: p.Cmdline, Container: c,
			RSSBytes: p.RSSBytes, Threads: p.Threads, CPUMillis: p.CPUMillis,
		})
	}
	writeJSON(w, http.StatusOK, resp)
}

// agents lists every node agent with when it last reported and whether its
// data is stale. It needs the cluster-wide ViewAgents capability.
func (s *Server) agents(w http.ResponseWriter, r *http.Request) {
	if !s.can(r, auth.ViewAgents) {
		writeError(w, http.StatusForbidden, "you may not list the node agents")
		return
	}
	out := s.Processes.(agentLister).Agents()
	if out == nil {
		out = []procmon.AgentStatus{}
	}
	writeJSON(w, http.StatusOK, out)
}

// countReports feeds kubesentry_agent_reports_total{code}, including
// reports the token guard refuses.
func countReports(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		metrics.AgentReports.With(strconv.Itoa(sw.code())).Inc()
	})
}
