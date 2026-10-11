package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
	"github.com/ByronGary/kubesentry/internal/procmon"
)

// ProcessBackend stores reports from node agents and answers per-pod queries.
type ProcessBackend interface {
	Update(r procmon.Report)
	ForPod(uid string) (procmon.PodView, bool)
}

const (
	maxAgentBody      = 8 << 20
	maxAgentProcesses = 20000
	// Agents report every 15s by default; data older than this is flagged.
	processStaleAfter = 2 * time.Minute
)

// agentReport receives a node snapshot. Like the audit webhook it fails closed
// without a token: anyone who could post here could invent process data.
func (s *Server) agentReport(w http.ResponseWriter, r *http.Request) {
	if s.AgentToken == "" {
		writeError(w, http.StatusServiceUnavailable, "agent endpoint disabled: no agent token configured")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxAgentBody)
	var rep procmon.Report
	if err := decodeJSON(r, &rep); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, "report too large")
			return
		}
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
func (s *Server) podProcesses(w http.ResponseWriter, r *http.Request) {
	ns, name := r.PathValue("namespace"), r.PathValue("name")
	if !validName(ns) || !validName(name) {
		writeError(w, http.StatusBadRequest, "invalid namespace or pod name")
		return
	}
	pod, err := s.Cluster.GetPod(r.Context(), ns, name)
	if errors.Is(err, model.ErrNotFound) {
		writeError(w, http.StatusNotFound, "pod not found")
		return
	}
	if err != nil {
		upstreamError(w, "kubernetes", err)
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
	resp.Stale = s.now().Sub(obs) > processStaleAfter
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

func decodeJSON(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}
