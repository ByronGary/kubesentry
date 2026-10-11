// Package api exposes the detectors over a small JSON HTTP API.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"time"

	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/model"
)

// ClusterSource lists Kubernetes objects.
type ClusterSource interface {
	ListPVCs(ctx context.Context) ([]model.PVC, error)
	ListPods(ctx context.Context) ([]model.Pod, error)
	// GetPod and GetPVC return model.ErrNotFound for a missing object.
	GetPod(ctx context.Context, namespace, name string) (*model.Pod, error)
	GetPVC(ctx context.Context, namespace, name string) (*model.PVC, error)
}

// MetricsSource provides container memory history. It is optional.
type MetricsSource interface {
	ContainerMemory(ctx context.Context, lookback, step time.Duration) ([]model.ContainerSeries, error)
	ContainerMemoryLimits(ctx context.Context) (map[model.ContainerKey]float64, error)
	// PodMemory returns history and limits for one pod's containers.
	PodMemory(ctx context.Context, namespace, pod string, lookback, step time.Duration) ([]model.ContainerSeries, map[model.ContainerKey]float64, error)
}

type Server struct {
	Cluster     ClusterSource
	Metrics     MetricsSource // nil disables leak detection
	Audit       AuditBackend  // nil disables the audit endpoints
	PVCOptions  detectors.PVCOptions
	LeakOptions detectors.LeakOptions
	// APIToken, if set, is required as a bearer token on every /api/ route.
	// Leave it empty only when the listener is not reachable by others.
	APIToken string
	// AuditToken is the bearer token the audit webhook requires. The webhook
	// refuses all requests while it is empty.
	AuditToken string
	// Processes, if set, enables process monitoring: the agent endpoint and per-pod process lists.
	Processes ProcessBackend
	// AgentToken is the bearer token node agents must send. The agent endpoint
	// refuses all requests while it is empty.
	AgentToken string
	// Inventory, if set, enables the map, workloads, nodes, storage and security routes.
	Inventory InventorySource
	// Certs, if set, enables the certificates route.
	Certs CertSource
	// UI, if set, serves the web interface for every path the API does not claim.
	UI http.Handler
	// Demo marks the data as synthetic so the UI can say so.
	Demo bool
	Now  func() time.Time // defaults to time.Now
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /api/v1/info", guard(s.APIToken, s.info))
	mux.HandleFunc("GET /api/v1/pvcs/unused", guard(s.APIToken, s.unusedPVCs))
	mux.HandleFunc("GET /api/v1/oom", guard(s.APIToken, s.oom))
	mux.HandleFunc("GET /api/v1/pods", guard(s.APIToken, s.pods))
	mux.HandleFunc("GET /api/v1/pods/{namespace}/{name}/diagnostics", guard(s.APIToken, s.podDiagnostics))
	if s.Audit != nil {
		mux.HandleFunc("POST /audit/webhook", guard(s.AuditToken, s.auditWebhook))
		mux.HandleFunc("GET /api/v1/audit/events", guard(s.APIToken, s.auditEvents))
		mux.HandleFunc("GET /api/v1/audit/summary", guard(s.APIToken, s.auditSummary))
	}
	if s.Processes != nil {
		mux.HandleFunc("POST /agent/report", guard(s.AgentToken, s.agentReport))
		mux.HandleFunc("GET /api/v1/pods/{namespace}/{name}/processes", guard(s.APIToken, s.podProcesses))
	}
	if s.Inventory != nil {
		mux.HandleFunc("GET /api/v1/workloads", guard(s.APIToken, s.workloads))
		mux.HandleFunc("GET /api/v1/nodes", guard(s.APIToken, s.nodes))
		mux.HandleFunc("GET /api/v1/storage", guard(s.APIToken, s.storage))
		mux.HandleFunc("GET /api/v1/security", guard(s.APIToken, s.security))
		mux.HandleFunc("GET /api/v1/map", guard(s.APIToken, s.topology))
	}
	if s.Certs != nil {
		mux.HandleFunc("GET /api/v1/certificates", guard(s.APIToken, s.certificates))
	}
	if s.UI != nil {
		mux.Handle("/", s.UI)
	}
	return mux
}

type unusedPVCResponse struct {
	Count                  int                   `json:"count"`
	TotalEstMonthlyCostUSD float64               `json:"totalEstMonthlyCostUSD"`
	Items                  []detectors.UnusedPVC `json:"items"`
}

func (s *Server) unusedPVCs(w http.ResponseWriter, r *http.Request) {
	opts := s.PVCOptions
	minAge, err := durationParam(r, "minAge", opts.MinAge, 0, 10*365*24*time.Hour)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	opts.MinAge = minAge

	pvcs, err := s.Cluster.ListPVCs(r.Context())
	if err != nil {
		upstreamError(w, "kubernetes", err)
		return
	}
	pods, err := s.Cluster.ListPods(r.Context())
	if err != nil {
		upstreamError(w, "kubernetes", err)
		return
	}

	items := detectors.FindUnusedPVCs(pvcs, pods, s.now(), opts)
	resp := unusedPVCResponse{Count: len(items), Items: items}
	for _, it := range items {
		resp.TotalEstMonthlyCostUSD += it.EstMonthlyCostUSD
	}
	writeJSON(w, http.StatusOK, resp)
}

type oomResponse struct {
	Window           string                  `json:"window"`
	MetricsAvailable bool                    `json:"metricsAvailable"`
	Events           []detectors.OOMEvent    `json:"events"`
	Leaks            []detectors.LeakFinding `json:"leaks"`
	Warnings         []string                `json:"warnings,omitempty"`
}

func (s *Server) oom(w http.ResponseWriter, r *http.Request) {
	window, err := durationParam(r, "window", 24*time.Hour, 10*time.Minute, 7*24*time.Hour)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	pods, err := s.Cluster.ListPods(r.Context())
	if err != nil {
		upstreamError(w, "kubernetes", err)
		return
	}
	now := s.now()
	resp := oomResponse{
		Window: window.String(),
		Events: detectors.FindOOMKills(pods, now.Add(-window)),
		Leaks:  []detectors.LeakFinding{},
	}

	if s.Metrics != nil {
		leaks, err := s.findLeaks(r.Context(), window, resp.Events)
		if err != nil {
			slog.Error("leak detection failed", "err", err)
			resp.Warnings = append(resp.Warnings, "leak detection unavailable: could not query Prometheus")
		} else {
			resp.MetricsAvailable = true
			resp.Leaks = leaks
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) findLeaks(ctx context.Context, window time.Duration, events []detectors.OOMEvent) ([]detectors.LeakFinding, error) {
	// ~240 points per series keeps queries cheap and well under Prometheus'
	// 11,000-point limit, while still giving slow leaks enough samples.
	step := window / 240
	if step < 30*time.Second {
		step = 30 * time.Second
	}
	step = step.Round(time.Second)

	series, err := s.Metrics.ContainerMemory(ctx, window, step)
	if err != nil {
		return nil, fmt.Errorf("memory series: %w", err)
	}
	limits, err := s.Metrics.ContainerMemoryLimits(ctx)
	if err != nil {
		return nil, fmt.Errorf("memory limits: %w", err)
	}

	oomByKey := make(map[model.ContainerKey]detectors.OOMEvent, len(events))
	for _, e := range events {
		oomByKey[e.ContainerKey] = e
	}

	out := []detectors.LeakFinding{}
	for _, ser := range series {
		f, ok := detectors.AnalyzeLeak(ser, limits[ser.Key], s.LeakOptions)
		if !ok {
			continue
		}
		if e, hit := oomByKey[ser.Key]; hit {
			f.OOMKilled = true
			t := e.LastOOMAt
			f.LastOOMAt = &t
		}
		out = append(out, f)
	}

	// Most urgent first: closest to its limit, then fastest growing.
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].TimeToLimitHours, out[j].TimeToLimitHours
		switch {
		case a != nil && b != nil && *a != *b:
			return *a < *b
		case (a == nil) != (b == nil):
			return a != nil
		}
		return out[i].SlopeBytesPerHour > out[j].SlopeBytesPerHour
	})
	return out, nil
}

// durationParam reads a Go-style duration query parameter such as "24h".
func durationParam(r *http.Request, name string, def, min, max time.Duration) (time.Duration, error) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return def, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid %s %q: use a duration like 24h or 90m", name, raw)
	}
	if d < min || d > max {
		return 0, fmt.Errorf("%s must be between %s and %s", name, min, max)
	}
	return d, nil
}

func upstreamError(w http.ResponseWriter, what string, err error) {
	slog.Error("upstream query failed", "upstream", what, "err", err)
	writeError(w, http.StatusBadGateway, "failed to query "+what)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("write response", "err", err)
	}
}
