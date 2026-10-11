package api

import (
	"context"
	"net/http"
	"net/http/pprof"
	"sort"
	"sync"
	"time"

	"github.com/ByronGary/kubesentry/internal/metrics"
)

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type readyResponse struct {
	Status string `json:"status"` // "ready" or "starting"
	// Degraded lists dependencies that fail now, with the reason. They do not
	// fail readiness: the last view keeps serving.
	Degraded    map[string]string `json:"degraded,omitempty"`
	Unavailable map[string]string `json:"unavailable,omitempty"`
}

// readyz answers 503 until Ready reports true, then 200; the body names the
// dependencies that are degraded (Checks) and the sources that cannot be read.
func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	s.readiness(w, r, true)
}

// readyzStatus is readyz for the web listener (no -ops-addr), which anyone
// reaching the UI can call: the status only, without dependency errors
// (hosts, users, SQL states) that the ops listener reports.
func (s *Server) readyzStatus(w http.ResponseWriter, r *http.Request) {
	s.readiness(w, r, false)
}

func (s *Server) readiness(w http.ResponseWriter, r *http.Request, detail bool) {
	resp := readyResponse{Status: "ready"}
	code := http.StatusOK
	if s.Ready != nil && !s.Ready() {
		resp.Status, code = "starting", http.StatusServiceUnavailable
	}
	if !detail {
		writeJSON(w, code, resp)
		return
	}
	resp.Degraded = s.runChecks(r.Context())
	if err := s.prometheusDown(); err != nil {
		resp.Degraded = mergeUnavailable(resp.Degraded, map[string]string{"prometheus": err.Error()})
	}
	if s.Unavailable != nil {
		if u := s.Unavailable(); len(u) > 0 {
			resp.Unavailable = u
		}
	}
	writeJSON(w, code, resp)
}

// prometheusDown is why Prometheus cannot be queried now, or nil.
func (s *Server) prometheusDown() error {
	if s.PrometheusHealth == nil {
		return nil
	}
	return s.PrometheusHealth()
}

// runChecks runs every check concurrently, each bounded to 2s, and returns
// the failures by name.
func (s *Server) runChecks(ctx context.Context) map[string]string {
	if len(s.Checks) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	var mu sync.Mutex
	var wg sync.WaitGroup
	out := map[string]string{}
	for _, c := range s.Checks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.Check(ctx); err != nil {
				mu.Lock()
				out[c.Name] = err.Error()
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if len(out) == 0 {
		return nil
	}
	return out
}

func metricsHandler() http.Handler { return metrics.Handler() }

// registerPprof serves the runtime profiles under /debug/pprof/.
func registerPprof(mux *http.ServeMux) {
	mux.HandleFunc("GET /debug/pprof/", pprof.Index)
	mux.HandleFunc("GET /debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("GET /debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("GET /debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("GET /debug/pprof/trace", pprof.Trace)
}

// mergeUnavailable joins source → reason maps; nil when all are empty.
func mergeUnavailable(ms ...map[string]string) map[string]string {
	var out map[string]string
	for _, m := range ms {
		for k, v := range m {
			if out == nil {
				out = map[string]string{}
			}
			out[k] = v
		}
	}
	return out
}

// sortedKeys returns m's keys in order.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
