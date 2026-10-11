package api

import (
	"context"
	"time"

	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/model"
	"github.com/ByronGary/kubesentry/internal/prom"
)

// A MetricsSource may also implement these.
type (
	// metricsAvailability lets a source that finds its Prometheus later
	// (discovery) say whether it has one yet; without it, a configured
	// source counts as available.
	metricsAvailability interface{ MetricsAvailable() bool }
	// leakReporter serves the background leak scan, for /oom when the
	// requested window is the scan's window.
	leakReporter interface {
		LeakReport() (report detectors.LeakReport, window time.Duration, ok bool)
	}
	// namespacedMetrics restricts the /oom queries to namespaces, for
	// callers who may not see the whole cluster. A source without it serves
	// such callers only the background leak report.
	namespacedMetrics interface {
		ContainerMemoryIn(ctx context.Context, namespaces []string, lookback, step time.Duration) ([]model.ContainerSeries, error)
		ContainerMemoryLimitsIn(ctx context.Context, namespaces []string) (map[model.ContainerKey]float64, error)
	}
)

// metrics returns the metrics source, or nil when there is none (yet).
func (s *Server) metrics() MetricsSource {
	if s.Metrics == nil {
		return nil
	}
	if a, ok := s.Metrics.(metricsAvailability); ok && !a.MetricsAvailable() {
		return nil
	}
	return s.Metrics
}

// prometheusInfo is /info's prometheus field. Its URL never carries user
// info: every signed-in user reads it.
func (s *Server) prometheusInfo() *PrometheusInfo {
	if s.PrometheusInfo != nil {
		if p := s.PrometheusInfo(); p != nil {
			out := *p
			out.URL = prom.Redact(out.URL)
			return &out
		}
	}
	if s.metrics() != nil {
		return &PrometheusInfo{Source: "flag"}
	}
	return &PrometheusInfo{Source: "none"}
}

// podLimits returns each container's memory limit from the pods themselves
// (prom.LimitsFromPods: the limit the kubelet applied, which follows in-place
// resizes, else the spec); limits the metrics source reports
// (kube-state-metrics, with -prometheus-ksm-limits) win.
func podLimits(pods []model.Pod, fromSource map[model.ContainerKey]float64) map[model.ContainerKey]float64 {
	out := prom.LimitsFromPods(pods)
	for k, v := range fromSource {
		out[k] = v
	}
	return out
}
