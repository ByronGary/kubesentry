package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"time"

	"github.com/ByronGary/kubesentry/internal/auth"
	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/model"
	"github.com/ByronGary/kubesentry/internal/snapshot"
)

type oomResponse struct {
	Window           string                  `json:"window"`
	MetricsAvailable bool                    `json:"metricsAvailable"`
	Events           []detectors.OOMEvent    `json:"events"`
	Leaks            []detectors.LeakFinding `json:"leaks"`
	Warnings         []string                `json:"warnings,omitempty"`
}

// oomEvents is every container whose last termination was an OOM kill,
// newest first, once per view.
func oomEvents(v *snapshot.View) []detectors.OOMEvent {
	return v.Memo("api/oom", func() any { return detectors.FindOOMKills(v.Inv.Pods, time.Time{}) }).([]detectors.OOMEvent)
}

// oom lists OOM kills within the window and containers whose memory climbs
// steadily, in the caller's namespaces. Leaks come from the background scan
// when the window is the scan's own; any other window queries Prometheus for
// every container now, which is costly on large clusters.
func (s *Server) oom(w http.ResponseWriter, r *http.Request) {
	window, err := durationParam(r, "window", 24*time.Hour, 10*time.Minute, 7*24*time.Hour)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	v, ok := s.view(w, r)
	if !ok {
		return
	}
	sc := s.scope(r, auth.ViewNamespace)
	since := s.now().Add(-window)
	resp := oomResponse{Window: window.String(), Events: []detectors.OOMEvent{}, Leaks: []detectors.LeakFinding{}}
	for _, e := range oomEvents(v) {
		if !e.LastOOMAt.Before(since) && sc.Has(e.Namespace) {
			resp.Events = append(resp.Events, e)
		}
	}

	m := s.metrics()
	if lr, ok := m.(leakReporter); ok {
		if rep, win, ok := lr.LeakReport(); ok && win == window && !rep.GeneratedAt.IsZero() {
			resp.MetricsAvailable = true
			for _, f := range rep.Findings {
				if sc.Has(f.Namespace) {
					resp.Leaks = append(resp.Leaks, f)
				}
			}
			for _, msg := range rep.Warnings {
				resp.Warnings = append(resp.Warnings, "leak scan: "+msg)
			}
			if len(rep.Errors) > 0 {
				resp.Warnings = append(resp.Warnings, fmt.Sprintf("leak scan of %s had errors; findings may be incomplete", rep.LastAttempt.UTC().Format(time.RFC3339)))
			}
			writeJSON(w, http.StatusOK, resp)
			return
		}
	}
	if m != nil {
		leaks, err := s.findLeaks(r.Context(), m, v, window, resp.Events, sc)
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

// findLeaks queries every container's memory over the window and analyses
// the series in the caller's namespaces. Limits come from the pod specs
// unless the source reports them (kube-state-metrics).
func (s *Server) findLeaks(ctx context.Context, m MetricsSource, v *snapshot.View, window time.Duration, events []detectors.OOMEvent, sc auth.Scope) ([]detectors.LeakFinding, error) {
	// ~240 points per series keeps queries cheap and well under Prometheus'
	// 11,000-point limit, while still giving slow leaks enough samples.
	step := window / 240
	if step < 30*time.Second {
		step = 30 * time.Second
	}
	step = step.Round(time.Second)

	series, err := m.ContainerMemory(ctx, window, step)
	if err != nil {
		return nil, fmt.Errorf("memory series: %w", err)
	}
	ksm, err := m.ContainerMemoryLimits(ctx)
	if err != nil {
		return nil, fmt.Errorf("memory limits: %w", err)
	}
	limits := podLimits(v.Inv.Pods, ksm)

	oomByKey := make(map[model.ContainerKey]detectors.OOMEvent, len(events))
	for _, e := range events {
		oomByKey[e.ContainerKey] = e
	}

	out := []detectors.LeakFinding{}
	for _, ser := range series {
		if !sc.Has(ser.Key.Namespace) {
			continue
		}
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
	sortLeaks(out)
	return out, nil
}

// sortLeaks puts the most urgent first: closest to its limit, then fastest
// growing.
func sortLeaks(out []detectors.LeakFinding) {
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
}
