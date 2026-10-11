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
// steadily, in the caller's namespaces.
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

	if s.Metrics != nil {
		leaks, err := s.findLeaks(r.Context(), window, resp.Events, sc)
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
// the series in the caller's namespaces.
func (s *Server) findLeaks(ctx context.Context, window time.Duration, events []detectors.OOMEvent, sc auth.Scope) ([]detectors.LeakFinding, error) {
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
