package api

import (
	"errors"
	"net/http"
	"regexp"
	"sort"
	"time"

	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/model"
)

// dnsName matches Kubernetes object and namespace names (DNS-1123 subdomains).
// Names reach Prometheus queries, so anything else is rejected up front.
var dnsName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`)

func validName(s string) bool { return len(s) <= 253 && dnsName.MatchString(s) }

const podActivityWindow = 7 * 24 * time.Hour

type podSummary struct {
	Namespace  string `json:"namespace"`
	Name       string `json:"name"`
	Phase      string `json:"phase"`
	Containers int    `json:"containers"`
	Restarts   int32  `json:"restarts"`
	OOMKilled  bool   `json:"oomKilled"`
}

type podsResponse struct {
	Count int          `json:"count"`
	Items []podSummary `json:"items"`
}

// pods lists pods, most troubled first: OOMKilled, then most restarts.
func (s *Server) pods(w http.ResponseWriter, r *http.Request) {
	ns := r.URL.Query().Get("namespace")
	if ns != "" && !validName(ns) {
		writeError(w, http.StatusBadRequest, "invalid namespace")
		return
	}
	pods, err := s.Cluster.ListPods(r.Context())
	if err != nil {
		upstreamError(w, "kubernetes", err)
		return
	}
	items := []podSummary{}
	for _, p := range pods {
		if ns != "" && p.Namespace != ns {
			continue
		}
		sum := podSummary{Namespace: p.Namespace, Name: p.Name, Phase: p.Phase, Containers: len(p.Containers)}
		for _, c := range p.Containers {
			sum.Restarts += c.RestartCount
			if c.LastTerminatedReason == "OOMKilled" {
				sum.OOMKilled = true
			}
		}
		items = append(items, sum)
	}
	sort.Slice(items, func(i, j int) bool {
		a, b := items[i], items[j]
		switch {
		case a.OOMKilled != b.OOMKilled:
			return a.OOMKilled
		case a.Restarts != b.Restarts:
			return a.Restarts > b.Restarts
		case a.Namespace != b.Namespace:
			return a.Namespace < b.Namespace
		}
		return a.Name < b.Name
	})
	writeJSON(w, http.StatusOK, podsResponse{Count: len(items), Items: items})
}

type containerDiag struct {
	Name                 string                 `json:"name"`
	RestartCount         int32                  `json:"restartCount"`
	LastTerminatedReason string                 `json:"lastTerminatedReason,omitempty"`
	LastTerminatedAt     *time.Time             `json:"lastTerminatedAt,omitempty"`
	LastExitCode         int32                  `json:"lastExitCode,omitempty"`
	LimitBytes           float64                `json:"limitBytes,omitempty"`
	CurrentBytes         float64                `json:"currentBytes,omitempty"`
	Series               [][2]float64           `json:"series"` // [unix ms, bytes]
	Leak                 *detectors.LeakFinding `json:"leak,omitempty"`
}

type podDiagnosticsResponse struct {
	Namespace        string                  `json:"namespace"`
	Name             string                  `json:"name"`
	Phase            string                  `json:"phase"`
	Window           string                  `json:"window"`
	MetricsAvailable bool                    `json:"metricsAvailable"`
	AuditAvailable   bool                    `json:"auditAvailable"`
	Checks           []detectors.Check       `json:"checks"`
	Containers       []containerDiag         `json:"containers"`
	Volumes          []detectors.VolumeState `json:"volumes"`
	Activity         []audit.Event           `json:"activity"`
	Warnings         []string                `json:"warnings,omitempty"`
}

// podDiagnostics builds the per-pod report: a verdict per check, memory history
// per container, mounted volumes and recent user activity against the pod.
// Missing data sources degrade to "unknown" checks and a warning, not an error.
func (s *Server) podDiagnostics(w http.ResponseWriter, r *http.Request) {
	ns, name := r.PathValue("namespace"), r.PathValue("name")
	if !validName(ns) || !validName(name) {
		writeError(w, http.StatusBadRequest, "invalid namespace or pod name")
		return
	}
	window, err := durationParam(r, "window", 6*time.Hour, 10*time.Minute, 7*24*time.Hour)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	ctx := r.Context()
	pod, err := s.Cluster.GetPod(ctx, ns, name)
	if errors.Is(err, model.ErrNotFound) {
		writeError(w, http.StatusNotFound, "pod not found")
		return
	}
	if err != nil {
		upstreamError(w, "kubernetes", err)
		return
	}

	resp := podDiagnosticsResponse{
		Namespace: ns, Name: name, Phase: pod.Phase, Window: window.String(),
		Containers: []containerDiag{}, Volumes: []detectors.VolumeState{}, Activity: []audit.Event{},
	}

	seen := map[string]bool{}
	for _, claim := range pod.Claims {
		if seen[claim] {
			continue
		}
		seen[claim] = true
		pvc, err := s.Cluster.GetPVC(ctx, ns, claim)
		if errors.Is(err, model.ErrNotFound) {
			resp.Volumes = append(resp.Volumes, detectors.VolumeState{Claim: claim})
			continue
		}
		if err != nil {
			upstreamError(w, "kubernetes", err)
			return
		}
		resp.Volumes = append(resp.Volumes, detectors.VolumeState{
			Claim: claim, Found: true, Phase: pvc.Phase, StorageClass: pvc.StorageClass, CapacityBytes: pvc.CapacityBytes,
		})
	}

	var series []model.ContainerSeries
	var limits map[model.ContainerKey]float64
	if s.Metrics != nil {
		step := window / 120
		if step < 30*time.Second {
			step = 30 * time.Second
		}
		series, limits, err = s.Metrics.PodMemory(ctx, ns, name, window, step.Round(time.Second))
		if err != nil {
			resp.Warnings = append(resp.Warnings, "Memory history is unavailable: could not query Prometheus.")
		} else {
			resp.MetricsAvailable = true
		}
	}

	var leaks []detectors.LeakFinding
	for _, c := range pod.Containers {
		key := model.ContainerKey{Namespace: ns, Pod: name, Container: c.Name}
		cd := containerDiag{
			Name: c.Name, RestartCount: c.RestartCount, LastTerminatedReason: c.LastTerminatedReason,
			LastExitCode: c.LastExitCode, LimitBytes: limits[key], Series: [][2]float64{},
		}
		if !c.LastTerminatedAt.IsZero() {
			t := c.LastTerminatedAt
			cd.LastTerminatedAt = &t
		}
		for _, ser := range series {
			if ser.Key != key {
				continue
			}
			for _, smp := range ser.Samples {
				cd.Series = append(cd.Series, [2]float64{float64(smp.T.UnixMilli()), smp.V})
			}
			if n := len(cd.Series); n > 0 {
				cd.CurrentBytes = cd.Series[n-1][1]
			}
			if f, ok := detectors.AnalyzeLeak(ser, cd.LimitBytes, s.LeakOptions); ok {
				cd.Leak = &f
				leaks = append(leaks, f)
			}
		}
		resp.Containers = append(resp.Containers, cd)
	}

	var execCount, deniedCount int
	if s.Audit != nil {
		resp.AuditAvailable = true
		resp.Activity = s.Audit.Query(audit.Query{
			Since:        s.now().Add(-podActivityWindow),
			Namespace:    ns,
			Resource:     "pods",
			Name:         name,
			Actors:       allActors,
			IncludeReads: true,
			Limit:        50,
		})
		for _, e := range resp.Activity {
			for _, t := range e.Tags {
				switch t {
				case audit.TagExec:
					execCount++
				case audit.TagDenied:
					deniedCount++
				}
			}
		}
	}

	resp.Checks = detectors.DiagnosePod(detectors.PodInput{
		Pod: *pod, Volumes: resp.Volumes, Leaks: leaks,
		MetricsAvailable: resp.MetricsAvailable, AuditAvailable: resp.AuditAvailable,
		ExecCount: execCount, DeniedCount: deniedCount, Now: s.now(),
	})
	writeJSON(w, http.StatusOK, resp)
}
