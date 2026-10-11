package api

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"time"

	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/auth"
	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/model"
	"github.com/ByronGary/kubesentry/internal/snapshot"
)

// dnsName matches Kubernetes object and namespace names (DNS-1123 subdomains).
// Names reach Prometheus queries, so anything else is rejected up front.
var dnsName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`)

func validName(s string) bool { return len(s) <= 253 && dnsName.MatchString(s) }

type podsResponse struct {
	Count    int                    `json:"count"`
	Items    []detectors.PodSummary `json:"items"`
	Continue string                 `json:"continue,omitempty"`
}

// podRows is every pod, most troubled first: OOMKilled, then most restarts.
func podRows(v *snapshot.View) []keyed[detectors.PodSummary] {
	return memoRows(v, "pods", func() []keyed[detectors.PodSummary] {
		a := v.Assoc()
		pods := v.Inv.Pods
		rows := make([]keyed[detectors.PodSummary], 0, len(pods))
		for i := range pods {
			sum := detectors.PodSummaryOf(&pods[i], a)
			oom := "1"
			if sum.OOMKilled {
				oom = "0"
			}
			rows = append(rows, keyed[detectors.PodSummary]{
				key: keyJoin(oom, keyDesc(int64(sum.Restarts)), sum.Namespace, sum.Name), ns: sum.Namespace, v: sum,
			})
		}
		return rows
	})
}

// pods lists the pods in the caller's namespaces, most troubled first, a page
// at a time.
func (s *Server) pods(w http.ResponseWriter, r *http.Request) {
	ns, ok := namespaceParam(w, r)
	if !ok {
		return
	}
	pg, ok := pageParams(w, r, "pods")
	if !ok {
		return
	}
	v, ok := s.view(w, r)
	if !ok {
		return
	}
	items, last := pageRows(podRows(v), pg.after, pg.limit, inScope[detectors.PodSummary](s.scope(r, auth.ViewNamespace), ns))
	writeJSON(w, http.StatusOK, podsResponse{Count: len(items), Items: items, Continue: encodeToken("pods", last)})
}

// getPod looks a pod up in the cluster source (fresh, and cheap from the
// informer cache) or, without one, in the view.
func (s *Server) getPod(ctx context.Context, v *snapshot.View, ns, name string) (*model.Pod, error) {
	if s.Cluster != nil {
		return s.Cluster.GetPod(ctx, ns, name)
	}
	for _, p := range v.Assoc().PodsIn(ns) {
		if p.Name == name {
			c := *p
			return &c, nil
		}
	}
	return nil, model.ErrNotFound
}

func (s *Server) getPVC(ctx context.Context, v *snapshot.View, ns, name string) (*model.PVC, error) {
	if s.Cluster != nil {
		return s.Cluster.GetPVC(ctx, ns, name)
	}
	for i := range v.Inv.PVCs {
		if p := &v.Inv.PVCs[i]; p.Namespace == ns && p.Name == name {
			c := *p
			return &c, nil
		}
	}
	return nil, model.ErrNotFound
}

// visiblePod resolves the pod named by the path for a caller who may see its
// namespace. It answers 400, 404 (also for a namespace the caller may not
// see, so existence does not leak) or 502 and returns false otherwise.
func (s *Server) visiblePod(w http.ResponseWriter, r *http.Request) (*model.Pod, *snapshot.View, bool) {
	ns, name := r.PathValue("namespace"), r.PathValue("name")
	if !validName(ns) || !validName(name) {
		writeError(w, http.StatusBadRequest, "invalid namespace or pod name")
		return nil, nil, false
	}
	v, ok := s.view(w, r)
	if !ok {
		return nil, nil, false
	}
	if !allowed(r.Context(), s.Authorizer, auth.ViewNamespace, ns) {
		writeError(w, http.StatusNotFound, "pod not found")
		return nil, nil, false
	}
	pod, err := s.getPod(r.Context(), v, ns, name)
	if errors.Is(err, model.ErrNotFound) {
		writeError(w, http.StatusNotFound, "pod not found")
		return nil, nil, false
	}
	if err != nil {
		upstreamError(w, "kubernetes", err)
		return nil, nil, false
	}
	return pod, v, true
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
	ActivityWindow   string                  `json:"activityWindow"` // Go duration of the activity look-back
	Warnings         []string                `json:"warnings,omitempty"`
}

// podDiagnostics builds the per-pod report: a verdict per check, memory history
// per container, mounted volumes and recent user activity against the pod.
// Missing data sources degrade to "unknown" checks and a warning, not an error.
func (s *Server) podDiagnostics(w http.ResponseWriter, r *http.Request) {
	window, err := durationParam(r, "window", 6*time.Hour, 10*time.Minute, 7*24*time.Hour)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	pod, v, ok := s.visiblePod(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	ns, name := pod.Namespace, pod.Name

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
		pvc, err := s.getPVC(ctx, v, ns, claim)
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
	limits := podLimits([]model.Pod{*pod}, nil)
	if m := s.metrics(); m != nil {
		step := window / 120
		if step < 30*time.Second {
			step = 30 * time.Second
		}
		var ksm map[model.ContainerKey]float64
		series, ksm, err = m.PodMemory(ctx, ns, name, window, step.Round(time.Second))
		if err != nil {
			resp.Warnings = append(resp.Warnings, "Memory history is unavailable: could not query Prometheus.")
		} else {
			resp.MetricsAvailable = true
			limits = podLimits([]model.Pod{*pod}, ksm)
		}
	}

	var leaks []detectors.LeakFinding
	for _, c := range pod.Containers {
		if detectors.IsInitOnly(c) {
			continue // ordinary init containers ran to completion; the containers check covers a stuck one
		}
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

	policy := v.Policy
	resp.ActivityWindow = policy.Thresholds.ActivityWindow.String()
	var execCount, deniedCount int
	if s.Audit != nil {
		if allowed(ctx, s.Authorizer, auth.ViewAudit, ns) {
			events, err := s.auditStore().Query(ctx, audit.Query{
				Since:        s.now().Add(-policy.Thresholds.ActivityWindow),
				Namespace:    ns,
				Resource:     "pods",
				Name:         name,
				Actors:       allActors,
				IncludeReads: true,
				Limit:        50,
			})
			if err != nil {
				resp.Warnings = append(resp.Warnings, "Activity is unavailable: could not query the audit store.")
			} else {
				resp.AuditAvailable = true
				resp.Activity = events
			}
		} else {
			resp.Warnings = append(resp.Warnings, "Activity is hidden: you may not read audit events in this namespace.")
		}
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

	resp.Checks = detectors.DiagnosePodWith(detectors.PodInput{
		Pod: *pod, Volumes: resp.Volumes, Leaks: leaks,
		MetricsAvailable: resp.MetricsAvailable, AuditAvailable: resp.AuditAvailable,
		ExecCount: execCount, DeniedCount: deniedCount, Now: s.now(),
	}, policy)
	writeJSON(w, http.StatusOK, resp)
}
