package detectors

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
)

// Check statuses. "unknown" means the data needed to judge is not available.
const (
	StatusOK      = "ok"
	StatusWarn    = "warn"
	StatusCrit    = "crit"
	StatusUnknown = "unknown"
)

// Check is one line of a pod's diagnostic report.
type Check struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

// VolumeState is a PVC a pod mounts, resolved against the cluster.
type VolumeState struct {
	Claim         string `json:"claim"`
	Found         bool   `json:"found"`
	Phase         string `json:"phase,omitempty"`
	StorageClass  string `json:"storageClass,omitempty"`
	CapacityBytes int64  `json:"capacityBytes,omitempty"`
}

// PodInput is everything DiagnosePod needs. Pure data, so it is testable
// without a cluster.
type PodInput struct {
	Pod              model.Pod
	Volumes          []VolumeState
	Leaks            []LeakFinding // findings for this pod's containers
	MetricsAvailable bool
	AuditAvailable   bool
	ExecCount        int // exec/attach sessions seen in the audit window
	DeniedCount      int // denied requests against this pod in the audit window
	Now              time.Time
}

// DiagnosePod runs the checks in a fixed order: phase, OOM kills, restarts,
// memory growth, storage, activity.
func DiagnosePod(in PodInput) []Check {
	return []Check{
		phaseCheck(in.Pod),
		oomCheck(in),
		restartCheck(in.Pod),
		memoryCheck(in),
		storageCheck(in.Volumes),
		activityCheck(in),
	}
}

func phaseCheck(p model.Pod) Check {
	c := Check{ID: "phase", Title: "Pod phase", Detail: "Pod is " + p.Phase + "."}
	switch p.Phase {
	case "Running", "Succeeded":
		c.Status = StatusOK
	case "Failed":
		c.Status = StatusCrit
	default: // Pending, Unknown
		c.Status = StatusWarn
	}
	return c
}

func oomCheck(in PodInput) Check {
	c := Check{ID: "oom", Title: "Out-of-memory kills"}
	var recent, older []string
	for _, ct := range in.Pod.Containers {
		if ct.LastTerminatedReason != "OOMKilled" {
			continue
		}
		age := in.Now.Sub(ct.LastTerminatedAt)
		entry := fmt.Sprintf("%s (%s)", ct.Name, ago(age))
		if age <= 24*time.Hour {
			recent = append(recent, entry)
		} else {
			older = append(older, entry)
		}
	}
	switch {
	case len(recent) > 0:
		c.Status = StatusCrit
		c.Detail = "OOMKilled in the last day: " + strings.Join(recent, ", ") + "."
	case len(older) > 0:
		c.Status = StatusWarn
		c.Detail = "OOMKilled earlier: " + strings.Join(older, ", ") + "."
	default:
		c.Status = StatusOK
		c.Detail = "No container was OOMKilled."
	}
	return c
}

func restartCheck(p model.Pod) Check {
	c := Check{ID: "restarts", Title: "Restarts"}
	var total int32
	for _, ct := range p.Containers {
		total += ct.RestartCount
	}
	switch {
	case total >= 10:
		c.Status = StatusCrit
	case total >= 3:
		c.Status = StatusWarn
	default:
		c.Status = StatusOK
	}
	if total == 0 {
		c.Detail = "No restarts."
	} else {
		c.Detail = fmt.Sprintf("%d restarts across %d containers.", total, len(p.Containers))
	}
	return c
}

func memoryCheck(in PodInput) Check {
	c := Check{ID: "memory", Title: "Memory growth"}
	if !in.MetricsAvailable {
		c.Status = StatusUnknown
		c.Detail = "Memory history is unavailable. Connect Prometheus to enable this check."
		return c
	}
	if len(in.Leaks) == 0 {
		c.Status = StatusOK
		c.Detail = "No steady memory growth in the selected window."
		return c
	}
	// Report the most urgent finding: soonest to its limit, else fastest growing.
	worst := in.Leaks[0]
	for _, l := range in.Leaks[1:] {
		if moreUrgent(l, worst) {
			worst = l
		}
	}
	rate := formatBytes(worst.SlopeBytesPerHour) + "/h"
	switch {
	case worst.TimeToLimitHours != nil && *worst.TimeToLimitHours < 6:
		c.Status = StatusCrit
		c.Detail = fmt.Sprintf("%s grows %s and reaches its memory limit in about %s.", worst.Container, rate, hours(*worst.TimeToLimitHours))
	case worst.TimeToLimitHours != nil:
		c.Status = StatusWarn
		c.Detail = fmt.Sprintf("%s grows %s and reaches its memory limit in about %s.", worst.Container, rate, hours(*worst.TimeToLimitHours))
	default:
		c.Status = StatusWarn
		c.Detail = fmt.Sprintf("%s grows %s. No memory limit is set, so nothing stops it growing.", worst.Container, rate)
	}
	return c
}

func moreUrgent(a, b LeakFinding) bool {
	switch {
	case a.TimeToLimitHours != nil && b.TimeToLimitHours != nil:
		return *a.TimeToLimitHours < *b.TimeToLimitHours
	case a.TimeToLimitHours != nil:
		return true
	case b.TimeToLimitHours != nil:
		return false
	}
	return a.SlopeBytesPerHour > b.SlopeBytesPerHour
}

func storageCheck(vols []VolumeState) Check {
	c := Check{ID: "storage", Title: "Volumes"}
	if len(vols) == 0 {
		c.Status = StatusOK
		c.Detail = "No persistent volumes mounted."
		return c
	}
	var missing, lost, notBound []string
	for _, v := range vols {
		switch {
		case !v.Found:
			missing = append(missing, v.Claim)
		case v.Phase == "Lost":
			lost = append(lost, v.Claim)
		case v.Phase != "Bound":
			notBound = append(notBound, v.Claim+" ("+v.Phase+")")
		}
	}
	switch {
	case len(missing) > 0:
		c.Status = StatusCrit
		c.Detail = "Claim does not exist: " + strings.Join(missing, ", ") + "."
	case len(lost) > 0:
		c.Status = StatusCrit
		c.Detail = "Claim lost its volume: " + strings.Join(lost, ", ") + "."
	case len(notBound) > 0:
		c.Status = StatusWarn
		c.Detail = "Claim not bound: " + strings.Join(notBound, ", ") + "."
	default:
		c.Status = StatusOK
		c.Detail = fmt.Sprintf("%d %s, all bound.", len(vols), plural(len(vols), "volume", "volumes"))
	}
	return c
}

func activityCheck(in PodInput) Check {
	c := Check{ID: "activity", Title: "User activity"}
	if !in.AuditAvailable {
		c.Status = StatusUnknown
		c.Detail = "Audit logging is not enabled."
		return c
	}
	var parts []string
	if in.ExecCount > 0 {
		parts = append(parts, fmt.Sprintf("%d exec or attach %s", in.ExecCount, plural(in.ExecCount, "session", "sessions")))
	}
	if in.DeniedCount > 0 {
		parts = append(parts, fmt.Sprintf("%d denied %s", in.DeniedCount, plural(in.DeniedCount, "request", "requests")))
	}
	if len(parts) == 0 {
		c.Status = StatusOK
		c.Detail = "No exec sessions or denied requests in the last 7 days."
		return c
	}
	c.Status = StatusWarn
	c.Detail = strings.Join(parts, " and ") + " in the last 7 days."
	return c
}

func ago(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

func hours(h float64) string {
	if h < 1 {
		m := int(h * 60)
		if m < 1 {
			m = 1
		}
		return fmt.Sprintf("%d %s", m, plural(m, "minute", "minutes"))
	}
	n := int(math.Round(h))
	return fmt.Sprintf("%d %s", n, plural(n, "hour", "hours"))
}

func formatBytes(b float64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GiB", b/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.0f MiB", b/(1<<20))
	default:
		return fmt.Sprintf("%.0f KiB", b/(1<<10))
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
