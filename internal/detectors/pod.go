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

	th *Thresholds // set by DiagnosePodWith; nil means the defaults
}

func (in PodInput) thresholds() Thresholds {
	if in.th != nil {
		return *in.th
	}
	return DefaultPolicy().Thresholds
}

// DiagnosePod runs the checks with the default policy.
func DiagnosePod(in PodInput) []Check { return DiagnosePodWith(in, compatPolicy()) }

// DiagnosePodWith runs the checks in a fixed order: phase, containers, OOM
// kills, restarts, memory growth, storage, activity. Thresholds come from p.
func DiagnosePodWith(in PodInput, p Policy) []Check {
	th := p.Thresholds
	in.th = &th
	return []Check{
		phaseCheck(in.Pod),
		containersCheck(in),
		oomCheck(in),
		restartCheck(in),
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
	if p.Unschedulable != "" {
		c.Detail += " Unschedulable: " + sentence(p.Unschedulable, "")
	}
	return c
}

// stuckReasons are container waiting reasons that do not clear by themselves.
var stuckReasons = map[string]bool{
	"CrashLoopBackOff":           true,
	"ImagePullBackOff":           true,
	"ErrImagePull":               true,
	"ErrImageNeverPull":          true,
	"InvalidImageName":           true,
	"CreateContainerConfigError": true,
	"CreateContainerError":       true,
	"RunContainerError":          true,
}

// waitingRank orders waiting reasons worst first: stuck ones, then the rest
// (ContainerCreating, PodInitializing).
func waitingRank(reason string) int {
	switch reason {
	case "CrashLoopBackOff":
		return 0
	case "ImagePullBackOff", "ErrImagePull", "ErrImageNeverPull", "InvalidImageName":
		return 1
	case "CreateContainerConfigError", "CreateContainerError", "RunContainerError":
		return 2
	}
	return 5
}

// waiting returns a container's waiting reason, "" unless it is waiting.
func waiting(c model.ContainerStatus) string {
	if c.State == "waiting" || (c.State == "" && stuckReasons[c.Reason]) {
		return c.Reason
	}
	return ""
}

// IsInitOnly reports whether a container status belongs to an ordinary init
// container: one that runs to completion before the app starts. Completed, it
// is terminated with reason Completed and never Ready, so its restarts,
// readiness, OOM kills and benign waiting states say nothing about the running
// pod and are left out of totals. Native sidecars (restartPolicy Always) run
// beside the app and count as app containers; internal/kube reports them like
// app containers, and an Init entry that is running is treated as one too.
func IsInitOnly(c model.ContainerStatus) bool { return c.Init && c.State != "running" }

// initFailure returns the reason an ordinary init container failed (Error,
// OOMKilled, ...) while it held the pod back, or "".
func initFailure(p *model.Pod, c model.ContainerStatus) string {
	if !c.Init || c.State != "terminated" || c.Reason == "" || c.Reason == "Completed" {
		return ""
	}
	if p.Phase != "Pending" && p.Phase != "Failed" {
		return ""
	}
	return c.Reason
}

// WaitingReason returns the worst waiting reason among a pod's containers
// (e.g. CrashLoopBackOff); "" when none waits. Init containers count only when
// they are stuck (CrashLoopBackOff, ImagePullBackOff, ...).
func WaitingReason(p *model.Pod) string {
	worst := ""
	for _, c := range p.Containers {
		r := waiting(c)
		if r == "" || (c.Init && !stuckReasons[r]) {
			continue
		}
		if worst == "" || waitingRank(r) < waitingRank(worst) {
			worst = r
		}
	}
	return worst
}

// podLevelReason is the pod's own status.reason and message (Evicted,
// NodeLost, UnexpectedAdmissionError, ...).
//
// INTEGRATION HOOK: model.Pod does not carry status.reason yet. Once it gains
// a pod-level Reason (and Message), return them here; PodReason,
// containersCheck and the map's pod status already use this function.
func podLevelReason(p *model.Pod) (reason, message string) {
	_ = p
	return "", ""
}

// PodReason is a short reason a pod is not plainly running: the pod's own
// reason (Evicted, ...), else a stuck container's waiting reason
// (CrashLoopBackOff), else an init container's failure (Error), else any
// other waiting reason (ContainerCreating), else Unschedulable or
// Terminating; "" otherwise.
func PodReason(p *model.Pod) string {
	if r, _ := podLevelReason(p); r != "" {
		return r
	}
	waitingFor := WaitingReason(p)
	if stuckReasons[waitingFor] {
		return waitingFor
	}
	for _, c := range p.Containers {
		if r := initFailure(p, c); r != "" {
			return r
		}
	}
	if waitingFor != "" {
		return waitingFor
	}
	if p.Unschedulable != "" {
		return "Unschedulable"
	}
	if !p.DeletedAt.IsZero() {
		return "Terminating"
	}
	return ""
}

// appContainers sums restarts over a pod's app containers and sidecars,
// leaving ordinary init containers out, and counts those containers.
func appContainers(p *model.Pod) (restarts int32, n int) {
	for _, c := range p.Containers {
		if !IsInitOnly(c) {
			restarts += c.RestartCount
			n++
		}
	}
	return restarts, n
}

// stuckContainers lists the containers that cannot get going by themselves,
// as "name: Reason", with the worst one's message: any container (init ones
// included) waiting in CrashLoopBackOff, ImagePullBackOff and the like, and an
// init container that failed while the pod was starting.
func stuckContainers(p *model.Pod) (stuck []string, worst, msg string) {
	for _, ct := range p.Containers {
		r := waiting(ct)
		if !stuckReasons[r] {
			if r = initFailure(p, ct); r == "" {
				continue
			}
		}
		name := ct.Name
		if ct.Init {
			name += " (init)"
		}
		stuck = append(stuck, name+": "+r)
		if worst == "" || waitingRank(r) < waitingRank(worst) {
			worst, msg = r, ct.Message
		}
	}
	return stuck, worst, msg
}

// notReadyFor reports how long a running pod has been not ready. ok is false
// for a ready or terminating pod, and when readiness was not reported.
func notReadyFor(p *model.Pod, now time.Time) (time.Duration, bool) {
	if p.Phase != "Running" || p.Ready || p.ReadyChanged.IsZero() || !p.DeletedAt.IsZero() {
		return 0, false
	}
	return now.Sub(p.ReadyChanged), true
}

// overdueTermination reports how long past its deletion time a pod still
// exists. The deletion timestamp already includes the pod's grace period.
func overdueTermination(p *model.Pod, now time.Time) (time.Duration, bool) {
	if p.DeletedAt.IsZero() {
		return 0, false
	}
	return now.Sub(p.DeletedAt), true
}

// containersCheck is crit when the pod itself was failed by the node (see
// podLevelReason) or a container is stuck: waiting in CrashLoopBackOff,
// ImagePullBackOff and the like (init containers included), or an init
// container failed while the pod was starting. It warns when the pod is still
// terminating TerminatingGrace past its deletion time, or has been running but
// not ready for longer than NotReadyGrace. Completed init containers, which
// are never ready, are not held against the pod.
func containersCheck(in PodInput) Check {
	c := Check{ID: "containers", Title: "Containers"}
	p, t := &in.Pod, in.thresholds()
	if r, msg := podLevelReason(p); r != "" {
		c.Status, c.Detail = StatusCrit, r+": "+sentence(msg, "no message")
		return c
	}
	if stuck, _, msg := stuckContainers(p); len(stuck) > 0 {
		c.Status = StatusCrit
		c.Detail = "Stuck: " + list(stuck) + "."
		if msg != "" {
			c.Detail += " " + sentence(msg, "")
		}
		return c
	}
	if d, ok := overdueTermination(p, in.Now); ok {
		if d > t.TerminatingGrace {
			c.Status = StatusWarn
			c.Detail = "Still terminating " + duration(d) + " after its deletion time; a finalizer or an unreachable node may be holding it."
			return c
		}
		c.Status, c.Detail = StatusOK, "Terminating."
		return c
	}
	if d, ok := notReadyFor(p, in.Now); ok && d > t.NotReadyGrace {
		var names []string
		for _, ct := range p.Containers {
			if !IsInitOnly(ct) && !ct.Ready {
				names = append(names, ct.Name)
			}
		}
		c.Status = StatusWarn
		c.Detail = "Running but not ready for " + duration(d) + "."
		if len(names) > 0 {
			c.Detail = "Running but not ready for " + duration(d) + ": " + list(names) + "."
		}
		return c
	}
	c.Status = StatusOK
	switch {
	case len(p.Containers) == 0:
		c.Detail = "No container status reported yet."
	case p.Ready:
		c.Detail = "All containers ready."
	default:
		c.Detail = "No container is stuck."
	}
	return c
}

func oomCheck(in PodInput) Check {
	c := Check{ID: "oom", Title: "Out-of-memory kills"}
	window := in.thresholds().OOMRecent
	var recent, older []string
	for _, ct := range in.Pod.Containers {
		if ct.LastTerminatedReason != "OOMKilled" || IsInitOnly(ct) {
			continue
		}
		age := in.Now.Sub(ct.LastTerminatedAt)
		entry := fmt.Sprintf("%s (%s)", ct.Name, ago(age))
		if age <= window {
			recent = append(recent, entry)
		} else {
			older = append(older, entry)
		}
	}
	switch {
	case len(recent) > 0:
		c.Status = StatusCrit
		c.Detail = "OOMKilled in the last " + span(window) + ": " + strings.Join(recent, ", ") + "."
	case len(older) > 0:
		c.Status = StatusWarn
		c.Detail = "OOMKilled earlier: " + strings.Join(older, ", ") + "."
	default:
		c.Status = StatusOK
		c.Detail = "No container was OOMKilled."
	}
	return c
}

func restartCheck(in PodInput) Check {
	c := Check{ID: "restarts", Title: "Restarts"}
	t := in.thresholds()
	total, n := appContainers(&in.Pod)
	switch {
	case total >= t.RestartCrit:
		c.Status = StatusCrit
	case total >= t.RestartWarn:
		c.Status = StatusWarn
	default:
		c.Status = StatusOK
	}
	if total == 0 {
		c.Detail = "No restarts."
	} else {
		c.Detail = fmt.Sprintf("%d restarts across %d containers.", total, n)
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
	case worst.TimeToLimitHours != nil && *worst.TimeToLimitHours < in.thresholds().LeakCritHours:
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
	window := "in the last " + span(in.thresholds().ActivityWindow)
	var parts []string
	if in.ExecCount > 0 {
		parts = append(parts, fmt.Sprintf("%d exec or attach %s", in.ExecCount, plural(in.ExecCount, "session", "sessions")))
	}
	if in.DeniedCount > 0 {
		parts = append(parts, fmt.Sprintf("%d denied %s", in.DeniedCount, plural(in.DeniedCount, "request", "requests")))
	}
	if len(parts) == 0 {
		c.Status = StatusOK
		c.Detail = "No exec sessions or denied requests " + window + "."
		return c
	}
	c.Status = StatusWarn
	c.Detail = strings.Join(parts, " and ") + " " + window + "."
	return c
}

// PodSummary is one row of the pods list.
type PodSummary struct {
	Namespace  string `json:"namespace"`
	Name       string `json:"name"`
	Phase      string `json:"phase"`
	Containers int    `json:"containers"`
	Restarts   int32  `json:"restarts"`
	OOMKilled  bool   `json:"oomKilled"`
	Ready      bool   `json:"ready"`
	Reason     string `json:"reason,omitempty"`   // see PodReason
	Node       string `json:"node,omitempty"`     //
	Workload   string `json:"workload,omitempty"` // "Kind/name" of the owner
}

// PodSummaryOf summarises one pod for the pods list. Containers, Restarts and
// OOMKilled cover app containers and sidecars, not ordinary init containers.
// a may be nil, which leaves Workload empty.
func PodSummaryOf(p *model.Pod, a *Assoc) PodSummary {
	s := PodSummary{
		Namespace: p.Namespace, Name: p.Name, Phase: p.Phase,
		Ready: p.Ready, Reason: PodReason(p), Node: p.NodeName,
	}
	s.Restarts, s.Containers = appContainers(p)
	for _, c := range p.Containers {
		if c.LastTerminatedReason == "OOMKilled" && !IsInitOnly(c) {
			s.OOMKilled = true
		}
	}
	if a != nil {
		s.Workload = a.WorkloadOf(p)
	}
	return s
}

// span names a look-back window: "day", "7 days", "6 hours", "30 minutes".
func span(d time.Duration) string {
	const day = 24 * time.Hour
	switch {
	case d == day:
		return "day"
	case d > day && d%day == 0:
		return fmt.Sprintf("%d days", int(d/day))
	case d == time.Hour:
		return "hour"
	case d > time.Hour && d%time.Hour == 0:
		return fmt.Sprintf("%d hours", int(d/time.Hour))
	case d >= time.Minute:
		n := int(d / time.Minute)
		return fmt.Sprintf("%d %s", n, plural(n, "minute", "minutes"))
	}
	return d.String()
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
