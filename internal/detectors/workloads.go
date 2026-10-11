package detectors

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
)

// SummarizeWorkloads judges each workload from its status and the pods it
// owns, with the default policy. Pods without ownerReferences are matched by
// selector.
func SummarizeWorkloads(ws []model.Workload, pods []model.Pod, now time.Time) []WorkloadSummary {
	p := compatPolicy()
	return SummarizeWorkloadsWith(ws, Associate(listInventory(model.Inventory{Workloads: ws, Pods: pods}), p), p, now)
}

// listInventory marks the sources the older list-based entry points never
// have, so the association treats them as unknown rather than empty.
func listInventory(inv model.Inventory) model.Inventory {
	inv.Unavailable = map[string]string{}
	if inv.EndpointSlices == nil {
		inv.Unavailable[SourceEndpointSlices] = "not listed"
	}
	if inv.ReplicaSets == nil {
		inv.Unavailable[SourceReplicaSets] = "not listed"
	}
	return inv
}

// SummarizeWorkloadsWith judges each workload in ws from its status and the
// pods a associates with it. Most troubled first, then by namespace and name.
func SummarizeWorkloadsWith(ws []model.Workload, a *Assoc, p Policy, now time.Time) []WorkloadSummary {
	running := map[nsName]bool{} // CronJobs with a Job running now
	for i := range ws {
		if w := &ws[i]; w.Kind == "Job" && w.Active > 0 {
			if cj, _, ok := a.JobParent(w.Namespace, w.Name); ok {
				running[nsName{cj.Namespace, cj.Name}] = true
			}
		}
	}

	out := make([]WorkloadSummary, 0, len(ws))
	for i := range ws {
		w := &ws[i]
		s := WorkloadSummary{
			Kind: w.Kind, Namespace: w.Namespace, Name: w.Name,
			Desired: w.Desired, Ready: w.Ready, Updated: w.Updated, Available: w.Available,
			Images:  append([]string{}, w.Images...),
			Created: w.Created, Schedule: w.Schedule, Suspended: w.Suspended,
			LastScheduleTime: timePtr(w.LastScheduleTime), LastSuccessTime: timePtr(w.LastSuccessTime),
		}
		pending := 0
		stuck := map[string]int{}
		if w.Kind != "CronJob" {
			for _, pod := range a.PodsOf(Ref{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name}) {
				// A terminated pod's OOM kill still explains a failed Job, so it counts.
				for _, c := range pod.Containers {
					if c.LastTerminatedReason == "OOMKilled" && !IsInitOnly(c) {
						s.OOMKilled = true
					}
				}
				if !isLive(pod) {
					continue
				}
				s.Pods++
				if pod.Phase == "Pending" {
					pending++
				}
				restarts, _ := appContainers(pod)
				s.Restarts += restarts
				if readinessKnown(pod) && !pod.Ready {
					s.NotReady++
				}
				if r := WaitingReason(pod); r != "" {
					if s.Waiting == nil {
						s.Waiting = map[string]int{}
					}
					s.Waiting[r]++
					if stuckReasons[r] {
						stuck[r]++
					}
				}
			}
		}
		switch w.Kind {
		case "Job":
			s.Status, s.Detail = judgeJob(*w, s.Pods, pending)
		case "CronJob":
			s.Status, s.Detail = judgeCronJob(*w, running[nsName{w.Namespace, w.Name}], now)
		default:
			s.Status, s.Detail = judgeReplicas(*w)
		}
		if len(stuck) > 0 {
			// Status counters can look healthy while a surge pod crash-loops.
			if s.Status == StatusOK {
				s.Status = StatusWarn
			}
			s.Detail += " " + stuckDetail(stuck)
		}
		out = append(out, s)
	}

	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		switch {
		case statusRank(a.Status) != statusRank(b.Status):
			return statusRank(a.Status) < statusRank(b.Status)
		case a.Namespace != b.Namespace:
			return a.Namespace < b.Namespace
		case a.Name != b.Name:
			return a.Name < b.Name
		}
		return a.Kind < b.Kind
	})
	return out
}

// stuckDetail says "2 pods in CrashLoopBackOff, 1 in ImagePullBackOff."
func stuckDetail(stuck map[string]int) string {
	reasons := make([]string, 0, len(stuck))
	for r := range stuck {
		reasons = append(reasons, r)
	}
	sort.Slice(reasons, func(i, j int) bool {
		if waitingRank(reasons[i]) != waitingRank(reasons[j]) {
			return waitingRank(reasons[i]) < waitingRank(reasons[j])
		}
		return reasons[i] < reasons[j]
	})
	parts := make([]string, len(reasons))
	for i, r := range reasons {
		n := stuck[r]
		if i == 0 {
			parts[i] = fmt.Sprintf("%d %s in %s", n, plural(n, "pod", "pods"), r)
		} else {
			parts[i] = fmt.Sprintf("%d in %s", n, r)
		}
	}
	return list(parts) + "."
}

// judgeReplicas covers Deployments, StatefulSets and DaemonSets.
func judgeReplicas(w model.Workload) (string, string) {
	if w.Desired == 0 {
		if w.Kind == "DaemonSet" {
			return StatusOK, "No nodes to run on."
		}
		return StatusOK, "Scaled to zero."
	}
	if c, ok := condition(w.Conditions, "Progressing"); ok && c.Status == "False" && c.Reason == "ProgressDeadlineExceeded" {
		return StatusCrit, "Rollout stuck: " + sentence(c.Message, "progress deadline exceeded")
	}
	switch {
	case w.Ready == 0:
		return StatusCrit, fmt.Sprintf("0 of %d ready.", w.Desired)
	case w.Ready < w.Desired:
		return StatusWarn, fmt.Sprintf("%d of %d ready.", w.Ready, w.Desired)
	case w.Updated < w.Desired:
		return StatusWarn, fmt.Sprintf("Rollout in progress: %d of %d updated.", w.Updated, w.Desired)
	case w.Paused:
		return StatusWarn, "Rollout paused."
	}
	return StatusOK, fmt.Sprintf("%d of %d ready.", w.Desired, w.Desired)
}

func judgeJob(w model.Workload, livePods, pending int) (string, string) {
	if c, ok := condition(w.Conditions, "Failed"); ok && c.Status == "True" {
		return StatusCrit, "Failed: " + sentence(c.Message, c.Reason)
	}
	if c, ok := condition(w.Conditions, "Complete"); ok && c.Status == "True" {
		return StatusOK, "Completed."
	}
	if w.Active > 0 {
		// Pending pods count as active, but a Job whose pods cannot start is stuck.
		if livePods > 0 && pending == livePods {
			return StatusWarn, fmt.Sprintf("%d %s pending.", pending, plural(pending, "pod", "pods"))
		}
		return StatusOK, "Running."
	}
	return StatusWarn, "Not running and not complete."
}

func judgeCronJob(w model.Workload, running bool, now time.Time) (string, string) {
	switch {
	case w.Suspended:
		return StatusWarn, "Suspended."
	case running:
		// lastScheduleTime is already past lastSuccessfulTime while a run is in progress.
		return StatusOK, "Running now."
	case !w.LastSuccessTime.IsZero() && w.LastScheduleTime.After(w.LastSuccessTime):
		return StatusWarn, "Last run did not succeed."
	case w.LastScheduleTime.IsZero():
		return StatusOK, "Never run."
	}
	return StatusOK, "Last run " + ago(now.Sub(w.LastScheduleTime)) + "."
}

// cronJobOf returns the CronJob that created the Job named job, going by the
// controller's naming scheme: <cronjob>-<scheduled time in minutes>. The
// association uses it only for Jobs without ownerReferences.
func cronJobOf(ns, job string, ws []model.Workload) (string, bool) {
	i := strings.LastIndexByte(job, '-')
	if i <= 0 || i == len(job)-1 || strings.Trim(job[i+1:], "0123456789") != "" {
		return "", false
	}
	parent := job[:i]
	for _, w := range ws {
		if w.Kind == "CronJob" && w.Namespace == ns && w.Name == parent {
			return parent, true
		}
	}
	return "", false
}

func condition(cs []model.Condition, typ string) (model.Condition, bool) {
	for _, c := range cs {
		if c.Type == typ {
			return c, true
		}
	}
	return model.Condition{}, false
}

// sentence returns msg, or fallback when msg is empty, ending in a full stop.
func sentence(msg, fallback string) string {
	s := strings.TrimSpace(msg)
	if s == "" {
		s = fallback
	}
	if s == "" || strings.HasSuffix(s, ".") {
		return s
	}
	return s + "."
}

// statusRank orders statuses most urgent first.
func statusRank(s string) int {
	switch s {
	case StatusCrit:
		return 0
	case StatusWarn:
		return 1
	case StatusUnknown:
		return 2
	}
	return 3
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
