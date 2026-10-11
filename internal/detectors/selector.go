package detectors

import (
	"slices"

	"github.com/ByronGary/kubesentry/internal/model"
)

// MatchSelector reports whether labels satisfy sel, with Kubernetes semantics:
// a nil selector matches nothing and an empty one matches everything.
func MatchSelector(sel *model.LabelSelector, labels map[string]string) bool {
	if sel == nil {
		return false
	}
	for k, v := range sel.MatchLabels {
		if got, ok := labels[k]; !ok || got != v {
			return false
		}
	}
	for _, r := range sel.MatchExpressions {
		v, ok := labels[r.Key]
		switch r.Operator {
		case "In":
			if !ok || !slices.Contains(r.Values, v) {
				return false
			}
		case "NotIn":
			if ok && slices.Contains(r.Values, v) {
				return false
			}
		case "Exists":
			if !ok {
				return false
			}
		case "DoesNotExist":
			if ok {
				return false
			}
		default: // an unknown operator never matches, as the API server would reject it
			return false
		}
	}
	return true
}

// PodsFor returns the pods in w's namespace that its selector matches. A
// CronJob runs pods through Jobs, so it matches none directly.
func PodsFor(w model.Workload, pods []model.Pod) []model.Pod {
	if w.Kind == "CronJob" {
		return nil
	}
	var out []model.Pod
	for _, p := range pods {
		if p.Namespace == w.Namespace && MatchSelector(w.Selector, p.Labels) {
			out = append(out, p)
		}
	}
	return out
}

// OwnerOf returns the workload whose selector matches p. When several do, a
// Deployment, StatefulSet or DaemonSet wins over a Job, then the name sorting
// first, so the answer does not depend on list order.
func OwnerOf(p model.Pod, ws []model.Workload) (kind, name string, ok bool) {
	best := -1
	for i, w := range ws {
		if w.Kind == "CronJob" || w.Namespace != p.Namespace || !MatchSelector(w.Selector, p.Labels) {
			continue
		}
		if best < 0 || ownerRank(w) < ownerRank(ws[best]) ||
			(ownerRank(w) == ownerRank(ws[best]) && w.Kind+"/"+w.Name < ws[best].Kind+"/"+ws[best].Name) {
			best = i
		}
	}
	if best < 0 {
		return "", "", false
	}
	return ws[best].Kind, ws[best].Name, true
}

func ownerRank(w model.Workload) int {
	if w.Kind == "Job" {
		return 1
	}
	return 0
}

// live reports whether a pod still runs or may run: not Succeeded or Failed.
func live(p model.Pod) bool { return p.Phase != "Succeeded" && p.Phase != "Failed" }
