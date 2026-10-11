package verify

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ByronGary/kubesentry/test/stress/internal/truth"
)

// Mismatch is one disagreement, attributed to a case and a category.
type Mismatch struct {
	Case     string `json:"case"`     // tricky case ID, or "generated" / "system"
	Category string `json:"category"` // e.g. "pod-owner: wrong owner"
	Source   string `json:"source"`
	Detail   string `json:"detail"`
}

// Group is mismatches with the same case and category.
type Group struct {
	Case     string   `json:"case"`
	Category string   `json:"category"`
	Count    int      `json:"count"`
	Sources  []string `json:"sources"`
	Samples  []string `json:"samples"`
}

// caseOf attributes an edge to a tricky case through the case label of its
// pod, or to "generated" or "system" by namespace.
func caseOf(t *truth.Truth, generated map[string]bool, ids ...string) string {
	for _, id := range ids {
		if kindOf(id) == "Pod" {
			ns := NamespaceOf(id)
			if p := t.Pods[ns+"/"+strings.TrimPrefix(id, "Pod/"+ns+"/")]; p != nil {
				if c := p.Labels["kubesentry.io/stress-case"]; c != "" {
					return c
				}
			}
		}
	}
	for _, id := range ids {
		ns := NamespaceOf(id)
		switch {
		case ns == "":
			continue
		case strings.HasPrefix(ns, "stress-"):
			return ns
		case generated[ns]:
			return "generated"
		default:
			return "system"
		}
	}
	return "system"
}

// Categorize turns missing and extra edges of one relation into mismatches.
// For pod-owner it pairs them per pod: a pod with a missing and an extra
// owner edge has a wrong owner.
func Categorize(t *truth.Truth, generated map[string]bool, rel, source string, missing, extra []string) []Mismatch {
	var out []Mismatch
	switch rel {
	case truth.PodOwner:
		obsOwner := map[string]string{}
		for _, e := range extra {
			from, to := Split(e)
			obsOwner[to] = from
		}
		truthOwner := map[string]string{}
		for _, e := range missing {
			from, to := Split(e)
			truthOwner[to] = from
		}
		for pod, want := range truthOwner {
			c := caseOf(t, generated, pod)
			if got, ok := obsOwner[pod]; ok {
				out = append(out, Mismatch{c, "pod-owner: wrong owner (" + kindOf(got) + " instead of " + kindOf(want) + ")", source,
					fmt.Sprintf("%s owned by %s, reported %s", pod, want, got)})
			} else {
				out = append(out, Mismatch{c, "pod-owner: owner not reported (" + kindOf(want) + ")", source, fmt.Sprintf("%s owned by %s", pod, want)})
			}
		}
		for pod, got := range obsOwner {
			if _, ok := truthOwner[pod]; ok {
				continue
			}
			c := caseOf(t, generated, pod)
			reason := "pod has no workload owner"
			if p := podOf(t, pod); p == nil {
				reason = "pod not in ground truth (gone or not shown)"
			} else if p.Top != "" {
				reason = "pod owned by " + p.Top
			}
			out = append(out, Mismatch{c, "pod-owner: spurious owner", source, fmt.Sprintf("%s reported under %s; %s", pod, got, reason)})
		}
	case truth.ServicePods:
		eps := map[string]truth.Endpoint{}
		for _, list := range t.Endpoints {
			for _, ep := range list {
				eps[ep.Pod] = ep
			}
		}
		for _, e := range missing {
			svc, pod := Split(e)
			ep := eps[pod]
			cat := "service-pods: endpoint not reported"
			switch {
			case ep.Terminating:
				cat = "service-pods: terminating endpoint not reported"
			case !ep.Ready:
				cat = "service-pods: not-ready endpoint not reported"
			}
			out = append(out, Mismatch{caseOf(t, generated, pod, svc), cat, source, e})
		}
		for _, e := range extra {
			svc, pod := Split(e)
			cat := "service-pods: pod reported but not an endpoint"
			if p := podOf(t, pod); p != nil {
				switch {
				case !p.Live():
					cat = "service-pods: terminal pod reported"
				case p.Terminating:
					cat = "service-pods: terminating pod reported"
				}
			}
			out = append(out, Mismatch{caseOf(t, generated, pod, svc), cat, source, e})
		}
	case truth.SecurityGroup:
		for _, e := range missing {
			g, _ := Split(e)
			out = append(out, Mismatch{caseOfWorkload(t, generated, g), "security: group not reported (" + kindOf(g) + ")", source, g})
		}
		for _, e := range extra {
			g, _ := Split(e)
			out = append(out, Mismatch{caseOfWorkload(t, generated, g), "security: unexpected group (" + kindOf(g) + ")", source, g})
		}
	default:
		for _, e := range missing {
			from, to := Split(e)
			out = append(out, Mismatch{caseOf(t, generated, from, to), rel + ": not reported", source, e})
		}
		for _, e := range extra {
			from, to := Split(e)
			out = append(out, Mismatch{caseOf(t, generated, from, to), rel + ": not in ground truth", source, e})
		}
	}
	return out
}

// caseOfWorkload attributes a workload (or group) ID to the case of a pod it
// owns or groups, else by namespace.
func caseOfWorkload(t *truth.Truth, generated map[string]bool, w string) string {
	if kindOf(w) == "Pod" {
		return caseOf(t, generated, w)
	}
	ns := NamespaceOf(w)
	if strings.HasPrefix(ns, "stress-") {
		for _, p := range t.Pods {
			if p.Namespace == ns && (p.Top == w || p.Group == w) && p.Labels["kubesentry.io/stress-case"] != "" {
				return p.Labels["kubesentry.io/stress-case"]
			}
		}
		// A group kubesentry invented: attribute it through the pods it named.
		name := strings.TrimPrefix(w, kindOf(w)+"/"+ns+"/")
		for _, p := range t.Pods {
			if p.Namespace == ns && strings.HasPrefix(p.Name, name) && p.Labels["kubesentry.io/stress-case"] != "" {
				return p.Labels["kubesentry.io/stress-case"]
			}
		}
		return ns
	}
	return caseOf(t, generated, w)
}

func podOf(t *truth.Truth, id string) *truth.Pod {
	ns := NamespaceOf(id)
	return t.Pods[ns+"/"+strings.TrimPrefix(id, "Pod/"+ns+"/")]
}

// GroupMismatches groups by case and category, biggest first.
func GroupMismatches(ms []Mismatch) []Group {
	idx := map[string]*Group{}
	for _, m := range ms {
		k := m.Case + "\x00" + m.Category
		g := idx[k]
		if g == nil {
			g = &Group{Case: m.Case, Category: m.Category}
			idx[k] = g
		}
		g.Count++
		if !contains(g.Sources, m.Source) {
			g.Sources = append(g.Sources, m.Source)
		}
		if len(g.Samples) < 5 {
			g.Samples = append(g.Samples, m.Detail)
		}
	}
	out := make([]Group, 0, len(idx))
	for _, g := range idx {
		sort.Strings(g.Sources)
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Case != out[j].Case {
			return out[i].Case < out[j].Case
		}
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Category < out[j].Category
	})
	return out
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
