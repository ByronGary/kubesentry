package incidents

import (
	"maps"
	"sort"
	"strings"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
	"github.com/ByronGary/kubesentry/internal/snapshot"
)

// TagsOf returns the app and service tags of a subject in the view, nil
// when the view knows nothing of it:
//
//   - each tag key (keys, plus the custom key) from the workload's labels,
//     or else the most common value across its live pods (ties go to the
//     smaller value);
//   - TagService: the Services whose endpoints include its pods, and
//     TagIngress: the Ingresses routing to those Services (comma-separated);
//   - TagApp, the display app: the first of the custom key,
//     app.kubernetes.io/name, app, or the subject's name.
//
// It is computed for every subject once per view (View.Memo); the map
// returned is the caller's.
func TagsOf(v *snapshot.View, s Subject, keys []string, custom string) map[string]string {
	if len(keys) == 0 {
		keys = DefaultTagKeys
	}
	all := v.Memo("incidents/tags\x00"+strings.Join(keys, ",")+"\x00"+custom, func() any {
		return buildTags(v, keys, custom)
	}).(map[Subject]map[string]string)
	t, ok := all[s]
	if !ok {
		return nil
	}
	return maps.Clone(t)
}

func buildTags(v *snapshot.View, keys []string, custom string) map[Subject]map[string]string {
	x := indexOf(v)
	a := v.Assoc()
	keyList := append([]string(nil), keys...)
	if custom != "" && !contains(keyList, custom) {
		keyList = append(keyList, custom)
	}
	ingressesTo := map[[2]string][]string{} // namespace, service → ingresses
	for i := range v.Inv.Ingresses {
		ing := &v.Inv.Ingresses[i]
		seen := map[string]bool{}
		add := func(svc string) {
			if svc != "" && !seen[svc] {
				seen[svc] = true
				k := [2]string{ing.Namespace, svc}
				ingressesTo[k] = append(ingressesTo[k], ing.Name)
			}
		}
		add(ing.DefaultBackend)
		for _, r := range ing.Rules {
			add(r.Service)
		}
	}
	subjects := map[Subject]bool{}
	for s := range x.pods {
		subjects[s] = true
	}
	for s := range x.workloads {
		subjects[s] = true
	}
	out := make(map[Subject]map[string]string, len(subjects))
	for s := range subjects {
		w := x.workloads[s]
		var live []*model.Pod
		for _, p := range x.pods[s] {
			if livePod(p) {
				live = append(live, p)
			}
		}
		tags := map[string]string{}
		for _, k := range keyList {
			if w != nil && w.Labels[k] != "" {
				tags[k] = w.Labels[k]
				continue
			}
			if val := mostCommon(live, k); val != "" {
				tags[k] = val
			}
		}
		svcs := map[string]bool{}
		for _, p := range live {
			for _, svc := range a.ServicesOfPod(p.UID) {
				svcs[svc] = true
			}
		}
		if len(svcs) > 0 {
			names := sortedKeys(svcs)
			tags[TagService] = strings.Join(names, ",")
			ings := map[string]bool{}
			for _, svc := range names {
				for _, ing := range ingressesTo[[2]string{s.Namespace, svc}] {
					ings[ing] = true
				}
			}
			if len(ings) > 0 {
				tags[TagIngress] = strings.Join(sortedKeys(ings), ",")
			}
		}
		app := s.Name
		for _, k := range []string{custom, "app.kubernetes.io/name", "app"} {
			if k != "" && tags[k] != "" {
				app = tags[k]
				break
			}
		}
		tags[TagApp] = app
		out[s] = tags
	}
	return out
}

func mostCommon(pods []*model.Pod, key string) string {
	n := map[string]int{}
	for _, p := range pods {
		if val := p.Labels[key]; val != "" {
			n[val]++
		}
	}
	best, bestN := "", 0
	for val, c := range n {
		if c > bestN || (c == bestN && val < best) {
			best, bestN = val, c
		}
	}
	return best
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// Related returns the incidents among candidates related to in: they share
// app.kubernetes.io/part-of, app.kubernetes.io/instance or the custom tag
// (same value), or a Service in the same namespace, and their [start, end]
// ranges overlap (open ones end now). Related incidents are never merged;
// they are listed newest first, in itself left out.
func Related(in Incident, candidates []Incident, custom string, now time.Time) []Incident {
	keys := []string{"app.kubernetes.io/part-of", "app.kubernetes.io/instance"}
	if custom != "" {
		keys = append(keys, custom)
	}
	from, to := in.Start, now
	if in.End != nil {
		to = *in.End
	}
	var out []Incident
	for _, c := range candidates {
		if c.ID == in.ID || !overlaps(&c, from, to, now) {
			continue
		}
		if shareTags(&in, &c, keys) || shareService(&in, &c) {
			out = append(out, c)
		}
	}
	SortNewest(out)
	return out
}

func shareTags(a, b *Incident, keys []string) bool {
	for _, k := range keys {
		if v := a.Tags[k]; v != "" && b.Tags[k] == v {
			return true
		}
	}
	return false
}

func shareService(a, b *Incident) bool {
	if a.Subject.Namespace == "" || a.Subject.Namespace != b.Subject.Namespace {
		return false
	}
	for _, s := range a.Services {
		if contains(b.Services, s) {
			return true
		}
	}
	return false
}
