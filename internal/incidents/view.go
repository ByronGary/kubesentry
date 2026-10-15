package incidents

import (
	"reflect"
	"sort"
	"strings"

	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/model"
	"github.com/ByronGary/kubesentry/internal/snapshot"
)

// viewIndex is what the incidents derive once per view (View.Memo): pods by
// workload root, workloads and namespaces by name.
type viewIndex struct {
	pods       map[Subject][]*model.Pod // every pod, live or finished, by root
	workloads  map[Subject]*model.Workload
	byName     map[[2]string][]*model.Workload // namespace, name → workloads of any kind
	namespaces map[string]*model.Namespace
}

func indexOf(v *snapshot.View) *viewIndex {
	return v.Memo("incidents/index", func() any {
		a := v.Assoc()
		inv := &v.Inv
		x := &viewIndex{
			pods:       map[Subject][]*model.Pod{},
			workloads:  make(map[Subject]*model.Workload, len(inv.Workloads)),
			byName:     make(map[[2]string][]*model.Workload, len(inv.Workloads)),
			namespaces: make(map[string]*model.Namespace, len(inv.Namespaces)),
		}
		for i := range inv.Pods {
			p := &inv.Pods[i]
			s := subjectOfPod(a, p)
			x.pods[s] = append(x.pods[s], p)
		}
		for i := range inv.Workloads {
			w := &inv.Workloads[i]
			x.workloads[Subject{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name}] = w
			k := [2]string{w.Namespace, w.Name}
			x.byName[k] = append(x.byName[k], w)
		}
		for i := range inv.Namespaces {
			x.namespaces[inv.Namespaces[i].Name] = &inv.Namespaces[i]
		}
		return x
	}).(*viewIndex)
}

func subjectOfPod(a *detectors.Assoc, p *model.Pod) Subject {
	kind, name := a.RootOf(p)
	return Subject{Kind: kind, Namespace: p.Namespace, Name: name}
}

// SubjectOfPod is the workload root of the named pod. A pod no longer in
// the view (replaced after an OOM kill, rolled by a deploy) is resolved by
// the controllers' naming schemes: <replicaset>-<suffix> for Deployments,
// <statefulset>-<ordinal>, <daemonset or job>-<suffix>. ok is false when
// nothing matches.
func SubjectOfPod(v *snapshot.View, ns, pod string) (Subject, bool) {
	a := v.Assoc()
	if p, ok := a.PodByName(ns, pod); ok {
		return subjectOfPod(a, p), true
	}
	x := indexOf(v)
	i := strings.LastIndexByte(pod, '-')
	if i <= 0 {
		return Subject{}, false
	}
	prefix, suffix := pod[:i], pod[i+1:]
	if rs, ok := a.ReplicaSet(ns, prefix); ok {
		for _, o := range rs.Owners {
			if o.Controller && o.Kind == "Deployment" {
				if _, ok := x.workloads[Subject{Kind: "Deployment", Namespace: ns, Name: o.Name}]; ok {
					return Subject{Kind: "Deployment", Namespace: ns, Name: o.Name}, true
				}
			}
		}
		return Subject{Kind: detectors.KindReplicaSet, Namespace: ns, Name: rs.Name}, true
	}
	numeric := strings.Trim(suffix, "0123456789") == ""
	for _, w := range x.byName[[2]string{ns, prefix}] {
		switch {
		case w.Kind == "StatefulSet" && numeric, w.Kind == "DaemonSet":
			return Subject{Kind: w.Kind, Namespace: ns, Name: w.Name}, true
		case w.Kind == "Job":
			if cj, _, ok := a.JobParent(ns, w.Name); ok {
				return Subject{Kind: "CronJob", Namespace: ns, Name: cj.Name}, true
			}
			return Subject{Kind: "Job", Namespace: ns, Name: w.Name}, true
		}
	}
	// <deployment>-<pod-template-hash>-<suffix> whose ReplicaSet is gone.
	if j := strings.LastIndexByte(prefix, '-'); j > 0 {
		if _, ok := x.workloads[Subject{Kind: "Deployment", Namespace: ns, Name: prefix[:j]}]; ok {
			return Subject{Kind: "Deployment", Namespace: ns, Name: prefix[:j]}, true
		}
	}
	return Subject{}, false
}

// SubjectOfWorkload is the root of a workload object: a ReplicaSet's
// Deployment, a Job's CronJob, else the object itself.
func SubjectOfWorkload(v *snapshot.View, kind, ns, name string) (Subject, bool) {
	a := v.Assoc()
	x := indexOf(v)
	switch kind {
	case "ReplicaSet":
		rs, ok := a.ReplicaSet(ns, name)
		if !ok {
			return Subject{}, false
		}
		for _, o := range rs.Owners {
			if o.Controller && o.Kind == "Deployment" {
				return Subject{Kind: "Deployment", Namespace: ns, Name: o.Name}, true
			}
		}
		return Subject{Kind: detectors.KindReplicaSet, Namespace: ns, Name: name}, true
	case "Job":
		if cj, _, ok := a.JobParent(ns, name); ok {
			return Subject{Kind: "CronJob", Namespace: ns, Name: cj.Name}, true
		}
	}
	s := Subject{Kind: kind, Namespace: ns, Name: name}
	_, ok := x.workloads[s]
	return s, ok
}

// SubjectsOfService are the roots of a Service's endpoints, sorted.
func SubjectsOfService(v *snapshot.View, ns, svc string) []Subject {
	a := v.Assoc()
	seen := map[Subject]bool{}
	var out []Subject
	for _, ep := range a.ServiceEndpoints(ns, svc) {
		var s Subject
		switch {
		case ep.PodName != "":
			var ok bool
			if s, ok = SubjectOfPod(v, ns, ep.PodName); !ok {
				continue
			}
		case ep.Owner.Name != "":
			s = Subject{Kind: ep.Owner.Kind, Namespace: ns, Name: ep.Owner.Name}
		default:
			continue
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sortSubjects(out)
	return out
}

func sortSubjects(l []Subject) {
	sort.Slice(l, func(i, j int) bool {
		if l[i].Namespace != l[j].Namespace {
			return l[i].Namespace < l[j].Namespace
		}
		if l[i].Kind != l[j].Kind {
			return l[i].Kind < l[j].Kind
		}
		return l[i].Name < l[j].Name
	})
}

// PodsOf returns the pods of a subject in the view (finished ones too).
func PodsOf(v *snapshot.View, s Subject) []*model.Pod { return indexOf(v).pods[s] }

func livePod(p *model.Pod) bool { return p.Phase != "Succeeded" && p.Phase != "Failed" }

// enrich refreshes what the view says about t's subject: owner, production,
// tags, and the pods, nodes and Services involved (lists only grow, up to
// MaxListed).
func (e *Engine) enrich(t *tracked) {
	t.enrich = false
	v := e.view
	if v == nil {
		return
	}
	in := &t.in
	before := CloneIncident(*in)
	x := indexOf(v)
	a := v.Assoc()
	owner, prod := "", false
	if n := x.namespaces[in.Subject.Namespace]; n != nil {
		owner, prod = v.Policy.OwnerOf(*n), v.Policy.IsProduction(*n)
	}
	if owner == "" {
		owner = e.o.DefaultOwner
	}
	in.Owner, in.Production = owner, prod
	if tags := TagsOf(v, in.Subject, e.o.TagKeys, e.o.AppLabel); tags != nil {
		in.Tags = tags
	}

	var pods, nodes, services []string
	ids := make([]string, 0, len(t.sigs))
	for id := range t.sigs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		s := t.sigs[id]
		switch s.Object.Kind {
		case "Pod":
			pods = append(pods, s.Object.Name)
		case "Node":
			nodes = append(nodes, s.Object.Name)
		case "Service":
			services = append(services, s.Object.Name)
		}
		if p := s.Attrs["pod"]; p != "" {
			pods = append(pods, p)
		}
	}
	if in.Subject.Kind == KindNode {
		nodes = append(nodes, in.Subject.Name)
	}
	for _, p := range x.pods[in.Subject] {
		if livePod(p) {
			pods = append(pods, p.Name)
		}
	}
	if in.Subject.Kind == "Pod" {
		pods = append(pods, in.Subject.Name)
	}
	in.Pods = addListed(in.Pods, pods...)
	for _, name := range in.Pods {
		if p, ok := a.PodByName(in.Subject.Namespace, name); ok && p.NodeName != "" {
			nodes = append(nodes, p.NodeName)
		}
	}
	in.Nodes = addListed(in.Nodes, nodes...)
	if svc := in.Tags[TagService]; svc != "" {
		services = append(services, strings.Split(svc, ",")...)
	}
	in.Services = addListed(in.Services, services...)
	if !reflect.DeepEqual(before, *in) {
		e.markIncident(t)
	}
}

// addListed adds items not yet listed while there is room (MaxListed), so
// a full list never changes; the result is sorted.
func addListed(list []string, items ...string) []string {
	have := make(map[string]bool, len(list))
	for _, s := range list {
		have[s] = true
	}
	out := list
	added := false
	for _, s := range items {
		if s == "" || have[s] || len(out) >= MaxListed {
			continue
		}
		if !added {
			out = append([]string(nil), list...)
			added = true
		}
		have[s] = true
		out = append(out, s)
	}
	if added {
		sort.Strings(out)
	}
	return out
}
