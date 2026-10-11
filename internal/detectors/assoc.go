package detectors

import (
	"sort"
	"strings"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
)

// Kinds an owner can have besides the workload kinds (Deployment,
// StatefulSet, DaemonSet, Job, CronJob).
const (
	// KindReplicaSet is a ReplicaSet no Deployment owns: it has no controller,
	// or its Deployment is gone.
	KindReplicaSet = "ReplicaSet"
	// KindController is an owner kubesentry does not model, such as an Argo
	// Rollout or a CRD-based operator. Its real kind is kept (ControllerKind).
	KindController = "Controller"
	// KindNode owns static pods: the kubelet's mirror pods point at their node.
	KindNode = "Node"
)

// howName marks a CronJob→Job link found by the CronJob controller's naming
// scheme because the Job carries no ownerReferences.
const howName = "name"

// youngService is how long a new Service may lack EndpointSlices before that
// counts as "no endpoints": the EndpointSlice controller needs a moment.
const youngService = 30 * time.Second

// Ref identifies the object that owns a pod: the workload (ReplicaSets are
// collapsed into their Deployment), an orphaned ReplicaSet, a Node for static
// pods, or a Controller of a kind kubesentry does not model.
type Ref struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	UID       string `json:"uid,omitempty"`
}

// EndpointState is one endpoint of a Service: a pod (or, for hand-managed
// slices, possibly a bare address) and whether it receives traffic.
type EndpointState struct {
	PodUID  string `json:"podUID,omitempty"`
	PodName string `json:"podName,omitempty"` // "" when the endpoint is not a pod
	// Address is the endpoint's first address (the pod IP when it came from
	// the Service selector).
	Address     string `json:"address,omitempty"`
	NodeName    string `json:"nodeName,omitempty"`
	Ready       bool   `json:"ready"`
	Serving     bool   `json:"serving"`
	Terminating bool   `json:"terminating"`
	// Owner is the pod's owner; zero when the pod is unknown or nothing owns it.
	Owner Ref `json:"owner"`
}

type nsName struct{ ns, name string }

type refKey struct{ kind, ns, name string }

func keyOf(r Ref) refKey { return refKey{r.Kind, r.Namespace, r.Name} }

// owner is a resolved pod owner.
type owner struct {
	ref   Ref
	how   string // HowOwner or HowSelector (JobParent may also say howName)
	ok    bool   // the pod has an owner
	found bool   // the owning object is in the inventory; false means its status is unknown
	real  string // the real kind behind a Controller ref
}

// nsIndex is one namespace's objects.
type nsIndex struct {
	pods      []*model.Pod
	workloads []*model.Workload
	services  []*model.Service
	ingresses []*model.Ingress
	pvcs      []*model.PVC
	// Selector candidates for pods without ownerReferences: each workload is
	// filed under one of its matchLabels pairs ("k=v"), or under rest.
	selByKV map[string][]*model.Workload
	selRest []*model.Workload
	// podsByKV files pods under each of their labels; built only when a
	// Service in the namespace falls back to its selector.
	podsByKV map[string][]int
}

// Assoc answers "who owns this pod" and "which pods back this Service" for one
// inventory. Associate builds it in time linear in the inventory; afterwards
// it is read-only and safe for concurrent use. Slices it returns are shared:
// do not modify them.
type Assoc struct {
	inv               model.Inventory
	policy            Policy
	system            map[string]bool
	slicesUnavailable bool

	ns       map[string]*nsIndex
	podAt    map[nsName]int
	podByUID map[string]int
	owners   []owner // aligned with inv.Pods
	podsOf   map[refKey][]*model.Pod
	ownerOf  map[refKey]owner // one representative per owner, for Found and ControllerKind
	onNode   map[string][]*model.Pod

	workloads   map[refKey]int
	workloadUID map[string]int
	rs          map[nsName]int
	rsUID       map[string]int
	nodes       map[string]int

	jobParent map[nsName]owner

	endpoints map[nsName][]EndpointState
	svcHow    map[nsName]string
	podSvcs   map[string][]string // pod UID → Service names
}

// Associate indexes inv: pods to owners and Services to endpoints. The rules:
//
//   - A pod's controller ownerReference is followed: Pod→ReplicaSet→Deployment,
//     Pod→Job, Pod→StatefulSet, Pod→DaemonSet. A ReplicaSet without a
//     controller, or whose Deployment is missing, is its own owner (kind
//     ReplicaSet). A ReplicaSet controlled by anything else (an Argo Rollout)
//     makes that the owner, kind Controller. A Node owner marks a static pod.
//     Any other kind becomes a Controller with its real kind kept.
//   - An owner that is not in the inventory is still the owner (how "owner"),
//     but Found reports false so its status shows as unknown. A missing
//     ReplicaSet is resolved to its Deployment when the pod's
//     pod-template-hash label ties the two names together.
//   - Only pods with no ownerReferences at all fall back to selectors: the
//     Deployments, StatefulSets, DaemonSets and Jobs of the namespace whose
//     selector matches (how "selector"); controllers beat Jobs, then names
//     sort.
//   - A Job's CronJob comes from the Job's controller ownerReference; the
//     controller's naming scheme (<cronjob>-<minutes>) is used only for Jobs
//     without ownerReferences.
//   - A Service's endpoints come from its EndpointSlices (merged, deduplicated
//     by pod), keeping ready, serving and terminating. The Service selector is
//     used instead only when there are no slices for the Service and either
//     EndpointSlices are unavailable (Inventory.Unavailable) or the Service is
//     younger than 30 seconds. Selector-less Services list whatever their
//     hand-made slices target.
func Associate(inv model.Inventory, p Policy) *Assoc {
	a := &Assoc{
		inv:               inv,
		policy:            p,
		system:            SystemNamespaceSet(p, inv.Namespaces),
		slicesUnavailable: unavailable(inv.Unavailable, SourceEndpointSlices),
		ns:                map[string]*nsIndex{},
		podAt:             make(map[nsName]int, len(inv.Pods)),
		podByUID:          make(map[string]int, len(inv.Pods)),
		owners:            make([]owner, len(inv.Pods)),
		podsOf:            make(map[refKey][]*model.Pod, len(inv.Workloads)),
		ownerOf:           make(map[refKey]owner, len(inv.Workloads)),
		onNode:            make(map[string][]*model.Pod, len(inv.Nodes)),
		workloads:         make(map[refKey]int, len(inv.Workloads)),
		workloadUID:       make(map[string]int, len(inv.Workloads)),
		rs:                make(map[nsName]int, len(inv.ReplicaSets)),
		rsUID:             make(map[string]int, len(inv.ReplicaSets)),
		nodes:             make(map[string]int, len(inv.Nodes)),
		jobParent:         map[nsName]owner{},
		endpoints:         make(map[nsName][]EndpointState, len(inv.Services)),
		svcHow:            make(map[nsName]string, len(inv.Services)),
		podSvcs:           map[string][]string{},
	}
	in := &a.inv

	for i := range in.Workloads {
		w := &in.Workloads[i]
		a.workloads[refKey{w.Kind, w.Namespace, w.Name}] = i
		if w.UID != "" {
			a.workloadUID[w.UID] = i
		}
		x := a.nsx(w.Namespace)
		x.workloads = append(x.workloads, w)
		switch w.Kind {
		case "Deployment", "StatefulSet", "DaemonSet", "Job":
			if w.Selector == nil {
				continue
			}
			if k, v, ok := firstLabel(w.Selector.MatchLabels); ok {
				if x.selByKV == nil {
					x.selByKV = map[string][]*model.Workload{}
				}
				x.selByKV[k+"="+v] = append(x.selByKV[k+"="+v], w)
			} else {
				x.selRest = append(x.selRest, w)
			}
		}
	}
	for i := range in.ReplicaSets {
		r := &in.ReplicaSets[i]
		a.rs[nsName{r.Namespace, r.Name}] = i
		if r.UID != "" {
			a.rsUID[r.UID] = i
		}
	}
	for i := range in.Nodes {
		a.nodes[in.Nodes[i].Name] = i
	}
	for i := range in.Services {
		x := a.nsx(in.Services[i].Namespace)
		x.services = append(x.services, &in.Services[i])
	}
	for i := range in.Ingresses {
		x := a.nsx(in.Ingresses[i].Namespace)
		x.ingresses = append(x.ingresses, &in.Ingresses[i])
	}
	for i := range in.PVCs {
		x := a.nsx(in.PVCs[i].Namespace)
		x.pvcs = append(x.pvcs, &in.PVCs[i])
	}
	for i := range in.Pods {
		p := &in.Pods[i]
		a.podAt[nsName{p.Namespace, p.Name}] = i
		if p.UID != "" {
			a.podByUID[p.UID] = i
		}
		x := a.nsx(p.Namespace)
		x.pods = append(x.pods, p)
		if p.NodeName != "" {
			a.onNode[p.NodeName] = append(a.onNode[p.NodeName], p)
		}
	}

	for i := range in.Pods {
		o := a.resolve(&in.Pods[i])
		a.owners[i] = o
		if !o.ok {
			continue
		}
		k := keyOf(o.ref)
		a.podsOf[k] = append(a.podsOf[k], &in.Pods[i])
		if _, seen := a.ownerOf[k]; !seen {
			a.ownerOf[k] = o
		}
	}
	for i := range in.Workloads {
		if w := &in.Workloads[i]; w.Kind == "Job" {
			if o := a.resolveJobParent(w); o.ok {
				a.jobParent[nsName{w.Namespace, w.Name}] = o
			}
		}
	}
	a.buildEndpoints()
	return a
}

func (a *Assoc) nsx(ns string) *nsIndex {
	x := a.ns[ns]
	if x == nil {
		x = &nsIndex{}
		a.ns[ns] = x
	}
	return x
}

// firstLabel returns the alphabetically first pair of m, so a selector is
// always filed under the same key.
func firstLabel(m map[string]string) (string, string, bool) {
	first := ""
	found := false
	for k := range m {
		if !found || k < first {
			first, found = k, true
		}
	}
	return first, m[first], found
}

// controllerOf returns the ownerReference marked controller.
func controllerOf(refs []model.OwnerRef) (model.OwnerRef, bool) {
	for _, r := range refs {
		if r.Controller {
			return r, true
		}
	}
	return model.OwnerRef{}, false
}

func (a *Assoc) wref(i int) Ref {
	w := &a.inv.Workloads[i]
	return Ref{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name, UID: w.UID}
}

// findWorkload looks an owner reference up by UID, then by name. A same-named
// object with a different UID is a replacement, not the owner.
func (a *Assoc) findWorkload(kind, ns string, o model.OwnerRef) (int, bool) {
	if o.UID != "" {
		if i, ok := a.workloadUID[o.UID]; ok && a.inv.Workloads[i].Kind == kind && a.inv.Workloads[i].Namespace == ns {
			return i, true
		}
	}
	i, ok := a.workloads[refKey{kind, ns, o.Name}]
	if !ok || (o.UID != "" && a.inv.Workloads[i].UID != "" && a.inv.Workloads[i].UID != o.UID) {
		return 0, false
	}
	return i, true
}

func (a *Assoc) findRS(ns string, o model.OwnerRef) (int, bool) {
	if o.UID != "" {
		if i, ok := a.rsUID[o.UID]; ok && a.inv.ReplicaSets[i].Namespace == ns {
			return i, true
		}
	}
	i, ok := a.rs[nsName{ns, o.Name}]
	if !ok || (o.UID != "" && a.inv.ReplicaSets[i].UID != "" && a.inv.ReplicaSets[i].UID != o.UID) {
		return 0, false
	}
	return i, true
}

// resolve finds a pod's owner; see Associate for the rules.
func (a *Assoc) resolve(p *model.Pod) owner {
	if len(p.Owners) == 0 {
		return a.bySelector(p)
	}
	o, ok := controllerOf(p.Owners)
	if !ok {
		o = p.Owners[0]
	}
	switch o.Kind {
	case "ReplicaSet":
		if i, ok := a.findRS(p.Namespace, o); ok {
			return a.rsOwner(&a.inv.ReplicaSets[i])
		}
		if i, ok := a.deploymentByHash(p, o.Name); ok {
			return owner{ref: a.wref(i), how: HowOwner, ok: true, found: true}
		}
		return owner{ref: Ref{Kind: KindReplicaSet, Namespace: p.Namespace, Name: o.Name, UID: o.UID}, how: HowOwner, ok: true}
	case "Node":
		_, found := a.nodes[o.Name]
		return owner{ref: Ref{Kind: KindNode, Name: o.Name, UID: o.UID}, how: HowOwner, ok: true, found: found}
	case "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob":
		if i, ok := a.findWorkload(o.Kind, p.Namespace, o); ok {
			return owner{ref: a.wref(i), how: HowOwner, ok: true, found: true}
		}
		return owner{ref: Ref{Kind: o.Kind, Namespace: p.Namespace, Name: o.Name, UID: o.UID}, how: HowOwner, ok: true}
	}
	return owner{ref: Ref{Kind: KindController, Namespace: p.Namespace, Name: o.Name, UID: o.UID}, real: o.Kind, how: HowOwner, ok: true}
}

// rsOwner climbs from a ReplicaSet to its Deployment or other controller.
func (a *Assoc) rsOwner(rs *model.ReplicaSet) owner {
	self := owner{ref: Ref{Kind: KindReplicaSet, Namespace: rs.Namespace, Name: rs.Name, UID: rs.UID}, how: HowOwner, ok: true, found: true}
	c, ok := controllerOf(rs.Owners)
	if !ok {
		return self
	}
	if c.Kind == "Deployment" {
		if i, ok := a.findWorkload("Deployment", rs.Namespace, c); ok {
			return owner{ref: a.wref(i), how: HowOwner, ok: true, found: true}
		}
		return self // orphaned: its Deployment is gone
	}
	return owner{ref: Ref{Kind: KindController, Namespace: rs.Namespace, Name: c.Name, UID: c.UID}, real: c.Kind, how: HowOwner, ok: true}
}

// deploymentByHash ties a ReplicaSet missing from the inventory to its
// Deployment: the ReplicaSet is named <deployment>-<pod-template-hash>.
func (a *Assoc) deploymentByHash(p *model.Pod, rsName string) (int, bool) {
	h := p.Labels["pod-template-hash"]
	if h == "" || !strings.HasSuffix(rsName, "-"+h) {
		return 0, false
	}
	i, ok := a.workloads[refKey{"Deployment", p.Namespace, strings.TrimSuffix(rsName, "-"+h)}]
	return i, ok
}

// bySelector is the fallback for pods without ownerReferences.
func (a *Assoc) bySelector(p *model.Pod) owner {
	x := a.ns[p.Namespace]
	if x == nil {
		return owner{}
	}
	var best *model.Workload
	visit := func(w *model.Workload) {
		if !MatchSelector(w.Selector, p.Labels) {
			return
		}
		if best == nil || jobRank(w) < jobRank(best) ||
			(jobRank(w) == jobRank(best) && (w.Kind < best.Kind || (w.Kind == best.Kind && w.Name < best.Name))) {
			best = w
		}
	}
	if len(x.selByKV) > 0 {
		for k, v := range p.Labels {
			for _, w := range x.selByKV[k+"="+v] {
				visit(w)
			}
		}
	}
	for _, w := range x.selRest {
		visit(w)
	}
	if best == nil {
		return owner{}
	}
	return owner{ref: Ref{Kind: best.Kind, Namespace: best.Namespace, Name: best.Name, UID: best.UID}, how: HowSelector, ok: true, found: true}
}

// jobRank puts controllers before Jobs when several selectors match a pod.
func jobRank(w *model.Workload) int {
	if w.Kind == "Job" {
		return 1
	}
	return 0
}

func (a *Assoc) resolveJobParent(w *model.Workload) owner {
	if len(w.Owners) == 0 {
		i := strings.LastIndexByte(w.Name, '-')
		if i <= 0 || i == len(w.Name)-1 || strings.Trim(w.Name[i+1:], "0123456789") != "" {
			return owner{}
		}
		if j, ok := a.workloads[refKey{"CronJob", w.Namespace, w.Name[:i]}]; ok {
			return owner{ref: a.wref(j), how: howName, ok: true, found: true}
		}
		return owner{}
	}
	c, ok := controllerOf(w.Owners)
	if !ok || c.Kind != "CronJob" {
		return owner{}
	}
	if i, ok := a.findWorkload("CronJob", w.Namespace, c); ok {
		return owner{ref: a.wref(i), how: HowOwner, ok: true, found: true}
	}
	return owner{ref: Ref{Kind: "CronJob", Namespace: w.Namespace, Name: c.Name, UID: c.UID}, how: HowOwner, ok: true}
}

func (a *Assoc) buildEndpoints() {
	in := &a.inv
	bySvc := make(map[nsName][]int, len(in.Services))
	for i := range in.EndpointSlices {
		s := &in.EndpointSlices[i]
		if s.Service != "" {
			k := nsName{s.Namespace, s.Service}
			bySvc[k] = append(bySvc[k], i)
		}
	}
	for i := range in.Services {
		svc := &in.Services[i]
		k := nsName{svc.Namespace, svc.Name}
		if idx := bySvc[k]; len(idx) > 0 {
			a.svcHow[k] = HowEndpoints
			a.endpoints[k] = a.fromSlices(svc, idx)
			continue
		}
		if svc.Type == "ExternalName" || len(svc.Selector) == 0 {
			continue
		}
		if a.slicesUnavailable || a.young(svc) {
			a.svcHow[k] = HowSelector
			a.endpoints[k] = a.fromSelector(svc)
		}
	}
	for k, eps := range a.endpoints {
		for _, e := range eps {
			if e.PodUID != "" {
				a.podSvcs[e.PodUID] = append(a.podSvcs[e.PodUID], k.name)
			}
		}
	}
	for _, names := range a.podSvcs {
		sort.Strings(names)
	}
}

func (a *Assoc) young(svc *model.Service) bool {
	return !svc.Created.IsZero() && !a.inv.ReadAt.IsZero() && a.inv.ReadAt.Sub(svc.Created) < youngService
}

// podIndex finds an endpoint's pod by UID, else by name.
func (a *Assoc) podIndex(ns, uid, name string) (int, bool) {
	if uid != "" {
		if i, ok := a.podByUID[uid]; ok && a.inv.Pods[i].Namespace == ns {
			return i, true
		}
	}
	if name == "" {
		return 0, false
	}
	i, ok := a.podAt[nsName{ns, name}]
	if ok && uid != "" && a.inv.Pods[i].UID != "" && a.inv.Pods[i].UID != uid {
		return 0, false // a new pod with the old pod's name
	}
	return i, ok
}

// fromSlices merges a Service's EndpointSlices. A pod listed twice (dual-stack
// Services have one slice per address family) is one endpoint.
func (a *Assoc) fromSlices(svc *model.Service, idx []int) []EndpointState {
	seen := map[string]int{}
	out := []EndpointState{}
	for _, si := range idx {
		for _, ep := range a.inv.EndpointSlices[si].Endpoints {
			var key string
			switch {
			case ep.TargetUID != "":
				key = "uid:" + ep.TargetUID
			case ep.TargetName != "":
				key = "ref:" + ep.TargetKind + "/" + ep.TargetName
			case len(ep.Addresses) > 0:
				key = "ip:" + ep.Addresses[0]
			}
			if j, ok := seen[key]; ok && key != "" {
				out[j].Ready = out[j].Ready || ep.Ready
				out[j].Serving = out[j].Serving || ep.Serving
				out[j].Terminating = out[j].Terminating || ep.Terminating
				continue
			}
			st := EndpointState{Ready: ep.Ready, Serving: ep.Serving, Terminating: ep.Terminating, NodeName: ep.NodeName}
			if len(ep.Addresses) > 0 {
				st.Address = ep.Addresses[0]
			}
			if ep.TargetKind == "Pod" || (ep.TargetKind == "" && ep.TargetUID != "") {
				if i, ok := a.podIndex(svc.Namespace, ep.TargetUID, ep.TargetName); ok {
					p := &a.inv.Pods[i]
					st.PodUID, st.PodName = p.UID, p.Name
					if a.owners[i].ok {
						st.Owner = a.owners[i].ref
					}
				} else {
					st.PodUID, st.PodName = ep.TargetUID, ep.TargetName
				}
			}
			if key != "" {
				seen[key] = len(out)
			}
			out = append(out, st)
		}
	}
	sortEndpoints(out)
	return out
}

// fromSelector stands in for EndpointSlices when they are unknown: the live
// pods the selector matches, ready by their Ready condition.
func (a *Assoc) fromSelector(svc *model.Service) []EndpointState {
	x := a.ns[svc.Namespace]
	if x == nil {
		return []EndpointState{}
	}
	if x.podsByKV == nil {
		x.podsByKV = map[string][]int{}
		for _, p := range x.pods {
			i := a.podAt[nsName{p.Namespace, p.Name}]
			for k, v := range p.Labels {
				x.podsByKV[k+"="+v] = append(x.podsByKV[k+"="+v], i)
			}
		}
	}
	var cand []int
	first := true
	for k, v := range svc.Selector {
		if b := x.podsByKV[k+"="+v]; first || len(b) < len(cand) {
			cand, first = b, false
		}
	}
	sel := &model.LabelSelector{MatchLabels: svc.Selector}
	out := []EndpointState{}
	for _, i := range cand {
		p := &a.inv.Pods[i]
		if !isLive(p) || !MatchSelector(sel, p.Labels) {
			continue
		}
		ready := p.Ready || (!readinessKnown(p) && p.Phase == "Running")
		terminating := !p.DeletedAt.IsZero()
		st := EndpointState{
			PodUID: p.UID, PodName: p.Name, Address: p.PodIP, NodeName: p.NodeName,
			Ready: ready && !terminating, Serving: ready, Terminating: terminating,
		}
		if a.owners[i].ok {
			st.Owner = a.owners[i].ref
		}
		out = append(out, st)
	}
	sortEndpoints(out)
	return out
}

func sortEndpoints(eps []EndpointState) {
	sort.Slice(eps, func(i, j int) bool {
		if eps[i].PodName != eps[j].PodName {
			return eps[i].PodName < eps[j].PodName
		}
		return eps[i].Address < eps[j].Address
	})
}

// readinessKnown reports whether the pod's Ready condition was reported. Old
// fixtures and partial sources leave it unset; such pods are not judged on it.
func readinessKnown(p *model.Pod) bool { return p.Ready || !p.ReadyChanged.IsZero() }

func isLive(p *model.Pod) bool { return p.Phase != "Succeeded" && p.Phase != "Failed" }

func (a *Assoc) indexOf(p *model.Pod) (int, bool) {
	i, ok := a.podAt[nsName{p.Namespace, p.Name}]
	if !ok || (p.UID != "" && a.inv.Pods[i].UID != "" && a.inv.Pods[i].UID != p.UID) {
		return 0, false
	}
	return i, true
}

func (a *Assoc) ownerOfPod(p *model.Pod) owner {
	if i, ok := a.indexOf(p); ok {
		return a.owners[i]
	}
	return a.resolve(p) // a pod read after the inventory, e.g. on the pod page
}

// OwnerOf returns the pod's owner and how it was found (HowOwner or
// HowSelector). ok is false for a bare pod. The pod need not be one of the
// inventory's own: others are resolved against the same index.
func (a *Assoc) OwnerOf(p *model.Pod) (r Ref, how string, ok bool) {
	o := a.ownerOfPod(p)
	return o.ref, o.how, o.ok
}

// PodsOf returns the pods r owns, including finished ones. A Deployment owns
// the pods of all its ReplicaSets; a CronJob owns none directly (see JobParent).
func (a *Assoc) PodsOf(r Ref) []*model.Pod { return a.podsOf[keyOf(r)] }

// ServiceEndpoints returns a Service's endpoints sorted by pod name; nil when
// it has none or the Service is unknown.
func (a *Assoc) ServiceEndpoints(ns, svc string) []EndpointState {
	return a.endpoints[nsName{ns, svc}]
}

// ServiceHow says where a Service's endpoints came from: HowEndpoints
// (EndpointSlices), HowSelector (the fallback), or "" when it has none.
func (a *Assoc) ServiceHow(ns, svc string) string { return a.svcHow[nsName{ns, svc}] }

// ServicesOfPod returns the names of the Services (in the pod's namespace)
// that list the pod with this UID as an endpoint, sorted.
func (a *Assoc) ServicesOfPod(uid string) []string { return a.podSvcs[uid] }

// JobParent returns the CronJob that created a Job. how is HowOwner, or "name"
// when it was matched by the CronJob naming scheme because the Job has no
// ownerReferences.
func (a *Assoc) JobParent(ns, job string) (r Ref, how string, ok bool) {
	o, ok := a.jobParent[nsName{ns, job}]
	return o.ref, o.how, ok
}

// Found reports whether the owner r is in the inventory. A pod can point at an
// owner that is gone or not yet seen; its status is then unknown. Controllers
// of kinds kubesentry does not model are never found.
func (a *Assoc) Found(r Ref) bool {
	switch r.Kind {
	case KindController:
		return false
	case KindReplicaSet:
		_, ok := a.rs[nsName{r.Namespace, r.Name}]
		return ok
	case KindNode:
		_, ok := a.nodes[r.Name]
		return ok
	}
	_, ok := a.workloads[keyOf(r)]
	return ok
}

// ControllerKind returns the real kind behind a Controller ref (e.g. Rollout).
func (a *Assoc) ControllerKind(r Ref) string { return a.ownerOf[keyOf(r)].real }

// WorkloadOf names a pod's owner as "Kind/name", using the real kind for
// Controllers; "" for a bare pod.
func (a *Assoc) WorkloadOf(p *model.Pod) string {
	o := a.ownerOfPod(p)
	if !o.ok {
		return ""
	}
	if o.real != "" {
		return o.real + "/" + o.ref.Name
	}
	return o.ref.Kind + "/" + o.ref.Name
}

// IsSystem reports whether ns is cluster plumbing under the policy, including
// the namespace label override.
func (a *Assoc) IsSystem(ns string) bool { return a.system[ns] }

// SystemNamespaces returns the resolved set of system namespaces.
func (a *Assoc) SystemNamespaces() map[string]bool { return a.system }

// Policy returns the policy the index was built with.
func (a *Assoc) Policy() Policy { return a.policy }

// Inventory returns the indexed inventory. It is shared: do not modify it.
func (a *Assoc) Inventory() *model.Inventory { return &a.inv }

// PodsIn returns the pods of one namespace, in inventory order.
func (a *Assoc) PodsIn(ns string) []*model.Pod {
	if x := a.ns[ns]; x != nil {
		return x.pods
	}
	return nil
}

// PodsOnNode returns the pods scheduled to a node, in inventory order.
func (a *Assoc) PodsOnNode(node string) []*model.Pod { return a.onNode[node] }

// Pod returns the pod with this UID.
func (a *Assoc) Pod(uid string) (*model.Pod, bool) {
	i, ok := a.podByUID[uid]
	if !ok {
		return nil, false
	}
	return &a.inv.Pods[i], true
}

// ReplicaSet returns a ReplicaSet by namespace and name.
func (a *Assoc) ReplicaSet(ns, name string) (*model.ReplicaSet, bool) {
	i, ok := a.rs[nsName{ns, name}]
	if !ok {
		return nil, false
	}
	return &a.inv.ReplicaSets[i], true
}

// HasNamespace reports whether any indexed object lives in ns.
func (a *Assoc) HasNamespace(ns string) bool {
	_, ok := a.ns[ns]
	return ok
}

// Namespaces returns every namespace that holds an indexed object, sorted.
func (a *Assoc) Namespaces() []string {
	out := make([]string, 0, len(a.ns))
	for ns := range a.ns {
		out = append(out, ns)
	}
	sort.Strings(out)
	return out
}

func (a *Assoc) workloadsIn(ns string) []*model.Workload {
	if x := a.ns[ns]; x != nil {
		return x.workloads
	}
	return nil
}

func (a *Assoc) servicesIn(ns string) []*model.Service {
	if x := a.ns[ns]; x != nil {
		return x.services
	}
	return nil
}

func (a *Assoc) ingressesIn(ns string) []*model.Ingress {
	if x := a.ns[ns]; x != nil {
		return x.ingresses
	}
	return nil
}

func (a *Assoc) pvcsIn(ns string) []*model.PVC {
	if x := a.ns[ns]; x != nil {
		return x.pvcs
	}
	return nil
}

// rootOf is the owner findings are grouped under: a Job's CronJob when it has
// one, otherwise the owner itself. Static and bare pods group by pod.
func (a *Assoc) rootOf(p *model.Pod) (kind, name string) {
	o := a.ownerOfPod(p)
	switch {
	case !o.ok || o.ref.Kind == KindNode:
		return "Pod", p.Name
	case o.ref.Kind == "Job":
		if cj, _, ok := a.JobParent(p.Namespace, o.ref.Name); ok {
			return "CronJob", cj.Name
		}
	case o.real != "":
		return o.real, o.ref.Name
	}
	return o.ref.Kind, o.ref.Name
}
