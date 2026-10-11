package detectors

import (
	"fmt"
	"sort"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
)

// TopologyInput is everything BuildTopology needs, for the whole cluster.
type TopologyInput struct {
	Pods      []model.Pod
	Workloads []model.Workload
	Services  []model.Service
	Ingresses []model.Ingress
	Nodes     []model.Node
	PVCs      []model.PVC
	// StorageClasses let PVCs be judged as on the Storage page.
	StorageClasses []model.StorageClass
	// ReplicaSets and EndpointSlices are optional. Without slices, Services
	// are linked by their selectors.
	ReplicaSets    []model.ReplicaSet
	EndpointSlices []model.EndpointSlice
	Now            time.Time
}

var graphKindOrder = map[string]int{
	"Ingress": 0, "Service": 1, "Deployment": 2, "StatefulSet": 3, "DaemonSet": 4,
	"Job": 5, "CronJob": 6, KindReplicaSet: 7, KindController: 8, "Pod": 9, "PVC": 10, "Node": 11,
}

// BuildTopology maps one namespace with the default policy.
func BuildTopology(namespace string, in TopologyInput) Graph {
	p := compatPolicy()
	inv := listInventory(model.Inventory{
		Pods: in.Pods, Workloads: in.Workloads, Services: in.Services, Ingresses: in.Ingresses, Nodes: in.Nodes,
		PVCs: in.PVCs, StorageClasses: in.StorageClasses, ReplicaSets: in.ReplicaSets, EndpointSlices: in.EndpointSlices,
		ReadAt: in.Now,
	})
	return BuildTopologyWith(namespace, Associate(inv, p), p, in.Now)
}

// BuildTopologyWith maps one namespace: Ingress→Service→owner→Pod→Node,
// CronJob→Job and Pod→PVC. Pods are the live ones plus those that ended within
// Thresholds.RecentPod. Owners come from the association: a Deployment stands
// for its ReplicaSets, an orphaned ReplicaSet or a Controller of another kind
// (an Argo Rollout) is its own node, and an owner missing from the inventory
// is shown with status unknown. A Service links to the owners of the pods its
// EndpointSlices list (or that its selector matches, the fallback), each edge
// carrying how many of those endpoints are ready, not ready and terminating; a
// pod nothing owns is linked directly. Nodes and edges come in a fixed order.
func BuildTopologyWith(namespace string, a *Assoc, p Policy, now time.Time) Graph {
	t := p.Thresholds
	b := graphBuilder{nodes: map[string]GraphNode{}, edges: map[[2]string]*GraphEdge{}}
	id := func(kind, name string) string { return kind + "/" + namespace + "/" + name }
	inv := a.Inventory()

	wptr := a.workloadsIn(namespace)
	ws := make([]model.Workload, len(wptr))
	for i, w := range wptr {
		ws[i] = *w
	}
	for _, s := range SummarizeWorkloadsWith(ws, a, p, now) {
		b.node(GraphNode{ID: id(s.Kind, s.Name), Kind: s.Kind, Name: s.Name, Namespace: namespace, Status: s.Status, Detail: s.Detail})
	}
	for _, w := range wptr {
		if w.Kind != "Job" {
			continue
		}
		if cj, how, ok := a.JobParent(namespace, w.Name); ok {
			if !a.Found(cj) {
				b.missingOwner(id("CronJob", cj.Name), cj)
			}
			if how == howName {
				how = ""
			}
			b.edge(id("CronJob", cj.Name), id("Job", w.Name), how)
		}
	}

	nsPods := a.PodsIn(namespace)
	claims := map[string]bool{}
	hosts := map[string]bool{}
	owners := map[refKey]Ref{} // owners of shown pods that are not workloads on the map
	for _, pod := range nsPods {
		if !shownPod(pod, t.RecentPod, now) {
			continue
		}
		pid := id("Pod", pod.Name)
		st, detail := podStatus(pod, t, now)
		b.node(GraphNode{ID: pid, Kind: "Pod", Name: pod.Name, Namespace: namespace, Status: st, Detail: detail})
		if o := a.ownerOfPod(pod); o.ok && o.ref.Kind != KindNode {
			b.edge(id(o.ref.Kind, o.ref.Name), pid, o.how)
			if o.ref.Kind == KindReplicaSet || o.ref.Kind == KindController || !o.found {
				owners[keyOf(o.ref)] = o.ref
			}
		}
		if pod.NodeName != "" {
			hosts[pod.NodeName] = true
			b.edge(pid, "Node/"+pod.NodeName, "")
		}
		for _, c := range pod.Claims {
			claims[c] = true
			b.edge(pid, id("PVC", c), "")
		}
	}
	for _, r := range owners {
		b.ownerNode(id(r.Kind, r.Name), r, a, t, now)
	}

	if len(claims) > 0 {
		var nsPVCs []model.PVC
		for _, c := range a.pvcsIn(namespace) {
			nsPVCs = append(nsPVCs, *c)
		}
		var podsCopy []model.Pod
		for _, pod := range nsPods {
			if isLive(pod) {
				podsCopy = append(podsCopy, *pod)
			}
		}
		summaries, _, _ := SummarizeStorageWith(nsPVCs, nil, inv.StorageClasses, podsCopy, p, now)
		byClaim := make(map[string]ClaimSummary, len(summaries))
		for _, s := range summaries {
			byClaim[s.Name] = s
		}
		for c := range claims {
			n := GraphNode{ID: id("PVC", c), Kind: "PVC", Name: c, Namespace: namespace, Status: StatusCrit, Detail: "Claim does not exist."}
			if s, ok := byClaim[c]; ok {
				n.Status, n.Detail = s.Status, s.Detail
			}
			b.node(n)
		}
	}

	for h := range hosts {
		n := GraphNode{ID: "Node/" + h, Kind: "Node", Name: h, Status: StatusUnknown, Detail: "Not in the node list."}
		if i, ok := a.nodes[h]; ok {
			node := &inv.Nodes[i]
			n.Status, n.Detail = judgeNode(*node, pressure(*node))
		}
		b.node(n)
	}

	services := map[string]bool{}
	for _, svc := range a.servicesIn(namespace) {
		services[svc.Name] = true
		b.service(id("Service", svc.Name), svc, a, id)
	}

	for _, ing := range a.ingressesIn(namespace) {
		iid := id("Ingress", ing.Name)
		var backends, missing, hostNames []string
		for _, r := range ing.Rules {
			if r.Service != "" {
				backends = appendNew(backends, r.Service)
			}
			h := r.Host
			if h == "" {
				h = "*"
			}
			hostNames = appendNew(hostNames, h)
		}
		if ing.DefaultBackend != "" {
			backends = appendNew(backends, ing.DefaultBackend)
		}
		for _, svc := range backends {
			if services[svc] {
				b.edge(iid, id("Service", svc), "")
			} else {
				missing = append(missing, svc)
			}
		}
		n := GraphNode{ID: iid, Kind: "Ingress", Name: ing.Name, Namespace: namespace, Status: StatusOK}
		switch {
		case len(missing) > 0:
			n.Status = StatusWarn
			n.Detail = "Backend " + plural(len(missing), "service ", "services ") + list(missing) + " " + plural(len(missing), "does", "do") + " not exist."
		case len(hostNames) == 0:
			n.Detail = "Default backend only."
		case ingressTLS(*ing):
			n.Detail = "Routes " + list(hostNames) + " with TLS."
		default:
			n.Detail = "Routes " + list(hostNames) + " without TLS."
		}
		b.node(n)
	}
	return b.graph()
}

// service adds a Service node and its edges to the owners of its endpoints.
func (b *graphBuilder) service(sid string, svc *model.Service, a *Assoc, id func(kind, name string) string) {
	n := GraphNode{ID: sid, Kind: "Service", Name: svc.Name, Namespace: svc.Namespace}
	if svc.Type == "ExternalName" {
		n.Status, n.Detail = StatusOK, "Points outside the cluster (ExternalName)."
		b.node(n)
		return
	}
	how := a.ServiceHow(svc.Namespace, svc.Name)
	eps := a.ServiceEndpoints(svc.Namespace, svc.Name)

	var ready, notReady, terminating int
	for _, e := range eps {
		r, nr, term := endpointCounts(e, svc.PublishNotReady)
		ready, notReady, terminating = ready+r, notReady+nr, terminating+term
		target := ""
		switch {
		case e.Owner.Kind != "" && e.Owner.Kind != KindNode:
			target = id(e.Owner.Kind, e.Owner.Name)
		case e.PodName != "":
			target = id("Pod", e.PodName)
		default:
			continue // an address that is not a pod
		}
		ed := b.edge(sid, target, how)
		ed.Ready += r
		ed.NotReady += nr
		ed.Terminating += term
	}
	total := len(eps)

	switch {
	case how == HowSelector:
		// No EndpointSlices to go by: say what the selector matches, as before.
		if total == 0 {
			n.Status, n.Detail = StatusWarn, "Selects no pods."
		} else {
			n.Status, n.Detail = StatusOK, fmt.Sprintf("%s, selects %d %s.", svcType(svc.Type), total, plural(total, "pod", "pods"))
		}
	case len(svc.Selector) == 0 && total == 0:
		n.Status, n.Detail = StatusOK, "No selector; its endpoints are managed separately."
	case total == 0:
		n.Status, n.Detail = StatusWarn, svcType(svc.Type)+", no endpoints."
	default:
		n.Detail = svcType(svc.Type) + ", " + endpointSummary(ready, notReady, terminating) + "."
		if len(svc.Selector) == 0 {
			n.Detail = "No selector; " + endpointSummary(ready, notReady, terminating) + " managed by hand."
		}
		if svc.PublishNotReady {
			n.Detail += " Publishes not-ready addresses."
		}
		switch {
		case ready == 0:
			n.Status = StatusCrit
		case notReady > 0:
			n.Status = StatusWarn
		default:
			n.Status = StatusOK
		}
	}
	b.node(n)
}

// endpointCounts classifies one endpoint as ready, not ready or terminating.
// A Service that publishes not-ready addresses marks every endpoint ready, so
// its pods' own readiness (serving) is used instead.
func endpointCounts(e EndpointState, publishNotReady bool) (ready, notReady, terminating int) {
	switch {
	case e.Terminating:
		return 0, 0, 1
	case publishNotReady && e.Serving, !publishNotReady && e.Ready:
		return 1, 0, 0
	}
	return 0, 1, 0
}

// endpointSummary says "3 ready, 1 not ready, 2 terminating", leaving out
// zero counts other than ready.
func endpointSummary(ready, notReady, terminating int) string {
	s := fmt.Sprintf("%d ready", ready)
	if notReady > 0 {
		s += fmt.Sprintf(", %d not ready", notReady)
	}
	if terminating > 0 {
		s += fmt.Sprintf(", %d terminating", terminating)
	}
	return s
}

// ownerNode adds a node for a pod owner that is not a workload on the map: an
// orphaned ReplicaSet, a Controller of another kind, or an owner missing from
// the inventory.
func (b *graphBuilder) ownerNode(nid string, r Ref, a *Assoc, t Thresholds, now time.Time) {
	if _, ok := b.nodes[nid]; ok {
		return
	}
	n := GraphNode{ID: nid, Kind: r.Kind, Name: r.Name, Namespace: r.Namespace}
	switch {
	case r.Kind == KindController:
		n.OwnerKind = a.ControllerKind(r)
		n.Status, n.Detail = podsVerdict(a.PodsOf(r), t, now)
		n.Detail = "Managed by " + n.OwnerKind + " " + r.Name + ", which kubesentry does not track; " + n.Detail
	case r.Kind == KindReplicaSet && a.Found(r):
		rs, _ := a.ReplicaSet(r.Namespace, r.Name)
		w := model.Workload{Kind: "ReplicaSet", Desired: rs.Desired, Ready: rs.Ready, Updated: rs.Desired}
		var detail string
		n.Status, detail = judgeReplicas(w)
		n.Detail = "No Deployment owns it. " + detail
	default:
		b.missingOwner(nid, r)
		return
	}
	b.node(n)
}

// missingOwner adds a node for an owner the inventory does not have.
func (b *graphBuilder) missingOwner(nid string, r Ref) {
	if _, ok := b.nodes[nid]; ok {
		return
	}
	b.node(GraphNode{ID: nid, Kind: r.Kind, Name: r.Name, Namespace: r.Namespace,
		Status: StatusUnknown, Detail: r.Kind + " " + r.Name + " was not found; it may have just been deleted or not yet been seen."})
}

// podsVerdict judges an untracked owner by its live pods' readiness.
func podsVerdict(pods []*model.Pod, t Thresholds, now time.Time) (string, string) {
	live, ready, known := 0, 0, 0
	for _, p := range pods {
		if !isLive(p) {
			continue
		}
		live++
		if readinessKnown(p) {
			known++
			if p.Ready {
				ready++
			}
		}
	}
	detail := fmt.Sprintf("%d %s", live, plural(live, "pod", "pods"))
	switch {
	case live == 0:
		return StatusUnknown, "no live pods."
	case known < live:
		return StatusUnknown, detail + "."
	case ready == live:
		return StatusOK, fmt.Sprintf("%d of %d pods ready.", ready, live)
	case ready == 0:
		return StatusCrit, fmt.Sprintf("0 of %d pods ready.", live)
	}
	return StatusWarn, fmt.Sprintf("%d of %d pods ready.", ready, live)
}

func svcType(t string) string {
	if t == "" {
		return "ClusterIP"
	}
	return t
}

type graphBuilder struct {
	nodes map[string]GraphNode
	edges map[[2]string]*GraphEdge
}

func (b *graphBuilder) node(n GraphNode) { b.nodes[n.ID] = n }

// edge adds (or returns the existing) edge from→to. The first non-empty how wins.
func (b *graphBuilder) edge(from, to, how string) *GraphEdge {
	k := [2]string{from, to}
	e := b.edges[k]
	if e == nil {
		e = &GraphEdge{From: from, To: to, How: how}
		b.edges[k] = e
	} else if e.How == "" {
		e.How = how
	}
	return e
}

// graph returns the nodes in kind order, then by name, and drops any edge
// whose ends are not both on the map.
func (b *graphBuilder) graph() Graph {
	g := Graph{Nodes: make([]GraphNode, 0, len(b.nodes)), Edges: make([]GraphEdge, 0, len(b.edges))}
	for _, n := range b.nodes {
		g.Nodes = append(g.Nodes, n)
	}
	sort.Slice(g.Nodes, func(i, j int) bool {
		a, c := g.Nodes[i], g.Nodes[j]
		if graphKindOrder[a.Kind] != graphKindOrder[c.Kind] {
			return graphKindOrder[a.Kind] < graphKindOrder[c.Kind]
		}
		return a.ID < c.ID
	})
	for _, e := range b.edges {
		if _, ok := b.nodes[e.From]; !ok {
			continue
		}
		if _, ok := b.nodes[e.To]; !ok {
			continue
		}
		g.Edges = append(g.Edges, *e)
	}
	sort.Slice(g.Edges, func(i, j int) bool {
		if g.Edges[i].From != g.Edges[j].From {
			return g.Edges[i].From < g.Edges[j].From
		}
		return g.Edges[i].To < g.Edges[j].To
	})
	return g
}

// shownPod reports whether a pod belongs on the map and node views: it is
// live, or it ended recently enough to explain what just happened.
func shownPod(p *model.Pod, recent time.Duration, now time.Time) bool {
	return isLive(p) || (!p.Created.IsZero() && now.Sub(p.Created) < recent)
}

// podStatus is a one-line verdict for a pod on the map, using the same
// thresholds as the pod page.
func podStatus(p *model.Pod, t Thresholds, now time.Time) (string, string) {
	restarts, _ := appContainers(p)
	var oom []string
	for _, c := range p.Containers {
		if c.LastTerminatedReason == "OOMKilled" && !IsInitOnly(c) && now.Sub(c.LastTerminatedAt) <= t.OOMRecent {
			oom = append(oom, c.Name+" ("+ago(now.Sub(c.LastTerminatedAt))+")")
		}
	}
	stuck, _, _ := stuckContainers(p)
	overdue, terminating := overdueTermination(p, now)
	notReady, nrKnown := notReadyFor(p, now)
	reason, _ := podLevelReason(p)
	switch {
	case reason != "":
		return StatusCrit, reason + "."
	case p.Phase == "Failed":
		return StatusCrit, "Failed."
	case len(stuck) > 0:
		return StatusCrit, list(stuck) + "."
	case terminating && overdue > t.TerminatingGrace:
		return StatusWarn, "Still terminating " + duration(overdue) + " after its deletion time."
	case p.Phase == "Pending" && p.Unschedulable != "":
		return StatusWarn, "Unschedulable: " + sentence(p.Unschedulable, "")
	case p.Phase == "Pending":
		return StatusWarn, "Pending."
	case len(oom) > 0:
		return StatusWarn, "OOMKilled: " + list(oom) + "."
	case restarts >= t.RestartWarn:
		return StatusWarn, fmt.Sprintf("%d restarts.", restarts)
	case nrKnown && notReady > t.NotReadyGrace:
		return StatusWarn, "Not ready for " + duration(notReady) + "."
	case terminating:
		return StatusOK, "Terminating."
	case p.Phase == "Running":
		return StatusOK, "Running."
	case p.Phase == "Succeeded":
		return StatusOK, "Completed."
	}
	phase := p.Phase
	if phase == "" {
		phase = "unknown"
	}
	return StatusUnknown, "Phase " + phase + "."
}

// SummarizeNodes lists each node with the default policy.
func SummarizeNodes(nodes []model.Node, pods []model.Pod, ws []model.Workload, now time.Time) []NodeSummary {
	p := compatPolicy()
	a := Associate(listInventory(model.Inventory{Nodes: nodes, Pods: pods, Workloads: ws}), p)
	return SummarizeNodesWith(nodes, a, p, now)
}

// SummarizeNodesWith lists each node with its conditions, placement,
// requested resources and pods, sorted by name. Requests are summed over app
// containers of pods that have not terminated; pods are listed as on the map,
// and PodCount counts the live ones.
func SummarizeNodesWith(nodes []model.Node, a *Assoc, p Policy, now time.Time) []NodeSummary {
	t := p.Thresholds
	out := make([]NodeSummary, 0, len(nodes))
	for _, n := range nodes {
		s := NodeSummary{
			Name: n.Name, Roles: NodeRoles(n), Ready: n.Ready, Unschedulable: n.Unschedulable,
			KubeletVersion: n.KubeletVersion, OSImage: n.OSImage, ContainerRuntime: n.ContainerRuntime,
			Pressure: pressure(n), Taints: append([]string{}, n.Taints...),
			CPUAllocatableMilli: n.CPUAllocatableMilli, MemoryAllocatableBytes: n.MemoryAllocatableBytes,
			PodsAllocatable: n.PodsAllocatable, Pods: []NodePod{}, Placement: PlacementOf(n),
		}
		for _, pod := range a.PodsOnNode(n.Name) {
			if isLive(pod) {
				s.PodCount++
				for _, c := range pod.Specs {
					if !c.Init {
						s.CPURequestedMilli += c.CPURequestMilli
						s.MemoryRequestedBytes += c.MemoryRequestBytes
					}
				}
			}
			if !shownPod(pod, t.RecentPod, now) {
				continue
			}
			np := NodePod{Namespace: pod.Namespace, Name: pod.Name, Phase: pod.Phase, Ready: pod.Ready, Reason: PodReason(pod)}
			np.Status, _ = podStatus(pod, t, now)
			np.Workload = a.WorkloadOf(pod)
			s.Pods = append(s.Pods, np)
		}
		sort.Slice(s.Pods, func(i, j int) bool {
			if s.Pods[i].Namespace != s.Pods[j].Namespace {
				return s.Pods[i].Namespace < s.Pods[j].Namespace
			}
			return s.Pods[i].Name < s.Pods[j].Name
		})
		s.Status, s.Detail = judgeNode(n, s.Pressure)
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// pressure returns the node's resource pressure conditions that are True.
func pressure(n model.Node) []string {
	out := []string{}
	for _, c := range n.Conditions {
		switch c.Type {
		case "MemoryPressure", "DiskPressure", "PIDPressure":
			if c.Status == "True" {
				out = append(out, c.Type)
			}
		}
	}
	return out
}

func judgeNode(n model.Node, pressure []string) (string, string) {
	switch {
	case !n.Ready:
		if c, ok := condition(n.Conditions, "Ready"); ok && c.Message != "" {
			return StatusCrit, "Not ready: " + sentence(c.Message, "")
		}
		return StatusCrit, "Not ready."
	case len(pressure) > 0:
		return StatusWarn, "Reports " + list(pressure) + "."
	case n.Unschedulable:
		return StatusWarn, "Cordoned: no new pods are scheduled here."
	}
	return StatusOK, "Ready."
}
