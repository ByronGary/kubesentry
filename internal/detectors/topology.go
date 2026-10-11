package detectors

import (
	"fmt"
	"sort"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
)

// recentPod is how long a Succeeded or Failed pod stays on the map.
const recentPod = 24 * time.Hour

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
	Now            time.Time
}

var graphKindOrder = map[string]int{
	"Ingress": 0, "Service": 1, "Deployment": 2, "StatefulSet": 3, "DaemonSet": 4,
	"Job": 5, "CronJob": 6, "Pod": 7, "PVC": 8, "Node": 9,
}

// BuildTopology maps one namespace: Ingress→Service→Workload→Pod→Node, and
// Pod→PVC. Pods are the live ones plus those that ended in the last day. A
// Service links to the workloads whose pods it selects, or straight to a pod
// that nothing owns. Nodes and edges come in a fixed order.
func BuildTopology(namespace string, in TopologyInput) Graph {
	b := graphBuilder{nodes: map[string]GraphNode{}, edges: map[GraphEdge]bool{}}
	id := func(kind, name string) string { return kind + "/" + namespace + "/" + name }

	var ws []model.Workload
	for _, w := range in.Workloads {
		if w.Namespace == namespace {
			ws = append(ws, w)
		}
	}
	var nsPods, shown, livePods []model.Pod
	for _, p := range in.Pods {
		if p.Namespace != namespace {
			continue
		}
		nsPods = append(nsPods, p)
		if shownPod(p, in.Now) {
			shown = append(shown, p)
		}
		if live(p) {
			livePods = append(livePods, p)
		}
	}

	for _, s := range SummarizeWorkloads(ws, nsPods, in.Now) {
		b.node(GraphNode{ID: id(s.Kind, s.Name), Kind: s.Kind, Name: s.Name, Namespace: namespace, Status: s.Status, Detail: s.Detail})
	}
	for _, w := range ws {
		if w.Kind != "Job" {
			continue
		}
		if parent, ok := cronJobOf(namespace, w.Name, ws); ok {
			b.edge(id("CronJob", parent), id("Job", w.Name))
		}
	}

	claims := map[string]bool{}
	hosts := map[string]bool{}
	for _, p := range shown {
		pid := id("Pod", p.Name)
		st, detail := podStatus(p, in.Now)
		b.node(GraphNode{ID: pid, Kind: "Pod", Name: p.Name, Namespace: namespace, Status: st, Detail: detail})
		if kind, name, ok := OwnerOf(p, ws); ok {
			b.edge(id(kind, name), pid)
		}
		if p.NodeName != "" {
			hosts[p.NodeName] = true
			b.edge(pid, "Node/"+p.NodeName)
		}
		for _, c := range p.Claims {
			claims[c] = true
			b.edge(pid, id("PVC", c))
		}
	}

	var nsPVCs []model.PVC
	for _, c := range in.PVCs {
		if c.Namespace == namespace {
			nsPVCs = append(nsPVCs, c)
		}
	}
	summaries, _, _ := SummarizeStorage(nsPVCs, nil, in.StorageClasses, nsPods, in.Now)
	byClaim := map[string]ClaimSummary{}
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

	nodes := map[string]model.Node{}
	for _, n := range in.Nodes {
		nodes[n.Name] = n
	}
	for h := range hosts {
		n := GraphNode{ID: "Node/" + h, Kind: "Node", Name: h, Status: StatusUnknown, Detail: "Not in the node list."}
		if node, ok := nodes[h]; ok {
			n.Status, n.Detail = judgeNode(node, pressure(node))
		}
		b.node(n)
	}

	services := map[string]bool{}
	for _, svc := range in.Services {
		if svc.Namespace != namespace {
			continue
		}
		services[svc.Name] = true
		sid := id("Service", svc.Name)
		n := GraphNode{ID: sid, Kind: "Service", Name: svc.Name, Namespace: namespace}
		switch {
		case svc.Type == "ExternalName":
			n.Status, n.Detail = StatusOK, "Points outside the cluster (ExternalName)."
		case len(svc.Selector) == 0:
			n.Status, n.Detail = StatusOK, "No selector; its endpoints are managed separately."
		default:
			sel := &model.LabelSelector{MatchLabels: svc.Selector}
			matched := 0
			for _, p := range livePods {
				if !MatchSelector(sel, p.Labels) {
					continue
				}
				matched++
				if kind, name, ok := OwnerOf(p, ws); ok {
					b.edge(sid, id(kind, name))
				} else {
					b.edge(sid, id("Pod", p.Name))
				}
			}
			if matched == 0 {
				n.Status, n.Detail = StatusWarn, "Selects no pods."
			} else {
				n.Status, n.Detail = StatusOK, fmt.Sprintf("%s, selects %d %s.", svcType(svc.Type), matched, plural(matched, "pod", "pods"))
			}
		}
		b.node(n)
	}

	for _, ing := range in.Ingresses {
		if ing.Namespace != namespace {
			continue
		}
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
				b.edge(iid, id("Service", svc))
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
		case len(ing.TLS) > 0:
			n.Detail = "Routes " + list(hostNames) + " with TLS."
		default:
			n.Detail = "Routes " + list(hostNames) + " without TLS."
		}
		b.node(n)
	}
	return b.graph()
}

func svcType(t string) string {
	if t == "" {
		return "ClusterIP"
	}
	return t
}

type graphBuilder struct {
	nodes map[string]GraphNode
	edges map[GraphEdge]bool
}

func (b *graphBuilder) node(n GraphNode) { b.nodes[n.ID] = n }

func (b *graphBuilder) edge(from, to string) { b.edges[GraphEdge{From: from, To: to}] = true }

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
	for e := range b.edges {
		if _, ok := b.nodes[e.From]; !ok {
			continue
		}
		if _, ok := b.nodes[e.To]; !ok {
			continue
		}
		g.Edges = append(g.Edges, e)
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
func shownPod(p model.Pod, now time.Time) bool {
	return live(p) || (!p.Created.IsZero() && now.Sub(p.Created) < recentPod)
}

// podStatus is a one-line verdict for a pod on the map, using the same
// restart threshold as the pod page.
func podStatus(p model.Pod, now time.Time) (string, string) {
	var restarts int32
	var oom []string
	for _, c := range p.Containers {
		restarts += c.RestartCount
		if c.LastTerminatedReason == "OOMKilled" && now.Sub(c.LastTerminatedAt) <= 24*time.Hour {
			oom = append(oom, c.Name+" ("+ago(now.Sub(c.LastTerminatedAt))+")")
		}
	}
	switch {
	case p.Phase == "Failed":
		return StatusCrit, "Failed."
	case p.Phase == "Pending":
		return StatusWarn, "Pending."
	case len(oom) > 0:
		return StatusWarn, "OOMKilled: " + list(oom) + "."
	case restarts >= 3:
		return StatusWarn, fmt.Sprintf("%d restarts.", restarts)
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

// SummarizeNodes lists each node with its conditions, requested resources and
// pods, sorted by name. Requests are summed over app containers of pods that
// have not terminated; pods are listed as on the map.
func SummarizeNodes(nodes []model.Node, pods []model.Pod, ws []model.Workload, now time.Time) []NodeSummary {
	byNode := map[string][]model.Pod{}
	for _, p := range pods {
		if p.NodeName != "" {
			byNode[p.NodeName] = append(byNode[p.NodeName], p)
		}
	}
	out := make([]NodeSummary, 0, len(nodes))
	for _, n := range nodes {
		s := NodeSummary{
			Name: n.Name, Roles: append([]string{}, n.Roles...), Ready: n.Ready, Unschedulable: n.Unschedulable,
			KubeletVersion: n.KubeletVersion, OSImage: n.OSImage, ContainerRuntime: n.ContainerRuntime,
			Pressure: pressure(n), Taints: append([]string{}, n.Taints...),
			CPUAllocatableMilli: n.CPUAllocatableMilli, MemoryAllocatableBytes: n.MemoryAllocatableBytes,
			PodsAllocatable: n.PodsAllocatable, Pods: []NodePod{},
		}
		for _, p := range byNode[n.Name] {
			if live(p) {
				for _, c := range p.Specs {
					if !c.Init {
						s.CPURequestedMilli += c.CPURequestMilli
						s.MemoryRequestedBytes += c.MemoryRequestBytes
					}
				}
			}
			if !shownPod(p, now) {
				continue
			}
			np := NodePod{Namespace: p.Namespace, Name: p.Name, Phase: p.Phase}
			np.Status, _ = podStatus(p, now)
			if kind, name, ok := OwnerOf(p, ws); ok {
				np.Workload = kind + "/" + name
			}
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
