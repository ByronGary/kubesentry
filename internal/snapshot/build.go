package snapshot

import (
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"
	"weak"

	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/model"
)

// versions numbers every view built in this process, so a version identifies
// one view (response caches key on it).
var versions atomic.Uint64

// Build runs every detector over inv once and returns the view. A zero (or
// partly zero) policy is filled from detectors.DefaultPolicy. Unused claims
// are listed regardless of age: filter on AgeHours for a minimum age.
func Build(inv model.Inventory, p detectors.Policy, now time.Time) *View {
	start := time.Now()
	p = p.WithDefaults()
	a := detectors.Associate(inv, p)
	rb := detectors.NewRBACIndex(inv.RBAC, p)

	v := &View{Version: versions.Add(1), Built: now, Inv: inv, Policy: p}

	v.Workloads = map[string][]detectors.WorkloadSummary{}
	for _, s := range detectors.SummarizeWorkloadsWith(inv.Workloads, a, p, now) {
		v.Workloads[s.Namespace] = append(v.Workloads[s.Namespace], s)
	}

	claims, volumes, classes := detectors.SummarizeStorageWith(inv.PVCs, inv.PVs, inv.StorageClasses, inv.Pods, p, now)
	v.Claims = map[string][]detectors.ClaimSummary{}
	for _, c := range claims {
		v.Claims[c.Namespace] = append(v.Claims[c.Namespace], c)
	}
	v.Volumes, v.Classes = volumes, classes

	v.Unused = map[string][]detectors.UnusedPVC{}
	for _, u := range detectors.FindUnusedPVCsWith(inv.PVCs, inv.Pods, inv.StorageClasses, now, 0, p.Pricing) {
		v.Unused[u.Namespace] = append(v.Unused[u.Namespace], u)
	}

	certs, issuers, reqs := detectors.SummarizeCertsWith(inv.Certs, p, now)
	v.Certs = map[string][]detectors.CertSummary{}
	for _, c := range certs {
		v.Certs[c.Namespace] = append(v.Certs[c.Namespace], c)
	}
	v.Requests = map[string][]detectors.RequestSummary{}
	for _, r := range reqs {
		v.Requests[r.Namespace] = append(v.Requests[r.Namespace], r)
	}
	v.Issuers = issuers

	findings, posture := detectors.AuditSecurityWith(a, p)
	v.Findings = map[string][]detectors.SecurityFinding{}
	for _, f := range findings {
		v.Findings[f.Namespace] = append(v.Findings[f.Namespace], f)
	}
	v.Posture = posture

	v.Nodes = detectors.SummarizeNodesWith(inv.Nodes, a, p, now)

	v.LivePods = map[string]int{}
	v.NamespacesWithPods = []string{}
	seen := map[string]bool{}
	for i := range inv.Pods {
		pod := &inv.Pods[i]
		if !seen[pod.Namespace] {
			seen[pod.Namespace] = true
			v.NamespacesWithPods = append(v.NamespacesWithPods, pod.Namespace)
		}
		if pod.Phase != "Succeeded" && pod.Phase != "Failed" {
			v.LivePods[pod.Namespace]++
		}
	}
	sort.Strings(v.NamespacesWithPods)

	e := &extras{assoc: a, rbac: rb}
	e.ready.Do(func() {})
	link(v, e)
	v.BuildDuration = time.Since(start)
	return v
}

// Assoc returns the view's pod and Service association index.
func (v *View) Assoc() *detectors.Assoc { return extrasOf(v).get(v).assoc }

// RBAC returns the view's RBAC index, which proposes candidate namespaces for
// authorization (auth.Candidates).
func (v *View) RBAC() *detectors.RBACIndex { return extrasOf(v).get(v).rbac }

// Topology returns the map of one namespace. It is built on first use and
// memoised for the life of the view; concurrent callers share one build. The
// graph is shared: do not modify it.
func (v *View) Topology(ns string) detectors.Graph {
	e := extrasOf(v).get(v)
	if !e.assoc.HasNamespace(ns) {
		// Not memoised, so arbitrary names cannot grow the cache.
		return detectors.BuildTopologyWith(ns, e.assoc, v.Policy, v.Built)
	}
	e.mu.Lock()
	if e.topo == nil {
		e.topo = map[string]*topoEntry{}
	}
	t := e.topo[ns]
	if t == nil {
		t = &topoEntry{}
		e.topo[ns] = t
	}
	e.mu.Unlock()
	t.once.Do(func() { t.g = detectors.BuildTopologyWith(ns, e.assoc, v.Policy, v.Built) })
	return t.g
}

// extras holds what a view computes besides its exported fields: the indexes
// and the memoised topologies. snapshot.go is a shared contract file, so they
// live in a side table keyed weakly by the view instead of in View itself;
// an entry goes away with its view.
type extras struct {
	ready sync.Once
	assoc *detectors.Assoc
	rbac  *detectors.RBACIndex

	mu   sync.Mutex
	topo map[string]*topoEntry
}

type topoEntry struct {
	once sync.Once
	g    detectors.Graph
}

var side sync.Map // weak.Pointer[View] → *extras

// extrasOf returns v's extras, creating empty ones for a view that was not
// made by Build (for example one assembled by hand in a test).
func extrasOf(v *View) *extras {
	if e, ok := side.Load(weak.Make(v)); ok {
		return e.(*extras)
	}
	return link(v, &extras{})
}

// link attaches e to v unless v already has extras, and returns v's extras.
func link(v *View, e *extras) *extras {
	k := weak.Make(v)
	actual, loaded := side.LoadOrStore(k, e)
	if !loaded {
		runtime.AddCleanup(v, func(k weak.Pointer[View]) { side.Delete(k) }, k)
	}
	return actual.(*extras)
}

// get builds the indexes from the view's own inventory if Build did not.
func (e *extras) get(v *View) *extras {
	e.ready.Do(func() {
		e.assoc = detectors.Associate(v.Inv, v.Policy)
		e.rbac = detectors.NewRBACIndex(v.Inv.RBAC, v.Policy)
	})
	return e
}

// withStale returns a copy of v marked stale with err, sharing v's indexes.
func withStale(v *View, err error) *View {
	nv := *v
	nv.Stale = true
	nv.Err = err.Error()
	link(&nv, extrasOf(v))
	return &nv
}
