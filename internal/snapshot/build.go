package snapshot

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"

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
	v.ext.Store(e)
	v.BuildDuration = time.Since(start)
	return v
}

// Assoc returns the view's pod and Service association index.
func (v *View) Assoc() *detectors.Assoc { return v.extras().assoc }

// RBAC returns the view's RBAC index, which proposes candidate namespaces for
// authorization (auth.Candidates).
func (v *View) RBAC() *detectors.RBACIndex { return v.extras().rbac }

// Topology returns the map of one namespace. It is built on first use and
// memoised for the life of the view; concurrent callers share one build. The
// graph is shared: do not modify it.
func (v *View) Topology(ns string) detectors.Graph {
	e := v.extras()
	if !e.assoc.HasNamespace(ns) {
		// Not memoised, so arbitrary names cannot grow the cache.
		return detectors.BuildTopologyWith(ns, e.assoc, v.Policy, v.Built)
	}
	e.mu.Lock()
	if e.topo == nil {
		e.topo = map[string]*memoEntry{}
	}
	t := e.topo[ns]
	if t == nil {
		t = &memoEntry{}
		e.topo[ns] = t
	}
	e.mu.Unlock()
	t.once.Do(func() { t.val = detectors.BuildTopologyWith(ns, e.assoc, v.Policy, v.Built) })
	return t.val.(detectors.Graph)
}

// Memo returns the value build computes from this view, computing it on the
// first call for key and sharing it with every later caller (concurrent
// callers wait for one build). It lets consumers such as the HTTP API keep
// derived data (sorted indexes, summaries) exactly as long as the view. Keys
// must come from a fixed set, never from request input; the value is shared
// and must not be modified.
func (v *View) Memo(key string, build func() any) any {
	e := v.extras()
	m, _ := e.memo.LoadOrStore(key, &memoEntry{})
	me := m.(*memoEntry)
	me.once.Do(func() { me.val = build() })
	return me.val
}

// extras holds what a view computes besides its exported fields: the indexes,
// the memoised topologies and Memo values. Build attaches them; a view
// assembled by hand (for example in a test, or for Static) gets empty ones on
// first use, whose indexes are then built from the view's own inventory.
type extras struct {
	ready sync.Once
	assoc *detectors.Assoc
	rbac  *detectors.RBACIndex

	mu   sync.Mutex
	topo map[string]*memoEntry // namespace → graph

	memo sync.Map // key → *memoEntry
}

type memoEntry struct {
	once sync.Once
	val  any
}

// extras returns v's extras, attaching empty ones on first use; concurrent
// first callers agree on one set.
func (v *View) extras() *extras {
	e := v.ext.Load()
	if e == nil {
		v.ext.CompareAndSwap(nil, &extras{})
		e = v.ext.Load()
	}
	e.ready.Do(func() {
		e.assoc = detectors.Associate(v.Inv, v.Policy)
		e.rbac = detectors.NewRBACIndex(v.Inv.RBAC, v.Policy)
	})
	return e
}

// withStale returns a copy of v marked stale with err, sharing v's indexes
// and memoised values. Fields are copied one by one because a View holds an
// atomic and must not be copied whole; TestWithStaleCopiesEveryField keeps
// this list complete.
func withStale(v *View, err error) *View {
	nv := &View{
		Version:            v.Version,
		Built:              v.Built,
		BuildDuration:      v.BuildDuration,
		Stale:              true,
		Err:                err.Error(),
		Inv:                v.Inv,
		Policy:             v.Policy,
		Workloads:          v.Workloads,
		Claims:             v.Claims,
		Unused:             v.Unused,
		Certs:              v.Certs,
		Requests:           v.Requests,
		Findings:           v.Findings,
		Posture:            v.Posture,
		Issuers:            v.Issuers,
		Nodes:              v.Nodes,
		Volumes:            v.Volumes,
		Classes:            v.Classes,
		NamespacesWithPods: v.NamespacesWithPods,
		LivePods:           v.LivePods,
	}
	nv.ext.Store(v.extras())
	return nv
}
