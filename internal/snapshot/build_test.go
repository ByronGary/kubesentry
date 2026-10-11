package snapshot

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"sync"
	"testing"

	"github.com/ByronGary/kubesentry/internal/auth"
	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/model"
)

func TestBuildFillsTheView(t *testing.T) {
	inv, _ := synthInventory(sizeSmall)
	v := Build(inv, detectors.DefaultPolicy(), synthNow)

	if v.Version == 0 || !v.Built.Equal(synthNow) || v.BuildDuration <= 0 || v.Stale {
		t.Errorf("header = %d %v %v %v", v.Version, v.Built, v.BuildDuration, v.Stale)
	}
	nonEmpty := map[string]int{
		"workloads": len(v.Workloads), "claims": len(v.Claims), "unused": len(v.Unused), "certs": len(v.Certs),
		"findings": len(v.Findings), "posture": len(v.Posture), "issuers": len(v.Issuers), "nodes": len(v.Nodes),
		"classes": len(v.Classes), "namespaces": len(v.NamespacesWithPods), "livePods": len(v.LivePods),
	}
	for k, n := range nonEmpty {
		if n == 0 {
			t.Errorf("%s is empty", k)
		}
	}
	if v.Volumes == nil || v.Requests == nil {
		t.Error("volumes and requests must be non-nil")
	}

	total := 0
	for ns, ws := range v.Workloads {
		for _, w := range ws {
			total++
			if w.Namespace != ns {
				t.Fatalf("workload %s/%s filed under %q", w.Namespace, w.Name, ns)
			}
		}
	}
	if total != len(inv.Workloads) {
		t.Errorf("%d workload summaries for %d workloads", total, len(inv.Workloads))
	}
	for ns, fs := range v.Findings {
		for _, f := range fs {
			if f.Namespace != ns {
				t.Fatalf("finding %s filed under %q", f.ID, ns)
			}
		}
	}
	if fs := v.Findings[""]; len(fs) == 0 || fs[0].Check != detectors.CheckAWSAuthMasters {
		t.Errorf("cluster-scoped findings should lead with aws-auth: %+v", fs)
	}
	if !sort.StringsAreSorted(v.NamespacesWithPods) {
		t.Error("NamespacesWithPods must be sorted")
	}
	live := 0
	for _, n := range v.LivePods {
		live += n
	}
	if live != len(inv.Pods) {
		t.Errorf("live pods %d, want %d", live, len(inv.Pods))
	}

	// The unused list ignores age; the claims carry prices.
	for _, us := range v.Unused {
		for _, u := range us {
			if u.StorageClass == "gp3" && (!u.CostKnown || u.PriceSource != detectors.PriceFromEBSTable) {
				t.Fatalf("gp3 claim unpriced: %+v", u)
			}
			if u.StorageClass == "efs" && (u.CostKnown || u.PriceSource != detectors.PriceUsageBilled) {
				t.Fatalf("efs claim priced: %+v", u)
			}
		}
	}

	if got := v.RBAC().Namespaces("someone", []string{"group-team-003"}, auth.ViewNamespace); len(got) == 0 {
		t.Error("RBAC index finds no namespaces for a bound group")
	}
	if v.Assoc() == nil || v.Assoc() != v.Assoc() {
		t.Error("Assoc must be built once")
	}
}

// A cache shares the inventory between calls, so building a view (and
// everything a view computes later) must leave it exactly as it was.
func TestBuildLeavesInventoryUntouched(t *testing.T) {
	inv, _ := synthInventory(sizeSmall)
	// Reverse the lists so an accidental in-place sort would show, and give
	// some objects unsorted inner slices.
	rev := func(n int, swap func(i, j int)) {
		for i, j := 0, n-1; i < j; i, j = i+1, j-1 {
			swap(i, j)
		}
	}
	rev(len(inv.Pods), func(i, j int) { inv.Pods[i], inv.Pods[j] = inv.Pods[j], inv.Pods[i] })
	rev(len(inv.Workloads), func(i, j int) { inv.Workloads[i], inv.Workloads[j] = inv.Workloads[j], inv.Workloads[i] })
	rev(len(inv.Services), func(i, j int) { inv.Services[i], inv.Services[j] = inv.Services[j], inv.Services[i] })
	rev(len(inv.EndpointSlices), func(i, j int) {
		inv.EndpointSlices[i], inv.EndpointSlices[j] = inv.EndpointSlices[j], inv.EndpointSlices[i]
	})
	rev(len(inv.PVCs), func(i, j int) { inv.PVCs[i], inv.PVCs[j] = inv.PVCs[j], inv.PVCs[i] })
	rev(len(inv.Nodes), func(i, j int) { inv.Nodes[i], inv.Nodes[j] = inv.Nodes[j], inv.Nodes[i] })
	rev(len(inv.RBAC.Bindings), func(i, j int) {
		inv.RBAC.Bindings[i], inv.RBAC.Bindings[j] = inv.RBAC.Bindings[j], inv.RBAC.Bindings[i]
	})
	rev(len(inv.Certs.Certificates), func(i, j int) {
		inv.Certs.Certificates[i], inv.Certs.Certificates[j] = inv.Certs.Certificates[j], inv.Certs.Certificates[i]
	})
	inv.Nodes[0].Roles = []string{"z", "a"}
	inv.Nodes[0].Taints = []string{"z=1:NoSchedule", "a=1:NoSchedule"}
	inv.Workloads[0].Images = []string{"z:1", "a:1"}
	inv.Certs.Certificates[0].DNSNames = []string{"z.example.com", "a.example.com"}
	inv.Pods[0].Claims = []string{"z", "a", "z"}
	inv.Unavailable["something"] = "forbidden"
	before, err := json.Marshal(inv)
	if err != nil {
		t.Fatal(err)
	}

	src := &fakeSource{inv: inv}
	v, err := OnDemand{Source: src}.View(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, ns := range v.Assoc().Namespaces() {
		v.Topology(ns)
	}
	a := v.Assoc()
	for i := range inv.Pods {
		detectors.PodSummaryOf(&inv.Pods[i], a)
		a.ServicesOfPod(inv.Pods[i].UID)
	}
	v.RBAC().Namespaces("u", []string{"group-team-001"}, auth.ViewNamespace)
	Build(inv, detectors.Policy{}, synthNow) // a second build over the same, shared inventory

	after, _ := json.Marshal(inv)
	if string(after) != string(before) {
		t.Error("building a view modified the inventory it was given")
	}
	if after, _ := json.Marshal(v.Inv); string(after) != string(before) {
		t.Error("the view's inventory differs from the source's")
	}
}

func TestViewTopologyIsMemoised(t *testing.T) {
	inv, _ := synthInventory(sizeSmall)
	v := Build(inv, detectors.DefaultPolicy(), synthNow)
	ns := v.NamespacesWithPods[1]

	var wg sync.WaitGroup
	graphs := make([]detectors.Graph, 8)
	for i := range graphs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			graphs[i] = v.Topology(ns)
		}()
	}
	wg.Wait()
	if len(graphs[0].Nodes) == 0 || len(graphs[0].Edges) == 0 {
		t.Fatalf("empty map for %s", ns)
	}
	for _, g := range graphs[1:] {
		if &g.Nodes[0] != &graphs[0].Nodes[0] {
			t.Fatal("concurrent callers should share one memoised build")
		}
	}
	hows := map[string]int{}
	for _, e := range graphs[0].Edges {
		hows[e.How]++
	}
	if hows[detectors.HowOwner] == 0 || hows[detectors.HowEndpoints] == 0 || hows[detectors.HowSelector] != 0 {
		t.Errorf("edge kinds = %v", hows)
	}
	if g := v.Topology("no-such-namespace"); len(g.Nodes) != 0 || g.Nodes == nil {
		t.Errorf("unknown namespace = %+v", g)
	}
}

func TestHandMadeViewBuildsIndexesLazily(t *testing.T) {
	v := &View{Inv: smallInventory(), Policy: detectors.DefaultPolicy()}
	if v.Assoc() == nil || v.RBAC() == nil {
		t.Fatal("indexes should be built on demand")
	}
	if g := v.Topology("a"); len(g.Nodes) != 2 {
		t.Errorf("hand-made view topology = %+v", g)
	}
	stale := withStale(v, errors.New("x"))
	if stale.Assoc() != v.Assoc() || !stale.Stale {
		t.Error("withStale should share the indexes")
	}
}

func TestHandMadeViewIsSafeUnderConcurrency(t *testing.T) {
	v := &View{Inv: smallInventory(), Policy: detectors.DefaultPolicy()}
	var wg sync.WaitGroup
	assocs := make([]*detectors.Assoc, 16)
	memos := make([]any, 16)
	builds := 0
	var mu sync.Mutex
	for i := range assocs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			assocs[i] = v.Assoc()
			v.Topology("a")
			memos[i] = v.Memo("k", func() any {
				mu.Lock()
				builds++
				mu.Unlock()
				return new(int)
			})
		}()
	}
	wg.Wait()
	for i := range assocs {
		if assocs[i] != assocs[0] || memos[i] != memos[0] {
			t.Fatal("concurrent first callers must share one set of extras")
		}
	}
	if builds != 1 {
		t.Errorf("Memo built %d times, want 1", builds)
	}
	if got := withStale(v, errors.New("x")).Memo("k", func() any { return nil }); got != memos[0] {
		t.Error("a stale copy shares memoised values")
	}
}

// withStale copies a View field by field; this catches a field added to View
// but not to that list.
func TestWithStaleCopiesEveryField(t *testing.T) {
	inv, _ := synthInventory(sizeSmall)
	v := Build(inv, detectors.DefaultPolicy(), synthNow)
	s := withStale(v, errors.New("boom"))
	rv, rs := reflect.ValueOf(v).Elem(), reflect.ValueOf(s).Elem()
	for i := 0; i < rv.NumField(); i++ {
		f := rv.Type().Field(i)
		switch {
		case !f.IsExported():
			continue
		case f.Name == "Stale" || f.Name == "Err":
			continue
		case rv.Field(i).IsZero():
			t.Errorf("field %s is zero in the built view; the test needs data there", f.Name)
		case !reflect.DeepEqual(rv.Field(i).Interface(), rs.Field(i).Interface()):
			t.Errorf("withStale does not copy %s", f.Name)
		}
	}
	if !s.Stale || s.Err != "boom" || v.Stale {
		t.Errorf("stale = %v %q, original stale = %v", s.Stale, s.Err, v.Stale)
	}
}

// listFakes satisfy the list interfaces; err fails the named sources.
type listFakes struct {
	fail map[string]error
	inv  model.Inventory
}

func (f listFakes) e(name string) error { return f.fail[name] }

func (f listFakes) ListPVCs(context.Context) ([]model.PVC, error) {
	return f.inv.PVCs, f.e(SourcePVCs)
}
func (f listFakes) ListPods(context.Context) ([]model.Pod, error) {
	return f.inv.Pods, f.e(SourcePods)
}
func (f listFakes) GetPod(context.Context, string, string) (*model.Pod, error) {
	return nil, model.ErrNotFound
}
func (f listFakes) GetPVC(context.Context, string, string) (*model.PVC, error) {
	return nil, model.ErrNotFound
}
func (f listFakes) ListWorkloads(context.Context) ([]model.Workload, error) {
	return f.inv.Workloads, f.e(SourceWorkloads)
}
func (f listFakes) ListServices(context.Context) ([]model.Service, error) {
	return f.inv.Services, f.e(SourceServices)
}
func (f listFakes) ListIngresses(context.Context) ([]model.Ingress, error) {
	return f.inv.Ingresses, f.e(SourceIngresses)
}
func (f listFakes) ListNodes(context.Context) ([]model.Node, error) {
	return f.inv.Nodes, f.e(SourceNodes)
}
func (f listFakes) ListPVs(context.Context) ([]model.PV, error) { return f.inv.PVs, f.e(SourcePVs) }
func (f listFakes) ListStorageClasses(context.Context) ([]model.StorageClass, error) {
	return f.inv.StorageClasses, f.e(SourceStorageClasses)
}
func (f listFakes) ListNamespaces(context.Context) ([]model.Namespace, error) {
	return f.inv.Namespaces, f.e(SourceNamespaces)
}
func (f listFakes) ListRBAC(context.Context) (model.RBAC, error) { return f.inv.RBAC, f.e(SourceRBAC) }
func (f listFakes) CertManager(context.Context) (model.CertManager, error) {
	return f.inv.Certs, f.e(SourceCertManager)
}

type withSlices struct{ listFakes }

func (w withSlices) ListEndpointSlices(context.Context) ([]model.EndpointSlice, error) {
	return w.inv.EndpointSlices, nil
}
func (w withSlices) ListReplicaSets(context.Context) ([]model.ReplicaSet, error) {
	return w.inv.ReplicaSets, nil
}

func TestFromLists(t *testing.T) {
	inv, _ := synthInventory(sizeSmall)
	forbidden := errors.New(`rolebindings.rbac.authorization.k8s.io is forbidden`)
	f := listFakes{inv: inv, fail: map[string]error{SourceRBAC: forbidden}}

	got, err := FromLists(f, f, f).Inventory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Unavailable[SourceRBAC] != forbidden.Error() || len(got.RBAC.Bindings) != 0 {
		t.Errorf("RBAC should be unavailable: %v", got.Unavailable)
	}
	if got.Unavailable[detectors.SourceEndpointSlices] == "" || got.Unavailable[detectors.SourceReplicaSets] == "" {
		t.Errorf("the list interfaces cannot provide slices or ReplicaSets: %v", got.Unavailable)
	}
	if len(got.Pods) != len(inv.Pods) || len(got.Services) != len(inv.Services) || got.ReadAt.IsZero() {
		t.Errorf("lists not copied: %d pods, %d services", len(got.Pods), len(got.Services))
	}
	// Without slices the view falls back to selectors, as the old handlers did.
	v := Build(got, detectors.DefaultPolicy(), synthNow)
	s := inv.Services[1]
	if how := v.Assoc().ServiceHow(s.Namespace, s.Name); how != detectors.HowSelector {
		t.Errorf("service %s via %q, want selector", s.Name, how)
	}

	rich, err := FromLists(withSlices{f}, withSlices{f}, nil).Inventory(context.Background())
	if err != nil || rich.Unavailable[detectors.SourceEndpointSlices] != "" || len(rich.EndpointSlices) == 0 || rich.Unavailable[SourceCertManager] != "not configured" {
		t.Errorf("optional listers: %v %v", rich.Unavailable, err)
	}

	only, err := FromLists(f, nil, nil).Inventory(context.Background())
	if err != nil || only.Unavailable[SourceWorkloads] != "not configured" || len(only.Pods) == 0 {
		t.Errorf("cluster only: %v %v", only.Unavailable, err)
	}

	down := errors.New("connection refused")
	all := listFakes{fail: map[string]error{}}
	for _, n := range []string{SourcePods, SourcePVCs, SourceWorkloads, SourceServices, SourceIngresses, SourceNodes, SourcePVs, SourceStorageClasses, SourceNamespaces, SourceRBAC, SourceCertManager} {
		all.fail[n] = down
	}
	if _, err := FromLists(all, all, all).Inventory(context.Background()); !errors.Is(err, down) {
		t.Errorf("every source failing is an error, got %v", err)
	}
}
