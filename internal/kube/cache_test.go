package kube

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/version"
	fakediscovery "k8s.io/client-go/discovery/fake"
	dynfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/ByronGary/kubesentry/internal/model"
)

const eksVersion = "v1.33.4-eks-a737599"

// newFakes builds a fake clientset whose SelfSubjectAccessReviews allow
// everything deny does not match, and a dynamic fake holding certs.
func newFakes(objs, certs []runtime.Object, deny func(*authorizationv1.ResourceAttributes) bool) (*fake.Clientset, *dynfake.FakeDynamicClient) {
	cs := fake.NewClientset(objs...)
	cs.PrependReactor("create", "selfsubjectaccessreviews", func(a k8stesting.Action) (bool, runtime.Object, error) {
		r := a.(k8stesting.CreateAction).GetObject().(*authorizationv1.SelfSubjectAccessReview).DeepCopy()
		r.Status.Allowed = deny == nil || !deny(r.Spec.ResourceAttributes)
		if !r.Status.Allowed {
			r.Status.Reason = "RBAC: no rule"
		}
		return true, r, nil
	})
	disc := cs.Discovery().(*fakediscovery.FakeDiscovery)
	disc.FakedServerVersion = &version.Info{GitVersion: eksVersion}
	if certs != nil {
		disc.Resources = []*metav1.APIResourceList{{GroupVersion: certManagerGroupVersion}}
	}
	dyn := dynfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), certListKinds, certs...)
	return cs, dyn
}

// startCache starts c and waits for it to sync; the informers stop at the end of the test.
func startCache(t *testing.T, c *Cache) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	wctx, wcancel := context.WithTimeout(ctx, 10*time.Second)
	defer wcancel()
	if err := c.WaitSynced(wctx); err != nil {
		t.Fatal(err)
	}
}

// eventually polls cond until it holds or 5s pass.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func drain(ch <-chan struct{}) int {
	n := 0
	for {
		select {
		case <-ch:
			n++
		default:
			return n
		}
	}
}

func waitSignal(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("no change signal after %s", what)
	}
}

func pod(name, uid, rv string, labels map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: name, UID: types.UID("uid-" + uidOr(uid, name)), ResourceVersion: rv, Labels: labels},
		Spec:       corev1.PodSpec{NodeName: "n1", Containers: []corev1.Container{{Name: "c", Image: "img", Env: []corev1.EnvVar{{Name: "SECRET", Value: "x"}}}}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

func uidOr(uid, name string) string {
	if uid != "" {
		return uid
	}
	return name
}

func TestCacheSyncAndChanges(t *testing.T) {
	cs, _ := newFakes([]runtime.Object{pod("a", "", "1", map[string]string{"v": "1"})}, nil, nil)
	c := NewCache(&Clients{CS: cs, Disc: cs.Discovery()}, CacheOptions{})
	if c.Ready() {
		t.Fatal("ready before start")
	}
	if _, err := c.Inventory(context.Background()); !errors.Is(err, ErrNotSynced) {
		t.Fatalf("inventory before start: %v", err)
	}
	startCache(t, c)
	if !c.Ready() {
		t.Fatal("not ready after WaitSynced")
	}
	ctx := context.Background()
	inv, err := c.Inventory(ctx)
	if err != nil || len(inv.Pods) != 1 || len(inv.Unavailable) != 0 || inv.Certs.Installed || inv.AWSAuth != nil {
		t.Fatalf("initial inventory: %+v, %v", inv, err)
	}
	if inv.Cluster.Version != eksVersion || inv.Cluster.Platform != "eks" {
		t.Errorf("cluster: %+v", inv.Cluster)
	}
	drain(c.Changes())

	pods := cs.CoreV1().Pods("app")
	if _, err := pods.Create(ctx, pod("b", "", "2", nil), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	waitSignal(t, c.Changes(), "create")
	eventually(t, "second pod", func() bool { inv, _ := c.Inventory(ctx); return len(inv.Pods) == 2 })

	// An update with a new resourceVersion is converted again (memo miss).
	if _, err := pods.Update(ctx, pod("a", "", "3", map[string]string{"v": "2"}), metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	waitSignal(t, c.Changes(), "update")
	eventually(t, "updated label", func() bool {
		p, err := c.GetPod(ctx, "app", "a")
		return err == nil && p.Labels["v"] == "2"
	})

	if err := pods.Delete(ctx, "b", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	waitSignal(t, c.Changes(), "delete")
	eventually(t, "deleted pod", func() bool { inv, _ := c.Inventory(ctx); return len(inv.Pods) == 1 })
	if n := c.m.pods.size(); n != 1 {
		t.Errorf("memo keeps %d pods after the delete, want 1", n)
	}
	if _, err := c.GetPod(ctx, "app", "b"); !errors.Is(err, model.ErrNotFound) {
		t.Errorf("deleted pod: %v", err)
	}

	// Many changes coalesce into at most one pending signal, and the reader
	// is never blocked.
	drain(c.Changes())
	for i := range 20 {
		if _, err := pods.Create(ctx, pod(fmt.Sprintf("burst-%d", i), "", "10", nil), metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	eventually(t, "burst", func() bool { inv, _ := c.Inventory(ctx); return len(inv.Pods) == 21 })
	if n := drain(c.Changes()); n > 1 {
		t.Errorf("%d pending signals, want at most 1", n)
	}

	// The transform ran: the cached pod has no env.
	obj, _, _ := c.res["pods"].inf.GetStore().GetByKey("app/a")
	if env := obj.(*corev1.Pod).Spec.Containers[0].Env; env != nil {
		t.Errorf("informer kept env: %v", env)
	}
	if counts := c.ObjectCounts(); counts["pods"] != 21 {
		t.Errorf("object counts: %v", counts)
	}
}

// fieldDiff names the Inventory fields that differ.
func fieldDiff(got, want model.Inventory) []string {
	var out []string
	gv, wv := reflect.ValueOf(got), reflect.ValueOf(want)
	for i := range gv.NumField() {
		if !reflect.DeepEqual(gv.Field(i).Interface(), wv.Field(i).Interface()) {
			out = append(out, fmt.Sprintf("%s:\n got %+v\nwant %+v", gv.Type().Field(i).Name, gv.Field(i).Interface(), wv.Field(i).Interface()))
		}
	}
	return out
}

func TestCacheInventoryMatchesSource(t *testing.T) {
	cs, dyn := newFakes(fixtureObjects(), certObjects(), nil)
	fixed := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	add, apps := []string{"example.com/rack"}, []string{"team"}
	src := NewSourceWithOptions(cs, dyn, SourceOptions{AWSAuth: true, NodeLabelKeysAdd: add, AppLabelKeys: apps, ClusterName: "prod", Now: func() time.Time { return fixed }})
	c := NewCache(&Clients{CS: cs, Dyn: dyn, Disc: cs.Discovery()}, CacheOptions{AWSAuth: true, NodeLabelKeysAdd: add, AppLabelKeys: apps, ClusterName: "prod", Now: func() time.Time { return fixed }})
	startCache(t, c)
	ctx := context.Background()

	want, err := src.Inventory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Inventory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range fieldDiff(got, want) {
		t.Error(d)
	}
	// Twice: the second read comes from the memo and must not differ.
	again, _ := c.Inventory(ctx)
	for _, d := range fieldDiff(again, want) {
		t.Error("memoized read: " + d)
	}

	// Sanity on the shared expectations, so an empty-vs-empty match cannot pass.
	if len(got.Pods) != 3 || len(got.Workloads) != 5 || len(got.ReplicaSets) != 2 || len(got.EndpointSlices) != 1 ||
		len(got.RBAC.Roles) != 3 || len(got.RBAC.Bindings) != 2 || !got.Certs.Installed || len(got.Certs.Issuers) != 2 ||
		got.AWSAuth == nil || len(got.AWSAuth.MapRoles) != 2 || len(got.Unavailable) != 0 || !got.ReadAt.Equal(fixed) {
		t.Errorf("inventory: %+v", got)
	}
	if got.Cluster != (model.ClusterInfo{Name: "prod", Version: eksVersion, Platform: "eks", Provider: "aws", Region: "us-east-1"}) {
		t.Errorf("cluster: %+v", got.Cluster)
	}
	if kinds := []string{got.Workloads[0].Kind, got.Workloads[4].Kind}; kinds[0] != "Deployment" || kinds[1] != "CronJob" {
		t.Errorf("workload order: %v", kinds)
	}
	if w := got.Workloads[0]; w.Revision != "7" || w.Labels["team"] != "payments" || w.Labels["app.kubernetes.io/part-of"] != "shop" {
		t.Errorf("deployment tags and revision: %q %v", w.Revision, w.Labels)
	}

	// The older per-resource interfaces agree as well.
	check := func(name string, a, b any, errA, errB error) {
		t.Helper()
		if errA != nil || errB != nil || !reflect.DeepEqual(a, b) {
			t.Errorf("%s: cache %+v (%v), source %+v (%v)", name, a, errA, b, errB)
		}
	}
	{
		a, ea := c.ListPods(ctx)
		b, eb := src.ListPods(ctx)
		check("ListPods", a, b, ea, eb)
	}
	{
		a, ea := c.ListPVCs(ctx)
		b, eb := src.ListPVCs(ctx)
		check("ListPVCs", a, b, ea, eb)
	}
	{
		a, ea := c.ListWorkloads(ctx)
		b, eb := src.ListWorkloads(ctx)
		check("ListWorkloads", a, b, ea, eb)
	}
	{
		a, ea := c.ListServices(ctx)
		b, eb := src.ListServices(ctx)
		check("ListServices", a, b, ea, eb)
	}
	{
		a, ea := c.ListIngresses(ctx)
		b, eb := src.ListIngresses(ctx)
		check("ListIngresses", a, b, ea, eb)
	}
	{
		a, ea := c.ListNodes(ctx)
		b, eb := src.ListNodes(ctx)
		check("ListNodes", a, b, ea, eb)
	}
	{
		a, ea := c.ListPVs(ctx)
		b, eb := src.ListPVs(ctx)
		check("ListPVs", a, b, ea, eb)
	}
	{
		a, ea := c.ListStorageClasses(ctx)
		b, eb := src.ListStorageClasses(ctx)
		check("ListStorageClasses", a, b, ea, eb)
	}
	{
		a, ea := c.ListNamespaces(ctx)
		b, eb := src.ListNamespaces(ctx)
		check("ListNamespaces", a, b, ea, eb)
	}
	{
		a, ea := c.ListRBAC(ctx)
		b, eb := src.ListRBAC(ctx)
		check("ListRBAC", a, b, ea, eb)
	}
	{
		a, ea := c.CertManager(ctx)
		b, eb := src.CertManager(ctx)
		check("CertManager", a, b, ea, eb)
	}
	{
		a, ea := c.GetPod(ctx, "app", "crash-0")
		b, eb := src.GetPod(ctx, "app", "crash-0")
		check("GetPod", a, b, ea, eb)
	}
	{
		a, ea := c.GetPVC(ctx, "app", "data")
		b, eb := src.GetPVC(ctx, "app", "data")
		check("GetPVC", a, b, ea, eb)
	}
	if _, err := c.GetPVC(ctx, "app", "missing"); !errors.Is(err, model.ErrNotFound) {
		t.Errorf("missing pvc: %v", err)
	}
}

func TestForbiddenResourceIsUnavailable(t *testing.T) {
	deny := func(a *authorizationv1.ResourceAttributes) bool {
		return a.Resource == "nodes" || (a.Resource == "clusterrolebindings" && a.Verb == "watch") || a.Resource == "configmaps"
	}
	cs, _ := newFakes(fixtureObjects(), nil, deny)
	// The probe allows persistentvolumes, but the LIST itself is forbidden: the
	// informer must give up waiting instead of blocking WaitSynced.
	forbidden := apierrors.NewForbidden(schema.GroupResource{Resource: "persistentvolumes"}, "", errors.New("RBAC: access denied"))
	cs.PrependReactor("list", "persistentvolumes", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, forbidden
	})
	c := NewCache(&Clients{CS: cs, Disc: cs.Discovery()}, CacheOptions{AWSAuth: true})
	startCache(t, c)
	ctx := context.Background()

	inv, err := c.Inventory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"nodes", "clusterrolebindings", "persistentvolumes", awsAuthName} {
		if r := inv.Unavailable[name]; !strings.Contains(r, "forbidden") {
			t.Errorf("Unavailable[%s] = %q", name, r)
		}
	}
	if !strings.Contains(inv.Unavailable["clusterrolebindings"], "cannot watch") {
		t.Errorf("reason should name the verb: %q", inv.Unavailable["clusterrolebindings"])
	}
	if len(inv.Unavailable) != 4 {
		t.Errorf("unavailable: %v", inv.Unavailable)
	}
	if inv.Nodes != nil || inv.PVs != nil || inv.AWSAuth != nil || len(inv.RBAC.Bindings) != 1 || len(inv.Pods) != 3 {
		t.Errorf("inventory: nodes %v, pvs %v, aws-auth %v, bindings %v, pods %d", inv.Nodes, inv.PVs, inv.AWSAuth, inv.RBAC.Bindings, len(inv.Pods))
	}
	// Without nodes the cluster is identified by its version only.
	if inv.Cluster.Platform != "eks" || inv.Cluster.Provider != "" {
		t.Errorf("cluster: %+v", inv.Cluster)
	}
	if !reflect.DeepEqual(c.Unavailable(), inv.Unavailable) {
		t.Errorf("Unavailable(): %v", c.Unavailable())
	}
	if _, err := c.ListNodes(ctx); err == nil || !strings.Contains(err.Error(), "nodes unavailable") {
		t.Errorf("ListNodes: %v", err)
	}
	if _, err := c.ListRBAC(ctx); err == nil {
		t.Error("ListRBAC should fail without clusterrolebindings")
	}
	if _, err := c.ListPods(ctx); err != nil {
		t.Errorf("ListPods: %v", err)
	}

	// The per-request Source reports the forbidden LIST the same way.
	srcInv, err := NewSource(cs, nil).Inventory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if r := srcInv.Unavailable["persistentvolumes"]; !strings.Contains(r, "forbidden") || srcInv.PVs != nil {
		t.Errorf("source: %v", srcInv.Unavailable)
	}
}

// switchDiscovery serves cert-manager.io/v1 only while served is set.
type switchDiscovery struct {
	*fakediscovery.FakeDiscovery
	served atomic.Bool
}

func (d *switchDiscovery) ServerResourcesForGroupVersion(gv string) (*metav1.APIResourceList, error) {
	if gv == certManagerGroupVersion && d.served.Load() {
		return &metav1.APIResourceList{GroupVersion: gv}, nil
	}
	return nil, apierrors.NewNotFound(schema.GroupResource{Group: "discovery"}, gv)
}

func TestCertManagerAppearsLater(t *testing.T) {
	cs, dyn := newFakes(nil, certObjects(), nil)
	disc := &switchDiscovery{FakeDiscovery: cs.Discovery().(*fakediscovery.FakeDiscovery)}
	c := NewCache(&Clients{CS: cs, Dyn: dyn, Disc: disc}, CacheOptions{CertManagerRecheck: 20 * time.Millisecond})
	startCache(t, c)
	ctx := context.Background()

	inv, err := c.Inventory(ctx)
	if err != nil || inv.Certs.Installed {
		t.Fatalf("before install: %+v, %v", inv.Certs, err)
	}
	if cm, err := c.CertManager(ctx); err != nil || cm.Installed {
		t.Fatalf("CertManager before install: %+v, %v", cm, err)
	}
	drain(c.Changes())

	disc.served.Store(true)
	waitSignal(t, c.Changes(), "cert-manager install")
	eventually(t, "cert-manager informers", func() bool {
		inv, err := c.Inventory(ctx)
		return err == nil && inv.Certs.Installed && len(inv.Certs.Certificates) == 1 && len(inv.Unavailable) == 0
	})
	cm, err := c.CertManager(ctx)
	if err != nil || len(cm.Issuers) != 2 || len(cm.Requests) != 1 || cm.Requests[0].Certificate != "web-tls" {
		t.Errorf("CertManager after install: %+v, %v", cm, err)
	}

	disc.served.Store(false)
	eventually(t, "cert-manager removal", func() bool {
		inv, err := c.Inventory(ctx)
		return err == nil && !inv.Certs.Installed
	})
	if n := c.m.certificates.size(); n != 0 {
		t.Errorf("certificate memo keeps %d entries after removal", n)
	}
}
