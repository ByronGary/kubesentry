package kube

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/ByronGary/kubesentry/internal/model"
)

// ErrNotSynced is returned by Cache reads before the informers have synced.
var ErrNotSynced = errors.New("kube: informer cache has not synced yet")

// DefaultCertManagerRecheck is how often the Cache looks for a cert-manager
// (or an AWS Load Balancer Controller) that was installed or removed after it
// started.
const DefaultCertManagerRecheck = 5 * time.Minute

// CacheOptions configures a Cache.
type CacheOptions struct {
	// AWSAuth watches kube-system/aws-auth (and only that ConfigMap).
	AWSAuth bool
	// NodeLabelKeysAdd are node labels kept on top of DefaultNodeLabelKeys;
	// "prefix*" keeps every key with that prefix.
	NodeLabelKeysAdd []string
	// NamespaceAnnotationKeysAdd are namespace annotations kept besides
	// kubesentry.io/* (the owner annotation, when configured elsewhere).
	NamespaceAnnotationKeysAdd []string
	// AppLabelKeys are workload labels kept besides DefaultAppLabelKeys
	// (the custom app tag, -incident-app-label; "prefix*" matches by prefix).
	AppLabelKeys []string
	// CertManagerRecheck is how often discovery is re-run for the custom
	// resource APIs (cert-manager, the AWS Load Balancer Controller's
	// TargetGroupBindings) and the server version; default 5m.
	CertManagerRecheck time.Duration
	ClusterName        string
	Now                func() time.Time // defaults to time.Now
}

// Cache serves the cluster from shared informers. Start probes which
// resources kubesentry may list and watch, starts informers for those, and
// records the rest as unavailable. Objects are stripped by a transform before
// they are stored, and conversions are memoized by UID and resourceVersion.
//
// Cache implements snapshot.Source and snapshot.Notifier, and the older
// api.ClusterSource, api.InventorySource and api.CertSource from the same
// informers.
type Cache struct {
	cs        kubernetes.Interface
	dyn       dynamic.Interface // nil disables the custom resources (cert-manager, TargetGroupBindings)
	disc      discovery.DiscoveryInterface
	opts      CacheOptions
	filters   filters
	transform cache.TransformFunc
	changes   chan struct{}

	starting, started, ready atomic.Bool
	res                      map[string]*informerState // built-in resources; fixed once started
	awsAuth                  *informerState            // nil unless AWSAuth

	mu      sync.Mutex // guards version and crds
	version string
	crds    map[*crdAPI]*crdState // an API is absent while it is not served

	m           memos
	awsAuthMemo struct {
		sync.Mutex
		uid, rv string
		v       model.AWSAuth
	}
}

// memos holds one conversion memo per resource.
type memos struct {
	pods                                  memo[model.Pod]
	pvcs                                  memo[model.PVC]
	pvs                                   memo[model.PV]
	classes                               memo[model.StorageClass]
	nodes                                 memo[model.Node]
	namespaces                            memo[model.Namespace]
	services                              memo[model.Service]
	slices                                memo[model.EndpointSlice]
	ingresses                             memo[model.Ingress]
	deployments, statefulsets, daemonsets memo[model.Workload]
	jobs, cronjobs                        memo[model.Workload]
	replicasets                           memo[model.ReplicaSet]
	roles, clusterroles                   memo[model.Role]
	rolebindings, clusterrolebindings     memo[model.RoleBinding]
	certificates                          memo[model.Certificate]
	issuers, clusterissuers               memo[model.Issuer]
	requests                              memo[model.CertificateRequest]
	serviceaccounts                       memo[model.ServiceAccount]
	targetgroupbindings                   memo[model.TargetGroupBinding]
}

// informerState is one watched resource.
type informerState struct {
	name   string
	inf    cache.SharedIndexInformer // nil when the resource is unavailable
	reason string                    // why it is unavailable; set before the informer starts

	mu      sync.Mutex
	failure string // a fatal list error (forbidden) seen before the first sync
}

func (s *informerState) setFailure(reason string) {
	s.mu.Lock()
	s.failure = reason
	s.mu.Unlock()
}

func (s *informerState) getFailure() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failure
}

// state reports whether the resource can be read and, if not, why.
func (s *informerState) state() (ok bool, reason string) {
	switch {
	case s == nil:
		return false, "not watched"
	case s.inf == nil:
		return false, s.reason
	case s.inf.HasSynced():
		return true, ""
	}
	if f := s.getFailure(); f != "" {
		return false, f
	}
	return false, "not synced yet"
}

// settled is true once the informer has synced or failed for good.
func (s *informerState) settled() bool {
	return s.inf == nil || s.inf.HasSynced() || s.getFailure() != ""
}

// access is what a permission probe checks.
type access struct {
	group, resource, subresource, namespace, name string
}

func (a access) String() string {
	s := a.resource
	if a.group != "" {
		s += "." + a.group
	}
	if a.subresource != "" {
		s += "/" + a.subresource
	}
	if a.name != "" {
		s += " " + a.name
	}
	if a.namespace != "" {
		s += " in namespace " + a.namespace
	}
	return s
}

// builtinResources are the typed informers, in Inventory order.
var builtinResources = []struct {
	name, group string
	informer    func(informers.SharedInformerFactory) cache.SharedIndexInformer
}{
	{"pods", "", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Core().V1().Pods().Informer()
	}},
	{"persistentvolumeclaims", "", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Core().V1().PersistentVolumeClaims().Informer()
	}},
	{"persistentvolumes", "", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Core().V1().PersistentVolumes().Informer()
	}},
	{"storageclasses", "storage.k8s.io", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Storage().V1().StorageClasses().Informer()
	}},
	{"nodes", "", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Core().V1().Nodes().Informer()
	}},
	{"namespaces", "", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Core().V1().Namespaces().Informer()
	}},
	{"serviceaccounts", "", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Core().V1().ServiceAccounts().Informer()
	}},
	{"services", "", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Core().V1().Services().Informer()
	}},
	{"endpointslices", "discovery.k8s.io", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Discovery().V1().EndpointSlices().Informer()
	}},
	{"ingresses", "networking.k8s.io", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Networking().V1().Ingresses().Informer()
	}},
	{"deployments", "apps", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Apps().V1().Deployments().Informer()
	}},
	{"replicasets", "apps", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Apps().V1().ReplicaSets().Informer()
	}},
	{"statefulsets", "apps", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Apps().V1().StatefulSets().Informer()
	}},
	{"daemonsets", "apps", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Apps().V1().DaemonSets().Informer()
	}},
	{"jobs", "batch", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Batch().V1().Jobs().Informer()
	}},
	{"cronjobs", "batch", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Batch().V1().CronJobs().Informer()
	}},
	{"roles", "rbac.authorization.k8s.io", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Rbac().V1().Roles().Informer()
	}},
	{"rolebindings", "rbac.authorization.k8s.io", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Rbac().V1().RoleBindings().Informer()
	}},
	{"clusterroles", "rbac.authorization.k8s.io", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Rbac().V1().ClusterRoles().Informer()
	}},
	{"clusterrolebindings", "rbac.authorization.k8s.io", func(f informers.SharedInformerFactory) cache.SharedIndexInformer {
		return f.Rbac().V1().ClusterRoleBindings().Informer()
	}},
}

// NewCache prepares a Cache; nothing is read until Start.
func NewCache(c *Clients, o CacheOptions) *Cache {
	if o.CertManagerRecheck <= 0 {
		o.CertManagerRecheck = DefaultCertManagerRecheck
	}
	disc := c.Disc
	if disc == nil && c.CS != nil {
		disc = c.CS.Discovery()
	}
	f := newFilters(o.NodeLabelKeysAdd, o.NamespaceAnnotationKeysAdd, o.AppLabelKeys)
	return &Cache{
		cs: c.CS, dyn: c.Dyn, disc: disc, opts: o,
		filters:   f,
		transform: newTransform(f),
		changes:   make(chan struct{}, 1),
		res:       map[string]*informerState{},
	}
}

// Changes signals that the cluster changed. Signals are coalesced: one
// pending signal stands for any number of changes.
func (c *Cache) Changes() <-chan struct{} { return c.changes }

func (c *Cache) notify() {
	select {
	case c.changes <- struct{}{}:
	default:
	}
}

// Start probes permissions with SelfSubjectAccessReviews and starts the
// permitted informers; they run until ctx is done. It returns once the
// informers are started, not synced (see WaitSynced).
func (c *Cache) Start(ctx context.Context) error {
	if !c.starting.CompareAndSwap(false, true) {
		return errors.New("kube: cache already started")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	checks := make([]access, len(builtinResources))
	for i, b := range builtinResources {
		checks[i] = access{group: b.group, resource: b.name}
	}
	if c.opts.AWSAuth {
		checks = append(checks, access{resource: "configmaps", namespace: awsAuthNamespace, name: awsAuthName})
	}
	allowed, reasons := c.probe(ctx, checks)

	factory := informers.NewSharedInformerFactoryWithOptions(c.cs, 0, informers.WithTransform(c.transform))
	for i, b := range builtinResources {
		st := &informerState{name: b.name}
		if allowed[i] {
			st.inf = b.informer(factory)
			c.watch(st)
		} else {
			st.reason = reasons[i]
		}
		c.res[b.name] = st
	}
	var awsFactory informers.SharedInformerFactory
	if c.opts.AWSAuth {
		i := len(builtinResources)
		c.awsAuth = &informerState{name: awsAuthName}
		if allowed[i] {
			awsFactory = informers.NewSharedInformerFactoryWithOptions(c.cs, 0,
				informers.WithNamespace(awsAuthNamespace),
				informers.WithTweakListOptions(func(o *metav1.ListOptions) {
					o.FieldSelector = fields.OneTermEqualSelector("metadata.name", awsAuthName).String()
				}),
				informers.WithTransform(c.transform))
			c.awsAuth.inf = awsFactory.Core().V1().ConfigMaps().Informer()
			c.watch(c.awsAuth)
		} else {
			c.awsAuth.reason = reasons[i]
		}
	}
	c.refreshVersion()
	c.syncCRDs(ctx)

	factory.Start(ctx.Done())
	if awsFactory != nil {
		awsFactory.Start(ctx.Done())
	}
	c.started.Store(true)
	go c.recheck(ctx)
	return nil
}

// probe runs the permission checks concurrently. A check that cannot be
// made (the review itself fails) counts as allowed: the informer then finds
// out, and a forbidden list still ends up in Unavailable.
func (c *Cache) probe(ctx context.Context, checks []access) ([]bool, []string) {
	allowed := make([]bool, len(checks))
	reasons := make([]string, len(checks))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i, a := range checks {
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			allowed[i], reasons[i] = c.permitted(ctx, a)
		})
	}
	wg.Wait()
	return allowed, reasons
}

func (c *Cache) permitted(ctx context.Context, a access) (bool, string) {
	return permitted(ctx, c.cs, a, "list", "watch")
}

// permitted asks with SelfSubjectAccessReviews whether kubesentry may do
// every verb on a. A review that cannot be made counts as allowed: the
// reader then finds out for itself.
func permitted(ctx context.Context, cs kubernetes.Interface, a access, verbs ...string) (bool, string) {
	for _, verb := range verbs {
		r, err := cs.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &authorizationv1.SelfSubjectAccessReview{
			Spec: authorizationv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authorizationv1.ResourceAttributes{
				Namespace: a.namespace, Verb: verb, Group: a.group, Resource: a.resource, Subresource: a.subresource, Name: a.name,
			}},
		}, metav1.CreateOptions{})
		if err != nil {
			slog.Warn("permission probe failed; trying anyway", "resource", a.String(), "err", err)
			return true, ""
		}
		if !r.Status.Allowed || r.Status.Denied {
			reason := fmt.Sprintf("forbidden: cannot %s %s", verb, a)
			if r.Status.Reason != "" {
				reason += " (" + r.Status.Reason + ")"
			}
			return false, reason
		}
	}
	return true, ""
}

// watch hooks change notification and fatal list errors into st. It must run
// before the informer starts.
func (c *Cache) watch(st *informerState) {
	_ = st.inf.SetWatchErrorHandlerWithContext(func(ctx context.Context, r *cache.Reflector, err error) {
		if !st.inf.HasSynced() && (apierrors.IsForbidden(err) || apierrors.IsNotFound(err) || apierrors.IsMethodNotSupported(err)) {
			if st.getFailure() == "" {
				slog.Warn("informer cannot list; marking it unavailable", "resource", st.name, "err", err)
			}
			st.setFailure(listFailure(err))
			c.notify()
		}
		cache.DefaultWatchErrorHandler(ctx, r, err)
	})
	_, _ = st.inf.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(any) { c.notify() },
		UpdateFunc: func(oldObj, newObj any) {
			// Relists deliver unchanged objects as updates; skip those.
			o, ok1 := oldObj.(metav1.Object)
			n, ok2 := newObj.(metav1.Object)
			if ok1 && ok2 && o.GetResourceVersion() == n.GetResourceVersion() && n.GetResourceVersion() != "" {
				return
			}
			c.notify()
		},
		DeleteFunc: func(any) { c.notify() },
	})
}

func listFailure(err error) string {
	switch {
	case apierrors.IsForbidden(err):
		return forbiddenReason(err)
	case apierrors.IsNotFound(err):
		return "not served by the API server"
	}
	return err.Error()
}

// refreshVersion reads the API server version from discovery.
func (c *Cache) refreshVersion() {
	if c.disc == nil {
		return
	}
	v, err := c.disc.ServerVersion()
	if err != nil {
		slog.Warn("read server version", "err", err)
		return
	}
	c.mu.Lock()
	changed := c.version != v.GitVersion
	c.version = v.GitVersion
	c.mu.Unlock()
	if changed && c.started.Load() {
		c.notify()
	}
}

func (c *Cache) recheck(ctx context.Context) {
	t := time.NewTicker(c.opts.CertManagerRecheck)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.refreshVersion()
			c.syncCRDs(ctx)
		}
	}
}

// states lists every informer started or skipped, the custom resources
// included.
func (c *Cache) states() []*informerState {
	out := make([]*informerState, 0, len(c.res)+6)
	for _, b := range builtinResources {
		out = append(out, c.res[b.name])
	}
	if c.awsAuth != nil {
		out = append(out, c.awsAuth)
	}
	c.mu.Lock()
	for _, a := range crdAPIs {
		if st := c.crds[a]; st != nil {
			for _, r := range a.resources {
				out = append(out, st.res[r])
			}
		}
	}
	c.mu.Unlock()
	return out
}

// WaitSynced blocks until every started informer has synced (or failed for
// good, e.g. forbidden despite the probe), or ctx is done.
func (c *Cache) WaitSynced(ctx context.Context) error {
	t := time.NewTicker(50 * time.Millisecond)
	defer t.Stop()
	for {
		if c.Ready() {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for informer sync: %w", ctx.Err())
		case <-t.C:
		}
	}
}

// Ready reports whether the informers have synced. Once true it stays true;
// a custom resource API (cert-manager) installed later is reported
// unavailable until its own informers sync.
func (c *Cache) Ready() bool {
	if c.ready.Load() {
		return true
	}
	if !c.started.Load() {
		return false
	}
	for _, st := range c.states() {
		if !st.settled() {
			return false
		}
	}
	c.ready.Store(true)
	return true
}

// Unavailable returns the resources that cannot be read, with the reason.
func (c *Cache) Unavailable() map[string]string {
	out := map[string]string{}
	if !c.started.Load() {
		return out
	}
	for _, st := range c.states() {
		if ok, reason := st.state(); !ok {
			out[st.name] = reason
		}
	}
	return out
}

// ObjectCounts returns how many objects each informer holds (for metrics).
func (c *Cache) ObjectCounts() map[string]int {
	out := map[string]int{}
	if !c.started.Load() {
		return out
	}
	for _, st := range c.states() {
		if st.inf != nil {
			out[st.name] = len(st.inf.GetStore().ListKeys())
		}
	}
	return out
}

// st returns a built-in resource's state; nil until Start has finished, so
// a read racing Start never touches the map while it is being filled.
func (c *Cache) st(name string) *informerState {
	if !c.started.Load() {
		return nil
	}
	return c.res[name]
}

// inventoryItems converts one resource for Inventory; an unreadable
// resource is recorded in unavailable and yields nil.
func inventoryItems[O metav1.Object, T any](st *informerState, m *memo[T], conv func(O) T, unavailable map[string]string) []T {
	if st == nil {
		return nil
	}
	if ok, reason := st.state(); !ok {
		unavailable[st.name] = reason
		return nil
	}
	return convertAll(m, sortedObjects[O](st.inf.GetStore()), conv)
}

// inventoryItemsWhere is inventoryItems for the objects keep accepts; the
// others are neither converted nor remembered.
func inventoryItemsWhere[O metav1.Object, T any](st *informerState, m *memo[T], keep func(O) bool, conv func(O) T, unavailable map[string]string) []T {
	if st == nil {
		return nil
	}
	if ok, reason := st.state(); !ok {
		unavailable[st.name] = reason
		return nil
	}
	objs := sortedObjects[O](st.inf.GetStore())
	kept := objs[:0]
	for _, o := range objs {
		if keep(o) {
			kept = append(kept, o)
		}
	}
	return convertAll(m, kept, conv)
}

// listCached converts one resource for the per-resource methods; an
// unreadable resource is an error.
func listCached[O metav1.Object, T any](c *Cache, st *informerState, m *memo[T], conv func(O) T) ([]T, error) {
	if !c.Ready() || st == nil {
		return nil, ErrNotSynced
	}
	if ok, reason := st.state(); !ok {
		return nil, fmt.Errorf("%s unavailable: %s", st.name, reason)
	}
	return convertAll(m, sortedObjects[O](st.inf.GetStore()), conv), nil
}

func (c *Cache) convertNode(n *corev1.Node) model.Node { return convertNode(n, c.filters.nodeLabels) }

func (c *Cache) convertNamespace(n *corev1.Namespace) model.Namespace {
	return convertNamespace(n, c.filters.nsAnnotations)
}

func issuerConv(kind string) func(*unstructured.Unstructured) model.Issuer {
	return func(u *unstructured.Unstructured) model.Issuer { return convertIssuer(u, kind) }
}

// Inventory returns a copy of everything the inventory pages need, read from
// the informers. Unchanged objects reuse their previous conversion; the
// returned values are shared with later reads and must not be modified.
// Implements snapshot.Source.
func (c *Cache) Inventory(ctx context.Context) (model.Inventory, error) {
	if err := ctx.Err(); err != nil {
		return model.Inventory{}, err
	}
	if !c.Ready() {
		return model.Inventory{}, ErrNotSynced
	}
	inv := model.Inventory{Unavailable: map[string]string{}}
	u, m := inv.Unavailable, &c.m
	inv.Pods = inventoryItems(c.st("pods"), &m.pods, convertPod, u)
	inv.PVCs = inventoryItems(c.st("persistentvolumeclaims"), &m.pvcs, convertPVC, u)
	inv.PVs = inventoryItems(c.st("persistentvolumes"), &m.pvs, convertPV, u)
	inv.StorageClasses = inventoryItems(c.st("storageclasses"), &m.classes, convertStorageClass, u)
	inv.Workloads = c.workloads(u)
	inv.ReplicaSets = inventoryItems(c.st("replicasets"), &m.replicasets, convertReplicaSet, u)
	inv.Services = inventoryItems(c.st("services"), &m.services, convertService, u)
	inv.EndpointSlices = inventoryItems(c.st("endpointslices"), &m.slices, convertEndpointSlice, u)
	inv.Ingresses = inventoryItems(c.st("ingresses"), &m.ingresses, convertIngress, u)
	inv.Nodes = inventoryItems(c.st("nodes"), &m.nodes, c.convertNode, u)
	inv.Namespaces = inventoryItems(c.st("namespaces"), &m.namespaces, c.convertNamespace, u)
	inv.ServiceAccounts = inventoryItemsWhere(c.st("serviceaccounts"), &m.serviceaccounts, hasIRSARole, convertServiceAccount, u)
	inv.TargetGroupBindings = c.targetGroupBindings(u)
	inv.RBAC = c.rbac(u)
	inv.Certs = c.certs(u)
	if c.opts.AWSAuth {
		if ok, reason := c.awsAuth.state(); !ok {
			u[awsAuthName] = reason
		} else {
			a := c.readAWSAuth()
			inv.AWSAuth = &a
		}
	}
	c.mu.Lock()
	version := c.version
	c.mu.Unlock()
	inv.Cluster = clusterInfo(c.opts.ClusterName, version, inv.Nodes)
	inv.ReadAt = now(c.opts.Now)
	return inv, nil
}

// workloads converts Deployments, StatefulSets, DaemonSets, Jobs and
// CronJobs, in that order.
func (c *Cache) workloads(unavailable map[string]string) []model.Workload {
	m := &c.m
	var out []model.Workload
	apps := c.filters.appLabels
	out = append(out, inventoryItems(c.st("deployments"), &m.deployments, func(o *appsv1.Deployment) model.Workload { return convertDeployment(o, apps) }, unavailable)...)
	out = append(out, inventoryItems(c.st("statefulsets"), &m.statefulsets, func(o *appsv1.StatefulSet) model.Workload { return convertStatefulSet(o, apps) }, unavailable)...)
	out = append(out, inventoryItems(c.st("daemonsets"), &m.daemonsets, func(o *appsv1.DaemonSet) model.Workload { return convertDaemonSet(o, apps) }, unavailable)...)
	out = append(out, inventoryItems(c.st("jobs"), &m.jobs, func(o *batchv1.Job) model.Workload { return convertJob(o, apps) }, unavailable)...)
	out = append(out, inventoryItems(c.st("cronjobs"), &m.cronjobs, func(o *batchv1.CronJob) model.Workload { return convertCronJob(o, apps) }, unavailable)...)
	return out
}

// rbac converts Roles then ClusterRoles, and RoleBindings then
// ClusterRoleBindings.
func (c *Cache) rbac(unavailable map[string]string) model.RBAC {
	m := &c.m
	var out model.RBAC
	out.Roles = append(out.Roles, inventoryItems(c.st("roles"), &m.roles, convertRole, unavailable)...)
	out.Roles = append(out.Roles, inventoryItems(c.st("clusterroles"), &m.clusterroles, convertClusterRole, unavailable)...)
	out.Bindings = append(out.Bindings, inventoryItems(c.st("rolebindings"), &m.rolebindings, convertRoleBinding, unavailable)...)
	out.Bindings = append(out.Bindings, inventoryItems(c.st("clusterrolebindings"), &m.clusterrolebindings, convertClusterRoleBinding, unavailable)...)
	return out
}

// certs converts the cert-manager objects; Installed is false while the
// cert-manager.io/v1 API is not served.
func (c *Cache) certs(unavailable map[string]string) model.CertManager {
	cm := c.crd(certManagerAPI)
	if cm == nil {
		return model.CertManager{}
	}
	m := &c.m
	out := model.CertManager{Installed: true}
	out.Certificates = inventoryItems(cm.res["certificates"], &m.certificates, convertCertificate, unavailable)
	out.Issuers = append(out.Issuers, inventoryItems(cm.res["issuers"], &m.issuers, issuerConv("Issuer"), unavailable)...)
	out.Issuers = append(out.Issuers, inventoryItems(cm.res["clusterissuers"], &m.clusterissuers, issuerConv("ClusterIssuer"), unavailable)...)
	out.Requests = inventoryItems(cm.res["certificaterequests"], &m.requests, convertCertificateRequest, unavailable)
	return out
}

// targetGroupBindings converts the AWS Load Balancer Controller's
// TargetGroupBindings; nil while the elbv2.k8s.aws API is not served.
func (c *Cache) targetGroupBindings(unavailable map[string]string) []model.TargetGroupBinding {
	st := c.crd(targetGroupBindingAPI)
	if st == nil {
		return nil
	}
	return inventoryItems(st.res[targetGroupBindingResource], &c.m.targetgroupbindings, convertTargetGroupBinding, unavailable)
}

// readAWSAuth parses the cached aws-auth ConfigMap, once per resourceVersion.
// A missing ConfigMap reads as no mappings.
func (c *Cache) readAWSAuth() model.AWSAuth {
	obj, exists, err := c.awsAuth.inf.GetStore().GetByKey(awsAuthNamespace + "/" + awsAuthName)
	if err != nil || !exists {
		return model.AWSAuth{}
	}
	cm, ok := obj.(*corev1.ConfigMap)
	if !ok {
		return model.AWSAuth{}
	}
	am := &c.awsAuthMemo
	am.Lock()
	defer am.Unlock()
	if am.uid == string(cm.UID) && am.rv == cm.ResourceVersion && cm.ResourceVersion != "" {
		return am.v
	}
	am.uid, am.rv, am.v = string(cm.UID), cm.ResourceVersion, awsAuthFromConfigMap(cm)
	return am.v
}

// The methods below serve the older per-resource interfaces from the
// informers. An unavailable resource is an error, as a failed LIST was.

// unavailableErr turns what a composite read could not see into an error.
func unavailableErr(unavailable map[string]string) error {
	if len(unavailable) == 0 {
		return nil
	}
	names := make([]string, 0, len(unavailable))
	for name := range unavailable {
		names = append(names, name)
	}
	sort.Strings(names)
	return fmt.Errorf("%s unavailable: %s", names[0], unavailable[names[0]])
}

func (c *Cache) ListPods(ctx context.Context) ([]model.Pod, error) {
	return listCached(c, c.st("pods"), &c.m.pods, convertPod)
}

func (c *Cache) ListPVCs(ctx context.Context) ([]model.PVC, error) {
	return listCached(c, c.st("persistentvolumeclaims"), &c.m.pvcs, convertPVC)
}

// getCached looks one object up by namespace and name.
func getCached[O metav1.Object, T any](c *Cache, st *informerState, m *memo[T], conv func(O) T, namespace, name string) (*T, error) {
	if !c.Ready() || st == nil {
		return nil, ErrNotSynced
	}
	if ok, reason := st.state(); !ok {
		return nil, fmt.Errorf("%s unavailable: %s", st.name, reason)
	}
	obj, exists, err := st.inf.GetStore().GetByKey(namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	o, ok := obj.(O)
	if !exists || !ok {
		return nil, model.ErrNotFound
	}
	v := convertOne(m, o, conv)
	return &v, nil
}

// GetPod returns model.ErrNotFound if the pod does not exist.
func (c *Cache) GetPod(ctx context.Context, namespace, name string) (*model.Pod, error) {
	return getCached(c, c.st("pods"), &c.m.pods, convertPod, namespace, name)
}

// GetPVC returns model.ErrNotFound if the claim does not exist.
func (c *Cache) GetPVC(ctx context.Context, namespace, name string) (*model.PVC, error) {
	return getCached(c, c.st("persistentvolumeclaims"), &c.m.pvcs, convertPVC, namespace, name)
}

// ListWorkloads lists Deployments, StatefulSets, DaemonSets, Jobs and CronJobs.
func (c *Cache) ListWorkloads(ctx context.Context) ([]model.Workload, error) {
	if !c.Ready() {
		return nil, ErrNotSynced
	}
	u := map[string]string{}
	out := c.workloads(u)
	if err := unavailableErr(u); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Cache) ListServices(ctx context.Context) ([]model.Service, error) {
	return listCached(c, c.st("services"), &c.m.services, convertService)
}

func (c *Cache) ListIngresses(ctx context.Context) ([]model.Ingress, error) {
	return listCached(c, c.st("ingresses"), &c.m.ingresses, convertIngress)
}

func (c *Cache) ListNodes(ctx context.Context) ([]model.Node, error) {
	return listCached(c, c.st("nodes"), &c.m.nodes, c.convertNode)
}

func (c *Cache) ListPVs(ctx context.Context) ([]model.PV, error) {
	return listCached(c, c.st("persistentvolumes"), &c.m.pvs, convertPV)
}

func (c *Cache) ListStorageClasses(ctx context.Context) ([]model.StorageClass, error) {
	return listCached(c, c.st("storageclasses"), &c.m.classes, convertStorageClass)
}

func (c *Cache) ListNamespaces(ctx context.Context) ([]model.Namespace, error) {
	return listCached(c, c.st("namespaces"), &c.m.namespaces, c.convertNamespace)
}

// ListRBAC lists Roles, ClusterRoles, RoleBindings and ClusterRoleBindings.
func (c *Cache) ListRBAC(ctx context.Context) (model.RBAC, error) {
	if !c.Ready() {
		return model.RBAC{}, ErrNotSynced
	}
	u := map[string]string{}
	out := c.rbac(u)
	if err := unavailableErr(u); err != nil {
		return model.RBAC{}, err
	}
	return out, nil
}

// CertManager reports Installed: false, without an error, while the
// cert-manager.io/v1 API is not served.
func (c *Cache) CertManager(ctx context.Context) (model.CertManager, error) {
	if !c.Ready() {
		return model.CertManager{}, ErrNotSynced
	}
	u := map[string]string{}
	out := c.certs(u)
	if err := unavailableErr(u); err != nil {
		return model.CertManager{}, err
	}
	return out, nil
}
