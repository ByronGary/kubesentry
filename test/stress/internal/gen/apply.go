// Package gen creates (and deletes) the objects of a load-level plan. It is
// idempotent: objects that already exist are left alone, so re-running a level
// or ramping to the next one only creates what is missing.
package gen

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/ByronGary/kubesentry/test/stress/internal/out"
)

// Applier creates objects concurrently, in batches with pauses so the API
// server and the controllers keep up.
type Applier struct {
	CS      kubernetes.Interface
	Dyn     dynamic.Interface
	Workers int
	Batch   int           // objects per batch
	Pause   time.Duration // between batches

	created, existed, failed atomic.Int64
	errMu                    sync.Mutex
	errs                     []string
}

// Counts reports created, already existing and failed objects.
func (a *Applier) Counts() (created, existed, failed int64) {
	return a.created.Load(), a.existed.Load(), a.failed.Load()
}

// Errors returns up to 20 distinct error messages.
func (a *Applier) Errors() []string {
	a.errMu.Lock()
	defer a.errMu.Unlock()
	return append([]string(nil), a.errs...)
}

// Apply creates objs in batches; it returns after all are done.
func (a *Applier) Apply(ctx context.Context, what string, objs []runtime.Object) {
	if len(objs) == 0 {
		return
	}
	batch := a.Batch
	if batch <= 0 {
		batch = 500
	}
	start := time.Now()
	c0, e0, f0 := a.Counts()
	for lo := 0; lo < len(objs); lo += batch {
		hi := min(lo+batch, len(objs))
		a.applyBatch(ctx, objs[lo:hi])
		if hi < len(objs) && a.Pause > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(a.Pause):
			}
		}
	}
	c1, e1, f1 := a.Counts()
	out.Logf("%-28s %6d objects: %d created, %d existed, %d failed in %s", what, len(objs), c1-c0, e1-e0, f1-f0, time.Since(start).Round(time.Millisecond))
}

func (a *Applier) applyBatch(ctx context.Context, objs []runtime.Object) {
	workers := a.Workers
	if workers <= 0 {
		workers = 32
	}
	ch := make(chan runtime.Object)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for o := range ch {
				a.one(ctx, o)
			}
		}()
	}
	for _, o := range objs {
		ch <- o
	}
	close(ch)
	wg.Wait()
}

func (a *Applier) one(ctx context.Context, o runtime.Object) {
	var err error
	for attempt := 0; attempt < 4; attempt++ {
		err = Create(ctx, a.CS, a.Dyn, o)
		if err == nil || apierrors.IsAlreadyExists(err) || !retryable(err) {
			break
		}
		time.Sleep(time.Duration(attempt+1) * 500 * time.Millisecond)
	}
	switch {
	case err == nil:
		a.created.Add(1)
	case apierrors.IsAlreadyExists(err):
		a.existed.Add(1)
	default:
		a.failed.Add(1)
		a.errMu.Lock()
		if len(a.errs) < 20 {
			a.errs = append(a.errs, describe(o)+": "+err.Error())
		}
		a.errMu.Unlock()
	}
}

func retryable(err error) bool {
	return apierrors.IsServerTimeout(err) || apierrors.IsTimeout(err) || apierrors.IsTooManyRequests(err) ||
		apierrors.IsInternalError(err) || apierrors.IsServiceUnavailable(err) ||
		// The namespace may still be initialising, or a CRD not yet served.
		apierrors.IsNotFound(err)
}

func describe(o runtime.Object) string {
	if m, ok := o.(metav1.Object); ok {
		return fmt.Sprintf("%T %s/%s", o, m.GetNamespace(), m.GetName())
	}
	return fmt.Sprintf("%T", o)
}

var co = metav1.CreateOptions{}

// Create creates one object with the typed client for its type, or the
// dynamic client for unstructured objects.
func Create(ctx context.Context, cs kubernetes.Interface, dyn dynamic.Interface, o runtime.Object) error {
	var err error
	switch v := o.(type) {
	case *corev1.Namespace:
		_, err = cs.CoreV1().Namespaces().Create(ctx, v, co)
	case *corev1.Node:
		_, err = cs.CoreV1().Nodes().Create(ctx, v, co)
	case *corev1.ServiceAccount:
		_, err = cs.CoreV1().ServiceAccounts(v.Namespace).Create(ctx, v, co)
	case *corev1.ConfigMap:
		_, err = cs.CoreV1().ConfigMaps(v.Namespace).Create(ctx, v, co)
	case *corev1.Secret:
		_, err = cs.CoreV1().Secrets(v.Namespace).Create(ctx, v, co)
	case *corev1.Service:
		_, err = cs.CoreV1().Services(v.Namespace).Create(ctx, v, co)
	case *corev1.Pod:
		_, err = cs.CoreV1().Pods(v.Namespace).Create(ctx, v, co)
	case *corev1.PersistentVolume:
		_, err = cs.CoreV1().PersistentVolumes().Create(ctx, v, co)
	case *corev1.PersistentVolumeClaim:
		_, err = cs.CoreV1().PersistentVolumeClaims(v.Namespace).Create(ctx, v, co)
	case *appsv1.Deployment:
		_, err = cs.AppsV1().Deployments(v.Namespace).Create(ctx, v, co)
	case *appsv1.StatefulSet:
		_, err = cs.AppsV1().StatefulSets(v.Namespace).Create(ctx, v, co)
	case *appsv1.DaemonSet:
		_, err = cs.AppsV1().DaemonSets(v.Namespace).Create(ctx, v, co)
	case *appsv1.ReplicaSet:
		_, err = cs.AppsV1().ReplicaSets(v.Namespace).Create(ctx, v, co)
	case *batchv1.Job:
		_, err = cs.BatchV1().Jobs(v.Namespace).Create(ctx, v, co)
	case *batchv1.CronJob:
		_, err = cs.BatchV1().CronJobs(v.Namespace).Create(ctx, v, co)
	case *discoveryv1.EndpointSlice:
		_, err = cs.DiscoveryV1().EndpointSlices(v.Namespace).Create(ctx, v, co)
	case *networkingv1.Ingress:
		_, err = cs.NetworkingV1().Ingresses(v.Namespace).Create(ctx, v, co)
	case *networkingv1.IngressClass:
		_, err = cs.NetworkingV1().IngressClasses().Create(ctx, v, co)
	case *rbacv1.Role:
		_, err = cs.RbacV1().Roles(v.Namespace).Create(ctx, v, co)
	case *rbacv1.RoleBinding:
		_, err = cs.RbacV1().RoleBindings(v.Namespace).Create(ctx, v, co)
	case *rbacv1.ClusterRole:
		_, err = cs.RbacV1().ClusterRoles().Create(ctx, v, co)
	case *rbacv1.ClusterRoleBinding:
		_, err = cs.RbacV1().ClusterRoleBindings().Create(ctx, v, co)
	case *storagev1.StorageClass:
		_, err = cs.StorageV1().StorageClasses().Create(ctx, v, co)
	case *storagev1.CSIDriver:
		_, err = cs.StorageV1().CSIDrivers().Create(ctx, v, co)
	case *unstructured.Unstructured:
		gvr, namespaced := GVR(v.GroupVersionKind())
		if namespaced {
			_, err = dyn.Resource(gvr).Namespace(v.GetNamespace()).Create(ctx, v, co)
		} else {
			_, err = dyn.Resource(gvr).Create(ctx, v, co)
		}
	default:
		return fmt.Errorf("gen: no create for %T", o)
	}
	return err
}

// GVR maps the unstructured kinds the harness creates to their resources.
func GVR(gvk schema.GroupVersionKind) (schema.GroupVersionResource, bool) {
	res := map[string]struct {
		r          string
		namespaced bool
	}{
		"Certificate":              {"certificates", true},
		"Issuer":                   {"issuers", true},
		"ClusterIssuer":            {"clusterissuers", false},
		"CustomResourceDefinition": {"customresourcedefinitions", false},
		"Widget":                   {"widgets", true},
		"Rollout":                  {"rollouts", true},
		"ServiceMonitor":           {"servicemonitors", true},
	}[gvk.Kind]
	return gvk.GroupVersion().WithResource(res.r), res.namespaced
}
