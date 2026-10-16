package kube

import (
	"context"
	"reflect"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	"github.com/ByronGary/kubesentry/internal/detectors"
)

const ownerKey = "kubesentry.io/owner"

// ownedMeta is metadata naming team-x as the owner, among other
// annotations (a routing hint and an unrelated one) that must not be kept.
func ownedMeta(ns, name string) metav1.ObjectMeta {
	return metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID(ns + "/" + name), ResourceVersion: "1",
		Annotations: map[string]string{ownerKey: " team-x ", "kubesentry.io/slack-channel": "#x", "example.com/other": "y"}}
}

// ownedObjects are one of each kind that may name its owner.
func ownedObjects() []runtime.Object {
	cert := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "cert-manager.io/v1", "kind": "Certificate",
		"metadata": map[string]any{"namespace": "app", "name": "tls", "uid": "cert-tls", "resourceVersion": "1",
			"annotations": map[string]any{ownerKey: " team-x ", "kubesentry.io/slack-channel": "#x", "example.com/other": "y"}},
		"spec": map[string]any{"secretName": "tls", "issuerRef": map[string]any{"name": "le", "kind": "ClusterIssuer"}},
	}}
	return []runtime.Object{
		&appsv1.Deployment{ObjectMeta: ownedMeta("app", "web")},
		&appsv1.StatefulSet{ObjectMeta: ownedMeta("app", "db")},
		&appsv1.DaemonSet{ObjectMeta: ownedMeta("app", "agent")},
		&batchv1.Job{ObjectMeta: ownedMeta("app", "once")},
		&batchv1.CronJob{ObjectMeta: ownedMeta("app", "nightly")},
		&corev1.Service{ObjectMeta: ownedMeta("app", "web")},
		&networkingv1.Ingress{ObjectMeta: ownedMeta("app", "web")},
		&rbacv1.Role{ObjectMeta: ownedMeta("app", "reader")},
		&rbacv1.RoleBinding{ObjectMeta: ownedMeta("app", "readers"), RoleRef: rbacv1.RoleRef{Kind: "Role", Name: "reader"}},
		&rbacv1.ClusterRole{ObjectMeta: ownedMeta("", "ops")},
		&rbacv1.ClusterRoleBinding{ObjectMeta: ownedMeta("", "ops"), RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "ops"}},
		cert,
	}
}

// otherObjects are kinds that keep no owner annotation.
func otherObjects() []runtime.Object {
	req := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "cert-manager.io/v1", "kind": "CertificateRequest",
		"metadata": map[string]any{"namespace": "app", "name": "tls-1", "uid": "cr-tls", "resourceVersion": "1",
			"annotations": map[string]any{ownerKey: "team-x", certificateNameAnnotation: "tls"}},
	}}
	issuer := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "cert-manager.io/v1", "kind": "Issuer",
		"metadata": map[string]any{"namespace": "app", "name": "self", "uid": "iss", "resourceVersion": "1", "annotations": map[string]any{ownerKey: "team-x"}},
		"spec":     map[string]any{"selfSigned": map[string]any{}},
	}}
	return []runtime.Object{
		&corev1.Pod{ObjectMeta: ownedMeta("app", "web-0")},
		&appsv1.ReplicaSet{ObjectMeta: ownedMeta("app", "web-5d8f")},
		&corev1.PersistentVolumeClaim{ObjectMeta: ownedMeta("app", "data")},
		&corev1.PersistentVolume{ObjectMeta: ownedMeta("", "pv-1")},
		&corev1.Node{ObjectMeta: ownedMeta("", "n1")},
		&storagev1.StorageClass{ObjectMeta: ownedMeta("", "gp3")},
		&discoveryv1.EndpointSlice{ObjectMeta: ownedMeta("app", "web-abc")},
		&corev1.ServiceAccount{ObjectMeta: ownedMeta("app", "web")},
		&corev1.ConfigMap{ObjectMeta: ownedMeta("kube-system", "aws-auth")},
		req, issuer,
	}
}

func annotationsOf(obj runtime.Object) map[string]string {
	return obj.(metav1.Object).GetAnnotations()
}

// The informer transform keeps exactly the owner annotation on the kinds
// that may name their owner, and on no other kind; without an owner key it
// keeps it nowhere.
func TestTransformKeepsOnlyTheOwnerAnnotation(t *testing.T) {
	with := newFilters(nil, nil, nil).withOwner(ownerKey)
	without := newFilters(nil, nil, nil)
	for _, obj := range ownedObjects() {
		if got := annotationsOf(transformed(obj, with)); !reflect.DeepEqual(got, map[string]string{ownerKey: " team-x "}) {
			t.Errorf("%s: kept %v", describe(obj), got)
		}
		if got := annotationsOf(transformed(obj, without)); len(got) != 0 {
			t.Errorf("%s without an owner key: kept %v", describe(obj), got)
		}
		// Idempotent, and the conversion reads the same before and after.
		once := transformed(obj, with)
		if twice := transformed(once, with); !reflect.DeepEqual(once, twice) {
			t.Errorf("%s: transform not idempotent", describe(obj))
		}
		if a, b := convertAny(t, obj, with), convertAny(t, once, with); !reflect.DeepEqual(a, b) {
			t.Errorf("%s: convert(transform) differs:\n got %+v\nwant %+v", describe(obj), b, a)
		}
	}
	for _, obj := range otherObjects() {
		if _, ok := annotationsOf(transformed(obj, with))[ownerKey]; ok {
			t.Errorf("%s keeps the owner annotation", describe(obj))
		}
	}
	// Namespaces keep their kubesentry.io/* annotations as before (the
	// owner and the routing hints).
	ns := &corev1.Namespace{ObjectMeta: ownedMeta("", "app")}
	if got := annotationsOf(transformed(ns, with)); len(got) != 2 || got[ownerKey] == "" || got["kubesentry.io/slack-channel"] == "" {
		t.Errorf("namespace kept %v", got)
	}
}

// The cache and the per-request source fill Owner from the owner
// annotation, trimmed, on every kind that may name its owner.
func TestCacheReadsObjectOwners(t *testing.T) {
	var typed, crs []runtime.Object
	for _, o := range append(ownedObjects(), otherObjects()...) {
		if _, ok := o.(*unstructured.Unstructured); ok {
			crs = append(crs, o)
		} else {
			typed = append(typed, o)
		}
	}
	cs, dyn := newFakes(typed, crs, nil)
	c := NewCache(&Clients{CS: cs, Dyn: dyn, Disc: cs.Discovery()}, CacheOptions{OwnerAnnotation: ownerKey})
	startCache(t, c)
	ctx := context.Background()
	inv, err := c.Inventory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	owners := detectors.ObjectOwners(&inv)
	want := map[detectors.ObjectRef]string{}
	for _, ref := range []detectors.ObjectRef{
		{Kind: "Deployment", Namespace: "app", Name: "web"}, {Kind: "StatefulSet", Namespace: "app", Name: "db"},
		{Kind: "DaemonSet", Namespace: "app", Name: "agent"}, {Kind: "Job", Namespace: "app", Name: "once"},
		{Kind: "CronJob", Namespace: "app", Name: "nightly"}, {Kind: "Service", Namespace: "app", Name: "web"},
		{Kind: "Ingress", Namespace: "app", Name: "web"}, {Kind: "Role", Namespace: "app", Name: "reader"},
		{Kind: "RoleBinding", Namespace: "app", Name: "readers"}, {Kind: "ClusterRole", Name: "ops"},
		{Kind: "ClusterRoleBinding", Name: "ops"}, {Kind: "Certificate", Namespace: "app", Name: "tls"},
	} {
		want[ref] = "team-x"
	}
	if !reflect.DeepEqual(owners, want) {
		t.Fatalf("owners from the cache:\n got %v\nwant %v", owners, want)
	}
	src := NewSourceWithOptions(cs, dyn, SourceOptions{OwnerAnnotation: ownerKey})
	sinv, err := src.Inventory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := detectors.ObjectOwners(&sinv); !reflect.DeepEqual(got, want) {
		t.Errorf("owners from the source:\n got %v\nwant %v", got, want)
	}
	// Without -owner-annotation nothing names an owner.
	plain := NewCache(&Clients{CS: cs, Dyn: dyn, Disc: cs.Discovery()}, CacheOptions{})
	startCache(t, plain)
	pinv, _ := plain.Inventory(ctx)
	if got := detectors.ObjectOwners(&pinv); len(got) != 0 {
		t.Errorf("owners without the option: %v", got)
	}
}
