package kube

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"

	"github.com/ByronGary/kubesentry/internal/model"
)

// convertAny converts a fixture with the conversion the Cache and Source use.
func convertAny(t testing.TB, obj runtime.Object, f filters) any {
	t.Helper()
	switch o := obj.(type) {
	case *corev1.Pod:
		return convertPod(o)
	case *corev1.Node:
		return convertNode(o, f.nodeLabels)
	case *corev1.PersistentVolumeClaim:
		return convertPVC(o)
	case *corev1.PersistentVolume:
		return convertPV(o)
	case *storagev1.StorageClass:
		return convertStorageClass(o)
	case *corev1.Namespace:
		return convertNamespace(o, f.nsAnnotations)
	case *corev1.Service:
		return convertService(o)
	case *discoveryv1.EndpointSlice:
		return convertEndpointSlice(o)
	case *networkingv1.Ingress:
		return convertIngress(o)
	case *appsv1.Deployment:
		return convertDeployment(o)
	case *appsv1.ReplicaSet:
		return convertReplicaSet(o)
	case *appsv1.StatefulSet:
		return convertStatefulSet(o)
	case *appsv1.DaemonSet:
		return convertDaemonSet(o)
	case *batchv1.Job:
		return convertJob(o)
	case *batchv1.CronJob:
		return convertCronJob(o)
	case *rbacv1.Role:
		return convertRole(o)
	case *rbacv1.ClusterRole:
		return convertClusterRole(o)
	case *rbacv1.RoleBinding:
		return convertRoleBinding(o)
	case *rbacv1.ClusterRoleBinding:
		return convertClusterRoleBinding(o)
	case *corev1.ConfigMap:
		a, _ := ParseAWSAuth(o.Data)
		return a
	case *unstructured.Unstructured:
		switch o.GetKind() {
		case "Certificate":
			return convertCertificate(o)
		case "Issuer", "ClusterIssuer":
			return convertIssuer(o, o.GetKind())
		case "CertificateRequest":
			return convertCertificateRequest(o)
		}
	}
	t.Fatalf("no conversion for %T", obj)
	return nil
}

func allFixtures() []runtime.Object { return append(fixtureObjects(), certObjects()...) }

func transformed(obj runtime.Object, f filters) runtime.Object {
	c := obj.DeepCopyObject()
	transformObject(c, f)
	return c
}

func describe(obj runtime.Object) string {
	if u, ok := obj.(*unstructured.Unstructured); ok {
		return u.GetKind() + " " + u.GetNamespace() + "/" + u.GetName()
	}
	m := obj.(interface {
		GetNamespace() string
		GetName() string
	})
	return fmt.Sprintf("%T %s/%s", obj, m.GetNamespace(), m.GetName())
}

func TestTransformPreservesConvert(t *testing.T) {
	for _, labels := range []filters{newFilters(nil, nil), newFilters([]string{"example.com/*"}, []string{"example.com/owner"})} {
		for _, obj := range allFixtures() {
			want := convertAny(t, obj, labels)
			got := convertAny(t, transformed(obj, labels), labels)
			if !reflect.DeepEqual(want, got) {
				t.Errorf("%s: convert(transform(obj)) differs\n got %+v\nwant %+v", describe(obj), got, want)
			}
		}
	}
}

func TestTransformIdempotent(t *testing.T) {
	labels := newFilters([]string{"example.com/rack"}, []string{"example.com/owner"})
	for _, obj := range allFixtures() {
		once := transformed(obj, labels)
		twice := transformed(once, labels)
		if !reflect.DeepEqual(once, twice) {
			t.Errorf("%s: transform is not idempotent\n once %+v\ntwice %+v", describe(obj), once, twice)
		}
	}
	// The informer transform passes unknown objects through untouched.
	tf := newTransform(labels)
	secret := &corev1.Secret{Data: map[string][]byte{"k": []byte("v")}}
	if out, err := tf(secret); err != nil || !reflect.DeepEqual(out, &corev1.Secret{Data: map[string][]byte{"k": []byte("v")}}) {
		t.Errorf("unknown type: %+v, %v", out, err)
	}
}

func jsonSize(t *testing.T, v any) int {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return len(b)
}

// TestTransformStrips checks the transform drops what it promises to, and
// logs how much smaller the stored objects get.
func TestTransformStrips(t *testing.T) {
	labels := newFilters(nil, nil)
	pod := fixturePods()[0]
	before := jsonSize(t, pod)
	p := transformed(pod, labels).(*corev1.Pod)
	t.Logf("pod: %d -> %d bytes of JSON", before, jsonSize(t, p))
	c := p.Spec.Containers[0]
	switch {
	case p.ManagedFields != nil, p.Annotations != nil, p.GenerateName != "", p.Finalizers != nil:
		t.Errorf("pod metadata not stripped: %+v", p.ObjectMeta)
	case c.Env != nil, c.EnvFrom != nil, c.Command != nil, c.Args != nil, c.LivenessProbe != nil, c.ReadinessProbe != nil,
		c.StartupProbe != nil, c.Lifecycle != nil, c.VolumeMounts != nil, c.Ports != nil:
		t.Errorf("container not stripped: %+v", c)
	case p.Spec.Affinity != nil, p.Spec.Tolerations != nil, p.Spec.TopologySpreadConstraints != nil, p.Spec.ImagePullSecrets != nil:
		t.Errorf("pod spec not stripped: %+v", p.Spec)
	case len(p.Spec.Volumes) != 3, p.Spec.Volumes[1].Ephemeral.VolumeClaimTemplate != nil:
		t.Errorf("volumes: %+v", p.Spec.Volumes)
	case p.Status.ContainerStatuses[0].ImageID != "", p.Status.ContainerStatuses[0].AllocatedResources != nil, len(p.Status.Conditions) != 2:
		t.Errorf("pod status not stripped: %+v", p.Status)
	case p.OwnerReferences[0].APIVersion != "" || p.OwnerReferences[0].BlockOwnerDeletion != nil:
		t.Errorf("owner refs: %+v", p.OwnerReferences)
	}
	if _, ok := c.Resources.Requests[corev1.ResourceEphemeralStorage]; ok {
		t.Errorf("ephemeral-storage request kept: %+v", c.Resources)
	}

	node := fixtureNodes()[0]
	before = jsonSize(t, node)
	n := transformed(node, labels).(*corev1.Node)
	t.Logf("node: %d -> %d bytes of JSON", before, jsonSize(t, n))
	if n.Status.Images != nil || n.Status.VolumesInUse != nil || n.Status.VolumesAttached != nil || n.Annotations != nil ||
		n.Status.NodeInfo.MachineID != "" || len(n.Status.Addresses) != 1 || n.Status.Capacity != nil {
		t.Errorf("node not stripped: %+v", n)
	}
	if _, ok := n.Labels["kubernetes.io/hostname"]; ok {
		t.Errorf("hostname label kept: %v", n.Labels)
	}
	if _, ok := n.Labels["node-role.kubernetes.io/worker"]; !ok || n.Labels["topology.kubernetes.io/zone"] != "us-east-1a" {
		t.Errorf("placement labels dropped: %v", n.Labels)
	}
	if m := n.Status.Conditions[1].Message; len(m) > maxMessage {
		t.Errorf("condition message not truncated: %d bytes", len(m))
	}

	for _, obj := range fixtureObjects() {
		switch o := transformed(obj, labels).(type) {
		case *appsv1.Deployment:
			want := []corev1.Container{{Name: "web", Image: "registry.example.com/web:1.2.3"}}
			if !reflect.DeepEqual(o.Spec.Template.Spec.Containers, want) || o.Spec.Template.Labels != nil || len(o.Spec.Template.Spec.Volumes) != 0 {
				t.Errorf("deployment template: %+v", o.Spec.Template)
			}
			if o.Annotations != nil || len(o.Status.Conditions[0].Message) > maxMessage {
				t.Errorf("deployment: %+v", o.ObjectMeta)
			}
		case *corev1.Service:
			if o.Name == "web" && (len(o.Annotations) != 3 || o.Status.Conditions != nil) {
				t.Errorf("service: %+v", o)
			}
		case *discoveryv1.EndpointSlice:
			if len(o.Labels) != 2 || o.Ports != nil || o.OwnerReferences != nil || o.Endpoints[0].Zone != nil || o.Endpoints[0].Hints != nil {
				t.Errorf("endpointslice: %+v", o)
			}
		case *corev1.ConfigMap:
			if _, ok := o.Data["mapAccounts"]; ok || o.Annotations != nil {
				t.Errorf("configmap: %+v", o)
			}
		case *corev1.PersistentVolume:
			if o.Spec.NodeAffinity != nil || (o.Spec.CSI != nil && o.Spec.CSI.VolumeAttributes != nil) {
				t.Errorf("pv: %+v", o.Spec)
			}
		}
	}
	for _, obj := range certObjects() {
		u := transformed(obj, labels).(*unstructured.Unstructured)
		if _, ok, _ := unstructured.NestedFieldNoCopy(u.Object, "metadata", "managedFields"); ok {
			t.Errorf("%s: managedFields kept", u.GetName())
		}
		for _, f := range [][]string{{"spec", "request"}, {"status", "certificate"}, {"status", "ca"}, {"spec", "acme", "solvers"}} {
			if _, ok, _ := unstructured.NestedFieldNoCopy(u.Object, f...); ok {
				t.Errorf("%s: %s kept", u.GetName(), strings.Join(f, "."))
			}
		}
		if u.GetKind() == "CertificateRequest" && len(u.GetAnnotations()) != 1 {
			t.Errorf("request annotations: %v", u.GetAnnotations())
		}
	}
}

func TestTruncateKeepsUTF8(t *testing.T) {
	s := strings.Repeat("é", 400) // 800 bytes, 2 per rune
	got := truncate(s)
	if len(got) > maxMessage || !strings.HasPrefix(s, got) || strings.ToValidUTF8(got, "?") != got {
		t.Errorf("truncate: %d bytes, valid=%v", len(got), strings.ToValidUTF8(got, "?") == got)
	}
	if truncate("short") != "short" {
		t.Error("short strings must pass through")
	}
}

func benchPods(n int) []*corev1.Pod {
	base := fixturePods()[0]
	transformPod(base)
	pods := make([]*corev1.Pod, n)
	for i := range pods {
		p := base.DeepCopy()
		p.Name = fmt.Sprintf("web-%d", i)
		p.UID = types.UID(fmt.Sprintf("uid-%d", i))
		pods[i] = p
	}
	return pods
}

// BenchmarkConvertPods converts 20,000 transformed pods: "miss" with an
// empty memo (the first build, or every pod changed), "hit" with nothing
// changed since the last build.
func BenchmarkConvertPods(b *testing.B) {
	pods := benchPods(20000)
	b.Run("miss", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			var m memo[model.Pod]
			convertAll(&m, pods, convertPod)
		}
	})
	b.Run("hit", func(b *testing.B) {
		var m memo[model.Pod]
		convertAll(&m, pods, convertPod)
		b.ReportAllocs()
		for b.Loop() {
			convertAll(&m, pods, convertPod)
		}
	})
}
