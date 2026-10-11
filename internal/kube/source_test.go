package kube

import (
	"context"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
)

func ptr[T any](v T) *T { return &v }

func TestConvertPodSecurityAndSidecars(t *testing.T) {
	always := corev1.ContainerRestartPolicyAlways
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "web-0", Labels: map[string]string{"app": "web"}},
		Spec: corev1.PodSpec{
			NodeName: "n1", HostPID: true,
			SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: ptr(true), RunAsUser: ptr(int64(1000))},
			Volumes: []corev1.Volume{
				{Name: "logs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/log"}}},
				{Name: "data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "data"}}},
			},
			Containers: []corev1.Container{{
				Name: "web", Image: "web:1",
				SecurityContext: &corev1.SecurityContext{
					Privileged: ptr(true), RunAsUser: ptr(int64(0)),
					Capabilities: &corev1.Capabilities{Add: []corev1.Capability{"SYS_ADMIN"}, Drop: []corev1.Capability{"all"}},
				},
				Resources: corev1.ResourceRequirements{
					Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("250m")},
					Limits:   corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("512Mi")},
				},
			}},
			InitContainers: []corev1.Container{
				{Name: "proxy", Image: "envoy:1", RestartPolicy: &always},
				{Name: "migrate", Image: "migrate:1"},
			},
		},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{{Name: "web", ContainerID: "containerd://abc"}},
			InitContainerStatuses: []corev1.ContainerStatus{
				{Name: "proxy", LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "OOMKilled"}}},
				{Name: "migrate"},
			},
		},
	}
	got := convertPod(p)
	if got.NodeName != "n1" || !got.HostPID || !got.AutomountToken || len(got.HostPaths) != 1 || got.HostPaths[0] != "/var/log" || len(got.Claims) != 1 {
		t.Fatalf("pod fields: %+v", got)
	}
	if len(got.Specs) != 3 || got.Specs[1].Name != "proxy" || !got.Specs[1].Init {
		t.Fatalf("specs: %+v", got.Specs)
	}
	web := got.Specs[0]
	if !web.Privileged || !web.RunAsNonRoot || *web.RunAsUser != 0 || !web.CapabilitiesDropAll ||
		len(web.CapabilitiesAdd) != 1 || web.CPURequestMilli != 250 || web.MemoryLimitBytes != 512<<20 {
		t.Errorf("container spec (pod defaults overridden by the container): %+v", web)
	}
	if got.Specs[1].RunAsUser == nil || *got.Specs[1].RunAsUser != 1000 {
		t.Errorf("pod-level runAsUser should apply to the sidecar: %+v", got.Specs[1])
	}
	// The sidecar's status is kept so its OOMKill counts; the ordinary init container's is not.
	if len(got.Containers) != 2 || got.Containers[1].Name != "proxy" || got.Containers[1].LastTerminatedReason != "OOMKilled" {
		t.Errorf("container statuses: %+v", got.Containers)
	}
}

func TestListInventory(t *testing.T) {
	cs := fake.NewClientset(
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "web"},
			Spec: appsv1.DeploymentSpec{
				Replicas: ptr(int32(3)),
				Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
				Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{Image: "web:1"}}}},
			},
			Status: appsv1.DeploymentStatus{ReadyReplicas: 2},
		},
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "n1", Labels: map[string]string{"node-role.kubernetes.io/control-plane": ""}},
			Spec:       corev1.NodeSpec{Taints: []corev1.Taint{{Key: "node-role.kubernetes.io/control-plane", Effect: corev1.TaintEffectNoSchedule}}},
			Status: corev1.NodeStatus{
				Allocatable: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("4"), corev1.ResourceMemory: resource.MustParse("8Gi")},
				Conditions:  []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
			},
		},
		&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "erin-admin"},
			RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
			Subjects:   []rbacv1.Subject{{Kind: "User", Name: "erin"}},
		},
	)
	s := NewSource(cs, nil)
	ctx := context.Background()

	ws, err := s.ListWorkloads(ctx)
	if err != nil || len(ws) != 1 {
		t.Fatalf("workloads %+v, %v", ws, err)
	}
	if w := ws[0]; w.Kind != "Deployment" || w.Desired != 3 || w.Ready != 2 || w.Selector.MatchLabels["app"] != "web" || w.Images[0] != "web:1" {
		t.Errorf("deployment: %+v", w)
	}
	nodes, err := s.ListNodes(ctx)
	if err != nil || len(nodes) != 1 {
		t.Fatalf("nodes %+v, %v", nodes, err)
	}
	if n := nodes[0]; !n.Ready || n.Roles[0] != "control-plane" || n.CPUAllocatableMilli != 4000 || n.Taints[0] != "node-role.kubernetes.io/control-plane:NoSchedule" {
		t.Errorf("node: %+v", n)
	}
	rbac, err := s.ListRBAC(ctx)
	if err != nil || len(rbac.Bindings) != 1 || rbac.Bindings[0].Subjects[0].Name != "erin" {
		t.Errorf("rbac %+v, %v", rbac, err)
	}
	// Without a dynamic client, cert-manager is simply reported as absent.
	if cm, err := s.CertManager(ctx); err != nil || cm.Installed {
		t.Errorf("certmanager without dynamic client: %+v, %v", cm, err)
	}
}

func TestCertManager(t *testing.T) {
	cs := fake.NewClientset()
	ctx := context.Background()

	// API not served: not installed, no error.
	absent := NewSource(cs, dynfake.NewSimpleDynamicClient(runtime.NewScheme()))
	if cm, err := absent.CertManager(ctx); err != nil || cm.Installed {
		t.Fatalf("absent: %+v, %v", cm, err)
	}

	cs.Resources = []*metav1.APIResourceList{{GroupVersion: certManagerGroupVersion}}
	notAfter := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	objs := []runtime.Object{
		&unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "cert-manager.io/v1", "kind": "Certificate",
			"metadata": map[string]any{"namespace": "app", "name": "web-tls"},
			"spec":     map[string]any{"secretName": "web-tls", "dnsNames": []any{"web.example.com"}, "issuerRef": map[string]any{"name": "ca", "kind": "ClusterIssuer"}},
			"status": map[string]any{
				"notAfter":   notAfter.Format(time.RFC3339),
				"conditions": []any{map[string]any{"type": "Ready", "status": "True", "reason": "Ready"}},
			},
		}},
		&unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "cert-manager.io/v1", "kind": "ClusterIssuer",
			"metadata": map[string]any{"name": "vault-intermediate"},
			"spec":     map[string]any{"vault": map[string]any{"server": "https://vault:8200"}},
			"status":   map[string]any{"conditions": []any{map[string]any{"type": "Ready", "status": "False", "message": "permission denied"}}},
		}},
		&unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "cert-manager.io/v1", "kind": "CertificateRequest",
			"metadata": map[string]any{"namespace": "app", "name": "web-tls-1", "annotations": map[string]any{"cert-manager.io/certificate-name": "web-tls"}},
			"spec":     map[string]any{"issuerRef": map[string]any{"name": "ca"}},
			"status":   map[string]any{"conditions": []any{map[string]any{"type": "Denied", "status": "True"}}},
		}},
	}
	listKinds := map[schema.GroupVersionResource]string{
		certGVR("certificates"):        "CertificateList",
		certGVR("issuers"):             "IssuerList",
		certGVR("clusterissuers"):      "ClusterIssuerList",
		certGVR("certificaterequests"): "CertificateRequestList",
	}
	dyn := dynfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), listKinds, objs...)

	cm, err := NewSource(cs, dyn).CertManager(ctx)
	if err != nil || !cm.Installed {
		t.Fatalf("installed: %+v, %v", cm, err)
	}
	if len(cm.Certificates) != 1 || len(cm.Issuers) != 1 || len(cm.Requests) != 1 {
		t.Fatalf("counts: %+v", cm)
	}
	c := cm.Certificates[0]
	if c.IssuerKind != "ClusterIssuer" || c.Ready != "True" || !c.NotAfter.Equal(notAfter) || c.DNSNames[0] != "web.example.com" {
		t.Errorf("certificate: %+v", c)
	}
	if is := cm.Issuers[0]; is.Kind != "ClusterIssuer" || is.Type != "vault" || is.Server != "https://vault:8200" || is.Ready != "False" || is.Message != "permission denied" {
		t.Errorf("issuer: %+v", is)
	}
	if r := cm.Requests[0]; r.Certificate != "web-tls" || r.IssuerKind != "Issuer" || !r.Denied {
		t.Errorf("request: %+v", r)
	}
}
