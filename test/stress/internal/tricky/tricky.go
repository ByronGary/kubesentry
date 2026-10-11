// Package tricky creates the deterministic association edge cases on the real
// kind workers (plus one wide Service on fake nodes) and writes the relations
// they are expected to produce to expected.json.
package tricky

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/ByronGary/kubesentry/test/stress/internal/gen"
	"github.com/ByronGary/kubesentry/test/stress/internal/out"
)

// Namespaces of the tricky cases.
const (
	NS     = "stress-tricky"
	WideNS = "stress-wide"
	// CaseLabel names the case an object belongs to.
	CaseLabel = "kubesentry.io/stress-case"
	// Image is a small real image, kind-loaded by hack/stress-up.sh.
	Image = "busybox:1.36"
	// StaticNode is the worker that gets the static pod manifest.
	StaticNode     = "kubesentry-worker"
	staticManifest = "/etc/kubernetes/manifests/stress-static-web.yaml"
)

// Expectation is one relation a case should produce.
type Expectation struct {
	Relation string `json:"relation"` // pod-owner, service-pods, pod-node, pod-pvc, cronjob-job, ingress-service, workload-pods, status
	From     string `json:"from"`     // e.g. Deployment/stress-tricky/web
	// To names the target: a pod name prefix ("web-"), a node, a claim, or a status.
	To    string `json:"to"`
	Count int    `json:"count,omitempty"` // how many pods match To, when it is a prefix
	Note  string `json:"note,omitempty"`
}

// Case is one association edge case.
type Case struct {
	ID          string        `json:"id"`
	Namespace   string        `json:"namespace"`
	Description string        `json:"description"`
	Expect      []Expectation `json:"expect"`
}

// Cases is the case list written to expected.json.
var Cases = []Case{
	{ID: "overlap-selectors", Namespace: NS, Description: "Deployment web (app=web) and web-canary (app=web,track=canary): the canary pods match both selectors but are owned by web-canary.",
		Expect: []Expectation{
			{Relation: "pod-owner", From: "Deployment/stress-tricky/web", To: "web-", Count: 2, Note: "pods named web-<hash>, not web-canary-"},
			{Relation: "pod-owner", From: "Deployment/stress-tricky/web-canary", To: "web-canary-", Count: 1},
			{Relation: "workload-pods", From: "Deployment/stress-tricky/web", Count: 2},
			{Relation: "workload-pods", From: "Deployment/stress-tricky/web-canary", Count: 1},
			{Relation: "service-pods", From: "Service/stress-tricky/web", To: "web-", Count: 3},
			{Relation: "ingress-service", From: "Ingress/stress-tricky/web", To: "Service/stress-tricky/web"},
		}},
	{ID: "jobs-identical-labels", Namespace: NS, Description: "Jobs batch-a and batch-b with identical pod labels (app=batch) and generated selectors.",
		Expect: []Expectation{
			{Relation: "pod-owner", From: "Job/stress-tricky/batch-a", To: "batch-a-", Count: 1},
			{Relation: "pod-owner", From: "Job/stress-tricky/batch-b", To: "batch-b-", Count: 1},
		}},
	{ID: "jobs-manual-selector", Namespace: NS, Description: "Jobs manual-a and manual-b with manualSelector app=batch-manual: both selectors match both pods; ownerReferences decide.",
		Expect: []Expectation{
			{Relation: "pod-owner", From: "Job/stress-tricky/manual-a", To: "manual-a-", Count: 1},
			{Relation: "pod-owner", From: "Job/stress-tricky/manual-b", To: "manual-b-", Count: 1},
			{Relation: "workload-pods", From: "Job/stress-tricky/manual-a", Count: 1},
			{Relation: "workload-pods", From: "Job/stress-tricky/manual-b", Count: 1},
		}},
	{ID: "orphan-replicaset", Namespace: NS, Description: "Deployment orphan-src deleted with propagationPolicy=Orphan: its ReplicaSet and pods remain, owned by nothing above the ReplicaSet.",
		Expect: []Expectation{{Relation: "pod-owner", From: "ReplicaSet/stress-tricky/orphan-src-*", To: "orphan-src-", Count: 2}}},
	{ID: "custom-owner", Namespace: NS, Description: "Pods widget-a-0/1 owned directly by a custom resource Widget/widget-a (widgets.stress.kubesentry.io).",
		Expect: []Expectation{{Relation: "pod-owner", From: "Widget/stress-tricky/widget-a", To: "widget-a-", Count: 2}}},
	{ID: "rollout-like", Namespace: NS, Description: "A Rollout custom resource owns ReplicaSet checkout-rs, which owns 2 pods (as Argo Rollouts does).",
		Expect: []Expectation{
			{Relation: "pod-owner", From: "Rollout/stress-tricky/checkout", To: "checkout-rs-", Count: 2},
			{Relation: "service-pods", From: "Service/stress-tricky/checkout", To: "checkout-rs-", Count: 2},
		}},
	{ID: "failing-readiness", Namespace: NS, Description: "Deployment unready: readiness probe always fails; Service unready lists both pods as not ready.",
		Expect: []Expectation{
			{Relation: "service-pods", From: "Service/stress-tricky/unready", To: "unready-", Count: 2, Note: "endpoints ready=false"},
			{Relation: "status", From: "Pod/stress-tricky/unready-", To: "NotReady"},
		}},
	{ID: "terminating-endpoint", Namespace: NS, Description: "Deployment term (2 replicas, preStop sleep 3600): one pod deleted and stuck terminating; its endpoint is terminating, a replacement runs.",
		Expect: []Expectation{
			{Relation: "service-pods", From: "Service/stress-tricky/term", To: "term-", Count: 3, Note: "1 endpoint terminating=true"},
			{Relation: "workload-pods", From: "Deployment/stress-tricky/term", Count: 2, Note: "the terminating pod is no longer counted"},
		}},
	{ID: "publish-not-ready", Namespace: NS, Description: "Service pnra with publishNotReadyAddresses: its unready pod is published as ready.",
		Expect: []Expectation{{Relation: "service-pods", From: "Service/stress-tricky/pnra", To: "pnra-", Count: 1, Note: "endpoint ready=true although the pod is not"}}},
	{ID: "crashloop", Namespace: NS, Description: "Deployment crashloop exits 1 immediately: CrashLoopBackOff.",
		Expect: []Expectation{
			{Relation: "pod-owner", From: "Deployment/stress-tricky/crashloop", To: "crashloop-", Count: 1},
			{Relation: "status", From: "Pod/stress-tricky/crashloop-", To: "CrashLoopBackOff"},
		}},
	{ID: "image-pull", Namespace: NS, Description: "Deployment imagepull uses an image that does not exist: ImagePullBackOff.",
		Expect: []Expectation{
			{Relation: "pod-owner", From: "Deployment/stress-tricky/imagepull", To: "imagepull-", Count: 1},
			{Relation: "status", From: "Pod/stress-tricky/imagepull-", To: "ImagePullBackOff"},
		}},
	{ID: "unschedulable", Namespace: NS, Description: "Deployment unschedulable selects a node label nothing has: Pending, no node.",
		Expect: []Expectation{
			{Relation: "pod-owner", From: "Deployment/stress-tricky/unschedulable", To: "unschedulable-", Count: 1},
			{Relation: "pod-node", From: "Pod/stress-tricky/unschedulable-", To: ""},
			{Relation: "status", From: "Pod/stress-tricky/unschedulable-", To: "Unschedulable"},
		}},
	{ID: "bare-pod", Namespace: NS, Description: "Pod bare-1 with no owner.",
		Expect: []Expectation{{Relation: "pod-owner", From: "", To: "bare-1", Count: 1, Note: "no owner"}}},
	{ID: "static-pod", Namespace: NS, Description: "Static pod from a manifest in kubesentry-worker:/etc/kubernetes/manifests; its mirror pod is owned by the Node.",
		Expect: []Expectation{
			{Relation: "pod-owner", From: "", To: "static-web-kubesentry-worker", Count: 1, Note: "mirror pod, owned by the Node: no workload"},
			{Relation: "pod-node", From: "Pod/stress-tricky/static-web-kubesentry-worker", To: "Node/kubesentry-worker"},
		}},
	{ID: "succeeded-selected", Namespace: NS, Description: "Pod done-1 has Succeeded; Service done selects it. The EndpointSlice keeps it as an endpoint that is neither ready nor serving, so it gets no traffic.",
		Expect: []Expectation{{Relation: "service-pods", From: "Service/stress-tricky/done", To: "done-1", Count: 1, Note: "ready=false, serving=false"}}},
	{ID: "mid-rollout", Namespace: NS, Description: "Deployment rollout: revision 2 never becomes ready (maxUnavailable 0), so 3 old and 1 new pod coexist.",
		Expect: []Expectation{
			{Relation: "pod-owner", From: "Deployment/stress-tricky/rollout", To: "rollout-", Count: 4},
			{Relation: "service-pods", From: "Service/stress-tricky/rollout", To: "rollout-", Count: 4, Note: "1 not ready"},
		}},
	{ID: "multi-workload-service", Namespace: NS, Description: "Service backend (tier=backend) spans Deployments api and worker.",
		Expect: []Expectation{{Relation: "service-pods", From: "Service/stress-tricky/backend", To: "", Count: 2}}},
	{ID: "statefulset", Namespace: NS, Description: "StatefulSet db with a headless Service.",
		Expect: []Expectation{
			{Relation: "pod-owner", From: "StatefulSet/stress-tricky/db", To: "db-", Count: 2},
			{Relation: "service-pods", From: "Service/stress-tricky/db", To: "db-", Count: 2},
		}},
	{ID: "cronjob", Namespace: NS, Description: "CronJob tick runs every 2 minutes; CronJob → Job → pod.",
		Expect: []Expectation{{Relation: "cronjob-job", From: "CronJob/stress-tricky/tick", To: "tick-"}}},
	{ID: "pvc-mount", Namespace: NS, Description: "Deployment pvc-user mounts a dynamically provisioned claim tricky-data; Ingress ghost points at a missing Service.",
		Expect: []Expectation{
			{Relation: "pod-pvc", From: "Pod/stress-tricky/pvc-user-", To: "PVC/stress-tricky/tricky-data"},
			{Relation: "ingress-service", From: "Ingress/stress-tricky/ghost", To: "", Note: "backend Service missing"},
		}},
	{ID: "wide-service", Namespace: WideNS, Description: "Service wide selects a 300-replica Deployment on fake nodes: 3+ EndpointSlices.",
		Expect: []Expectation{
			{Relation: "service-pods", From: "Service/stress-wide/wide", To: "wide-", Count: 300},
			{Relation: "workload-pods", From: "Deployment/stress-wide/wide", Count: 300},
		}},
}

func lbl(caseID string, kv ...string) map[string]string {
	m := map[string]string{"kubesentry.io/stress": "true", CaseLabel: caseID}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return m
}

func ptr[T any](v T) *T { return &v }

func om(caseID, name string, kv ...string) metav1.ObjectMeta {
	return metav1.ObjectMeta{Namespace: NS, Name: name, Labels: lbl(caseID, kv...)}
}

// realSpec runs a small real container on the untainted real workers.
func realSpec(cmd ...string) corev1.PodSpec {
	if len(cmd) == 0 {
		cmd = []string{"sh", "-c", "trap 'exit 0' TERM; while true; do sleep 5; done"}
	}
	return corev1.PodSpec{
		TerminationGracePeriodSeconds: ptr(int64(2)),
		Affinity: &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
			NodeSelectorTerms: []corev1.NodeSelectorTerm{{MatchExpressions: []corev1.NodeSelectorRequirement{
				{Key: "type", Operator: corev1.NodeSelectorOpNotIn, Values: []string{"kwok"}},
			}}},
		}}},
		Containers: []corev1.Container{{
			Name: "main", Image: Image, ImagePullPolicy: corev1.PullIfNotPresent, Command: cmd,
			Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("5m"), corev1.ResourceMemory: resource.MustParse("8Mi")},
				Limits:   corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("32Mi")},
			},
		}},
	}
}

func tpl(caseID string, spec corev1.PodSpec, kv ...string) corev1.PodTemplateSpec {
	return corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: lbl(caseID, kv...)}, Spec: spec}
}

func deploy(caseID, name string, reps int32, sel map[string]string, t corev1.PodTemplateSpec) *appsv1.Deployment {
	return &appsv1.Deployment{ObjectMeta: om(caseID, name), Spec: appsv1.DeploymentSpec{
		Replicas: ptr(reps), Selector: &metav1.LabelSelector{MatchLabels: sel}, Template: t}}
}

func svc(caseID, name string, sel map[string]string) *corev1.Service {
	return &corev1.Service{ObjectMeta: om(caseID, name), Spec: corev1.ServiceSpec{
		Selector: sel, Ports: []corev1.ServicePort{{Name: "http", Port: 80, TargetPort: intstr.FromInt32(8080)}}}}
}

func failingReadiness(spec corev1.PodSpec) corev1.PodSpec {
	spec.Containers[0].ReadinessProbe = &corev1.Probe{
		ProbeHandler:  corev1.ProbeHandler{Exec: &corev1.ExecAction{Command: []string{"false"}}},
		PeriodSeconds: 10, FailureThreshold: 1,
	}
	return spec
}

// baseObjects are the objects that need no sequencing.
func baseObjects() []runtime.Object {
	var o []runtime.Object
	add := func(x runtime.Object) { o = append(o, x) }
	add(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: NS, Labels: lbl("namespace")}})
	add(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: WideNS, Labels: lbl("namespace")}})

	// overlap-selectors
	add(deploy("overlap-selectors", "web", 2, map[string]string{"app": "web"}, tpl("overlap-selectors", realSpec(), "app", "web")))
	add(deploy("overlap-selectors", "web-canary", 1, map[string]string{"app": "web", "track": "canary"}, tpl("overlap-selectors", realSpec(), "app", "web", "track", "canary")))
	add(svc("overlap-selectors", "web", map[string]string{"app": "web"}))
	add(&networkingv1.Ingress{ObjectMeta: om("overlap-selectors", "web"), Spec: networkingv1.IngressSpec{
		IngressClassName: ptr("nginx"),
		TLS:              []networkingv1.IngressTLS{{Hosts: []string{"web.tricky.example.com"}, SecretName: "web-tls"}},
		Rules: []networkingv1.IngressRule{{Host: "web.tricky.example.com", IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{
			Paths: []networkingv1.HTTPIngressPath{{Path: "/", PathType: ptr(networkingv1.PathTypePrefix), Backend: networkingv1.IngressBackend{
				Service: &networkingv1.IngressServiceBackend{Name: "web", Port: networkingv1.ServiceBackendPort{Number: 80}}}}}}}}}}})

	// jobs
	for _, n := range []string{"batch-a", "batch-b"} {
		spec := realSpec("sh", "-c", "sleep 86400")
		spec.RestartPolicy = corev1.RestartPolicyNever
		add(&batchv1.Job{ObjectMeta: om("jobs-identical-labels", n), Spec: batchv1.JobSpec{BackoffLimit: ptr(int32(0)),
			Template: tpl("jobs-identical-labels", spec, "app", "batch")}})
	}
	for _, n := range []string{"manual-a", "manual-b"} {
		spec := realSpec("sh", "-c", "sleep 86400")
		spec.RestartPolicy = corev1.RestartPolicyNever
		add(&batchv1.Job{ObjectMeta: om("jobs-manual-selector", n), Spec: batchv1.JobSpec{BackoffLimit: ptr(int32(0)), ManualSelector: ptr(true),
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "batch-manual"}},
			Template: tpl("jobs-manual-selector", spec, "app", "batch-manual")}})
	}

	// orphan-replicaset (the Deployment is deleted with Orphan later)
	add(deploy("orphan-replicaset", "orphan-src", 2, map[string]string{"app": "orphan-src"}, tpl("orphan-replicaset", realSpec(), "app", "orphan-src")))

	// failing readiness, publishNotReadyAddresses
	add(deploy("failing-readiness", "unready", 2, map[string]string{"app": "unready"}, tpl("failing-readiness", failingReadiness(realSpec()), "app", "unready")))
	add(svc("failing-readiness", "unready", map[string]string{"app": "unready"}))
	add(deploy("publish-not-ready", "pnra", 1, map[string]string{"app": "pnra"}, tpl("publish-not-ready", failingReadiness(realSpec()), "app", "pnra")))
	p := svc("publish-not-ready", "pnra", map[string]string{"app": "pnra"})
	p.Spec.PublishNotReadyAddresses = true
	add(p)

	// terminating endpoint
	term := realSpec("sh", "-c", "while true; do sleep 5; done")
	term.TerminationGracePeriodSeconds = ptr(int64(3600))
	term.Containers[0].Lifecycle = &corev1.Lifecycle{PreStop: &corev1.LifecycleHandler{Exec: &corev1.ExecAction{Command: []string{"sleep", "3600"}}}}
	add(deploy("terminating-endpoint", "term", 2, map[string]string{"app": "term"}, tpl("terminating-endpoint", term, "app", "term")))
	add(svc("terminating-endpoint", "term", map[string]string{"app": "term"}))

	// crashloop, image pull, unschedulable
	add(deploy("crashloop", "crashloop", 1, map[string]string{"app": "crashloop"}, tpl("crashloop", realSpec("sh", "-c", "echo boom; exit 1"), "app", "crashloop")))
	ip := realSpec()
	ip.Containers[0].Image = "registry.invalid/stress/does-not-exist:1"
	add(deploy("image-pull", "imagepull", 1, map[string]string{"app": "imagepull"}, tpl("image-pull", ip, "app", "imagepull")))
	un := realSpec()
	un.NodeSelector = map[string]string{"kubesentry.io/nowhere": "true"}
	add(deploy("unschedulable", "unschedulable", 1, map[string]string{"app": "unschedulable"}, tpl("unschedulable", un, "app", "unschedulable")))

	// bare pod and a Succeeded pod selected by a Service
	add(&corev1.Pod{ObjectMeta: om("bare-pod", "bare-1", "app", "bare"), Spec: realSpec()})
	done := realSpec("true")
	done.RestartPolicy = corev1.RestartPolicyNever
	add(&corev1.Pod{ObjectMeta: om("succeeded-selected", "done-1", "app", "done"), Spec: done})
	add(svc("succeeded-selected", "done", map[string]string{"app": "done"}))

	// mid-rollout (revision 2 is patched in later)
	ro := deploy("mid-rollout", "rollout", 3, map[string]string{"app": "rollout"}, tpl("mid-rollout", realSpec(), "app", "rollout"))
	ro.Spec.Strategy = appsv1.DeploymentStrategy{Type: appsv1.RollingUpdateDeploymentStrategyType, RollingUpdate: &appsv1.RollingUpdateDeployment{
		MaxUnavailable: ptr(intstr.FromInt32(0)), MaxSurge: ptr(intstr.FromInt32(1))}}
	add(ro)
	add(svc("mid-rollout", "rollout", map[string]string{"app": "rollout"}))

	// multi-workload Service
	add(deploy("multi-workload-service", "api", 1, map[string]string{"app": "api"}, tpl("multi-workload-service", realSpec(), "app", "api", "tier", "backend")))
	add(deploy("multi-workload-service", "worker", 1, map[string]string{"app": "worker"}, tpl("multi-workload-service", realSpec(), "app", "worker", "tier", "backend")))
	add(svc("multi-workload-service", "backend", map[string]string{"tier": "backend"}))

	// StatefulSet
	dbSvc := svc("statefulset", "db", map[string]string{"app": "db"})
	dbSvc.Spec.ClusterIP = corev1.ClusterIPNone
	add(dbSvc)
	add(&appsv1.StatefulSet{ObjectMeta: om("statefulset", "db"), Spec: appsv1.StatefulSetSpec{
		Replicas: ptr(int32(2)), ServiceName: "db", PodManagementPolicy: appsv1.ParallelPodManagement,
		Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "db"}},
		Template: tpl("statefulset", realSpec(), "app", "db")}})

	// CronJob
	cj := realSpec("date")
	cj.RestartPolicy = corev1.RestartPolicyNever
	add(&batchv1.CronJob{ObjectMeta: om("cronjob", "tick"), Spec: batchv1.CronJobSpec{
		Schedule: "*/2 * * * *", SuccessfulJobsHistoryLimit: ptr(int32(2)), FailedJobsHistoryLimit: ptr(int32(1)),
		JobTemplate: batchv1.JobTemplateSpec{Spec: batchv1.JobSpec{BackoffLimit: ptr(int32(0)), Template: tpl("cronjob", cj, "app", "tick")}}}})

	// PVC mount (kind's local-path "standard" class provisions it) and an Ingress to a missing Service
	add(&corev1.PersistentVolumeClaim{ObjectMeta: om("pvc-mount", "tricky-data"), Spec: corev1.PersistentVolumeClaimSpec{
		AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
		Resources:   corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("10Mi")}}}})
	pv := realSpec()
	pv.Volumes = []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "tricky-data"}}}}
	pv.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: "data", MountPath: "/data"}}
	add(deploy("pvc-mount", "pvc-user", 1, map[string]string{"app": "pvc-user"}, tpl("pvc-mount", pv, "app", "pvc-user")))
	add(&networkingv1.Ingress{ObjectMeta: om("pvc-mount", "ghost"), Spec: networkingv1.IngressSpec{
		DefaultBackend: &networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "ghost", Port: networkingv1.ServiceBackendPort{Number: 80}}}}})

	// wide Service on fake nodes
	wideSpec := corev1.PodSpec{
		NodeSelector: map[string]string{"type": "kwok"},
		Tolerations:  []corev1.Toleration{{Key: "kwok.x-k8s.io/node", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule}},
		Containers: []corev1.Container{{Name: "wide", Image: "123456789012.dkr.ecr.us-east-1.amazonaws.com/stress/wide:1",
			Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("10m"), corev1.ResourceMemory: resource.MustParse("16Mi")}}}},
	}
	wide := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: WideNS, Name: "wide", Labels: lbl("wide-service")}, Spec: appsv1.DeploymentSpec{
		Replicas: ptr(int32(300)), Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "wide"}},
		Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: lbl("wide-service", "app", "wide")}, Spec: wideSpec}}}
	add(wide)
	ws := svc("wide-service", "wide", map[string]string{"app": "wide"})
	ws.Namespace = WideNS
	add(ws)
	return o
}

var (
	crdGVR    = schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}
	widgetGVR = schema.GroupVersionResource{Group: "stress.kubesentry.io", Version: "v1", Resource: "widgets"}
	rollGVR   = schema.GroupVersionResource{Group: "stress.kubesentry.io", Version: "v1", Resource: "rollouts"}
)

func crd(kind, plural string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition",
		"metadata": map[string]any{"name": plural + ".stress.kubesentry.io", "labels": map[string]any{"kubesentry.io/stress": "true"}},
		"spec": map[string]any{
			"group": "stress.kubesentry.io", "scope": "Namespaced",
			"names": map[string]any{"kind": kind, "plural": plural, "singular": strings.ToLower(kind), "listKind": kind + "List"},
			"versions": []any{map[string]any{"name": "v1", "served": true, "storage": true,
				"schema": map[string]any{"openAPIV3Schema": map[string]any{"type": "object", "x-kubernetes-preserve-unknown-fields": true}}}},
		},
	}}
}

func cr(gvr schema.GroupVersionResource, kind, name string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": gvr.GroupVersion().String(), "kind": kind,
		"metadata": map[string]any{"namespace": NS, "name": name, "labels": map[string]any{"kubesentry.io/stress": "true", CaseLabel: map[string]string{"Widget": "custom-owner", "Rollout": "rollout-like"}[kind]}},
		"spec":     map[string]any{"replicas": int64(2)},
	}}
}

func ownerRef(u *unstructured.Unstructured) metav1.OwnerReference {
	return metav1.OwnerReference{APIVersion: u.GetAPIVersion(), Kind: u.GetKind(), Name: u.GetName(), UID: u.GetUID(), Controller: ptr(true), BlockOwnerDeletion: ptr(true)}
}

// Apply creates every case; it is safe to run again.
func Apply(ctx context.Context, cs kubernetes.Interface, dyn dynamic.Interface, a *gen.Applier, staticPod bool) error {
	a.Apply(ctx, "tricky: CRDs", []runtime.Object{crd("Widget", "widgets"), crd("Rollout", "rollouts")})
	for _, n := range []string{"widgets", "rollouts"} {
		if err := waitCRD(ctx, dyn, n+".stress.kubesentry.io"); err != nil {
			return err
		}
	}
	base := baseObjects()
	if orphaned(ctx, cs) {
		// Re-creating orphan-src would adopt the orphaned ReplicaSet again.
		kept := base[:0]
		for _, o := range base {
			if d, ok := o.(*appsv1.Deployment); ok && d.Name == "orphan-src" {
				continue
			}
			kept = append(kept, o)
		}
		base = kept
	}
	a.Apply(ctx, "tricky: base objects", base)

	// Custom owners need the owner's UID.
	widget, err := getOrCreate(ctx, dyn, widgetGVR, cr(widgetGVR, "Widget", "widget-a"))
	if err != nil {
		return fmt.Errorf("widget: %w", err)
	}
	var owned []runtime.Object
	for k := 0; k < 2; k++ {
		p := &corev1.Pod{ObjectMeta: om("custom-owner", fmt.Sprintf("widget-a-%d", k), "app", "widget"), Spec: realSpec()}
		p.OwnerReferences = []metav1.OwnerReference{ownerRef(widget)}
		owned = append(owned, p)
	}
	roll, err := getOrCreate(ctx, dyn, rollGVR, cr(rollGVR, "Rollout", "checkout"))
	if err != nil {
		return fmt.Errorf("rollout: %w", err)
	}
	rs := &appsv1.ReplicaSet{ObjectMeta: om("rollout-like", "checkout-rs"), Spec: appsv1.ReplicaSetSpec{
		Replicas: ptr(int32(2)),
		Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "checkout", "rollouts-pod-template-hash": "6b9f7c"}},
		Template: tpl("rollout-like", realSpec(), "app", "checkout", "rollouts-pod-template-hash", "6b9f7c")}}
	rs.OwnerReferences = []metav1.OwnerReference{ownerRef(roll)}
	owned = append(owned, rs, svc("rollout-like", "checkout", map[string]string{"app": "checkout"}))
	a.Apply(ctx, "tricky: custom owners", owned)

	if err := orphan(ctx, cs); err != nil {
		out.Logf("tricky: orphan-replicaset: %v", err)
	}
	if err := midRollout(ctx, cs); err != nil {
		out.Logf("tricky: mid-rollout: %v", err)
	}
	if err := terminate(ctx, cs); err != nil {
		out.Logf("tricky: terminating-endpoint: %v", err)
	}
	if staticPod {
		if err := writeStaticPod(ctx); err != nil {
			out.Logf("tricky: static pod: %v", err)
		}
	}
	return nil
}

func waitCRD(ctx context.Context, dyn dynamic.Interface, name string) error {
	return wait.PollUntilContextTimeout(ctx, time.Second, 60*time.Second, true, func(ctx context.Context) (bool, error) {
		u, err := dyn.Resource(crdGVR).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		conds, _, _ := unstructured.NestedSlice(u.Object, "status", "conditions")
		for _, c := range conds {
			m, _ := c.(map[string]any)
			if m["type"] == "Established" && m["status"] == "True" {
				return true, nil
			}
		}
		return false, nil
	})
}

func getOrCreate(ctx context.Context, dyn dynamic.Interface, gvr schema.GroupVersionResource, u *unstructured.Unstructured) (*unstructured.Unstructured, error) {
	got, err := dyn.Resource(gvr).Namespace(u.GetNamespace()).Get(ctx, u.GetName(), metav1.GetOptions{})
	if err == nil {
		return got, nil
	}
	var res *unstructured.Unstructured
	err = wait.PollUntilContextTimeout(ctx, 2*time.Second, 60*time.Second, true, func(ctx context.Context) (bool, error) {
		r, err := dyn.Resource(gvr).Namespace(u.GetNamespace()).Create(ctx, u, metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(err) {
			r, err = dyn.Resource(gvr).Namespace(u.GetNamespace()).Get(ctx, u.GetName(), metav1.GetOptions{})
		}
		if err != nil {
			return false, nil // CRD may not be served yet
		}
		res = r
		return true, nil
	})
	return res, err
}

func waitAvailable(ctx context.Context, cs kubernetes.Interface, name string, want int32) error {
	return wait.PollUntilContextTimeout(ctx, 2*time.Second, 4*time.Minute, true, func(ctx context.Context) (bool, error) {
		d, err := cs.AppsV1().Deployments(NS).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, nil
		}
		return d.Status.AvailableReplicas >= want, nil
	})
}

// orphaned reports whether orphan-src's ReplicaSet already lost its owner.
func orphaned(ctx context.Context, cs kubernetes.Interface) bool {
	rsl, err := cs.AppsV1().ReplicaSets(NS).List(ctx, metav1.ListOptions{LabelSelector: "app=orphan-src"})
	if err != nil {
		return false
	}
	for _, rs := range rsl.Items {
		if len(rs.OwnerReferences) == 0 {
			return true
		}
	}
	return false
}

// orphan deletes Deployment orphan-src with propagationPolicy=Orphan once its
// pods run, leaving the ReplicaSet and pods behind.
func orphan(ctx context.Context, cs kubernetes.Interface) error {
	if _, err := cs.AppsV1().Deployments(NS).Get(ctx, "orphan-src", metav1.GetOptions{}); apierrors.IsNotFound(err) || orphaned(ctx, cs) {
		return nil // already orphaned
	}
	if err := waitAvailable(ctx, cs, "orphan-src", 2); err != nil {
		return fmt.Errorf("waiting for orphan-src: %w", err)
	}
	orphanPolicy := metav1.DeletePropagationOrphan
	return cs.AppsV1().Deployments(NS).Delete(ctx, "orphan-src", metav1.DeleteOptions{PropagationPolicy: &orphanPolicy})
}

// midRollout patches Deployment rollout to a revision whose pods never become ready.
func midRollout(ctx context.Context, cs kubernetes.Interface) error {
	d, err := cs.AppsV1().Deployments(NS).Get(ctx, "rollout", metav1.GetOptions{})
	if err != nil {
		return err
	}
	if d.Annotations["deployment.kubernetes.io/revision"] != "" && d.Annotations["deployment.kubernetes.io/revision"] != "1" {
		return nil
	}
	if err := waitAvailable(ctx, cs, "rollout", 3); err != nil {
		return err
	}
	patch := `{"spec":{"template":{"metadata":{"annotations":{"kubesentry.io/revision":"2"}},"spec":{"containers":[{"name":"main","readinessProbe":{"exec":{"command":["false"]},"periodSeconds":10,"failureThreshold":1}}]}}}}`
	_, err = cs.AppsV1().Deployments(NS).Patch(ctx, "rollout", types.StrategicMergePatchType, []byte(patch), metav1.PatchOptions{})
	return err
}

// EnsureTerminating re-arms the terminating-endpoint case before a
// verification: the preStop hook keeps a deleted pod terminating for an hour,
// so a later run may find none. It waits briefly for the EndpointSlice.
func EnsureTerminating(ctx context.Context, cs kubernetes.Interface) error {
	pods, err := cs.CoreV1().Pods(NS).List(ctx, metav1.ListOptions{LabelSelector: "app=term"})
	if err != nil {
		return err
	}
	for _, p := range pods.Items {
		if p.DeletionTimestamp != nil {
			return nil
		}
	}
	if err := terminate(ctx, cs); err != nil {
		return err
	}
	time.Sleep(10 * time.Second)
	return nil
}

// terminate deletes one term pod; preStop keeps it terminating for an hour.
func terminate(ctx context.Context, cs kubernetes.Interface) error {
	if err := waitAvailable(ctx, cs, "term", 2); err != nil {
		return err
	}
	pods, err := cs.CoreV1().Pods(NS).List(ctx, metav1.ListOptions{LabelSelector: "app=term"})
	if err != nil {
		return err
	}
	for _, p := range pods.Items {
		if p.DeletionTimestamp != nil {
			return nil
		}
	}
	for _, p := range pods.Items {
		if p.Status.Phase == corev1.PodRunning {
			return cs.CoreV1().Pods(NS).Delete(ctx, p.Name, metav1.DeleteOptions{})
		}
	}
	return fmt.Errorf("no running term pod")
}

const staticPodYAML = `apiVersion: v1
kind: Pod
metadata:
  name: static-web
  namespace: stress-tricky
  labels:
    app: static
    kubesentry.io/stress: "true"
    kubesentry.io/stress-case: static-pod
spec:
  containers:
    - name: main
      image: busybox:1.36
      imagePullPolicy: IfNotPresent
      command: ["sh", "-c", "trap 'exit 0' TERM; while true; do sleep 5; done"]
      resources:
        requests: {cpu: 5m, memory: 8Mi}
        limits: {memory: 32Mi}
`

// writeStaticPod puts the manifest on the worker through docker exec (host only).
func writeStaticPod(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "docker", "exec", "-i", StaticNode, "sh", "-c", "cat > "+staticManifest)
	cmd.Stdin = strings.NewReader(staticPodYAML)
	if b, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("docker exec: %v: %s", err, b)
	}
	return nil
}

// RemoveStaticPod deletes the manifest (host only).
func RemoveStaticPod(ctx context.Context) error {
	b, err := exec.CommandContext(ctx, "docker", "exec", StaticNode, "rm", "-f", staticManifest).CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker exec: %v: %s", err, b)
	}
	return nil
}

// Expected is the expected.json document.
type Expected struct {
	GeneratedAt time.Time `json:"generatedAt"`
	Level       string    `json:"level"`
	Cases       []Case    `json:"cases"`
	Notes       []string  `json:"notes"`
}

// ExpectedDoc returns the expected relations for the given level.
func ExpectedDoc(level string) Expected {
	return Expected{GeneratedAt: time.Now().UTC(), Level: level, Cases: Cases, Notes: []string{
		"Relations follow controller ownerReferences (Pod→ReplicaSet→Deployment, Pod→Job→CronJob, StatefulSet, DaemonSet, custom owners) and EndpointSlices for Service→Pod.",
		"pod-owner From is the nearest workload-level owner: a ReplicaSet owned by a Deployment collapses to the Deployment; an orphaned ReplicaSet or one owned by a custom resource does not.",
		"To is a pod name prefix where pod names are generated; Count is the number of such pods expected.",
		"workload-pods counts live pods (not Succeeded/Failed, not terminating).",
		"Generated namespaces (team and EKS add-on) are verified against the live ground truth only.",
	}}
}
