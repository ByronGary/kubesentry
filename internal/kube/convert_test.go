package kube

import (
	"reflect"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/ByronGary/kubesentry/internal/model"
)

// fixture returns the fixture of type T with the given name.
func fixture[T runtime.Object](t *testing.T, name string) T {
	t.Helper()
	for _, o := range fixtureObjects() {
		if v, ok := o.(T); ok && o.(interface{ GetName() string }).GetName() == name {
			return v
		}
	}
	var zero T
	t.Fatalf("no fixture %T %s", zero, name)
	return zero
}

func TestConvertPodStateFields(t *testing.T) {
	pods := fixturePods()
	web := convertPod(pods[0])
	if want := []model.OwnerRef{{Kind: "ReplicaSet", Name: "web-5d8f", UID: "rs-web", Controller: true}}; !reflect.DeepEqual(web.Owners, want) {
		t.Errorf("owners: %+v", web.Owners)
	}
	if !web.Ready || !web.ReadyChanged.Equal(t1.Time) || web.PodIP != "10.0.1.15" || web.QOSClass != "Burstable" ||
		web.Unschedulable != "" || !web.DeletedAt.IsZero() {
		t.Errorf("web pod: %+v", web)
	}
	if len(web.Containers) != 3 {
		t.Fatalf("containers: %+v", web.Containers)
	}
	app, proxy, migrate := web.Containers[0], web.Containers[1], web.Containers[2]
	if app.Init || !app.Ready || !app.Started || app.State != "running" || app.Reason != "" ||
		app.MemoryLimitBytes != 768<<20 || app.LastTerminatedReason != "OOMKilled" || app.LastExitCode != 137 || app.RestartCount != 4 {
		t.Errorf("app container: %+v", app)
	}
	if proxy.Name != "proxy" || !proxy.Init || proxy.State != "running" || proxy.MemoryLimitBytes != 0 {
		t.Errorf("sidecar: %+v", proxy)
	}
	if migrate.Name != "migrate" || !migrate.Init || migrate.State != "terminated" || migrate.Reason != "Completed" || migrate.Started {
		t.Errorf("ordinary init container: %+v", migrate)
	}

	pending := convertPod(pods[1])
	if pending.Ready || !strings.HasPrefix(longMsg, pending.Unschedulable) || len(pending.Unschedulable) == 0 || len(pending.Unschedulable) > maxMessage {
		t.Errorf("unschedulable: %q", pending.Unschedulable)
	}

	crash := convertPod(pods[2])
	if !crash.DeletedAt.Equal(t1.Time) || crash.Ready || !crash.ReadyChanged.Equal(t0.Time) || crash.QOSClass != "Guaranteed" {
		t.Errorf("crash pod: %+v", crash)
	}
	if crash.Reason != "Evicted" || len(crash.Message) != maxMessage || !strings.HasPrefix(longMsg, crash.Message) {
		t.Errorf("pod-level reason: %q %q", crash.Reason, crash.Message)
	}
	if web.Reason != "" || web.Message != "" {
		t.Errorf("ordinary pod has a reason: %q %q", web.Reason, web.Message)
	}
	byName := map[string]model.ContainerStatus{}
	for _, c := range crash.Containers {
		byName[c.Name] = c
	}
	if c := byName["web"]; c.State != "waiting" || c.Reason != "PodInitializing" || c.Init {
		t.Errorf("waiting app container: %+v", c)
	}
	if c := byName["migrate"]; !c.Init || c.State != "waiting" || c.Reason != "CrashLoopBackOff" || c.RestartCount != 7 ||
		c.LastTerminatedReason != "Error" || c.LastExitCode != 2 || len(c.Message) > maxMessage || !strings.HasPrefix(c.Message, "back-off") {
		t.Errorf("Init:CrashLoopBackOff: %+v", c)
	}
	if c := byName["proxy"]; c.State != "terminated" || c.Reason != "Error" || len(c.Message) != maxMessage {
		t.Errorf("terminated sidecar: %+v", c)
	}
}

func TestConvertWorkloadIdentity(t *testing.T) {
	apps := newAppLabelFilter(nil)
	job := convertJob(fixture[*batchv1.Job](t, "backup-29000"), apps)
	if job.UID != "job-backup" || len(job.Owners) != 1 || job.Owners[0].Kind != "CronJob" || job.Owners[0].Name != "backup" || !job.Owners[0].Controller {
		t.Errorf("job: %+v", job)
	}
	dep := convertDeployment(fixture[*appsv1.Deployment](t, "web"), apps)
	if dep.UID != "dep-web" || dep.Owners != nil || len(dep.Conditions[0].Message) > maxMessage {
		t.Errorf("deployment: %+v", dep)
	}
	if want := []string{"registry.example.com/web:1.2.3", "envoy:1.30", "registry.example.com/migrate:1.2.3"}; !reflect.DeepEqual(dep.Images, want) {
		t.Errorf("images: %v", dep.Images)
	}
}

// Workloads keep only the app tag labels, and a revision that changes on
// every rollout.
func TestConvertWorkloadTagsAndRevision(t *testing.T) {
	apps := newAppLabelFilter(nil)
	dep := convertDeployment(fixture[*appsv1.Deployment](t, "web"), apps)
	if want := map[string]string{"app": "web", "app.kubernetes.io/name": "web", "app.kubernetes.io/part-of": "shop"}; !reflect.DeepEqual(dep.Labels, want) {
		t.Errorf("deployment labels: %v", dep.Labels)
	}
	if dep.Revision != "7" {
		t.Errorf("deployment revision: %q", dep.Revision)
	}
	sts := convertStatefulSet(fixture[*appsv1.StatefulSet](t, "crash"), apps)
	if sts.Revision != "crash-6d4f" || !reflect.DeepEqual(sts.Labels, map[string]string{"app": "crash"}) {
		t.Errorf("statefulset: revision %q labels %v", sts.Revision, sts.Labels)
	}
	ds := convertDaemonSet(fixture[*appsv1.DaemonSet](t, "agent"), apps)
	if ds.Revision != "4" || !reflect.DeepEqual(ds.Labels, map[string]string{"app": "agent", "k8s-app": "agent"}) {
		t.Errorf("daemonset: revision %q labels %v", ds.Revision, ds.Labels)
	}
	for _, w := range []model.Workload{
		convertJob(fixture[*batchv1.Job](t, "backup-29000"), apps),
		convertCronJob(fixture[*batchv1.CronJob](t, "backup"), apps),
	} {
		if w.Revision != "" {
			t.Errorf("%s revision: %q", w.Kind, w.Revision)
		}
	}
	// The custom tag key (-incident-app-label) is kept as well; "prefix*" matches by prefix.
	custom := convertDeployment(fixture[*appsv1.Deployment](t, "web"), newAppLabelFilter([]string{" team ", ""}))
	if custom.Labels["team"] != "payments" || len(custom.Labels) != 4 {
		t.Errorf("custom tag: %v", custom.Labels)
	}
	if p := convertDeployment(fixture[*appsv1.Deployment](t, "web"), newAppLabelFilter([]string{"te*"})); p.Labels["team"] != "payments" {
		t.Errorf("custom tag prefix: %v", p.Labels)
	}
	// No tag labels at all: nil, not an empty map.
	bare := fixture[*appsv1.Deployment](t, "web").DeepCopy()
	bare.Labels = map[string]string{"team": "payments"}
	if l := convertDeployment(bare, apps).Labels; l != nil {
		t.Errorf("untagged labels: %#v", l)
	}
}

func TestConvertReplicaSet(t *testing.T) {
	rs := convertReplicaSet(fixture[*appsv1.ReplicaSet](t, "web-5d8f"))
	want := model.ReplicaSet{Namespace: "app", Name: "web-5d8f", UID: "rs-web", Desired: 3, Ready: 2, Created: t0.Time,
		Owners:   []model.OwnerRef{{Kind: "Deployment", Name: "web", UID: "dep-web", Controller: true}},
		Revision: "7", Images: []string{"registry.example.com/web:1.2.3", "envoy:1.30", "registry.example.com/migrate:1.2.3"}}
	if !reflect.DeepEqual(rs, want) {
		t.Errorf("replicaset:\n got %+v\nwant %+v", rs, want)
	}
	orphan := convertReplicaSet(fixture[*appsv1.ReplicaSet](t, "orphan-1"))
	if orphan.Owners != nil || orphan.Desired != 1 || orphan.Revision != "" {
		t.Errorf("orphan: %+v", orphan)
	}
}

func TestConvertEndpointSlice(t *testing.T) {
	got := convertEndpointSlice(fixture[*discoveryv1.EndpointSlice](t, "web-xyz12"))
	want := model.EndpointSlice{
		Namespace: "app", Name: "web-xyz12", Service: "web", ManagedBy: "endpointslice-controller.k8s.io",
		Endpoints: []model.Endpoint{
			// Nil conditions take the API defaults.
			{Addresses: []string{"10.0.1.15"}, Ready: true, Serving: true, Terminating: false, NodeName: "n1", TargetKind: "Pod", TargetName: "web-5d8f-abcde", TargetUID: "pod-web"},
			{Addresses: []string{"10.0.2.7"}, NodeName: "n2", TargetKind: "Pod", TargetName: "crash-0", TargetUID: "pod-crash"},
			{Addresses: []string{"10.0.3.9"}, Serving: true, Terminating: true},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("endpointslice:\n got %+v\nwant %+v", got, want)
	}
}

func TestConvertServiceAndIngressAnnotations(t *testing.T) {
	svc := convertService(fixture[*corev1.Service](t, "web"))
	wantAnn := map[string]string{
		"service.beta.kubernetes.io/aws-load-balancer-scheme":          "internal",
		"service.beta.kubernetes.io/aws-load-balancer-type":            "external",
		"service.beta.kubernetes.io/aws-load-balancer-nlb-target-type": "ip",
		"service.beta.kubernetes.io/aws-load-balancer-security-groups": "sg-0aaa,sg-0bbb",
	}
	if !reflect.DeepEqual(svc.Annotations, wantAnn) || svc.LoadBalancerClass != "service.k8s.aws/nlb" ||
		!reflect.DeepEqual(svc.SourceRanges, []string{"10.0.0.0/8"}) || !svc.PublishNotReady ||
		svc.LoadBalancerIngress[0] != "k8s-app-web-123.elb.us-east-1.amazonaws.com" {
		t.Errorf("service: %+v", svc)
	}
	if h := convertService(fixture[*corev1.Service](t, "web-headless")); h.Annotations != nil || h.LoadBalancerClass != "" || h.PublishNotReady {
		t.Errorf("headless: %+v", h)
	}
	ing := convertIngress(fixture[*networkingv1.Ingress](t, "web"))
	wantIng := map[string]string{
		"alb.ingress.kubernetes.io/scheme":             "internet-facing",
		"alb.ingress.kubernetes.io/certificate-arn":    "arn:aws:acm:us-east-1:123:certificate/abc",
		"alb.ingress.kubernetes.io/listen-ports":       `[{"HTTPS":443}]`,
		"kubernetes.io/ingress.class":                  "alb",
		"alb.ingress.kubernetes.io/group.name":         "shop",
		"alb.ingress.kubernetes.io/load-balancer-name": "shop-alb",
		"alb.ingress.kubernetes.io/security-groups":    "sg-0ccc",
	}
	if !reflect.DeepEqual(ing.Annotations, wantIng) || len(ing.Rules) != 2 || ing.Rules[1].Port != "8080" {
		t.Errorf("ingress: %+v", ing)
	}
}

func TestConvertNodePlacement(t *testing.T) {
	n := fixtureNodes()[0]
	got := convertNode(n, newNodeLabelFilter(nil))
	want := map[string]string{
		"topology.kubernetes.io/zone": "us-east-1a", "topology.kubernetes.io/region": "us-east-1",
		"node.kubernetes.io/instance-type": "m5.large", "kubernetes.io/arch": "amd64", "kubernetes.io/os": "linux",
		"eks.amazonaws.com/nodegroup": "general", "eks.amazonaws.com/capacityType": "ON_DEMAND", "karpenter.sh/capacity-type": "spot",
		"node-role.kubernetes.io/worker": "", "node-role.kubernetes.io/ingress": "",
	}
	if !reflect.DeepEqual(got.Labels, want) {
		t.Errorf("labels:\n got %v\nwant %v", got.Labels, want)
	}
	if got.ProviderID != "aws:///us-east-1a/i-0abc" || got.InternalIP != "192.168.1.1" || !reflect.DeepEqual(got.Roles, []string{"ingress", "worker"}) ||
		got.CPUAllocatableMilli != 1930 || got.PodsAllocatable != 29 || !got.Ready {
		t.Errorf("node: %+v", got)
	}
	for _, add := range [][]string{{"example.com/rack"}, {"example.com/*"}} {
		if got := convertNode(n, newNodeLabelFilter(add)); got.Labels["example.com/rack"] != "r12" {
			t.Errorf("-node-label-keys-add %v: %v", add, got.Labels)
		}
	}
}

// Namespaces keep kubesentry.io/* annotations (owner, routing hints) and an
// owner annotation configured outside kubesentry.io/, and nothing else.
func TestConvertNamespaceAnnotations(t *testing.T) {
	ns := fixture[*corev1.Namespace](t, "app")
	got := convertNamespace(ns, newNamespaceAnnotationFilter(nil))
	want := map[string]string{"kubesentry.io/owner": "team-payments", "kubesentry.io/slack-channel": "#payments"}
	if !reflect.DeepEqual(got.Annotations, want) || got.Labels["pod-security.kubernetes.io/enforce"] != "restricted" {
		t.Errorf("namespace: %+v", got)
	}
	got = convertNamespace(ns, newNamespaceAnnotationFilter([]string{"example.com/owner"}))
	if got.Annotations["example.com/owner"] != "payments@example.com" || len(got.Annotations) != 3 {
		t.Errorf("with -owner-annotation example.com/owner: %v", got.Annotations)
	}
	if got := convertNamespace(fixture[*corev1.Namespace](t, "kube-system"), newNamespaceAnnotationFilter(nil)); got.Annotations != nil {
		t.Errorf("kube-system annotations = %v, want none", got.Annotations)
	}
}

func TestConvertPVDriverAndClassParameters(t *testing.T) {
	cases := map[string]struct{ source, driver, handle string }{
		"pv-csi":      {"csi:ebs.csi.aws.com", "ebs.csi.aws.com", "vol-0abc"},
		"pv-intree":   {"awsElasticBlockStore", "kubernetes.io/aws-ebs", "vol-0intree"},
		"pv-hostpath": {"hostPath", "", ""},
	}
	for name, want := range cases {
		pv := convertPV(fixture[*corev1.PersistentVolume](t, name))
		if pv.Source != want.source || pv.Driver != want.driver || pv.VolumeHandle != want.handle {
			t.Errorf("%s: %+v", name, pv)
		}
	}
	if got := ebsVolumeID("vol-0plain"); got != "vol-0plain" {
		t.Errorf("plain volume ID: %s", got)
	}
	gp3 := convertStorageClass(fixture[*storagev1.StorageClass](t, "gp3"))
	if gp3.Parameters["type"] != "gp3" || gp3.PriceAnnotation != "0.08" || !gp3.Default || gp3.BindingMode != "WaitForFirstConsumer" || gp3.ReclaimPolicy != "Retain" {
		t.Errorf("gp3: %+v", gp3)
	}
	if efs := convertStorageClass(fixture[*storagev1.StorageClass](t, "efs")); efs.Default || efs.PriceAnnotation != "" || efs.Parameters != nil {
		t.Errorf("efs: %+v", efs)
	}
}

func TestConvertCertificateDurations(t *testing.T) {
	cert := certObjects()[0].(*unstructured.Unstructured)
	c := convertCertificate(cert)
	if c.Duration != 2160*time.Hour || c.RenewBefore != 360*time.Hour || len(c.Message) != maxMessage || c.IssuerKind != "ClusterIssuer" {
		t.Errorf("certificate: %+v", c)
	}
	_ = unstructured.SetNestedField(cert.Object, "90d", "spec", "duration") // not a Go duration
	unstructured.RemoveNestedField(cert.Object, "spec", "renewBefore")
	if c := convertCertificate(cert); c.Duration != 0 || c.RenewBefore != 0 {
		t.Errorf("malformed durations: %v %v", c.Duration, c.RenewBefore)
	}
}

func TestClusterInfo(t *testing.T) {
	aws := func(zone, region string) model.Node {
		return model.Node{ProviderID: "aws:///" + zone + "/i-1", Labels: map[string]string{regionLabel: region}}
	}
	kind := model.Node{ProviderID: "kind://docker/kind/kind-worker"}
	cases := []struct {
		name, version string
		nodes         []model.Node
		want          model.ClusterInfo
	}{
		{"eks by version", "v1.30.4-eks-a737599", []model.Node{kind},
			model.ClusterInfo{Name: "prod", Version: "v1.30.4-eks-a737599", Platform: "eks", Provider: "kind"}},
		{"eks by provider", "v1.31.0", []model.Node{aws("us-east-1a", "us-east-1"), aws("us-west-2a", "us-west-2"), aws("us-east-1b", "us-east-1"), kind},
			model.ClusterInfo{Name: "prod", Version: "v1.31.0", Platform: "eks", Provider: "aws", Region: "us-east-1"}},
		{"kind", "v1.33.1", []model.Node{kind, kind},
			model.ClusterInfo{Name: "prod", Version: "v1.33.1", Platform: "kind", Provider: "kind"}},
		{"gce", "v1.33.1-gke.100", []model.Node{{ProviderID: "gce://proj/us-central1-a/n1"}},
			model.ClusterInfo{Name: "prod", Version: "v1.33.1-gke.100", Platform: "gce", Provider: "gce"}},
		{"unknown", "", nil, model.ClusterInfo{Name: "prod", Platform: "kubernetes"}},
		{"region tie goes to the smaller name", "", []model.Node{{Labels: map[string]string{regionLabel: "b"}}, {Labels: map[string]string{regionLabel: "a"}}},
			model.ClusterInfo{Name: "prod", Platform: "kubernetes", Region: "a"}},
	}
	for _, c := range cases {
		if got := clusterInfo("prod", c.version, c.nodes); got != c.want {
			t.Errorf("%s:\n got %+v\nwant %+v", c.name, got, c.want)
		}
	}
}
