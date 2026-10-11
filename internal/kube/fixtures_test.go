package kube

import (
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// The fixtures carry everything a real API server sends that kubesentry
// does not read (managed fields, last-applied annotations, env, probes, node
// images, CSRs, ...) next to every field the conversions do read, so the
// transform tests can show the first is dropped and the second survives.

var (
	t0      = metav1.NewTime(time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC))
	t1      = metav1.NewTime(time.Date(2026, 10, 1, 8, 30, 0, 0, time.UTC))
	longMsg = strings.Repeat("0/3 nodes are available: 3 Insufficient memory. ", 20) // > maxMessage
)

func meta(ns, name, uid string) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Namespace: ns, Name: name, UID: types.UID(uid), ResourceVersion: "1", CreationTimestamp: t0,
		Generation: 3, GenerateName: name + "-",
		Labels: map[string]string{"app": name, "team": "payments"},
		Annotations: map[string]string{
			"kubectl.kubernetes.io/last-applied-configuration": `{"huge":"json"}`,
			"example.com/note": "dropped",
		},
		ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "kubectl", Operation: metav1.ManagedFieldsOperationApply, FieldsV1: &metav1.FieldsV1{Raw: []byte(`{"f:metadata":{}}`)}}},
		Finalizers:    []string{"example.com/finalizer"},
	}
}

func owner(kind, name, uid string, controller bool) metav1.OwnerReference {
	return metav1.OwnerReference{APIVersion: "apps/v1", Kind: kind, Name: name, UID: types.UID(uid), Controller: ptr(controller), BlockOwnerDeletion: ptr(true)}
}

func noisyContainer(name, image string) corev1.Container {
	return corev1.Container{
		Name: name, Image: image,
		Command: []string{"/bin/server"}, Args: []string{"--port=8080", "--verbose"},
		Env:        []corev1.EnvVar{{Name: "DB_PASSWORD", Value: "hunter2"}, {Name: "MODE", Value: "prod"}},
		EnvFrom:    []corev1.EnvFromSource{{ConfigMapRef: &corev1.ConfigMapEnvSource{LocalObjectReference: corev1.LocalObjectReference{Name: "cfg"}}}},
		Ports:      []corev1.ContainerPort{{Name: "http", ContainerPort: 8080}},
		WorkingDir: "/srv",
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("250m"), corev1.ResourceMemory: resource.MustParse("256Mi"), corev1.ResourceEphemeralStorage: resource.MustParse("1Gi")},
			Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("1"), corev1.ResourceMemory: resource.MustParse("512Mi")},
		},
		VolumeMounts:   []corev1.VolumeMount{{Name: "data", MountPath: "/data"}},
		LivenessProbe:  &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/healthz", Port: intstr.FromInt32(8080)}}},
		ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/ready", Port: intstr.FromInt32(8080)}}},
		StartupProbe:   &corev1.Probe{ProbeHandler: corev1.ProbeHandler{Exec: &corev1.ExecAction{Command: []string{"true"}}}},
		Lifecycle:      &corev1.Lifecycle{PreStop: &corev1.LifecycleHandler{Exec: &corev1.ExecAction{Command: []string{"sleep", "5"}}}},
		SecurityContext: &corev1.SecurityContext{
			RunAsNonRoot: ptr(true), RunAsUser: ptr(int64(1000)), ReadOnlyRootFilesystem: ptr(true), AllowPrivilegeEscalation: ptr(false),
			Capabilities: &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}, Add: []corev1.Capability{"NET_BIND_SERVICE"}},
		},
		TerminationMessagePath: "/dev/termination-log", ImagePullPolicy: corev1.PullIfNotPresent,
	}
}

func noisyPodSpec() corev1.PodSpec {
	always := corev1.ContainerRestartPolicyAlways
	sidecar := noisyContainer("proxy", "envoy:1.30")
	sidecar.RestartPolicy = &always
	return corev1.PodSpec{
		NodeName: "n1", ServiceAccountName: "web", AutomountServiceAccountToken: ptr(false),
		SecurityContext: &corev1.PodSecurityContext{RunAsNonRoot: ptr(true), RunAsUser: ptr(int64(1000)), FSGroup: ptr(int64(2000))},
		Containers:      []corev1.Container{noisyContainer("web", "registry.example.com/web:1.2.3")},
		InitContainers:  []corev1.Container{sidecar, noisyContainer("migrate", "registry.example.com/migrate:1.2.3")},
		Volumes: []corev1.Volume{
			{Name: "data", VolumeSource: corev1.VolumeSource{PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "data", ReadOnly: true}}},
			{Name: "scratch", VolumeSource: corev1.VolumeSource{Ephemeral: &corev1.EphemeralVolumeSource{VolumeClaimTemplate: &corev1.PersistentVolumeClaimTemplate{
				Spec: corev1.PersistentVolumeClaimSpec{StorageClassName: ptr("gp3")},
			}}}},
			{Name: "logs", VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/log"}}},
			{Name: "cfg", VolumeSource: corev1.VolumeSource{ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "cfg"}}}},
			{Name: "kube-api-access", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{Sources: []corev1.VolumeProjection{
				{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{Path: "token"}},
			}}}},
		},
		Affinity: &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
			NodeSelectorTerms: []corev1.NodeSelectorTerm{{MatchExpressions: []corev1.NodeSelectorRequirement{{Key: "kubernetes.io/arch", Operator: corev1.NodeSelectorOpIn, Values: []string{"amd64"}}}}},
		}}},
		Tolerations:               []corev1.Toleration{{Key: "dedicated", Operator: corev1.TolerationOpExists}},
		TopologySpreadConstraints: []corev1.TopologySpreadConstraint{{MaxSkew: 1, TopologyKey: "topology.kubernetes.io/zone"}},
		NodeSelector:              map[string]string{"kubernetes.io/os": "linux"},
		ImagePullSecrets:          []corev1.LocalObjectReference{{Name: "regcred"}},
	}
}

func fixturePods() []*corev1.Pod {
	web := &corev1.Pod{ObjectMeta: meta("app", "web-5d8f-abcde", "pod-web"), Spec: noisyPodSpec()}
	web.OwnerReferences = []metav1.OwnerReference{owner("ReplicaSet", "web-5d8f", "rs-web", true)}
	web.Status = corev1.PodStatus{
		Phase: corev1.PodRunning, PodIP: "10.0.1.15", PodIPs: []corev1.PodIP{{IP: "10.0.1.15"}}, HostIP: "192.168.1.10",
		QOSClass: corev1.PodQOSBurstable, StartTime: &t0,
		Conditions: []corev1.PodCondition{
			{Type: corev1.PodReady, Status: corev1.ConditionTrue, LastTransitionTime: t1},
			{Type: corev1.PodScheduled, Status: corev1.ConditionTrue, LastTransitionTime: t0},
			{Type: corev1.ContainersReady, Status: corev1.ConditionTrue, LastTransitionTime: t1},
			{Type: corev1.PodInitialized, Status: corev1.ConditionTrue, LastTransitionTime: t0},
		},
		ContainerStatuses: []corev1.ContainerStatus{{
			Name: "web", ContainerID: "containerd://abc123", Image: "registry.example.com/web:1.2.3", ImageID: "registry.example.com/web@sha256:" + strings.Repeat("f", 64),
			Ready: true, Started: ptr(true), RestartCount: 4,
			State:                corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: t1}},
			LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "OOMKilled", ExitCode: 137, FinishedAt: t1, StartedAt: t0, Message: "oom"}},
			Resources: &corev1.ResourceRequirements{
				Limits:   corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("768Mi"), corev1.ResourceCPU: resource.MustParse("1")},
				Requests: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("256Mi")},
			},
			AllocatedResources: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("256Mi")},
			VolumeMounts:       []corev1.VolumeMountStatus{{Name: "data", MountPath: "/data"}},
		}},
		InitContainerStatuses: []corev1.ContainerStatus{
			{Name: "proxy", ContainerID: "containerd://def456", Ready: true, Started: ptr(true), RestartCount: 1, ImageID: "envoy@sha256:abc",
				State: corev1.ContainerState{Running: &corev1.ContainerStateRunning{StartedAt: t0}}},
			{Name: "migrate", ContainerID: "containerd://789", Ready: false, Started: ptr(false), ImageID: "migrate@sha256:abc",
				State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "Completed", ExitCode: 0, FinishedAt: t0}}},
		},
	}

	pending := &corev1.Pod{ObjectMeta: meta("app", "pending-0", "pod-pending"), Spec: corev1.PodSpec{
		Containers: []corev1.Container{noisyContainer("app", "app:1")},
	}}
	pending.Status = corev1.PodStatus{
		Phase: corev1.PodPending, QOSClass: corev1.PodQOSBestEffort,
		Conditions: []corev1.PodCondition{{Type: corev1.PodScheduled, Status: corev1.ConditionFalse, Reason: corev1.PodReasonUnschedulable, Message: longMsg, LastTransitionTime: t1}},
	}

	crash := &corev1.Pod{ObjectMeta: meta("app", "crash-0", "pod-crash"), Spec: noisyPodSpec()}
	crash.OwnerReferences = []metav1.OwnerReference{owner("StatefulSet", "crash", "sts-crash", true)}
	crash.DeletionTimestamp = &t1
	crash.DeletionGracePeriodSeconds = ptr(int64(30))
	crash.Status = corev1.PodStatus{
		Phase: corev1.PodPending, PodIP: "10.0.2.7", QOSClass: corev1.PodQOSGuaranteed, Reason: "Evicted", Message: longMsg,
		Conditions: []corev1.PodCondition{
			{Type: corev1.PodReady, Status: corev1.ConditionFalse, Reason: "ContainersNotReady", LastTransitionTime: t0},
			{Type: corev1.PodScheduled, Status: corev1.ConditionTrue},
		},
		ContainerStatuses: []corev1.ContainerStatus{{
			Name: "web", State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "PodInitializing"}},
		}},
		InitContainerStatuses: []corev1.ContainerStatus{
			{Name: "proxy", State: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "Error", ExitCode: 1, Message: longMsg, FinishedAt: t1}}},
			{Name: "migrate", RestartCount: 7, State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff", Message: "back-off 5m0s restarting failed container=migrate " + longMsg}},
				LastTerminationState: corev1.ContainerState{Terminated: &corev1.ContainerStateTerminated{Reason: "Error", ExitCode: 2, FinishedAt: t1}}},
		},
	}
	return []*corev1.Pod{web, pending, crash}
}

func fixtureNodes() []*corev1.Node {
	node := func(name, uid, providerID, zone, region string) *corev1.Node {
		m := meta("", name, uid)
		m.Labels = map[string]string{
			"kubernetes.io/hostname": name, "kubernetes.io/arch": "amd64", "kubernetes.io/os": "linux",
			"node.kubernetes.io/instance-type": "m5.large", "eks.amazonaws.com/nodegroup": "general",
			"eks.amazonaws.com/capacityType": "ON_DEMAND", "karpenter.sh/capacity-type": "spot",
			"node-role.kubernetes.io/worker": "", "node-role.kubernetes.io/ingress": "", "example.com/rack": "r12",
		}
		if zone != "" {
			m.Labels["topology.kubernetes.io/zone"] = zone
		}
		if region != "" {
			m.Labels["topology.kubernetes.io/region"] = region
		}
		m.Annotations["csi.volume.kubernetes.io/nodeid"] = `{"ebs.csi.aws.com":"i-0abc"}`
		return &corev1.Node{
			ObjectMeta: m,
			Spec: corev1.NodeSpec{
				ProviderID: providerID, PodCIDR: "10.0.1.0/24", PodCIDRs: []string{"10.0.1.0/24"},
				Taints: []corev1.Taint{{Key: "dedicated", Value: "web", Effect: corev1.TaintEffectNoSchedule}},
			},
			Status: corev1.NodeStatus{
				Capacity: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("2"), corev1.ResourceMemory: resource.MustParse("8Gi")},
				Allocatable: corev1.ResourceList{
					corev1.ResourceCPU: resource.MustParse("1930m"), corev1.ResourceMemory: resource.MustParse("7Gi"),
					corev1.ResourcePods: resource.MustParse("29"), corev1.ResourceEphemeralStorage: resource.MustParse("18Gi"),
					"hugepages-2Mi": resource.MustParse("0"),
				},
				Conditions: []corev1.NodeCondition{
					{Type: corev1.NodeReady, Status: corev1.ConditionTrue, Reason: "KubeletReady", Message: "kubelet is posting ready status", LastTransitionTime: t0, LastHeartbeatTime: t1},
					{Type: corev1.NodeMemoryPressure, Status: corev1.ConditionFalse, Message: longMsg, LastTransitionTime: t0},
				},
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeHostName, Address: name + ".ec2.internal"},
					{Type: corev1.NodeInternalIP, Address: "192.168.1." + uid[len(uid)-1:]},
					{Type: corev1.NodeExternalIP, Address: "54.1.2.3"},
				},
				NodeInfo: corev1.NodeSystemInfo{
					KubeletVersion: "v1.33.4-eks-abc", OSImage: "Bottlerocket OS 1.20", ContainerRuntimeVersion: "containerd://1.7.20",
					MachineID: "ec2" + strings.Repeat("a", 29), SystemUUID: strings.Repeat("b", 36), BootID: strings.Repeat("c", 36),
					KernelVersion: "6.1.0", Architecture: "amd64", OperatingSystem: "linux",
				},
				Images:          []corev1.ContainerImage{{Names: []string{"registry.example.com/web@sha256:" + strings.Repeat("f", 64), "registry.example.com/web:1.2.3"}, SizeBytes: 123456789}},
				VolumesInUse:    []corev1.UniqueVolumeName{"kubernetes.io/csi/ebs.csi.aws.com^vol-0abc"},
				VolumesAttached: []corev1.AttachedVolume{{Name: "kubernetes.io/csi/ebs.csi.aws.com^vol-0abc", DevicePath: "/dev/xvdba"}},
			},
		}
	}
	return []*corev1.Node{
		node("n1", "node-1", "aws:///us-east-1a/i-0abc", "us-east-1a", "us-east-1"),
		node("n2", "node-2", "aws:///us-east-1b/i-0def", "us-east-1b", "us-east-1"),
		node("n3", "node-3", "kind://docker/kind/kind-worker", "", ""),
	}
}

func fixtureTemplate() corev1.PodTemplateSpec {
	return corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "web", "pod-template-hash": "5d8f"}, Annotations: map[string]string{"restarted-at": "now"}},
		Spec:       noisyPodSpec(),
	}
}

func fixtureObjects() []runtime.Object {
	var objs []runtime.Object
	for _, p := range fixturePods() {
		objs = append(objs, p)
	}
	for _, n := range fixtureNodes() {
		objs = append(objs, n)
	}
	nsApp := &corev1.Namespace{ObjectMeta: meta("", "app", "ns-app"), Spec: corev1.NamespaceSpec{Finalizers: []corev1.FinalizerName{"kubernetes"}},
		Status: corev1.NamespaceStatus{Phase: corev1.NamespaceActive}}
	nsApp.Labels["kubesentry.io/system"] = "false"
	nsApp.Labels["pod-security.kubernetes.io/enforce"] = "restricted"
	nsSys := &corev1.Namespace{ObjectMeta: meta("", "kube-system", "ns-sys"), Status: corev1.NamespaceStatus{Phase: corev1.NamespaceActive}}

	data := &corev1.PersistentVolumeClaim{ObjectMeta: meta("app", "data", "pvc-data"),
		Spec: corev1.PersistentVolumeClaimSpec{StorageClassName: ptr("gp3"), VolumeName: "pv-csi", AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			Resources: corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("10Gi")}}},
		Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimBound, Capacity: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("10Gi")},
			Conditions: []corev1.PersistentVolumeClaimCondition{{Type: corev1.PersistentVolumeClaimResizing, Status: corev1.ConditionFalse, Message: longMsg}}}}
	data.Annotations["pv.kubernetes.io/bind-completed"] = "yes"
	scratch := &corev1.PersistentVolumeClaim{ObjectMeta: meta("app", "web-5d8f-abcde-scratch", "pvc-scratch"),
		Spec: corev1.PersistentVolumeClaimSpec{StorageClassName: ptr("gp3")}, Status: corev1.PersistentVolumeClaimStatus{Phase: corev1.ClaimPending}}

	pvCSI := &corev1.PersistentVolume{ObjectMeta: meta("", "pv-csi", "pv-1"), Spec: corev1.PersistentVolumeSpec{
		StorageClassName: "gp3", PersistentVolumeReclaimPolicy: corev1.PersistentVolumeReclaimDelete,
		Capacity:    corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("10Gi")},
		AccessModes: []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
		ClaimRef:    &corev1.ObjectReference{Kind: "PersistentVolumeClaim", Namespace: "app", Name: "data", UID: "pvc-data", ResourceVersion: "77", APIVersion: "v1"},
		PersistentVolumeSource: corev1.PersistentVolumeSource{CSI: &corev1.CSIPersistentVolumeSource{
			Driver: "ebs.csi.aws.com", VolumeHandle: "vol-0abc", FSType: "ext4",
			VolumeAttributes: map[string]string{"storage.kubernetes.io/csiProvisionerIdentity": "1700000000000-1234-ebs.csi.aws.com"},
		}},
		NodeAffinity: &corev1.VolumeNodeAffinity{Required: &corev1.NodeSelector{NodeSelectorTerms: []corev1.NodeSelectorTerm{{
			MatchExpressions: []corev1.NodeSelectorRequirement{{Key: "topology.ebs.csi.aws.com/zone", Operator: corev1.NodeSelectorOpIn, Values: []string{"us-east-1a"}}},
		}}}},
		MountOptions: []string{"noatime"},
	}, Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeBound}}
	pvInTree := &corev1.PersistentVolume{ObjectMeta: meta("", "pv-intree", "pv-2"), Spec: corev1.PersistentVolumeSpec{
		StorageClassName: "gp2", PersistentVolumeReclaimPolicy: corev1.PersistentVolumeReclaimRetain,
		Capacity: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("100Gi")},
		PersistentVolumeSource: corev1.PersistentVolumeSource{AWSElasticBlockStore: &corev1.AWSElasticBlockStoreVolumeSource{
			VolumeID: "aws://us-east-1a/vol-0intree", FSType: "ext4",
		}},
	}, Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeReleased, Message: longMsg}}
	pvHost := &corev1.PersistentVolume{ObjectMeta: meta("", "pv-hostpath", "pv-3"), Spec: corev1.PersistentVolumeSpec{
		PersistentVolumeSource: corev1.PersistentVolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/mnt/data"}},
	}, Status: corev1.PersistentVolumeStatus{Phase: corev1.VolumeAvailable}}

	gp3 := &storagev1.StorageClass{ObjectMeta: meta("", "gp3", "sc-gp3"), Provisioner: "ebs.csi.aws.com",
		Parameters: map[string]string{"type": "gp3", "iops": "3000", "throughput": "125"}, ReclaimPolicy: ptr(corev1.PersistentVolumeReclaimRetain),
		VolumeBindingMode: ptr(storagev1.VolumeBindingWaitForFirstConsumer), AllowVolumeExpansion: ptr(true), MountOptions: []string{"noatime"},
		AllowedTopologies: []corev1.TopologySelectorTerm{{MatchLabelExpressions: []corev1.TopologySelectorLabelRequirement{{Key: "topology.kubernetes.io/zone", Values: []string{"us-east-1a"}}}}}}
	gp3.Annotations[defaultClassAnnotation] = "true"
	gp3.Annotations[PriceAnnotation] = "0.08"
	efs := &storagev1.StorageClass{ObjectMeta: meta("", "efs", "sc-efs"), Provisioner: "efs.csi.aws.com"}
	efs.Annotations[betaDefaultClassAnnotation] = "false"

	svc := &corev1.Service{ObjectMeta: meta("app", "web", "svc-web"), Spec: corev1.ServiceSpec{
		Type: corev1.ServiceTypeLoadBalancer, ClusterIP: "10.96.0.10", ClusterIPs: []string{"10.96.0.10"}, Selector: map[string]string{"app": "web"},
		Ports:             []corev1.ServicePort{{Name: "http", Protocol: corev1.ProtocolTCP, Port: 80, TargetPort: intstr.FromString("http"), NodePort: 30080}},
		LoadBalancerClass: ptr("service.k8s.aws/nlb"), LoadBalancerSourceRanges: []string{"10.0.0.0/8"}, PublishNotReadyAddresses: true,
		ExternalIPs: []string{"1.2.3.4"}, SessionAffinity: corev1.ServiceAffinityNone,
	}, Status: corev1.ServiceStatus{LoadBalancer: corev1.LoadBalancerStatus{Ingress: []corev1.LoadBalancerIngress{
		{Hostname: "k8s-app-web-123.elb.us-east-1.amazonaws.com", Ports: []corev1.PortStatus{{Port: 80, Protocol: corev1.ProtocolTCP}}},
	}}, Conditions: []metav1.Condition{{Type: "LoadBalancerReady", Status: metav1.ConditionTrue, Message: longMsg}}}}
	svc.Annotations["service.beta.kubernetes.io/aws-load-balancer-scheme"] = "internal"
	svc.Annotations["service.beta.kubernetes.io/aws-load-balancer-type"] = "external"
	svc.Annotations["service.beta.kubernetes.io/aws-load-balancer-nlb-target-type"] = "ip"
	headless := &corev1.Service{ObjectMeta: meta("app", "web-headless", "svc-headless"), Spec: corev1.ServiceSpec{
		Type: corev1.ServiceTypeClusterIP, ClusterIP: corev1.ClusterIPNone, Selector: map[string]string{"app": "web"},
	}}

	slice := &discoveryv1.EndpointSlice{ObjectMeta: meta("app", "web-xyz12", "eps-web"), AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{"10.0.1.15"}, NodeName: ptr("n1"), Zone: ptr("us-east-1a"), Hostname: ptr("web-0"),
				TargetRef: &corev1.ObjectReference{Kind: "Pod", Namespace: "app", Name: "web-5d8f-abcde", UID: "pod-web", ResourceVersion: "99"},
				Hints:     &discoveryv1.EndpointHints{ForZones: []discoveryv1.ForZone{{Name: "us-east-1a"}}}},
			{Addresses: []string{"10.0.2.7"}, NodeName: ptr("n2"),
				Conditions: discoveryv1.EndpointConditions{Ready: ptr(false), Serving: ptr(false), Terminating: ptr(false)},
				TargetRef:  &corev1.ObjectReference{Kind: "Pod", Namespace: "app", Name: "crash-0", UID: "pod-crash"}},
			{Addresses: []string{"10.0.3.9"},
				Conditions: discoveryv1.EndpointConditions{Ready: ptr(false), Serving: ptr(true), Terminating: ptr(true)}},
		},
		Ports: []discoveryv1.EndpointPort{{Name: ptr("http"), Port: ptr(int32(8080))}},
	}
	slice.Labels[discoveryv1.LabelServiceName] = "web"
	slice.Labels[discoveryv1.LabelManagedBy] = "endpointslice-controller.k8s.io"
	slice.OwnerReferences = []metav1.OwnerReference{{APIVersion: "v1", Kind: "Service", Name: "web", UID: "svc-web", Controller: ptr(true)}}
	slice.Annotations["endpoints.kubernetes.io/last-change-trigger-time"] = t1.Format(time.RFC3339)

	ing := &networkingv1.Ingress{ObjectMeta: meta("app", "web", "ing-web"), Spec: networkingv1.IngressSpec{
		IngressClassName: ptr("alb"),
		DefaultBackend:   &networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "web", Port: networkingv1.ServiceBackendPort{Number: 80}}},
		Rules: []networkingv1.IngressRule{{Host: "web.example.com", IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{
			Paths: []networkingv1.HTTPIngressPath{
				{Path: "/", Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "web", Port: networkingv1.ServiceBackendPort{Name: "http"}}}},
				{Path: "/api", Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: "api", Port: networkingv1.ServiceBackendPort{Number: 8080}}}},
			},
		}}}},
		TLS: []networkingv1.IngressTLS{{Hosts: []string{"web.example.com"}, SecretName: "web-tls"}},
	}, Status: networkingv1.IngressStatus{LoadBalancer: networkingv1.IngressLoadBalancerStatus{Ingress: []networkingv1.IngressLoadBalancerIngress{{Hostname: "alb.example.com"}}}}}
	ing.Annotations["alb.ingress.kubernetes.io/scheme"] = "internet-facing"
	ing.Annotations["alb.ingress.kubernetes.io/certificate-arn"] = "arn:aws:acm:us-east-1:123:certificate/abc"
	ing.Annotations["alb.ingress.kubernetes.io/listen-ports"] = `[{"HTTPS":443}]`
	ing.Annotations["kubernetes.io/ingress.class"] = "alb"

	dep := &appsv1.Deployment{ObjectMeta: meta("app", "web", "dep-web"), Spec: appsv1.DeploymentSpec{
		Replicas: ptr(int32(3)), Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"},
			MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "tier", Operator: metav1.LabelSelectorOpIn, Values: []string{"front"}}}},
		Template: fixtureTemplate(), Paused: true,
	}, Status: appsv1.DeploymentStatus{ReadyReplicas: 2, UpdatedReplicas: 3, AvailableReplicas: 2, Replicas: 3,
		Conditions: []appsv1.DeploymentCondition{{Type: appsv1.DeploymentProgressing, Status: corev1.ConditionTrue, Reason: "NewReplicaSetAvailable", Message: longMsg, LastTransitionTime: t1, LastUpdateTime: t1}}}}
	dep.Annotations["deployment.kubernetes.io/revision"] = "7"
	rs := &appsv1.ReplicaSet{ObjectMeta: meta("app", "web-5d8f", "rs-web"), Spec: appsv1.ReplicaSetSpec{
		Replicas: ptr(int32(3)), Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "web", "pod-template-hash": "5d8f"}}, Template: fixtureTemplate(),
	}, Status: appsv1.ReplicaSetStatus{Replicas: 3, ReadyReplicas: 2,
		Conditions: []appsv1.ReplicaSetCondition{{Type: appsv1.ReplicaSetReplicaFailure, Status: corev1.ConditionTrue, Message: longMsg}}}}
	rs.OwnerReferences = []metav1.OwnerReference{owner("Deployment", "web", "dep-web", true)}
	orphanRS := &appsv1.ReplicaSet{ObjectMeta: meta("app", "orphan-1", "rs-orphan"), Spec: appsv1.ReplicaSetSpec{Template: fixtureTemplate()}}
	sts := &appsv1.StatefulSet{ObjectMeta: meta("app", "crash", "sts-crash"), Spec: appsv1.StatefulSetSpec{
		Replicas: ptr(int32(1)), Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "crash"}}, Template: fixtureTemplate(),
		VolumeClaimTemplates: []corev1.PersistentVolumeClaim{{ObjectMeta: metav1.ObjectMeta{Name: "data"}}},
	}, Status: appsv1.StatefulSetStatus{ReadyReplicas: 0, UpdatedReplicas: 1,
		Conditions: []appsv1.StatefulSetCondition{{Type: "Odd", Status: corev1.ConditionFalse, Message: longMsg}}}}
	ds := &appsv1.DaemonSet{ObjectMeta: meta("kube-system", "agent", "ds-agent"), Spec: appsv1.DaemonSetSpec{
		Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "agent"}}, Template: fixtureTemplate(),
	}, Status: appsv1.DaemonSetStatus{DesiredNumberScheduled: 3, NumberReady: 3, UpdatedNumberScheduled: 3, NumberAvailable: 3}}
	job := &batchv1.Job{ObjectMeta: meta("app", "backup-29000", "job-backup"), Spec: batchv1.JobSpec{
		Completions: ptr(int32(2)), Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"batch.kubernetes.io/controller-uid": "job-backup"}},
		Template: fixtureTemplate(),
	}, Status: batchv1.JobStatus{Succeeded: 1, Failed: 2, Active: 1, Ready: ptr(int32(1)),
		Conditions:              []batchv1.JobCondition{{Type: batchv1.JobFailed, Status: corev1.ConditionTrue, Message: longMsg, LastTransitionTime: t1}},
		UncountedTerminatedPods: &batchv1.UncountedTerminatedPods{Succeeded: []types.UID{"x"}}}}
	job.OwnerReferences = []metav1.OwnerReference{owner("CronJob", "backup", "cj-backup", true)}
	cj := &batchv1.CronJob{ObjectMeta: meta("app", "backup", "cj-backup"), Spec: batchv1.CronJobSpec{
		Schedule: "0 * * * *", Suspend: ptr(true),
		JobTemplate: batchv1.JobTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"x": "y"}}, Spec: batchv1.JobSpec{Template: fixtureTemplate()}},
	}, Status: batchv1.CronJobStatus{
		Active:           []corev1.ObjectReference{{Kind: "Job", Namespace: "app", Name: "backup-29000", UID: "job-backup", APIVersion: "batch/v1", ResourceVersion: "5"}},
		LastScheduleTime: &t0, LastSuccessfulTime: &t1,
	}}

	role := &rbacv1.Role{ObjectMeta: meta("app", "reader", "role-reader"), Rules: []rbacv1.PolicyRule{{Verbs: []string{"get", "list"}, APIGroups: []string{""}, Resources: []string{"pods"}}}}
	crole := &rbacv1.ClusterRole{ObjectMeta: meta("", "admin-agg", "cr-admin"),
		Rules:           []rbacv1.PolicyRule{{Verbs: []string{"*"}, APIGroups: []string{"*"}, Resources: []string{"*"}}, {Verbs: []string{"get"}, NonResourceURLs: []string{"/healthz"}}},
		AggregationRule: &rbacv1.AggregationRule{ClusterRoleSelectors: []metav1.LabelSelector{{MatchLabels: map[string]string{"aggregate": "true"}}}}}
	empty := &rbacv1.ClusterRole{ObjectMeta: meta("", "empty", "cr-empty")}
	rb := &rbacv1.RoleBinding{ObjectMeta: meta("app", "read", "rb-read"), RoleRef: rbacv1.RoleRef{Kind: "Role", Name: "reader"},
		Subjects: []rbacv1.Subject{{Kind: "Group", Name: "devs"}, {Kind: "ServiceAccount", Name: "ci", Namespace: "app"}}}
	crb := &rbacv1.ClusterRoleBinding{ObjectMeta: meta("", "erin-admin", "crb-erin"), RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
		Subjects: []rbacv1.Subject{{Kind: "User", Name: "erin"}}}

	awsAuth := &corev1.ConfigMap{ObjectMeta: meta(awsAuthNamespace, awsAuthName, "cm-aws-auth"), Data: map[string]string{
		"mapRoles": `- rolearn: arn:aws:iam::123:role/nodes
  username: system:node:{{EC2PrivateDNSName}}
  groups: [system:bootstrappers, system:nodes]
- rolearn: arn:aws:iam::123:role/admins
  username: admin
  groups:
    - system:masters
`,
		"mapUsers":    "- userarn: arn:aws:iam::123:user/erin\n  username: erin\n  groups: [devs]\n",
		"mapAccounts": "- \"123\"\n",
	}}
	otherCM := &corev1.ConfigMap{ObjectMeta: meta(awsAuthNamespace, "coredns", "cm-coredns"), Data: map[string]string{"Corefile": ".:53 {}"}}

	return append(objs, nsApp, nsSys, data, scratch, pvCSI, pvInTree, pvHost, gp3, efs, svc, headless, slice, ing,
		dep, rs, orphanRS, sts, ds, job, cj, role, crole, empty, rb, crb, awsAuth, otherCM)
}

func certObjects() []runtime.Object {
	cert := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "cert-manager.io/v1", "kind": "Certificate",
		"metadata": map[string]any{
			"namespace": "app", "name": "web-tls", "uid": "cert-web", "resourceVersion": "1", "creationTimestamp": t0.UTC().Format(time.RFC3339),
			"annotations":   map[string]any{"kubectl.kubernetes.io/last-applied-configuration": "{}"},
			"managedFields": []any{map[string]any{"manager": "kubectl", "operation": "Apply"}},
		},
		"spec": map[string]any{
			"secretName": "web-tls", "commonName": "web.example.com", "dnsNames": []any{"web.example.com", "www.example.com"},
			"duration": "2160h0m0s", "renewBefore": "360h", "issuerRef": map[string]any{"name": "letsencrypt", "kind": "ClusterIssuer"},
			"privateKey": map[string]any{"algorithm": "ECDSA"},
		},
		"status": map[string]any{
			"notBefore": "2026-09-01T00:00:00Z", "notAfter": "2026-11-30T00:00:00Z", "renewalTime": "2026-11-15T00:00:00Z",
			"conditions": []any{map[string]any{"type": "Ready", "status": "True", "reason": "Ready", "message": longMsg}},
		},
	}}
	issuer := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "cert-manager.io/v1", "kind": "Issuer",
		"metadata": map[string]any{"namespace": "app", "name": "selfsigned", "uid": "iss-self", "resourceVersion": "1"},
		"spec":     map[string]any{"selfSigned": map[string]any{}},
		"status":   map[string]any{"conditions": []any{map[string]any{"type": "Ready", "status": "True"}}},
	}}
	clusterIssuer := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "cert-manager.io/v1", "kind": "ClusterIssuer",
		"metadata": map[string]any{"name": "letsencrypt", "uid": "ciss-le", "resourceVersion": "1"},
		"spec": map[string]any{"acme": map[string]any{
			"server": "https://acme-v02.api.letsencrypt.org/directory", "email": "ops@example.com",
			"privateKeySecretRef": map[string]any{"name": "le-key"},
			"solvers":             []any{map[string]any{"http01": map[string]any{"ingress": map[string]any{"class": "alb"}}}},
		}},
		"status": map[string]any{"conditions": []any{map[string]any{"type": "Ready", "status": "False", "message": "acme account not registered"}}},
	}}
	request := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "cert-manager.io/v1", "kind": "CertificateRequest",
		"metadata": map[string]any{
			"namespace": "app", "name": "web-tls-1", "uid": "cr-web", "resourceVersion": "1",
			"annotations": map[string]any{certificateNameAnnotation: "web-tls", "cert-manager.io/private-key-secret-name": "web-tls-xyz"},
		},
		"spec": map[string]any{"request": strings.Repeat("Q1NS", 400), "issuerRef": map[string]any{"name": "letsencrypt", "kind": "ClusterIssuer"}},
		"status": map[string]any{
			"certificate": strings.Repeat("Q0VSVA", 600), "ca": strings.Repeat("Q0E", 300),
			"conditions": []any{
				map[string]any{"type": "Approved", "status": "True"},
				map[string]any{"type": "Ready", "status": "True", "reason": "Issued"},
			},
		},
	}}
	return []runtime.Object{cert, issuer, clusterIssuer, request}
}

// certListKinds registers the cert-manager list kinds with the dynamic fake.
var certListKinds = map[schema.GroupVersionResource]string{
	certGVR("certificates"):        "CertificateList",
	certGVR("issuers"):             "IssuerList",
	certGVR("clusterissuers"):      "ClusterIssuerList",
	certGVR("certificaterequests"): "CertificateRequestList",
}
