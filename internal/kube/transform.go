package kube

import (
	"strings"
	"unicode/utf8"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/tools/cache"
)

// The informer cache keeps only what the conversions read. Each transform
// below is idempotent (informers may hand an object through twice) and keeps
// convert(transform(obj)) == convert(obj); transform_test.go checks both over
// the shared fixtures. Anything a new model field needs must be kept here too.

// maxMessage caps condition and container state messages. Termination
// messages can be 4 KiB and event-like condition messages grow unbounded.
const maxMessage = 512

// truncate cuts s to maxMessage bytes without splitting a UTF-8 sequence.
func truncate(s string) string { return truncateTo(s, maxMessage) }

// truncateTo cuts s to at most n bytes without splitting a UTF-8 sequence.
func truncateTo(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// Annotation keys kubesentry reads, besides the per-type allowlists below.
const (
	defaultClassAnnotation     = "storageclass.kubernetes.io/is-default-class"
	betaDefaultClassAnnotation = "storageclass.beta.kubernetes.io/is-default-class"
	// PriceAnnotation on a StorageClass overrides the storage price, in USD per GiB-month.
	PriceAnnotation = "kubesentry.io/price-per-gib-month"
	// PrometheusAnnotation set to "true" on a Service marks the Prometheus to discover.
	PrometheusAnnotation      = "kubesentry.io/prometheus"
	certificateNameAnnotation = "cert-manager.io/certificate-name"
	// revisionAnnotation numbers a Deployment's rollouts; each ReplicaSet
	// carries the revision it was created for.
	revisionAnnotation = "deployment.kubernetes.io/revision"
	// daemonSetGenerationAnnotation counts a DaemonSet's pod template
	// changes (the API server keeps spec.templateGeneration here in apps/v1).
	daemonSetGenerationAnnotation = appsv1.DeprecatedTemplateGeneration
	// namespaceAnnotationPrefix: every kubesentry.io/* annotation on a
	// namespace is kept: the owner (kubesentry.io/owner) and the routing hints
	// alerting reads (kubesentry.io/slack-channel, ...).
	namespaceAnnotationPrefix = "kubesentry.io/"
)

// Labels, names and keys kubesentry reads.
const (
	serviceNameLabel         = discoveryv1.LabelServiceName // kubernetes.io/service-name
	managedByLabel           = discoveryv1.LabelManagedBy   // endpointslice.kubernetes.io/managed-by
	nodeRolePrefix           = "node-role.kubernetes.io/"
	regionLabel              = "topology.kubernetes.io/region"
	awsAuthNamespace         = "kube-system"
	awsAuthName              = "aws-auth"
	mapRolesKey, mapUsersKey = "mapRoles", "mapUsers"
)

func keySet(keys ...string) map[string]bool {
	m := make(map[string]bool, len(keys))
	for _, k := range keys {
		m[k] = true
	}
	return m
}

var (
	serviceAnnotations = keySet(
		"service.beta.kubernetes.io/aws-load-balancer-scheme",
		"service.beta.kubernetes.io/aws-load-balancer-internal",
		"service.beta.kubernetes.io/aws-load-balancer-type",
		"service.beta.kubernetes.io/aws-load-balancer-nlb-target-type",
		// Security groups tie CloudTrail changes to the Service's NLB.
		"service.beta.kubernetes.io/aws-load-balancer-security-groups",
		"service.beta.kubernetes.io/aws-load-balancer-extra-security-groups",
		"service.beta.kubernetes.io/aws-load-balancer-name",
		PrometheusAnnotation,
	)
	ingressAnnotations = keySet(
		"alb.ingress.kubernetes.io/scheme",
		"alb.ingress.kubernetes.io/certificate-arn",
		"alb.ingress.kubernetes.io/listen-ports",
		"alb.ingress.kubernetes.io/ssl-redirect",
		"kubernetes.io/ingress.class",
		// The ALB's name and security groups tie CloudTrail changes to the
		// Ingress (incidents' related-resource index).
		"alb.ingress.kubernetes.io/group.name",
		"alb.ingress.kubernetes.io/load-balancer-name",
		"alb.ingress.kubernetes.io/security-groups",
	)
	revisionAnnotations     = keySet(revisionAnnotation)
	daemonSetAnnotations    = keySet(daemonSetGenerationAnnotation)
	storageClassAnnotations = keySet(defaultClassAnnotation, betaDefaultClassAnnotation, PriceAnnotation)
	certAnnotations         = keySet(certificateNameAnnotation)
	endpointSliceLabels     = keySet(serviceNameLabel, managedByLabel)
)

// DefaultNodeLabelKeys are the node labels kept: placement (zone, region,
// instance type, arch, os), EKS node groups and Fargate, Karpenter pools and
// capacity types. node-role.kubernetes.io/* is always kept as well.
var DefaultNodeLabelKeys = []string{
	"topology.kubernetes.io/zone",
	regionLabel,
	"node.kubernetes.io/instance-type",
	"kubernetes.io/arch",
	"kubernetes.io/os",
	"eks.amazonaws.com/nodegroup",
	"eks.amazonaws.com/capacityType",
	"eks.amazonaws.com/compute-type",
	"karpenter.sh/nodepool",
	"karpenter.sh/capacity-type",
	"karpenter.k8s.aws/instance-family",
}

// DefaultAppLabelKeys are the workload labels kept: the app and service tags
// incidents correlate on.
var DefaultAppLabelKeys = []string{
	"app.kubernetes.io/name",
	"app.kubernetes.io/instance",
	"app.kubernetes.io/part-of",
	"app.kubernetes.io/component",
	"app",
	"k8s-app",
}

// labelFilter keeps an allowlist of label keys. A key ending in "*" matches
// by prefix.
type labelFilter struct {
	exact    map[string]bool
	prefixes []string
}

// add allows more keys; "prefix*" matches by prefix, blanks are ignored.
func (f *labelFilter) add(keys []string) {
	for _, k := range keys {
		k = strings.TrimSpace(k)
		switch {
		case k == "":
		case strings.HasSuffix(k, "*"):
			f.prefixes = append(f.prefixes, strings.TrimSuffix(k, "*"))
		default:
			f.exact[k] = true
		}
	}
}

// newNodeLabelFilter keeps DefaultNodeLabelKeys, node-role.kubernetes.io/*
// and the extra keys (from -node-label-keys-add).
func newNodeLabelFilter(add []string) labelFilter {
	f := labelFilter{exact: keySet(DefaultNodeLabelKeys...), prefixes: []string{nodeRolePrefix}}
	f.add(add)
	return f
}

// newNamespaceAnnotationFilter keeps kubesentry.io/* annotations and the
// extra keys (the owner annotation, when -owner-annotation names one outside
// kubesentry.io/; "prefix*" matches by prefix).
func newNamespaceAnnotationFilter(add []string) labelFilter {
	f := labelFilter{exact: map[string]bool{}, prefixes: []string{namespaceAnnotationPrefix}}
	f.add(add)
	return f
}

// newAppLabelFilter keeps DefaultAppLabelKeys and the extra keys (the custom
// tag from -incident-app-label; "prefix*" matches by prefix).
func newAppLabelFilter(add []string) labelFilter {
	f := labelFilter{exact: keySet(DefaultAppLabelKeys...)}
	f.add(add)
	return f
}

// filters are the configurable allowlists the transform and the conversions
// apply: node labels, namespace annotations, workload (app tag) labels, and
// the owner annotation objects may carry.
type filters struct {
	nodeLabels    labelFilter
	nsAnnotations labelFilter
	appLabels     labelFilter
	// owner is the owner annotation key (-owner-annotation); "" keeps none.
	owner string
	allow annotationAllow
}

// annotationAllow are the per-kind annotation allowlists, with the owner
// annotation added where an object may name its own owner: workloads,
// Services, Ingresses, cert-manager Certificates and RBAC objects. Pods and
// everything else keep no owner annotation.
type annotationAllow struct {
	workload, deployment, daemonSet, service, ingress, rbac, certificate map[string]bool
}

func newFilters(nodeLabelKeysAdd, namespaceAnnotationKeysAdd, appLabelKeys []string) filters {
	f := filters{
		nodeLabels:    newNodeLabelFilter(nodeLabelKeysAdd),
		nsAnnotations: newNamespaceAnnotationFilter(namespaceAnnotationKeysAdd),
		appLabels:     newAppLabelFilter(appLabelKeys),
	}
	return f.withOwner("")
}

// withOwner returns f keeping the owner annotation key on the kinds that
// may name their own owner ("" keeps it nowhere).
func (f filters) withOwner(key string) filters {
	key = strings.TrimSpace(key)
	plus := func(base map[string]bool) map[string]bool {
		if key == "" {
			return base
		}
		m := make(map[string]bool, len(base)+1)
		for k := range base {
			m[k] = true
		}
		m[key] = true
		return m
	}
	f.owner = key
	f.allow = annotationAllow{
		workload: plus(nil), deployment: plus(revisionAnnotations), daemonSet: plus(daemonSetAnnotations),
		service: plus(serviceAnnotations), ingress: plus(ingressAnnotations), rbac: plus(nil), certificate: plus(certAnnotations),
	}
	return f
}

// ownerOf reads the owner annotation key from ann, trimmed; "" without one.
func ownerOf(ann map[string]string, key string) string {
	if key == "" {
		return ""
	}
	return strings.TrimSpace(ann[key])
}

func (f labelFilter) keep(k string) bool {
	if f.exact[k] {
		return true
	}
	for _, p := range f.prefixes {
		if strings.HasPrefix(k, p) {
			return true
		}
	}
	return false
}

// filter returns the kept entries, nil when none are kept.
func (f labelFilter) filter(m map[string]string) map[string]string {
	var out map[string]string
	for k, v := range m {
		if f.keep(k) {
			if out == nil {
				out = make(map[string]string)
			}
			out[k] = v
		}
	}
	return out
}

// filterKeys returns the entries of m whose key is in allow, nil when none.
func filterKeys(m map[string]string, allow map[string]bool) map[string]string {
	var out map[string]string
	for k, v := range m {
		if allow[k] {
			if out == nil {
				out = make(map[string]string, len(allow))
			}
			out[k] = v
		}
	}
	return out
}

// newTransform returns the informer transform for every resource the Cache
// watches (typed, aws-auth, cert-manager and TargetGroupBindings). Unknown
// types pass through untouched.
func newTransform(f filters) cache.TransformFunc {
	return func(obj any) (any, error) {
		transformObject(obj, f)
		return obj, nil
	}
}

// transformObject strips obj in place.
func transformObject(obj any, f filters) {
	switch o := obj.(type) {
	case *corev1.Pod:
		transformPod(o)
	case *corev1.Node:
		transformNode(o, f.nodeLabels)
	case *corev1.PersistentVolumeClaim:
		transformPVC(o)
	case *corev1.PersistentVolume:
		transformPV(o)
	case *storagev1.StorageClass:
		stripMeta(&o.ObjectMeta, storageClassAnnotations)
		o.MountOptions, o.AllowedTopologies = nil, nil
	case *corev1.Namespace:
		ann := f.nsAnnotations.filter(o.Annotations)
		stripMeta(&o.ObjectMeta, nil)
		o.Annotations = ann
		o.Spec = corev1.NamespaceSpec{}
		o.Status.Conditions = nil
	case *corev1.Service:
		transformService(o, f.allow.service)
	case *discoveryv1.EndpointSlice:
		transformEndpointSlice(o)
	case *networkingv1.Ingress:
		stripMeta(&o.ObjectMeta, f.allow.ingress)
		o.Status = networkingv1.IngressStatus{}
	case *appsv1.Deployment:
		stripWorkloadMeta(&o.ObjectMeta, f.allow.deployment, f.appLabels)
		trimTemplate(&o.Spec.Template)
		trimMessages(o.Status.Conditions, func(c *appsv1.DeploymentCondition) *string { return &c.Message })
	case *appsv1.ReplicaSet:
		stripMeta(&o.ObjectMeta, revisionAnnotations)
		trimTemplate(&o.Spec.Template)
		trimMessages(o.Status.Conditions, func(c *appsv1.ReplicaSetCondition) *string { return &c.Message })
	case *appsv1.StatefulSet:
		stripWorkloadMeta(&o.ObjectMeta, f.allow.workload, f.appLabels)
		trimTemplate(&o.Spec.Template)
		o.Spec.VolumeClaimTemplates = nil
		trimMessages(o.Status.Conditions, func(c *appsv1.StatefulSetCondition) *string { return &c.Message })
	case *appsv1.DaemonSet:
		stripWorkloadMeta(&o.ObjectMeta, f.allow.daemonSet, f.appLabels)
		trimTemplate(&o.Spec.Template)
		trimMessages(o.Status.Conditions, func(c *appsv1.DaemonSetCondition) *string { return &c.Message })
	case *batchv1.Job:
		stripWorkloadMeta(&o.ObjectMeta, f.allow.workload, f.appLabels)
		trimTemplate(&o.Spec.Template)
		o.Spec.PodFailurePolicy, o.Spec.SuccessPolicy = nil, nil
		o.Status.UncountedTerminatedPods = nil
		trimMessages(o.Status.Conditions, func(c *batchv1.JobCondition) *string { return &c.Message })
	case *batchv1.CronJob:
		stripWorkloadMeta(&o.ObjectMeta, f.allow.workload, f.appLabels)
		o.Spec.JobTemplate.ObjectMeta = metav1.ObjectMeta{}
		trimTemplate(&o.Spec.JobTemplate.Spec.Template)
		o.Spec.JobTemplate.Spec.PodFailurePolicy, o.Spec.JobTemplate.Spec.SuccessPolicy = nil, nil
		for i := range o.Status.Active {
			a := &o.Status.Active[i]
			*a = corev1.ObjectReference{Kind: a.Kind, Namespace: a.Namespace, Name: a.Name, UID: a.UID}
		}
	case *rbacv1.Role:
		stripMeta(&o.ObjectMeta, f.allow.rbac)
	case *rbacv1.ClusterRole:
		stripMeta(&o.ObjectMeta, f.allow.rbac)
		o.AggregationRule = nil // the rules are already aggregated
	case *rbacv1.RoleBinding:
		stripMeta(&o.ObjectMeta, f.allow.rbac)
	case *rbacv1.ClusterRoleBinding:
		stripMeta(&o.ObjectMeta, f.allow.rbac)
	case *corev1.ServiceAccount:
		transformServiceAccount(o)
	case *corev1.ConfigMap:
		transformConfigMap(o)
	case *unstructured.Unstructured:
		switch {
		case isTargetGroupBinding(o):
			transformTargetGroupBinding(o)
		case o.GetKind() == "Certificate":
			transformCertManager(o, f.allow.certificate)
		default:
			transformCertManager(o, certAnnotations)
		}
	}
}

// stripMeta drops managed fields, annotations outside allow, and the parts of
// ownerReferences and metadata nothing reads.
func stripMeta(m *metav1.ObjectMeta, allow map[string]bool) {
	m.ManagedFields = nil
	m.Annotations = filterKeys(m.Annotations, allow)
	m.GenerateName = ""
	m.Finalizers = nil
	m.DeletionGracePeriodSeconds = nil
	for i := range m.OwnerReferences {
		r := &m.OwnerReferences[i]
		*r = metav1.OwnerReference{Kind: r.Kind, Name: r.Name, UID: r.UID, Controller: r.Controller}
	}
}

// stripWorkloadMeta is stripMeta for workloads, which keep only the app tag
// labels (Workload.Labels).
func stripWorkloadMeta(m *metav1.ObjectMeta, allow map[string]bool, apps labelFilter) {
	stripMeta(m, allow)
	m.Labels = apps.filter(m.Labels)
}

// trimMessages truncates each condition's message in place.
func trimMessages[C any](conds []C, msg func(*C) *string) {
	for i := range conds {
		p := msg(&conds[i])
		*p = truncate(*p)
	}
}

// trimTemplate keeps only container names and images of a pod template.
func trimTemplate(t *corev1.PodTemplateSpec) {
	*t = corev1.PodTemplateSpec{Spec: corev1.PodSpec{
		Containers:     namesAndImages(t.Spec.Containers),
		InitContainers: namesAndImages(t.Spec.InitContainers),
	}}
}

func namesAndImages(cs []corev1.Container) []corev1.Container {
	if len(cs) == 0 {
		return nil
	}
	out := make([]corev1.Container, len(cs))
	for i, c := range cs {
		out[i] = corev1.Container{Name: c.Name, Image: c.Image}
	}
	return out
}

// transformPod rebuilds the spec and status from the fields convertPod reads.
// Pods dominate memory, so this is an allowlist rather than a denylist: a
// field added to the API later is dropped until something needs it.
func transformPod(p *corev1.Pod) {
	stripMeta(&p.ObjectMeta, nil)
	s := &p.Spec
	spec := corev1.PodSpec{
		NodeName:                     s.NodeName,
		ServiceAccountName:           s.ServiceAccountName,
		HostPID:                      s.HostPID,
		HostNetwork:                  s.HostNetwork,
		HostIPC:                      s.HostIPC,
		AutomountServiceAccountToken: s.AutomountServiceAccountToken,
		Containers:                   trimContainers(s.Containers),
		InitContainers:               trimContainers(s.InitContainers),
	}
	if sc := s.SecurityContext; sc != nil && (sc.RunAsNonRoot != nil || sc.RunAsUser != nil) {
		spec.SecurityContext = &corev1.PodSecurityContext{RunAsNonRoot: sc.RunAsNonRoot, RunAsUser: sc.RunAsUser}
	}
	for _, v := range s.Volumes {
		switch {
		case v.PersistentVolumeClaim != nil:
			spec.Volumes = append(spec.Volumes, corev1.Volume{Name: v.Name, VolumeSource: corev1.VolumeSource{
				PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: v.PersistentVolumeClaim.ClaimName},
			}})
		case v.Ephemeral != nil:
			// Only the volume name matters: the claim is named <pod>-<volume>.
			spec.Volumes = append(spec.Volumes, corev1.Volume{Name: v.Name, VolumeSource: corev1.VolumeSource{Ephemeral: &corev1.EphemeralVolumeSource{}}})
		case v.HostPath != nil:
			spec.Volumes = append(spec.Volumes, corev1.Volume{Name: v.Name, VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{Path: v.HostPath.Path},
			}})
		}
	}
	p.Spec = spec

	st := &p.Status
	status := corev1.PodStatus{
		Phase:                 st.Phase,
		Reason:                st.Reason,
		Message:               truncate(st.Message),
		PodIP:                 st.PodIP,
		QOSClass:              st.QOSClass,
		ContainerStatuses:     trimStatuses(st.ContainerStatuses),
		InitContainerStatuses: trimStatuses(st.InitContainerStatuses),
	}
	for _, c := range st.Conditions {
		if c.Type == corev1.PodReady || c.Type == corev1.PodScheduled {
			status.Conditions = append(status.Conditions, corev1.PodCondition{
				Type: c.Type, Status: c.Status, Reason: c.Reason, Message: truncate(c.Message), LastTransitionTime: c.LastTransitionTime,
			})
		}
	}
	p.Status = status
}

// trimContainers keeps what convertSpec reads: name, image, security context,
// CPU and memory resources, and the restart policy that marks native sidecars.
// Env, command, args, probes, lifecycle hooks and mounts are dropped.
func trimContainers(cs []corev1.Container) []corev1.Container {
	if len(cs) == 0 {
		return nil
	}
	out := make([]corev1.Container, len(cs))
	for i, c := range cs {
		out[i] = corev1.Container{
			Name:            c.Name,
			Image:           c.Image,
			SecurityContext: c.SecurityContext,
			RestartPolicy:   c.RestartPolicy,
			Resources: corev1.ResourceRequirements{
				Requests: cpuMemory(c.Resources.Requests),
				Limits:   cpuMemory(c.Resources.Limits),
			},
		}
	}
	return out
}

func cpuMemory(l corev1.ResourceList) corev1.ResourceList {
	var out corev1.ResourceList
	for _, name := range []corev1.ResourceName{corev1.ResourceCPU, corev1.ResourceMemory} {
		if q, ok := l[name]; ok {
			if out == nil {
				out = corev1.ResourceList{}
			}
			out[name] = q
		}
	}
	return out
}

func trimStatuses(ss []corev1.ContainerStatus) []corev1.ContainerStatus {
	if len(ss) == 0 {
		return nil
	}
	out := make([]corev1.ContainerStatus, len(ss))
	for i, s := range ss {
		out[i] = corev1.ContainerStatus{
			Name:                 s.Name,
			ContainerID:          s.ContainerID,
			RestartCount:         s.RestartCount,
			Ready:                s.Ready,
			Started:              s.Started,
			State:                trimState(s.State),
			LastTerminationState: corev1.ContainerState{Terminated: trimTerminated(s.LastTerminationState.Terminated)},
		}
		if s.Resources != nil {
			if q, ok := s.Resources.Limits[corev1.ResourceMemory]; ok {
				out[i].Resources = &corev1.ResourceRequirements{Limits: corev1.ResourceList{corev1.ResourceMemory: q}}
			}
		}
	}
	return out
}

func trimState(s corev1.ContainerState) corev1.ContainerState {
	var out corev1.ContainerState
	if w := s.Waiting; w != nil {
		out.Waiting = &corev1.ContainerStateWaiting{Reason: w.Reason, Message: truncate(w.Message)}
	}
	if r := s.Running; r != nil {
		out.Running = &corev1.ContainerStateRunning{StartedAt: r.StartedAt}
	}
	out.Terminated = trimTerminated(s.Terminated)
	return out
}

func trimTerminated(t *corev1.ContainerStateTerminated) *corev1.ContainerStateTerminated {
	if t == nil {
		return nil
	}
	return &corev1.ContainerStateTerminated{Reason: t.Reason, Message: truncate(t.Message), ExitCode: t.ExitCode, FinishedAt: t.FinishedAt}
}

// transformNode keeps placement labels, the fields convertNode reads, and
// drops status.images, volumes in use and every annotation.
func transformNode(n *corev1.Node, labels labelFilter) {
	stripMeta(&n.ObjectMeta, nil)
	n.Labels = labels.filter(n.Labels)
	n.Spec = corev1.NodeSpec{Unschedulable: n.Spec.Unschedulable, Taints: n.Spec.Taints, ProviderID: n.Spec.ProviderID}
	st := &n.Status
	status := corev1.NodeStatus{
		Allocatable: allocatable(st.Allocatable),
		NodeInfo: corev1.NodeSystemInfo{
			KubeletVersion:          st.NodeInfo.KubeletVersion,
			OSImage:                 st.NodeInfo.OSImage,
			ContainerRuntimeVersion: st.NodeInfo.ContainerRuntimeVersion,
		},
	}
	for _, a := range st.Addresses {
		if a.Type == corev1.NodeInternalIP {
			status.Addresses = append(status.Addresses, a)
		}
	}
	if len(st.Conditions) > 0 {
		status.Conditions = make([]corev1.NodeCondition, len(st.Conditions))
		for i, c := range st.Conditions {
			status.Conditions[i] = corev1.NodeCondition{
				Type: c.Type, Status: c.Status, Reason: c.Reason, Message: truncate(c.Message), LastTransitionTime: c.LastTransitionTime,
			}
		}
	}
	n.Status = status
}

func allocatable(l corev1.ResourceList) corev1.ResourceList {
	var out corev1.ResourceList
	for _, name := range []corev1.ResourceName{corev1.ResourceCPU, corev1.ResourceMemory, corev1.ResourcePods} {
		if q, ok := l[name]; ok {
			if out == nil {
				out = corev1.ResourceList{}
			}
			out[name] = q
		}
	}
	return out
}

func transformPVC(p *corev1.PersistentVolumeClaim) {
	stripMeta(&p.ObjectMeta, nil)
	p.Spec.Selector, p.Spec.DataSource, p.Spec.DataSourceRef = nil, nil, nil
	p.Status.Conditions = nil
	p.Status.AllocatedResources, p.Status.AllocatedResourceStatuses = nil, nil
	p.Status.ModifyVolumeStatus = nil
}

func transformPV(pv *corev1.PersistentVolume) {
	stripMeta(&pv.ObjectMeta, nil)
	s := &pv.Spec
	s.NodeAffinity, s.MountOptions = nil, nil
	if c := s.CSI; c != nil {
		s.CSI = &corev1.CSIPersistentVolumeSource{Driver: c.Driver, VolumeHandle: c.VolumeHandle}
	}
	if r := s.ClaimRef; r != nil {
		s.ClaimRef = &corev1.ObjectReference{Kind: r.Kind, Namespace: r.Namespace, Name: r.Name, UID: r.UID}
	}
	pv.Status.Message = truncate(pv.Status.Message)
}

func transformService(s *corev1.Service, allow map[string]bool) {
	stripMeta(&s.ObjectMeta, allow)
	ing := s.Status.LoadBalancer.Ingress
	s.Status = corev1.ServiceStatus{}
	for _, in := range ing {
		s.Status.LoadBalancer.Ingress = append(s.Status.LoadBalancer.Ingress, corev1.LoadBalancerIngress{IP: in.IP, Hostname: in.Hostname})
	}
}

func transformEndpointSlice(e *discoveryv1.EndpointSlice) {
	stripMeta(&e.ObjectMeta, nil)
	e.Labels = filterKeys(e.Labels, endpointSliceLabels)
	e.OwnerReferences = nil
	e.Ports = nil
	for i := range e.Endpoints {
		ep := &e.Endpoints[i]
		out := discoveryv1.Endpoint{Addresses: ep.Addresses, Conditions: ep.Conditions, NodeName: ep.NodeName}
		if r := ep.TargetRef; r != nil {
			out.TargetRef = &corev1.ObjectReference{Kind: r.Kind, Name: r.Name, UID: r.UID}
		}
		*ep = out
	}
}

func transformConfigMap(c *corev1.ConfigMap) {
	stripMeta(&c.ObjectMeta, nil)
	c.BinaryData = nil
	var data map[string]string
	for _, k := range []string{mapRolesKey, mapUsersKey} {
		if v, ok := c.Data[k]; ok {
			if data == nil {
				data = map[string]string{}
			}
			data[k] = v
		}
	}
	c.Data = data
}

// transformCertManager strips cert-manager objects: the CSR and issued
// certificate PEMs, ACME solver configs and every annotation outside allow
// (the owning Certificate's name, and on Certificates the owner annotation).
func transformCertManager(u *unstructured.Unstructured, allow map[string]bool) {
	unstructured.RemoveNestedField(u.Object, "metadata", "managedFields")
	if a := filterKeys(u.GetAnnotations(), allow); a != nil {
		u.SetAnnotations(a)
	} else {
		unstructured.RemoveNestedField(u.Object, "metadata", "annotations")
	}
	unstructured.RemoveNestedField(u.Object, "spec", "request")       // CertificateRequest CSR
	unstructured.RemoveNestedField(u.Object, "status", "certificate") // issued PEM
	unstructured.RemoveNestedField(u.Object, "status", "ca")
	// Issuers: keep the backend key and its server only.
	if spec, ok := u.Object["spec"].(map[string]any); ok {
		for _, t := range issuerTypes {
			sub, ok := spec[t].(map[string]any)
			if !ok {
				continue
			}
			kept := map[string]any{}
			if s, ok := sub["server"]; ok {
				kept["server"] = s
			}
			spec[t] = kept
		}
	}
	if conds, ok := nestedSlice(u.Object, "status", "conditions"); ok {
		for _, c := range conds {
			if m, ok := c.(map[string]any); ok {
				if msg, ok := m["message"].(string); ok {
					m["message"] = truncate(msg)
				}
			}
		}
	}
}

// nestedSlice returns the slice at fields without copying it (unstructured's
// NestedSlice deep-copies).
func nestedSlice(obj map[string]any, fields ...string) ([]any, bool) {
	v, ok, err := unstructured.NestedFieldNoCopy(obj, fields...)
	if !ok || err != nil {
		return nil, false
	}
	s, ok := v.([]any)
	return s, ok
}
