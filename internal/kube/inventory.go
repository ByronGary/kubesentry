package kube

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
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

	"github.com/ByronGary/kubesentry/internal/model"
)

// paginate calls list until the server stops returning a continue token.
func paginate(what string, list func(opts metav1.ListOptions) (string, error)) error {
	opts := metav1.ListOptions{Limit: pageSize}
	for {
		cont, err := list(opts)
		if err != nil {
			return fmt.Errorf("list %s: %w", what, err)
		}
		if cont == "" {
			return nil
		}
		opts.Continue = cont
	}
}

func (s *Source) listDeployments(ctx context.Context) ([]model.Workload, error) {
	apps := s.appLabels()
	return collect("deployments", func(o metav1.ListOptions) ([]appsv1.Deployment, string, error) {
		l, err := s.cs.AppsV1().Deployments(metav1.NamespaceAll).List(ctx, o)
		if err != nil {
			return nil, "", err
		}
		return l.Items, l.Continue, nil
	}, func(o *appsv1.Deployment) model.Workload { return convertDeployment(o, apps) })
}

func (s *Source) listStatefulSets(ctx context.Context) ([]model.Workload, error) {
	apps := s.appLabels()
	return collect("statefulsets", func(o metav1.ListOptions) ([]appsv1.StatefulSet, string, error) {
		l, err := s.cs.AppsV1().StatefulSets(metav1.NamespaceAll).List(ctx, o)
		if err != nil {
			return nil, "", err
		}
		return l.Items, l.Continue, nil
	}, func(o *appsv1.StatefulSet) model.Workload { return convertStatefulSet(o, apps) })
}

func (s *Source) listDaemonSets(ctx context.Context) ([]model.Workload, error) {
	apps := s.appLabels()
	return collect("daemonsets", func(o metav1.ListOptions) ([]appsv1.DaemonSet, string, error) {
		l, err := s.cs.AppsV1().DaemonSets(metav1.NamespaceAll).List(ctx, o)
		if err != nil {
			return nil, "", err
		}
		return l.Items, l.Continue, nil
	}, func(o *appsv1.DaemonSet) model.Workload { return convertDaemonSet(o, apps) })
}

func (s *Source) listJobs(ctx context.Context) ([]model.Workload, error) {
	apps := s.appLabels()
	return collect("jobs", func(o metav1.ListOptions) ([]batchv1.Job, string, error) {
		l, err := s.cs.BatchV1().Jobs(metav1.NamespaceAll).List(ctx, o)
		if err != nil {
			return nil, "", err
		}
		return l.Items, l.Continue, nil
	}, func(o *batchv1.Job) model.Workload { return convertJob(o, apps) })
}

func (s *Source) listCronJobs(ctx context.Context) ([]model.Workload, error) {
	apps := s.appLabels()
	return collect("cronjobs", func(o metav1.ListOptions) ([]batchv1.CronJob, string, error) {
		l, err := s.cs.BatchV1().CronJobs(metav1.NamespaceAll).List(ctx, o)
		if err != nil {
			return nil, "", err
		}
		return l.Items, l.Continue, nil
	}, func(o *batchv1.CronJob) model.Workload { return convertCronJob(o, apps) })
}

// ListWorkloads lists Deployments, StatefulSets, DaemonSets, Jobs and CronJobs.
func (s *Source) ListWorkloads(ctx context.Context) ([]model.Workload, error) {
	var out []model.Workload
	for _, list := range []func(context.Context) ([]model.Workload, error){
		s.listDeployments, s.listStatefulSets, s.listDaemonSets, s.listJobs, s.listCronJobs,
	} {
		ws, err := list(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, ws...)
	}
	return out, nil
}

// ListReplicaSets lists ReplicaSets, for resolving Pod → ReplicaSet → Deployment.
func (s *Source) ListReplicaSets(ctx context.Context) ([]model.ReplicaSet, error) {
	return collect("replicasets", func(o metav1.ListOptions) ([]appsv1.ReplicaSet, string, error) {
		l, err := s.cs.AppsV1().ReplicaSets(metav1.NamespaceAll).List(ctx, o)
		if err != nil {
			return nil, "", err
		}
		return l.Items, l.Continue, nil
	}, convertReplicaSet)
}

// ListEndpointSlices lists discovery.k8s.io/v1 EndpointSlices.
func (s *Source) ListEndpointSlices(ctx context.Context) ([]model.EndpointSlice, error) {
	return collect("endpointslices", func(o metav1.ListOptions) ([]discoveryv1.EndpointSlice, string, error) {
		l, err := s.cs.DiscoveryV1().EndpointSlices(metav1.NamespaceAll).List(ctx, o)
		if err != nil {
			return nil, "", err
		}
		return l.Items, l.Continue, nil
	}, convertEndpointSlice)
}

// baseWorkload reads what every workload kind has; apps picks the labels
// kept (the app tags).
func baseWorkload(kind string, m metav1.ObjectMeta, sel *metav1.LabelSelector, tpl *corev1.PodTemplateSpec, apps labelFilter) model.Workload {
	w := model.Workload{
		Kind: kind, Namespace: m.Namespace, Name: m.Name, UID: string(m.UID), Owners: convertOwners(m.OwnerReferences),
		Created: m.CreationTimestamp.Time, Selector: convertSelector(sel), Labels: apps.filter(m.Labels),
	}
	if tpl != nil {
		w.Images = templateImages(tpl.Spec)
	}
	return w
}

func templateImages(spec corev1.PodSpec) []string {
	var out []string
	for _, c := range spec.Containers {
		out = append(out, c.Image)
	}
	for _, c := range spec.InitContainers {
		out = append(out, c.Image)
	}
	return out
}

func convertSelector(sel *metav1.LabelSelector) *model.LabelSelector {
	if sel == nil {
		return nil
	}
	out := &model.LabelSelector{MatchLabels: sel.MatchLabels}
	for _, r := range sel.MatchExpressions {
		out.MatchExpressions = append(out.MatchExpressions, model.SelectorRequirement{
			Key: r.Key, Operator: string(r.Operator), Values: r.Values,
		})
	}
	return out
}

func condition(typ, status, reason, message string, at time.Time) model.Condition {
	return model.Condition{Type: typ, Status: status, Reason: reason, Message: truncate(message), LastTransition: at}
}

func replicas(p *int32) int32 {
	if p == nil {
		return 1 // the API server's default
	}
	return *p
}

func convertDeployment(d *appsv1.Deployment, apps labelFilter) model.Workload {
	w := baseWorkload("Deployment", d.ObjectMeta, d.Spec.Selector, &d.Spec.Template, apps)
	w.Revision = d.Annotations[revisionAnnotation]
	w.Desired = replicas(d.Spec.Replicas)
	w.Ready, w.Updated, w.Available = d.Status.ReadyReplicas, d.Status.UpdatedReplicas, d.Status.AvailableReplicas
	w.Paused = d.Spec.Paused
	for _, c := range d.Status.Conditions {
		w.Conditions = append(w.Conditions, condition(string(c.Type), string(c.Status), c.Reason, c.Message, c.LastTransitionTime.Time))
	}
	return w
}

func convertStatefulSet(s *appsv1.StatefulSet, apps labelFilter) model.Workload {
	w := baseWorkload("StatefulSet", s.ObjectMeta, s.Spec.Selector, &s.Spec.Template, apps)
	w.Revision = s.Status.UpdateRevision
	w.Desired = replicas(s.Spec.Replicas)
	w.Ready, w.Updated, w.Available = s.Status.ReadyReplicas, s.Status.UpdatedReplicas, s.Status.AvailableReplicas
	for _, c := range s.Status.Conditions {
		w.Conditions = append(w.Conditions, condition(string(c.Type), string(c.Status), c.Reason, c.Message, c.LastTransitionTime.Time))
	}
	return w
}

// convertDaemonSet takes Revision from the template generation annotation:
// DaemonSetStatus has no updateRevision, and the generation the API server
// keeps there changes exactly when the pod template does.
func convertDaemonSet(d *appsv1.DaemonSet, apps labelFilter) model.Workload {
	w := baseWorkload("DaemonSet", d.ObjectMeta, d.Spec.Selector, &d.Spec.Template, apps)
	w.Revision = d.Annotations[daemonSetGenerationAnnotation]
	w.Desired, w.Ready = d.Status.DesiredNumberScheduled, d.Status.NumberReady
	w.Updated, w.Available = d.Status.UpdatedNumberScheduled, d.Status.NumberAvailable
	for _, c := range d.Status.Conditions {
		w.Conditions = append(w.Conditions, condition(string(c.Type), string(c.Status), c.Reason, c.Message, c.LastTransitionTime.Time))
	}
	return w
}

func convertJob(j *batchv1.Job, apps labelFilter) model.Workload {
	w := baseWorkload("Job", j.ObjectMeta, j.Spec.Selector, &j.Spec.Template, apps)
	w.Desired = replicas(j.Spec.Completions)
	w.Succeeded, w.Failed, w.Active = j.Status.Succeeded, j.Status.Failed, j.Status.Active
	if j.Status.Ready != nil {
		w.Ready = *j.Status.Ready
	}
	for _, c := range j.Status.Conditions {
		w.Conditions = append(w.Conditions, condition(string(c.Type), string(c.Status), c.Reason, c.Message, c.LastTransitionTime.Time))
	}
	return w
}

func convertCronJob(c *batchv1.CronJob, apps labelFilter) model.Workload {
	w := baseWorkload("CronJob", c.ObjectMeta, nil, &c.Spec.JobTemplate.Spec.Template, apps)
	w.Schedule = c.Spec.Schedule
	w.Suspended = c.Spec.Suspend != nil && *c.Spec.Suspend
	w.Active = int32(len(c.Status.Active))
	if t := c.Status.LastScheduleTime; t != nil {
		w.LastScheduleTime = t.Time
	}
	if t := c.Status.LastSuccessfulTime; t != nil {
		w.LastSuccessTime = t.Time
	}
	return w
}

func convertReplicaSet(r *appsv1.ReplicaSet) model.ReplicaSet {
	return model.ReplicaSet{
		Namespace: r.Namespace, Name: r.Name, UID: string(r.UID), Owners: convertOwners(r.OwnerReferences),
		Desired: replicas(r.Spec.Replicas), Ready: r.Status.ReadyReplicas, Created: r.CreationTimestamp.Time,
		Revision: r.Annotations[revisionAnnotation], Images: templateImages(r.Spec.Template.Spec),
	}
}

// convertEndpointSlice reads the slice's Service and endpoint conditions. A
// nil condition takes the API's documented default: ready and serving true,
// terminating false.
func convertEndpointSlice(e *discoveryv1.EndpointSlice) model.EndpointSlice {
	out := model.EndpointSlice{
		Namespace: e.Namespace, Name: e.Name,
		Service: e.Labels[serviceNameLabel], ManagedBy: e.Labels[managedByLabel],
	}
	if len(e.Endpoints) > 0 {
		out.Endpoints = make([]model.Endpoint, len(e.Endpoints))
	}
	for i, ep := range e.Endpoints {
		c := ep.Conditions
		m := model.Endpoint{
			Addresses:   ep.Addresses,
			Ready:       c.Ready == nil || *c.Ready,
			Serving:     c.Serving == nil || *c.Serving,
			Terminating: c.Terminating != nil && *c.Terminating,
		}
		if ep.NodeName != nil {
			m.NodeName = *ep.NodeName
		}
		if r := ep.TargetRef; r != nil {
			m.TargetKind, m.TargetName, m.TargetUID = r.Kind, r.Name, string(r.UID)
		}
		out.Endpoints[i] = m
	}
	return out
}

func (s *Source) ListServices(ctx context.Context) ([]model.Service, error) {
	return collect("services", func(o metav1.ListOptions) ([]corev1.Service, string, error) {
		l, err := s.cs.CoreV1().Services(metav1.NamespaceAll).List(ctx, o)
		if err != nil {
			return nil, "", err
		}
		return l.Items, l.Continue, nil
	}, convertService)
}

func convertService(s *corev1.Service) model.Service {
	out := model.Service{
		Namespace: s.Namespace, Name: s.Name, Type: string(s.Spec.Type), ClusterIP: s.Spec.ClusterIP,
		Selector: s.Spec.Selector, ExternalIPs: s.Spec.ExternalIPs, Created: s.CreationTimestamp.Time,
		SourceRanges: s.Spec.LoadBalancerSourceRanges, PublishNotReady: s.Spec.PublishNotReadyAddresses,
		Annotations: filterKeys(s.Annotations, serviceAnnotations),
	}
	if c := s.Spec.LoadBalancerClass; c != nil {
		out.LoadBalancerClass = *c
	}
	for _, p := range s.Spec.Ports {
		out.Ports = append(out.Ports, model.ServicePort{
			Name: p.Name, Protocol: string(p.Protocol), Port: p.Port, TargetPort: p.TargetPort.String(), NodePort: p.NodePort,
		})
	}
	for _, in := range s.Status.LoadBalancer.Ingress {
		if in.IP != "" {
			out.LoadBalancerIngress = append(out.LoadBalancerIngress, in.IP)
		} else if in.Hostname != "" {
			out.LoadBalancerIngress = append(out.LoadBalancerIngress, in.Hostname)
		}
	}
	return out
}

func (s *Source) ListIngresses(ctx context.Context) ([]model.Ingress, error) {
	return collect("ingresses", func(o metav1.ListOptions) ([]networkingv1.Ingress, string, error) {
		l, err := s.cs.NetworkingV1().Ingresses(metav1.NamespaceAll).List(ctx, o)
		if err != nil {
			return nil, "", err
		}
		return l.Items, l.Continue, nil
	}, convertIngress)
}

func convertIngress(in *networkingv1.Ingress) model.Ingress {
	out := model.Ingress{
		Namespace: in.Namespace, Name: in.Name, Created: in.CreationTimestamp.Time,
		Annotations: filterKeys(in.Annotations, ingressAnnotations),
	}
	if in.Spec.IngressClassName != nil {
		out.Class = *in.Spec.IngressClassName
	}
	if b := in.Spec.DefaultBackend; b != nil && b.Service != nil {
		out.DefaultBackend = b.Service.Name
	}
	for _, r := range in.Spec.Rules {
		if r.HTTP == nil {
			continue
		}
		for _, p := range r.HTTP.Paths {
			if p.Backend.Service == nil {
				continue // resource backends do not route to a Service
			}
			port := p.Backend.Service.Port.Name
			if port == "" && p.Backend.Service.Port.Number != 0 {
				port = fmt.Sprint(p.Backend.Service.Port.Number)
			}
			out.Rules = append(out.Rules, model.IngressRule{Host: r.Host, Path: p.Path, Service: p.Backend.Service.Name, Port: port})
		}
	}
	for _, t := range in.Spec.TLS {
		out.TLS = append(out.TLS, model.IngressTLS{Hosts: t.Hosts, SecretName: t.SecretName})
	}
	return out
}

func (s *Source) ListNodes(ctx context.Context) ([]model.Node, error) {
	labels := s.nodeLabels()
	return collect("nodes", func(o metav1.ListOptions) ([]corev1.Node, string, error) {
		l, err := s.cs.CoreV1().Nodes().List(ctx, o)
		if err != nil {
			return nil, "", err
		}
		return l.Items, l.Continue, nil
	}, func(n *corev1.Node) model.Node { return convertNode(n, labels) })
}

func convertNode(n *corev1.Node, labels labelFilter) model.Node {
	out := model.Node{
		Name:                   n.Name,
		Unschedulable:          n.Spec.Unschedulable,
		KubeletVersion:         n.Status.NodeInfo.KubeletVersion,
		OSImage:                n.Status.NodeInfo.OSImage,
		ContainerRuntime:       n.Status.NodeInfo.ContainerRuntimeVersion,
		CPUAllocatableMilli:    n.Status.Allocatable.Cpu().MilliValue(),
		MemoryAllocatableBytes: n.Status.Allocatable.Memory().Value(),
		PodsAllocatable:        n.Status.Allocatable.Pods().Value(),
		Labels:                 labels.filter(n.Labels),
		ProviderID:             n.Spec.ProviderID,
		Created:                n.CreationTimestamp.Time,
	}
	for k := range n.Labels {
		if role, ok := strings.CutPrefix(k, nodeRolePrefix); ok && role != "" {
			out.Roles = append(out.Roles, role)
		}
	}
	sort.Strings(out.Roles)
	for _, a := range n.Status.Addresses {
		if a.Type == corev1.NodeInternalIP {
			out.InternalIP = a.Address
			break
		}
	}
	for _, c := range n.Status.Conditions {
		out.Conditions = append(out.Conditions, condition(string(c.Type), string(c.Status), c.Reason, c.Message, c.LastTransitionTime.Time))
		if c.Type == corev1.NodeReady && c.Status == corev1.ConditionTrue {
			out.Ready = true
		}
	}
	for _, t := range n.Spec.Taints {
		taint := t.Key
		if t.Value != "" {
			taint += "=" + t.Value
		}
		out.Taints = append(out.Taints, taint+":"+string(t.Effect))
	}
	return out
}

func (s *Source) ListPVs(ctx context.Context) ([]model.PV, error) {
	return collect("persistentvolumes", func(o metav1.ListOptions) ([]corev1.PersistentVolume, string, error) {
		l, err := s.cs.CoreV1().PersistentVolumes().List(ctx, o)
		if err != nil {
			return nil, "", err
		}
		return l.Items, l.Continue, nil
	}, convertPV)
}

// inTreeEBS is the in-tree plugin name reported as the Driver of
// awsElasticBlockStore volumes.
const inTreeEBS = "kubernetes.io/aws-ebs"

func convertPV(pv *corev1.PersistentVolume) model.PV {
	out := model.PV{
		Name: pv.Name, StorageClass: pv.Spec.StorageClassName, Phase: string(pv.Status.Phase),
		ReclaimPolicy: string(pv.Spec.PersistentVolumeReclaimPolicy), Source: pvSource(pv.Spec.PersistentVolumeSource),
		Created: pv.CreationTimestamp.Time,
	}
	switch src := pv.Spec.PersistentVolumeSource; {
	case src.CSI != nil:
		out.Driver, out.VolumeHandle = src.CSI.Driver, src.CSI.VolumeHandle
	case src.AWSElasticBlockStore != nil:
		out.Driver, out.VolumeHandle = inTreeEBS, ebsVolumeID(src.AWSElasticBlockStore.VolumeID)
	}
	if q, ok := pv.Spec.Capacity[corev1.ResourceStorage]; ok {
		out.CapacityBytes = q.Value()
	}
	for _, m := range pv.Spec.AccessModes {
		out.AccessModes = append(out.AccessModes, string(m))
	}
	if r := pv.Spec.ClaimRef; r != nil {
		out.ClaimNamespace, out.ClaimName = r.Namespace, r.Name
	}
	return out
}

// ebsVolumeID turns the in-tree form "aws://us-east-1a/vol-0abc" into "vol-0abc".
func ebsVolumeID(id string) string {
	if rest, ok := strings.CutPrefix(id, "aws://"); ok {
		if i := strings.LastIndex(rest, "/"); i >= 0 {
			return rest[i+1:]
		}
		return rest
	}
	return id
}

func pvSource(s corev1.PersistentVolumeSource) string {
	switch {
	case s.CSI != nil:
		return "csi:" + s.CSI.Driver
	case s.AWSElasticBlockStore != nil:
		return "awsElasticBlockStore"
	case s.HostPath != nil:
		return "hostPath"
	case s.Local != nil:
		return "local"
	case s.NFS != nil:
		return "nfs"
	case s.ISCSI != nil:
		return "iscsi"
	case s.FC != nil:
		return "fc"
	}
	return "other"
}

func (s *Source) ListStorageClasses(ctx context.Context) ([]model.StorageClass, error) {
	return collect("storageclasses", func(o metav1.ListOptions) ([]storagev1.StorageClass, string, error) {
		l, err := s.cs.StorageV1().StorageClasses().List(ctx, o)
		if err != nil {
			return nil, "", err
		}
		return l.Items, l.Continue, nil
	}, convertStorageClass)
}

func convertStorageClass(c *storagev1.StorageClass) model.StorageClass {
	out := model.StorageClass{
		Name: c.Name, Provisioner: c.Provisioner, Created: c.CreationTimestamp.Time,
		ReclaimPolicy: string(corev1.PersistentVolumeReclaimDelete), BindingMode: string(storagev1.VolumeBindingImmediate),
		Default:         c.Annotations[defaultClassAnnotation] == "true" || c.Annotations[betaDefaultClassAnnotation] == "true",
		Parameters:      c.Parameters,
		PriceAnnotation: c.Annotations[PriceAnnotation],
	}
	if c.ReclaimPolicy != nil {
		out.ReclaimPolicy = string(*c.ReclaimPolicy)
	}
	if c.VolumeBindingMode != nil {
		out.BindingMode = string(*c.VolumeBindingMode)
	}
	if c.AllowVolumeExpansion != nil {
		out.AllowExpansion = *c.AllowVolumeExpansion
	}
	return out
}

func (s *Source) ListNamespaces(ctx context.Context) ([]model.Namespace, error) {
	ann := s.namespaceAnnotations()
	return collect("namespaces", func(o metav1.ListOptions) ([]corev1.Namespace, string, error) {
		l, err := s.cs.CoreV1().Namespaces().List(ctx, o)
		if err != nil {
			return nil, "", err
		}
		return l.Items, l.Continue, nil
	}, func(n *corev1.Namespace) model.Namespace { return convertNamespace(n, ann) })
}

// convertNamespace keeps the namespace's labels and only the annotations
// ann allows (kubesentry.io/* and the owner annotation).
func convertNamespace(n *corev1.Namespace, ann labelFilter) model.Namespace {
	return model.Namespace{Name: n.Name, Phase: string(n.Status.Phase), Labels: n.Labels, Annotations: ann.filter(n.Annotations),
		Created: n.CreationTimestamp.Time}
}

func (s *Source) listRoles(ctx context.Context) ([]model.Role, error) {
	return collect("roles", func(o metav1.ListOptions) ([]rbacv1.Role, string, error) {
		l, err := s.cs.RbacV1().Roles(metav1.NamespaceAll).List(ctx, o)
		if err != nil {
			return nil, "", err
		}
		return l.Items, l.Continue, nil
	}, convertRole)
}

func (s *Source) listClusterRoles(ctx context.Context) ([]model.Role, error) {
	return collect("clusterroles", func(o metav1.ListOptions) ([]rbacv1.ClusterRole, string, error) {
		l, err := s.cs.RbacV1().ClusterRoles().List(ctx, o)
		if err != nil {
			return nil, "", err
		}
		return l.Items, l.Continue, nil
	}, convertClusterRole)
}

func (s *Source) listRoleBindings(ctx context.Context) ([]model.RoleBinding, error) {
	return collect("rolebindings", func(o metav1.ListOptions) ([]rbacv1.RoleBinding, string, error) {
		l, err := s.cs.RbacV1().RoleBindings(metav1.NamespaceAll).List(ctx, o)
		if err != nil {
			return nil, "", err
		}
		return l.Items, l.Continue, nil
	}, convertRoleBinding)
}

func (s *Source) listClusterRoleBindings(ctx context.Context) ([]model.RoleBinding, error) {
	return collect("clusterrolebindings", func(o metav1.ListOptions) ([]rbacv1.ClusterRoleBinding, string, error) {
		l, err := s.cs.RbacV1().ClusterRoleBindings().List(ctx, o)
		if err != nil {
			return nil, "", err
		}
		return l.Items, l.Continue, nil
	}, convertClusterRoleBinding)
}

// ListRBAC lists Roles, ClusterRoles, RoleBindings and ClusterRoleBindings.
func (s *Source) ListRBAC(ctx context.Context) (model.RBAC, error) {
	var out model.RBAC
	for _, list := range []func(context.Context) ([]model.Role, error){s.listRoles, s.listClusterRoles} {
		rs, err := list(ctx)
		if err != nil {
			return model.RBAC{}, err
		}
		out.Roles = append(out.Roles, rs...)
	}
	for _, list := range []func(context.Context) ([]model.RoleBinding, error){s.listRoleBindings, s.listClusterRoleBindings} {
		bs, err := list(ctx)
		if err != nil {
			return model.RBAC{}, err
		}
		out.Bindings = append(out.Bindings, bs...)
	}
	return out, nil
}

func convertRole(x *rbacv1.Role) model.Role {
	return model.Role{Kind: "Role", Namespace: x.Namespace, Name: x.Name, Rules: convertRules(x.Rules)}
}

func convertClusterRole(x *rbacv1.ClusterRole) model.Role {
	return model.Role{Kind: "ClusterRole", Name: x.Name, Rules: convertRules(x.Rules)}
}

func convertRoleBinding(x *rbacv1.RoleBinding) model.RoleBinding {
	return model.RoleBinding{
		Kind: "RoleBinding", Namespace: x.Namespace, Name: x.Name,
		RoleKind: x.RoleRef.Kind, RoleName: x.RoleRef.Name, Subjects: convertSubjects(x.Subjects),
	}
}

func convertClusterRoleBinding(x *rbacv1.ClusterRoleBinding) model.RoleBinding {
	return model.RoleBinding{
		Kind: "ClusterRoleBinding", Name: x.Name,
		RoleKind: x.RoleRef.Kind, RoleName: x.RoleRef.Name, Subjects: convertSubjects(x.Subjects),
	}
}

func convertRules(rules []rbacv1.PolicyRule) []model.PolicyRule {
	out := make([]model.PolicyRule, 0, len(rules))
	for _, r := range rules {
		out = append(out, model.PolicyRule{
			Verbs: r.Verbs, APIGroups: r.APIGroups, Resources: r.Resources,
			ResourceNames: r.ResourceNames, NonResourceURLs: r.NonResourceURLs,
		})
	}
	return out
}

func convertSubjects(subjects []rbacv1.Subject) []model.Subject {
	out := make([]model.Subject, 0, len(subjects))
	for _, s := range subjects {
		out = append(out, model.Subject{Kind: s.Kind, Name: s.Name, Namespace: s.Namespace})
	}
	return out
}

// forbiddenReason describes a forbidden list for Inventory.Unavailable.
func forbiddenReason(err error) string {
	var st apierrors.APIStatus
	if errors.As(err, &st) && st.Status().Message != "" {
		return st.Status().Message // "<resource> is forbidden: ..."
	}
	return "forbidden: " + err.Error()
}

// Inventory lists everything the inventory pages need with one LIST per
// resource. A forbidden resource is reported in Unavailable with an empty
// slice; any other error fails the read. Implements snapshot.Source.
func (s *Source) Inventory(ctx context.Context) (model.Inventory, error) {
	inv := model.Inventory{Unavailable: map[string]string{}}
	var firstErr error
	// read records a failed list: forbidden as unavailable, anything else as
	// the error to return.
	read := func(name string, err error) {
		switch {
		case err == nil:
		case apierrors.IsForbidden(err):
			inv.Unavailable[name] = forbiddenReason(err)
		case firstErr == nil:
			firstErr = err
		}
	}
	var err error
	inv.Pods, err = s.ListPods(ctx)
	read("pods", err)
	inv.PVCs, err = s.ListPVCs(ctx)
	read("persistentvolumeclaims", err)
	inv.PVs, err = s.ListPVs(ctx)
	read("persistentvolumes", err)
	inv.StorageClasses, err = s.ListStorageClasses(ctx)
	read("storageclasses", err)
	for _, w := range []struct {
		name string
		list func(context.Context) ([]model.Workload, error)
	}{
		{"deployments", s.listDeployments}, {"statefulsets", s.listStatefulSets}, {"daemonsets", s.listDaemonSets},
		{"jobs", s.listJobs}, {"cronjobs", s.listCronJobs},
	} {
		ws, err := w.list(ctx)
		read(w.name, err)
		inv.Workloads = append(inv.Workloads, ws...)
	}
	inv.ReplicaSets, err = s.ListReplicaSets(ctx)
	read("replicasets", err)
	inv.Services, err = s.ListServices(ctx)
	read("services", err)
	inv.EndpointSlices, err = s.ListEndpointSlices(ctx)
	read("endpointslices", err)
	inv.Ingresses, err = s.ListIngresses(ctx)
	read("ingresses", err)
	inv.Nodes, err = s.ListNodes(ctx)
	read("nodes", err)
	inv.Namespaces, err = s.ListNamespaces(ctx)
	read("namespaces", err)
	inv.ServiceAccounts, err = s.listServiceAccounts(ctx)
	read("serviceaccounts", err)
	inv.TargetGroupBindings, err = s.targetGroupBindings(ctx, inv.Unavailable)
	read(targetGroupBindingResource, err)
	for _, r := range []struct {
		name string
		list func(context.Context) ([]model.Role, error)
	}{{"roles", s.listRoles}, {"clusterroles", s.listClusterRoles}} {
		rs, err := r.list(ctx)
		read(r.name, err)
		inv.RBAC.Roles = append(inv.RBAC.Roles, rs...)
	}
	for _, b := range []struct {
		name string
		list func(context.Context) ([]model.RoleBinding, error)
	}{{"rolebindings", s.listRoleBindings}, {"clusterrolebindings", s.listClusterRoleBindings}} {
		bs, err := b.list(ctx)
		read(b.name, err)
		inv.RBAC.Bindings = append(inv.RBAC.Bindings, bs...)
	}
	inv.Certs, err = s.certManager(ctx, inv.Unavailable)
	read("cert-manager", err)
	if s.opts.AWSAuth {
		cm, err := s.cs.CoreV1().ConfigMaps(awsAuthNamespace).Get(ctx, awsAuthName, metav1.GetOptions{})
		switch {
		case apierrors.IsNotFound(err):
			inv.AWSAuth = &model.AWSAuth{}
		case err != nil:
			read(awsAuthName, err)
		default:
			a := awsAuthFromConfigMap(cm)
			inv.AWSAuth = &a
		}
	}
	if firstErr != nil {
		return model.Inventory{}, firstErr
	}
	var version string
	if v, err := s.cs.Discovery().ServerVersion(); err == nil {
		version = v.GitVersion
	}
	inv.Cluster = clusterInfo(s.opts.ClusterName, version, inv.Nodes)
	inv.ReadAt = now(s.opts.Now)
	return inv, nil
}

func now(f func() time.Time) time.Time {
	if f != nil {
		return f()
	}
	return time.Now()
}
