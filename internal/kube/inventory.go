package kube

import (
	"context"
	"fmt"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
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

// ListWorkloads lists Deployments, StatefulSets, DaemonSets, Jobs and CronJobs.
func (s *Source) ListWorkloads(ctx context.Context) ([]model.Workload, error) {
	var out []model.Workload
	apps, batch := s.cs.AppsV1(), s.cs.BatchV1()
	err := paginate("deployments", func(o metav1.ListOptions) (string, error) {
		l, err := apps.Deployments(metav1.NamespaceAll).List(ctx, o)
		if err != nil {
			return "", err
		}
		for i := range l.Items {
			out = append(out, convertDeployment(&l.Items[i]))
		}
		return l.Continue, nil
	})
	if err != nil {
		return nil, err
	}
	err = paginate("statefulsets", func(o metav1.ListOptions) (string, error) {
		l, err := apps.StatefulSets(metav1.NamespaceAll).List(ctx, o)
		if err != nil {
			return "", err
		}
		for i := range l.Items {
			out = append(out, convertStatefulSet(&l.Items[i]))
		}
		return l.Continue, nil
	})
	if err != nil {
		return nil, err
	}
	err = paginate("daemonsets", func(o metav1.ListOptions) (string, error) {
		l, err := apps.DaemonSets(metav1.NamespaceAll).List(ctx, o)
		if err != nil {
			return "", err
		}
		for i := range l.Items {
			out = append(out, convertDaemonSet(&l.Items[i]))
		}
		return l.Continue, nil
	})
	if err != nil {
		return nil, err
	}
	err = paginate("jobs", func(o metav1.ListOptions) (string, error) {
		l, err := batch.Jobs(metav1.NamespaceAll).List(ctx, o)
		if err != nil {
			return "", err
		}
		for i := range l.Items {
			out = append(out, convertJob(&l.Items[i]))
		}
		return l.Continue, nil
	})
	if err != nil {
		return nil, err
	}
	err = paginate("cronjobs", func(o metav1.ListOptions) (string, error) {
		l, err := batch.CronJobs(metav1.NamespaceAll).List(ctx, o)
		if err != nil {
			return "", err
		}
		for i := range l.Items {
			out = append(out, convertCronJob(&l.Items[i]))
		}
		return l.Continue, nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func baseWorkload(kind string, m metav1.ObjectMeta, sel *metav1.LabelSelector, tpl *corev1.PodTemplateSpec) model.Workload {
	w := model.Workload{Kind: kind, Namespace: m.Namespace, Name: m.Name, Created: m.CreationTimestamp.Time, Selector: convertSelector(sel)}
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
	return model.Condition{Type: typ, Status: status, Reason: reason, Message: message, LastTransition: at}
}

func replicas(p *int32) int32 {
	if p == nil {
		return 1 // the API server's default
	}
	return *p
}

func convertDeployment(d *appsv1.Deployment) model.Workload {
	w := baseWorkload("Deployment", d.ObjectMeta, d.Spec.Selector, &d.Spec.Template)
	w.Desired = replicas(d.Spec.Replicas)
	w.Ready, w.Updated, w.Available = d.Status.ReadyReplicas, d.Status.UpdatedReplicas, d.Status.AvailableReplicas
	w.Paused = d.Spec.Paused
	for _, c := range d.Status.Conditions {
		w.Conditions = append(w.Conditions, condition(string(c.Type), string(c.Status), c.Reason, c.Message, c.LastTransitionTime.Time))
	}
	return w
}

func convertStatefulSet(s *appsv1.StatefulSet) model.Workload {
	w := baseWorkload("StatefulSet", s.ObjectMeta, s.Spec.Selector, &s.Spec.Template)
	w.Desired = replicas(s.Spec.Replicas)
	w.Ready, w.Updated, w.Available = s.Status.ReadyReplicas, s.Status.UpdatedReplicas, s.Status.AvailableReplicas
	for _, c := range s.Status.Conditions {
		w.Conditions = append(w.Conditions, condition(string(c.Type), string(c.Status), c.Reason, c.Message, c.LastTransitionTime.Time))
	}
	return w
}

func convertDaemonSet(d *appsv1.DaemonSet) model.Workload {
	w := baseWorkload("DaemonSet", d.ObjectMeta, d.Spec.Selector, &d.Spec.Template)
	w.Desired, w.Ready = d.Status.DesiredNumberScheduled, d.Status.NumberReady
	w.Updated, w.Available = d.Status.UpdatedNumberScheduled, d.Status.NumberAvailable
	for _, c := range d.Status.Conditions {
		w.Conditions = append(w.Conditions, condition(string(c.Type), string(c.Status), c.Reason, c.Message, c.LastTransitionTime.Time))
	}
	return w
}

func convertJob(j *batchv1.Job) model.Workload {
	w := baseWorkload("Job", j.ObjectMeta, j.Spec.Selector, &j.Spec.Template)
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

func convertCronJob(c *batchv1.CronJob) model.Workload {
	w := baseWorkload("CronJob", c.ObjectMeta, nil, &c.Spec.JobTemplate.Spec.Template)
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

func (s *Source) ListServices(ctx context.Context) ([]model.Service, error) {
	var out []model.Service
	err := paginate("services", func(o metav1.ListOptions) (string, error) {
		l, err := s.cs.CoreV1().Services(metav1.NamespaceAll).List(ctx, o)
		if err != nil {
			return "", err
		}
		for i := range l.Items {
			out = append(out, convertService(&l.Items[i]))
		}
		return l.Continue, nil
	})
	return out, err
}

func convertService(s *corev1.Service) model.Service {
	out := model.Service{
		Namespace: s.Namespace, Name: s.Name, Type: string(s.Spec.Type), ClusterIP: s.Spec.ClusterIP,
		Selector: s.Spec.Selector, ExternalIPs: s.Spec.ExternalIPs, Created: s.CreationTimestamp.Time,
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
	var out []model.Ingress
	err := paginate("ingresses", func(o metav1.ListOptions) (string, error) {
		l, err := s.cs.NetworkingV1().Ingresses(metav1.NamespaceAll).List(ctx, o)
		if err != nil {
			return "", err
		}
		for i := range l.Items {
			out = append(out, convertIngress(&l.Items[i]))
		}
		return l.Continue, nil
	})
	return out, err
}

func convertIngress(in *networkingv1.Ingress) model.Ingress {
	out := model.Ingress{Namespace: in.Namespace, Name: in.Name, Created: in.CreationTimestamp.Time}
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
	var out []model.Node
	err := paginate("nodes", func(o metav1.ListOptions) (string, error) {
		l, err := s.cs.CoreV1().Nodes().List(ctx, o)
		if err != nil {
			return "", err
		}
		for i := range l.Items {
			out = append(out, convertNode(&l.Items[i]))
		}
		return l.Continue, nil
	})
	return out, err
}

const rolePrefix = "node-role.kubernetes.io/"

func convertNode(n *corev1.Node) model.Node {
	out := model.Node{
		Name:                   n.Name,
		Unschedulable:          n.Spec.Unschedulable,
		KubeletVersion:         n.Status.NodeInfo.KubeletVersion,
		OSImage:                n.Status.NodeInfo.OSImage,
		ContainerRuntime:       n.Status.NodeInfo.ContainerRuntimeVersion,
		CPUAllocatableMilli:    n.Status.Allocatable.Cpu().MilliValue(),
		MemoryAllocatableBytes: n.Status.Allocatable.Memory().Value(),
		PodsAllocatable:        n.Status.Allocatable.Pods().Value(),
		Created:                n.CreationTimestamp.Time,
	}
	for k := range n.Labels {
		if role, ok := strings.CutPrefix(k, rolePrefix); ok && role != "" {
			out.Roles = append(out.Roles, role)
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
	var out []model.PV
	err := paginate("persistentvolumes", func(o metav1.ListOptions) (string, error) {
		l, err := s.cs.CoreV1().PersistentVolumes().List(ctx, o)
		if err != nil {
			return "", err
		}
		for i := range l.Items {
			out = append(out, convertPV(&l.Items[i]))
		}
		return l.Continue, nil
	})
	return out, err
}

func convertPV(pv *corev1.PersistentVolume) model.PV {
	out := model.PV{
		Name: pv.Name, StorageClass: pv.Spec.StorageClassName, Phase: string(pv.Status.Phase),
		ReclaimPolicy: string(pv.Spec.PersistentVolumeReclaimPolicy), Source: pvSource(pv.Spec.PersistentVolumeSource),
		Created: pv.CreationTimestamp.Time,
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

func pvSource(s corev1.PersistentVolumeSource) string {
	switch {
	case s.CSI != nil:
		return "csi:" + s.CSI.Driver
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
	var out []model.StorageClass
	err := paginate("storageclasses", func(o metav1.ListOptions) (string, error) {
		l, err := s.cs.StorageV1().StorageClasses().List(ctx, o)
		if err != nil {
			return "", err
		}
		for i := range l.Items {
			out = append(out, convertStorageClass(&l.Items[i]))
		}
		return l.Continue, nil
	})
	return out, err
}

func convertStorageClass(c *storagev1.StorageClass) model.StorageClass {
	out := model.StorageClass{
		Name: c.Name, Provisioner: c.Provisioner, Created: c.CreationTimestamp.Time,
		ReclaimPolicy: string(corev1.PersistentVolumeReclaimDelete), BindingMode: string(storagev1.VolumeBindingImmediate),
		Default: c.Annotations["storageclass.kubernetes.io/is-default-class"] == "true" ||
			c.Annotations["storageclass.beta.kubernetes.io/is-default-class"] == "true",
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
	var out []model.Namespace
	err := paginate("namespaces", func(o metav1.ListOptions) (string, error) {
		l, err := s.cs.CoreV1().Namespaces().List(ctx, o)
		if err != nil {
			return "", err
		}
		for _, n := range l.Items {
			out = append(out, model.Namespace{Name: n.Name, Phase: string(n.Status.Phase), Labels: n.Labels, Created: n.CreationTimestamp.Time})
		}
		return l.Continue, nil
	})
	return out, err
}

// ListRBAC lists Roles, ClusterRoles, RoleBindings and ClusterRoleBindings.
func (s *Source) ListRBAC(ctx context.Context) (model.RBAC, error) {
	var out model.RBAC
	r := s.cs.RbacV1()
	err := paginate("roles", func(o metav1.ListOptions) (string, error) {
		l, err := r.Roles(metav1.NamespaceAll).List(ctx, o)
		if err != nil {
			return "", err
		}
		for _, x := range l.Items {
			out.Roles = append(out.Roles, model.Role{Kind: "Role", Namespace: x.Namespace, Name: x.Name, Rules: convertRules(x.Rules)})
		}
		return l.Continue, nil
	})
	if err != nil {
		return model.RBAC{}, err
	}
	err = paginate("clusterroles", func(o metav1.ListOptions) (string, error) {
		l, err := r.ClusterRoles().List(ctx, o)
		if err != nil {
			return "", err
		}
		for _, x := range l.Items {
			out.Roles = append(out.Roles, model.Role{Kind: "ClusterRole", Name: x.Name, Rules: convertRules(x.Rules)})
		}
		return l.Continue, nil
	})
	if err != nil {
		return model.RBAC{}, err
	}
	err = paginate("rolebindings", func(o metav1.ListOptions) (string, error) {
		l, err := r.RoleBindings(metav1.NamespaceAll).List(ctx, o)
		if err != nil {
			return "", err
		}
		for _, x := range l.Items {
			out.Bindings = append(out.Bindings, model.RoleBinding{
				Kind: "RoleBinding", Namespace: x.Namespace, Name: x.Name,
				RoleKind: x.RoleRef.Kind, RoleName: x.RoleRef.Name, Subjects: convertSubjects(x.Subjects),
			})
		}
		return l.Continue, nil
	})
	if err != nil {
		return model.RBAC{}, err
	}
	err = paginate("clusterrolebindings", func(o metav1.ListOptions) (string, error) {
		l, err := r.ClusterRoleBindings().List(ctx, o)
		if err != nil {
			return "", err
		}
		for _, x := range l.Items {
			out.Bindings = append(out.Bindings, model.RoleBinding{
				Kind: "ClusterRoleBinding", Name: x.Name,
				RoleKind: x.RoleRef.Kind, RoleName: x.RoleRef.Name, Subjects: convertSubjects(x.Subjects),
			})
		}
		return l.Continue, nil
	})
	if err != nil {
		return model.RBAC{}, err
	}
	return out, nil
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
