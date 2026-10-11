package kube

import (
	"context"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/ByronGary/kubesentry/internal/model"
)

const pageSize = 500

// Source lists cluster objects per request and converts them to model types.
// It backs -cache=false (debugging); the informer Cache is the default.
type Source struct {
	cs   kubernetes.Interface
	dyn  dynamic.Interface // for cert-manager custom resources; nil disables them
	opts SourceOptions
}

// SourceOptions configures the parts of a Source's Inventory that are not
// read from the API's defaults. The zero value reads no aws-auth, keeps the
// default node labels and uses time.Now.
type SourceOptions struct {
	AWSAuth          bool     // read kube-system/aws-auth
	NodeLabelKeysAdd []string // extra node label keys to keep ("prefix*" matches by prefix)
	ClusterName      string
	Now              func() time.Time
}

// NewSource wraps a clientset and an optional dynamic client.
func NewSource(cs kubernetes.Interface, dyn dynamic.Interface) *Source {
	return NewSourceWithOptions(cs, dyn, SourceOptions{})
}

// NewSourceWithOptions is NewSource with options for Inventory and node labels.
func NewSourceWithOptions(cs kubernetes.Interface, dyn dynamic.Interface, o SourceOptions) *Source {
	return &Source{cs: cs, dyn: dyn, opts: o}
}

func (s *Source) nodeLabels() labelFilter { return newNodeLabelFilter(s.opts.NodeLabelKeysAdd) }

// collect pages through a list and converts each item.
func collect[O, T any](what string, list func(metav1.ListOptions) ([]O, string, error), conv func(*O) T) ([]T, error) {
	var out []T
	err := paginate(what, func(o metav1.ListOptions) (string, error) {
		items, cont, err := list(o)
		if err != nil {
			return "", err
		}
		for i := range items {
			out = append(out, conv(&items[i]))
		}
		return cont, nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Source) ListPVCs(ctx context.Context) ([]model.PVC, error) {
	return collect("pvcs", func(o metav1.ListOptions) ([]corev1.PersistentVolumeClaim, string, error) {
		l, err := s.cs.CoreV1().PersistentVolumeClaims(metav1.NamespaceAll).List(ctx, o)
		if err != nil {
			return nil, "", err
		}
		return l.Items, l.Continue, nil
	}, convertPVC)
}

func (s *Source) ListPods(ctx context.Context) ([]model.Pod, error) {
	return collect("pods", func(o metav1.ListOptions) ([]corev1.Pod, string, error) {
		l, err := s.cs.CoreV1().Pods(metav1.NamespaceAll).List(ctx, o)
		if err != nil {
			return nil, "", err
		}
		return l.Items, l.Continue, nil
	}, convertPod)
}

// GetPod returns model.ErrNotFound if the pod does not exist.
func (s *Source) GetPod(ctx context.Context, namespace, name string) (*model.Pod, error) {
	p, err := s.cs.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, model.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get pod: %w", err)
	}
	out := convertPod(p)
	return &out, nil
}

// GetPVC returns model.ErrNotFound if the claim does not exist.
func (s *Source) GetPVC(ctx context.Context, namespace, name string) (*model.PVC, error) {
	p, err := s.cs.CoreV1().PersistentVolumeClaims(namespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, model.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get pvc: %w", err)
	}
	out := convertPVC(p)
	return &out, nil
}

func convertPVC(p *corev1.PersistentVolumeClaim) model.PVC {
	var class string
	if p.Spec.StorageClassName != nil {
		class = *p.Spec.StorageClassName
	}
	var capacity int64
	if q, ok := p.Status.Capacity[corev1.ResourceStorage]; ok {
		capacity = q.Value()
	}
	return model.PVC{
		Namespace:     p.Namespace,
		Name:          p.Name,
		StorageClass:  class,
		Phase:         string(p.Status.Phase),
		CapacityBytes: capacity,
		VolumeName:    p.Spec.VolumeName,
		Created:       p.CreationTimestamp.Time,
	}
}

func convertOwners(refs []metav1.OwnerReference) []model.OwnerRef {
	if len(refs) == 0 {
		return nil
	}
	out := make([]model.OwnerRef, len(refs))
	for i, r := range refs {
		out[i] = model.OwnerRef{Kind: r.Kind, Name: r.Name, UID: string(r.UID), Controller: r.Controller != nil && *r.Controller}
	}
	return out
}

func convertPod(p *corev1.Pod) model.Pod {
	out := model.Pod{
		UID:            string(p.UID),
		Namespace:      p.Namespace,
		Name:           p.Name,
		Phase:          string(p.Status.Phase),
		NodeName:       p.Spec.NodeName,
		Labels:         p.Labels,
		ServiceAccount: p.Spec.ServiceAccountName,
		Created:        p.CreationTimestamp.Time,
		HostPID:        p.Spec.HostPID,
		HostNetwork:    p.Spec.HostNetwork,
		HostIPC:        p.Spec.HostIPC,
		AutomountToken: p.Spec.AutomountServiceAccountToken == nil || *p.Spec.AutomountServiceAccountToken,
		Owners:         convertOwners(p.OwnerReferences),
		PodIP:          p.Status.PodIP,
		QOSClass:       string(p.Status.QOSClass),
		Reason:         p.Status.Reason,
		Message:        truncate(p.Status.Message),
	}
	if t := p.DeletionTimestamp; t != nil {
		out.DeletedAt = t.Time
	}
	for _, c := range p.Status.Conditions {
		switch c.Type {
		case corev1.PodReady:
			out.Ready = c.Status == corev1.ConditionTrue
			out.ReadyChanged = c.LastTransitionTime.Time
		case corev1.PodScheduled:
			if c.Status == corev1.ConditionFalse && c.Reason == corev1.PodReasonUnschedulable {
				out.Unschedulable = truncate(c.Message)
				if out.Unschedulable == "" {
					out.Unschedulable = c.Reason
				}
			}
		}
	}
	for _, v := range p.Spec.Volumes {
		switch {
		case v.PersistentVolumeClaim != nil:
			out.Claims = append(out.Claims, v.PersistentVolumeClaim.ClaimName)
		case v.Ephemeral != nil:
			// Generic ephemeral volumes create a PVC named <pod>-<volume>.
			out.Claims = append(out.Claims, p.Name+"-"+v.Name)
		case v.HostPath != nil:
			out.HostPaths = append(out.HostPaths, v.HostPath.Path)
		}
	}
	if n := len(p.Spec.Containers) + len(p.Spec.InitContainers); n > 0 {
		out.Specs = make([]model.ContainerSpec, 0, n)
	}
	for i := range p.Spec.Containers {
		out.Specs = append(out.Specs, convertSpec(&p.Spec.Containers[i], p.Spec.SecurityContext, false))
	}
	for i := range p.Spec.InitContainers {
		out.Specs = append(out.Specs, convertSpec(&p.Spec.InitContainers[i], p.Spec.SecurityContext, true))
	}
	if n := len(p.Status.ContainerStatuses) + len(p.Status.InitContainerStatuses); n > 0 {
		out.Containers = make([]model.ContainerStatus, 0, n)
	}
	for _, cs := range p.Status.ContainerStatuses {
		out.Containers = append(out.Containers, convertContainer(cs, false))
	}
	// Init containers follow the app containers, marked Init. Native sidecars
	// run for the pod's whole life and can be OOMKilled like any container;
	// ordinary init containers are kept so Init:CrashLoopBackOff and similar
	// stuck states are visible.
	for _, cs := range p.Status.InitContainerStatuses {
		out.Containers = append(out.Containers, convertContainer(cs, true))
	}
	return out
}

// convertSpec reads one container's security settings and resources, with the
// pod-level securityContext as the default.
func convertSpec(c *corev1.Container, podSC *corev1.PodSecurityContext, init bool) model.ContainerSpec {
	s := model.ContainerSpec{Name: c.Name, Image: c.Image, Init: init}
	runAsUser := (*int64)(nil)
	if podSC != nil {
		if podSC.RunAsNonRoot != nil {
			s.RunAsNonRoot = *podSC.RunAsNonRoot
		}
		runAsUser = podSC.RunAsUser
	}
	if sc := c.SecurityContext; sc != nil {
		if sc.Privileged != nil {
			s.Privileged = *sc.Privileged
		}
		if sc.AllowPrivilegeEscalation != nil {
			v := *sc.AllowPrivilegeEscalation
			s.AllowPrivilegeEscalation = &v
		}
		if sc.RunAsNonRoot != nil {
			s.RunAsNonRoot = *sc.RunAsNonRoot
		}
		if sc.RunAsUser != nil {
			runAsUser = sc.RunAsUser
		}
		if sc.ReadOnlyRootFilesystem != nil {
			s.ReadOnlyRootFilesystem = *sc.ReadOnlyRootFilesystem
		}
		if caps := sc.Capabilities; caps != nil {
			for _, a := range caps.Add {
				s.CapabilitiesAdd = append(s.CapabilitiesAdd, string(a))
			}
			for _, d := range caps.Drop {
				if strings.EqualFold(string(d), "ALL") {
					s.CapabilitiesDropAll = true
				}
			}
		}
	}
	s.RunAsUser = copyInt64(runAsUser)
	// Index the lists directly: ResourceList.Cpu() and friends allocate.
	if q, ok := c.Resources.Requests[corev1.ResourceCPU]; ok {
		s.CPURequestMilli = q.MilliValue()
	}
	if q, ok := c.Resources.Limits[corev1.ResourceCPU]; ok {
		s.CPULimitMilli = q.MilliValue()
	}
	if q, ok := c.Resources.Requests[corev1.ResourceMemory]; ok {
		s.MemoryRequestBytes = q.Value()
	}
	if q, ok := c.Resources.Limits[corev1.ResourceMemory]; ok {
		s.MemoryLimitBytes = q.Value()
	}
	return s
}

func copyInt64(p *int64) *int64 {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func convertContainer(cs corev1.ContainerStatus, init bool) model.ContainerStatus {
	c := model.ContainerStatus{
		Name: cs.Name, ContainerID: trimRuntime(cs.ContainerID), RestartCount: cs.RestartCount,
		Init: init, Ready: cs.Ready, Started: cs.Started != nil && *cs.Started,
	}
	switch st := cs.State; {
	case st.Waiting != nil:
		c.State, c.Reason, c.Message = "waiting", st.Waiting.Reason, truncate(st.Waiting.Message)
	case st.Terminated != nil:
		c.State, c.Reason, c.Message = "terminated", st.Terminated.Reason, truncate(st.Terminated.Message)
	case st.Running != nil:
		c.State = "running"
	}
	// A container that is terminated right now is more recent than its
	// LastTerminationState, so check State first.
	t := cs.State.Terminated
	if t == nil {
		t = cs.LastTerminationState.Terminated
	}
	if t != nil {
		c.LastTerminatedReason = t.Reason
		c.LastTerminatedAt = t.FinishedAt.Time
		c.LastExitCode = t.ExitCode
	}
	if r := cs.Resources; r != nil {
		if q, ok := r.Limits[corev1.ResourceMemory]; ok {
			c.MemoryLimitBytes = q.Value()
		}
	}
	return c
}

// trimRuntime turns "containerd://abc..." into "abc...".
func trimRuntime(id string) string {
	if i := strings.Index(id, "://"); i >= 0 {
		return id[i+3:]
	}
	return id
}
