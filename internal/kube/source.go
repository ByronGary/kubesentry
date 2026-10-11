package kube

import (
	"context"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/ByronGary/kubesentry/internal/model"
)

const pageSize = 500

// Source lists cluster objects and converts them to model types. For the MVP it
// does paginated LISTs per request; shared informers are on the roadmap for
// large clusters.
type Source struct {
	cs  kubernetes.Interface
	dyn dynamic.Interface // for cert-manager custom resources; nil disables them
}

// NewSource wraps a clientset and an optional dynamic client.
func NewSource(cs kubernetes.Interface, dyn dynamic.Interface) *Source {
	return &Source{cs: cs, dyn: dyn}
}

func (s *Source) ListPVCs(ctx context.Context) ([]model.PVC, error) {
	var out []model.PVC
	opts := metav1.ListOptions{Limit: pageSize}
	for {
		l, err := s.cs.CoreV1().PersistentVolumeClaims(metav1.NamespaceAll).List(ctx, opts)
		if err != nil {
			return nil, fmt.Errorf("list pvcs: %w", err)
		}
		for i := range l.Items {
			out = append(out, convertPVC(&l.Items[i]))
		}
		if l.Continue == "" {
			return out, nil
		}
		opts.Continue = l.Continue
	}
}

func (s *Source) ListPods(ctx context.Context) ([]model.Pod, error) {
	var out []model.Pod
	opts := metav1.ListOptions{Limit: pageSize}
	for {
		l, err := s.cs.CoreV1().Pods(metav1.NamespaceAll).List(ctx, opts)
		if err != nil {
			return nil, fmt.Errorf("list pods: %w", err)
		}
		for i := range l.Items {
			out = append(out, convertPod(&l.Items[i]))
		}
		if l.Continue == "" {
			return out, nil
		}
		opts.Continue = l.Continue
	}
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
	for _, c := range p.Spec.Containers {
		out.Specs = append(out.Specs, convertSpec(c, p.Spec.SecurityContext, false))
	}
	sidecars := map[string]bool{}
	for _, c := range p.Spec.InitContainers {
		out.Specs = append(out.Specs, convertSpec(c, p.Spec.SecurityContext, true))
		if c.RestartPolicy != nil && *c.RestartPolicy == corev1.ContainerRestartPolicyAlways {
			sidecars[c.Name] = true
		}
	}
	for _, cs := range p.Status.ContainerStatuses {
		out.Containers = append(out.Containers, convertContainer(cs))
	}
	// Native sidecars run for the pod's whole life, so they can be OOMKilled
	// like any other container. Ordinary init containers are left out.
	for _, cs := range p.Status.InitContainerStatuses {
		if sidecars[cs.Name] {
			out.Containers = append(out.Containers, convertContainer(cs))
		}
	}
	return out
}

// convertSpec reads one container's security settings and resources, with the
// pod-level securityContext as the default.
func convertSpec(c corev1.Container, podSC *corev1.PodSecurityContext, init bool) model.ContainerSpec {
	s := model.ContainerSpec{Name: c.Name, Image: c.Image, Init: init}
	if podSC != nil {
		if podSC.RunAsNonRoot != nil {
			s.RunAsNonRoot = *podSC.RunAsNonRoot
		}
		s.RunAsUser = copyInt64(podSC.RunAsUser)
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
			s.RunAsUser = copyInt64(sc.RunAsUser)
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
	s.CPURequestMilli = c.Resources.Requests.Cpu().MilliValue()
	s.CPULimitMilli = c.Resources.Limits.Cpu().MilliValue()
	s.MemoryRequestBytes = c.Resources.Requests.Memory().Value()
	s.MemoryLimitBytes = c.Resources.Limits.Memory().Value()
	return s
}

func copyInt64(p *int64) *int64 {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func convertContainer(cs corev1.ContainerStatus) model.ContainerStatus {
	c := model.ContainerStatus{Name: cs.Name, ContainerID: trimRuntime(cs.ContainerID), RestartCount: cs.RestartCount}
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
	return c
}

// trimRuntime turns "containerd://abc..." into "abc...".
func trimRuntime(id string) string {
	if i := strings.Index(id, "://"); i >= 0 {
		return id[i+3:]
	}
	return id
}
