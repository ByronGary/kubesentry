package prom

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
)

// PodMemory returns the working-set memory history for the containers of a
// single pod, and their memory limits from kube-state-metrics when the client
// uses KSMLimits (otherwise an empty map; see PodMemoryFor). Names are
// embedded as quoted PromQL string literals, so a hostile value cannot break
// out of the selector.
func (c *Client) PodMemory(ctx context.Context, namespace, pod string, lookback, step time.Duration) ([]model.ContainerSeries, map[model.ContainerKey]float64, error) {
	ns, po := `namespace=`+strconv.Quote(namespace), `pod=`+strconv.Quote(pod)
	memQ := fmt.Sprintf(`max by (namespace, pod, container) (%s)`, c.sel(memMetric, ns, po, `container!=""`, `container!="POD"`))

	end := c.clock()
	raw, err := c.QueryRange(ctx, memQ, end.Add(-lookback), end, step)
	if err != nil {
		return nil, nil, err
	}
	series := toContainerSeries(raw)
	if !c.ksmLimits {
		return series, map[model.ContainerKey]float64{}, nil
	}
	limQ := fmt.Sprintf(`max by (namespace, pod, container) (%s)`, c.sel("kube_pod_container_resource_limits", ns, po, `resource="memory"`))
	rawLimits, err := c.Query(ctx, limQ, end)
	if err != nil {
		return nil, nil, err
	}
	return series, lastValues(rawLimits), nil
}

// PodMemoryFor is PodMemory for a pod the caller already holds. Limits come
// from the pod (LimitsFromPod); with KSMLimits, kube-state-metrics values take
// precedence and the pod fills the gaps.
func (c *Client) PodMemoryFor(ctx context.Context, pod model.Pod, lookback, step time.Duration) ([]model.ContainerSeries, map[model.ContainerKey]float64, error) {
	series, ksm, err := c.PodMemory(ctx, pod.Namespace, pod.Name, lookback, step)
	if err != nil {
		return nil, nil, err
	}
	limits := LimitsFromPod(pod)
	for k, v := range ksm {
		limits[k] = v
	}
	return series, limits, nil
}

// LimitsFromPod returns each container's memory limit in bytes. The limit the
// kubelet applied (ContainerStatus.MemoryLimitBytes) wins because it follows
// in-place resizes; the spec is the fallback. Containers without a limit are
// left out.
func LimitsFromPod(p model.Pod) map[model.ContainerKey]float64 {
	out := map[model.ContainerKey]float64{}
	addPodLimits(out, p)
	return out
}

// LimitsFromPods is LimitsFromPod for many pods.
func LimitsFromPods(pods []model.Pod) map[model.ContainerKey]float64 {
	out := make(map[model.ContainerKey]float64, len(pods))
	for _, p := range pods {
		addPodLimits(out, p)
	}
	return out
}

func addPodLimits(out map[model.ContainerKey]float64, p model.Pod) {
	key := func(name string) model.ContainerKey {
		return model.ContainerKey{Namespace: p.Namespace, Pod: p.Name, Container: name}
	}
	for _, s := range p.Specs {
		if s.MemoryLimitBytes > 0 {
			out[key(s.Name)] = float64(s.MemoryLimitBytes)
		}
	}
	for _, s := range p.Containers {
		if s.MemoryLimitBytes > 0 {
			out[key(s.Name)] = float64(s.MemoryLimitBytes)
		}
	}
}
