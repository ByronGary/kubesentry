package prom

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
)

// PodMemory returns the working-set memory history and memory limits for the
// containers of a single pod. Names are embedded as quoted PromQL string
// literals, so a hostile value cannot break out of the selector.
func (c *Client) PodMemory(ctx context.Context, namespace, pod string, lookback, step time.Duration) ([]model.ContainerSeries, map[model.ContainerKey]float64, error) {
	sel := fmt.Sprintf(`namespace=%s,pod=%s`, strconv.Quote(namespace), strconv.Quote(pod))
	memQ := fmt.Sprintf(`max by (namespace, pod, container) (container_memory_working_set_bytes{%s,container!="",container!="POD"})`, sel)
	limQ := fmt.Sprintf(`max by (namespace, pod, container) (kube_pod_container_resource_limits{%s,resource="memory"})`, sel)

	end := time.Now()
	raw, err := c.QueryRange(ctx, memQ, end.Add(-lookback), end, step)
	if err != nil {
		return nil, nil, err
	}
	series := make([]model.ContainerSeries, 0, len(raw))
	for _, s := range raw {
		series = append(series, model.ContainerSeries{Key: keyFrom(s.Labels), Samples: s.Samples})
	}

	rawLimits, err := c.Query(ctx, limQ, end)
	if err != nil {
		return nil, nil, err
	}
	limits := make(map[model.ContainerKey]float64, len(rawLimits))
	for _, s := range rawLimits {
		if len(s.Samples) > 0 {
			limits[keyFrom(s.Labels)] = s.Samples[len(s.Samples)-1].V
		}
	}
	return series, limits, nil
}
