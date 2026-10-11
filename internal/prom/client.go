// Package prom is a minimal Prometheus HTTP API client (standard library only).
package prom

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
)

const maxBody = 64 << 20

// Client talks to a Prometheus-compatible server.
type Client struct {
	BearerToken string
	base        string
	http        *http.Client
}

func New(baseURL string) *Client {
	return &Client{
		base: strings.TrimRight(baseURL, "/"),
		http: &http.Client{Timeout: 30 * time.Second},
	}
}

// Series is one labelled series from a query result.
type Series struct {
	Labels  map[string]string
	Samples []model.Sample
}

type apiResponse struct {
	Status    string `json:"status"`
	ErrorType string `json:"errorType"`
	Error     string `json:"error"`
	Data      struct {
		ResultType string `json:"resultType"`
		Result     []struct {
			Metric map[string]string `json:"metric"`
			Value  []any             `json:"value"`
			Values [][]any           `json:"values"`
		} `json:"result"`
	} `json:"data"`
}

// QueryRange runs a range query.
func (c *Client) QueryRange(ctx context.Context, query string, start, end time.Time, step time.Duration) ([]Series, error) {
	v := url.Values{}
	v.Set("query", query)
	v.Set("start", formatTime(start))
	v.Set("end", formatTime(end))
	v.Set("step", strconv.FormatFloat(step.Seconds(), 'f', -1, 64))
	return c.do(ctx, "/api/v1/query_range", v)
}

// Query runs an instant query at the given time.
func (c *Client) Query(ctx context.Context, query string, at time.Time) ([]Series, error) {
	v := url.Values{}
	v.Set("query", query)
	v.Set("time", formatTime(at))
	return c.do(ctx, "/api/v1/query", v)
}

func (c *Client) do(ctx context.Context, path string, params url.Values) ([]Series, error) {
	// POST keeps long queries out of URL length limits.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.BearerToken)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("prometheus request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("read prometheus response: %w", err)
	}

	var r apiResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("prometheus returned HTTP %d with non-JSON body", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK || r.Status != "success" {
		return nil, fmt.Errorf("prometheus error (HTTP %d): %s: %s", resp.StatusCode, r.ErrorType, r.Error)
	}

	out := make([]Series, 0, len(r.Data.Result))
	for _, res := range r.Data.Result {
		s := Series{Labels: res.Metric}
		points := res.Values
		if res.Value != nil {
			points = append(points, res.Value)
		}
		for _, p := range points {
			sample, ok := parsePoint(p)
			if !ok {
				continue // NaN, Inf or malformed: skip rather than poison a fit
			}
			s.Samples = append(s.Samples, sample)
		}
		out = append(out, s)
	}
	return out, nil
}

func parsePoint(p []any) (model.Sample, bool) {
	if len(p) != 2 {
		return model.Sample{}, false
	}
	ts, ok := p[0].(float64)
	if !ok {
		return model.Sample{}, false
	}
	str, ok := p[1].(string)
	if !ok {
		return model.Sample{}, false
	}
	val, err := strconv.ParseFloat(str, 64)
	if err != nil || math.IsNaN(val) || math.IsInf(val, 0) {
		return model.Sample{}, false
	}
	sec, frac := math.Modf(ts)
	return model.Sample{T: time.Unix(int64(sec), int64(frac*1e9)).UTC(), V: val}, true
}

func formatTime(t time.Time) string {
	return strconv.FormatFloat(float64(t.UnixNano())/1e9, 'f', 3, 64)
}

// ContainerMemory returns the working-set memory of every container over the
// lookback window. cAdvisor series carry a per-container-instance `id` label
// that changes on restart, so max-by-aggregation stitches the lifetimes of one
// container into a single continuous series, which is what the sawtooth
// detector needs.
func (c *Client) ContainerMemory(ctx context.Context, lookback, step time.Duration) ([]model.ContainerSeries, error) {
	const q = `max by (namespace, pod, container) (container_memory_working_set_bytes{container!="",container!="POD"})`
	end := time.Now()
	series, err := c.QueryRange(ctx, q, end.Add(-lookback), end, step)
	if err != nil {
		return nil, err
	}
	out := make([]model.ContainerSeries, 0, len(series))
	for _, s := range series {
		out = append(out, model.ContainerSeries{Key: keyFrom(s.Labels), Samples: s.Samples})
	}
	return out, nil
}

// ContainerMemoryLimits returns memory limits in bytes from kube-state-metrics.
func (c *Client) ContainerMemoryLimits(ctx context.Context) (map[model.ContainerKey]float64, error) {
	const q = `max by (namespace, pod, container) (kube_pod_container_resource_limits{resource="memory"})`
	series, err := c.Query(ctx, q, time.Now())
	if err != nil {
		return nil, err
	}
	out := make(map[model.ContainerKey]float64, len(series))
	for _, s := range series {
		if len(s.Samples) > 0 {
			out[keyFrom(s.Labels)] = s.Samples[len(s.Samples)-1].V
		}
	}
	return out, nil
}

func keyFrom(l map[string]string) model.ContainerKey {
	return model.ContainerKey{Namespace: l["namespace"], Pod: l["pod"], Container: l["container"]}
}
