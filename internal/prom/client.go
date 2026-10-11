// Package prom is a minimal Prometheus HTTP API client (standard library only).
//
// Every selector the package builds carries the extra matchers from
// Options.Selector, so one shared workspace (AMP, Thanos, Mimir) can hold many
// clusters. Raw Query and QueryRange calls are sent exactly as written.
package prom

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

// DefaultMaxResponseBytes caps one Prometheus response.
const DefaultMaxResponseBytes = 64 << 20

const defaultTimeout = 30 * time.Second

// Query kinds reported to an Observer.
const (
	KindInstant = "instant"
	KindRange   = "range"
)

// Client talks to a Prometheus-compatible server.
//
// With a Cache, results are shared between callers: the returned slice is the
// caller's own, but the Labels maps and Samples slices inside it must be
// treated as read-only.
type Client struct {
	BearerToken string
	base        string
	http        *http.Client
	maxBody     int64
	selector    Matchers
	ksmLimits   bool
	cache       *Cache
	obs         Observer
	now         func() time.Time
}

// Options configures NewClient. The zero value is a plain uncached client that
// takes memory limits from pod specs.
type Options struct {
	BearerToken string
	// Transport replaces the HTTP transport, e.g. awsauth's SigV4 signer for
	// Amazon Managed Prometheus.
	Transport http.RoundTripper
	// Timeout bounds one request; default 30s.
	Timeout time.Duration
	// MaxResponseBytes caps one response; default DefaultMaxResponseBytes.
	MaxResponseBytes int64
	// Selector is injected into every selector the package builds
	// (-prometheus-selector).
	Selector Matchers
	// KSMLimits reads memory limits from kube-state-metrics
	// (-prometheus-ksm-limits). Otherwise ContainerMemoryLimits and PodMemory
	// return no limits and callers take them from the pod (LimitsFromPod).
	KSMLimits bool
	// Cache shares query results between callers; nil disables caching.
	Cache    *Cache
	Observer Observer
}

// New returns a client with the original behaviour: no cache, no extra
// matchers, and memory limits from kube-state-metrics.
func New(baseURL string) *Client {
	return &Client{
		base:      strings.TrimRight(baseURL, "/"),
		http:      &http.Client{Timeout: defaultTimeout},
		maxBody:   DefaultMaxResponseBytes,
		ksmLimits: true,
	}
}

// NewClient returns a client for an http(s) base URL, such as
// http://prometheus.monitoring.svc:9090 or an AMP workspace URL ending in
// /workspaces/<id>.
func NewClient(baseURL string, opts Options) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("prometheus URL must be http(s)://host[:port][/path], got %q", baseURL)
	}
	if opts.Timeout <= 0 {
		opts.Timeout = defaultTimeout
	}
	if opts.MaxResponseBytes <= 0 {
		opts.MaxResponseBytes = DefaultMaxResponseBytes
	}
	return &Client{
		BearerToken: opts.BearerToken,
		base:        strings.TrimRight(baseURL, "/"),
		http:        &http.Client{Timeout: opts.Timeout, Transport: opts.Transport},
		maxBody:     opts.MaxResponseBytes,
		selector:    opts.Selector,
		ksmLimits:   opts.KSMLimits,
		cache:       opts.Cache,
		obs:         opts.Observer,
	}, nil
}

// BaseURL is the server the client queries.
func (c *Client) BaseURL() string { return c.base }

// Selector is the extra matchers injected into built selectors.
func (c *Client) Selector() Matchers { return c.selector }

// KSMLimits reports whether memory limits come from kube-state-metrics.
func (c *Client) KSMLimits() bool { return c.ksmLimits }

func (c *Client) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
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
			Value  *point            `json:"value"`
			Values []point           `json:"values"`
		} `json:"result"`
	} `json:"data"`
}

// QueryRange runs a range query. With a cache, end is aligned down to the step
// (start moves with it) so callers within one step share a result.
func (c *Client) QueryRange(ctx context.Context, query string, start, end time.Time, step time.Duration) ([]Series, error) {
	return c.queryRange(ctx, query, start, end, step, c.cache)
}

func (c *Client) queryRange(ctx context.Context, query string, start, end time.Time, step time.Duration, cache *Cache) ([]Series, error) {
	if cache != nil && step > 0 {
		aligned := alignDown(end, step)
		start, end = start.Add(aligned.Sub(end)), aligned
	}
	v := url.Values{}
	v.Set("query", query)
	v.Set("start", formatTime(start))
	v.Set("end", formatTime(end))
	v.Set("step", strconv.FormatFloat(step.Seconds(), 'f', -1, 64))
	return c.do(ctx, cache, KindRange, "/api/v1/query_range", v, step)
}

// Query runs an instant query at the given time. With a cache, the time is
// aligned down to the instant TTL so callers within it share a result.
func (c *Client) Query(ctx context.Context, query string, at time.Time) ([]Series, error) {
	return c.query(ctx, query, at, c.cache)
}

func (c *Client) query(ctx context.Context, query string, at time.Time, cache *Cache) ([]Series, error) {
	if cache != nil {
		at = alignDown(at, cache.opts.InstantTTL)
	}
	v := url.Values{}
	v.Set("query", query)
	v.Set("time", formatTime(at))
	return c.do(ctx, cache, KindInstant, "/api/v1/query", v, 0)
}

func (c *Client) do(ctx context.Context, cache *Cache, kind, path string, params url.Values, step time.Duration) ([]Series, error) {
	if cache == nil {
		series, _, err := c.fetch(ctx, kind, path, params)
		return series, err
	}
	key := c.base + path + "?" + params.Encode()
	return cache.do(ctx, key, cache.ttl(kind, step), c.obs, func(ctx context.Context) ([]Series, int64, error) {
		return c.fetch(ctx, kind, path, params)
	})
}

// fetch sends one request and returns the parsed series with their estimated
// in-memory size.
func (c *Client) fetch(ctx context.Context, kind, path string, params url.Values) ([]Series, int64, error) {
	started := time.Now()
	if c.obs != nil {
		defer func() { c.obs.ObserveQuery(kind, time.Since(started)) }()
	}
	// POST keeps long queries out of URL length limits.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.BearerToken)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("prometheus request: %w", err)
	}
	defer resp.Body.Close()
	limit := c.maxBody
	if limit <= 0 {
		limit = DefaultMaxResponseBytes
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, 0, fmt.Errorf("read prometheus response: %w", err)
	}
	if int64(len(body)) > limit {
		return nil, 0, fmt.Errorf("%w: more than %d bytes", ErrResponseTooLarge, limit)
	}
	return parseResponse(resp.StatusCode, body)
}

// ErrResponseTooLarge is returned when a response exceeds the client's cap.
var ErrResponseTooLarge = errors.New("prometheus response too large")

func parseResponse(status int, body []byte) ([]Series, int64, error) {
	var r apiResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, 0, fmt.Errorf("prometheus returned HTTP %d with non-JSON body", status)
	}
	if status != http.StatusOK || r.Status != "success" {
		return nil, 0, fmt.Errorf("prometheus error (HTTP %d): %s: %s", status, r.ErrorType, r.Error)
	}

	out := make([]Series, 0, len(r.Data.Result))
	var size int64
	for _, res := range r.Data.Result {
		s := Series{Labels: res.Metric}
		points := res.Values
		if res.Value != nil {
			points = append(points, *res.Value)
		}
		if len(points) > 0 {
			s.Samples = make([]model.Sample, 0, len(points))
		}
		for _, p := range points {
			if p.ok { // NaN, Inf or malformed: skip rather than poison a fit
				s.Samples = append(s.Samples, p.s)
			}
		}
		size += seriesSize(s)
		out = append(out, s)
	}
	return out, size, nil
}

// seriesSize estimates the heap a parsed series holds, for the cache's byte
// budget: map and slice headers, label strings, and 32 bytes per sample.
func seriesSize(s Series) int64 {
	n := int64(96 + 32*cap(s.Samples))
	for k, v := range s.Labels {
		n += int64(len(k) + len(v) + 48)
	}
	return n
}

// point is one [timestamp, "value"] pair. Decoding it by hand avoids the
// []any allocations of the generic decoder; malformed, NaN and Inf points
// decode with ok false and are dropped.
type point struct {
	s  model.Sample
	ok bool
}

func (p *point) UnmarshalJSON(b []byte) error {
	*p = point{}
	b = bytes.TrimSpace(b)
	if len(b) < 2 || b[0] != '[' || b[len(b)-1] != ']' {
		return nil
	}
	inner := b[1 : len(b)-1]
	comma := bytes.IndexByte(inner, ',')
	if comma < 0 {
		return nil
	}
	ts, err := strconv.ParseFloat(string(bytes.TrimSpace(inner[:comma])), 64)
	if err != nil {
		return nil
	}
	raw := bytes.TrimSpace(inner[comma+1:])
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return nil
	}
	val, err := strconv.ParseFloat(string(raw[1:len(raw)-1]), 64)
	if err != nil || math.IsNaN(val) || math.IsInf(val, 0) {
		return nil
	}
	sec, frac := math.Modf(ts)
	p.s = model.Sample{T: time.Unix(int64(sec), int64(frac*1e9)).UTC(), V: val}
	p.ok = true
	return nil
}

func formatTime(t time.Time) string {
	return strconv.FormatFloat(float64(t.UnixNano())/1e9, 'f', 3, 64)
}

// alignDown rounds t down to a multiple of d since the Unix epoch.
func alignDown(t time.Time, d time.Duration) time.Time {
	if d <= 0 {
		return t
	}
	ns := t.UnixNano()
	return time.Unix(0, ns-ns%int64(d)).UTC()
}

const memMetric = "container_memory_working_set_bytes"

// ContainerMemory returns the working-set memory of every container over the
// lookback window. cAdvisor series carry a per-container-instance `id` label
// that changes on restart, so max-by-aggregation stitches the lifetimes of one
// container into a single continuous series, which is what the sawtooth
// detector needs. On large clusters prefer the LeakScanner, which fetches only
// candidate containers.
func (c *Client) ContainerMemory(ctx context.Context, lookback, step time.Duration) ([]model.ContainerSeries, error) {
	q := `max by (namespace, pod, container) (` + c.sel(memMetric, `container!=""`, `container!="POD"`) + `)`
	end := c.clock()
	series, err := c.QueryRange(ctx, q, end.Add(-lookback), end, step)
	if err != nil {
		return nil, err
	}
	return toContainerSeries(series), nil
}

// ContainerMemoryLimits returns memory limits in bytes from kube-state-metrics.
// Without KSMLimits it returns an empty map: limits then come from pod specs
// (LimitsFromPods), which follow in-place resizes.
func (c *Client) ContainerMemoryLimits(ctx context.Context) (map[model.ContainerKey]float64, error) {
	if !c.ksmLimits {
		return map[model.ContainerKey]float64{}, nil
	}
	q := `max by (namespace, pod, container) (` + c.sel("kube_pod_container_resource_limits", `resource="memory"`) + `)`
	series, err := c.Query(ctx, q, c.clock())
	if err != nil {
		return nil, err
	}
	return lastValues(series), nil
}

func toContainerSeries(series []Series) []model.ContainerSeries {
	out := make([]model.ContainerSeries, 0, len(series))
	for _, s := range series {
		out = append(out, model.ContainerSeries{Key: keyFrom(s.Labels), Samples: s.Samples})
	}
	return out
}

func lastValues(series []Series) map[model.ContainerKey]float64 {
	out := make(map[model.ContainerKey]float64, len(series))
	for _, s := range series {
		if len(s.Samples) > 0 {
			out[keyFrom(s.Labels)] = s.Samples[len(s.Samples)-1].V
		}
	}
	return out
}

func keyFrom(l map[string]string) model.ContainerKey {
	return model.ContainerKey{Namespace: l["namespace"], Pod: l["pod"], Container: l["container"]}
}
