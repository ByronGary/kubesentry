package report

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Instant runs an instant query at t and returns the value per series, keyed
// by the value of label by ("" for a single unlabelled result).
func (p *Prom) Instant(ctx context.Context, q string, t time.Time, by string) (map[string]float64, error) {
	params := map[string]string{"query": q, "time": strconv.FormatInt(t.Unix(), 10)}
	b, err := p.CS.CoreV1().Services(p.Namespace).ProxyGet("http", p.Service, p.Port, "/api/v1/query", params).DoRaw(ctx)
	if err != nil {
		return nil, fmt.Errorf("prometheus %q: %w", q, err)
	}
	var r promResp
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	if r.Status != "success" {
		return nil, fmt.Errorf("prometheus %q: %s", q, r.Error)
	}
	out := map[string]float64{}
	for _, res := range r.Data.Result {
		f, err := strconv.ParseFloat(fmt.Sprint(res.Value[1]), 64)
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			continue
		}
		out[res.Metric[by]] += f
	}
	return out, nil
}

// Window is a named time range (a users stage, a step, a chaos scenario).
type Window struct {
	Name string    `json:"name"`
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

// ServerMetrics is what kubesentry and the components around it did during
// one window, from Prometheus (30s scrapes).
type ServerMetrics struct {
	Window
	Seconds float64 `json:"seconds"`
	// SubjectAccessReviews kubesentry sent, per second, and by result.
	SARPerSec   float64            `json:"sarPerSec"`
	SARByResult map[string]float64 `json:"sarByResult,omitempty"`
	// Authorization decision cache and HTTP response cache lookups by result,
	// and the share answered from the cache (hit / all).
	AuthzCache    map[string]float64 `json:"authzCache,omitempty"`
	AuthzHitRatio float64            `json:"authzCacheHitRatio"`
	HTTPCache     map[string]float64 `json:"httpCache,omitempty"`
	HTTPHitRatio  float64            `json:"httpCacheHitRatio"`
	// kubesentry → API server requests per second (its own counter), by verb.
	KubePerSec float64            `json:"kubeRequestsPerSec"`
	KubeByVerb map[string]float64 `json:"kubeRequestsByVerb,omitempty"`
	// Requests kubesentry served, per second, by code.
	HTTPPerSec float64            `json:"httpRequestsPerSec"`
	HTTPByCode map[string]float64 `json:"httpRequestsByCode,omitempty"`
	// Per replica (pod name): max RSS and working set (cAdvisor), max Go heap,
	// max goroutines, CPU cores avg and max (1m rate).
	RSSMaxMiB        map[string]float64 `json:"rssMaxMiB,omitempty"`
	WorkingSetMaxMiB map[string]float64 `json:"workingSetMaxMiB,omitempty"`
	HeapMaxMiB       map[string]float64 `json:"heapMaxMiB,omitempty"`
	GoroutinesMax    map[string]float64 `json:"goroutinesMax,omitempty"`
	CPUAvg           map[string]float64 `json:"cpuAvg,omitempty"`
	CPUMax           map[string]float64 `json:"cpuMax,omitempty"`
	// Snapshot age as scraped (per replica p99 and max; the worst replica).
	SnapshotAgeP99 float64 `json:"snapshotAgeP99Seconds"`
	SnapshotAgeMax float64 `json:"snapshotAgeMaxSeconds"`
	// Postgres and the oauth2-proxy sidecars (per pod).
	PostgresCPUAvg    float64            `json:"postgresCpuAvg"`
	PostgresCPUMax    float64            `json:"postgresCpuMax"`
	PostgresMemMaxMiB float64            `json:"postgresMemMaxMiB"`
	ProxyCPUAvg       map[string]float64 `json:"oauth2ProxyCpuAvg,omitempty"`
	ProxyCPUMax       map[string]float64 `json:"oauth2ProxyCpuMax,omitempty"`
	ProxyMemMaxMiB    map[string]float64 `json:"oauth2ProxyMemMaxMiB,omitempty"`
	ProxyThrottled    map[string]float64 `json:"oauth2ProxyThrottledRatio,omitempty"`
	// Audit pipeline.
	CloudWatchLagMax float64            `json:"cloudwatchLagMaxSeconds"`
	CloudWatchLagAvg float64            `json:"cloudwatchLagAvgSeconds"`
	AuditQueueMax    float64            `json:"auditQueueMax"`
	AuditIngested    map[string]float64 `json:"auditIngested,omitempty"`
	AuditStoreErrors float64            `json:"auditStoreErrors"`
	// All clients → API server, per second.
	APIServerPerSec float64  `json:"apiserverRequestsPerSec"`
	Errors          []string `json:"errors,omitempty"`
}

func ratio(m map[string]float64, hit string) float64 {
	t := 0.0
	for _, v := range m {
		t += v
	}
	if t == 0 {
		return 0
	}
	return m[hit] / t
}

func sumOf(m map[string]float64) float64 {
	t := 0.0
	for _, v := range m {
		t += v
	}
	return t
}

func round(m map[string]float64, f float64) map[string]float64 {
	for k, v := range m {
		m[k] = math.Round(v*f) / f
	}
	return m
}

// Collect queries Prometheus for one window.
func Collect(ctx context.Context, p *Prom, w Window) ServerMetrics {
	m := ServerMetrics{Window: w, Seconds: w.To.Sub(w.From).Seconds()}
	d := int(math.Max(60, math.Round(m.Seconds)))
	at := w.To
	q := func(query, by string) map[string]float64 {
		v, err := p.Instant(ctx, strings.ReplaceAll(query, "%ds", strconv.Itoa(d)+"s"), at, by)
		if err != nil {
			m.Errors = append(m.Errors, err.Error())
			return map[string]float64{}
		}
		return v
	}
	one := func(query string) float64 { return q(query, "")[""] }
	const ks = `job="kubesentry-ops"`
	const server = `namespace="kubesentry",container="server"`
	const proxy = `namespace="kubesentry",container="oauth2-proxy"`
	const pg = `namespace="stress-pg",container="postgres"`
	secs := float64(d)

	m.SARByResult = round(q(`sum by (result) (increase(kubesentry_authz_reviews_total[%ds]))`, "result"), 1)
	m.SARPerSec = sumOf(m.SARByResult) / secs
	m.AuthzCache = round(q(`sum by (result) (increase(kubesentry_authz_cache_total[%ds]))`, "result"), 1)
	m.AuthzHitRatio = ratio(m.AuthzCache, "hit")
	m.HTTPCache = round(q(`sum by (result) (increase(kubesentry_http_cache_total[%ds]))`, "result"), 1)
	m.HTTPHitRatio = ratio(m.HTTPCache, "hit")
	m.KubeByVerb = round(q(`sum by (verb) (increase(kubesentry_kube_requests_total[%ds]))`, "verb"), 1)
	m.KubePerSec = sumOf(m.KubeByVerb) / secs
	m.HTTPByCode = round(q(`sum by (code) (increase(kubesentry_http_requests_total[%ds]))`, "code"), 1)
	m.HTTPPerSec = sumOf(m.HTTPByCode) / secs

	m.RSSMaxMiB = round(q(`max by (pod) (max_over_time(container_memory_rss{`+server+`}[%ds])) / 1048576`, "pod"), 1)
	m.WorkingSetMaxMiB = round(q(`max by (pod) (max_over_time(container_memory_working_set_bytes{`+server+`}[%ds])) / 1048576`, "pod"), 1)
	m.HeapMaxMiB = round(q(`max by (pod) (max_over_time(go_memstats_heap_alloc_bytes{`+ks+`}[%ds])) / 1048576`, "pod"), 1)
	m.GoroutinesMax = q(`max by (pod) (max_over_time(go_goroutines{`+ks+`}[%ds]))`, "pod")
	m.CPUAvg = round(q(`max by (pod) (avg_over_time(rate(container_cpu_usage_seconds_total{`+server+`}[1m])[%ds:30s]))`, "pod"), 1000)
	m.CPUMax = round(q(`max by (pod) (max_over_time(rate(container_cpu_usage_seconds_total{`+server+`}[1m])[%ds:30s]))`, "pod"), 1000)
	m.SnapshotAgeP99 = one(`max(quantile_over_time(0.99, kubesentry_snapshot_age_seconds{` + ks + `}[%ds]))`)
	m.SnapshotAgeMax = one(`max(max_over_time(kubesentry_snapshot_age_seconds{` + ks + `}[%ds]))`)

	m.PostgresCPUAvg = one(`avg_over_time(sum(rate(container_cpu_usage_seconds_total{` + pg + `}[1m]))[%ds:30s])`)
	m.PostgresCPUMax = one(`max_over_time(sum(rate(container_cpu_usage_seconds_total{` + pg + `}[1m]))[%ds:30s])`)
	m.PostgresMemMaxMiB = one(`max_over_time(sum(container_memory_working_set_bytes{` + pg + `})[%ds:30s]) / 1048576`)
	m.ProxyCPUAvg = round(q(`max by (pod) (avg_over_time(rate(container_cpu_usage_seconds_total{`+proxy+`}[1m])[%ds:30s]))`, "pod"), 1000)
	m.ProxyCPUMax = round(q(`max by (pod) (max_over_time(rate(container_cpu_usage_seconds_total{`+proxy+`}[1m])[%ds:30s]))`, "pod"), 1000)
	m.ProxyMemMaxMiB = round(q(`max by (pod) (max_over_time(container_memory_working_set_bytes{`+proxy+`}[%ds])) / 1048576`, "pod"), 1)
	m.ProxyThrottled = round(q(`sum by (pod) (increase(container_cpu_cfs_throttled_periods_total{`+proxy+`}[%ds])) / sum by (pod) (increase(container_cpu_cfs_periods_total{`+proxy+`}[%ds]))`, "pod"), 1000)

	m.CloudWatchLagMax = one(`max(max_over_time(kubesentry_cloudwatch_lag_seconds{` + ks + `}[%ds]))`)
	m.CloudWatchLagAvg = one(`max(avg_over_time(kubesentry_cloudwatch_lag_seconds{` + ks + `}[%ds]))`)
	m.AuditQueueMax = one(`max(max_over_time(kubesentry_audit_queue_depth{` + ks + `}[%ds]))`)
	m.AuditIngested = round(q(`sum by (source) (increase(kubesentry_audit_ingested_total[%ds]))`, "source"), 1)
	m.AuditStoreErrors = math.Round(one(`sum(increase(kubesentry_audit_store_errors_total[%ds]))`))
	m.APIServerPerSec = one(`sum(increase(apiserver_request_total[%ds]))`) / secs
	return m
}

// CollectAll collects every window.
func CollectAll(ctx context.Context, p *Prom, ws []Window) []ServerMetrics {
	out := make([]ServerMetrics, 0, len(ws))
	for _, w := range ws {
		out = append(out, Collect(ctx, p, w))
	}
	return out
}

func podList(m map[string]float64, f string) string {
	if len(m) == 0 {
		return "-"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf(f, m[k]))
	}
	return strings.Join(parts, " / ")
}

func maxOf(m map[string]float64) float64 {
	x := 0.0
	for _, v := range m {
		x = math.Max(x, v)
	}
	return x
}

// ServerMarkdown renders a table of windows.
func ServerMarkdown(ms []ServerMetrics) string {
	var b strings.Builder
	b.WriteString("| Window | SAR/s | authz cache hit | HTTP cache hit | kubesentry→API req/s | served req/s | RSS max MiB (per replica) | working set max MiB | goroutines max | kubesentry CPU avg / max (per replica) | snapshot age p99 / max | Postgres CPU avg / max, mem MiB | oauth2-proxy CPU avg / max (per pod) | oauth2-proxy mem MiB | oauth2-proxy throttled | CloudWatch lag max | audit queue max |\n")
	b.WriteString("|---|---:|---:|---:|---:|---:|---|---|---|---|---|---|---|---|---|---:|---:|\n")
	for _, m := range ms {
		cpu := podList(m.CPUAvg, "%.2f") + " ; " + podList(m.CPUMax, "%.2f")
		pcpu := podList(m.ProxyCPUAvg, "%.2f") + " ; " + podList(m.ProxyCPUMax, "%.2f")
		fmt.Fprintf(&b, "| %s | %.1f | %.0f%% | %.0f%% | %.2f | %.1f | %s | %s | %s | %s | %.1fs / %.1fs | %.2f / %.2f, %.0f | %s | %s | %s | %.0fs | %.0f |\n",
			m.Name, m.SARPerSec, 100*m.AuthzHitRatio, 100*m.HTTPHitRatio, m.KubePerSec, m.HTTPPerSec,
			podList(m.RSSMaxMiB, "%.0f"), podList(m.WorkingSetMaxMiB, "%.0f"), podList(m.GoroutinesMax, "%.0f"), cpu,
			m.SnapshotAgeP99, m.SnapshotAgeMax, m.PostgresCPUAvg, m.PostgresCPUMax, m.PostgresMemMaxMiB,
			pcpu, podList(m.ProxyMemMaxMiB, "%.0f"), podList(m.ProxyThrottled, "%.2f"), m.CloudWatchLagMax, m.AuditQueueMax)
	}
	return b.String()
}
