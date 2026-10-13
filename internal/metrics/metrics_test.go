package metrics

import (
	"fmt"
	"io"
	"math"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestExpositionGolden(t *testing.T) {
	r := NewRegistry()
	req := r.NewCounterVec("app_requests_total", "Requests.\nSecond line with a \\ backslash.", "route", "code")
	req.With("pods", "200").Add(3)
	req.With("pods", "500").Inc()
	req.With(`we"ird\path`+"\n", "200").Inc()
	req.With("pods", "200").Add(-5) // ignored: counters only go up

	g := r.NewGauge("app_inflight", "In flight.")
	g.Inc()
	g.Inc()
	g.Dec()

	f := r.NewGaugeVec("app_objects", "Objects.", "resource")
	f.With("pods").Set(1.5)
	f.With("nodes").SetFunc(func() float64 { return math.Inf(1) })

	h := r.NewHistogramVec("app_latency_seconds", "Latency.", []float64{1, 0.1, 0.5}, "route")
	for _, v := range []float64{0.05, 0.1, 0.3, 2} {
		h.With("pods").Observe(v)
	}
	r.NewCounterVec("app_unused_total", "Never touched: left out.", "x")
	r.NewCounter("app_errors_total", "Errors.")

	var b strings.Builder
	if err := r.WriteText(&b); err != nil {
		t.Fatal(err)
	}
	want := `# HELP app_errors_total Errors.
# TYPE app_errors_total counter
app_errors_total 0
# HELP app_inflight In flight.
# TYPE app_inflight gauge
app_inflight 1
# HELP app_latency_seconds Latency.
# TYPE app_latency_seconds histogram
app_latency_seconds_bucket{route="pods",le="0.1"} 2
app_latency_seconds_bucket{route="pods",le="0.5"} 3
app_latency_seconds_bucket{route="pods",le="1"} 3
app_latency_seconds_bucket{route="pods",le="+Inf"} 4
app_latency_seconds_sum{route="pods"} 2.45
app_latency_seconds_count{route="pods"} 4
# HELP app_objects Objects.
# TYPE app_objects gauge
app_objects{resource="nodes"} +Inf
app_objects{resource="pods"} 1.5
# HELP app_requests_total Requests.\nSecond line with a \\ backslash.
# TYPE app_requests_total counter
app_requests_total{route="pods",code="200"} 3
app_requests_total{route="pods",code="500"} 1
app_requests_total{route="we\"ird\\path\n",code="200"} 1
`
	if got := b.String(); got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}

	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain; version=0.0.4") {
		t.Fatalf("content type %q", ct)
	}
	if rec.Body.String() != want {
		t.Fatal("handler output differs from WriteText")
	}
}

func TestRegistrationPanics(t *testing.T) {
	for name, fn := range map[string]func(r *Registry){
		"duplicate":    func(r *Registry) { r.NewGauge("a", ""); r.NewCounter("a", "") },
		"bad name":     func(r *Registry) { r.NewGauge("1abc", "") },
		"bad label":    func(r *Registry) { r.NewGaugeVec("a", "", "bad-label") },
		"reserved le":  func(r *Registry) { r.NewHistogramVec("a", "", nil, "le") },
		"label arity":  func(r *Registry) { r.NewCounterVec("a", "", "x").With("1", "2") },
		"dup buckets":  func(r *Registry) { r.NewHistogram("a", "", []float64{1, 1}) },
		"reserved __":  func(r *Registry) { r.NewGaugeVec("a", "", "__x") },
		"colon label":  func(r *Registry) { r.NewGaugeVec("a", "", "a:b") },
		"empty metric": func(r *Registry) { r.NewGauge("", "") },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: no panic", name)
				}
			}()
			fn(NewRegistry())
		}()
	}
}

func TestSeriesAreBounded(t *testing.T) {
	r := NewRegistry()
	c := r.NewCounterVec("a_total", "", "path")
	for i := range MaxSeries + 50 {
		c.With(fmt.Sprint(i)).Inc()
	}
	if n := len(c.f.children); n != MaxSeries+1 {
		t.Fatalf("%d series", n)
	}
	if v := c.With("_overflow").Value(); v != 50 {
		t.Fatalf("overflow %v", v)
	}
}

func TestConcurrentUpdates(t *testing.T) {
	r := NewRegistry()
	c := r.NewCounterVec("c_total", "", "k")
	h := r.NewHistogram("h", "", []float64{1})
	g := r.NewGauge("g", "")
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 1000 {
				c.With(fmt.Sprint(i % 2)).Inc()
				h.Observe(0.5)
				g.Add(1)
				_ = r.WriteText(io.Discard)
			}
		}()
	}
	wg.Wait()
	if c.With("0").Value()+c.With("1").Value() != 8000 || h.Count() != 8000 || g.Value() != 8000 {
		t.Fatalf("lost updates: %v %v %d %v", c.With("0").Value(), c.With("1").Value(), h.Count(), g.Value())
	}
}

func TestDefaultRegistry(t *testing.T) {
	before := AuthzReviews.With("allowed").Value()
	HTTPRequests.With("pods", "200").Inc()
	AuthzObserver.ObserveReview("allowed")
	AuthzObserver.ObserveCache("hit")
	if AuthzReviews.With("allowed").Value() != before+1 {
		t.Fatal("observer did not count")
	}
	var b strings.Builder
	if err := Default.WriteText(&b); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		`kubesentry_http_requests_total{route="pods",code="200"} `,
		`kubesentry_authz_reviews_total{result="allowed"} `,
		`kubesentry_authz_cache_total{result="hit"} `,
		"# TYPE kubesentry_http_inflight gauge\nkubesentry_http_inflight 0\n",
		"# TYPE kubesentry_audit_store_errors_total counter\n",
		"# TYPE kubesentry_snapshot_build_seconds histogram\n",
		"# TYPE go_goroutines gauge\ngo_goroutines ",
		"# TYPE go_gc_cycles_total counter\n",
		"# TYPE go_memstats_heap_alloc_bytes gauge\n",
		`go_info{version="go`,
		"process_start_time_seconds ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	// Every exported name from the contract is present.
	for _, name := range []string{
		"kubesentry_http_requests_total", "kubesentry_http_request_duration_seconds", "kubesentry_http_inflight",
		"kubesentry_snapshot_build_seconds", "kubesentry_snapshot_age_seconds", "kubesentry_snapshot_version",
		"kubesentry_informer_objects", "kubesentry_kube_requests_total", "kubesentry_authz_reviews_total",
		"kubesentry_authz_cache_total", "kubesentry_prometheus_query_seconds", "kubesentry_prometheus_cache_total",
		"kubesentry_audit_ingested_total", "kubesentry_audit_queue_depth", "kubesentry_audit_store_errors_total",
		"kubesentry_cloudwatch_lag_seconds", "kubesentry_agent_reports_total", "kubesentry_agent_nodes_reporting",
		"kubesentry_http_rejected_total", "kubesentry_dependency_up", "kubesentry_leak_scan_runs_total",
		"kubesentry_snapshot_last_change_timestamp_seconds", "kubesentry_findings", "kubesentry_alerts_sent_total",
		"kubesentry_alerts_queue_depth", "kubesentry_alerts_evaluation_seconds", "kubesentry_alerts_leader",
	} {
		Default.mu.Lock()
		_, ok := Default.metrics[name]
		Default.mu.Unlock()
		if !ok {
			t.Errorf("%s not registered", name)
		}
	}
}
