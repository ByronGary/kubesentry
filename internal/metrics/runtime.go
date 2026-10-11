package metrics

import (
	"bufio"
	"net/http"
	"runtime"
	rtm "runtime/metrics"
	"time"
)

// runtimeMetric maps one runtime/metrics sample to an exposed metric.
type runtimeMetric struct {
	name, help, typ, source string
}

var runtimeMetrics = []runtimeMetric{
	{"go_goroutines", "Number of goroutines that currently exist.", "gauge", "/sched/goroutines:goroutines"},
	{"go_memstats_heap_alloc_bytes", "Bytes of allocated heap objects.", "gauge", "/memory/classes/heap/objects:bytes"},
	{"go_memstats_sys_bytes", "Bytes of memory obtained from the OS.", "gauge", "/memory/classes/total:bytes"},
	{"go_gc_heap_goal_bytes", "Heap size target for the end of the GC cycle.", "gauge", "/gc/heap/goal:bytes"},
	{"go_gc_gomemlimit_bytes", "Go runtime memory limit (GOMEMLIMIT).", "gauge", "/gc/gomemlimit:bytes"},
	{"go_gc_cycles_total", "Completed GC cycles.", "counter", "/gc/cycles/total:gc-cycles"},
	{"go_gc_heap_allocs_bytes_total", "Cumulative bytes allocated to the heap.", "counter", "/gc/heap/allocs:bytes"},
	{"go_gc_cpu_seconds_total", "Estimated CPU time spent in the garbage collector.", "counter", "/cpu/classes/gc/total:cpu-seconds"},
}

// runtimeCollector reads the Go runtime at scrape time.
type runtimeCollector struct {
	metrics []runtimeMetric
	start   float64
}

// RegisterRuntime adds Go runtime gauges and counters (goroutines, heap, GC)
// plus go_info and process_start_time_seconds to r.
func (r *Registry) RegisterRuntime() {
	supported := map[string]bool{}
	for _, d := range rtm.All() {
		supported[d.Name] = true
	}
	c := &runtimeCollector{start: float64(time.Now().UnixNano()) / 1e9}
	for _, m := range runtimeMetrics {
		if supported[m.source] {
			c.metrics = append(c.metrics, m)
		}
	}
	r.register(c)
}

func (c *runtimeCollector) name() string { return "go_" } // sorts before every go_* metric

func (c *runtimeCollector) write(w *bufio.Writer) {
	samples := make([]rtm.Sample, len(c.metrics))
	for i, m := range c.metrics {
		samples[i].Name = m.source
	}
	rtm.Read(samples)
	for i, m := range c.metrics {
		var v float64
		switch samples[i].Value.Kind() {
		case rtm.KindUint64:
			v = float64(samples[i].Value.Uint64())
		case rtm.KindFloat64:
			v = samples[i].Value.Float64()
		default:
			continue
		}
		d := desc{fqName: m.name, help: m.help, typ: m.typ}
		d.header(w)
		sample(w, m.name, nil, nil, "", "", v)
	}
	info := desc{fqName: "go_info", help: "Information about the Go environment.", typ: "gauge", labels: []string{"version"}}
	info.header(w)
	sample(w, "go_info", info.labels, []string{runtime.Version()}, "", "", 1)
	start := desc{fqName: "process_start_time_seconds", help: "Start time of the process since the Unix epoch in seconds.", typ: "gauge"}
	start.header(w)
	sample(w, start.fqName, nil, nil, "", "", c.start)
}

// NewCounter registers a counter without labels on r.
func (r *Registry) NewCounter(name, help string) *Counter { return r.NewCounterVec(name, help).With() }

// NewGauge registers a gauge without labels on r.
func (r *Registry) NewGauge(name, help string) *Gauge { return r.NewGaugeVec(name, help).With() }

// NewHistogram registers a histogram without labels on r.
func (r *Registry) NewHistogram(name, help string, buckets []float64) *Histogram {
	return r.NewHistogramVec(name, help, buckets).With()
}

// NewCounterVec registers a counter on the Default registry.
func NewCounterVec(name, help string, labels ...string) *CounterVec {
	return Default.NewCounterVec(name, help, labels...)
}

// NewGaugeVec registers a gauge on the Default registry.
func NewGaugeVec(name, help string, labels ...string) *GaugeVec {
	return Default.NewGaugeVec(name, help, labels...)
}

// NewHistogramVec registers a histogram on the Default registry.
func NewHistogramVec(name, help string, buckets []float64, labels ...string) *HistogramVec {
	return Default.NewHistogramVec(name, help, buckets, labels...)
}

// NewCounter registers a counter without labels on the Default registry.
func NewCounter(name, help string) *Counter { return Default.NewCounter(name, help) }

// NewGauge registers a gauge without labels on the Default registry.
func NewGauge(name, help string) *Gauge { return Default.NewGauge(name, help) }

// NewHistogram registers a histogram without labels on the Default registry.
func NewHistogram(name, help string, buckets []float64) *Histogram {
	return Default.NewHistogram(name, help, buckets)
}

// Handler serves the Default registry.
func Handler() http.Handler { return Default.Handler() }
