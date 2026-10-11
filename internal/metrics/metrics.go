// Package metrics is a small, stdlib-only metrics registry that writes the
// Prometheus text exposition format. It has counters, gauges and histograms
// with labels, plus Go runtime gauges read from runtime/metrics.
//
// The metric names kubesentry exposes are registered once, in names.go, on
// the Default registry; every package uses those variables so names and
// labels stay consistent.
package metrics

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// MaxSeries bounds the label combinations of one metric. Further
// combinations are folded into one series whose label values are all
// "_overflow", so a bug that labels by an unbounded value cannot exhaust
// memory.
const MaxSeries = 10_000

// DefBuckets are latency buckets in seconds, from 5ms to 30s.
var DefBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30}

// Registry holds metrics and writes them out.
type Registry struct {
	mu      sync.Mutex
	metrics map[string]collector
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{metrics: map[string]collector{}} }

// Default is the registry the names in names.go are registered on.
var Default = NewRegistry()

type collector interface {
	name() string
	write(w *bufio.Writer)
}

func (r *Registry) register(c collector) {
	if !validName(c.name()) {
		panic("metrics: invalid metric name " + strconv.Quote(c.name()))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.metrics[c.name()]; dup {
		panic("metrics: duplicate metric " + c.name())
	}
	r.metrics[c.name()] = c
}

// Handler serves the registry in the Prometheus text format.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_ = r.WriteText(w)
	})
}

// WriteText writes every metric, sorted by name, in the text format.
func (r *Registry) WriteText(w io.Writer) error {
	r.mu.Lock()
	cs := make([]collector, 0, len(r.metrics))
	for _, c := range r.metrics {
		cs = append(cs, c)
	}
	r.mu.Unlock()
	sort.Slice(cs, func(i, j int) bool { return cs[i].name() < cs[j].name() })
	bw := bufio.NewWriter(w)
	for _, c := range cs {
		c.write(bw)
	}
	return bw.Flush()
}

// desc is what every metric family has.
type desc struct {
	fqName string
	help   string
	typ    string
	labels []string
}

func (d *desc) name() string { return d.fqName }

func (d *desc) header(w *bufio.Writer) {
	w.WriteString("# HELP ")
	w.WriteString(d.fqName)
	w.WriteByte(' ')
	w.WriteString(escapeHelp(d.help))
	w.WriteString("\n# TYPE ")
	w.WriteString(d.fqName)
	w.WriteByte(' ')
	w.WriteString(d.typ)
	w.WriteByte('\n')
}

// family stores the children of a labelled metric.
type family[T any] struct {
	desc
	mu       sync.RWMutex
	children map[string]*child[T]
	newT     func() *T
	writeFn  func(w *bufio.Writer) // writes the samples
}

// write writes the family; one with no series yet is left out.
func (f *family[T]) write(w *bufio.Writer) {
	f.mu.RLock()
	n := len(f.children)
	f.mu.RUnlock()
	if n == 0 {
		return
	}
	f.header(w)
	f.writeFn(w)
}

type child[T any] struct {
	values []string
	m      *T
}

const labelSep = "\xff"

func (f *family[T]) with(values []string) *T {
	if len(values) != len(f.labels) {
		panic(fmt.Sprintf("metrics: %s takes %d label values, got %d", f.fqName, len(f.labels), len(values)))
	}
	key := strings.Join(values, labelSep)
	f.mu.RLock()
	c, ok := f.children[key]
	f.mu.RUnlock()
	if ok {
		return c.m
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.children[key]; ok {
		return c.m
	}
	if len(f.children) >= MaxSeries {
		values = make([]string, len(f.labels))
		for i := range values {
			values[i] = "_overflow"
		}
		key = strings.Join(values, labelSep)
		if c, ok := f.children[key]; ok {
			return c.m
		}
	}
	c = &child[T]{values: append([]string(nil), values...), m: f.newT()}
	f.children[key] = c
	return c.m
}

func (f *family[T]) sorted() []*child[T] {
	f.mu.RLock()
	cs := make([]*child[T], 0, len(f.children))
	for _, c := range f.children {
		cs = append(cs, c)
	}
	f.mu.RUnlock()
	sort.Slice(cs, func(i, j int) bool {
		a, b := cs[i].values, cs[j].values
		for k := range a {
			if a[k] != b[k] {
				return a[k] < b[k]
			}
		}
		return false
	})
	return cs
}

func newFamily[T any](name, help, typ string, labels []string, newT func() *T) *family[T] {
	for _, l := range labels {
		if !validLabel(l) {
			panic("metrics: invalid label name " + strconv.Quote(l) + " on " + name)
		}
	}
	f := &family[T]{
		desc:     desc{fqName: name, help: help, typ: typ, labels: append([]string(nil), labels...)},
		children: map[string]*child[T]{},
		newT:     newT,
	}
	if len(labels) == 0 {
		f.with(nil) // an unlabelled metric is exposed from the start, at zero
	}
	return f
}

// atomicFloat is a float64 updated with compare-and-swap.
type atomicFloat struct{ bits atomic.Uint64 }

func (a *atomicFloat) add(v float64) {
	for {
		old := a.bits.Load()
		if a.bits.CompareAndSwap(old, math.Float64bits(math.Float64frombits(old)+v)) {
			return
		}
	}
}

func (a *atomicFloat) set(v float64) { a.bits.Store(math.Float64bits(v)) }
func (a *atomicFloat) load() float64 { return math.Float64frombits(a.bits.Load()) }

// Counter only goes up.
type Counter struct{ v atomicFloat }

// Inc adds one.
func (c *Counter) Inc() { c.v.add(1) }

// Add adds v, which must not be negative (negative values are ignored).
func (c *Counter) Add(v float64) {
	if v > 0 {
		c.v.add(v)
	}
}

// Value returns the current count.
func (c *Counter) Value() float64 { return c.v.load() }

// CounterVec is a counter with labels.
type CounterVec struct{ f *family[Counter] }

// NewCounterVec registers a counter on r.
func (r *Registry) NewCounterVec(name, help string, labels ...string) *CounterVec {
	v := &CounterVec{f: newFamily(name, help, "counter", labels, func() *Counter { return &Counter{} })}
	r.register(v.f)
	v.f.writeFn = func(w *bufio.Writer) {
		for _, c := range v.f.sorted() {
			sample(w, name, v.f.labels, c.values, "", "", c.m.Value())
		}
	}
	return v
}

// With returns the counter for the label values, in the order the labels
// were declared.
func (v *CounterVec) With(values ...string) *Counter { return v.f.with(values) }

// Gauge goes up and down, or reports a function's value at scrape time.
type Gauge struct {
	v  atomicFloat
	fn atomic.Pointer[func() float64]
}

// Set sets the value.
func (g *Gauge) Set(v float64) { g.v.set(v) }

// Add adds v (which may be negative).
func (g *Gauge) Add(v float64) { g.v.add(v) }

// Inc adds one.
func (g *Gauge) Inc() { g.v.add(1) }

// Dec subtracts one.
func (g *Gauge) Dec() { g.v.add(-1) }

// SetFunc makes the gauge report fn() at scrape time instead of its stored
// value. fn must be cheap and safe for concurrent use; nil reverts.
func (g *Gauge) SetFunc(fn func() float64) {
	if fn == nil {
		g.fn.Store(nil)
		return
	}
	g.fn.Store(&fn)
}

// Value returns the current value.
func (g *Gauge) Value() float64 {
	if fn := g.fn.Load(); fn != nil {
		return (*fn)()
	}
	return g.v.load()
}

// GaugeVec is a gauge with labels.
type GaugeVec struct{ f *family[Gauge] }

// NewGaugeVec registers a gauge on r.
func (r *Registry) NewGaugeVec(name, help string, labels ...string) *GaugeVec {
	v := &GaugeVec{f: newFamily(name, help, "gauge", labels, func() *Gauge { return &Gauge{} })}
	r.register(v.f)
	v.f.writeFn = func(w *bufio.Writer) {
		for _, c := range v.f.sorted() {
			sample(w, name, v.f.labels, c.values, "", "", c.m.Value())
		}
	}
	return v
}

// With returns the gauge for the label values.
func (v *GaugeVec) With(values ...string) *Gauge { return v.f.with(values) }

// Histogram counts observations into fixed buckets.
type Histogram struct {
	upper  []float64 // shared, sorted
	counts []atomic.Uint64
	sum    atomicFloat
}

// Observe records one value.
func (h *Histogram) Observe(v float64) {
	i := sort.SearchFloat64s(h.upper, v) // first bucket with upper >= v; len = +Inf
	h.counts[i].Add(1)
	h.sum.add(v)
}

// Count returns the number of observations.
func (h *Histogram) Count() uint64 {
	var n uint64
	for i := range h.counts {
		n += h.counts[i].Load()
	}
	return n
}

// HistogramVec is a histogram with labels.
type HistogramVec struct{ f *family[Histogram] }

// NewHistogramVec registers a histogram on r. Nil buckets means DefBuckets.
func (r *Registry) NewHistogramVec(name, help string, buckets []float64, labels ...string) *HistogramVec {
	if buckets == nil {
		buckets = DefBuckets
	}
	upper := append([]float64(nil), buckets...)
	sort.Float64s(upper)
	for i := 1; i < len(upper); i++ {
		if upper[i] == upper[i-1] {
			panic("metrics: duplicate bucket in " + name)
		}
	}
	if n := len(upper); n > 0 && math.IsInf(upper[n-1], +1) {
		upper = upper[:n-1]
	}
	for _, l := range labels {
		if l == "le" {
			panic("metrics: histogram label \"le\" is reserved: " + name)
		}
	}
	v := &HistogramVec{f: newFamily(name, help, "histogram", labels, func() *Histogram {
		return &Histogram{upper: upper, counts: make([]atomic.Uint64, len(upper)+1)}
	})}
	r.register(v.f)
	v.f.writeFn = func(w *bufio.Writer) {
		for _, c := range v.f.sorted() {
			h := c.m
			var cum uint64
			for i := range h.counts {
				cum += h.counts[i].Load()
				le := "+Inf"
				if i < len(h.upper) {
					le = formatFloat(h.upper[i])
				}
				sample(w, name+"_bucket", v.f.labels, c.values, "le", le, float64(cum))
			}
			sample(w, name+"_sum", v.f.labels, c.values, "", "", h.sum.load())
			sample(w, name+"_count", v.f.labels, c.values, "", "", float64(cum))
		}
	}
	return v
}

// With returns the histogram for the label values.
func (v *HistogramVec) With(values ...string) *Histogram { return v.f.with(values) }

// sample writes one line: name{labels,extra="extraV"} value.
func sample(w *bufio.Writer, name string, labels, values []string, extra, extraV string, v float64) {
	w.WriteString(name)
	if len(labels) > 0 || extra != "" {
		w.WriteByte('{')
		for i, l := range labels {
			if i > 0 {
				w.WriteByte(',')
			}
			w.WriteString(l)
			w.WriteString(`="`)
			w.WriteString(escapeLabel(values[i]))
			w.WriteByte('"')
		}
		if extra != "" {
			if len(labels) > 0 {
				w.WriteByte(',')
			}
			w.WriteString(extra)
			w.WriteString(`="`)
			w.WriteString(escapeLabel(extraV))
			w.WriteByte('"')
		}
		w.WriteByte('}')
	}
	w.WriteByte(' ')
	w.WriteString(formatFloat(v))
	w.WriteByte('\n')
}

func formatFloat(v float64) string {
	switch {
	case math.IsInf(v, +1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	case math.IsNaN(v):
		return "NaN"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

var helpEscaper = strings.NewReplacer(`\`, `\\`, "\n", `\n`)
var labelEscaper = strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`)

func escapeHelp(s string) string  { return helpEscaper.Replace(s) }
func escapeLabel(s string) string { return labelEscaper.Replace(s) }

func validName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		ok := r == '_' || r == ':' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (i > 0 && r >= '0' && r <= '9')
		if !ok {
			return false
		}
	}
	return true
}

func validLabel(s string) bool {
	return validName(s) && !strings.Contains(s, ":") && !strings.HasPrefix(s, "__")
}
