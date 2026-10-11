// Package hist is a mergeable latency histogram with logarithmic buckets
// (about 1% relative error), safe for concurrent use.
package hist

import (
	"encoding/json"
	"math"
	"sort"
	"sync"
	"time"
)

const (
	minMs  = 0.01 // values below land in bucket 0
	growth = 1.02 // bucket width ratio: quantiles are within ±1%
)

var logGrowth = math.Log(growth)

// Hist records durations in milliseconds.
type Hist struct {
	mu      sync.Mutex
	buckets map[int]int64
	n       int64
	sum     float64
	min     float64
	max     float64
}

// New returns an empty histogram.
func New() *Hist { return &Hist{buckets: map[int]int64{}, min: math.Inf(1)} }

func bucketOf(ms float64) int {
	if ms <= minMs {
		return 0
	}
	return int(math.Log(ms/minMs)/logGrowth) + 1
}

// upper is the geometric middle of bucket b, the value reported for it.
func mid(b int) float64 {
	if b == 0 {
		return minMs
	}
	lo := minMs * math.Pow(growth, float64(b-1))
	return lo * math.Sqrt(growth)
}

// Add records one value in milliseconds.
func (h *Hist) Add(ms float64) {
	h.mu.Lock()
	h.buckets[bucketOf(ms)]++
	h.n++
	h.sum += ms
	h.min = math.Min(h.min, ms)
	h.max = math.Max(h.max, ms)
	h.mu.Unlock()
}

// AddDuration records d.
func (h *Hist) AddDuration(d time.Duration) { h.Add(float64(d.Microseconds()) / 1000) }

// Merge adds o's samples to h.
func (h *Hist) Merge(o *Hist) {
	o.mu.Lock()
	b := make(map[int]int64, len(o.buckets))
	for k, v := range o.buckets {
		b[k] = v
	}
	n, sum, mn, mx := o.n, o.sum, o.min, o.max
	o.mu.Unlock()
	h.mu.Lock()
	for k, v := range b {
		h.buckets[k] += v
	}
	h.n += n
	h.sum += sum
	h.min = math.Min(h.min, mn)
	h.max = math.Max(h.max, mx)
	h.mu.Unlock()
}

// Count returns the number of samples.
func (h *Hist) Count() int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.n
}

// Quantile returns the q-quantile (0..1) in ms, 0 when empty. The exact
// minimum and maximum are returned at the ends.
func (h *Hist) Quantile(q float64) float64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.quantile(q)
}

func (h *Hist) quantile(q float64) float64 {
	if h.n == 0 {
		return 0
	}
	if q <= 0 {
		return h.min
	}
	if q >= 1 {
		return h.max
	}
	keys := make([]int, 0, len(h.buckets))
	for k := range h.buckets {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	rank := int64(math.Ceil(q * float64(h.n)))
	var acc int64
	for _, k := range keys {
		acc += h.buckets[k]
		if acc >= rank {
			v := mid(k)
			return math.Max(h.min, math.Min(h.max, v))
		}
	}
	return h.max
}

// Summary is the JSON form.
type Summary struct {
	Count int64   `json:"count"`
	Mean  float64 `json:"meanMs"`
	Min   float64 `json:"minMs"`
	P50   float64 `json:"p50Ms"`
	P90   float64 `json:"p90Ms"`
	P95   float64 `json:"p95Ms"`
	P99   float64 `json:"p99Ms"`
	Max   float64 `json:"maxMs"`
}

// Summarize returns count, mean and the usual quantiles.
func (h *Hist) Summarize() Summary {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.n == 0 {
		return Summary{}
	}
	r := func(v float64) float64 { return math.Round(v*100) / 100 }
	return Summary{
		Count: h.n, Mean: r(h.sum / float64(h.n)), Min: r(h.min),
		P50: r(h.quantile(0.50)), P90: r(h.quantile(0.90)), P95: r(h.quantile(0.95)), P99: r(h.quantile(0.99)), Max: r(h.max),
	}
}

// MarshalJSON writes the summary.
func (h *Hist) MarshalJSON() ([]byte, error) { return json.Marshal(h.Summarize()) }
