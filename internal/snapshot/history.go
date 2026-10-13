package snapshot

import (
	"sync"
	"time"
)

// History defaults: a day in five-minute buckets.
const (
	DefaultHistoryStep    = 5 * time.Minute
	DefaultHistoryBuckets = 288
)

// History keeps the Overview's counters (View.Counts) for the last day, in
// fixed buckets per CountKey, so the dashboard can draw sparklines and say
// what is new since yesterday. It lives in memory: each replica keeps its own
// and a restart starts it afresh.
//
// Memory is bounded by keys × NumSeries × buckets int32 (5.6 KiB per key at
// the defaults), and only keys with something to count hold a ring: a key
// whose counters have been zero for a whole window (a healthy namespace, or
// one deleted a day ago) is dropped. Sums over every key are kept as well, so
// a caller who sees everything costs one ring, not one per namespace.
//
// It is safe for concurrent use.
type History struct {
	step time.Duration
	n    int

	mu      sync.RWMutex
	rings   map[CountKey]*historyRing
	total   historyRing
	started bool
	first   int64 // bucket of the first sample
	last    int64 // bucket of the latest sample
}

// historyRing is one key's buckets: bucket b's series s sits at
// (b mod n)*NumSeries + s.
type historyRing struct {
	vals    []int32
	cur     Counts // the latest sample, carried into later buckets
	nonZero int64  // bucket of the latest non-zero sample
}

// NewHistory keeps buckets of step (DefaultHistoryStep and
// DefaultHistoryBuckets for values below 1).
func NewHistory(step time.Duration, buckets int) *History {
	if step <= 0 {
		step = DefaultHistoryStep
	}
	if buckets <= 0 {
		buckets = DefaultHistoryBuckets
	}
	return &History{step: step, n: buckets, rings: map[CountKey]*historyRing{}}
}

// Step is the bucket width.
func (h *History) Step() time.Duration { return h.step }

// Buckets is how many buckets the window holds.
func (h *History) Buckets() int { return h.n }

// Keys returns how many keys hold a ring (for tests and metrics).
func (h *History) Keys() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.rings)
}

func (h *History) bucket(t time.Time) int64 {
	ns, step := t.UnixNano(), int64(h.step)
	b := ns / step
	if ns%step < 0 {
		b--
	}
	return b
}

func (h *History) newRing() *historyRing {
	return &historyRing{vals: make([]int32, h.n*NumSeries)}
}

func (r *historyRing) slot(b int64, n int) []int32 {
	i := int(b % int64(n))
	if i < 0 {
		i += n
	}
	return r.vals[i*NumSeries : (i+1)*NumSeries]
}

// carry fills the buckets after last up to (not including) b with the
// ring's latest sample: nothing was recorded, so nothing changed.
func (r *historyRing) carry(last, b int64, n int) {
	from := max(last+1, b-int64(n)+1)
	for x := from; x < b; x++ {
		copy(r.slot(x, n), r.cur[:])
	}
}

// put stores c in bucket b: replacing what a previous window left there when
// fresh, otherwise keeping the higher value of each series.
func (r *historyRing) put(b int64, n int, c Counts, fresh bool) {
	s := r.slot(b, n)
	for i, v := range c {
		if fresh || v > s[i] {
			s[i] = v
		}
	}
	r.cur = c
}

// Record adds the view's counters, sampled at its build time.
func (h *History) Record(v *View) { h.RecordCounts(v.Built, v.Counts()) }

// RecordCounts adds one sample of counts taken at `at` (keys left out count
// zero). A bucket keeps the highest value sampled in it, so a spike between
// two looks still shows; buckets without a sample repeat the one before
// them. A sample older than the latest one counts towards the latest bucket.
func (h *History) RecordCounts(at time.Time, counts map[CountKey]Counts) {
	b := h.bucket(at)
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.started {
		h.started, h.first, h.last = true, b, b-1
		h.total = *h.newRing()
	}
	if b < h.last {
		b = h.last
	}
	fresh := b > h.last
	var sum Counts
	for k, r := range h.rings {
		c := counts[k]
		r.carry(h.last, b, h.n)
		r.put(b, h.n, c, fresh)
		if !c.IsZero() {
			r.nonZero = b
		} else if b-r.nonZero >= int64(h.n) {
			delete(h.rings, k) // nothing but zeros in the whole window
		}
	}
	for k, c := range counts {
		for i, v := range c {
			sum[i] += v
		}
		if _, ok := h.rings[k]; ok || c.IsZero() {
			continue
		}
		// A new key: zero until now, which a fresh ring already says.
		r := h.newRing()
		r.put(b, h.n, c, true)
		r.nonZero = b
		h.rings[k] = r
	}
	h.total.carry(h.last, b, h.n)
	h.total.put(b, h.n, sum, fresh)
	h.last = b
}

// HistoryWindow is the last day of counters, summed over the keys asked for.
type HistoryWindow struct {
	Step time.Duration
	// Start is when the first bucket begins; zero before the first sample.
	Start time.Time
	// Series holds one value per bucket, oldest first, for each counter.
	Series [NumSeries][]int64
	// Full is true when the samples reach back over the whole window, so
	// its first bucket really is a day ago (no restart in between).
	Full bool
}

// Window sums the rings keep accepts (every key when keep is nil) over the
// window ending in now's bucket, starting no earlier than the first sample.
// Buckets after the latest sample repeat it.
func (h *History) Window(now time.Time, keep func(CountKey) bool) HistoryWindow {
	h.mu.RLock()
	defer h.mu.RUnlock()
	w := HistoryWindow{Step: h.step}
	if !h.started {
		return w
	}
	end := max(h.bucket(now), h.last)
	start := max(end-int64(h.n)+1, h.first)
	w.Full = h.first <= end-int64(h.n)+1
	w.Start = time.Unix(0, start*int64(h.step)).UTC()
	length := int(end - start + 1)
	for s := range w.Series {
		w.Series[s] = make([]int64, length)
	}
	add := func(r *historyRing) {
		for x := start; x <= end; x++ {
			var vals []int32
			if x <= h.last {
				vals = r.slot(x, h.n)
			} else {
				vals = r.cur[:]
			}
			i := int(x - start)
			for s, v := range vals {
				w.Series[s][i] += int64(v)
			}
		}
	}
	if keep == nil {
		add(&h.total)
		return w
	}
	for k, r := range h.rings {
		if keep(k) {
			add(r)
		}
	}
	return w
}
