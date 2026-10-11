package hist

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// Outcome classifies one request.
type Outcome int

const (
	OK      Outcome = iota // got a response (any status)
	Timeout                // client timeout
	Aborted                // cancelled by the client: the user navigated away, or the stage ended (neutral)
	Error                  // transport error
	// Superseded: still running when the next poll of the same page hook
	// started, which aborts it as the browser does. A failure: the user waited
	// longer than the poll interval. Its elapsed time is a lower bound.
	Superseded
)

// Classify maps a transport error to an outcome.
func Classify(err error, ctxErr error) Outcome {
	switch {
	case err == nil:
		return OK
	case errors.Is(ctxErr, context.Canceled):
		return Aborted
	case errors.Is(err, context.DeadlineExceeded) || isTimeout(err):
		return Timeout
	case errors.Is(err, context.Canceled):
		return Aborted
	}
	return Error
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// RouteStats aggregates one route.
type RouteStats struct {
	mu        sync.Mutex
	Completed *Hist            // requests that got a response
	All       *Hist            // completed plus timeouts and aborts at their elapsed time (a lower bound)
	Status    map[string]int64 // "200", "502", "timeout", "aborted", "error"
	Bytes     int64
	Errors    map[string]int64 // sample of error messages
}

func newRoute() *RouteStats {
	return &RouteStats{Completed: New(), All: New(), Status: map[string]int64{}, Errors: map[string]int64{}}
}

// Recorder collects per-route stats and a 10-second time series.
type Recorder struct {
	mu     sync.Mutex
	routes map[string]*RouteStats
	series map[int64]*Bucket // by unix time / 10s
	start  time.Time
}

// Bucket is 10 seconds of traffic over all routes.
type Bucket struct {
	T        time.Time `json:"t"`
	Requests int64     `json:"requests"`
	Errors   int64     `json:"errors"` // status >= 500, timeouts, transport errors
	Aborted  int64     `json:"aborted"`
	Users    int       `json:"users"`
	hist     *Hist
	P50      float64 `json:"p50Ms"`
	P99      float64 `json:"p99Ms"`
}

// NewRecorder returns an empty recorder.
func NewRecorder() *Recorder {
	return &Recorder{routes: map[string]*RouteStats{}, series: map[int64]*Bucket{}, start: time.Now()}
}

// Record adds one request.
func (r *Recorder) Record(route string, status int, bytes int64, elapsed time.Duration, out Outcome, err error) {
	r.mu.Lock()
	rs := r.routes[route]
	if rs == nil {
		rs = newRoute()
		r.routes[route] = rs
	}
	now := time.Now()
	k := now.Unix() / 10
	b := r.series[k]
	if b == nil {
		b = &Bucket{T: time.Unix(k*10, 0).UTC(), hist: New()}
		r.series[k] = b
	}
	r.mu.Unlock()

	ms := float64(elapsed.Microseconds()) / 1000
	rs.mu.Lock()
	var key string
	isErr := false
	switch out {
	case OK:
		key = fmt.Sprint(status)
		rs.Completed.Add(ms)
		rs.Bytes += bytes
		isErr = status >= 500 || status == 429
	case Timeout:
		key, isErr = "timeout", true
	case Aborted:
		key = "aborted"
	case Superseded:
		key, isErr = "superseded", true
	default:
		key, isErr = "error", true
	}
	rs.All.Add(ms)
	rs.Status[key]++
	if err != nil && out == Error && len(rs.Errors) < 10 {
		msg := err.Error()
		if i := strings.LastIndex(msg, ": "); i > 0 && len(msg) > 120 {
			msg = msg[i+2:]
		}
		rs.Errors[msg]++
	}
	rs.mu.Unlock()

	r.mu.Lock()
	b.Requests++
	if isErr {
		b.Errors++
	}
	if out == Aborted {
		b.Aborted++
	}
	r.mu.Unlock()
	if out != Aborted {
		b.hist.Add(ms)
	}
}

// SetUsers notes the active user count in the current bucket.
func (r *Recorder) SetUsers(n int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := time.Now().Unix() / 10
	b := r.series[k]
	if b == nil {
		b = &Bucket{T: time.Unix(k*10, 0).UTC(), hist: New()}
		r.series[k] = b
	}
	b.Users = n
}

// Series returns the time series, oldest first.
func (r *Recorder) Series() []Bucket {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Bucket, 0, len(r.series))
	for _, b := range r.series {
		c := *b
		c.P50, c.P99 = b.hist.Quantile(0.5), b.hist.Quantile(0.99)
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].T.Before(out[j].T) })
	return out
}

// RouteReport is the JSON form of one route.
type RouteReport struct {
	Route      string           `json:"route"`
	Requests   int64            `json:"requests"`
	Completed  Summary          `json:"completed"`
	All        Summary          `json:"all"`
	Status     map[string]int64 `json:"status"`
	Bytes      int64            `json:"bytes"`
	MeanBytes  int64            `json:"meanBytes"`
	ErrorRate  float64          `json:"errorRate"` // 5xx, 429, timeouts, superseded polls and transport errors over requests that were not abandoned
	Timeouts   int64            `json:"timeouts"`
	Superseded int64            `json:"superseded"`
	Aborted    int64            `json:"aborted"`
	Errors     map[string]int64 `json:"errorSamples,omitempty"`
}

// Report returns every route, by name.
func (r *Recorder) Report() []RouteReport {
	r.mu.Lock()
	names := make([]string, 0, len(r.routes))
	for n := range r.routes {
		names = append(names, n)
	}
	r.mu.Unlock()
	sort.Strings(names)
	out := make([]RouteReport, 0, len(names))
	for _, n := range names {
		r.mu.Lock()
		rs := r.routes[n]
		r.mu.Unlock()
		rs.mu.Lock()
		rr := RouteReport{Route: n, Status: map[string]int64{}, Bytes: rs.Bytes, Errors: map[string]int64{}}
		var bad int64
		for k, v := range rs.Status {
			rr.Status[k] = v
			rr.Requests += v
			switch {
			case k == "timeout":
				rr.Timeouts, bad = v, bad+v
			case k == "superseded":
				rr.Superseded, bad = v, bad+v
			case k == "aborted":
				rr.Aborted = v
			case k == "error" || k == "429" || strings.HasPrefix(k, "5"):
				bad += v
			}
		}
		for k, v := range rs.Errors {
			rr.Errors[k] = v
		}
		rs.mu.Unlock()
		rr.Completed, rr.All = rs.Completed.Summarize(), rs.All.Summarize()
		if rr.Completed.Count > 0 {
			rr.MeanBytes = rr.Bytes / rr.Completed.Count
		}
		if n := rr.Requests - rr.Aborted; n > 0 {
			rr.ErrorRate = float64(bad) / float64(n)
		}
		out = append(out, rr)
	}
	return out
}

// Window summarises the buckets that started within the last d.
type Window struct {
	Requests int64
	Errors   int64
	Aborted  int64
	P99      float64
}

// Window returns traffic stats over the last d.
func (r *Recorder) Window(d time.Duration) Window {
	cut := time.Now().Add(-d).Unix() / 10
	h := New()
	var w Window
	r.mu.Lock()
	var bs []*Bucket
	for k, b := range r.series {
		if k > cut {
			bs = append(bs, b)
			w.Requests += b.Requests
			w.Errors += b.Errors
			w.Aborted += b.Aborted
		}
	}
	r.mu.Unlock()
	for _, b := range bs {
		h.Merge(b.hist)
	}
	w.P99 = h.Quantile(0.99)
	return w
}
