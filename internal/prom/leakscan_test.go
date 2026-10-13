package prom

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/model"
)

const mib = 1 << 20

// Kinds of synthetic container in the fake Prometheus.
const (
	flat      = iota // noise around a constant
	sawtooth         // leaks within each lifetime, restarted every few hours: a leak
	linear           // one long lifetime growing steadily: a leak
	noisy            // grows, but buried in noise: a candidate, not a leak (low R²)
	slow             // grows steadily below the leak threshold: a candidate, not a leak
	creep            // grows too slowly to be a candidate at all
	restarted        // flat, but restarted recently: a candidate from the pod list
)

type fakeContainer struct {
	key    model.ContainerKey
	kind   int
	base   float64       // bytes
	slope  float64       // bytes per second
	period time.Duration // sawtooth lifetime
	phase  time.Duration
	noise  float64 // relative amplitude
	seed   uint64
}

// value returns the working set at t and the lifetime it belongs to.
func (f *fakeContainer) value(t time.Time) (float64, int64) {
	sec := float64(t.Unix())
	v, life := f.base, int64(0)
	switch f.kind {
	case sawtooth:
		since := t.Sub(time.Unix(0, 0)) - f.phase
		life = int64(since / f.period)
		v += f.slope * (since % f.period).Seconds()
	case linear, noisy, slow, creep:
		v += f.slope * (sec - 1_791_500_000) // about 2.5 days before the tests' "now"
	}
	return v * (1 + f.noise*jitterAt(f.seed, t.Unix())), life
}

// jitterAt is deterministic noise in [-1, 1].
func jitterAt(seed uint64, t int64) float64 {
	z := seed ^ uint64(t)*0x9E3779B97F4A7C15
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	z ^= z >> 31
	return float64(z%2_000_001)/1_000_000 - 1
}

type fakeProm struct {
	containers []*fakeContainer
	byNS       map[string][]*fakeContainer
	now        time.Time

	mu         sync.Mutex
	queries    []string
	maxBody    int
	maxSeries  int           // most series in one range response
	gate       chan struct{} // when set, the candidate query waits for it
	failCands  atomic.Bool
	failRanges atomic.Bool
}

// newFakeProm builds 100 namespaces × 50 pods × 2 containers = 10,000
// containers, with 20 leaks (10 sawtooth, 10 linear) and 32 decoys.
func newFakeProm(now time.Time) *fakeProm {
	f := &fakeProm{byNS: map[string][]*fakeContainer{}, now: now}
	i := 0
	for n := range 100 {
		ns := fmt.Sprintf("team-%03d", n)
		for p := range 50 {
			pod := fmt.Sprintf("svc%02d-%d-7d9f8", p%7, p)
			for _, ctr := range []string{"app", "proxy"} {
				c := &fakeContainer{
					key:  model.ContainerKey{Namespace: ns, Pod: pod, Container: ctr},
					kind: flat, base: float64(100+(i%400)) * mib, noise: 0.03, seed: uint64(i) + 1,
				}
				// Spread the special containers over many namespaces.
				switch {
				case i%500 == 7: // 20 of these; the first 10 saw, the rest climb
					if i/500 < 10 {
						c.kind, c.base, c.slope, c.period, c.phase, c.noise = sawtooth, 200*mib, 40*mib/3600.0, 6*time.Hour, time.Duration(i)*time.Minute, 0.002
					} else {
						c.kind, c.base, c.slope, c.noise = linear, 300*mib, 5*mib/3600.0, 0.002
					}
				case i%1000 == 123: // 10
					c.kind, c.base, c.slope, c.noise = noisy, 300*mib, 3*mib/3600.0, 0.12
				case i%1000 == 456: // 10
					c.kind, c.base, c.slope, c.noise = slow, 300*mib, 0.7*mib/3600.0, 0.0005
				case i%1000 == 789: // 10
					c.kind, c.base, c.slope, c.noise = creep, 300*mib, 0.2*mib/3600.0, 0.0005
				case i == 4242 || i == 8484: // 2
					c.kind = restarted
				}
				f.containers = append(f.containers, c)
				f.byNS[ns] = append(f.byNS[ns], c)
				i++
			}
		}
	}
	return f
}

func (f *fakeProm) leaks() map[model.ContainerKey]bool {
	out := map[model.ContainerKey]bool{}
	for _, c := range f.containers {
		if c.kind == sawtooth || c.kind == linear {
			out[c.key] = true
		}
	}
	return out
}

// pods is what the scanner's PodLister returns: limits on every container,
// restarts and an OOM kill on the sawtooth leaks, and the two restarted pods.
func (f *fakeProm) pods() []model.Pod {
	byPod := map[[2]string]*model.Pod{}
	var order [][2]string
	for _, c := range f.containers {
		k := [2]string{c.key.Namespace, c.key.Pod}
		p, ok := byPod[k]
		if !ok {
			p = &model.Pod{Namespace: c.key.Namespace, Name: c.key.Pod}
			byPod[k] = p
			order = append(order, k)
		}
		p.Specs = append(p.Specs, model.ContainerSpec{Name: c.key.Container, MemoryLimitBytes: 1 << 30})
		st := model.ContainerStatus{Name: c.key.Container}
		switch c.kind {
		case sawtooth:
			st.RestartCount, st.LastTerminatedReason, st.LastTerminatedAt = 4, "OOMKilled", f.now.Add(-time.Hour)
		case restarted:
			st.RestartCount, st.LastTerminatedReason, st.LastTerminatedAt = 9, "Error", f.now.Add(-2*time.Hour)
		}
		p.Containers = append(p.Containers, st)
	}
	out := make([]model.Pod, 0, len(order))
	for _, k := range order {
		out = append(out, *byPod[k])
	}
	return out
}

var (
	candRe  = regexp.MustCompile(`^topk\((\d+), max by \(namespace, pod, container\) \(deriv\(container_memory_working_set_bytes\{container!="",container!="POD"\}\[(\w+):(\w+)\]\)\) > ([0-9.e+-]+)\)$`)
	selRe   = regexp.MustCompile(`container_memory_working_set_bytes\{([^}]*)\}`)
	matchRe = regexp.MustCompile(`(\w+)(=~|=)("(?:[^"\\]|\\.)*")`)
)

func (f *fakeProm) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	q := r.PostForm.Get("query")
	f.mu.Lock()
	f.queries = append(f.queries, q)
	f.mu.Unlock()

	var series []string
	var err error
	if r.URL.Path == "/api/v1/query" {
		if f.gate != nil {
			<-f.gate
		}
		if f.failCands.Load() {
			http.Error(w, `{"status":"error","errorType":"timeout","error":"query timed out"}`, http.StatusServiceUnavailable)
			return
		}
		series, err = f.candidates(q, r.PostForm.Get("time"))
	} else {
		if f.failRanges.Load() {
			http.Error(w, `{"status":"error","errorType":"timeout","error":"query timed out"}`, http.StatusServiceUnavailable)
			return
		}
		series, err = f.ranges(q, r.PostForm)
	}
	if err != nil {
		http.Error(w, `{"status":"error","errorType":"bad_data","error":`+strconv.Quote(err.Error())+`}`, http.StatusBadRequest)
		return
	}
	body := `{"status":"success","data":{"resultType":"matrix","result":[` + strings.Join(series, ",") + `]}}`
	f.mu.Lock()
	f.maxBody = max(f.maxBody, len(body))
	if r.URL.Path == "/api/v1/query_range" {
		f.maxSeries = max(f.maxSeries, len(series))
	}
	f.mu.Unlock()
	w.Write([]byte(body))
}

func unixParam(s string) time.Time {
	v, _ := strconv.ParseFloat(s, 64)
	return time.Unix(int64(v), 0)
}

func parseDur(s string) time.Duration {
	if strings.HasSuffix(s, "h") || strings.HasSuffix(s, "m") || strings.HasSuffix(s, "s") {
		d, _ := time.ParseDuration(s)
		return d
	}
	return 0
}

// candidates evaluates the candidate query the way Prometheus would on
// per-lifetime cAdvisor series: the least-squares slope of each lifetime over
// the subquery's points, the largest per container, above the threshold, top k.
func (f *fakeProm) candidates(q, at string) ([]string, error) {
	m := candRe.FindStringSubmatch(q)
	if m == nil {
		return nil, fmt.Errorf("unexpected instant query %q", q)
	}
	k, _ := strconv.Atoi(m[1])
	window, step := parseDur(m[2]), parseDur(m[3])
	thr, _ := strconv.ParseFloat(m[4], 64)
	end := unixParam(at)
	type hit struct {
		c     *fakeContainer
		slope float64
	}
	var hits []hit
	for _, c := range f.containers {
		lives := map[int64][]model.Sample{}
		for t := end.Add(-window); !t.After(end); t = t.Add(step) {
			v, life := c.value(t)
			lives[life] = append(lives[life], model.Sample{T: t, V: v})
		}
		best := math.Inf(-1)
		for _, s := range lives {
			if len(s) >= 2 {
				best = math.Max(best, lsSlope(s))
			}
		}
		if best > thr {
			hits = append(hits, hit{c, best})
		}
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].slope > hits[j].slope })
	if len(hits) > k {
		hits = hits[:k]
	}
	out := make([]string, len(hits))
	for i, h := range hits {
		out[i] = fmt.Sprintf(`{"metric":{"namespace":%q,"pod":%q,"container":%q},"value":[%d,"%g"]}`,
			h.c.key.Namespace, h.c.key.Pod, h.c.key.Container, end.Unix(), h.slope)
	}
	return out, nil
}

func lsSlope(s []model.Sample) float64 {
	n := float64(len(s))
	var mx, my float64
	for _, p := range s {
		mx += float64(p.T.Unix())
		my += p.V
	}
	mx, my = mx/n, my/n
	var sxx, sxy float64
	for _, p := range s {
		dx := float64(p.T.Unix()) - mx
		sxx += dx * dx
		sxy += dx * (p.V - my)
	}
	return sxy / sxx
}

// ranges answers a chunk query: every selector joined by "or", each matching
// one namespace and listed pods and containers.
func (f *fakeProm) ranges(q string, form map[string][]string) ([]string, error) {
	if !strings.HasPrefix(q, "max by (namespace, pod, container) (") {
		return nil, fmt.Errorf("unexpected range query %q", q)
	}
	start, end := unixParam(form["start"][0]), unixParam(form["end"][0])
	stepSec, _ := strconv.ParseFloat(form["step"][0], 64)
	step := time.Duration(stepSec * float64(time.Second))
	var out []string
	for _, sel := range selRe.FindAllStringSubmatch(q, -1) {
		match := map[string]func(string) bool{}
		for _, mm := range matchRe.FindAllStringSubmatch(sel[1], -1) {
			val, err := strconv.Unquote(mm[3])
			if err != nil {
				return nil, err
			}
			if mm[2] == "=" {
				match[mm[1]] = func(s string) bool { return s == val }
			} else {
				re, err := regexp.Compile("^(?:" + val + ")$")
				if err != nil {
					return nil, err
				}
				match[mm[1]] = re.MatchString
			}
		}
		if match["namespace"] == nil || match["pod"] == nil {
			return nil, fmt.Errorf("unscoped selector %q", sel[0])
		}
		for _, c := range f.byNS[c0(match["namespace"], f.byNS)] {
			if !match["pod"](c.key.Pod) || (match["container"] != nil && !match["container"](c.key.Container)) {
				continue
			}
			var b strings.Builder
			fmt.Fprintf(&b, `{"metric":{"namespace":%q,"pod":%q,"container":%q},"values":[`, c.key.Namespace, c.key.Pod, c.key.Container)
			for t := start; !t.After(end); t = t.Add(step) {
				if t != start {
					b.WriteByte(',')
				}
				v, _ := c.value(t)
				fmt.Fprintf(&b, `[%d,"%.0f"]`, t.Unix(), v)
			}
			b.WriteString("]}")
			out = append(out, b.String())
		}
	}
	return out, nil
}

// c0 finds the one namespace a selector names.
func c0(match func(string) bool, byNS map[string][]*fakeContainer) string {
	for ns := range byNS {
		if match(ns) {
			return ns
		}
	}
	return ""
}

func (f *fakeProm) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queries, f.maxBody, f.maxSeries = nil, 0, 0
}

func (f *fakeProm) stats() (queries []string, maxBody, maxSeries int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.queries...), f.maxBody, f.maxSeries
}

func newScanner(t *testing.T, f *fakeProm, opts LeakScanOptions) *LeakScanner {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	// A 4 MiB cap: the scan must never need anything like the 64 MiB a
	// fetch-everything query would.
	c, err := NewClient(srv.URL, Options{MaxResponseBytes: 4 << 20})
	if err != nil {
		t.Fatal(err)
	}
	c.now = func() time.Time { return f.now }
	pods := f.pods()
	return NewLeakScanner(c, func(context.Context) ([]model.Pod, error) { return pods, nil }, opts)
}

func TestLeakScanFindsExactlyTheLeaksWithBoundedQueries(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 3, 17, 0, time.UTC)
	f := newFakeProm(now)
	want := f.leaks()
	if len(f.containers) != 10_000 || len(want) != 20 {
		t.Fatalf("fixture: %d containers, %d leaks", len(f.containers), len(want))
	}
	// Judging every container's full history, as the old /oom path did, finds
	// the same 20: the candidate query loses nothing on this fixture.
	end := alignDown(now, 6*time.Minute)
	for _, c := range f.containers {
		ser := model.ContainerSeries{Key: c.key}
		for ts := end.Add(-24 * time.Hour); !ts.After(end); ts = ts.Add(6 * time.Minute) {
			v, _ := c.value(ts)
			ser.Samples = append(ser.Samples, model.Sample{T: ts, V: v})
		}
		if _, leak := detectors.AnalyzeLeak(ser, 0, detectors.DefaultLeakOptions()); leak != want[c.key] {
			t.Fatalf("fixture: full analysis of %v says leak=%v", c.key, leak)
		}
	}

	for _, chunk := range []int{0, 8} { // 0: the default of 200
		t.Run(fmt.Sprintf("chunk=%d", chunk), func(t *testing.T) {
			f.reset()
			s := newScanner(t, f, LeakScanOptions{ChunkSize: chunk})
			rep := s.Scan(context.Background())
			if len(rep.Errors) > 0 {
				t.Fatalf("errors: %v", rep.Errors)
			}
			got := map[model.ContainerKey]bool{}
			for _, lf := range rep.Findings {
				got[lf.ContainerKey] = true
				if !want[lf.ContainerKey] {
					t.Errorf("false positive: %+v", lf)
				}
				if lf.LimitBytes != 1<<30 || lf.TimeToLimitHours == nil {
					t.Errorf("limit from the pod spec missing: %+v", lf)
				}
			}
			for k := range want {
				if !got[k] {
					t.Errorf("missed leak %v", k)
				}
			}
			for _, lf := range rep.Findings {
				saw := lf.Confidence == "high" // several lifetimes leaked
				if saw != lf.OOMKilled {
					t.Errorf("OOM link: %+v", lf)
				}
			}

			// 20 leaks + 10 noisy + 10 slow from the candidate query, 2 restarts
			// from the pod list. The 10 creepers and 9,948 flat containers are
			// never fetched.
			if rep.Candidates != 42 {
				t.Errorf("candidates = %d, want 42", rep.Candidates)
			}
			size := s.Options().ChunkSize
			wantQueries := 1 + (rep.Candidates+size-1)/size
			queries, maxBody, maxSeries := f.stats()
			if len(queries) != wantQueries {
				t.Errorf("%d queries, want %d", len(queries), wantQueries)
			}
			if maxSeries > 2*size { // a chunk may include sibling containers of its pods
				t.Errorf("a response carried %d series for chunks of %d", maxSeries, size)
			}
			if maxBody > 1<<20 {
				t.Errorf("largest response %d bytes", maxBody)
			}
			points := int(s.Options().Window/s.Options().Step) + 1
			t.Logf("chunk %d: %d queries, largest response %d bytes / %d series; fetching all 10,000 containers would be ~%d MiB",
				size, len(queries), maxBody, maxSeries, 10_000*points*26/mib)
			if rep.Window != "24h0m0s" || !rep.GeneratedAt.Equal(now) {
				t.Errorf("report header: %q %v", rep.Window, rep.GeneratedAt)
			}
		})
	}
}

func TestLeakScanCandidateCap(t *testing.T) {
	f := newFakeProm(time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC))
	s := newScanner(t, f, LeakScanOptions{MaxCandidates: 5})
	rep := s.Scan(context.Background())
	if rep.Candidates != 5 {
		t.Fatalf("candidates = %d", rep.Candidates)
	}
	if len(rep.Errors) != 0 || len(rep.Warnings) != 1 || !strings.Contains(rep.Warnings[0], "more than 5 candidates") {
		t.Fatalf("cap not reported as a warning: errors %v warnings %v", rep.Errors, rep.Warnings)
	}
	queries, _, _ := f.stats()
	if !strings.HasPrefix(queries[0], "topk(6, ") {
		t.Errorf("candidate response not bounded: %s", queries[0])
	}
	// The fastest growers are kept: all five are sawtooth leaks (40 MiB/h).
	if len(rep.Findings) != 5 {
		t.Errorf("findings = %d", len(rep.Findings))
	}
}

func TestLeakScanKeepsLastGoodFindings(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	f := newFakeProm(now)
	var results []string
	s := newScanner(t, f, LeakScanOptions{ChunkSize: 10, OnScan: func(r string) { results = append(results, r) }})
	if !s.Latest().GeneratedAt.IsZero() {
		t.Fatal("report before any scan should have a zero time")
	}
	first := s.Scan(context.Background())
	if len(first.Findings) != 20 {
		t.Fatalf("first scan: %d findings %v", len(first.Findings), first.Errors)
	}

	// The candidate query fails: everything from the last good scan stays.
	f.failCands.Store(true)
	s.c.now = func() time.Time { return now.Add(5 * time.Minute) }
	rep := s.Scan(context.Background())
	if len(rep.Findings) != 20 || !rep.GeneratedAt.Equal(first.GeneratedAt) || len(rep.Errors) != 1 || !strings.Contains(rep.Errors[0], "candidate query") {
		t.Fatalf("after a failed scan: %d findings at %v, errors %v", len(rep.Findings), rep.GeneratedAt, rep.Errors)
	}
	if !first.LastAttempt.Equal(first.GeneratedAt) || !rep.LastAttempt.Equal(now.Add(5*time.Minute)) {
		t.Errorf("last attempt: first %v, after the failure %v", first.LastAttempt, rep.LastAttempt)
	}
	if got := s.Latest(); len(got.Findings) != 20 || len(got.Errors) != 1 {
		t.Fatalf("Latest: %+v", got)
	}

	// Range queries fail: known leaks are carried over from the last good scan.
	f.failCands.Store(false)
	f.failRanges.Store(true)
	rep = s.Scan(context.Background())
	if len(rep.Findings) != 20 || len(rep.Errors) == 0 || !rep.GeneratedAt.Equal(now.Add(5*time.Minute)) {
		t.Fatalf("after failed chunks: %d findings, errors %v", len(rep.Findings), rep.Errors)
	}
	if strings.Join(results, ",") != "ok,failed,partial" {
		t.Errorf("OnScan results = %v, want ok,failed,partial", results)
	}

	// A scanner that never succeeded reports errors and no findings.
	f2 := newFakeProm(now)
	f2.failCands.Store(true)
	s2 := newScanner(t, f2, LeakScanOptions{})
	rep = s2.Scan(context.Background())
	if len(rep.Findings) != 0 || rep.Findings == nil || len(rep.Errors) != 1 || !rep.GeneratedAt.IsZero() {
		t.Fatalf("never-good scanner: %+v", rep)
	}
}

func TestLeakScanOneAtATimeAndRunStops(t *testing.T) {
	f := newFakeProm(time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC))
	f.gate = make(chan struct{})
	s := newScanner(t, f, LeakScanOptions{Interval: time.Hour, StartJitter: -1})

	var wg sync.WaitGroup
	reports := make([]int, 5)
	scan := func(i int) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reports[i] = len(s.Scan(context.Background()).Findings)
		}()
	}
	scan(0)
	for {
		if q, _, _ := f.stats(); len(q) > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	// The first scan is held at its candidate query; the rest arrive meanwhile.
	for i := 1; i < len(reports); i++ {
		scan(i)
	}
	for {
		s.mu.Lock()
		w := s.waiting
		s.mu.Unlock()
		if w == len(reports)-1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	close(f.gate)
	wg.Wait()
	cands := 0
	queries, _, _ := f.stats()
	for _, q := range queries {
		if strings.HasPrefix(q, "topk(") {
			cands++
		}
	}
	if cands != 1 {
		t.Errorf("%d scans ran concurrently, want 1", cands)
	}
	for _, n := range reports {
		if n != 20 {
			t.Errorf("a waiting caller got %d findings", n)
		}
	}

	// Run scans immediately (no jitter), then waits for the interval; cancel stops it.
	f.reset()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	for {
		if q, _, _ := f.stats(); len(q) > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not stop")
	}
}

func TestLeakScanDefaults(t *testing.T) {
	c, _ := NewClient("http://prom:9090", Options{})
	o := NewLeakScanner(c, nil, LeakScanOptions{}).Options()
	if o.Interval != 5*time.Minute || o.Window != 24*time.Hour || o.Step != 6*time.Minute || o.MaxCandidates != 5000 ||
		o.ChunkSize != 200 || o.StartJitter != 30*time.Second || o.Leak.MinR2 != 0.8 {
		t.Fatalf("defaults: %+v", o)
	}
	if o := NewLeakScanner(c, nil, LeakScanOptions{Window: time.Hour}).Options(); o.Step != 30*time.Second {
		t.Fatalf("short window step: %v", o.Step)
	}
	for d, want := range map[time.Duration]string{24 * time.Hour: "24h", 6 * time.Minute: "6m", 90 * time.Second: "90s", 1500 * time.Millisecond: "1500ms"} {
		if got := promDuration(d); got != want {
			t.Errorf("promDuration(%v) = %q", d, got)
		}
	}
}

func TestLeakScanDropsInvalidNames(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if strings.HasPrefix(r.PostForm.Get("query"), "topk(") {
			w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[
				{"metric":{"namespace":"ok","pod":"x\"} or vector(1) #","container":"c"},"value":[1,"1e9"]}]}}`))
			return
		}
		t.Errorf("hostile label reached a query: %s", r.PostForm.Get("query"))
	}))
	defer srv.Close()
	c, _ := NewClient(srv.URL, Options{})
	rep := NewLeakScanner(c, nil, LeakScanOptions{}).Scan(context.Background())
	if rep.Candidates != 0 || len(rep.Errors) != 0 {
		t.Fatalf("%+v", rep)
	}
}
