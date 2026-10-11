package prom

import (
	"context"
	"fmt"
	"math/rand/v2"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/model"
)

// LeakScanOptions configures a LeakScanner. Zero fields take the defaults.
type LeakScanOptions struct {
	Interval time.Duration // between scans; default 5m (-leak-scan-interval)
	Window   time.Duration // look-back; default 24h (-leak-scan-window)
	// Step is the sample spacing; default Window/240 and at least 30s, the
	// resolution the /oom handler uses, so both judge the same samples.
	Step time.Duration
	// StartJitter delays the first scan by a random time up to this, so
	// replicas restarted together do not scan together; default
	// min(Interval, 30s). Negative means no delay.
	StartJitter   time.Duration
	MaxCandidates int // containers analysed per scan; default 5000
	ChunkSize     int // candidate series per range query; default 200
	Parallel      int // range queries in flight; default 4
	// CandidateFactor scales Leak.MinSlopeBytesPerHour into the candidate
	// query's threshold. Below 1 it leaves a margin for the coarser candidate
	// fit; default 0.5.
	CandidateFactor float64
	Leak            detectors.LeakOptions // zero: detectors.DefaultLeakOptions()
}

func (o *LeakScanOptions) defaults() {
	if o.Interval <= 0 {
		o.Interval = 5 * time.Minute
	}
	if o.Window <= 0 {
		o.Window = 24 * time.Hour
	}
	if o.Step <= 0 {
		o.Step = max(o.Window/240, 30*time.Second).Round(time.Second)
	}
	if o.StartJitter == 0 {
		o.StartJitter = min(o.Interval, 30*time.Second)
	}
	if o.MaxCandidates <= 0 {
		o.MaxCandidates = 5000
	}
	if o.ChunkSize <= 0 {
		o.ChunkSize = 200
	}
	if o.Parallel <= 0 {
		o.Parallel = 4
	}
	if o.CandidateFactor <= 0 {
		o.CandidateFactor = 0.5
	}
	if o.Leak == (detectors.LeakOptions{}) {
		o.Leak = detectors.DefaultLeakOptions()
	}
}

// PodLister returns the cluster's pods. The scanner uses them for memory
// limits, OOM kills and containers that restarted inside the window.
type PodLister func(ctx context.Context) ([]model.Pod, error)

// LeakScanner finds memory leaks in the background without fetching every
// container's history. One instant query picks candidates: containers whose
// memory grew within a single lifetime (deriv over each cAdvisor series, which
// starts afresh on restart) faster than a fraction of the leak threshold.
// Containers that restarted inside the window are added from the pod list,
// for setups that drop cAdvisor's per-lifetime id label. Only candidates are
// then fetched, in range queries of at most ChunkSize series, and judged by
// detectors.AnalyzeLeak exactly as the /oom handler judges them.
type LeakScanner struct {
	c    *Client
	pods PodLister
	opts LeakScanOptions
	rand func() float64

	mu      sync.Mutex
	latest  detectors.LeakReport
	good    bool          // latest carries a successful scan's findings
	running chan struct{} // closed when the scan in progress ends
	waiting int           // callers waiting for the scan in progress
}

// NewLeakScanner returns a scanner that queries through c. pods may be nil:
// limits then come only from kube-state-metrics (with KSMLimits), and OOM
// kills and restarts are not considered.
func NewLeakScanner(c *Client, pods PodLister, opts LeakScanOptions) *LeakScanner {
	opts.defaults()
	return &LeakScanner{
		c: c, pods: pods, opts: opts, rand: rand.Float64,
		latest: detectors.LeakReport{Window: opts.Window.String(), Findings: []detectors.LeakFinding{}},
	}
}

// Window is the look-back the scanner judges; LeakReport.Window is its String.
func (s *LeakScanner) Window() time.Duration { return s.opts.Window }

// Options returns the effective options, defaults filled in.
func (s *LeakScanner) Options() LeakScanOptions { return s.opts }

// Latest returns the most recent report. Until the first scan succeeds its
// GeneratedAt is zero. After a failed scan it keeps the last good findings and
// lists what went wrong in Errors.
func (s *LeakScanner) Latest() detectors.LeakReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.latest
}

// Run scans after a random start delay and then every Interval until ctx is
// cancelled.
func (s *LeakScanner) Run(ctx context.Context) {
	delay := time.Duration(0)
	if s.opts.StartJitter > 0 {
		delay = time.Duration(s.rand() * float64(s.opts.StartJitter))
	}
	t := time.NewTimer(delay)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s.Scan(ctx)
		t.Reset(s.opts.Interval)
	}
}

// Scan runs one scan now and returns the resulting report. At most one scan
// runs at a time: a call made while another is in progress waits for it and
// returns its report.
func (s *LeakScanner) Scan(ctx context.Context) detectors.LeakReport {
	s.mu.Lock()
	if ch := s.running; ch != nil {
		s.waiting++
		s.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
		}
		s.mu.Lock()
		s.waiting--
		s.mu.Unlock()
		return s.Latest()
	}
	ch := make(chan struct{})
	s.running = ch
	prev, prevGood := s.latest, s.good
	s.mu.Unlock()

	rep, ok := s.scan(ctx, prev, prevGood)

	s.mu.Lock()
	s.latest, s.good, s.running = rep, ok || prevGood, nil
	s.mu.Unlock()
	close(ch)
	return rep
}

// candidate is one container chosen for a detailed look.
type candidate struct {
	key   model.ContainerKey
	slope float64 // bytes per second from the candidate query; 0 for restarts
}

// scan returns the new report and whether it holds fresh findings.
func (s *LeakScanner) scan(ctx context.Context, prev detectors.LeakReport, prevGood bool) (detectors.LeakReport, bool) {
	now := s.c.clock()
	end := alignDown(now, s.opts.Step)
	var errs []string

	var pods []model.Pod
	if s.pods != nil {
		p, err := s.pods(ctx)
		if err != nil {
			errs = append(errs, "list pods: "+err.Error())
		}
		pods = p
	}

	cands, total, err := s.candidates(ctx, end, pods)
	if err != nil {
		rep := prev
		rep.Errors = append(errs, "candidate query: "+err.Error())
		if !prevGood {
			rep.Findings = []detectors.LeakFinding{}
		}
		return rep, false
	}
	if total > len(cands) {
		errs = append(errs, fmt.Sprintf("more than %d candidates: analysed the %d fastest-growing", s.opts.MaxCandidates, len(cands)))
	}

	limits := LimitsFromPods(pods)
	ooms := map[model.ContainerKey]detectors.OOMEvent{}
	for _, e := range detectors.FindOOMKills(pods, end.Add(-s.opts.Window)) {
		ooms[e.ContainerKey] = e
	}

	findings, failed, chunkErrs := s.analyse(ctx, end, cands, limits, ooms)
	errs = append(errs, chunkErrs...)
	// Containers whose chunk failed keep their previous finding, so one bad
	// query does not make a known leak disappear.
	if len(failed) > 0 && prevGood {
		for _, f := range prev.Findings {
			if failed[f.ContainerKey] {
				findings = append(findings, f)
			}
		}
	}
	sortLeaks(findings)
	return detectors.LeakReport{
		GeneratedAt: now.UTC(),
		Window:      s.opts.Window.String(),
		Findings:    findings,
		Candidates:  len(cands),
		Errors:      errs,
	}, true
}

// CandidateQuery is the PromQL that picks candidates: the fastest-growing
// container lifetimes over the window, one series per container, at most
// MaxCandidates+1 so the scanner can tell when it had to cut the list.
func (s *LeakScanner) CandidateQuery() string {
	thr := s.opts.Leak.MinSlopeBytesPerHour * s.opts.CandidateFactor / 3600
	inner := s.c.sel(memMetric, `container!=""`, `container!="POD"`)
	return fmt.Sprintf(`topk(%d, max by (namespace, pod, container) (deriv(%s[%s:%s])) > %s)`,
		s.opts.MaxCandidates+1, inner, promDuration(s.opts.Window), promDuration(s.opts.Step),
		strconv.FormatFloat(thr, 'g', -1, 64))
}

// candidates returns at most MaxCandidates containers, fastest-growing first,
// then restarted ones, and how many there were before the cut.
func (s *LeakScanner) candidates(ctx context.Context, end time.Time, pods []model.Pod) ([]candidate, int, error) {
	raw, err := s.c.query(ctx, s.CandidateQuery(), end, nil)
	if err != nil {
		return nil, 0, err
	}
	seen := make(map[model.ContainerKey]bool, len(raw))
	out := make([]candidate, 0, len(raw))
	for _, r := range raw {
		k := keyFrom(r.Labels)
		if !validKey(k) || seen[k] || len(r.Samples) == 0 {
			continue
		}
		seen[k] = true
		out = append(out, candidate{key: k, slope: r.Samples[len(r.Samples)-1].V})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].slope > out[j].slope })
	total := len(out)
	if len(raw) > s.opts.MaxCandidates {
		total = max(total, s.opts.MaxCandidates+1)
	}

	// Restarted inside the window, newest first.
	since := end.Add(-s.opts.Window)
	type restart struct {
		key model.ContainerKey
		at  time.Time
	}
	var restarts []restart
	for _, p := range pods {
		for _, c := range p.Containers {
			k := model.ContainerKey{Namespace: p.Namespace, Pod: p.Name, Container: c.Name}
			if c.RestartCount == 0 || c.LastTerminatedAt.Before(since) || seen[k] || !validKey(k) {
				continue
			}
			seen[k] = true
			restarts = append(restarts, restart{k, c.LastTerminatedAt})
		}
	}
	sort.Slice(restarts, func(i, j int) bool { return restarts[i].at.After(restarts[j].at) })
	for _, r := range restarts {
		out = append(out, candidate{key: r.key})
	}
	total += len(restarts)

	if len(out) > s.opts.MaxCandidates {
		out = out[:s.opts.MaxCandidates]
	}
	return out, total, nil
}

// analyse fetches candidates chunk by chunk and judges them. It returns the
// findings, the keys of chunks that failed, and their errors.
func (s *LeakScanner) analyse(ctx context.Context, end time.Time, cands []candidate, limits map[model.ContainerKey]float64, ooms map[model.ContainerKey]detectors.OOMEvent) ([]detectors.LeakFinding, map[model.ContainerKey]bool, []string) {
	keys := make([]model.ContainerKey, len(cands))
	for i, c := range cands {
		keys[i] = c.key
	}
	chunks := chunkKeys(keys, s.opts.ChunkSize)

	var (
		mu       sync.Mutex
		findings = []detectors.LeakFinding{}
		failed   = map[model.ContainerKey]bool{}
		errs     []string
		wg       sync.WaitGroup
		sem      = make(chan struct{}, s.opts.Parallel)
	)
	for _, chunk := range chunks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				mu.Lock()
				defer mu.Unlock()
				for _, k := range chunk {
					failed[k] = true
				}
				errs = append(errs, "range query: "+ctx.Err().Error())
				return
			}
			got, err := s.analyseChunk(ctx, end, chunk, limits, ooms)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				for _, k := range chunk {
					failed[k] = true
				}
				errs = append(errs, "range query: "+err.Error())
				return
			}
			findings = append(findings, got...)
		}()
	}
	wg.Wait()
	return findings, failed, dedupe(errs)
}

func (s *LeakScanner) analyseChunk(ctx context.Context, end time.Time, chunk []model.ContainerKey, podLimits map[model.ContainerKey]float64, ooms map[model.ContainerKey]detectors.OOMEvent) ([]detectors.LeakFinding, error) {
	want := make(map[model.ContainerKey]bool, len(chunk))
	for _, k := range chunk {
		want[k] = true
	}
	raw, err := s.c.queryRange(ctx, s.c.chunkQuery(memMetric, chunk), end.Add(-s.opts.Window), end, s.opts.Step, nil)
	if err != nil {
		return nil, err
	}
	var ksm map[model.ContainerKey]float64
	if s.c.ksmLimits {
		lim, err := s.c.query(ctx, s.c.chunkQuery("kube_pod_container_resource_limits", chunk, `resource="memory"`), end, nil)
		if err != nil {
			return nil, fmt.Errorf("kube-state-metrics limits: %w", err)
		}
		ksm = lastValues(lim)
	}

	var out []detectors.LeakFinding
	for _, ser := range toContainerSeries(raw) {
		if !want[ser.Key] {
			continue // another container of a candidate pod
		}
		limit, ok := ksm[ser.Key]
		if !ok {
			limit = podLimits[ser.Key]
		}
		f, ok := detectors.AnalyzeLeak(ser, limit, s.opts.Leak)
		if !ok {
			continue
		}
		if e, hit := ooms[ser.Key]; hit {
			t := e.LastOOMAt
			f.OOMKilled, f.LastOOMAt = true, &t
		}
		out = append(out, f)
	}
	return out, nil
}

// chunkQuery selects exactly the given containers: one selector per
// namespace, joined with "or" so pods of one namespace never match names from
// another, aggregated per container to stitch restarts together.
func (c *Client) chunkQuery(metric string, keys []model.ContainerKey, extra ...string) string {
	byNS := map[string][]model.ContainerKey{}
	var order []string
	for _, k := range keys {
		if _, ok := byNS[k.Namespace]; !ok {
			order = append(order, k.Namespace)
		}
		byNS[k.Namespace] = append(byNS[k.Namespace], k)
	}
	sort.Strings(order)
	sels := make([]string, 0, len(order))
	for _, ns := range order {
		var pods, ctrs []string
		for _, k := range byNS[ns] {
			pods = append(pods, k.Pod)
			ctrs = append(ctrs, k.Container)
		}
		parts := []string{`namespace=` + strconv.Quote(ns), nameMatcher("pod", pods), nameMatcher("container", ctrs)}
		sels = append(sels, c.sel(metric, append(parts, extra...)...))
	}
	return `max by (namespace, pod, container) (` + strings.Join(sels, " or ") + `)`
}

// nameMatcher matches a set of validated names: equality for one name, an
// escaped alternation otherwise.
func nameMatcher(label string, names []string) string {
	names = uniqueSorted(names)
	if len(names) == 1 {
		return label + "=" + strconv.Quote(names[0])
	}
	for i, n := range names {
		names[i] = regexp.QuoteMeta(n)
	}
	return label + "=~" + strconv.Quote(strings.Join(names, "|"))
}

// chunkKeys sorts keys by namespace, pod and container and cuts them into
// chunks of at most size, so each chunk touches as few namespaces as possible.
func chunkKeys(keys []model.ContainerKey, size int) [][]model.ContainerKey {
	sorted := append([]model.ContainerKey(nil), keys...)
	sort.Slice(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		if a.Pod != b.Pod {
			return a.Pod < b.Pod
		}
		return a.Container < b.Container
	})
	var out [][]model.ContainerKey
	for len(sorted) > 0 {
		n := min(size, len(sorted))
		out = append(out, sorted[:n:n])
		sorted = sorted[n:]
	}
	return out
}

// sortLeaks orders findings like the /oom handler: closest to its limit
// first, then fastest growing.
func sortLeaks(out []detectors.LeakFinding) {
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i].TimeToLimitHours, out[j].TimeToLimitHours
		switch {
		case a != nil && b != nil && *a != *b:
			return *a < *b
		case (a == nil) != (b == nil):
			return a != nil
		}
		if out[i].SlopeBytesPerHour != out[j].SlopeBytesPerHour {
			return out[i].SlopeBytesPerHour > out[j].SlopeBytesPerHour
		}
		return keyLess(out[i].ContainerKey, out[j].ContainerKey)
	})
}

func keyLess(a, b model.ContainerKey) bool {
	if a.Namespace != b.Namespace {
		return a.Namespace < b.Namespace
	}
	if a.Pod != b.Pod {
		return a.Pod < b.Pod
	}
	return a.Container < b.Container
}

// dnsName matches Kubernetes object names (DNS-1123 subdomains). Names reach
// PromQL, so labels that are not valid names are dropped.
var dnsName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`)

func validName(s string) bool { return len(s) <= 253 && dnsName.MatchString(s) }

func validKey(k model.ContainerKey) bool {
	return validName(k.Namespace) && validName(k.Pod) && validName(k.Container)
}

// promDuration formats d in the largest whole PromQL unit.
func promDuration(d time.Duration) string {
	switch {
	case d%time.Hour == 0:
		return strconv.FormatInt(int64(d/time.Hour), 10) + "h"
	case d%time.Minute == 0:
		return strconv.FormatInt(int64(d/time.Minute), 10) + "m"
	case d%time.Second == 0:
		return strconv.FormatInt(int64(d/time.Second), 10) + "s"
	default:
		return strconv.FormatInt(max(int64(d/time.Millisecond), 1), 10) + "ms"
	}
}

func uniqueSorted(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	n := 0
	for i, v := range out {
		if i == 0 || v != out[n-1] {
			out[n] = v
			n++
		}
	}
	return out[:n]
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
