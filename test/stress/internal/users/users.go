package users

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ByronGary/kubesentry/test/stress/internal/hist"
	"github.com/ByronGary/kubesentry/test/stress/internal/ks"
	"github.com/ByronGary/kubesentry/test/stress/internal/out"
)

// Options configure a run.
type Options struct {
	Client     *ks.Client
	Identities func(i int) ks.Identity // identity of virtual user i
	// Scope, if set, limits user i's pod and map targets to these namespaces
	// (nil: all), so team members open their own pods.
	Scope func(i int) map[string]bool
	// Kind, if set, names user i's persona kind; each stage also reports
	// the routes per kind (e.g. what admins, who see everything, get).
	Kind func(i int) string
	// InfoEvery polls /api/v1/info for the whole session (the new UI: 30s);
	// 0 fetches it once, as the baseline UI did.
	InfoEvery   time.Duration
	Stages      []Stage
	RampUp      time.Duration // spread new users of a stage over this
	ThinkMin    time.Duration
	ThinkMax    time.Duration
	PageTimeout time.Duration // stop waiting for a page's first load
	ReqTimeout  time.Duration
	Targets     *Targets
	Pages       []Page
	// Abort when, for AbortAfter, every 30s window has p99 > AbortP99 or an
	// error rate > AbortErrRate (or requests stuck longer than AbortP99).
	AbortP99     time.Duration
	AbortErrRate float64
	AbortAfter   time.Duration
	Seed         uint64
}

// StageResult is one stage's numbers.
type StageResult struct {
	Users     int                `json:"users"`
	Started   time.Time          `json:"started"`
	Seconds   float64            `json:"seconds"`
	Routes    []hist.RouteReport `json:"routes"`
	PageLoads []hist.RouteReport `json:"pageLoads"`
	Aborted   bool               `json:"aborted"`
	Reason    string             `json:"reason,omitempty"`
	Requests  int64              `json:"requests"`
	RPS       float64            `json:"rps"`
	// SnapshotAge is the snapshot age every /info answer reported during the
	// stage, in ms (what users saw; the target is p99 < 15s).
	SnapshotAge hist.Summary `json:"snapshotAgeMs"`
	// SnapshotStale counts /info answers that said stale.
	SnapshotStale int64 `json:"snapshotStale"`
	// ByKind is Routes per persona kind (with Options.Kind).
	ByKind map[string][]hist.RouteReport `json:"byKind,omitempty"`
}

// Result is users.json.
type Result struct {
	Started  time.Time     `json:"started"`
	Finished time.Time     `json:"finished"`
	Options  OptionsDoc    `json:"options"`
	Stages   []StageResult `json:"stages"`
	Series   []hist.Bucket `json:"series"`
	Aborted  bool          `json:"aborted"`
	Reason   string        `json:"reason,omitempty"`
	Targets  int           `json:"targetPods"`
}

// OptionsDoc records the options in results.
type OptionsDoc struct {
	Stages       string  `json:"stages"`
	RampUp       string  `json:"rampUp"`
	Think        string  `json:"think"`
	ReqTimeout   string  `json:"requestTimeout"`
	PageTimeout  string  `json:"pageTimeout"`
	AbortP99     string  `json:"abortP99"`
	AbortErrRate float64 `json:"abortErrorRate"`
	AbortAfter   string  `json:"abortAfter"`
}

type runner struct {
	o        Options
	stage    atomic.Pointer[hist.Recorder]
	pages    atomic.Pointer[hist.Recorder]
	snapAge  atomic.Pointer[hist.Hist]
	byKind   atomic.Pointer[sync.Map] // kind → *hist.Recorder for the stage
	stale    atomic.Int64
	all      *hist.Recorder
	active   atomic.Int64
	inflight sync.Map // *int64 start nanos
}

// Run executes the ramp and returns per-stage results.
func Run(ctx context.Context, o Options) *Result {
	r := &runner{o: o, all: hist.NewRecorder()}
	res := &Result{Started: time.Now().UTC(), Targets: len(o.Targets.Pods), Options: OptionsDoc{
		RampUp: o.RampUp.String(), Think: o.ThinkMin.String() + "-" + o.ThinkMax.String(), ReqTimeout: o.ReqTimeout.String(),
		PageTimeout: o.PageTimeout.String(), AbortP99: o.AbortP99.String(), AbortErrRate: o.AbortErrRate, AbortAfter: o.AbortAfter.String(),
	}}
	for i, s := range o.Stages {
		if i > 0 {
			res.Options.Stages += ","
		}
		res.Options.Stages += fmt.Sprintf("%d:%s", s.Users, s.Hold)
	}
	runCtx, stopAll := context.WithCancel(ctx)
	defer stopAll()
	var wg sync.WaitGroup
	started := 0
	for _, st := range o.Stages {
		rec, pageRec, ages := hist.NewRecorder(), hist.NewRecorder(), hist.New()
		r.stage.Store(rec)
		r.pages.Store(pageRec)
		r.snapAge.Store(ages)
		r.stale.Store(0)
		kinds := &sync.Map{}
		r.byKind.Store(kinds)
		sr := StageResult{Users: st.Users, Started: time.Now().UTC()}
		out.Logf("users: stage %d users (hold %s)", st.Users, st.Hold)
		add := st.Users - started
		stageStart := time.Now()
		for k := 0; k < add; k++ {
			id := started + k
			wg.Add(1)
			go func() {
				defer wg.Done()
				r.user(runCtx, id)
			}()
			if add > 1 && o.RampUp > 0 {
				select {
				case <-time.After(o.RampUp / time.Duration(add)):
				case <-ctx.Done():
				}
			}
		}
		started = st.Users
		reason := r.hold(ctx, rec, stageStart, st.Hold)
		sr.Seconds = time.Since(stageStart).Seconds()
		sr.Routes, sr.PageLoads = rec.Report(), pageRec.Report()
		for _, rt := range sr.Routes {
			sr.Requests += rt.Requests
		}
		sr.RPS = float64(sr.Requests) / sr.Seconds
		sr.SnapshotAge, sr.SnapshotStale = ages.Summarize(), r.stale.Load()
		kinds.Range(func(k, v any) bool {
			if sr.ByKind == nil {
				sr.ByKind = map[string][]hist.RouteReport{}
			}
			sr.ByKind[k.(string)] = v.(*hist.Recorder).Report()
			return true
		})
		if reason != "" {
			sr.Aborted, sr.Reason = true, reason
			res.Aborted, res.Reason = true, fmt.Sprintf("stage %d users: %s", st.Users, reason)
		}
		res.Stages = append(res.Stages, sr)
		logStage(sr)
		if reason != "" || ctx.Err() != nil {
			break
		}
	}
	stopAll()
	wg.Wait()
	res.Series = r.all.Series()
	res.Finished = time.Now().UTC()
	return res
}

func logStage(s StageResult) {
	out.Logf("users: stage %d users done: %d requests (%.1f/s)%s; snapshot age p50 %.1fs p99 %.1fs max %.1fs (%d answers, %d stale)", s.Users, s.Requests, s.RPS,
		map[bool]string{true: " ABORTED: " + s.Reason, false: ""}[s.Aborted], s.SnapshotAge.P50/1000, s.SnapshotAge.P99/1000, s.SnapshotAge.Max/1000, s.SnapshotAge.Count, s.SnapshotStale)
	for _, rt := range s.Routes {
		out.Logf("  %-14s n=%-6d p50=%8.0fms p95=%8.0fms p99=%8.0fms max=%8.0fms err=%.1f%% timeouts=%d aborted=%d status=%v",
			rt.Route, rt.Requests, rt.All.P50, rt.All.P95, rt.All.P99, rt.All.Max, 100*rt.ErrorRate, rt.Timeouts, rt.Aborted, rt.Status)
	}
}

// hold waits out the stage, checking the abort criteria every 10s.
func (r *runner) hold(ctx context.Context, rec *hist.Recorder, start time.Time, d time.Duration) string {
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	var badSince time.Time
	for {
		select {
		case <-ctx.Done():
			return "cancelled"
		case <-tick.C:
		}
		r.all.SetUsers(int(r.active.Load()))
		w := rec.Window(30 * time.Second)
		stuck := r.stuck(r.o.AbortP99)
		errRate := 0.0
		if n := w.Requests - w.Aborted; n > 0 {
			errRate = float64(w.Errors) / float64(n)
		}
		bad := errRate > r.o.AbortErrRate || w.P99 > float64(r.o.AbortP99.Milliseconds()) || stuck > 0 && w.Requests-w.Aborted == 0
		out.Logf("users: %d active, last 30s: %d requests, err %.1f%%, p99 %.0fms, %d stuck > %s",
			r.active.Load(), w.Requests, 100*errRate, w.P99, stuck, r.o.AbortP99)
		switch {
		case !bad:
			badSince = time.Time{}
		case badSince.IsZero():
			badSince = time.Now()
		case time.Since(badSince) >= r.o.AbortAfter:
			return fmt.Sprintf("abort criteria held for %s (last 30s: err %.0f%%, p99 %.0fs, %d requests stuck > %s)",
				r.o.AbortAfter, 100*errRate, w.P99/1000, stuck, r.o.AbortP99)
		}
		if time.Since(start) >= d {
			return ""
		}
	}
}

func (r *runner) stuck(older time.Duration) int {
	n := 0
	cut := time.Now().Add(-older).UnixNano()
	r.inflight.Range(func(_, v any) bool {
		if v.(int64) < cut {
			n++
		}
		return true
	})
	return n
}

// noteSnapshot records the snapshot age an /info answer reports.
func (r *runner) noteSnapshot(body []byte) {
	var v struct {
		Snapshot *struct {
			AgeSeconds float64 `json:"ageSeconds"`
			Stale      bool    `json:"stale"`
		} `json:"snapshot"`
	}
	if json.Unmarshal(body, &v) != nil || v.Snapshot == nil {
		return
	}
	if h := r.snapAge.Load(); h != nil {
		h.Add(v.Snapshot.AgeSeconds * 1000)
	}
	if v.Snapshot.Stale {
		r.stale.Add(1)
	}
}

var reqSeq atomic.Int64

// errSuperseded cancels a request that the hook's next poll replaces.
var errSuperseded = errors.New("superseded by the next poll")

func (r *runner) request(ctx context.Context, id ks.Identity, route, path string) hist.Outcome {
	oc, _ := r.requestBody(ctx, id, route, path, false)
	return oc
}

func (r *runner) requestBody(ctx context.Context, id ks.Identity, route, path string, keep bool) (hist.Outcome, []byte) {
	rctx, cancel := context.WithTimeout(ctx, r.o.ReqTimeout)
	defer cancel()
	k := reqSeq.Add(1)
	r.inflight.Store(k, time.Now().UnixNano())
	resp := r.o.Client.Do(rctx, id, http.MethodGet, path, nil, "", keep)
	r.inflight.Delete(k)
	outcome := hist.Classify(resp.Err, ctx.Err())
	switch {
	case resp.Err != nil && rctx.Err() == context.DeadlineExceeded && ctx.Err() == nil:
		outcome = hist.Timeout
	case resp.Err != nil && errors.Is(context.Cause(ctx), errSuperseded):
		// The next poll replaced it: the screen kept waiting for longer than
		// the poll interval, which counts as a failure, not a neutral abort.
		outcome = hist.Superseded
	}
	r.stage.Load().Record(route, resp.Status, resp.Bytes, resp.Elapsed, outcome, resp.Err)
	r.all.Record(route, resp.Status, resp.Bytes, resp.Elapsed, outcome, resp.Err)
	if kind, _ := ctx.Value(kindKey{}).(string); kind != "" {
		if m := r.byKind.Load(); m != nil {
			v, _ := m.LoadOrStore(kind, hist.NewRecorder())
			v.(*hist.Recorder).Record(route, resp.Status, resp.Bytes, resp.Elapsed, outcome, resp.Err)
		}
	}
	return outcome, resp.Body
}

// fetch runs one hook request: a single GET, or for a paged hook every page
// in turn (limit=h.Limit, following continue). It reports whether the result
// had a single page (the UI polls paged lists only then).
func (r *runner) fetch(ctx context.Context, id ks.Identity, h Hook) (hist.Outcome, bool) {
	if !h.Paged {
		return r.request(ctx, id, h.Route, h.Path), true
	}
	sep := "?"
	if strings.Contains(h.Path, "?") {
		sep = "&"
	}
	cont := ""
	for page := 0; ; page++ {
		p := fmt.Sprintf("%s%slimit=%d", h.Path, sep, h.Limit)
		if cont != "" {
			p += "&continue=" + url.QueryEscape(cont)
		}
		route := h.Route
		if page > 0 {
			route = h.Route + "(next page)"
		}
		oc, body := r.requestBody(ctx, id, route, p, true)
		if oc != hist.OK {
			return oc, page == 0
		}
		var v struct {
			Continue string `json:"continue"`
		}
		_ = json.Unmarshal(body, &v)
		if v.Continue == "" || page >= 20 { // the UI stops at 20,000 rows
			return oc, page == 0
		}
		cont = v.Continue
	}
}

type kindKey struct{}

// user is one virtual user's session.
func (r *runner) user(ctx context.Context, n int) {
	if r.o.Kind != nil {
		ctx = context.WithValue(ctx, kindKey{}, r.o.Kind(n))
	}
	r.active.Add(1)
	defer r.active.Add(-1)
	rnd := rand.New(rand.NewPCG(r.o.Seed, uint64(n)))
	id := r.o.Identities(n)
	targets := r.o.Targets
	if r.o.Scope != nil {
		targets = targets.Within(r.o.Scope(n))
	}
	// App.tsx: /info first (the UI gates pages on its capabilities), then
	// polled every 30s by the new UI for the whole session.
	caps := map[string]bool{"audit": true, "processes": true}
	if oc, body := r.requestBody(ctx, id, "info", "/api/v1/info", true); oc == hist.OK {
		var info struct {
			Audit        bool            `json:"audit"`
			Processes    bool            `json:"processes"`
			Capabilities map[string]bool `json:"capabilities"`
		}
		r.noteSnapshot(body)
		if json.Unmarshal(body, &info) == nil {
			caps["audit"], caps["processes"] = info.Audit, info.Processes
			if info.Capabilities != nil {
				caps["audit"] = info.Audit && (info.Capabilities["audit"] || info.Capabilities["clusterAudit"])
				caps["processes"] = info.Processes && info.Capabilities["processes"]
			}
		}
	}
	if r.o.InfoEvery > 0 {
		go func() {
			t := time.NewTicker(r.o.InfoEvery)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					if oc, body := r.requestBody(ctx, id, "info", "/api/v1/info", true); oc == hist.OK {
						r.noteSnapshot(body)
					}
				}
			}
		}()
	}
	for ctx.Err() == nil {
		page := Pick(r.o.Pages, rnd)
		var hooks []Hook
		for _, h := range page.Hooks(targets, rnd) {
			if h.Needs == "" || caps[h.Needs] {
				hooks = append(hooks, h)
			}
		}
		pctx, leave := context.WithCancel(ctx)
		loaded := make(chan struct{}, len(hooks))
		loadStart := time.Now()
		for _, h := range hooks {
			go r.hook(pctx, id, h, loaded)
		}
		// The user waits for the page (up to PageTimeout), then reads it.
		timeout := time.NewTimer(r.o.PageTimeout)
		got := 0
	wait:
		for got < len(hooks) {
			select {
			case <-loaded:
				got++
			case <-timeout.C:
				break wait
			case <-ctx.Done():
				break wait
			}
		}
		timeout.Stop()
		if ctx.Err() == nil {
			out := hist.OK
			if got < len(hooks) {
				out = hist.Timeout
			}
			r.pages.Load().Record("page:"+page.Name, 200, 0, time.Since(loadStart), out, nil)
		}
		think := r.o.ThinkMin + time.Duration(rnd.Int64N(int64(r.o.ThinkMax-r.o.ThinkMin)+1))
		select {
		case <-time.After(think):
		case <-ctx.Done():
		}
		leave() // navigation aborts whatever the page still has in flight
	}
}

// hook fires the request on load and then every h.Every, aborting a request
// still running when the next one starts (useApi's effect cleanup).
//
// The hook counts as loaded once a request ends other than by being aborted
// (a response, a timeout or an error), as the page then shows data or an error.
func (r *runner) hook(ctx context.Context, id ks.Identity, h Hook, loaded chan<- struct{}) {
	var cancelPrev context.CancelCauseFunc
	var signalled atomic.Bool
	var multiPage atomic.Bool
	fire := func(bool) {
		if multiPage.Load() {
			return // usePaged refreshes only while everything fits in one page
		}
		if cancelPrev != nil {
			cancelPrev(errSuperseded)
		}
		rctx, cancel := context.WithCancelCause(ctx)
		cancelPrev = cancel
		go func() {
			oc, single := r.fetch(rctx, id, h)
			if !single {
				multiPage.Store(true)
			}
			if oc != hist.Aborted && oc != hist.Superseded && signalled.CompareAndSwap(false, true) {
				loaded <- struct{}{}
			}
		}()
	}
	fire(true)
	t := time.NewTicker(h.Every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			if cancelPrev != nil {
				cancelPrev(context.Canceled)
			}
			return
		case <-t.C:
			fire(false)
		}
	}
}
