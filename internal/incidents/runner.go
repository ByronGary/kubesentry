package incidents

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ByronGary/kubesentry/internal/alerts"
	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/model"
	"github.com/ByronGary/kubesentry/internal/snapshot"
)

// Lease is a held leadership: internal/pgstore's "incidents" advisory lock,
// whose store writes only while it is held.
type Lease interface {
	// Lost is closed once the lease is gone.
	Lost() <-chan struct{}
	Release(ctx context.Context) error
	// Store writes through the lease: a commit fails once it is lost.
	Store() Store
}

// Elector tries to take the leadership without waiting; ok is false when
// another replica holds it.
type Elector func(ctx context.Context) (l Lease, ok bool, err error)

// Hooks feed metrics; any may be nil. They are called from the runner's
// goroutines and must not block.
type Hooks struct {
	// OnLeader reports whether this replica leads.
	OnLeader func(leading bool)
	// OnCommit reports each commit: the open incidents by severity
	// (kubesentry_incidents{severity}).
	OnCommit func(open map[Severity]int, took time.Duration, err error)
	// OnSignals counts signals by type (kubesentry_incident_signals_total).
	OnSignals func(typ string, n int)
	// OnEvents counts Kubernetes events: "stored", "error"
	// (kubesentry_k8s_events_total{result}).
	OnEvents func(result string, n int)
	// OnCloudTrail counts CloudTrail events: "read", "kept", "error"
	// (kubesentry_cloudtrail_events_total{result}).
	OnCloudTrail func(result string, n int)
	// OnLogFetch counts log reads: source "kubernetes" or "cloudwatch",
	// result "ok", "truncated" or "error"
	// (kubesentry_incident_log_fetches_total{source,result}).
	OnLogFetch func(source, result string)
}

// Config is what NewRunner needs. Store is required; every source is
// optional (a missing one is "absent" in Sources and its signals are not
// produced).
type Config struct {
	// Store keeps the incidents; replicas that do not lead read it. With
	// Elect nil it is also the leader's store.
	Store Store
	// Events keeps the raw Kubernetes events (a memory store when nil).
	Events EventStore
	// Elect takes the leadership; nil means this replica always leads (the
	// memory store, one replica).
	Elect Elector
	// View returns the current snapshot view (nil before the first).
	View func() *snapshot.View
	// Kick is signalled after each snapshot build.
	Kick <-chan struct{}

	Rates       []RateSource
	Memory      MemorySource
	Series      SeriesSource
	EventSource EventSource
	// Logs are the log sources in order of preference ("auto" takes the
	// first): put CloudWatch before Kubernetes when it is configured.
	Logs       []LogSource
	CloudTrail CloudTrailSource
	// Alerts returns the current alert findings (the alerts board); nil
	// when alerting is off.
	Alerts func() []alerts.Finding
	// Audit is the audit store, for audit-change signals and the bundle.
	Audit audit.Store

	Options Options
	Hooks   Hooks
	Logger  *slog.Logger
}

// Runner keeps the engine and its producers running on the lease holder,
// and the board fresh everywhere. It also serves the API's reads: an
// incident's detail, its logs and its bundle.
type Runner struct {
	c     Config
	o     Options
	red   *Redactor
	board *MemBoard
	log   *slog.Logger

	leading atomic.Bool
	logSem  chan struct{}

	mu      sync.Mutex
	sources map[string]string
}

// ErrNotFound means no incident has the ID.
var ErrNotFound = errors.New("incidents: no such incident")

// ErrNoLogSource means no configured log source matches the request.
var ErrNoLogSource = errors.New("incidents: no log source")

// NewRunner checks the options and returns a runner; Run starts it.
func NewRunner(c Config) (*Runner, error) {
	if c.Store == nil {
		return nil, errors.New("incidents: a store is required")
	}
	if err := c.Options.Validate(); err != nil {
		return nil, err
	}
	o := c.Options.WithDefaults()
	red, err := NewRedactor(o.RedactPatterns)
	if err != nil {
		return nil, err
	}
	if c.Events == nil {
		c.Events = NewMemoryEventStore()
	}
	if c.View == nil {
		c.View = func() *snapshot.View { return nil }
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	r := &Runner{c: c, o: o, red: red, board: NewBoard(o.BoardWindow), log: c.Logger.With("component", "incidents"),
		logSem: make(chan struct{}, 4), sources: map[string]string{}}
	r.initSources()
	return r, nil
}

// Options returns the options in force, defaults applied.
func (r *Runner) Options() Options { return r.o }

// Redactor returns the redactor in force.
func (r *Runner) Redactor() *Redactor { return r.red }

// Board returns the board the API lists from.
func (r *Runner) Board() *MemBoard { return r.board }

// Leader reports whether this replica runs the engine.
func (r *Runner) Leader() bool { return r.leading.Load() }

// Signals returns the signals of an incident on the board.
func (r *Runner) Signals(id string) ([]Signal, bool) { return r.board.Signals(id) }

// Sources reports each source's state for /info: "ok", "absent" or
// "error: …". Keys: requests:<name>, memory, series, events, logs:<name>,
// cloudtrail, audit, alerts.
func (r *Runner) Sources() map[string]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]string, len(r.sources))
	for k, v := range r.sources {
		out[k] = v
	}
	return out
}

func (r *Runner) setSource(k, v string) {
	r.mu.Lock()
	r.sources[k] = v
	r.mu.Unlock()
}

func (r *Runner) initSources() {
	set := func(k string, ok bool) {
		if ok {
			r.sources[k] = "ok"
		} else {
			r.sources[k] = "absent"
		}
	}
	for _, s := range r.c.Rates {
		r.sources["requests:"+s.Name()] = "ok"
	}
	set("memory", r.c.Memory != nil)
	set("series", r.c.Series != nil)
	set("events", r.c.EventSource != nil)
	set("cloudtrail", r.c.CloudTrail != nil)
	set("audit", r.c.Audit != nil)
	set("alerts", r.c.Alerts != nil)
	for _, l := range r.c.Logs {
		r.sources["logs:"+l.Name()] = "ok"
	}
	if len(r.c.Logs) == 0 {
		r.sources["logs"] = "absent"
	}
}

// probe asks the sources that can tell whether they have data.
func (r *Runner) probe(ctx context.Context) {
	for _, s := range r.c.Rates {
		pctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		r.setSource("requests:"+s.Name(), s.Probe(pctx))
		cancel()
	}
	if r.c.CloudTrail != nil {
		pctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		r.setSource("cloudtrail", r.c.CloudTrail.Probe(pctx))
		cancel()
	}
}

// Run leads (runs the engine and producers) or follows (refreshes the
// board) until ctx ends.
func (r *Runner) Run(ctx context.Context) {
	go func() {
		t := time.NewTicker(r.o.ProbeEvery)
		defer t.Stop()
		for {
			r.probe(ctx)
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	if r.c.Elect == nil {
		r.lead(ctx, nil)
		return
	}
	for ctx.Err() == nil {
		l, ok, err := r.c.Elect(ctx)
		switch {
		case err != nil:
			r.log.Warn("incidents: could not try for the lock", "err", err)
		case ok:
			r.lead(ctx, l)
			continue
		}
		r.follow(ctx, r.o.Retry)
	}
}

// follow refreshes the board from the store for d.
func (r *Runner) follow(ctx context.Context, d time.Duration) {
	end := time.After(d)
	t := time.NewTicker(r.o.Refresh)
	defer t.Stop()
	for {
		if err := r.Refresh(ctx, r.c.Store, false); err != nil && ctx.Err() == nil {
			r.log.Warn("incidents: reading the board failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-end:
			return
		case <-t.C:
		}
	}
}

// Refresh replaces the board with the store's incidents of the last
// BoardWindow, reading the signals only of incidents that changed.
func (r *Runner) Refresh(ctx context.Context, store Store, leader bool) error {
	now := NormalTime(r.o.Now())
	ins, err := store.List(ctx, Query{From: now.Add(-r.o.BoardWindow), Limit: MemoryMaxIncidents})
	if err != nil {
		return err
	}
	sigs := make(map[string][]Signal, len(ins))
	var changed []string
	for _, in := range ins {
		if prev, ok := r.board.Get(in.ID); ok && reflect.DeepEqual(prev, in) {
			sigs[in.ID], _ = r.board.Signals(in.ID)
			continue
		}
		changed = append(changed, in.ID)
	}
	if len(changed) > 0 {
		if sl, ok := store.(SignalsLoader); ok {
			got, err := sl.SignalsOf(ctx, changed)
			if err != nil {
				return err
			}
			for _, id := range changed {
				sigs[id] = got[id]
			}
		} else {
			for _, id := range changed {
				_, ss, _, err := store.Get(ctx, id)
				if err != nil {
					return err
				}
				sigs[id] = ss
			}
		}
	}
	r.board.Replace(ins, sigs, now, leader)
	return nil
}

func (r *Runner) setLeading(on bool) {
	r.leading.Store(on)
	if r.c.Hooks.OnLeader != nil {
		r.c.Hooks.OnLeader(on)
	}
}

// batch is what a producer hands the engine.
type batch struct {
	sigs  []Signal
	cpKey string
	cp    []byte
}

// lead runs the engine while l is held (always, when l is nil), then
// releases it. The moment the lease is lost every producer stops.
func (r *Runner) lead(ctx context.Context, l Lease) {
	store := r.c.Store
	lctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if l != nil {
		store = l.Store()
		go func() {
			select {
			case <-l.Lost():
				cancel()
			case <-lctx.Done():
			}
		}()
	}
	defer func() {
		if l != nil {
			rctx, rcancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			_ = l.Release(rctx)
			rcancel()
			if ctx.Err() == nil {
				r.log.Warn("incidents: leadership ended")
			}
		}
	}()
	leaseAt := r.o.Now()
	eng := NewEngine(store, r.board, r.o)
	for {
		err := eng.Load(lctx)
		if err == nil {
			err = r.Refresh(lctx, store, true)
		}
		if err == nil {
			break
		}
		r.log.Warn("incidents: loading failed; retrying", "err", err)
		select {
		case <-lctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
	r.setLeading(true)
	defer r.setLeading(false)
	r.log.Info("incidents: this replica runs the engine", "open", len(eng.Open()))

	in := make(chan batch, 64)
	var wg sync.WaitGroup
	defer wg.Wait()
	defer cancel()
	send := func(b batch) bool {
		select {
		case in <- b:
			return true
		case <-lctx.Done():
			return false
		}
	}
	r.startProducers(lctx, &wg, eng, store, leaseAt, send)

	diff := NewViewDiff(r.o, leaseAt)
	diff.Resume(eng.Active(SourceView))
	var lastView *snapshot.View
	onView := func() {
		v := r.c.View()
		if v == nil || v == lastView {
			return
		}
		lastView = v
		eng.SetView(v)
		r.add(eng, diff.Diff(v, r.o.Now()))
	}
	onView()
	tick := time.NewTicker(r.o.CommitEvery)
	defer tick.Stop()
	prune := time.NewTicker(time.Hour)
	defer prune.Stop()
	lastFlush := time.Now()
	for {
		select {
		case <-lctx.Done():
			return
		case <-r.c.Kick:
			onView()
		case b := <-in:
			eng.SetView(lastView)
			r.add(eng, b.sigs)
			if b.cpKey != "" && b.cp != nil {
				eng.SetCheckpoint(b.cpKey, b.cp)
			}
		case <-tick.C:
			onView()
		case <-prune.C:
			r.prune(lctx, store)
		}
		eng.Tick()
		if eng.Dirty() && (eng.Changed() || time.Since(lastFlush) >= r.o.CommitEvery) {
			start := time.Now()
			err := eng.Flush(lctx)
			lastFlush = time.Now()
			if r.c.Hooks.OnCommit != nil {
				open := map[Severity]int{Warning: 0, Critical: 0}
				for _, o := range eng.Open() {
					open[o.Severity]++
				}
				r.c.Hooks.OnCommit(open, time.Since(start), err)
			}
			if err != nil && lctx.Err() == nil {
				if errors.Is(err, audit.ErrLeadershipLost) {
					r.log.Warn("incidents: the lease was lost", "err", err)
					return
				}
				r.log.Warn("incidents: commit failed; retrying", "err", err)
			}
		}
	}
}

func (r *Runner) add(eng *Engine, sigs []Signal) {
	if len(sigs) == 0 {
		return
	}
	eng.Add(sigs...)
	if r.c.Hooks.OnSignals != nil {
		n := map[string]int{}
		for _, s := range sigs {
			n[s.Type]++
		}
		types := make([]string, 0, len(n))
		for t := range n {
			types = append(types, t)
		}
		sort.Strings(types)
		for _, t := range types {
			r.c.Hooks.OnSignals(t, n[t])
		}
	}
}

func (r *Runner) prune(ctx context.Context, store Store) {
	now := r.o.Now()
	if n, err := store.Prune(ctx, now.Add(-r.o.Retention)); err != nil && ctx.Err() == nil {
		r.log.Warn("incidents: pruning failed", "err", err)
	} else if n > 0 {
		r.log.Info("incidents: pruned resolved incidents", "count", n)
	}
	if _, err := r.c.Events.PruneEvents(ctx, now.Add(-r.o.EventsRetention)); err != nil && ctx.Err() == nil {
		r.log.Warn("incidents: pruning events failed", "err", err)
	}
}

// every runs f now and then every d until ctx ends.
func every(ctx context.Context, wg *sync.WaitGroup, d time.Duration, f func()) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(d)
		defer t.Stop()
		for {
			f()
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
}

func (r *Runner) startProducers(ctx context.Context, wg *sync.WaitGroup, eng *Engine, store Store, leaseAt time.Time, send func(batch) bool) {
	if len(r.c.Rates) > 0 || r.c.Memory != nil {
		m := NewMetricsScan(r.o, r.c.Rates, r.c.Memory)
		m.Resume(eng.Active(SourceMetrics))
		every(ctx, wg, r.o.Interval, func() {
			sigs := m.Scan(ctx, r.c.View(), r.o.Now())
			for k, v := range m.Status() {
				if v != "ok" || r.Sources()[k] == "" || isError(r.Sources()[k]) {
					r.setSource(k, v)
				}
			}
			send(batch{sigs: sigs})
		})
	}
	if r.c.Alerts != nil {
		p := NewAlertEpisodes()
		p.Resume(eng.Active(SourceAlerts))
		every(ctx, wg, r.o.AlertsEvery, func() {
			send(batch{sigs: p.Scan(r.c.Alerts(), r.o.Now())})
		})
	}
	if r.c.Audit != nil {
		cp, err := store.Checkpoint(ctx, CheckpointAudit)
		if err != nil {
			r.log.Warn("incidents: reading the audit checkpoint failed; starting from the lookbehind", "err", err)
		}
		p := NewAuditPoll(r.c.Audit, r.o, cp, r.o.Now())
		every(ctx, wg, r.o.AuditEvery, func() {
			sigs, cp, err := p.Poll(ctx, r.c.View(), r.o.Now())
			if err != nil {
				if ctx.Err() == nil {
					r.setSource("audit", "error: "+err.Error())
				}
				return
			}
			r.setSource("audit", "ok")
			send(batch{sigs: sigs, cpKey: CheckpointAudit, cp: cp})
		})
	}
	if r.c.CloudTrail != nil {
		cp, err := store.Checkpoint(ctx, CheckpointCloudTrail)
		if err != nil {
			r.log.Warn("incidents: reading the CloudTrail checkpoint failed; starting over", "err", err)
		}
		p := NewCloudTrailPoll(r.c.CloudTrail, r.o, r.red, cp, r.o.Now())
		every(ctx, wg, r.o.CloudTrailEvery, func() {
			sigs, cp, read, kept, err := p.Poll(ctx, r.c.View(), r.o.Now())
			if h := r.c.Hooks.OnCloudTrail; h != nil {
				if err != nil {
					h("error", 1)
				} else {
					h("read", read)
					h("kept", kept)
				}
			}
			if err != nil {
				if ctx.Err() == nil {
					r.setSource("cloudtrail", "error: "+err.Error())
				}
				return
			}
			send(batch{sigs: sigs, cpKey: CheckpointCloudTrail, cp: cp})
		})
	}
	if len(r.c.Logs) > 0 {
		p := NewLogErrors(r.c.Logs[0], r.o)
		p.Resume(eng.Active(SourceLogs))
		every(ctx, wg, r.o.LogsEvery, func() {
			ins, _ := r.board.Snapshot()
			var open []Incident
			for _, in := range ins {
				if in.State == Open {
					open = append(open, in)
				}
			}
			sigs, err := p.Scan(ctx, open, r.o.Now())
			if err != nil && ctx.Err() == nil {
				r.log.Debug("incidents: counting error logs failed", "err", err)
			}
			send(batch{sigs: sigs})
		})
	}
	if r.c.EventSource != nil {
		ing := NewEventsIngest(r.o, r.red)
		var mu sync.Mutex
		sink := func(evs []model.KubeEvent) {
			mu.Lock()
			stored, sigs := ing.Handle(r.c.View(), evs, r.o.Now())
			mu.Unlock()
			if len(stored) > 0 {
				err := r.c.Events.AddEvents(ctx, stored)
				if h := r.c.Hooks.OnEvents; h != nil {
					if err != nil {
						h("error", len(stored))
					} else {
						h("stored", len(stored))
					}
				}
				if err != nil && ctx.Err() == nil {
					r.log.Warn("incidents: storing events failed", "err", err, "events", len(stored))
				}
			}
			send(batch{sigs: sigs})
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				err := r.c.EventSource.Run(ctx, sink)
				if ctx.Err() != nil {
					return
				}
				if err != nil {
					r.setSource("events", "error: "+err.Error())
					r.log.Warn("incidents: the event watch stopped; restarting", "err", err)
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(10 * time.Second):
				}
			}
		}()
	}
}

func isError(s string) bool { return len(s) >= 6 && s[:6] == "error:" }

// Get returns an incident and its signals: from the board when it is
// there, else from the store (older incidents, up to the retention).
func (r *Runner) Get(ctx context.Context, id string) (Incident, []Signal, bool, error) {
	if in, ok := r.board.Get(id); ok {
		sigs, _ := r.board.Signals(id)
		return in, sigs, true, nil
	}
	return r.c.Store.Get(ctx, id)
}

// Threshold is a horizontal line on an incident's chart.
type Threshold struct {
	Metric string  `json:"metric"` // "memory", "requests", "errors"
	Label  string  `json:"label"`
	Value  float64 `json:"value"`
}

// Detail is what the incident page shows, before the API gates it by the
// caller's capabilities (signals per source, audit, CloudTrail).
type Detail struct {
	Incident   Incident
	From, To   time.Time // the padded window
	Signals    []Signal
	Events     []StoredEvent // most recently seen first
	Series     []Series
	Thresholds []Threshold
	Related    []Incident
	// Sources is the state of each source for this incident.
	Sources  map[string]string
	Warnings []string
}

// DetailOptions tunes Detail.
type DetailOptions struct {
	// EventLimit caps the events (500).
	EventLimit int
	// NoSeries skips the metric series (a caller that will not chart them).
	NoSeries bool
}

// SeriesStep is the step of an incident's charts: the window / 240,
// clamped to 15s–5m.
func SeriesStep(from, to time.Time) time.Duration {
	step := to.Sub(from) / 240
	switch {
	case step < 15*time.Second:
		return 15 * time.Second
	case step > 5*time.Minute:
		return 5 * time.Minute
	}
	return step.Round(time.Second)
}

// Detail gathers an incident's detail. ok is false when the ID is unknown.
func (r *Runner) Detail(ctx context.Context, id string, o DetailOptions) (Detail, bool, error) {
	in, sigs, ok, err := r.Get(ctx, id)
	if err != nil || !ok {
		return Detail{}, ok, err
	}
	if o.EventLimit <= 0 {
		o.EventLimit = 500
	}
	now := r.o.Now()
	from, to := in.Window(r.o.LogLead, r.o.LogLag, now)
	d := Detail{Incident: in, From: from, To: to, Signals: sigs, Sources: map[string]string{}}
	subj := in.Subject
	evs, err := r.c.Events.Events(ctx, EventQuery{Subject: &subj, From: from, To: to, Limit: o.EventLimit})
	if err != nil {
		d.Warnings = append(d.Warnings, "events: "+err.Error())
		d.Sources["events"] = "error: " + err.Error()
	} else {
		d.Events = evs
		d.Sources["events"] = r.Sources()["events"]
	}
	if !o.NoSeries {
		if r.c.Series == nil {
			d.Sources["series"] = "absent"
		} else if ss, err := r.series(ctx, &in, from, to); err != nil {
			d.Warnings = append(d.Warnings, "metrics: "+err.Error())
			d.Sources["series"] = "error: " + err.Error()
		} else {
			d.Series = ss
			d.Sources["series"] = "ok"
		}
	}
	d.Thresholds = thresholdsOf(sigs)
	board, _ := r.board.Snapshot()
	d.Related = Related(in, board, r.o.AppLabel, now)
	for k, v := range r.Sources() {
		if _, ok := d.Sources[k]; !ok {
			d.Sources[k] = v
		}
	}
	return d, true, nil
}

func (r *Runner) series(ctx context.Context, in *Incident, from, to time.Time) ([]Series, error) {
	return r.c.Series.SubjectSeries(ctx, SeriesQuery{Namespace: in.Subject.Namespace, Pods: in.Pods, Services: in.Services,
		From: from, To: to, Step: SeriesStep(from, to), MaxSeries: 12})
}

// thresholdsOf are the thresholds of an incident's spikes, one per metric
// and label.
func thresholdsOf(sigs []Signal) []Threshold {
	var out []Threshold
	seen := map[string]bool{}
	for _, s := range sigs {
		if s.Threshold == nil {
			continue
		}
		var metric string
		switch s.Type {
		case TypeMemorySpike:
			metric = "memory"
		case TypeRequestSpike:
			metric = "requests"
		case TypeErrorRate:
			metric = "errors"
		default:
			continue
		}
		label := s.Object.Name
		if c := s.Attrs["container"]; c != "" {
			label += "/" + c
		}
		k := metric + "\x00" + label
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, Threshold{Metric: metric, Label: label, Value: *s.Threshold})
	}
	return out
}

// LogRequest asks for an incident's logs.
type LogRequest struct {
	// From and To narrow the padded window (zero: all of it).
	From, To time.Time
	// Pods narrows to some of the incident's pods (empty: up to 10 of them).
	Pods       []string
	Containers []string
	Level      string
	Text       string
	// Source is "auto" (the first configured), "kubernetes" or "cloudwatch".
	Source string
	// Limit caps the lines (LogsMaxLines at most).
	Limit int
}

// LogResponse is a page of redacted log lines.
type LogResponse struct {
	From, To  time.Time
	Source    string
	Lines     []LogLine
	Truncated bool
	Warnings  []string
}

// Logs reads an incident's logs within its padded window, redacted. At most
// four reads run at once across callers. ErrNotFound and ErrNoLogSource
// report an unknown incident and a source that is not configured.
func (r *Runner) Logs(ctx context.Context, id string, req LogRequest) (LogResponse, error) {
	in, _, ok, err := r.Get(ctx, id)
	if err != nil {
		return LogResponse{}, err
	}
	if !ok {
		return LogResponse{}, ErrNotFound
	}
	src, err := r.logSource(req.Source)
	if err != nil {
		return LogResponse{}, err
	}
	from, to := in.Window(r.o.LogLead, r.o.LogLag, r.o.Now())
	if !req.From.IsZero() && req.From.After(from) {
		from = req.From
	}
	if !req.To.IsZero() && req.To.Before(to) {
		to = req.To
	}
	resp := LogResponse{From: from, To: to, Source: src.Name(), Lines: []LogLine{}}
	if !to.After(from) {
		return resp, nil
	}
	pods := incidentPods(&in, req.Pods)
	if len(pods) == 0 {
		resp.Warnings = append(resp.Warnings, "the incident names no pods")
		return resp, nil
	}
	limit := r.o.LogsMaxLines
	if req.Limit > 0 && req.Limit < limit {
		limit = req.Limit
	}
	select {
	case r.logSem <- struct{}{}:
		defer func() { <-r.logSem }()
	case <-ctx.Done():
		return LogResponse{}, ctx.Err()
	}
	res, err := src.Logs(ctx, LogQuery{Namespace: in.Subject.Namespace, Pods: pods, Containers: req.Containers, From: from, To: to,
		Level: req.Level, Text: req.Text, Limit: limit, MaxBytes: r.o.LogsMaxBytes, Previous: true})
	if h := r.c.Hooks.OnLogFetch; h != nil {
		switch {
		case err != nil:
			h(src.Name(), "error")
		case res.Truncated:
			h(src.Name(), "truncated")
		default:
			h(src.Name(), "ok")
		}
	}
	if err != nil {
		return LogResponse{}, fmt.Errorf("incidents: logs from %s: %w", src.Name(), err)
	}
	resp.Truncated, resp.Warnings = res.Truncated, append(resp.Warnings, res.Warnings...)
	for _, l := range res.Lines {
		l.Text = r.red.String(l.Text)
		resp.Lines = append(resp.Lines, l)
	}
	return resp, nil
}

func (r *Runner) logSource(name string) (LogSource, error) {
	if len(r.c.Logs) == 0 {
		return nil, ErrNoLogSource
	}
	if name == "" || name == "auto" {
		return r.c.Logs[0], nil
	}
	for _, s := range r.c.Logs {
		if s.Name() == name {
			return s, nil
		}
	}
	return nil, fmt.Errorf("%w: %q", ErrNoLogSource, name)
}

// incidentPods are the requested pods that belong to the incident, or up
// to 10 of its pods.
func incidentPods(in *Incident, want []string) []string {
	if len(want) == 0 {
		if len(in.Pods) > 10 {
			return in.Pods[:10]
		}
		return in.Pods
	}
	var out []string
	for _, p := range want {
		if contains(in.Pods, p) && !contains(out, p) {
			out = append(out, p)
		}
	}
	return out
}

// AuditEvents returns the audit events of an incident's window: in its
// namespace (or about its node), newest first, at most limit. The caller
// checks the audit capability.
func (r *Runner) AuditEvents(ctx context.Context, in *Incident, limit int) ([]audit.Event, error) {
	if r.c.Audit == nil {
		return nil, nil
	}
	from, to := in.Window(r.o.LogLead, r.o.LogLag, r.o.Now())
	q := audit.Query{Since: from, Namespace: in.Subject.Namespace, Limit: limit * 2}
	if in.Subject.Namespace == "" {
		if in.Subject.Kind != KindNode {
			return nil, nil
		}
		q.Resource, q.Name = "nodes", in.Subject.Name
	}
	evs, err := r.c.Audit.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	out := evs[:0]
	for _, e := range evs {
		if !e.Time.After(to) {
			out = append(out, e)
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// BundleRequest asks for an incident's bundle.
type BundleRequest struct {
	// Omitted are the sections the caller may not see, with the reason
	// ("forbidden"); the API decides. They are neither read nor included.
	Omitted map[string]string
	// Cluster names the cluster in the header (Options.Cluster when empty).
	Cluster string
}

// Bundle assembles an incident's agent-ready bundle: its signals, metric
// series, Kubernetes events, logs, audit events and CloudTrail changes in
// its padded window, capped and redacted. A section whose read failed is
// omitted with the error (so the bundle is not complete); a section whose
// source is not configured is just empty. ErrNotFound reports an unknown
// incident.
func (r *Runner) Bundle(ctx context.Context, id string, req BundleRequest) (*Bundle, error) {
	in, sigs, ok, err := r.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrNotFound
	}
	now := r.o.Now()
	from, to := in.Window(r.o.LogLead, r.o.LogLag, now)
	omitted := map[string]string{}
	for k, v := range req.Omitted {
		omitted[k] = v
	}
	skip := func(s string) bool { _, ok := omitted[s]; return ok }
	bi := BundleInput{Cluster: req.Cluster, Incident: in, From: from, To: to, Signals: sigs, GeneratedAt: now}
	if bi.Cluster == "" {
		bi.Cluster = r.o.Cluster
	}
	if !skip(SectionMetrics) && r.c.Series != nil {
		if ss, err := r.series(ctx, &in, from, to); err != nil {
			omitted[SectionMetrics] = "error: " + err.Error()
		} else {
			bi.Metrics = ss
		}
	}
	if !skip(SectionEvents) {
		subj := in.Subject
		evs, err := r.c.Events.Events(ctx, EventQuery{Subject: &subj, From: from, To: to, Limit: BundleMaxEvents + 1})
		if err != nil {
			omitted[SectionEvents] = "error: " + err.Error()
		} else {
			bi.Events = evs
		}
	}
	if !skip(SectionLogs) {
		res, err := r.Logs(ctx, id, LogRequest{Limit: BundleMaxLogLines})
		switch {
		case errors.Is(err, ErrNoLogSource):
			// none configured: the section is empty, not withheld
		case err != nil:
			omitted[SectionLogs] = "error: " + err.Error()
		default:
			bi.Logs, bi.LogsTruncated = res.Lines, res.Truncated
		}
	}
	if !skip(SectionAudit) && r.c.Audit != nil {
		if evs, err := r.AuditEvents(ctx, &in, BundleMaxAudit+1); err != nil {
			omitted[SectionAudit] = "error: " + err.Error()
		} else {
			bi.Audit = evs
		}
	}
	bi.Omitted = omitted
	return BuildBundle(bi, r.red), nil
}
