package investigate

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/ByronGary/kubesentry/internal/incidents"
)

// Service defaults (docs/contracts.md: -investigator-per-hour,
// -investigator-per-hour-total, -investigator-concurrency).
const (
	DefaultPerHour      = 10
	DefaultPerHourTotal = 60
	DefaultConcurrency  = 2
	// StaleAfter is how old a running run's heartbeat may be before it
	// reads as failed, "interrupted" (its replica stopped).
	StaleAfter = 2 * time.Minute
	// CacheFor is how long a completed run answers a start with the same
	// input.
	CacheFor = 24 * time.Hour
	// DefaultHeartbeat is how often a running job touches its row.
	DefaultHeartbeat = 30 * time.Second
	// busyRetry is the Retry-After of a busy replica.
	busyRetry = 30 * time.Second
	// writeTimeout bounds each store write of a job.
	writeTimeout = 10 * time.Second
)

// Results counted by Hooks.OnResult (kubesentry_investigations_total).
const (
	ResultCompleted = "completed"
	ResultRefused   = "refused"
	ResultFailed    = "failed"
	ResultTimeout   = "timeout"
	ResultBudget    = "budget"
	ResultCancelled = "cancelled"
	ResultCached    = "cached"
	ResultQuota     = "quota"
	ResultBusy      = "busy"
)

// Hooks feed metrics (cmd/server wires them to internal/metrics); any may
// be nil. They must not block.
type Hooks struct {
	// OnResult counts each start that ended, or was turned away:
	// kubesentry_investigations_total{provider,result}.
	OnResult func(provider, result string)
	// OnDuration observes a finished run's length:
	// kubesentry_investigation_duration_seconds.
	OnDuration func(d time.Duration)
	// OnRunning reports this replica's running jobs:
	// kubesentry_investigations_running.
	OnRunning func(n int)
	// OnTokens counts each turn's tokens:
	// kubesentry_investigation_tokens_total{provider,model,kind}.
	OnTokens func(provider, model string, u Usage)
	// OnToolCall counts tool calls by result (ok, error, denied, invalid):
	// kubesentry_investigation_tool_calls_total{tool,result}.
	OnToolCall func(tool, result string)
}

// Config is what NewService needs. LLM, Source and Store are required.
type Config struct {
	LLM    LLM
	Source Source
	Store  Store
	// Egress filters what leaves (nil: the built-in redaction rules). Build
	// it over the incidents runner's redactor so -incident-redact-patterns
	// apply.
	Egress *Egress
	// Options are the model and the budgets.
	Options Options
	// PerHour (per identity), PerHourTotal and Concurrency (per replica)
	// limit starts; zero takes the defaults.
	PerHour      int
	PerHourTotal int
	Concurrency  int
	// Cluster names the cluster in the digest.
	Cluster string
	Hooks   Hooks
	Now     func() time.Time
	Logger  *slog.Logger
	// Heartbeat is how often a running job touches its row (30s).
	Heartbeat time.Duration
}

// Service runs investigations: it starts them asynchronously, enforces the
// quotas, the per-replica concurrency and one running run per incident,
// serves completed runs again for the same input, persists progress after
// every turn, and answers reads with the caller's access in mind.
type Service struct {
	c    Config
	o    Options
	eg   *Egress
	log  *slog.Logger
	now  func() time.Time
	base context.Context
	stop context.CancelFunc

	mu     sync.Mutex
	jobs   map[string]*job
	closed bool
}

type job struct {
	cancel   context.CancelCauseFunc
	done     chan struct{}
	started  time.Time
	mu       sync.Mutex // serialises the job's store writes
	inv      *Investigation
	p        *progress
	finished bool
}

// NewService checks the config and returns a service.
func NewService(c Config) (*Service, error) {
	if c.LLM == nil || c.Source == nil || c.Store == nil {
		return nil, errors.New("investigate: a model, a source and a store are required")
	}
	if err := c.Options.Validate(); err != nil {
		return nil, err
	}
	if c.PerHour <= 0 {
		c.PerHour = DefaultPerHour
	}
	if c.PerHourTotal <= 0 {
		c.PerHourTotal = DefaultPerHourTotal
	}
	if c.Concurrency <= 0 {
		c.Concurrency = DefaultConcurrency
	}
	if c.Heartbeat <= 0 {
		c.Heartbeat = DefaultHeartbeat
	}
	s := &Service{c: c, o: c.Options.WithDefaults(), eg: c.Egress, log: c.Logger, now: c.Now, jobs: map[string]*job{}}
	if s.eg == nil {
		s.eg = defaultEgress
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.now == nil {
		s.now = time.Now
	}
	s.base, s.stop = context.WithCancel(context.Background())
	return s, nil
}

// Provider names the model backend.
func (s *Service) Provider() string { return s.c.LLM.Provider() }

// Options returns the options in force, defaults applied.
func (s *Service) Options() Options { return s.o }

// PerHour is the per-identity hourly quota (for /info).
func (s *Service) PerHour() int { return s.c.PerHour }

// StartRequest asks for an investigation. The caller (the API) has checked
// that the incident is visible and that RequestedBy may investigate it.
type StartRequest struct {
	IncidentID  string
	RequestedBy string
	// Access is what RequestedBy may see inside the incident, frozen for
	// the run.
	Access Access
	// Fresh skips the cache.
	Fresh bool
}

func (s *Service) result(r string) {
	if h := s.c.Hooks.OnResult; h != nil {
		h(s.Provider(), r)
	}
}

func (s *Service) running() {
	if h := s.c.Hooks.OnRunning; h != nil {
		s.mu.Lock()
		n := len(s.jobs)
		s.mu.Unlock()
		h(n)
	}
}

// Start begins an investigation and returns it at once (status running),
// or, unless Fresh, a completed run with the same input from the last 24
// hours (cached true: no model call, no quota used). Errors: ErrIncidentNotFound,
// *ConflictError, *QuotaError, *BusyError.
func (s *Service) Start(ctx context.Context, req StartRequest) (*Investigation, bool, error) {
	if req.IncidentID == "" || req.RequestedBy == "" {
		return nil, false, errors.New("investigate: an incident and an identity are required")
	}
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return nil, false, &BusyError{RetryAfter: busyRetry}
	}
	now := s.now()
	if err := s.checkRunning(ctx, req.IncidentID, now); err != nil {
		return nil, false, err
	}

	// The digest decides the cache key, so it comes before the quotas.
	access := req.Access
	bundleOmitted := map[string]string{}
	for k, v := range access.Omitted() {
		if k != SectionNodes {
			bundleOmitted[k] = v
		}
	}
	b, err := s.c.Source.Bundle(ctx, req.IncidentID, incidents.BundleRequest{Omitted: bundleOmitted, Cluster: s.c.Cluster})
	if errors.Is(err, incidents.ErrNotFound) {
		return nil, false, ErrIncidentNotFound
	}
	if err != nil {
		return nil, false, fmt.Errorf("investigate: the incident's evidence: %w", err)
	}
	gateBundle(b, access)
	digest, stable, led := s.eg.digest(b, s.o.DigestBytes)
	hash := inputHash(stable, s.o.Model, s.o.Effort, access)

	if !req.Fresh {
		orig, err := s.c.Store.Cached(ctx, hash, now.Add(-CacheFor))
		switch {
		case err == nil:
			inv := cachedCopy(orig, req.RequestedBy, now)
			if err := s.c.Store.Create(ctx, inv); err != nil {
				return nil, false, err
			}
			s.result(ResultCached)
			s.log.Info("investigation started", "identity", req.RequestedBy, "incident", req.IncidentID, "provider", s.Provider(),
				"model", s.o.Model, "id", inv.ID, "cachedFrom", inv.CachedFrom)
			return inv, true, nil
		case !errors.Is(err, ErrNotFound):
			return nil, false, err
		}
	}

	if err := s.checkQuota(ctx, req.RequestedBy, now); err != nil {
		s.result(ResultQuota)
		return nil, false, err
	}

	inv := &Investigation{ID: newID(now), IncidentID: req.IncidentID, Namespace: b.Incident.Subject.Namespace, Status: Running,
		RequestedBy: req.RequestedBy, CreatedAt: now, UpdatedAt: now, Provider: s.Provider(), Model: s.o.Model, Effort: s.o.Effort,
		PromptVersion: PromptVersion, InputSHA256: hash, Access: access, Omitted: s.omitted(b), Steps: []Step{}}
	j := &job{done: make(chan struct{}), started: now, inv: inv, p: &progress{steps: []Step{}}}
	ctxJob, cancel := context.WithCancelCause(s.base)
	j.cancel = cancel
	s.mu.Lock()
	if s.closed || len(s.jobs) >= s.c.Concurrency {
		s.mu.Unlock()
		cancel(nil)
		s.result(ResultBusy)
		return nil, false, &BusyError{RetryAfter: busyRetry}
	}
	s.jobs[inv.ID] = j
	s.mu.Unlock()
	if err := s.c.Store.Create(ctx, inv); err != nil {
		s.mu.Lock()
		delete(s.jobs, inv.ID)
		s.mu.Unlock()
		cancel(nil)
		return nil, false, err
	}
	s.running()
	s.log.Info("investigation started", "identity", req.RequestedBy, "incident", req.IncidentID, "provider", s.Provider(),
		"model", s.o.Model, "id", inv.ID)
	tb := &toolbox{src: s.c.Source, egress: s.eg, access: access, inc: b.Incident, from: b.Window.From, to: b.Window.To,
		open: b.Incident.State == incidents.Open, now: s.now, ledger: led, timeout: s.o.ToolTimeout, bundleCT: b.CloudTrail}
	go s.run(ctxJob, j, tb, digest)
	return inv.Clone(), false, nil
}

// checkRunning refuses a second running run for the incident; a run whose
// heartbeat stopped is marked interrupted first.
func (s *Service) checkRunning(ctx context.Context, incidentID string, now time.Time) error {
	cur, err := s.c.Store.Running(ctx, incidentID)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if s.stale(cur, now) {
		s.interrupt(ctx, cur, now)
		return nil
	}
	return &ConflictError{RunningID: cur.ID}
}

func (s *Service) checkQuota(ctx context.Context, identity string, now time.Time) error {
	since := now.Add(-time.Hour)
	retry := func(oldest time.Time) time.Duration {
		d := oldest.Add(time.Hour).Sub(now).Round(time.Second)
		if d < time.Second {
			d = time.Second
		}
		return d
	}
	n, oldest, err := s.c.Store.CountSince(ctx, identity, since)
	if err != nil {
		return err
	}
	if n >= s.c.PerHour {
		return &QuotaError{Scope: "user", Limit: s.c.PerHour, RetryAfter: retry(oldest)}
	}
	n, oldest, err = s.c.Store.CountSince(ctx, "", since)
	if err != nil {
		return err
	}
	if n >= s.c.PerHourTotal {
		return &QuotaError{Scope: "total", Limit: s.c.PerHourTotal, RetryAfter: retry(oldest)}
	}
	return nil
}

// omitted is what the run's starter could not see, and sections the bundle
// could not read.
func (s *Service) omitted(b *incidents.Bundle) map[string]string {
	if len(b.Omitted) == 0 {
		return nil
	}
	out := make(map[string]string, len(b.Omitted))
	for k, v := range b.Omitted {
		out[k] = s.eg.Line(v, 200)
	}
	return out
}

// run is one job: the loop, a heartbeat, and the final write.
func (s *Service) run(ctx context.Context, j *job, tb *toolbox, digest []byte) {
	ctx, cancelT := context.WithTimeoutCause(ctx, s.o.Timeout, errTimeout)
	defer cancelT()
	provider, model := s.Provider(), s.o.Model
	a := &agent{llm: s.c.LLM, tb: tb, o: s.o, now: s.now, p: j.p, digest: digest, hooks: agentHooks{
		onTokens: func(u Usage) {
			if h := s.c.Hooks.OnTokens; h != nil {
				h(provider, model, u)
			}
		},
		onTool: s.c.Hooks.OnToolCall,
		onTurn: func() { s.persist(j) },
	}}
	hb := make(chan struct{})
	go func() {
		t := time.NewTicker(s.c.Heartbeat)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				s.persist(j)
			case <-hb:
				return
			}
		}
	}()
	out := a.run(ctx)
	close(hb)
	s.finish(j, out)
}

// persist writes the job's progress; a run finished elsewhere (cancelled
// from another replica, or marked interrupted) stops the job.
func (s *Service) persist(j *job) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.finished {
		return
	}
	inv := j.inv.Clone()
	j.p.snapshot(inv)
	inv.UpdatedAt = s.now()
	wctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
	defer cancel()
	err := s.c.Store.Update(wctx, inv)
	switch {
	case errors.Is(err, ErrNotRunning), errors.Is(err, ErrNotFound):
		j.cancel(errStopped)
	case err != nil:
		s.log.Warn("investigation progress not saved", "id", inv.ID, "err", err)
	}
}

// finish writes the outcome and counts it.
func (s *Service) finish(j *job, out outcome) {
	j.mu.Lock()
	j.finished = true
	now := s.now()
	inv := j.inv.Clone()
	j.p.snapshot(inv)
	inv.Status, inv.Error, inv.Refusal, inv.Report, inv.Evidence = out.status, out.err, out.refusal, out.report, out.evidence
	inv.UpdatedAt, inv.FinishedAt = now, &now
	wctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
	err := s.c.Store.Update(wctx, inv)
	cancel()
	j.mu.Unlock()
	switch {
	case err == nil:
		s.result(resultOf(out))
		if h := s.c.Hooks.OnDuration; h != nil {
			h(now.Sub(j.started))
		}
	case errors.Is(err, ErrNotRunning), errors.Is(err, ErrNotFound):
		// Finished elsewhere first; that writer counted it.
	default:
		s.log.Error("investigation result not saved", "id", inv.ID, "err", err)
	}
	s.log.Info("investigation finished", "id", inv.ID, "incident", inv.IncidentID, "status", out.status, "error", out.err,
		"turns", inv.Turns, "toolCalls", inv.ToolCalls, "tokens", inv.Usage.Total())
	s.mu.Lock()
	delete(s.jobs, inv.ID)
	s.mu.Unlock()
	close(j.done)
	s.running()
}

func resultOf(out outcome) string {
	switch out.status {
	case Completed:
		return ResultCompleted
	case Refused:
		return ResultRefused
	case Cancelled:
		return ResultCancelled
	}
	switch {
	case out.err == "timeout":
		return ResultTimeout
	case strings.HasPrefix(out.err, "budget"):
		return ResultBudget
	}
	return ResultFailed
}

func (s *Service) local(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.jobs[id]
	return ok
}

func (s *Service) stale(inv *Investigation, now time.Time) bool {
	return inv.Status == Running && now.Sub(inv.UpdatedAt) > StaleAfter && !s.local(inv.ID)
}

// interrupt marks a run whose replica stopped as failed.
func (s *Service) interrupt(ctx context.Context, inv *Investigation, now time.Time) {
	c := inv.Clone()
	c.Status, c.Error = Failed, "interrupted"
	c.UpdatedAt, c.FinishedAt = now, &now
	if err := s.c.Store.Update(ctx, c); err != nil && !errors.Is(err, ErrNotRunning) {
		s.log.Warn("could not mark an interrupted investigation", "id", inv.ID, "err", err)
	}
}

// present shows a running run with a stopped heartbeat as interrupted.
func (s *Service) present(inv *Investigation, now time.Time) *Investigation {
	if !s.stale(inv, now) {
		return inv
	}
	c := inv.Clone()
	c.Status, c.Error = Failed, "interrupted"
	t := inv.UpdatedAt
	c.FinishedAt = &t
	return c
}

// CanRead reports whether a reader with access reader may read a run
// started with access run: the reader must hold every capability the run
// recorded as true.
func CanRead(run, reader Access) bool { return reader.Covers(run) }

// Get returns one run of an incident, as the reader may see it:
// ErrNotFound when there is none or the reader's access does not cover the
// run's.
func (s *Service) Get(ctx context.Context, incidentID, id string, reader Access) (*Investigation, error) {
	inv, err := s.c.Store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if inv.IncidentID != incidentID || !CanRead(inv.Access, reader) {
		return nil, ErrNotFound
	}
	return s.present(inv, s.now()), nil
}

// List returns the summaries of an incident's runs the reader may read,
// newest first (at most 100), and how many others it may not.
func (s *Service) List(ctx context.Context, incidentID string, reader Access) ([]Summary, int, error) {
	runs, err := s.c.Store.List(ctx, incidentID, 100)
	if err != nil {
		return nil, 0, err
	}
	now := s.now()
	items := []Summary{}
	hidden := 0
	for _, r := range runs {
		if !CanRead(r.Access, reader) {
			hidden++
			continue
		}
		items = append(items, s.present(r, now).Summary())
	}
	return items, hidden, nil
}

// Cancel stops a running run. Only its starter may: ErrForbidden
// otherwise; ErrNotRunning when it has finished. A run on this replica
// stops at once and records its steps; one on another replica is marked
// cancelled, and that replica's job stops at its next write.
func (s *Service) Cancel(ctx context.Context, incidentID, id, identity string) (*Investigation, error) {
	inv, err := s.c.Store.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if inv.IncidentID != incidentID {
		return nil, ErrNotFound
	}
	if inv.RequestedBy != identity {
		return nil, ErrForbidden
	}
	now := s.now()
	if inv.Status != Running || s.stale(inv, now) {
		return nil, ErrNotRunning
	}
	s.mu.Lock()
	j := s.jobs[id]
	s.mu.Unlock()
	if j != nil {
		j.cancel(errCancelled)
		select {
		case <-j.done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		got, err := s.c.Store.Get(ctx, id)
		if err == nil && got.Status != Cancelled {
			return nil, ErrNotRunning // it finished first
		}
		return got, err
	}
	c := inv.Clone()
	c.Status, c.UpdatedAt, c.FinishedAt = Cancelled, now, &now
	c.Steps = append(c.Steps, Step{At: now, Kind: StepNote, Text: "cancelled by the starter"})
	if err := s.c.Store.Update(ctx, c); err != nil {
		return nil, err
	}
	s.result(ResultCancelled)
	return s.c.Store.Get(ctx, id)
}

// Shutdown stops taking new runs, stops this replica's running jobs and
// marks them failed ("interrupted"), waiting for them until ctx ends;
// jobs still writing then are marked from here.
func (s *Service) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	s.closed = true
	jobs := make([]*job, 0, len(s.jobs))
	for _, j := range s.jobs {
		jobs = append(jobs, j)
	}
	s.mu.Unlock()
	for _, j := range jobs {
		j.cancel(errShutdown)
	}
	var err error
	for _, j := range jobs {
		select {
		case <-j.done:
		case <-ctx.Done():
			err = ctx.Err()
			j.mu.Lock()
			if !j.finished {
				j.finished = true
				inv := j.inv.Clone()
				j.p.snapshot(inv)
				now := s.now()
				inv.Status, inv.Error, inv.UpdatedAt, inv.FinishedAt = Failed, "interrupted", now, &now
				wctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
				_ = s.c.Store.Update(wctx, inv)
				cancel()
			}
			j.mu.Unlock()
		}
	}
	s.stop()
	return err
}

// gateBundle leaves out what the access does not cover, whatever the
// source returned: logs, audit and CloudTrail sections and their signals,
// Node events without node access, events of other namespaces.
func gateBundle(b *incidents.Bundle, a Access) {
	if b.Omitted == nil {
		b.Omitted = map[string]string{}
	}
	for k, v := range a.Omitted() {
		b.Omitted[k] = v
	}
	if !a.Logs {
		b.Logs = nil
	}
	if !a.Audit {
		b.Audit = nil
	}
	if !a.CloudTrail {
		b.CloudTrail = nil
	}
	sigs := b.Signals[:0:0]
	for _, sg := range b.Signals {
		if a.signalVisible(sg.Type) {
			sigs = append(sigs, sg)
		}
	}
	b.Signals = sigs
	in := incidents.CloneIncident(b.Incident)
	types := []string{}
	for _, t := range in.Types {
		if a.signalVisible(t) {
			types = append(types, t)
		}
	}
	in.Types = types
	for t := range in.Counts {
		if !a.signalVisible(t) {
			delete(in.Counts, t)
		}
	}
	b.Incident = in
	ns := in.Subject.Namespace
	evs := b.Events[:0:0]
	for _, e := range b.Events {
		if e.Regarding.Kind == "Node" {
			if a.Nodes {
				evs = append(evs, e)
			}
			continue
		}
		if ns != "" && e.Namespace == ns {
			evs = append(evs, e)
		}
	}
	b.Events = evs
	b.Complete = len(b.Omitted) == 0
}

// inputHash is the cache key: the digest (without its "now"), the model,
// the effort, the prompt version and the access.
func inputHash(digest []byte, model, effort string, a Access) string {
	acc, _ := json.Marshal(a)
	h := sha256.New()
	for _, part := range [][]byte{digest, []byte(model), []byte(effort), []byte(PromptVersion), acc} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(part)))
		h.Write(n[:])
		h.Write(part)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// newID sorts by creation time: 20261016T120102Z-<8 hex>.
func newID(now time.Time) string {
	var r [4]byte
	_, _ = rand.Read(r[:])
	return now.UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(r[:])
}

// cachedCopy is a new run answering from orig: its report, evidence and
// steps, no new tokens.
func cachedCopy(orig *Investigation, identity string, now time.Time) *Investigation {
	c := orig.Clone()
	c.ID, c.RequestedBy, c.CreatedAt, c.UpdatedAt, c.FinishedAt, c.CachedFrom = newID(now), identity, now, now, &now, orig.ID
	c.Usage = Usage{}
	c.Steps = append(c.Steps, Step{At: now, Kind: StepNote, Text: "served from investigation " + orig.ID + " (same input; no new model call)"})
	return c
}
