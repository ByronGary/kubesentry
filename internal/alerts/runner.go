package alerts

import (
	"context"
	"log/slog"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Lease is a held leadership: a Postgres advisory lock (internal/pgstore
// Leader) whose store writes only while it is held.
type Lease interface {
	// Lost is closed once the lease is gone.
	Lost() <-chan struct{}
	Release(ctx context.Context) error
	// Store writes through the lease: a commit fails once it is lost.
	Store() Store
}

// actionDelay is the shortest time between evaluations when an action taken
// on this replica waits to be applied (the leader's own; another replica's
// action waits for the next evaluation, at most Interval).
const actionDelay = time.Second

// Elector tries to take the leadership without waiting; ok is false when
// another replica holds it.
type Elector func(ctx context.Context) (l Lease, ok bool, err error)

// Board is what the API lists: the findings one replica knows, sorted by
// SortKey (Keys holds them), built once per evaluation (the leader), store
// read (the others) or action taken here. It is shared and must not be
// modified.
type Board struct {
	Version  uint64
	At       time.Time
	Leader   bool
	Findings []Finding
	Keys     []string // SortKey of each finding

	byKey map[string]int // finding index by Key
}

// Find returns the finding with dedupe key key.
func (b *Board) Find(key string) (*Finding, bool) {
	if b == nil {
		return nil, false
	}
	if b.byKey != nil {
		i, ok := b.byKey[key]
		if !ok {
			return nil, false
		}
		return &b.Findings[i], true
	}
	for i := range b.Findings {
		if b.Findings[i].Key == key {
			return &b.Findings[i], true
		}
	}
	return nil, false
}

// ActResult is what came of one action: the finding as it is now, or why
// the action was not taken (ErrNotFound, ErrResolved, ErrInvalid).
type ActResult struct {
	Finding Finding
	Err     error
}

// Status is /info's alerts field, besides enabled.
type Status struct {
	Sink       string
	LastSentAt time.Time
	LastError  string
	Leader     bool
}

// Runner keeps the evaluator running on the leader and the board fresh
// everywhere.
type Runner struct {
	// Store reads the findings on replicas that do not lead (and is the
	// evaluator's store when Elect is nil).
	Store Store
	// Elect takes the leadership; nil means this replica always leads (the
	// memory store, one replica).
	Elect Elector
	Sink  Sink
	// Input returns what to evaluate: the current view and leak scan; ok is
	// false before the first view.
	Input   func() (Input, bool)
	Options Options
	// Interval is the shortest time between evaluations, and the longest a
	// quiet cluster waits for one (resends and resolves are due on time).
	// Default 30s.
	Interval time.Duration
	// Kick is signalled after each snapshot build: the evaluation that
	// follows runs as soon as Interval allows.
	Kick <-chan struct{}
	// Retry is how often a replica that does not lead tries for the lock,
	// and Refresh how often it re-reads the board. Defaults 30s and 15s.
	Retry, Refresh time.Duration
	// OnEvaluate and OnLeader feed metrics.
	OnEvaluate func(r Result, took time.Duration, err error)
	OnLeader   func(leading bool)
	Logger     *slog.Logger

	board      atomic.Pointer[Board]
	leading    atomic.Bool
	version    atomic.Uint64
	incidentOf atomic.Pointer[func(*Finding) string]

	initOnce sync.Once
	log      *actionLog    // the actions log as this replica read it; the leader's evaluator shares it
	wake     chan struct{} // an action was taken here: evaluate soon
	pubMu    sync.Mutex    // serializes publishing, so an action's board never undoes a newer one
}

// init applies the defaults and makes the actions log, once, before any
// method reads them: Run, Reload, Act and the API's calls may come from
// different goroutines.
func (r *Runner) init() {
	r.initOnce.Do(func() {
		r.log = newActionLog()
		r.wake = make(chan struct{}, 1)
		r.Options.defaults()
		if r.Interval <= 0 {
			r.Interval = 30 * time.Second
		}
		if r.Retry <= 0 {
			r.Retry = 30 * time.Second
		}
		if r.Refresh <= 0 {
			r.Refresh = 15 * time.Second
		}
		if r.Sink == nil {
			r.Sink = NopSink{}
		}
		if r.Logger == nil {
			r.Logger = slog.Default()
		}
	})
}

// SetIncidentLookup sets how a finding's incident is found (Options.
// IncidentOf), at any time: the incidents runner starts after this one.
// The next evaluation uses it; nil turns it off.
func (r *Runner) SetIncidentLookup(fn func(*Finding) string) {
	if fn == nil {
		r.incidentOf.Store(nil)
		return
	}
	r.incidentOf.Store(&fn)
}

// incidentLookup is Options.IncidentOf for the evaluator: the lookup set
// last, else the one in Options.
func (r *Runner) incidentLookup() func(*Finding) string {
	base := r.Options.IncidentOf
	return func(f *Finding) string {
		if fn := r.incidentOf.Load(); fn != nil {
			return (*fn)(f)
		}
		if base != nil {
			return base(f)
		}
		return ""
	}
}

// Board returns the latest board; nil before the first evaluation or read.
func (r *Runner) Board() *Board { return r.board.Load() }

// Status reports the sink's state and whether this replica leads.
func (r *Runner) Status() Status {
	r.init()
	s := Status{Sink: "none", Leader: r.leading.Load()}
	if r.Sink != nil {
		st := r.Sink.Status()
		s.Sink, s.LastSentAt, s.LastError = st.Name, st.LastSent, st.LastError
	}
	return s
}

// Run evaluates (leading) or follows until ctx ends.
func (r *Runner) Run(ctx context.Context) {
	r.init()
	if r.Elect == nil {
		r.lead(ctx, nil)
		return
	}
	for ctx.Err() == nil {
		l, ok, err := r.Elect(ctx)
		switch {
		case err != nil:
			r.Logger.Warn("alerts: could not try for the lock", "err", err)
		case ok:
			r.lead(ctx, l)
			continue
		}
		r.follow(ctx, r.Retry)
	}
}

// follow refreshes the board from the store for d.
func (r *Runner) follow(ctx context.Context, d time.Duration) {
	end := time.After(d)
	t := time.NewTicker(r.Refresh)
	defer t.Stop()
	for {
		r.refresh(ctx)
		select {
		case <-ctx.Done():
			return
		case <-end:
			return
		case <-t.C:
		}
	}
}

// Reload reads the stored findings and actions and publishes them as the
// board, as a replica that does not lead does every Refresh interval. Run
// does this itself; Reload serves a runner that is not run (the demo,
// tests), and must not be called while Run runs.
func (r *Runner) Reload(ctx context.Context) {
	r.init()
	r.refresh(ctx)
}

// refresh reads the findings the leader stored and the actions any replica
// recorded, and publishes them as the board (with the actions applied).
func (r *Runner) refresh(ctx context.Context) {
	fs, err := r.Store.Load(ctx, r.now().Add(-BoardWindow))
	if err != nil {
		if ctx.Err() == nil {
			r.Logger.Warn("alerts: reading findings failed", "err", err)
		}
		return
	}
	if err := r.log.sync(ctx, r.Store, r.now()); err != nil && ctx.Err() == nil {
		r.Logger.Warn("alerts: reading the actions log failed; acknowledgements and silences may lag", "err", err)
	}
	r.publish(fs, false)
}

// now is Options.Now, before and after defaults.
func (r *Runner) now() time.Time {
	if r.Options.Now != nil {
		return r.Options.Now()
	}
	return time.Now()
}

// lead evaluates while l is held (always, when l is nil), then releases it.
// The moment the lease is lost the evaluation context is cancelled and the
// sink forgets what it has queued: another replica notifies now.
func (r *Runner) lead(ctx context.Context, l Lease) {
	store := r.Store
	lctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if l != nil {
		store = l.Store()
		r.Logger.Info("alerts: this replica evaluates and notifies")
		go func() {
			select {
			case <-l.Lost():
				cancel()
			case <-lctx.Done():
			}
		}()
	}
	r.setLeading(true)
	defer func() {
		r.setLeading(false)
		r.Sink.Drop()
		if l != nil {
			rctx, rcancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			_ = l.Release(rctx)
			rcancel()
			if ctx.Err() == nil {
				r.Logger.Warn("alerts: leadership ended; notifications stop here")
			}
		}
	}()

	o := r.Options
	o.IncidentOf = r.incidentLookup()
	ev := NewEvaluator(store, r.Sink, o)
	ev.log = r.log // Act and the API see what the evaluator read, and the reverse
	var last, pruned time.Time
	acted := false // an action was taken here since the last evaluation
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-lctx.Done():
			return
		case <-r.Kick:
		case <-r.wake:
			acted = true
		case <-timer.C:
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		// At most one evaluation per Interval, but an action is applied
		// (and its notification sent) within actionDelay.
		gap := r.Interval
		if acted {
			gap = min(gap, actionDelay)
		}
		if wait := gap - time.Since(last); wait > 0 {
			timer.Reset(wait)
			continue
		}
		acted = false
		in, ok := r.Input()
		if !ok {
			timer.Reset(time.Second) // no view yet
			continue
		}
		start := time.Now()
		res, err := ev.Evaluate(lctx, in)
		took := time.Since(start)
		last = time.Now()
		if r.OnEvaluate != nil {
			r.OnEvaluate(res, took, err)
		}
		switch {
		case err != nil && lctx.Err() == nil:
			r.Logger.Warn("alerts: evaluation failed; retrying at the next one", "err", err)
		case err == nil:
			r.publish(ev.Findings(), true)
			if res.New > 0 || res.Resolved > 0 || len(res.Baselined) > 0 {
				r.Logger.Info("alerts evaluated", "new", res.New, "resolved", res.Resolved, "open", res.Open, "sent", res.Sent,
					"digest", res.Digest, "baselined", res.Baselined)
			}
		}
		if now := in.Now; now.Sub(pruned) >= time.Hour {
			pruned = now
			if n, err := store.Prune(lctx, now.Add(-Retention)); err != nil && lctx.Err() == nil {
				r.Logger.Warn("alerts: pruning resolved findings failed", "err", err)
			} else if n > 0 {
				r.Logger.Info("alerts: pruned resolved findings", "count", n)
			}
		}
		timer.Reset(r.Interval)
	}
}

func (r *Runner) setLeading(on bool) {
	r.leading.Store(on)
	if r.OnLeader != nil {
		r.OnLeader(on)
	}
}

// publish applies the actions log to fs (which it keeps) and sorts them
// into a new board.
func (r *Runner) publish(fs []Finding, leader bool) {
	r.pubMu.Lock()
	defer r.pubMu.Unlock()
	r.publishLocked(fs, leader)
}

func (r *Runner) publishLocked(fs []Finding, leader bool) *Board {
	now := r.now()
	for i := range fs {
		applyMarks(&fs[i], r.log.mark(fs[i].Key), now)
	}
	b := NewBoard(fs, now)
	b.Leader = leader
	b.Version = r.version.Add(1)
	r.board.Store(b)
	return b
}

// MaxSilence is the longest silence Act sets (Options.MaxSilence).
func (r *Runner) MaxSilence() time.Duration {
	r.init()
	return r.Options.MaxSilence
}

// Act records actions on findings of the board and applies them at once:
// each is checked against its finding (ErrNotFound, ErrResolved,
// ErrInvalid in its result), written to the actions log (through the
// store's pool, on any replica), and the board is published again with a
// new version. The leader is woken, so its notifications follow within an
// evaluation interval (another replica's leader reads the log at its next
// evaluation). Act fills each action's FirstSeen, Severity and At, and
// shortens a silence to MaxSilence. The error is the store's: actions
// before the failing one are recorded and applied.
func (r *Runner) Act(ctx context.Context, acts ...Action) ([]ActResult, error) {
	r.init()
	now := r.now()
	maxUntil := now.Add(r.MaxSilence())
	b := r.Board()
	results := make([]ActResult, len(acts))
	wrote := false
	var err error
	for i, a := range acts {
		f, ok := b.Find(a.Key)
		if !ok {
			results[i].Err = ErrNotFound
			continue
		}
		results[i].Finding = *f
		if a.Action == ActionSilence && a.Until != nil && a.Until.After(maxUntil) {
			a.Until = timePtr(maxUntil)
		}
		if e := checkAction(f, &a, now); e != nil {
			results[i].Err = e
			continue
		}
		a.ID, a.FirstSeen, a.Severity, a.At = 0, f.FirstSeen, f.Severity, now
		if a.Action != ActionSilence {
			a.Until = nil
		}
		var stored Action
		if stored, err = r.Store.AddAction(ctx, a); err != nil {
			results = results[:i]
			break
		}
		r.log.merge([]Action{stored}, now)
		wrote = true
	}
	if !wrote {
		return results, err
	}
	r.pubMu.Lock()
	cur := r.Board()
	var fs []Finding
	leader := false
	if cur != nil {
		fs, leader = slices.Clone(cur.Findings), cur.Leader
	}
	nb := r.publishLocked(fs, leader)
	r.pubMu.Unlock()
	for i := range results {
		if results[i].Err == nil {
			if f, ok := nb.Find(acts[i].Key); ok {
				results[i].Finding = *f
			}
		}
	}
	select {
	case r.wake <- struct{}{}:
	default:
	}
	return results, err
}

// Actions returns the actions this replica has read (and taken), newest
// first: those on key, or on every key when key is "", at most limit, that
// keep accepts.
func (r *Runner) Actions(key string, limit int, keep func(*Action) bool) []Action {
	r.init()
	return r.log.list(key, limit, keep)
}

// NewBoard sorts fs (which it keeps) into a board. Its version is 0.
func NewBoard(fs []Finding, at time.Time) *Board {
	keys := make([]string, len(fs))
	idx := make([]int, len(fs))
	for i := range fs {
		keys[i] = SortKey(&fs[i])
		idx[i] = i
	}
	sort.Slice(idx, func(a, b int) bool { return keys[idx[a]] < keys[idx[b]] })
	b := &Board{At: at, Findings: make([]Finding, len(fs)), Keys: make([]string, len(fs)), byKey: make(map[string]int, len(fs))}
	for i, j := range idx {
		b.Findings[i], b.Keys[i] = fs[j], keys[j]
		b.byKey[fs[j].Key] = i
	}
	return b
}
