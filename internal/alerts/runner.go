package alerts

import (
	"context"
	"log/slog"
	"sort"
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

// Elector tries to take the leadership without waiting; ok is false when
// another replica holds it.
type Elector func(ctx context.Context) (l Lease, ok bool, err error)

// Board is what the API lists: the findings one replica knows, sorted by
// SortKey (Keys holds them), built once per evaluation (the leader) or
// store read (the others). It is shared and must not be modified.
type Board struct {
	Version  uint64
	At       time.Time
	Leader   bool
	Findings []Finding
	Keys     []string // SortKey of each finding
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

	board   atomic.Pointer[Board]
	leading atomic.Bool
	version atomic.Uint64
}

func (r *Runner) defaults() {
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
}

// Board returns the latest board; nil before the first evaluation or read.
func (r *Runner) Board() *Board { return r.board.Load() }

// Status reports the sink's state and whether this replica leads.
func (r *Runner) Status() Status {
	s := Status{Sink: "none", Leader: r.leading.Load()}
	if r.Sink != nil {
		st := r.Sink.Status()
		s.Sink, s.LastSentAt, s.LastError = st.Name, st.LastSent, st.LastError
	}
	return s
}

// Run evaluates (leading) or follows until ctx ends.
func (r *Runner) Run(ctx context.Context) {
	r.defaults()
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

func (r *Runner) refresh(ctx context.Context) {
	fs, err := r.Store.Load(ctx, r.Options.Now().Add(-BoardWindow))
	if err != nil {
		if ctx.Err() == nil {
			r.Logger.Warn("alerts: reading findings failed", "err", err)
		}
		return
	}
	r.publish(fs, false)
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

	ev := NewEvaluator(store, r.Sink, r.Options)
	var last, pruned time.Time
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-lctx.Done():
			return
		case <-r.Kick:
			if wait := r.Interval - time.Since(last); wait > 0 {
				continue // the timer runs the next evaluation
			}
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		case <-timer.C:
		}
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

// publish sorts fs into a new board.
func (r *Runner) publish(fs []Finding, leader bool) {
	b := NewBoard(fs, r.Options.Now())
	b.Leader = leader
	b.Version = r.version.Add(1)
	r.board.Store(b)
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
	b := &Board{At: at, Findings: make([]Finding, len(fs)), Keys: make([]string, len(fs))}
	for i, j := range idx {
		b.Findings[i], b.Keys[i] = fs[j], keys[j]
	}
	return b
}
