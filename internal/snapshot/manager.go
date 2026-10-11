package snapshot

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ByronGary/kubesentry/internal/detectors"
)

// Default debounce bounds for a Manager.
const (
	DefaultMinInterval = 2 * time.Second
	DefaultMaxDelay    = 10 * time.Second
)

// Manager keeps a current view. It builds one at start, then rebuilds after
// the cluster changes: when the Source is a Notifier, a change starts a wait
// of the current interval during which further changes are coalesced, then
// one rebuild runs; otherwise it rebuilds every interval. The interval adapts
// to the cost of a build: max(MinInterval, 5 × the last build time), capped
// at MaxDelay. A failed rebuild keeps serving the last good view, marked Stale
// with the error, and is retried after the interval.
type Manager struct {
	Source      Source
	Policy      detectors.Policy
	MinInterval time.Duration    // default DefaultMinInterval
	MaxDelay    time.Duration    // default DefaultMaxDelay
	Now         func() time.Time // default time.Now; stamps View.Built
	// OnBuild, if set, is called after every build attempt with the view now
	// being served (nil before the first success) and the error, if any. Use
	// it for metrics.
	OnBuild func(v *View, took time.Duration, err error)

	initOnce  sync.Once
	ready     chan struct{}
	readyOnce sync.Once
	cur       atomic.Pointer[View]
	lastErr   atomic.Pointer[error]
	lastBuild atomic.Int64 // nanoseconds the last build took

	// after is time.After; tests replace it with a fake clock.
	after func(time.Duration) <-chan time.Time
}

var (
	_ ViewProvider = (*Manager)(nil)
	_ ViewProvider = OnDemand{}
)

func (m *Manager) init() {
	m.initOnce.Do(func() {
		m.ready = make(chan struct{})
		if m.after == nil {
			m.after = time.After
		}
	})
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// interval is the current debounce and polling interval.
func (m *Manager) interval() time.Duration {
	lo, hi := m.MinInterval, m.MaxDelay
	if lo <= 0 {
		lo = DefaultMinInterval
	}
	if hi <= 0 {
		hi = DefaultMaxDelay
	}
	d := 5 * time.Duration(m.lastBuild.Load())
	if d < lo {
		d = lo
	}
	if d > hi {
		d = hi
	}
	return d
}

// Run builds views until ctx is done, then returns ctx.Err().
func (m *Manager) Run(ctx context.Context) error {
	m.init()
	var changes <-chan struct{}
	if n, ok := m.Source.(Notifier); ok {
		changes = n.Changes()
	}
	ok := m.rebuild(ctx)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if changes == nil || !ok {
			// Poll, or retry a failed build even if nothing announces a change.
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-m.after(m.interval()):
			}
			ok = m.rebuild(ctx)
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case _, open := <-changes:
			if !open {
				changes = nil
				continue
			}
		}
		timer := m.after(m.interval())
	coalesce:
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case _, open := <-changes:
				if !open {
					changes = nil // a nil channel never fires; wait for the timer
				}
			case <-timer:
				break coalesce
			}
		}
		ok = m.rebuild(ctx)
	}
}

// rebuild reads the source and swaps in a new view. It reports success.
func (m *Manager) rebuild(ctx context.Context) bool {
	start := time.Now()
	inv, err := m.Source.Inventory(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return false // shutting down; not a failure of the source
		}
		m.lastErr.Store(&err)
		v := m.cur.Load()
		if v != nil {
			v = withStale(v, err)
			m.cur.Store(v)
		}
		if m.OnBuild != nil {
			m.OnBuild(v, time.Since(start), err)
		}
		return false
	}
	v := Build(inv, m.Policy, m.now())
	took := time.Since(start)
	m.lastBuild.Store(int64(took))
	m.cur.Store(v)
	m.lastErr.Store(nil)
	m.readyOnce.Do(func() { close(m.ready) })
	if m.OnBuild != nil {
		m.OnBuild(v, took, nil)
	}
	return true
}

// Current returns the view being served, or nil before the first build.
func (m *Manager) Current() *View { return m.cur.Load() }

// Ready is closed once the first view exists.
func (m *Manager) Ready() <-chan struct{} {
	m.init()
	return m.ready
}

// View returns the current view, waiting for the first one until ctx is done.
func (m *Manager) View(ctx context.Context) (*View, error) {
	m.init()
	if v := m.cur.Load(); v != nil {
		return v, nil
	}
	select {
	case <-m.ready:
		return m.cur.Load(), nil
	case <-ctx.Done():
		if e := m.lastErr.Load(); e != nil {
			return nil, fmt.Errorf("snapshot: no view yet (last build failed: %v): %w", *e, ctx.Err())
		}
		return nil, fmt.Errorf("snapshot: no view yet: %w", ctx.Err())
	}
}

// OnDemand builds a fresh view on every call: the -cache=false debugging path,
// and tests.
type OnDemand struct {
	Source Source
	Policy detectors.Policy
	Now    func() time.Time // default time.Now
}

// View reads the source and builds a view.
func (o OnDemand) View(ctx context.Context) (*View, error) {
	inv, err := o.Source.Inventory(ctx)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if o.Now != nil {
		now = o.Now()
	}
	return Build(inv, o.Policy, now), nil
}

// Static always hands out v.
func Static(v *View) ViewProvider { return staticView{v} }

type staticView struct{ v *View }

func (s staticView) View(context.Context) (*View, error) {
	if s.v == nil {
		return nil, errors.New("snapshot: no view")
	}
	return s.v, nil
}
