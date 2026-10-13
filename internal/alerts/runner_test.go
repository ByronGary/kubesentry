package alerts

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeLease struct {
	lost     chan struct{}
	store    Store
	released atomic.Bool
}

func (l *fakeLease) Lost() <-chan struct{}         { return l.lost }
func (l *fakeLease) Release(context.Context) error { l.released.Store(true); return nil }
func (l *fakeLease) Store() Store                  { return l.store }

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The leader evaluates and notifies; once its lease is lost it stops at
// once, drops what its sink queued and releases the lease. As a follower it
// sends nothing and serves the board from the store.
func TestRunnerStopsNotifyingWhenLeadershipIsLost(t *testing.T) {
	store := NewMemoryStore()
	sink := &recordSink{}
	lease := &fakeLease{lost: make(chan struct{}), store: store}
	var elections atomic.Int32
	var mu sync.Mutex
	evals := 0
	var leaderFlips []bool
	r := &Runner{
		Store: store, Sink: sink, Interval: 10 * time.Millisecond, Retry: 30 * time.Millisecond, Refresh: 5 * time.Millisecond,
		Elect: func(context.Context) (Lease, bool, error) {
			if elections.Add(1) == 1 {
				return lease, true, nil
			}
			return nil, false, nil
		},
		// Each evaluation is a minute later, so every one re-posts.
		Input: func() (Input, bool) {
			mu.Lock()
			defer mu.Unlock()
			evals++
			now := t0.Add(time.Duration(evals) * time.Minute)
			return Input{View: view(fixture(), now), Leaks: leakReport(now), Now: now}, true
		},
		Options:  Options{Now: func() time.Time { return t0 }},
		OnLeader: func(on bool) { mu.Lock(); leaderFlips = append(leaderFlips, on); mu.Unlock() },
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	eventually(t, "a few notifying evaluations", func() bool {
		sink.mu.Lock()
		defer sink.mu.Unlock()
		return len(sink.batches) >= 3
	})
	if b := r.Board(); b == nil || !b.Leader || len(b.Findings) == 0 || !r.Status().Leader {
		t.Fatalf("leader board = %+v", b)
	}
	close(lease.lost)
	eventually(t, "the lease released", func() bool { return lease.released.Load() && !r.Status().Leader })
	sink.mu.Lock()
	dropped := sink.dropped
	sink.mu.Unlock()
	if dropped == 0 {
		t.Error("the sink's queue was not dropped")
	}
	sink.take()
	eventually(t, "a follower board", func() bool { b := r.Board(); return b != nil && !b.Leader && len(b.Findings) > 0 })
	time.Sleep(50 * time.Millisecond)
	if sent := sink.take(); len(sent) != 0 {
		t.Fatalf("a replica without the lease sent %v", names(sent))
	}
	mu.Lock()
	defer mu.Unlock()
	if len(leaderFlips) < 2 || !leaderFlips[0] || leaderFlips[1] {
		t.Errorf("leader flips = %v", leaderFlips)
	}
}

// Without an elector (the memory store) the runner leads at once, waits for
// a view, and stops with its context.
func TestRunnerMemoryModeLeadsAlone(t *testing.T) {
	sink := &recordSink{}
	var ready atomic.Bool
	r := &Runner{
		Store: NewMemoryStore(), Sink: sink, Interval: 10 * time.Millisecond,
		Input: func() (Input, bool) {
			if !ready.Load() {
				return Input{}, false
			}
			return Input{View: view(fixture(), t0), Leaks: leakReport(t0), Now: t0}, true
		},
		Options: Options{Now: func() time.Time { return t0 }},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	eventually(t, "leading", func() bool { return r.Status().Leader })
	if r.Board() != nil {
		t.Error("a board before the first view")
	}
	ready.Store(true)
	eventually(t, "a board", func() bool { b := r.Board(); return b != nil && len(b.Findings) == 4 })
	if b := r.Board(); b.Keys[0] > b.Keys[len(b.Keys)-1] || b.Findings[0].Severity != SeverityCritical {
		t.Errorf("board not sorted worst first: %v", b.Keys)
	}
	cancel()
	<-done
	if r.Status().Leader {
		t.Error("still leading after stop")
	}
}
