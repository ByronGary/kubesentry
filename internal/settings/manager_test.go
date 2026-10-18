package settings

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"
)

// replica is one kubesentry replica's manager and what it last applied.
type replica struct {
	m       *Manager
	mu      sync.Mutex
	applied []Investigator
	fail    error
}

func (r *replica) apply(_ context.Context, s Investigator) (Commit, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail != nil {
		return nil, r.fail
	}
	return func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.applied = append(r.applied, s)
	}, nil
}

func (r *replica) last() Investigator {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.applied) == 0 {
		return Investigator{Provider: "nothing applied"}
	}
	return r.applied[len(r.applied)-1]
}

func (r *replica) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.applied)
}

func newReplica(t *testing.T, st Store, mode string, ack bool) *replica {
	t.Helper()
	r := &replica{}
	m, err := NewManager(ManagerConfig{Store: st, Helm: helmDefaults(), Mode: mode, PlatformAck: ack, Apply: r.apply,
		Env: func() Env { return okEnv }, Now: func() time.Time { return time.Date(2026, 10, 18, 9, 0, 0, 0, time.UTC) },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.m = m
	return r
}

func TestManagerReplicas(t *testing.T) {
	ctx := context.Background()
	st := NewMemoryStore()
	a, b := newReplica(t, st, ModeUI, false), newReplica(t, st, ModeUI, false)
	if a.last().Enabled || a.count() != 1 || b.count() != 1 {
		t.Fatalf("initial apply: %+v (%d)", a.last(), a.count())
	}
	s, _ := a.m.State(ctx)
	if s.Version != 0 || s.Locked || s.Mode != ModeUI || len(s.Audit) != 0 || s.Sources["enabled"].Source != SourceHelm {
		t.Fatalf("initial state %+v", s)
	}
	on := s.Values
	on.Enabled = true
	// Turning it on needs the egress acknowledgement.
	if _, err := a.m.Save(ctx, SaveRequest{Actor: "alice", Version: 0, Values: on}); !errors.Is(err, ErrEgressAck) {
		t.Fatalf("no acknowledgement: %v", err)
	}
	s, err := a.m.Save(ctx, SaveRequest{Actor: "alice", Version: 0, Values: on, EgressAcknowledged: true})
	if err != nil {
		t.Fatal(err)
	}
	// Applied at once on the saving replica.
	if !a.last().Enabled || s.Version != 1 || !s.Applied.Enabled || s.Sources["enabled"].Source != SourceUI || s.Sources["enabled"].By != "alice" ||
		len(s.Audit) != 1 || !s.Audit[0].EgressAcknowledged || s.Audit[0].Actor != "alice" || s.Audit[0].Changes[0].Field != "enabled" {
		t.Fatalf("after the save: %+v", s)
	}
	// The other replica follows at its next poll.
	if b.last().Enabled {
		t.Fatal("b applied before polling")
	}
	if err := b.m.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if !b.last().Enabled || b.count() != 2 {
		t.Fatalf("b after the poll: %+v (%d)", b.last(), b.count())
	}
	// Polling again without a change applies nothing.
	_ = b.m.Refresh(ctx)
	if b.count() != 2 {
		t.Error("b applied an unchanged version again")
	}
	// A save on a stale version conflicts.
	off := on
	off.Enabled = false
	if _, err := b.m.Save(ctx, SaveRequest{Actor: "bob", Version: 0, Values: off}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale save: %v", err)
	}
	// Turning it off needs no acknowledgement; the past stays in the audit.
	s, err = b.m.Save(ctx, SaveRequest{Actor: "bob", Version: 1, Values: off})
	if err != nil {
		t.Fatal(err)
	}
	if b.last().Enabled || s.Version != 2 || len(s.Audit) != 2 || s.Audit[0].Actor != "bob" || s.Audit[0].EgressAcknowledged {
		t.Fatalf("off: %+v", s)
	}
	_ = a.m.Refresh(ctx)
	if a.last().Enabled {
		t.Error("a still on")
	}
	// Reset to the Helm values.
	tuned := off
	tuned.Effort = "max"
	if _, err := a.m.Save(ctx, SaveRequest{Actor: "alice", Version: 2, Values: tuned}); err != nil {
		t.Fatal(err)
	}
	if !a.m.Overridden() {
		t.Error("not overridden")
	}
	s, err = a.m.Save(ctx, SaveRequest{Actor: "alice", Version: 3, Reset: true})
	if err != nil {
		t.Fatal(err)
	}
	if s.Values.Effort != "high" || s.Sources["effort"].Source != SourceHelm || s.Audit[0].Action != ActionReset || a.m.Overridden() {
		t.Errorf("reset: %+v", s)
	}
	// Invalid values are refused before anything is stored.
	bad := s.Values
	bad.Limits.MaxTurns = 0
	if _, err := a.m.Save(ctx, SaveRequest{Actor: "alice", Version: s.Version, Values: bad}); len(fieldsOf(err)) != 1 {
		t.Errorf("invalid: %v", err)
	}
	// Settings that cannot be built are refused, and nothing is stored.
	a.fail = errors.New("no credentials")
	tuned.Effort = "low"
	var ae *ApplyError
	if _, err := a.m.Save(ctx, SaveRequest{Actor: "alice", Version: s.Version, Values: tuned}); !errors.As(err, &ae) {
		t.Errorf("unbuildable: %v", err)
	}
	if got, _ := a.m.State(ctx); got.Version != s.Version {
		t.Errorf("an unbuildable save was stored: version %d", got.Version)
	}
	// No change, no write.
	a.fail = nil
	same, err := a.m.Save(ctx, SaveRequest{Actor: "alice", Version: s.Version, Values: s.Values})
	if err != nil || same.Version != s.Version {
		t.Errorf("no-op save: %v %d", err, same.Version)
	}
}

func TestManagerRefreshKeepsWhatRunsWhenApplyFails(t *testing.T) {
	ctx := context.Background()
	st := NewMemoryStore()
	a, b := newReplica(t, st, ModeUI, true), newReplica(t, st, ModeUI, true)
	on := helmDefaults()
	on.Enabled = true
	// The platform acknowledged the egress: no checkbox needed, and the
	// audit says so.
	s, err := a.m.Save(ctx, SaveRequest{Actor: "alice", Values: on})
	if err != nil {
		t.Fatal(err)
	}
	if !s.Audit[0].EgressAckByPlatform || s.Audit[0].EgressAcknowledged || !s.EgressAckByPlatform {
		t.Errorf("platform ack: %+v", s.Audit[0])
	}
	b.fail = errors.New("credentials expired")
	if err := b.m.Refresh(ctx); err == nil {
		t.Fatal("no error")
	}
	bs, _ := b.m.State(ctx)
	if b.last().Enabled || bs.Applied.Error == "" || bs.Applied.Enabled {
		t.Errorf("b after a failed apply: %+v", bs.Applied)
	}
	// The next poll retries.
	b.fail = nil
	if err := b.m.Refresh(ctx); err != nil || !b.last().Enabled {
		t.Errorf("retry: %v %+v", err, b.last())
	}
}

func TestManagerLocked(t *testing.T) {
	ctx := context.Background()
	st := NewMemoryStore()
	ui := newReplica(t, st, ModeUI, false)
	on := helmDefaults()
	on.Enabled, on.Effort = true, "max"
	if _, err := ui.m.Save(ctx, SaveRequest{Actor: "alice", Values: on, EgressAcknowledged: true}); err != nil {
		t.Fatal(err)
	}
	// Locked: stored values are ignored, writes refused.
	l := newReplica(t, st, ModeLocked, false)
	if l.last().Enabled || l.last().Effort != "high" {
		t.Errorf("locked applied %+v", l.last())
	}
	s, _ := l.m.State(ctx)
	if !s.Locked || s.Values.Enabled || s.Sources["effort"].Source != SourceHelm {
		t.Errorf("locked state %+v", s)
	}
	if _, err := l.m.Save(ctx, SaveRequest{Actor: "alice", Version: s.Version, Values: on}); !errors.Is(err, ErrLocked) {
		t.Errorf("locked save: %v", err)
	}
	if _, err := NewManager(ManagerConfig{Store: st, Apply: l.apply, Mode: "open"}); err == nil {
		t.Error("an unknown mode accepted")
	}
}

func TestMemoryStore(t *testing.T) {
	ctx := context.Background()
	st := NewMemoryStore()
	if _, err := st.Get(ctx, Name); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 18, 9, 0, 0, 123456789, time.UTC)
	r, err := st.Put(ctx, Record{Name: Name, Value: []byte(`{"a": 1}`), UpdatedAt: at, UpdatedBy: "alice"}, 0,
		AuditEntry{At: at, Actor: "alice", Action: ActionSave, Changes: []Change{{Field: "enabled", Old: "false", New: "true"}}})
	if err != nil || r.Version != 1 || string(r.Value) != `{"a":1}` || r.UpdatedAt.Nanosecond() != 123456000 {
		t.Fatalf("put: %+v %v", r, err)
	}
	if _, err := st.Put(ctx, Record{Name: Name, Value: []byte(`{}`)}, 0, AuditEntry{}); !errors.Is(err, ErrConflict) {
		t.Errorf("conflict: %v", err)
	}
	if _, err := st.Put(ctx, Record{Name: Name, Value: []byte(`{`)}, 1, AuditEntry{}); err == nil {
		t.Error("bad JSON accepted")
	}
	st.Put(ctx, Record{Name: Name, Value: []byte(`{}`)}, 1, AuditEntry{Actor: "bob"})
	st.Put(ctx, Record{Name: "other", Value: []byte(`{}`)}, 0, AuditEntry{Actor: "carol"})
	l, _ := st.Audit(ctx, Name, 0)
	if len(l) != 2 || l[0].Actor != "bob" || l[0].Version != 2 || l[1].Changes[0].Field != "enabled" {
		t.Errorf("audit %+v", l)
	}
	if l, _ := st.Audit(ctx, Name, 1); len(l) != 1 {
		t.Errorf("limit: %d", len(l))
	}
}
