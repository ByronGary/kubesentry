package settings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// Modes of -investigator-settings.
const (
	// ModeUI: the flags give the initial values; an admin's saved values
	// win over them, field by field.
	ModeUI = "ui"
	// ModeLocked: the flags are the only source; writes are refused.
	ModeLocked = "locked"
)

// DefaultPoll is how often every replica reads the stored version.
const DefaultPoll = 15 * time.Second

// AuditShown is how many audit entries State carries.
const AuditShown = 20

// Commit makes built settings the ones in force.
type Commit func()

// Applier builds what the settings need (the model client and the
// investigator's runtime) without changing anything; the returned Commit
// swaps it in. An error leaves everything as it was.
type Applier func(ctx context.Context, s Investigator) (Commit, error)

// ApplyError is settings that could not be built (for example Bedrock
// credentials that do not resolve).
type ApplyError struct{ Err error }

func (e *ApplyError) Error() string { return "settings: could not apply: " + e.Err.Error() }
func (e *ApplyError) Unwrap() error { return e.Err }

// ManagerConfig configures a Manager.
type ManagerConfig struct {
	Store Store
	// Helm is the settings the flags give.
	Helm Investigator
	// Mode is ModeUI (default) or ModeLocked.
	Mode string
	// Env reports the environment validation needs (live: incidents, the
	// Anthropic key's presence, the default region).
	Env func() Env
	// PlatformAck is -investigator-egress-ack: the platform acknowledged the
	// data egress, so enabling needs no acknowledgement from the admin.
	PlatformAck bool
	// Apply builds and swaps in the settings in force; required.
	Apply Applier
	// Poll is how often Run reads the stored version (DefaultPoll).
	Poll   time.Duration
	Now    func() time.Time
	Logger *slog.Logger
}

// Manager keeps one replica's investigator settings: it loads them, applies
// them, saves an admin's changes (and applies them at once on this replica),
// and follows other replicas' saves by polling the stored version.
type Manager struct {
	c   ManagerConfig
	now func() time.Time
	log *slog.Logger

	// wmu serialises this replica's writes and applies.
	wmu sync.Mutex

	mu        sync.Mutex
	version   int64
	stored    *Stored
	updatedAt time.Time
	updatedBy string
	applied   Investigator
	appliedOK bool
	appliedAt time.Time
	applyErr  error
}

// NewManager checks the config.
func NewManager(c ManagerConfig) (*Manager, error) {
	if c.Store == nil || c.Apply == nil {
		return nil, errors.New("settings: a store and an applier are required")
	}
	switch c.Mode {
	case "":
		c.Mode = ModeUI
	case ModeUI, ModeLocked:
	default:
		return nil, fmt.Errorf("settings: mode %q: use ui or locked", c.Mode)
	}
	if c.Env == nil {
		c.Env = func() Env { return Env{} }
	}
	if c.Poll <= 0 {
		c.Poll = DefaultPoll
	}
	m := &Manager{c: c, now: c.Now, log: c.Logger}
	if m.now == nil {
		m.now = time.Now
	}
	if m.log == nil {
		m.log = slog.Default()
	}
	return m, nil
}

// Locked reports whether the flags are the only source.
func (m *Manager) Locked() bool { return m.c.Mode == ModeLocked }

// Mode is ui or locked.
func (m *Manager) Mode() string { return m.c.Mode }

// Helm is the settings the flags give.
func (m *Manager) Helm() Investigator { return m.c.Helm }

// PlatformAck reports -investigator-egress-ack.
func (m *Manager) PlatformAck() bool { return m.c.PlatformAck }

// Env is the environment as validation sees it now.
func (m *Manager) Env() Env { return m.c.Env() }

// effective is the settings in force for stored settings st.
func (m *Manager) effective(st *Stored) (Investigator, map[string]Source) {
	if m.Locked() {
		st = nil
	}
	return Effective(m.c.Helm, st)
}

// Overridden reports whether saved settings override the flags.
func (m *Manager) Overridden() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return !m.Locked() && m.stored != nil && len(m.stored.Fields) > 0
}

// Load reads the stored settings and applies the settings in force. An
// error from building them is returned as *ApplyError (nothing applied);
// the caller decides whether that stops the server.
func (m *Manager) Load(ctx context.Context) error {
	m.wmu.Lock()
	defer m.wmu.Unlock()
	rec, st, err := m.read(ctx)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.setRecord(rec, st)
	m.mu.Unlock()
	eff, _ := m.effective(st)
	return m.apply(ctx, eff, true)
}

// read loads the stored record; nothing stored is (nil, nil, nil).
func (m *Manager) read(ctx context.Context) (*Record, *Stored, error) {
	rec, err := m.c.Store.Get(ctx, Name)
	if errors.Is(err, ErrNotFound) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	st, err := decodeStored(rec.Value)
	if err != nil {
		return nil, nil, err
	}
	return rec, st, nil
}

func decodeStored(raw json.RawMessage) (*Stored, error) {
	var st Stored
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("settings: the stored investigator settings: %w", err)
	}
	if st.Fields == nil {
		st.Fields = map[string]Mark{}
	}
	return &st, nil
}

// setRecord takes rec as the latest known; m.mu held.
func (m *Manager) setRecord(rec *Record, st *Stored) {
	if rec == nil {
		m.version, m.stored, m.updatedAt, m.updatedBy = 0, nil, time.Time{}, ""
		return
	}
	m.version, m.stored, m.updatedAt, m.updatedBy = rec.Version, st, rec.UpdatedAt, rec.UpdatedBy
}

// apply builds and swaps in s unless it is already in force (force applies
// anyway); wmu held.
func (m *Manager) apply(ctx context.Context, s Investigator, force bool) error {
	m.mu.Lock()
	same := m.appliedOK && len(Changes(m.applied, s)) == 0
	m.mu.Unlock()
	if same && !force {
		return nil
	}
	commit, err := m.c.Apply(ctx, s)
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		m.applyErr = &ApplyError{Err: err}
		return m.applyErr
	}
	commit()
	m.applied, m.appliedOK, m.appliedAt, m.applyErr = s, true, m.now().UTC(), nil
	return nil
}

// Refresh reads the stored version and, when it moved, applies the new
// settings in force.
func (m *Manager) Refresh(ctx context.Context) error {
	m.wmu.Lock()
	defer m.wmu.Unlock()
	rec, st, err := m.read(ctx)
	if err != nil {
		return err
	}
	var v int64
	if rec != nil {
		v = rec.Version
	}
	m.mu.Lock()
	moved := v != m.version
	if moved {
		m.setRecord(rec, st)
	}
	retry := m.applyErr != nil
	m.mu.Unlock()
	if !moved && !retry {
		return nil
	}
	eff, _ := m.effective(st)
	if err := m.apply(ctx, eff, false); err != nil {
		return err
	}
	if moved {
		m.log.Info("investigator settings applied", "version", v, "enabled", eff.Enabled, "provider", eff.Provider, "model", eff.ModelID())
	}
	return nil
}

// Run polls until ctx ends. In locked mode there is nothing to follow.
func (m *Manager) Run(ctx context.Context) {
	if m.Locked() {
		return
	}
	t := time.NewTicker(m.c.Poll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := m.Refresh(ctx); err != nil && ctx.Err() == nil {
				m.log.Warn("investigator settings not refreshed", "err", err)
			}
		}
	}
}

// Applied is what this replica runs with.
type Applied struct {
	Enabled bool       `json:"enabled"`
	At      *time.Time `json:"at,omitempty"`
	// Error is why the settings in force could not be applied on this
	// replica (it keeps what it ran before).
	Error string `json:"error,omitempty"`
}

// State is the settings as the Settings page shows them.
type State struct {
	Values  Investigator      `json:"values"`
	Helm    Investigator      `json:"helm"`
	Sources map[string]Source `json:"sources"`
	Mode    string            `json:"mode"`
	Locked  bool              `json:"locked"`
	// Version is what a save must name (optimistic concurrency).
	Version   int64        `json:"version"`
	UpdatedAt *time.Time   `json:"updatedAt,omitempty"`
	UpdatedBy string       `json:"updatedBy,omitempty"`
	Applied   Applied      `json:"applied"`
	Audit     []AuditEntry `json:"audit"`
	// EgressAckByPlatform: -investigator-egress-ack is set.
	EgressAckByPlatform bool   `json:"egressAckByPlatform"`
	Incidents           bool   `json:"incidents"`
	AnthropicKey        bool   `json:"anthropicKey"`
	DefaultRegion       string `json:"defaultRegion,omitempty"`
}

// State returns the settings in force, their sources and the newest audit
// entries.
func (m *Manager) State(ctx context.Context) (*State, error) {
	audit, err := m.c.Store.Audit(ctx, Name, AuditShown)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stateLocked(audit), nil
}

func (m *Manager) stateLocked(audit []AuditEntry) *State {
	eff, src := m.effective(m.stored)
	env := m.c.Env()
	s := &State{Values: eff, Helm: m.c.Helm, Sources: src, Mode: m.c.Mode, Locked: m.Locked(), Version: m.version,
		UpdatedBy: m.updatedBy, Audit: audit, EgressAckByPlatform: m.c.PlatformAck, Incidents: env.Incidents,
		AnthropicKey: env.AnthropicKey, DefaultRegion: env.DefaultRegion}
	if s.Audit == nil {
		s.Audit = []AuditEntry{}
	}
	if !m.updatedAt.IsZero() {
		t := m.updatedAt
		s.UpdatedAt = &t
	}
	s.Applied.Enabled = m.appliedOK && m.applied.Enabled
	if !m.appliedAt.IsZero() {
		t := m.appliedAt
		s.Applied.At = &t
	}
	if m.applyErr != nil {
		s.Applied.Error = m.applyErr.Error()
	}
	return s
}

// SaveRequest is an admin's write.
type SaveRequest struct {
	Actor string
	// Version is the version the admin's page showed.
	Version int64
	// Values are the settings to save (ignored with Reset).
	Values Investigator
	// Reset drops every override: the flags apply again.
	Reset bool
	// EgressAcknowledged: the admin ticked the data egress acknowledgement.
	EgressAcknowledged bool
}

// Save validates, builds, stores and applies an admin's change on this
// replica; the others follow within the poll interval. Errors: ErrLocked,
// ErrConflict, ErrEgressAck, *ValidationError, *ApplyError.
func (m *Manager) Save(ctx context.Context, req SaveRequest) (*State, error) {
	if m.Locked() {
		return nil, ErrLocked
	}
	if strings.TrimSpace(req.Actor) == "" {
		return nil, errors.New("settings: an actor is required")
	}
	m.wmu.Lock()
	defer m.wmu.Unlock()
	// The store's version is the one that counts; follow it first.
	rec, st, err := m.read(ctx)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	m.setRecord(rec, st)
	m.mu.Unlock()
	cur, _ := m.effective(st)
	var next *Stored
	var changes []Change
	action := ActionSave
	if req.Reset {
		next, changes = Reset(m.c.Helm, st)
		action = ActionReset
	} else {
		next, changes = Save(m.c.Helm, st, req.Values, req.Actor, m.now())
	}
	eff, _ := Effective(m.c.Helm, next)
	if err := eff.Validate(m.c.Env()); err != nil {
		return nil, err
	}
	enabling := eff.Enabled && !cur.Enabled
	if enabling && !req.EgressAcknowledged && !m.c.PlatformAck {
		return nil, ErrEgressAck
	}
	var version int64
	if rec != nil {
		version = rec.Version
	}
	if req.Version != version {
		return nil, ErrConflict
	}
	if len(changes) == 0 && (!req.Reset || st == nil || len(st.Fields) == 0) {
		// Nothing to write.
		return m.State(ctx)
	}
	commit, err := m.c.Apply(ctx, eff)
	if err != nil {
		return nil, &ApplyError{Err: err}
	}
	raw, err := json.Marshal(next)
	if err != nil {
		return nil, err
	}
	now := m.now().UTC()
	entry := AuditEntry{At: now, Actor: req.Actor, Action: action, Changes: changes,
		EgressAcknowledged: enabling && req.EgressAcknowledged, EgressAckByPlatform: enabling && m.c.PlatformAck}
	if entry.Changes == nil {
		entry.Changes = []Change{}
	}
	saved, err := m.c.Store.Put(ctx, Record{Name: Name, Value: raw, UpdatedAt: now, UpdatedBy: req.Actor}, version, entry)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	stored, _ := decodeStored(saved.Value)
	m.setRecord(saved, stored)
	commit()
	m.applied, m.appliedOK, m.appliedAt, m.applyErr = eff, true, now, nil
	m.mu.Unlock()
	m.log.Info("investigator settings saved", "actor", req.Actor, "action", action, "version", saved.Version, "changes", len(changes),
		"enabled", eff.Enabled, "provider", eff.Provider, "model", eff.ModelID())
	return m.State(ctx)
}
