package investigate

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/ByronGary/kubesentry/internal/incidents"
)

// Errors the API maps to statuses: ErrNotFound 404, ErrForbidden 403,
// ErrNotRunning and *ConflictError 409, *QuotaError 429, *BusyError 503.
var (
	ErrNotFound   = errors.New("investigate: no such investigation")
	ErrForbidden  = errors.New("investigate: only the person who started an investigation may cancel it")
	ErrNotRunning = errors.New("investigate: the investigation is not running")
	// ErrIncidentNotFound means the incident is unknown (or pruned).
	ErrIncidentNotFound = incidents.ErrNotFound
)

// ConflictError means the incident already has a running investigation.
type ConflictError struct{ RunningID string }

func (e *ConflictError) Error() string {
	return "investigate: investigation " + e.RunningID + " is already running for this incident"
}

// QuotaError means an hourly quota is spent. Scope is "user" (the
// caller's -investigator-per-hour) or "total" (-investigator-per-hour-total).
type QuotaError struct {
	Scope      string
	Limit      int
	RetryAfter time.Duration
}

func (e *QuotaError) Error() string {
	who := "you have"
	if e.Scope == "total" {
		who = "everyone together has"
	}
	return fmt.Sprintf("investigate: %s started %d investigations in the last hour, the most allowed", who, e.Limit)
}

// BusyError means this replica runs as many investigations as it may, or
// is shutting down.
type BusyError struct{ RetryAfter time.Duration }

func (e *BusyError) Error() string {
	return "investigate: this server is running as many investigations as it may; try again shortly"
}

// Store keeps investigations. The memory store and the Postgres store
// (internal/pgstore, table incident_investigations) must behave alike.
type Store interface {
	// Create inserts a run. A running run must be its incident's only
	// running run: *ConflictError otherwise (in Postgres, the partial
	// unique index incident_investigations_running).
	Create(ctx context.Context, inv *Investigation) error
	// Update writes a run's mutable fields (status, updated_at,
	// finished_at, error, refusal, steps, report, evidence, usage, turns,
	// tool calls), but only while the stored run is running: ErrNotRunning
	// once it has finished (cancelled from another replica, or marked
	// interrupted), ErrNotFound when it is gone.
	Update(ctx context.Context, inv *Investigation) error
	// Get returns a run; ErrNotFound when there is none.
	Get(ctx context.Context, id string) (*Investigation, error)
	// List returns an incident's runs, newest first, at most limit (0: all).
	List(ctx context.Context, incidentID string, limit int) ([]*Investigation, error)
	// CountSince counts the runs created at or after since, by requestedBy
	// ("" for everyone), leaving out those served from the cache; oldest
	// is the earliest one's creation time (zero when none).
	CountSince(ctx context.Context, requestedBy string, since time.Time) (n int, oldest time.Time, err error)
	// Cached returns the newest completed run with this input hash created
	// at or after since that was not itself served from the cache;
	// ErrNotFound when there is none.
	Cached(ctx context.Context, inputSHA256 string, since time.Time) (*Investigation, error)
	// Running returns the incident's running run; ErrNotFound when none.
	Running(ctx context.Context, incidentID string) (*Investigation, error)
}

// DefaultMaxRuns is how many runs the memory store keeps.
const DefaultMaxRuns = 1000

// MemoryStore is a Store in memory: one replica, the newest MaxRuns runs.
type MemoryStore struct {
	mu   sync.Mutex
	runs map[string]*Investigation
	max  int
}

// NewMemoryStore returns a store keeping the newest max runs (0:
// DefaultMaxRuns).
func NewMemoryStore(max int) *MemoryStore {
	if max <= 0 {
		max = DefaultMaxRuns
	}
	return &MemoryStore{runs: map[string]*Investigation{}, max: max}
}

func (m *MemoryStore) running(incidentID string) *Investigation {
	for _, r := range m.runs {
		if r.IncidentID == incidentID && r.Status == Running {
			return r
		}
	}
	return nil
}

// Create implements Store.
func (m *MemoryStore) Create(ctx context.Context, inv *Investigation) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.runs[inv.ID]; ok {
		return fmt.Errorf("investigate: investigation %s exists", inv.ID)
	}
	if inv.Status == Running {
		if cur := m.running(inv.IncidentID); cur != nil {
			return &ConflictError{RunningID: cur.ID}
		}
	}
	m.runs[inv.ID] = normalRun(inv.Clone())
	m.evict()
	return nil
}

// evict drops the oldest finished runs beyond the cap.
func (m *MemoryStore) evict() {
	over := len(m.runs) - m.max
	if over <= 0 {
		return
	}
	all := make([]*Investigation, 0, len(m.runs))
	for _, r := range m.runs {
		if r.Status != Running {
			all = append(all, r)
		}
	}
	sort.Slice(all, func(i, j int) bool { return older(all[i], all[j]) })
	for i := 0; i < over && i < len(all); i++ {
		delete(m.runs, all[i].ID)
	}
}

func older(a, b *Investigation) bool {
	if !a.CreatedAt.Equal(b.CreatedAt) {
		return a.CreatedAt.Before(b.CreatedAt)
	}
	return a.ID < b.ID
}

// normalRun keeps times as Postgres does (UTC, microseconds).
func normalRun(inv *Investigation) *Investigation {
	inv.CreatedAt = incidents.NormalTime(inv.CreatedAt)
	inv.UpdatedAt = incidents.NormalTime(inv.UpdatedAt)
	if inv.FinishedAt != nil {
		t := incidents.NormalTime(*inv.FinishedAt)
		inv.FinishedAt = &t
	}
	for i := range inv.Steps {
		inv.Steps[i].At = incidents.NormalTime(inv.Steps[i].At)
	}
	return inv
}

// Update implements Store.
func (m *MemoryStore) Update(ctx context.Context, inv *Investigation) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.runs[inv.ID]
	if !ok {
		return ErrNotFound
	}
	if cur.Status != Running {
		return ErrNotRunning
	}
	n := inv.Clone()
	// Only the mutable fields change.
	c := cur.Clone()
	c.Status, c.UpdatedAt, c.FinishedAt, c.Error, c.Refusal = n.Status, n.UpdatedAt, n.FinishedAt, n.Error, n.Refusal
	c.Steps, c.Report, c.Evidence, c.Usage, c.Turns, c.ToolCalls = n.Steps, n.Report, n.Evidence, n.Usage, n.Turns, n.ToolCalls
	m.runs[inv.ID] = normalRun(c)
	return nil
}

// Get implements Store.
func (m *MemoryStore) Get(ctx context.Context, id string) (*Investigation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.runs[id]
	if !ok {
		return nil, ErrNotFound
	}
	return r.Clone(), nil
}

// List implements Store.
func (m *MemoryStore) List(ctx context.Context, incidentID string, limit int) ([]*Investigation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*Investigation
	for _, r := range m.runs {
		if r.IncidentID == incidentID {
			out = append(out, r.Clone())
		}
	}
	sort.Slice(out, func(i, j int) bool { return older(out[j], out[i]) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// CountSince implements Store.
func (m *MemoryStore) CountSince(ctx context.Context, requestedBy string, since time.Time) (int, time.Time, error) {
	if err := ctx.Err(); err != nil {
		return 0, time.Time{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	var oldest time.Time
	for _, r := range m.runs {
		if r.CachedFrom != "" || r.CreatedAt.Before(since) || (requestedBy != "" && r.RequestedBy != requestedBy) {
			continue
		}
		n++
		if oldest.IsZero() || r.CreatedAt.Before(oldest) {
			oldest = r.CreatedAt
		}
	}
	return n, oldest, nil
}

// Cached implements Store.
func (m *MemoryStore) Cached(ctx context.Context, inputSHA256 string, since time.Time) (*Investigation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var best *Investigation
	for _, r := range m.runs {
		if r.Status != Completed || r.CachedFrom != "" || r.InputSHA256 != inputSHA256 || r.CreatedAt.Before(since) {
			continue
		}
		if best == nil || older(best, r) {
			best = r
		}
	}
	if best == nil {
		return nil, ErrNotFound
	}
	return best.Clone(), nil
}

// Running implements Store.
func (m *MemoryStore) Running(ctx context.Context, incidentID string) (*Investigation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if r := m.running(incidentID); r != nil {
		return r.Clone(), nil
	}
	return nil, ErrNotFound
}
