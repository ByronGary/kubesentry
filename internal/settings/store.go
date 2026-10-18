package settings

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

// Errors of the store and the manager.
var (
	// ErrNotFound: nothing is stored under the name.
	ErrNotFound = errors.New("settings: not found")
	// ErrConflict: the stored version is not the one the write expected.
	ErrConflict = errors.New("settings: changed by someone else; reload and try again")
	// ErrLocked: -investigator-settings=locked, the flags are the only source.
	ErrLocked = errors.New("settings: locked by Helm (-investigator-settings=locked): change incidents.investigator in the chart's values instead")
	// ErrEgressAck: enabling needs the data egress acknowledgement.
	ErrEgressAck = errors.New("settings: turning the investigator on needs the data egress acknowledgement")
)

// Record is one stored setting: its JSON value, a version that rises with
// every write, and who wrote it last.
type Record struct {
	Name      string          `json:"name"`
	Value     json.RawMessage `json:"value"`
	Version   int64           `json:"version"`
	UpdatedAt time.Time       `json:"updatedAt"`
	UpdatedBy string          `json:"updatedBy"`
}

// Actions an audit entry records.
const (
	ActionSave  = "save"
	ActionReset = "reset"
)

// AuditEntry is one write: who, when, what changed (old → new), and whether
// the writer acknowledged the data egress. Entries are append-only.
type AuditEntry struct {
	ID      int64     `json:"id"`
	Name    string    `json:"-"`
	At      time.Time `json:"at"`
	Actor   string    `json:"actor"`
	Action  string    `json:"action"`
	Version int64     `json:"version"`
	Changes []Change  `json:"changes"`
	// EgressAcknowledged: the actor ticked the data egress acknowledgement
	// (when turning the investigator on).
	EgressAcknowledged bool `json:"egressAcknowledged"`
	// EgressAckByPlatform: turned on while -investigator-egress-ack (the
	// chart's acknowledgeDataEgress) acknowledged it.
	EgressAckByPlatform bool `json:"egressAckByPlatform,omitempty"`
}

// Store keeps settings and their audit log; every replica reads and writes
// it (memory: one replica; Postgres: all).
type Store interface {
	// Get returns the record, or ErrNotFound.
	Get(ctx context.Context, name string) (*Record, error)
	// Put writes rec when the stored version is expect (0: nothing stored),
	// as version expect+1, and appends entry (its Version set to the new
	// one) in the same transaction. ErrConflict otherwise.
	Put(ctx context.Context, rec Record, expect int64, entry AuditEntry) (*Record, error)
	// Audit returns the newest limit entries of name, newest first.
	Audit(ctx context.Context, name string, limit int) ([]AuditEntry, error)
}

// MemoryStore is Store in memory, for one replica.
type MemoryStore struct {
	mu     sync.Mutex
	recs   map[string]Record
	audit  []AuditEntry
	nextID int64
}

var _ Store = (*MemoryStore)(nil)

// NewMemoryStore returns an empty store.
func NewMemoryStore() *MemoryStore { return &MemoryStore{recs: map[string]Record{}} }

// Get implements Store.
func (m *MemoryStore) Get(_ context.Context, name string) (*Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.recs[name]
	if !ok {
		return nil, ErrNotFound
	}
	r.Value = append(json.RawMessage(nil), r.Value...)
	return &r, nil
}

// Put implements Store.
func (m *MemoryStore) Put(_ context.Context, rec Record, expect int64, entry AuditEntry) (*Record, error) {
	if !json.Valid(rec.Value) {
		return nil, errors.New("settings: the value is not JSON")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if cur := m.recs[rec.Name]; cur.Version != expect {
		return nil, ErrConflict
	}
	rec.Version = expect + 1
	rec.UpdatedAt = rec.UpdatedAt.UTC().Truncate(time.Microsecond)
	rec.Value = compact(rec.Value)
	m.recs[rec.Name] = rec
	m.nextID++
	entry.ID, entry.Name, entry.Version = m.nextID, rec.Name, rec.Version
	entry.At = entry.At.UTC().Truncate(time.Microsecond)
	entry.Changes = append([]Change{}, entry.Changes...)
	m.audit = append(m.audit, entry)
	out := rec
	out.Value = append(json.RawMessage(nil), rec.Value...)
	return &out, nil
}

// Audit implements Store.
func (m *MemoryStore) Audit(_ context.Context, name string, limit int) ([]AuditEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []AuditEntry{}
	for i := len(m.audit) - 1; i >= 0 && (limit <= 0 || len(out) < limit); i-- {
		if e := m.audit[i]; e.Name == name {
			e.Changes = append([]Change{}, e.Changes...)
			out = append(out, e)
		}
	}
	return out, nil
}

// compact is the JSON as Postgres' jsonb would give it back, near enough:
// without insignificant whitespace.
func compact(b json.RawMessage) json.RawMessage {
	var v any
	if json.Unmarshal(b, &v) != nil {
		return b
	}
	out, err := json.Marshal(v)
	if err != nil {
		return b
	}
	return out
}
