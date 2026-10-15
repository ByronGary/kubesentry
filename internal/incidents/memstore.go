package incidents

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
)

// Bounds of the memory stores.
const (
	MemoryMaxIncidents = 10_000
	MemoryMaxEvents    = 100_000
)

// MemoryStore is a Store in memory, for one replica or tests. It keeps at
// most MemoryMaxIncidents: past that, the resolved incidents that ended
// first are dropped. internal/pgstore's Postgres store behaves the same
// (TestPGIncidentsMatchMemory).
type MemoryStore struct {
	mu        sync.Mutex
	max       int
	incidents map[string]Incident
	signals   map[string]map[string]Signal
	cps       map[string][]byte
}

var _ Store = (*MemoryStore)(nil)

// NewMemoryStore returns an empty store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{max: MemoryMaxIncidents, incidents: map[string]Incident{}, signals: map[string]map[string]Signal{}, cps: map[string][]byte{}}
}

// LoadOpen implements Store.
func (m *MemoryStore) LoadOpen(ctx context.Context) ([]Incident, map[string][]Signal, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Incident
	sigs := map[string][]Signal{}
	for id, in := range m.incidents {
		if in.State != Open {
			continue
		}
		out = append(out, CloneIncident(in))
		sigs[id] = m.signalList(id)
	}
	SortNewest(out)
	return out, sigs, nil
}

func (m *MemoryStore) signalList(id string) []Signal {
	ss := m.signals[id]
	if len(ss) == 0 {
		return nil
	}
	out := make([]Signal, 0, len(ss))
	for _, s := range ss {
		out = append(out, CloneSignal(s))
	}
	SortSignals(out)
	return out
}

// Commit implements Store. Signals must belong to an incident in the store
// or in the commit (Postgres enforces it with a foreign key).
func (m *MemoryStore) Commit(ctx context.Context, c Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	inCommit := make(map[string]bool, len(c.Incidents))
	for _, in := range c.Incidents {
		inCommit[in.ID] = true
	}
	for id := range c.Signals {
		if _, ok := m.incidents[id]; !ok && !inCommit[id] {
			return fmt.Errorf("incidents: signals for unknown incident %s", id)
		}
	}
	for _, in := range c.Incidents {
		m.incidents[in.ID] = NormalizeIncident(CloneIncident(in))
	}
	for id, ss := range c.Signals {
		if m.signals[id] == nil {
			m.signals[id] = map[string]Signal{}
		}
		for _, s := range ss {
			m.signals[id][s.ID] = NormalizeSignal(CloneSignal(s))
		}
	}
	for k, v := range c.Checkpoints {
		m.cps[k] = slices.Clone(v)
	}
	m.bound()
	return nil
}

// bound drops the resolved incidents that ended first while there are more
// than max.
func (m *MemoryStore) bound() {
	over := len(m.incidents) - m.max
	if over <= 0 {
		return
	}
	var resolved []Incident
	for _, in := range m.incidents {
		if in.State == Resolved {
			resolved = append(resolved, in)
		}
	}
	sort.Slice(resolved, func(i, j int) bool {
		a, b := resolved[i], resolved[j]
		ae, be := endOf(&a), endOf(&b)
		if !ae.Equal(be) {
			return ae.Before(be)
		}
		return a.ID < b.ID
	})
	for i := 0; i < over && i < len(resolved); i++ {
		delete(m.incidents, resolved[i].ID)
		delete(m.signals, resolved[i].ID)
	}
}

func endOf(in *Incident) time.Time {
	if in.End != nil {
		return *in.End
	}
	return in.Start
}

// Checkpoint implements Store.
func (m *MemoryStore) Checkpoint(ctx context.Context, source string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.cps[source]), nil
}

// List implements Store: matching incidents newest first (Query.Matches).
func (m *MemoryStore) List(ctx context.Context, q Query) ([]Incident, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Incident
	for _, in := range m.incidents {
		if q.Matches(&in) {
			out = append(out, CloneIncident(in))
		}
	}
	SortNewest(out)
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}

// Get implements Store.
func (m *MemoryStore) Get(ctx context.Context, id string) (Incident, []Signal, bool, error) {
	if err := ctx.Err(); err != nil {
		return Incident{}, nil, false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	in, ok := m.incidents[id]
	if !ok {
		return Incident{}, nil, false, nil
	}
	return CloneIncident(in), m.signalList(id), true, nil
}

// SignalsOf returns the signals of several incidents at once (the board's
// refresh); unknown IDs are left out.
func (m *MemoryStore) SignalsOf(ctx context.Context, ids []string) (map[string][]Signal, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string][]Signal, len(ids))
	for _, id := range ids {
		if ss := m.signalList(id); len(ss) > 0 {
			out[id] = ss
		}
	}
	return out, nil
}

// Prune implements Store: resolved incidents that ended before before go,
// with their signals.
func (m *MemoryStore) Prune(ctx context.Context, before time.Time) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for id, in := range m.incidents {
		if in.State == Resolved && in.End != nil && in.End.Before(before) {
			delete(m.incidents, id)
			delete(m.signals, id)
			n++
		}
	}
	return n, nil
}

// SignalsLoader is implemented by stores that read the signals of many
// incidents at once; the board's refresh uses it when present.
type SignalsLoader interface {
	SignalsOf(ctx context.Context, ids []string) (map[string][]Signal, error)
}

// MemoryEventStore is an EventStore in memory, keeping at most
// MemoryMaxEvents (the least recently seen go first).
type MemoryEventStore struct {
	mu     sync.Mutex
	max    int
	events map[string]StoredEvent // by UID
}

var _ EventStore = (*MemoryEventStore)(nil)

// NewMemoryEventStore returns an empty event store.
func NewMemoryEventStore() *MemoryEventStore {
	return &MemoryEventStore{max: MemoryMaxEvents, events: map[string]StoredEvent{}}
}

// NormalizeEvent gives a stored event the shape both stores keep.
func NormalizeEvent(e StoredEvent) StoredEvent {
	k := &e.KubeEvent
	k.UID = cleanString(k.UID, 256)
	k.Namespace = cleanString(k.Namespace, 256)
	k.Type = cleanString(k.Type, 64)
	k.Reason = cleanString(k.Reason, 256)
	k.Message = cleanString(k.Message, 2048)
	k.Source = cleanString(k.Source, 256)
	k.Regarding = model.ObjectRef{Kind: cleanString(k.Regarding.Kind, 256), Namespace: cleanString(k.Regarding.Namespace, 256),
		Name: cleanString(k.Regarding.Name, 512), UID: cleanString(k.Regarding.UID, 256)}
	if k.Count < 1 {
		k.Count = 1
	}
	k.FirstSeen, k.LastSeen = NormalTime(k.FirstSeen), NormalTime(k.LastSeen)
	if k.LastSeen.IsZero() {
		k.LastSeen = k.FirstSeen
	}
	if k.FirstSeen.IsZero() || k.FirstSeen.After(k.LastSeen) {
		k.FirstSeen = k.LastSeen
	}
	if e.Subject != nil {
		s := cleanSubject(*e.Subject)
		e.Subject = &s
	}
	return e
}

// AddEvents implements EventStore: events upsert by UID, and a report never
// replaces one seen later (LastSeen).
func (m *MemoryEventStore) AddEvents(ctx context.Context, evs []StoredEvent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range evs {
		e = NormalizeEvent(e)
		if e.UID == "" || e.LastSeen.IsZero() {
			continue
		}
		if cur, ok := m.events[e.UID]; ok && cur.LastSeen.After(e.LastSeen) {
			continue
		}
		m.events[e.UID] = cloneEvent(e)
	}
	if over := len(m.events) - m.max; over > 0 {
		all := make([]StoredEvent, 0, len(m.events))
		for _, e := range m.events {
			all = append(all, e)
		}
		sort.Slice(all, func(i, j int) bool {
			if !all[i].LastSeen.Equal(all[j].LastSeen) {
				return all[i].LastSeen.Before(all[j].LastSeen)
			}
			return all[i].UID < all[j].UID
		})
		for _, e := range all[:over] {
			delete(m.events, e.UID)
		}
	}
	return nil
}

func cloneEvent(e StoredEvent) StoredEvent {
	if e.Subject != nil {
		s := *e.Subject
		e.Subject = &s
	}
	return e
}

// Matches reports whether a stored event matches q, as both stores
// evaluate it: in the namespace (any when empty), about the subject and
// object when set, seen in [From, To] (any part of [FirstSeen, LastSeen]).
func (q EventQuery) Matches(e *StoredEvent) bool {
	if q.Namespace != "" && e.Namespace != q.Namespace {
		return false
	}
	if q.Subject != nil && (e.Subject == nil || *e.Subject != *q.Subject) {
		return false
	}
	if o := q.Object; o != nil {
		r := e.Regarding
		if r.Kind != o.Kind || r.Namespace != o.Namespace || r.Name != o.Name || (o.UID != "" && r.UID != o.UID) {
			return false
		}
	}
	if !q.From.IsZero() && e.LastSeen.Before(q.From) {
		return false
	}
	if !q.To.IsZero() && e.FirstSeen.After(q.To) {
		return false
	}
	return true
}

// EventNewer orders stored events as Events returns them: the most
// recently seen first, then by UID.
func EventNewer(a, b *StoredEvent) bool {
	if !a.LastSeen.Equal(b.LastSeen) {
		return a.LastSeen.After(b.LastSeen)
	}
	return a.UID < b.UID
}

// Events implements EventStore: matching events, most recently seen first.
func (m *MemoryEventStore) Events(ctx context.Context, q EventQuery) ([]StoredEvent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []StoredEvent
	for _, e := range m.events {
		if q.Matches(&e) {
			out = append(out, cloneEvent(e))
		}
	}
	sort.Slice(out, func(i, j int) bool { return EventNewer(&out[i], &out[j]) })
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}

// PruneEvents implements EventStore: events last seen before before go.
func (m *MemoryEventStore) PruneEvents(ctx context.Context, before time.Time) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for uid, e := range m.events {
		if e.LastSeen.Before(before) {
			delete(m.events, uid)
			n++
		}
	}
	return n, nil
}
