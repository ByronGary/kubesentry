package alerts

import (
	"context"
	"slices"
	"sort"
	"sync"
	"time"
)

// Retention is how long a resolved finding is kept: the Postgres store's
// maintenance loop deletes older ones, and the memory store drops them.
const Retention = 30 * 24 * time.Hour

// Store keeps findings and the baselines of the change-based checks. The
// memory store and internal/pgstore's Postgres store behave the same
// (TestPGAlertsMatchMemory).
type Store interface {
	// Load returns every finding not resolved, and those resolved at or
	// after resolvedSince, sorted by key.
	Load(ctx context.Context, resolvedSince time.Time) ([]Finding, error)
	// Baselines returns the recorded key set of each change-based check. A
	// check with no entry has no baseline yet; one with an empty slice has
	// recorded that nothing was there.
	Baselines(ctx context.Context) (map[string][]string, error)
	// Commit upserts the findings (by key) and replaces the baselines it
	// names, in one transaction.
	Commit(ctx context.Context, c Commit) error
	// Prune deletes findings resolved before before, and reports how many.
	Prune(ctx context.Context, before time.Time) (int, error)
}

// Commit is one evaluation's writes.
type Commit struct {
	Findings  []Finding
	Baselines map[string][]string // check → keys, sorted
}

// Empty reports whether there is nothing to write.
func (c Commit) Empty() bool { return len(c.Findings) == 0 && len(c.Baselines) == 0 }

// MemoryStore is a Store in memory: for a single replica, or tests. Its
// contents are lost on restart, so the first evaluation afterwards records
// the change-based baselines again (without notifying) and finds the
// standing problems anew; Alertmanager deduplicates what it still holds.
type MemoryStore struct {
	mu        sync.Mutex
	findings  map[string]Finding
	baselines map[string][]string
}

// NewMemoryStore returns an empty store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{findings: map[string]Finding{}, baselines: map[string][]string{}}
}

var _ Store = (*MemoryStore)(nil)

// Load implements Store.
func (m *MemoryStore) Load(ctx context.Context, resolvedSince time.Time) ([]Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Finding, 0, len(m.findings))
	for _, f := range m.findings {
		if f.Resolved() && (f.ResolvedAt == nil || f.ResolvedAt.Before(resolvedSince)) {
			continue
		}
		out = append(out, f.Clone())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// Baselines implements Store.
func (m *MemoryStore) Baselines(ctx context.Context) (map[string][]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string][]string, len(m.baselines))
	for k, v := range m.baselines {
		out[k] = slices.Clone(v)
	}
	return out, nil
}

// Commit implements Store.
func (m *MemoryStore) Commit(ctx context.Context, c Commit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, f := range c.Findings {
		m.findings[f.Key] = normalize(f.Clone())
	}
	for k, v := range c.Baselines {
		keys := slices.Clone(v)
		if keys == nil {
			keys = []string{}
		}
		sort.Strings(keys)
		m.baselines[k] = slices.Compact(keys)
	}
	return nil
}

// Prune implements Store.
func (m *MemoryStore) Prune(ctx context.Context, before time.Time) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for k, f := range m.findings {
		if f.Resolved() && f.ResolvedAt != nil && f.ResolvedAt.Before(before) {
			delete(m.findings, k)
			n++
		}
	}
	return n, nil
}

// normalize gives a finding the shape a round trip through Postgres gives
// it: empty maps rather than nil, times in UTC truncated to microseconds.
func normalize(f Finding) Finding {
	if f.Labels == nil {
		f.Labels = map[string]string{}
	}
	if f.Annotations == nil {
		f.Annotations = map[string]string{}
	}
	f.FirstSeen = NormalTime(f.FirstSeen)
	f.LastSeen = NormalTime(f.LastSeen)
	f.SilencedUntil = normalPtr(f.SilencedUntil)
	f.LastNotified = normalPtr(f.LastNotified)
	f.ResolvedAt = normalPtr(f.ResolvedAt)
	return f
}

// NormalTime is t as Postgres keeps a timestamptz: UTC, microseconds.
func NormalTime(t time.Time) time.Time { return t.UTC().Truncate(time.Microsecond) }

func normalPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := NormalTime(*t)
	return &v
}
