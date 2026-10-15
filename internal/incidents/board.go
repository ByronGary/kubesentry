package incidents

import (
	"reflect"
	"sync"
	"time"
)

// MemBoard is the Board the API serves: the incidents of the last
// BoardWindow (open ones always), newest first, with their signals. The
// leader applies each commit to it after the commit succeeded; the other
// replicas replace it from the store every Refresh. It is safe for
// concurrent use; what it returns is shared and must not be modified.
type MemBoard struct {
	window time.Duration

	mu      sync.RWMutex
	list    []Incident          // newest first
	byID    map[string]int      // index into list
	signals map[string][]Signal // sorted by start, then ID
	version uint64
	at      time.Time
	leader  bool
	ready   bool
}

var _ Board = (*MemBoard)(nil)

// NewBoard returns an empty board keeping incidents that ended less than
// window ago (DefaultBoardWindow when 0).
func NewBoard(window time.Duration) *MemBoard {
	if window <= 0 {
		window = DefaultBoardWindow
	}
	return &MemBoard{window: window, byID: map[string]int{}, signals: map[string][]Signal{}}
}

// Snapshot implements Board.
func (b *MemBoard) Snapshot() ([]Incident, uint64) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.list, b.version
}

// Signals implements Board.
func (b *MemBoard) Signals(id string) ([]Signal, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if _, ok := b.byID[id]; !ok {
		return nil, false
	}
	return b.signals[id], true
}

// Get returns one incident on the board.
func (b *MemBoard) Get(id string) (Incident, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	i, ok := b.byID[id]
	if !ok {
		return Incident{}, false
	}
	return b.list[i], true
}

// Status reports when the board was last published, whether by the leader,
// and whether it was published at all.
func (b *MemBoard) Status() (at time.Time, leader, ready bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.at, b.leader, b.ready
}

// Replace sets the whole board (a follower's refresh, or a new leader's
// first read), keeping what is inside the window.
func (b *MemBoard) Replace(ins []Incident, sigs map[string][]Signal, now time.Time, leader bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	keep := make(map[string]Incident, len(ins))
	ksigs := make(map[string][]Signal, len(ins))
	for _, in := range ins {
		if b.onBoard(&in, now) {
			keep[in.ID] = in
			ss := append([]Signal(nil), sigs[in.ID]...)
			SortSignals(ss)
			ksigs[in.ID] = ss
		}
	}
	if b.ready && b.same(keep, ksigs) {
		b.at, b.leader = now, leader // nothing changed: the version stays, so caches keyed on it hold
		return
	}
	b.rebuild(keep, ksigs, now, leader)
}

func (b *MemBoard) same(keep map[string]Incident, sigs map[string][]Signal) bool {
	if len(keep) != len(b.list) {
		return false
	}
	for id, in := range keep {
		i, ok := b.byID[id]
		if !ok || !reflect.DeepEqual(b.list[i], in) || !reflect.DeepEqual(b.signals[id], sigs[id]) {
			return false
		}
	}
	return true
}

// Apply merges a commit into the board: the incidents replace theirs and
// the signals replace theirs by ID.
func (b *MemBoard) Apply(ins []Incident, sigs map[string][]Signal, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	keep := make(map[string]Incident, len(b.list)+len(ins))
	ksigs := make(map[string][]Signal, len(b.list)+len(ins))
	for _, in := range b.list {
		keep[in.ID] = in
		ksigs[in.ID] = b.signals[in.ID]
	}
	for _, in := range ins {
		keep[in.ID] = in
	}
	for id, ss := range sigs {
		if _, ok := keep[id]; !ok || len(ss) == 0 {
			continue
		}
		merged := map[string]Signal{}
		for _, s := range ksigs[id] {
			merged[s.ID] = s
		}
		for _, s := range ss {
			merged[s.ID] = s
		}
		out := make([]Signal, 0, len(merged))
		for _, s := range merged {
			out = append(out, s)
		}
		SortSignals(out)
		ksigs[id] = out
	}
	for id, in := range keep {
		if !b.onBoard(&in, now) {
			delete(keep, id)
			delete(ksigs, id)
		}
	}
	b.rebuild(keep, ksigs, now, true)
}

// onBoard: open, or ended within the window.
func (b *MemBoard) onBoard(in *Incident, now time.Time) bool {
	return in.State == Open || in.End == nil || !in.End.Before(now.Add(-b.window))
}

func (b *MemBoard) rebuild(keep map[string]Incident, sigs map[string][]Signal, now time.Time, leader bool) {
	list := make([]Incident, 0, len(keep))
	for _, in := range keep {
		list = append(list, in)
	}
	SortNewest(list)
	byID := make(map[string]int, len(list))
	for i := range list {
		byID[list[i].ID] = i
	}
	b.list, b.byID, b.signals = list, byID, sigs
	b.version++
	b.at, b.leader, b.ready = now, leader, true
}
