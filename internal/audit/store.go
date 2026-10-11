package audit

import (
	"container/list"
	"sort"
	"sync"
	"time"
)

// Query selects events. The zero value matches the "interesting" default view.
type Query struct {
	Since     time.Time
	User      string // exact match on username
	Namespace string
	Resource  string
	Name      string // exact match on the object name
	Verb      string
	Tag       string
	// Actors restricts actor kinds ("user", "serviceaccount", "system"). When
	// nil, system components are hidden unless an event carries a tag.
	Actors map[string]bool
	// IncludeReads shows get/list/watch events. By default reads are hidden
	// unless tagged (secret access, denied, ...) or Verb is set explicitly.
	IncludeReads bool
	// Limit caps the result; 0 means no limit.
	Limit int
}

func (q Query) matches(e *Event) bool {
	if !q.Since.IsZero() && e.Time.Before(q.Since) {
		return false
	}
	if q.User != "" && e.Username != q.User {
		return false
	}
	if q.Namespace != "" && e.Namespace != q.Namespace {
		return false
	}
	if q.Resource != "" && e.Resource != q.Resource {
		return false
	}
	if q.Name != "" && e.Name != q.Name {
		return false
	}
	if q.Verb != "" && e.Verb != q.Verb {
		return false
	}
	if q.Tag != "" && !hasTag(e.Tags, q.Tag) {
		return false
	}
	if q.Actors != nil {
		if !q.Actors[e.ActorKind] {
			return false
		}
	} else if e.ActorKind == "system" && len(e.Tags) == 0 {
		return false
	}
	if !q.IncludeReads && q.Verb == "" && isRead(e.Verb) && len(e.Tags) == 0 {
		return false
	}
	return true
}

func hasTag(tags []string, t string) bool {
	for _, x := range tags {
		if x == t {
			return true
		}
	}
	return false
}

// stageRank orders stages of one request so a late-arriving earlier stage
// never overwrites a later one.
func stageRank(stage string) int {
	switch stage {
	case "ResponseStarted":
		return 1
	case "ResponseComplete":
		return 2
	case "Panic":
		return 3
	}
	return 0
}

// MemoryStore keeps the most recent events in memory. Events are keyed by
// auditID: ResponseStarted followed by ResponseComplete for the same request
// (exec sessions, watches) collapse into one record.
type MemoryStore struct {
	mu    sync.RWMutex
	cap   int
	order *list.List // front = oldest
	byID  map[string]*list.Element
}

func NewMemoryStore(capacity int) *MemoryStore {
	if capacity < 1 {
		capacity = 1
	}
	return &MemoryStore{cap: capacity, order: list.New(), byID: make(map[string]*list.Element)}
}

func (s *MemoryStore) Add(events ...Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range events {
		if e.AuditID != "" {
			if el, ok := s.byID[e.AuditID]; ok {
				if stageRank(e.Stage) >= stageRank(el.Value.(Event).Stage) {
					el.Value = e
				}
				continue
			}
		}
		el := s.order.PushBack(e)
		if e.AuditID != "" {
			s.byID[e.AuditID] = el
		}
		for s.order.Len() > s.cap {
			oldest := s.order.Front()
			old := oldest.Value.(Event)
			if old.AuditID != "" {
				delete(s.byID, old.AuditID)
			}
			s.order.Remove(oldest)
		}
	}
}

// Query returns matching events, newest first.
func (s *MemoryStore) Query(q Query) []Event {
	s.mu.RLock()
	out := []Event{}
	for el := s.order.Back(); el != nil; el = el.Prev() {
		e := el.Value.(Event)
		if q.matches(&e) {
			out = append(out, e)
		}
	}
	s.mu.RUnlock()

	sort.SliceStable(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out
}

func (s *MemoryStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.order.Len()
}
