package procmon

import (
	"sort"
	"sync"
	"time"
)

// Store keeps the latest report from each node.
type Store struct {
	mu    sync.RWMutex
	nodes map[string]Report
	Now   func() time.Time
}

// NewStore returns an empty store.
func NewStore() *Store { return &Store{nodes: map[string]Report{}} }

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Update replaces the node's previous report. The receive time is used rather
// than the agent's clock so skewed node clocks cannot make data look fresh.
func (s *Store) Update(r Report) {
	r.Time = s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nodes[r.Node] = r
}

// PodView is the processes of one pod from the node it runs on.
type PodView struct {
	Node       string
	ObservedAt time.Time
	Processes  []Process
}

// ForPod returns the pod's processes, busiest memory first, and false if no node reported any.
func (s *Store) ForPod(uid string) (PodView, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.nodes {
		var ps []Process
		for _, p := range r.Processes {
			if p.PodUID == uid {
				ps = append(ps, p)
			}
		}
		if len(ps) > 0 {
			sort.Slice(ps, func(i, j int) bool { return ps[i].RSSBytes > ps[j].RSSBytes })
			return PodView{Node: r.Node, ObservedAt: r.Time, Processes: ps}, true
		}
	}
	return PodView{}, false
}

// Nodes reports how many nodes have sent a report.
func (s *Store) Nodes() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.nodes)
}
