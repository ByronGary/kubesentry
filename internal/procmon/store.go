package procmon

import (
	"sort"
	"sync"
	"time"
)

// StoreOptions bounds a Store. Zero fields take the defaults.
type StoreOptions struct {
	// Interval is how often agents report; default 15s. The staleness and
	// eviction defaults are multiples of it.
	Interval time.Duration
	// StaleAfter marks a node's data stale; default 8 intervals (2 minutes).
	StaleAfter time.Duration
	// EvictAfter forgets a node that stopped reporting; default 40 intervals
	// (10 minutes).
	EvictAfter time.Duration
	// MaxNodes is the most nodes kept; when a new node arrives at the limit,
	// the one silent longest is dropped. Default 5000.
	MaxNodes int
	// MaxProcessesPerNode keeps a node's largest processes by memory; default
	// 20000, the most a report may carry.
	MaxProcessesPerNode int
}

func (o *StoreOptions) defaults() {
	if o.Interval <= 0 {
		o.Interval = 15 * time.Second
	}
	if o.StaleAfter <= 0 {
		o.StaleAfter = 8 * o.Interval
	}
	if o.EvictAfter <= 0 {
		o.EvictAfter = 40 * o.Interval
	}
	if o.MaxNodes <= 0 {
		o.MaxNodes = 5000
	}
	if o.MaxProcessesPerNode <= 0 {
		o.MaxProcessesPerNode = 20000
	}
}

// Store keeps the latest report from each node, indexed by pod UID so a pod's
// processes are found without scanning every node.
type Store struct {
	Now func() time.Time

	opts      StoreOptions
	mu        sync.RWMutex
	nodes     map[string]*nodeEntry
	pods      map[string]podEntry // pod UID → its processes on one node
	lastSweep time.Time
}

type nodeEntry struct {
	received  time.Time
	processes int   // kept, after the per-node cap
	dropped   int   // cut by the per-node cap
	bytes     int64 // size of the report as received
	pods      []string
}

type podEntry struct {
	node      string
	processes []Process // busiest memory first; never modified after insert
}

// AgentStatus is one node agent's reporting state, as /api/v1/agents returns
// it (web/src/types.ts AgentStatus).
type AgentStatus struct {
	Node       string    `json:"node"`
	LastReport time.Time `json:"lastReport"`
	Processes  int       `json:"processes"`
	Bytes      int64     `json:"bytes"`
	Stale      bool      `json:"stale"`
	// Dropped counts the smallest processes the per-node cap cut from the
	// last report.
	Dropped int `json:"dropped,omitempty"`
}

// NewStore returns an empty store with the default bounds.
func NewStore() *Store { return NewStoreWithOptions(StoreOptions{}) }

// NewStoreWithOptions returns an empty store with the given bounds.
func NewStoreWithOptions(opts StoreOptions) *Store {
	opts.defaults()
	return &Store{opts: opts, nodes: map[string]*nodeEntry{}, pods: map[string]podEntry{}}
}

// Options returns the effective bounds.
func (s *Store) Options() StoreOptions { return s.opts }

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Update replaces the node's previous report. The receive time is used rather
// than the agent's clock so skewed node clocks cannot make data look fresh.
// Grouping and sorting happen before the lock is taken.
func (s *Store) Update(r Report) {
	now := s.now()
	procs := r.Processes
	if len(procs) > s.opts.MaxProcessesPerNode {
		procs = append([]Process(nil), procs...)
		sort.SliceStable(procs, func(i, j int) bool { return procs[i].RSSBytes > procs[j].RSSBytes })
		procs = procs[:s.opts.MaxProcessesPerNode:s.opts.MaxProcessesPerNode]
	}
	byPod := map[string][]Process{}
	for _, p := range procs {
		byPod[p.PodUID] = append(byPod[p.PodUID], p)
	}
	uids := make([]string, 0, len(byPod))
	for uid, ps := range byPod {
		sort.SliceStable(ps, func(i, j int) bool { return ps[i].RSSBytes > ps[j].RSSBytes })
		uids = append(uids, uid)
	}
	entry := &nodeEntry{received: now, processes: len(procs), dropped: len(r.Processes) - len(procs), bytes: r.Bytes, pods: uids}

	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.nodes[r.Node]; ok {
		s.dropPods(r.Node, old)
	} else if len(s.nodes) >= s.opts.MaxNodes {
		s.sweep(now)
		if len(s.nodes) >= s.opts.MaxNodes {
			s.evictOldest()
		}
	}
	s.nodes[r.Node] = entry
	for uid, ps := range byPod {
		s.pods[uid] = podEntry{node: r.Node, processes: ps}
	}
	if now.Sub(s.lastSweep) >= s.opts.Interval {
		s.sweep(now)
	}
}

// dropPods removes a node's pods from the index; the caller holds the lock.
// A pod is only removed while this node still owns it.
func (s *Store) dropPods(node string, e *nodeEntry) {
	for _, uid := range e.pods {
		if pe, ok := s.pods[uid]; ok && pe.node == node {
			delete(s.pods, uid)
		}
	}
}

// sweep forgets nodes silent for longer than EvictAfter; the caller holds the
// write lock.
func (s *Store) sweep(now time.Time) {
	s.lastSweep = now
	for name, e := range s.nodes {
		if now.Sub(e.received) > s.opts.EvictAfter {
			s.dropPods(name, e)
			delete(s.nodes, name)
		}
	}
}

func (s *Store) evictOldest() {
	var oldest string
	var at time.Time
	for name, e := range s.nodes {
		if oldest == "" || e.received.Before(at) {
			oldest, at = name, e.received
		}
	}
	if oldest != "" {
		s.dropPods(oldest, s.nodes[oldest])
		delete(s.nodes, oldest)
	}
}

// Sweep forgets nodes that stopped reporting. Update sweeps once per
// interval, so calling this is only needed when no agent reports at all.
func (s *Store) Sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep(s.now())
}

// PodView is the processes of one pod from the node it runs on.
type PodView struct {
	Node       string
	ObservedAt time.Time
	Processes  []Process
}

// ForPod returns the pod's processes, busiest memory first, and false if no
// node reported any or the reporting node has been silent past EvictAfter.
// The slice is the caller's own.
func (s *Store) ForPod(uid string) (PodView, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	pe, ok := s.pods[uid]
	if !ok {
		return PodView{}, false
	}
	n := s.nodes[pe.node]
	if n == nil || s.now().Sub(n.received) > s.opts.EvictAfter {
		return PodView{}, false
	}
	return PodView{Node: pe.node, ObservedAt: n.received, Processes: append([]Process(nil), pe.processes...)}, true
}

// Nodes reports how many nodes have sent a report and not been forgotten.
func (s *Store) Nodes() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.nodes)
}

// Agents lists every known node's agent, by node name. Nodes silent past
// EvictAfter are left out even before the next sweep forgets them.
func (s *Store) Agents() []AgentStatus {
	now := s.now()
	s.mu.RLock()
	out := make([]AgentStatus, 0, len(s.nodes))
	for name, e := range s.nodes {
		age := now.Sub(e.received)
		if age > s.opts.EvictAfter {
			continue
		}
		out = append(out, AgentStatus{
			Node: name, LastReport: e.received, Processes: e.processes, Dropped: e.dropped, Bytes: e.bytes, Stale: age > s.opts.StaleAfter,
		})
	}
	s.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Node < out[j].Node })
	return out
}

// Reporting counts nodes whose data is fresh, for
// kubesentry_agent_nodes_reporting.
func (s *Store) Reporting() int {
	now := s.now()
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for _, e := range s.nodes {
		if now.Sub(e.received) <= s.opts.StaleAfter {
			n++
		}
	}
	return n
}
