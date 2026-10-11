package audit

import (
	"container/heap"
	"context"
	"math"
	"sort"
	"sync"
)

// MemoryStore keeps the most recent events in memory, up to a fixed count.
//
// Records are keyed by (AuditID, Time): the stages of one request share
// requestReceivedTimestamp, so ResponseStarted followed by ResponseComplete
// (exec sessions, watches) collapse into one record, and a late-arriving
// earlier stage never replaces a later one. This is the Postgres store's
// primary key too.
//
// Besides the insertion-ordered list used for eviction, events are indexed by
// username, namespace, namespace/resource/name, each tag, and membership of
// the default view. Every index node carries an upper bound on the times of
// itself and everything inserted before it in its list, so a query walks the
// most selective list newest-inserted first and stops exactly when no older
// node can still make the result: out-of-order arrival (a CloudWatch backfill
// after live webhook traffic) costs extra steps, never wrong answers.
//
// The zero-context methods (Add, Query, Len, Summarize, Coverage) are the
// historical API; AsStore returns the same store as an audit.Store.
type MemoryStore struct {
	mu    sync.RWMutex
	cap   int
	all   *ilist // every entry, front = oldest inserted
	def   *ilist // entries in the default view
	byKey map[recordKey]*entry
	users map[string]*ilist
	nss   map[string]*ilist
	objs  map[objKey]*ilist
	tags  map[string]*ilist
}

type recordKey struct {
	id string
	t  int64
}

type objKey struct{ ns, resource, name string }

type idxKind uint8

const (
	idxAll idxKind = iota
	idxDefault
	idxUser
	idxNS
	idxObj
	idxTag
)

// inode is an intrusive doubly linked list node. pmax is an upper bound on
// the UnixNano time of this node and of every node before it in its list.
type inode struct {
	prev, next *inode
	list       *ilist
	e          *entry
	pmax       int64
}

type ilist struct {
	head, tail *inode
	n          int
	kind       idxKind
	key        string
	obj        objKey
}

type entry struct {
	ev   Event
	t    int64 // ev.Time.UnixNano()
	main inode
	idx  []inode // index memberships; kept so eviction is O(indexes)
}

func (l *ilist) pushBack(nd *inode) {
	nd.list = l
	nd.prev = l.tail
	nd.next = nil
	m := nd.e.t
	if l.tail != nil {
		l.tail.next = nd
		if l.tail.pmax > m {
			m = l.tail.pmax
		}
	} else {
		l.head = nd
	}
	nd.pmax = m
	l.tail = nd
	l.n++
}

// remove unlinks nd. The bounds of the remaining nodes may now be loose, but
// they stay upper bounds, which is all a query needs.
func (l *ilist) remove(nd *inode) {
	if nd.prev != nil {
		nd.prev.next = nd.next
	} else {
		l.head = nd.next
	}
	if nd.next != nil {
		nd.next.prev = nd.prev
	} else {
		l.tail = nd.prev
	}
	nd.prev, nd.next, nd.list = nil, nil, nil
	l.n--
}

func NewMemoryStore(capacity int) *MemoryStore {
	if capacity < 1 {
		capacity = 1
	}
	return &MemoryStore{
		cap:   capacity,
		all:   &ilist{kind: idxAll},
		def:   &ilist{kind: idxDefault},
		byKey: make(map[recordKey]*entry),
		users: make(map[string]*ilist),
		nss:   make(map[string]*ilist),
		objs:  make(map[objKey]*ilist),
		tags:  make(map[string]*ilist),
	}
}

// Add stores events, evicting the oldest inserted beyond capacity. Events are
// normalized first (see NormalizeForStore).
func (s *MemoryStore) Add(events ...Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range events {
		e = NormalizeForStore(e)
		k := recordKey{e.AuditID, e.Time.UnixNano()}
		if old, ok := s.byKey[k]; ok {
			if stageRank(e.Stage) >= stageRank(old.ev.Stage) {
				s.replace(old, e)
			}
			continue
		}
		en := &entry{ev: e, t: k.t}
		en.main.e = en
		s.all.pushBack(&en.main)
		s.link(en)
		s.byKey[k] = en
		for s.all.n > s.cap {
			s.evict(s.all.head.e)
		}
	}
}

type listRef struct {
	kind idxKind
	key  string
	obj  objKey
}

// refsOf lists the indexes an event belongs to, in a fixed order.
func refsOf(e *Event, buf []listRef) []listRef {
	refs := append(buf[:0], listRef{kind: idxUser, key: e.Username}, listRef{kind: idxNS, key: e.Namespace})
	if e.Namespace != "" && e.Resource != "" && e.Name != "" {
		refs = append(refs, listRef{kind: idxObj, obj: objKey{e.Namespace, e.Resource, e.Name}})
	}
	for i, t := range e.Tags {
		if !hasTag(e.Tags[:i], t) {
			refs = append(refs, listRef{kind: idxTag, key: t})
		}
	}
	if InDefaultView(e) {
		refs = append(refs, listRef{kind: idxDefault})
	}
	return refs
}

func (s *MemoryStore) listFor(r listRef) *ilist {
	switch r.kind {
	case idxDefault:
		return s.def
	case idxUser:
		return getList(s.users, r)
	case idxNS:
		return getList(s.nss, r)
	case idxTag:
		return getList(s.tags, r)
	case idxObj:
		l := s.objs[r.obj]
		if l == nil {
			l = &ilist{kind: idxObj, obj: r.obj}
			s.objs[r.obj] = l
		}
		return l
	}
	panic("audit: unknown index")
}

func getList(m map[string]*ilist, r listRef) *ilist {
	l := m[r.key]
	if l == nil {
		l = &ilist{kind: r.kind, key: r.key}
		m[r.key] = l
	}
	return l
}

func (s *MemoryStore) link(en *entry) {
	var buf [8]listRef
	refs := refsOf(&en.ev, buf[:])
	en.idx = make([]inode, len(refs))
	for i, r := range refs {
		en.idx[i].e = en
		s.listFor(r).pushBack(&en.idx[i])
	}
}

func (s *MemoryStore) unlink(en *entry) {
	for i := range en.idx {
		nd := &en.idx[i]
		l := nd.list
		l.remove(nd)
		if l.n == 0 {
			switch l.kind {
			case idxUser:
				delete(s.users, l.key)
			case idxNS:
				delete(s.nss, l.key)
			case idxTag:
				delete(s.tags, l.key)
			case idxObj:
				delete(s.objs, l.obj)
			}
		}
	}
	en.idx = nil
}

// replace swaps in a later stage of the same record. The time is part of the
// key, so it never changes; index memberships can (a 403 adds "denied").
func (s *MemoryStore) replace(en *entry, e Event) {
	var buf [8]listRef
	refs := refsOf(&e, buf[:])
	same := len(refs) == len(en.idx)
	for i := 0; same && i < len(refs); i++ {
		l := en.idx[i].list
		same = l.kind == refs[i].kind && l.key == refs[i].key && l.obj == refs[i].obj
	}
	en.ev = e
	if !same {
		s.unlink(en)
		s.link(en)
	}
}

func (s *MemoryStore) evict(en *entry) {
	s.all.remove(&en.main)
	s.unlink(en)
	delete(s.byKey, recordKey{en.ev.AuditID, en.t})
}

// plan picks the smallest set of index lists that covers every event q can
// match.
func (s *MemoryStore) plan(q *Query) []*ilist {
	best, bestN := []*ilist{s.all}, s.all.n
	consider := func(ls ...*ilist) {
		n := 0
		out := ls[:0]
		for _, l := range ls {
			if l != nil {
				n += l.n
				out = append(out, l)
			}
		}
		if n < bestN {
			best, bestN = out, n
		}
	}
	if q.DefaultView() {
		consider(s.def)
	}
	if q.User != "" {
		consider(s.users[q.User])
	}
	if q.Namespace != "" {
		consider(s.nss[q.Namespace])
		if q.Resource != "" && q.Name != "" {
			consider(s.objs[objKey{q.Namespace, q.Resource, q.Name}])
		}
	}
	if q.Tag != "" {
		consider(s.tags[q.Tag])
	}
	if q.Namespaces != nil && q.Namespace == "" && len(q.Namespaces) < bestN {
		ls := make([]*ilist, 0, len(q.Namespaces)+1)
		for ns, ok := range q.Namespaces {
			if ok && ns != "" {
				ls = append(ls, s.nss[ns])
			}
		}
		if q.ClusterScoped {
			ls = append(ls, s.nss[""])
		}
		consider(ls...)
	}
	return best
}

// walk visits, newest inserted first, the entries of l that may match q,
// stopping once no older node can (its time bound is below Since, or below
// the worst event a full collector holds).
func walk(l *ilist, q *Query, since int64, c *collector) {
	for nd := l.tail; nd != nil; nd = nd.prev {
		if nd.pmax < since {
			return
		}
		if c != nil && c.full() && nd.pmax < c.worstT() {
			return
		}
		if q.matches(&nd.e.ev) {
			c.add(nd.e)
		}
	}
}

func sinceNanos(q *Query) int64 {
	if q.Since.IsZero() {
		return math.MinInt64
	}
	return q.Since.UnixNano()
}

// Query returns matching events, newest first (time, then AuditID).
func (s *MemoryStore) Query(q Query) []Event {
	q = q.Canonical()
	c := &collector{limit: q.Limit}
	since := sinceNanos(&q)
	s.mu.RLock()
	for _, l := range s.plan(&q) {
		walk(l, &q, since, c)
	}
	out := c.events()
	s.mu.RUnlock()
	return out
}

// Summarize aggregates the events matching q (Limit is ignored).
func (s *MemoryStore) Summarize(q Query) Summary {
	q = q.Canonical()
	since := sinceNanos(&q)
	var b SummaryBuilder
	s.mu.RLock()
	for _, l := range s.plan(&q) {
		for nd := l.tail; nd != nil && nd.pmax >= since; nd = nd.prev {
			if q.matches(&nd.e.ev) {
				b.Add(&nd.e.ev)
			}
		}
	}
	s.mu.RUnlock()
	return b.Summary()
}

// Coverage reports the time span and number of events held.
func (s *MemoryStore) Coverage() Coverage {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c := Coverage{Events: int64(s.all.n), MaxEvents: s.cap, Backend: "memory"}
	for nd := s.all.head; nd != nil; nd = nd.next {
		t := nd.e.ev.Time
		if c.Oldest.IsZero() || t.Before(c.Oldest) {
			c.Oldest = t
		}
		if t.After(c.Newest) {
			c.Newest = t
		}
	}
	return c
}

func (s *MemoryStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.all.n
}

// Cap returns the maximum number of events kept.
func (s *MemoryStore) Cap() int { return s.cap }

// AsStore returns s as an audit.Store. It never returns ErrBackpressure.
func (s *MemoryStore) AsStore() Store { return memoryStore{s} }

type memoryStore struct{ m *MemoryStore }

func (a memoryStore) Add(ctx context.Context, events []Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	a.m.Add(events...)
	return nil
}

func (a memoryStore) Query(ctx context.Context, q Query) ([]Event, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return a.m.Query(q), nil
}

func (a memoryStore) Summarize(ctx context.Context, q Query) (Summary, error) {
	if err := ctx.Err(); err != nil {
		return Summary{}, err
	}
	return a.m.Summarize(q), nil
}

func (a memoryStore) Coverage(ctx context.Context) (Coverage, error) {
	if err := ctx.Err(); err != nil {
		return Coverage{}, err
	}
	return a.m.Coverage(), nil
}

// MemoryOf returns the MemoryStore behind a Store made by AsStore.
func MemoryOf(st Store) (*MemoryStore, bool) {
	m, ok := st.(memoryStore)
	return m.m, ok
}

// collector keeps the newest limit entries seen (all when limit is 0) in a
// heap whose root is the oldest kept.
type collector struct {
	limit int
	h     []*entry
}

func (c *collector) full() bool { return c.limit > 0 && len(c.h) >= c.limit }

func (c *collector) worstT() int64 { return c.h[0].t }

func (c *collector) add(en *entry) {
	if c.limit <= 0 {
		c.h = append(c.h, en)
		return
	}
	if len(c.h) < c.limit {
		heap.Push((*entryHeap)(&c.h), en)
		return
	}
	if newer(&en.ev, &c.h[0].ev) {
		c.h[0] = en
		heap.Fix((*entryHeap)(&c.h), 0)
	}
}

func (c *collector) events() []Event {
	sort.Slice(c.h, func(i, j int) bool { return newer(&c.h[i].ev, &c.h[j].ev) })
	out := make([]Event, len(c.h))
	for i, en := range c.h {
		out[i] = en.ev
	}
	return out
}

// entryHeap is a min-heap in newest-first order: the root is the oldest.
type entryHeap []*entry

func (h entryHeap) Len() int           { return len(h) }
func (h entryHeap) Less(i, j int) bool { return newer(&h[j].ev, &h[i].ev) }
func (h entryHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *entryHeap) Push(x any)        { *h = append(*h, x.(*entry)) }
func (h *entryHeap) Pop() any {
	old := *h
	x := old[len(old)-1]
	*h = old[:len(old)-1]
	return x
}
