package kube

import (
	"slices"
	"strings"
	"sync"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
)

// memo remembers the conversion of each object by UID and resourceVersion,
// so a rebuild converts only the objects that changed since the last one.
// Converted values are shared between Inventory results: they are read-only.
type memo[T any] struct {
	mu  sync.Mutex
	gen uint64
	m   map[types.UID]*memoEntry[T]
}

type memoEntry[T any] struct {
	rv  string
	gen uint64 // the last pass that saw the object
	v   T
}

// convertAll converts objs in order, reusing memoized conversions, and then
// forgets objects the pass did not see (deleted ones). objs must be the
// complete set for the resource. Objects without a UID or resourceVersion
// (only fixtures) are converted every time.
func convertAll[O metav1.Object, T any](m *memo[T], objs []O, conv func(O) T) []T {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gen++
	if m.m == nil {
		m.m = make(map[types.UID]*memoEntry[T], len(objs))
	}
	var out []T
	if len(objs) > 0 {
		out = make([]T, len(objs))
	}
	for i, o := range objs {
		uid, rv := o.GetUID(), o.GetResourceVersion()
		if uid == "" || rv == "" {
			out[i] = conv(o)
			continue
		}
		if e, ok := m.m[uid]; ok && e.rv == rv {
			e.gen = m.gen
			out[i] = e.v
			continue
		}
		v := conv(o)
		m.m[uid] = &memoEntry[T]{rv: rv, gen: m.gen, v: v}
		out[i] = v
	}
	for uid, e := range m.m {
		if e.gen != m.gen {
			delete(m.m, uid)
		}
	}
	return out
}

// convertOne converts a single object through the memo without sweeping.
func convertOne[O metav1.Object, T any](m *memo[T], o O, conv func(O) T) T {
	uid, rv := o.GetUID(), o.GetResourceVersion()
	if uid == "" || rv == "" {
		return conv(o)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.m[uid]; ok && e.rv == rv {
		return e.v
	}
	v := conv(o)
	if m.m == nil {
		m.m = map[types.UID]*memoEntry[T]{}
	}
	m.m[uid] = &memoEntry[T]{rv: rv, gen: m.gen, v: v}
	return v
}

// reset forgets every conversion (the resource is no longer watched).
func (m *memo[T]) reset() {
	m.mu.Lock()
	m.m = nil
	m.mu.Unlock()
}

// size reports how many conversions are remembered.
func (m *memo[T]) size() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.m)
}

// sortedObjects returns the store's objects of type O sorted by namespace and
// name, the order a LIST from the API server has.
func sortedObjects[O metav1.Object](store cache.Store) []O {
	items := store.List()
	out := make([]O, 0, len(items))
	for _, it := range items {
		if o, ok := it.(O); ok {
			out = append(out, o)
		}
	}
	slices.SortFunc(out, func(a, b O) int {
		if c := strings.Compare(a.GetNamespace(), b.GetNamespace()); c != 0 {
			return c
		}
		return strings.Compare(a.GetName(), b.GetName())
	})
	return out
}
