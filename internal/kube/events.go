package kube

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/ByronGary/kubesentry/internal/model"
)

// Defaults for EventWatcherOptions.
const (
	DefaultEventBatch      = 500
	DefaultEventFlushEvery = 2 * time.Second
	// MaxEventMessage caps KubeEvent.Message, in bytes.
	MaxEventMessage = 1024
)

// DefaultNormalReasons are the Normal events watched besides every Warning:
// a HorizontalPodAutoscaler's rescale explains a change in load.
var DefaultNormalReasons = []string{"SuccessfulRescale"}

// EventWatcherOptions configures an EventWatcher.
type EventWatcherOptions struct {
	// NormalReasons are the reasons of Normal events kept besides every
	// Warning (-incident-event-normal-reasons). Nil means
	// DefaultNormalReasons; an empty, non-nil slice keeps Warnings only.
	NormalReasons []string
	// BatchSize caps the events per sink call (default 500); FlushEvery
	// sends a smaller batch once it is that old (default 2s).
	BatchSize  int
	FlushEvery time.Duration
}

// EventWatcher streams core/v1 Events to the incidents engine. It implements
// incidents.EventSource.
//
// It runs its own reflectors, separate from the Cache's shared informers:
// events churn, so they never wake the snapshot rebuild and are never part
// of Inventory. One watch takes every Warning (field selector type=Warning)
// and one per configured Normal reason takes those (type=Normal,reason=R),
// so the API server filters and the bulk of Normal events never arrives. The
// same filters are applied again in process.
//
// Each reflector starts with a full list, so events from a gap (a new lease
// holder, a restart) are delivered again; the sink upserts by UID. After
// that an event is delivered again only when it changes (a count goes up).
// The watcher keeps no event objects, only each event's resourceVersion.
type EventWatcher struct {
	cs   kubernetes.Interface
	opts EventWatcherOptions
}

// NewEventWatcher builds an EventWatcher on c's clientset.
func NewEventWatcher(c *Clients, o EventWatcherOptions) *EventWatcher {
	if o.NormalReasons == nil {
		o.NormalReasons = DefaultNormalReasons
	}
	if o.BatchSize <= 0 {
		o.BatchSize = DefaultEventBatch
	}
	if o.FlushEvery <= 0 {
		o.FlushEvery = DefaultEventFlushEvery
	}
	return &EventWatcher{cs: c.CS, opts: o}
}

// eventsAccess is what the watcher needs: list and watch events everywhere.
var eventsAccess = access{resource: "events"}

// Probe reports whether kubesentry may list and watch events: "ok", or the
// reason it may not ("forbidden: cannot watch events (...)").
func (w *EventWatcher) Probe(ctx context.Context) string {
	if ok, reason := permitted(ctx, w.cs, eventsAccess, "list", "watch"); !ok {
		return reason
	}
	return "ok"
}

// ErrEventsForbidden is returned by Run when kubesentry may not list and
// watch events.
var ErrEventsForbidden = errors.New("kube: events are forbidden")

// eventSelector is one watch: the field selector the API server applies and
// the same filter in process.
type eventSelector struct {
	field string
	keep  func(*corev1.Event) bool
}

func (w *EventWatcher) selectors() []eventSelector {
	out := []eventSelector{{
		field: fields.OneTermEqualSelector("type", corev1.EventTypeWarning).String(),
		keep:  func(ev *corev1.Event) bool { return ev.Type == corev1.EventTypeWarning },
	}}
	seen := map[string]bool{}
	for _, r := range w.opts.NormalReasons {
		r = strings.TrimSpace(r)
		if r == "" || seen[r] {
			continue
		}
		seen[r] = true
		out = append(out, eventSelector{
			field: fields.AndSelectors(fields.OneTermEqualSelector("type", corev1.EventTypeNormal), fields.OneTermEqualSelector("reason", r)).String(),
			keep:  func(ev *corev1.Event) bool { return ev.Type == corev1.EventTypeNormal && ev.Reason == r },
		})
	}
	return out
}

// Run watches events until ctx is done and hands them to sink in batches of
// at most BatchSize, at least every FlushEvery while events arrive. sink is
// called from one goroutine at a time and owns each batch; it is never
// called after Run returns. Events still pending when ctx ends are dropped:
// the next Run lists them again. Run returns nil when ctx ends, and an error
// wrapping ErrEventsForbidden when the permission probe fails.
func (w *EventWatcher) Run(ctx context.Context, sink func([]model.KubeEvent)) error {
	if ok, reason := permitted(ctx, w.cs, eventsAccess, "list", "watch"); !ok {
		return fmt.Errorf("%w: %s", ErrEventsForbidden, reason)
	}
	ch := make(chan model.KubeEvent, w.opts.BatchSize)
	emit := func(ev model.KubeEvent) bool {
		select {
		case ch <- ev:
			return true
		case <-ctx.Done():
			return false
		}
	}
	var wg sync.WaitGroup
	defer wg.Wait()
	for _, sel := range w.selectors() {
		lw := &cache.ListWatch{
			ListWithContextFunc: func(ctx context.Context, o metav1.ListOptions) (runtime.Object, error) {
				o.FieldSelector = sel.field
				return w.cs.CoreV1().Events(metav1.NamespaceAll).List(ctx, o)
			},
			WatchFuncWithContext: func(ctx context.Context, o metav1.ListOptions) (watch.Interface, error) {
				o.FieldSelector = sel.field
				return w.cs.CoreV1().Events(metav1.NamespaceAll).Watch(ctx, o)
			},
		}
		store := &eventStore{keep: sel.keep, emit: emit}
		r := cache.NewReflectorWithOptions(cache.ToListWatcherWithWatchListSemantics(lw, w.cs), &corev1.Event{}, store,
			cache.ReflectorOptions{Name: "events " + sel.field})
		wg.Go(func() { r.RunWithContext(ctx) })
	}

	t := time.NewTicker(w.opts.FlushEvery)
	defer t.Stop()
	var buf []model.KubeEvent
	flush := func() {
		if len(buf) > 0 {
			sink(buf)
			buf = nil
		}
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev := <-ch:
			if buf == nil {
				buf = make([]model.KubeEvent, 0, w.opts.BatchSize)
			}
			buf = append(buf, ev)
			if len(buf) >= w.opts.BatchSize {
				flush()
			}
		case <-t.C:
			flush()
		}
	}
}

// eventStore is the reflectors' store. It keeps only the resourceVersion of
// each event it passed on, so a relist re-sends only what changed, and
// converts everything else straight to the sink.
type eventStore struct {
	keep func(*corev1.Event) bool
	emit func(model.KubeEvent) bool // false once the watcher is stopping

	mu   sync.Mutex
	seen map[string]string // namespace/name -> resourceVersion
}

var _ cache.ReflectorStore = (*eventStore)(nil)

func eventKey(ev *corev1.Event) string { return ev.Namespace + "/" + ev.Name }

// changed reports whether ev is new or changed since it was last passed on,
// and remembers it.
func (s *eventStore) changed(ev *corev1.Event) bool {
	k, rv := eventKey(ev), ev.ResourceVersion
	s.mu.Lock()
	defer s.mu.Unlock()
	if prev, ok := s.seen[k]; ok && prev == rv && rv != "" {
		return false
	}
	if s.seen == nil {
		s.seen = map[string]string{}
	}
	s.seen[k] = rv
	return true
}

func (s *eventStore) offer(obj any) {
	ev, ok := obj.(*corev1.Event)
	if !ok || !s.keep(ev) || !s.changed(ev) {
		return
	}
	s.emit(convertEvent(ev))
}

func (s *eventStore) Add(obj any) error    { s.offer(obj); return nil }
func (s *eventStore) Update(obj any) error { s.offer(obj); return nil }
func (s *eventStore) Resync() error        { return nil }

func (s *eventStore) Delete(obj any) error {
	if d, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		obj = d.Obj
	}
	if ev, ok := obj.(*corev1.Event); ok {
		s.mu.Lock()
		delete(s.seen, eventKey(ev))
		s.mu.Unlock()
	}
	return nil
}

// Replace takes a full list (the start, or a relist after the watch could
// not resume): events not passed on before, or changed since, go to the
// sink; events gone from the list are forgotten.
func (s *eventStore) Replace(list []any, _ string) error {
	s.mu.Lock()
	old := s.seen
	s.mu.Unlock()
	fresh := make(map[string]string, len(list))
	for _, obj := range list {
		ev, ok := obj.(*corev1.Event)
		if !ok || !s.keep(ev) {
			continue
		}
		k, rv := eventKey(ev), ev.ResourceVersion
		fresh[k] = rv
		if prev, ok := old[k]; ok && prev == rv && rv != "" {
			continue
		}
		if !s.emit(convertEvent(ev)) {
			break
		}
	}
	s.mu.Lock()
	s.seen = fresh
	s.mu.Unlock()
	return nil
}

// convertEvent trims an Event to what incidents use. It reads both the
// core/v1 fields (count, first and last timestamp, source) and the
// events.k8s.io ones mirrored into core/v1 (eventTime, series, reporting
// controller), so events from old and new recorders look alike.
func convertEvent(ev *corev1.Event) model.KubeEvent {
	out := model.KubeEvent{
		UID: string(ev.UID), Namespace: ev.Namespace, Type: ev.Type, Reason: ev.Reason,
		Message: truncateTo(ev.Message, MaxEventMessage),
		Count:   ev.Count,
		Regarding: model.ObjectRef{
			Kind: ev.InvolvedObject.Kind, Namespace: ev.InvolvedObject.Namespace,
			Name: ev.InvolvedObject.Name, UID: string(ev.InvolvedObject.UID),
		},
		Source: ev.Source.Component,
	}
	if out.Source == "" {
		out.Source = ev.ReportingController
	}
	if s := ev.Series; s != nil && s.Count > out.Count {
		out.Count = s.Count
	}
	if out.Count < 1 {
		out.Count = 1
	}
	switch {
	case !ev.FirstTimestamp.IsZero():
		out.FirstSeen = ev.FirstTimestamp.Time
	case !ev.EventTime.IsZero():
		out.FirstSeen = ev.EventTime.Time
	default:
		out.FirstSeen = ev.CreationTimestamp.Time
	}
	out.LastSeen = out.FirstSeen
	for _, t := range []time.Time{ev.LastTimestamp.Time, ev.EventTime.Time} {
		if t.After(out.LastSeen) {
			out.LastSeen = t
		}
	}
	if s := ev.Series; s != nil && s.LastObservedTime.After(out.LastSeen) {
		out.LastSeen = s.LastObservedTime.Time
	}
	return out
}
