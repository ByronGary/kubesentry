package kube

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"

	"github.com/ByronGary/kubesentry/internal/model"
)

func kevent(name, typ, reason, rv string, count int32) *corev1.Event {
	return &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: name, UID: types.UID("ev-" + name), ResourceVersion: rv, CreationTimestamp: t0},
		Type:       typ, Reason: reason, Message: reason + " on " + name, Count: count,
		InvolvedObject: corev1.ObjectReference{Kind: "Pod", Namespace: "app", Name: "web-0", UID: "pod-web-0"},
		Source:         corev1.EventSource{Component: "kubelet", Host: "n1"},
		FirstTimestamp: t0, LastTimestamp: t1,
	}
}

func TestConvertEvent(t *testing.T) {
	old := kevent("old", "Warning", "BackOff", "1", 7)
	old.ManagedFields = []metav1.ManagedFieldsEntry{{Manager: "kubelet"}}
	got := convertEvent(old)
	want := model.KubeEvent{UID: "ev-old", Namespace: "app", Type: "Warning", Reason: "BackOff", Message: "BackOff on old", Count: 7,
		FirstSeen: t0.Time, LastSeen: t1.Time, Source: "kubelet",
		Regarding: model.ObjectRef{Kind: "Pod", Namespace: "app", Name: "web-0", UID: "pod-web-0"}}
	if got != want {
		t.Errorf("core/v1 event:\n got %+v\nwant %+v", got, want)
	}

	// events.k8s.io recorders set eventTime, series and the reporting
	// controller instead of the core/v1 fields.
	observed := metav1.NewMicroTime(t1.Add(time.Hour))
	nu := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "new", UID: "ev-new", CreationTimestamp: t1},
		Type:       "Warning", Reason: "FailedScheduling", ReportingController: "default-scheduler",
		EventTime: metav1.NewMicroTime(t0.Time), Series: &corev1.EventSeries{Count: 12, LastObservedTime: observed},
		Message: strings.Repeat("é", 700), // 1400 bytes
	}
	got = convertEvent(nu)
	if got.Count != 12 || got.Source != "default-scheduler" || !got.FirstSeen.Equal(t0.Time) || !got.LastSeen.Equal(observed.Time) {
		t.Errorf("events.k8s.io event: %+v", got)
	}
	if len(got.Message) > MaxEventMessage || len(got.Message) < MaxEventMessage-1 || strings.ToValidUTF8(got.Message, "?") != got.Message {
		t.Errorf("message: %d bytes, valid %v", len(got.Message), strings.ToValidUTF8(got.Message, "?") == got.Message)
	}

	// No count and no timestamps: one occurrence at creation.
	bare := &corev1.Event{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: "bare", CreationTimestamp: t1}, Type: "Warning", Reason: "Unhealthy"}
	if got := convertEvent(bare); got.Count != 1 || !got.FirstSeen.Equal(t1.Time) || !got.LastSeen.Equal(t1.Time) {
		t.Errorf("bare event: %+v", got)
	}
}

// eventFakes is a clientset whose event watches each get their own fake
// watcher, handed to the test by field selector. The fake ignores field
// selectors on lists and watches, so the in-process filters are exercised.
type eventFakes struct {
	cs       *fake.Clientset
	mu       sync.Mutex
	watchers map[string]chan *watch.RaceFreeFakeWatcher
}

func newEventFakes(t *testing.T, deny func(*authorizationv1.ResourceAttributes) bool, objs ...runtime.Object) *eventFakes {
	t.Helper()
	cs, _ := newFakes(objs, nil, deny)
	f := &eventFakes{cs: cs, watchers: map[string]chan *watch.RaceFreeFakeWatcher{}}
	cs.PrependWatchReactor("events", func(a k8stesting.Action) (bool, watch.Interface, error) {
		sel := a.(k8stesting.WatchActionImpl).GetWatchRestrictions().Fields.String()
		w := watch.NewRaceFreeFake()
		f.watcher(sel) <- w
		return true, w, nil
	})
	return f
}

func (f *eventFakes) watcher(sel string) chan *watch.RaceFreeFakeWatcher {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.watchers[sel] == nil {
		f.watchers[sel] = make(chan *watch.RaceFreeFakeWatcher, 4)
	}
	return f.watchers[sel]
}

func (f *eventFakes) next(t *testing.T, sel string) *watch.RaceFreeFakeWatcher {
	t.Helper()
	select {
	case w := <-f.watcher(sel):
		return w
	case <-time.After(5 * time.Second):
		t.Fatalf("no watch with field selector %q", sel)
		return nil
	}
}

// collector gathers the batches a watcher hands to its sink.
type collector struct {
	mu      sync.Mutex
	batches [][]model.KubeEvent
	got     chan struct{}
}

func newCollector() *collector { return &collector{got: make(chan struct{}, 1000)} }

func (c *collector) sink(b []model.KubeEvent) {
	c.mu.Lock()
	c.batches = append(c.batches, b)
	c.mu.Unlock()
	c.got <- struct{}{}
}

func (c *collector) events() []model.KubeEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []model.KubeEvent
	for _, b := range c.batches {
		out = append(out, b...)
	}
	return out
}

// await waits until the collected events number n, and returns them.
func (c *collector) await(t *testing.T, n int, what string) []model.KubeEvent {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		if evs := c.events(); len(evs) >= n {
			return evs
		}
		select {
		case <-c.got:
		case <-deadline:
			t.Fatalf("%s: %d events, want %d: %+v", what, len(c.events()), n, c.events())
		}
	}
}

func reasons(evs []model.KubeEvent) string {
	var out []string
	for _, e := range evs {
		out = append(out, fmt.Sprintf("%s:%s:%d", e.UID, e.Reason, e.Count))
	}
	return strings.Join(out, ",")
}

func startWatcher(t *testing.T, w *EventWatcher, c *collector) (stop func() error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx, c.sink) }()
	stop = func() error {
		cancel()
		select {
		case err := <-done:
			return err
		case <-time.After(5 * time.Second):
			t.Fatal("Run did not return after cancel")
			return nil
		}
	}
	t.Cleanup(func() { cancel() })
	return stop
}

func TestEventWatcher(t *testing.T) {
	// The fake reports the parsed selector, whose terms are sorted.
	const warnSel, rescaleSel = "type=Warning", "reason=SuccessfulRescale,type=Normal"
	f := newEventFakes(t, nil,
		kevent("backoff", "Warning", "BackOff", "10", 3),
		kevent("scheduled", "Normal", "Scheduled", "11", 1),
		kevent("rescale", "Normal", "SuccessfulRescale", "12", 1),
	)
	c := newCollector()
	w := NewEventWatcher(&Clients{CS: f.cs}, EventWatcherOptions{FlushEvery: 10 * time.Millisecond})
	stop := startWatcher(t, w, c)

	// The initial list covers what happened before the watch: every Warning
	// and the configured Normal reason, nothing else.
	evs := c.await(t, 2, "initial list")
	if got := reasons(evs); got != "ev-backoff:BackOff:3,ev-rescale:SuccessfulRescale:1" && got != "ev-rescale:SuccessfulRescale:1,ev-backoff:BackOff:3" {
		t.Fatalf("initial events: %s", got)
	}
	warn, rescale := f.next(t, warnSel), f.next(t, rescaleSel)

	// New and changed events arrive; an unchanged one (same resourceVersion,
	// e.g. replayed) does not, nor does a Normal event outside the list.
	warn.Add(kevent("unhealthy", "Warning", "Unhealthy", "20", 1))
	warn.Modify(kevent("backoff", "Warning", "BackOff", "10", 3))
	warn.Add(kevent("pulled", "Normal", "Pulled", "21", 1))
	rescale.Add(kevent("pulled-2", "Normal", "Pulled", "22", 1))
	warn.Modify(kevent("backoff", "Warning", "BackOff", "23", 4))
	rescale.Add(kevent("rescale-2", "Normal", "SuccessfulRescale", "24", 1))
	evs = c.await(t, 5, "watched events")
	time.Sleep(50 * time.Millisecond) // anything wrongly passed on would arrive by now
	evs = c.events()
	got := reasons(evs[2:])
	for _, want := range []string{"ev-unhealthy:Unhealthy:1", "ev-backoff:BackOff:4", "ev-rescale-2:SuccessfulRescale:1"} {
		if !strings.Contains(got, want) {
			t.Errorf("watched events %s: missing %s", got, want)
		}
	}
	if len(evs) != 5 || strings.Contains(got, "Pulled") {
		t.Errorf("watched events: %s", reasons(evs))
	}
	if e := evs[0]; e.Regarding.Name != "web-0" || e.Source != "kubelet" || !e.FirstSeen.Equal(t0.Time) {
		t.Errorf("converted event: %+v", e)
	}
	c.mu.Lock()
	for _, b := range c.batches {
		if len(b) > DefaultEventBatch {
			t.Errorf("batch of %d", len(b))
		}
	}
	c.mu.Unlock()

	// A deleted event (TTL) is forgotten, so the same name and version later
	// counts as new.
	warn.Delete(kevent("unhealthy", "Warning", "Unhealthy", "20", 1))
	warn.Add(kevent("unhealthy", "Warning", "Unhealthy", "20", 1))
	c.await(t, 6, "re-added event")

	if err := stop(); err != nil {
		t.Errorf("Run after cancel: %v", err)
	}
}

func TestEventWatcherBatches(t *testing.T) {
	var objs []runtime.Object
	for i := range 1000 {
		objs = append(objs, kevent(fmt.Sprintf("e%04d", i), "Warning", "FailedMount", fmt.Sprint(100+i), 1))
	}
	f := newEventFakes(t, nil, objs...)
	c := newCollector()
	// No Normal reasons: one watch. A flush interval this long means only full
	// batches are sent.
	w := NewEventWatcher(&Clients{CS: f.cs}, EventWatcherOptions{NormalReasons: []string{}, FlushEvery: time.Hour})
	if sels := w.selectors(); len(sels) != 1 || sels[0].field != "type=Warning" {
		t.Fatalf("selectors: %+v", sels)
	}
	stop := startWatcher(t, w, c)
	c.await(t, 1000, "initial list")
	c.mu.Lock()
	if len(c.batches) != 2 || len(c.batches[0]) != 500 || len(c.batches[1]) != 500 {
		t.Errorf("batches: %d", len(c.batches))
	}
	c.mu.Unlock()
	seen := map[string]bool{}
	for _, e := range c.events() {
		seen[e.UID] = true
	}
	if len(seen) != 1000 {
		t.Errorf("%d distinct events", len(seen))
	}
	_ = stop()
}

func TestEventWatcherSelectors(t *testing.T) {
	w := NewEventWatcher(&Clients{CS: fake.NewClientset()}, EventWatcherOptions{NormalReasons: []string{"SuccessfulRescale", " ScalingReplicaSet ", "", "SuccessfulRescale"}})
	var got []string
	for _, s := range w.selectors() {
		got = append(got, s.field)
	}
	if want := "type=Warning|type=Normal,reason=SuccessfulRescale|type=Normal,reason=ScalingReplicaSet"; strings.Join(got, "|") != want {
		t.Errorf("selectors: %v", got)
	}
	if d := NewEventWatcher(&Clients{CS: fake.NewClientset()}, EventWatcherOptions{}); len(d.selectors()) != 2 || d.opts.BatchSize != 500 || d.opts.FlushEvery != 2*time.Second {
		t.Errorf("defaults: %+v", d.opts)
	}
}

func TestEventWatcherForbidden(t *testing.T) {
	f := newEventFakes(t, func(a *authorizationv1.ResourceAttributes) bool { return a.Resource == "events" && a.Verb == "watch" },
		kevent("backoff", "Warning", "BackOff", "10", 3))
	w := NewEventWatcher(&Clients{CS: f.cs}, EventWatcherOptions{})
	if p := w.Probe(context.Background()); !strings.HasPrefix(p, "forbidden: cannot watch events") {
		t.Errorf("probe: %q", p)
	}
	c := newCollector()
	err := w.Run(context.Background(), c.sink)
	if !errors.Is(err, ErrEventsForbidden) || !strings.Contains(err.Error(), "cannot watch events") {
		t.Errorf("Run: %v", err)
	}
	if len(c.events()) != 0 {
		t.Errorf("events delivered: %v", c.events())
	}
	ok := newEventFakes(t, nil)
	if p := NewEventWatcher(&Clients{CS: ok.cs}, EventWatcherOptions{}).Probe(context.Background()); p != "ok" {
		t.Errorf("allowed probe: %q", p)
	}
}

// Replace (a relist) re-sends only what changed and forgets what is gone.
func TestEventStoreReplace(t *testing.T) {
	var sent []string
	s := &eventStore{keep: func(ev *corev1.Event) bool { return ev.Type == "Warning" }, emit: func(e model.KubeEvent) bool {
		sent = append(sent, fmt.Sprintf("%s:%d", e.UID, e.Count))
		return true
	}}
	a, b := kevent("a", "Warning", "BackOff", "1", 1), kevent("b", "Warning", "BackOff", "2", 1)
	_ = s.Replace([]any{a, b, kevent("n", "Normal", "Pulled", "3", 1)}, "3")
	_ = s.Replace([]any{a, kevent("b", "Warning", "BackOff", "4", 2)}, "4")
	_ = s.Replace([]any{a}, "5")
	_ = s.Add(b) // b was dropped by the last list, so it is new again
	_ = s.Update(b)
	if got := strings.Join(sent, ","); got != "ev-a:1,ev-b:1,ev-b:2,ev-b:1" {
		t.Errorf("sent: %s", got)
	}
	_ = s.Delete(cache.DeletedFinalStateUnknown{Key: "app/b", Obj: b})
	_ = s.Add(b)
	if len(sent) != 5 {
		t.Errorf("after tombstone: %v", sent)
	}
	if s.Resync() != nil {
		t.Error("resync")
	}
}
