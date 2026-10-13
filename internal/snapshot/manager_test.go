package snapshot

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/model"
)

// fakeSource counts reads and fails on demand. With changes set it is a Notifier.
type fakeSource struct {
	mu    sync.Mutex
	calls int
	err   error
	inv   model.Inventory
}

func (f *fakeSource) Inventory(context.Context) (model.Inventory, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return model.Inventory{}, f.err
	}
	return f.inv, nil
}

func (f *fakeSource) setErr(err error) {
	f.mu.Lock()
	f.err = err
	f.mu.Unlock()
}

func (f *fakeSource) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

type notifyingSource struct {
	*fakeSource
	changes chan struct{}
}

func (n notifyingSource) Changes() <-chan struct{} { return n.changes }

// fakeClock hands the test every timer the manager asks for.
type fakeClock struct{ timers chan fakeTimer }

type fakeTimer struct {
	d    time.Duration
	fire chan time.Time
}

// The buffer keeps a manager that asks for a timer during shutdown from
// blocking; tests read requests in order with next.
func newFakeClock() *fakeClock { return &fakeClock{timers: make(chan fakeTimer, 64)} }

func (c *fakeClock) after(d time.Duration) <-chan time.Time {
	t := fakeTimer{d: d, fire: make(chan time.Time, 1)}
	c.timers <- t
	return t.fire
}

func (c *fakeClock) next(t *testing.T) fakeTimer {
	t.Helper()
	select {
	case tm := <-c.timers:
		return tm
	case <-time.After(5 * time.Second):
		t.Fatal("the manager never asked for a timer")
		return fakeTimer{}
	}
}

func smallInventory() model.Inventory {
	return model.Inventory{
		Workloads: []model.Workload{{Kind: "Deployment", Namespace: "a", Name: "web", Desired: 1, Ready: 1, Updated: 1}},
		Pods:      []model.Pod{{Namespace: "a", Name: "web-1", Phase: "Running"}},
	}
}

// startManager runs m and returns a channel that receives every build result.
func startManager(t *testing.T, m *Manager) (builds chan error, stop func()) {
	t.Helper()
	builds = make(chan error, 16)
	m.OnBuild = func(_ *View, _ time.Duration, err error) { builds <- err }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.Run(ctx) }()
	return builds, func() {
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Errorf("Run returned %v", err)
		}
	}
}

func waitBuild(t *testing.T, builds chan error) error {
	t.Helper()
	select {
	case err := <-builds:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("no build")
		return nil
	}
}

func TestManagerDebounceCoalesces(t *testing.T) {
	src := notifyingSource{&fakeSource{inv: smallInventory()}, make(chan struct{})}
	clock := newFakeClock()
	m := &Manager{Source: src, MinInterval: 2 * time.Second, MaxDelay: 10 * time.Second, Now: func() time.Time { return synthNow }}
	m.after = clock.after
	builds, stop := startManager(t, m)
	defer stop()

	if err := waitBuild(t, builds); err != nil {
		t.Fatal(err)
	}
	v, err := m.View(context.Background())
	if err != nil || v == nil || !v.Built.Equal(synthNow) || len(v.Workloads["a"]) != 1 {
		t.Fatalf("first view = %+v, %v", v, err)
	}

	src.changes <- struct{}{}
	tm := clock.next(t)
	if tm.d != 2*time.Second {
		t.Errorf("debounce interval = %v, want the 2s minimum", tm.d)
	}
	for range 5 {
		src.changes <- struct{}{} // coalesced while the timer runs
	}
	if n := src.count(); n != 1 {
		t.Fatalf("source read %d times before the timer fired", n)
	}
	tm.fire <- synthNow
	if err := waitBuild(t, builds); err != nil {
		t.Fatal(err)
	}
	if n := src.count(); n != 2 {
		t.Errorf("six changes should cost one rebuild; source read %d times", n)
	}
	if v2 := m.Current(); v2.Version <= v.Version || v2.Stale {
		t.Errorf("second view = %+v", v2)
	}
}

func TestManagerKeepsLastViewOnError(t *testing.T) {
	src := notifyingSource{&fakeSource{inv: smallInventory()}, make(chan struct{})}
	clock := newFakeClock()
	m := &Manager{Source: src}
	m.after = clock.after
	builds, stop := startManager(t, m)
	defer stop()
	waitBuild(t, builds)
	good := m.Current()

	src.setErr(errors.New("apiserver unreachable"))
	src.changes <- struct{}{}
	clock.next(t).fire <- synthNow
	if err := waitBuild(t, builds); err == nil {
		t.Fatal("want a failed build")
	}
	stale := m.Current()
	if !stale.Stale || stale.Err != "apiserver unreachable" || stale.Version != good.Version || len(stale.Workloads["a"]) != 1 {
		t.Fatalf("stale view = %+v", stale)
	}
	if good.Stale {
		t.Error("the published view must not be modified in place")
	}
	if stale.Assoc() != good.Assoc() {
		t.Error("a stale copy shares the indexes")
	}

	// A failure is retried after the interval even without a change.
	src.setErr(nil)
	clock.next(t).fire <- synthNow
	if err := waitBuild(t, builds); err != nil {
		t.Fatal(err)
	}
	if v := m.Current(); v.Stale || v.Version <= good.Version {
		t.Errorf("recovered view = %+v", v)
	}
}

func TestManagerPollsWithoutNotifier(t *testing.T) {
	src := &fakeSource{inv: smallInventory()}
	clock := newFakeClock()
	m := &Manager{Source: src, MinInterval: time.Second}
	m.after = clock.after
	builds, stop := startManager(t, m)
	defer stop()
	waitBuild(t, builds)
	for i := range 3 {
		tm := clock.next(t)
		if tm.d != time.Second {
			t.Errorf("poll interval = %v", tm.d)
		}
		tm.fire <- synthNow
		waitBuild(t, builds)
		if n := src.count(); n != i+2 {
			t.Errorf("reads = %d, want %d", n, i+2)
		}
	}
}

func TestManagerAdaptiveInterval(t *testing.T) {
	m := &Manager{MinInterval: 2 * time.Second, MaxDelay: 10 * time.Second}
	for _, c := range []struct{ build, want time.Duration }{
		{0, 2 * time.Second},
		{100 * time.Millisecond, 2 * time.Second},
		{time.Second, 5 * time.Second},
		{3 * time.Second, 10 * time.Second},
	} {
		m.lastBuild.Store(int64(c.build))
		if got := m.interval(); got != c.want {
			t.Errorf("build %v: interval %v, want %v", c.build, got, c.want)
		}
	}
	if got := (&Manager{}).interval(); got != DefaultMinInterval {
		t.Errorf("default interval = %v", got)
	}
}

func TestManagerViewWaitsForFirstBuild(t *testing.T) {
	src := &fakeSource{err: errors.New("forbidden")}
	clock := newFakeClock()
	m := &Manager{Source: src}
	m.after = clock.after
	builds, stop := startManager(t, m)
	defer stop()
	waitBuild(t, builds)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if v, err := m.View(ctx); v != nil || err == nil || !strings.Contains(err.Error(), "forbidden") {
		t.Errorf("view before the first success = %v, %v", v, err)
	}
	if m.Current() != nil {
		t.Error("no view should exist yet")
	}

	src.setErr(nil)
	got := make(chan *View, 1)
	go func() {
		v, _ := m.View(context.Background())
		got <- v
	}()
	clock.next(t).fire <- synthNow
	waitBuild(t, builds)
	select {
	case v := <-got:
		if v == nil {
			t.Error("View returned nil after the first build")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("View did not wake up")
	}
	select {
	case <-m.Ready():
	default:
		t.Error("Ready should be closed")
	}
}

func TestOnDemandAndStatic(t *testing.T) {
	src := &fakeSource{inv: smallInventory()}
	od := OnDemand{Source: src, Now: func() time.Time { return synthNow }}
	v1, err := od.View(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	v2, _ := od.View(context.Background())
	if v1 == v2 || v2.Version <= v1.Version || src.count() != 2 {
		t.Errorf("OnDemand should build every call: %d %d reads=%d", v1.Version, v2.Version, src.count())
	}
	src.setErr(errors.New("down"))
	if _, err := od.View(context.Background()); err == nil {
		t.Error("OnDemand passes source errors through")
	}

	var p ViewProvider = Static(v1)
	if got, err := p.View(context.Background()); got != v1 || err != nil {
		t.Errorf("Static = %v, %v", got, err)
	}
	if _, err := Static(nil).View(context.Background()); err == nil {
		t.Error("Static(nil) should fail")
	}
	if v1.Policy.Thresholds != detectors.DefaultPolicy().Thresholds {
		t.Error("a zero policy builds with the defaults")
	}
}

// LastChange follows the source's change signals, so an unbuilt change
// shows as newer than the served view while a quiet cluster's view and
// change are both old.
func TestManagerLastChange(t *testing.T) {
	src := notifyingSource{&fakeSource{inv: smallInventory()}, make(chan struct{})}
	clock := newFakeClock()
	var mu sync.Mutex
	at := synthNow
	now := func() time.Time { mu.Lock(); defer mu.Unlock(); return at }
	set := func(t time.Time) { mu.Lock(); at = t; mu.Unlock() }
	m := &Manager{Source: src, Now: now}
	m.after = clock.after
	if !m.LastChange().IsZero() {
		t.Fatal("a change before Run")
	}
	builds, stop := startManager(t, m)
	defer stop()
	waitBuild(t, builds)
	if !m.LastChange().Equal(synthNow) || !m.Current().Built.Equal(synthNow) {
		t.Fatalf("after the first build: change %v, built %v", m.LastChange(), m.Current().Built)
	}

	set(synthNow.Add(time.Minute)) // quiet for a minute, then a change
	src.changes <- struct{}{}
	tm := clock.next(t)
	if got := m.LastChange(); !got.Equal(synthNow.Add(time.Minute)) || !got.After(m.Current().Built) {
		t.Fatalf("pending change %v, view built %v", got, m.Current().Built)
	}
	set(synthNow.Add(time.Minute + 2*time.Second))
	tm.fire <- synthNow
	waitBuild(t, builds)
	if m.LastChange().After(m.Current().Built) {
		t.Errorf("after the rebuild the change %v is still newer than the view %v", m.LastChange(), m.Current().Built)
	}
}
