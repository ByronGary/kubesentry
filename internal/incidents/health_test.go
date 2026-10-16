package incidents

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/model"
	"github.com/ByronGary/kubesentry/internal/snapshot"
)

// scriptedEvents is an event source with a permission probe. Each Run takes
// the next step: "fail" returns an error at once; "batch" waits for the
// gate, sends one batch, then waits for the end; "wait" waits for the end.
// Runs past the script wait.
type scriptedEvents struct {
	mu    sync.Mutex
	probe string
	steps []string
	gate  chan struct{}
	calls []time.Time
}

func (e *scriptedEvents) Probe(context.Context) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.probe
}

func (e *scriptedEvents) setProbe(v string) {
	e.mu.Lock()
	e.probe = v
	e.mu.Unlock()
}

func (e *scriptedEvents) runs() []time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]time.Time(nil), e.calls...)
}

func (e *scriptedEvents) Run(ctx context.Context, sink func([]model.KubeEvent)) error {
	e.mu.Lock()
	e.calls = append(e.calls, time.Now())
	step := "wait"
	if len(e.steps) > 0 {
		step, e.steps = e.steps[0], e.steps[1:]
	}
	e.mu.Unlock()
	switch step {
	case "fail":
		return errors.New("watch events: connection refused")
	case "batch":
		select {
		case <-e.gate:
		case <-ctx.Done():
			return nil
		}
		sink([]model.KubeEvent{kev("e1", "Pod", "shop", "api-7d9f-a", "BackOff", 1, t0, t0)})
	}
	<-ctx.Done()
	return nil
}

// probedLogs is a log source that answers a probe.
type probedLogs struct{ name, probe string }

func (l *probedLogs) Name() string                                      { return l.name }
func (l *probedLogs) Logs(context.Context, LogQuery) (LogResult, error) { return LogResult{}, nil }
func (l *probedLogs) Probe(context.Context) string                      { return l.probe }

// failingMemory always fails.
type failingMemory struct{}

func (failingMemory) MemoryUsage(context.Context, time.Time, []string) ([]model.MemorySample, error) {
	return nil, errors.New("prometheus: 503 Service Unavailable")
}

// failingAudit is an audit store whose reads fail.
type failingAudit struct{ audit.Store }

func (failingAudit) Query(context.Context, audit.Query) ([]audit.Event, error) {
	return nil, errors.New("audit store: connection refused")
}

// switchTrail is a CloudTrail source whose polls fail while fail is set;
// its probe always succeeds, and counts.
type switchTrail struct {
	mu     sync.Mutex
	fail   bool
	probes int
}

func (f *switchTrail) Name() string { return "lookup" }

func (f *switchTrail) Changes(context.Context, time.Time, []byte) ([]CloudTrailEvent, []byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return nil, nil, errors.New("ThrottlingException: Rate exceeded")
	}
	return nil, []byte(`{}`), nil
}

func (f *switchTrail) Probe(context.Context) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.probes++
	return "ok"
}

func (f *switchTrail) set(fail bool) {
	f.mu.Lock()
	f.fail = fail
	f.mu.Unlock()
}

func (f *switchTrail) probed() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.probes
}

// healthRunner is a runner on a fixed view and clock, with fast loops.
func healthRunner(t *testing.T, c Config) *Runner {
	t.Helper()
	v := view(fixture(), t0)
	c.Store = NewMemoryStore()
	c.View = func() *snapshot.View { return v }
	c.Options = Options{Now: func() time.Time { return t0 }, CommitEvery: 10 * time.Millisecond, Interval: 20 * time.Millisecond,
		AuditEvery: 20 * time.Millisecond, CloudTrailEvery: 20 * time.Millisecond, Refresh: 10 * time.Millisecond, Retry: 20 * time.Millisecond}
	r, err := NewRunner(c)
	if err != nil {
		t.Fatal(err)
	}
	r.eventsRetry, r.eventsMaxRetry, r.eventsUp = 20*time.Millisecond, 40*time.Millisecond, time.Hour
	return r
}

func run(t *testing.T, r *Runner) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
}

// Every replica probes the event source and each log source; a probe's bare
// reason reads as an error, and a successful probe brings events back.
func TestProbeEventsAndLogs(t *testing.T) {
	ev := &scriptedEvents{probe: "forbidden: cannot watch events (RBAC: access denied)"}
	r := healthRunner(t, Config{EventSource: ev,
		Logs: []LogSource{&probedLogs{name: "cloudwatch", probe: "error: cloudwatch: log group not found"}, &fakeLogs{}}})
	r.probe(context.Background())
	src := r.Sources()
	if src["events"] != "error: forbidden: cannot watch events (RBAC: access denied)" || src["logs:cloudwatch"] != "error: cloudwatch: log group not found" ||
		src["logs:kubernetes"] != "ok" {
		t.Errorf("after a failed probe: %v", src)
	}
	ev.setProbe("ok")
	r.probe(context.Background())
	if got := r.Source("events"); got != "ok" {
		t.Errorf("after a successful probe: events %q", got)
	}
	for in, want := range map[string]string{"ok": "ok", "absent": "absent", "error: x": "error: x", "forbidden: y": "error: forbidden: y", "": "error: the probe gave no answer"} {
		if got := probeState(in); got != want {
			t.Errorf("probeState(%q) = %q, want %q", in, got, want)
		}
	}
}

// On the leader a failed watch is an error until the watch delivers a
// batch; a successful permission probe meanwhile does not hide it.
func TestEventsBackOnABatch(t *testing.T) {
	ev := &scriptedEvents{probe: "ok", steps: []string{"fail", "batch"}, gate: make(chan struct{})}
	r := healthRunner(t, Config{EventSource: ev})
	run(t, r)
	eventually(t, "the failed watch reported", func() bool {
		return len(ev.runs()) == 2 && r.Source("events") == "error: watch events: connection refused"
	})
	r.probe(context.Background())
	if got := r.Source("events"); !isError(got) {
		t.Errorf("a successful probe cleared the failing watch's error: %q", got)
	}
	close(ev.gate)
	eventually(t, "events ok after a batch", func() bool { return r.Source("events") == "ok" })
}

// A watch that stays up eventsUp counts as working.
func TestEventsBackAfterStayingUp(t *testing.T) {
	ev := &scriptedEvents{probe: "ok", steps: []string{"fail", "wait"}}
	r := healthRunner(t, Config{EventSource: ev})
	r.eventsUp = time.Second
	run(t, r)
	eventually(t, "the watch restarted", func() bool { return len(ev.runs()) == 2 })
	if got := r.Source("events"); got != "error: watch events: connection refused" {
		t.Errorf("right after the restart: events %q", got)
	}
	eventually(t, "events ok once the watch stayed up", func() bool { return r.Source("events") == "ok" })
	if up := time.Since(ev.runs()[1]); up < time.Second {
		t.Errorf("ok after %s, before the watch stayed up a second", up)
	}
}

// Quick failures back off, doubling up to the maximum.
func TestEventsBackOff(t *testing.T) {
	ev := &scriptedEvents{probe: "ok", steps: []string{"fail", "fail", "fail", "fail"}}
	r := healthRunner(t, Config{EventSource: ev})
	r.eventsRetry, r.eventsMaxRetry = 30*time.Millisecond, 60*time.Millisecond
	run(t, r)
	eventually(t, "five watches", func() bool { return len(ev.runs()) == 5 })
	calls := ev.runs()
	for i, want := range []time.Duration{30, 60, 60, 60} {
		if gap := calls[i+1].Sub(calls[i]); gap < want*time.Millisecond {
			t.Errorf("retry %d after %s, want at least %dms", i+1, gap, want)
		}
	}
}

// A successful CloudTrail poll clears the error of a failed one.
func TestCloudTrailBackAfterAPoll(t *testing.T) {
	ct := &switchTrail{fail: true}
	r := healthRunner(t, Config{CloudTrail: ct})
	run(t, r)
	eventually(t, "a failed poll after the probe", func() bool {
		return ct.probed() > 0 && strings.HasPrefix(r.Source("cloudtrail"), "error: ")
	})
	ct.set(false) // the probe runs every 10 minutes: only a poll can clear it now
	eventually(t, "cloudtrail ok after a poll", func() bool { return r.Source("cloudtrail") == "ok" })
}

// When leadership ends, what only the leader updates goes back: memory and
// audit to their initial state, events and CloudTrail to their last probe.
func TestLeaderSourcesResetWhenLeadershipEnds(t *testing.T) {
	ev := &scriptedEvents{probe: "ok", steps: []string{"fail", "fail", "fail", "fail", "fail", "fail"}}
	ct := &switchTrail{fail: true}
	lease := &fakeLease{lost: make(chan struct{})}
	var elections sync.Mutex
	granted := false
	r := healthRunner(t, Config{EventSource: ev, CloudTrail: ct, Memory: failingMemory{}, Audit: failingAudit{},
		Elect: func(context.Context) (Lease, bool, error) {
			elections.Lock()
			defer elections.Unlock()
			if granted {
				return nil, false, nil
			}
			granted = true
			return lease, true, nil
		}})
	lease.store = r.c.Store
	run(t, r)
	eventually(t, "every leader-updated source failing", func() bool {
		src := r.Sources()
		return r.Leader() && ct.probed() > 0 && isError(src["events"]) && isError(src["cloudtrail"]) && isError(src["memory"]) && isError(src["audit"])
	})
	close(lease.lost)
	eventually(t, "a follower", func() bool { return !r.Leader() && lease.released.Load() })
	src := r.Sources()
	for _, k := range []string{"events", "cloudtrail", "memory", "audit", "series", "alerts"} {
		want := "ok"
		if k == "series" || k == "alerts" {
			want = "absent"
		}
		if src[k] != want {
			t.Errorf("after leadership ended %s = %q, want %q (all: %v)", k, src[k], want, src)
		}
	}
}
