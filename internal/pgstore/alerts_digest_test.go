package pgstore

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/alerts"
	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/model"
	"github.com/ByronGary/kubesentry/internal/snapshot"
)

// countSink counts the standing digest alerts it is handed.
type countSink struct {
	mu       sync.Mutex
	standing int
}

func (c *countSink) Send(as []alerts.Alert) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, a := range as {
		if a.Labels["alertname"] == alerts.AlertStandingDigest {
			c.standing++
		}
	}
}
func (c *countSink) Drop()                     {}
func (c *countSink) Status() alerts.SinkStatus { return alerts.SinkStatus{Name: "test"} }

func (c *countSink) take() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := c.standing
	c.standing = 0
	return n
}

// The standing digests' runs live in alert_digest_runs: the leader that
// sent a digest records it (on the lock's connection), a new leader reads
// it and does not send again, and the store and the memory store agree.
func TestPGStandingDigestRuns(t *testing.T) {
	ctx := context.Background()
	s := openTest(t, Options{})
	mem := alerts.NewMemoryStore()
	sched, err := alerts.ParseDigestSchedule("09:00", "")
	if err != nil {
		t.Fatal(err)
	}
	mon := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	inv := model.Inventory{
		Namespaces:     []model.Namespace{{Name: "shop", Annotations: map[string]string{"kubesentry.io/owner": "shop"}}},
		StorageClasses: []model.StorageClass{{Name: "gp3", PriceAnnotation: "0.08"}},
		PVCs:           []model.PVC{{Namespace: "shop", Name: "old", StorageClass: "gp3", Phase: "Bound", CapacityBytes: 50 << 30, Created: mon.Add(-30 * 24 * time.Hour)}},
	}
	evaluate := func(ev *alerts.Evaluator, at time.Time) {
		t.Helper()
		if _, err := ev.Evaluate(ctx, alerts.Input{View: snapshot.Build(inv, detectors.DefaultPolicy(), at), Now: at}); err != nil {
			t.Fatal(err)
		}
	}
	lead := func() (*Leader, *alerts.Evaluator, *countSink) {
		l, ok, err := s.TryLead(ctx, "alerts")
		if err != nil || !ok {
			t.Fatalf("lead: %v %v", ok, err)
		}
		sink := &countSink{}
		o := alerts.Options{Digests: alerts.DigestOptions{Schedule: sched, Kinds: []string{alerts.DigestUnusedVolumes}}}
		return l, alerts.NewEvaluator(l.Alerts(), sink, o), sink
	}
	memSink := &countSink{}
	memEv := alerts.NewEvaluator(mem, memSink, alerts.Options{Digests: alerts.DigestOptions{Schedule: sched, Kinds: []string{alerts.DigestUnusedVolumes}}})

	l, ev, sink := lead()
	tue := mon.Add(21*time.Hour + 1500*time.Microsecond + 700) // Tuesday 09:00, with sub-microsecond noise
	for _, at := range []time.Time{mon, tue} {
		evaluate(ev, at)
		evaluate(memEv, at)
	}
	if n := sink.take(); n != 1 {
		t.Fatalf("the leader sent %d standing digests, want 1", n)
	}
	if n := memSink.take(); n != 1 {
		t.Fatalf("the memory store's evaluator sent %d", n)
	}
	if err := l.Release(ctx); err != nil {
		t.Fatal(err)
	}

	// A new leader reads the run: nothing again that day.
	l, ev, sink = lead()
	defer l.Release(ctx)
	evaluate(ev, tue.Add(time.Minute))
	if n := sink.take(); n != 0 {
		t.Errorf("a new leader sent %d again", n)
	}
	got, err := s.Alerts().DigestRuns(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := mem.DigestRuns(ctx)
	if len(got) != 1 || !got[alerts.DigestUnusedVolumes].Equal(alerts.NormalTime(tue)) || !got[alerts.DigestUnusedVolumes].Equal(want[alerts.DigestUnusedVolumes]) {
		t.Errorf("runs: postgres %v, memory %v", got, want)
	}
	if !ev.LastDigest().Equal(alerts.NormalTime(tue)) {
		t.Errorf("the new leader's last digest %s", ev.LastDigest())
	}
}
