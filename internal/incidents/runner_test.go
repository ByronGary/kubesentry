package incidents

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/alerts"
	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/model"
	"github.com/ByronGary/kubesentry/internal/snapshot"
)

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// fakeEvents sends one batch, then waits.
type fakeEvents struct{ batch []model.KubeEvent }

func (f *fakeEvents) Run(ctx context.Context, sink func([]model.KubeEvent)) error {
	sink(f.batch)
	<-ctx.Done()
	return ctx.Err()
}

type fakeSeries struct{}

func (fakeSeries) SubjectSeries(_ context.Context, q SeriesQuery) ([]Series, error) {
	return []Series{{Metric: "memory", Label: q.Pods[0] + "/app", Unit: "bytes", Points: [][2]float64{{float64(q.From.UnixMilli()), 1}}}}, nil
}

type fakeLease struct {
	lost     chan struct{}
	store    Store
	released atomic.Bool
}

func (l *fakeLease) Lost() <-chan struct{}         { return l.lost }
func (l *fakeLease) Release(context.Context) error { l.released.Store(true); return nil }
func (l *fakeLease) Store() Store                  { return l.store }

// The leader runs every producer into one engine and publishes committed
// incidents; the API helpers read them back.
func TestRunnerLeads(t *testing.T) {
	now := t0.Add(time.Minute)
	inv := withPod(fixture(), "api-7d9f-b", func(p *model.Pod) { p.Containers[0].State, p.Containers[0].Reason = "waiting", "CrashLoopBackOff" })
	var cur atomic.Pointer[snapshot.View]
	cur.Store(view(inv, now))
	st := audit.NewMemoryStore(100).AsStore()
	_ = st.Add(context.Background(), []audit.Event{{AuditID: "a1", Time: now.Add(-2 * time.Minute), Verb: "patch", Username: "alice",
		ActorKind: "user", Resource: "deployments", Namespace: "shop", Name: "api", StatusCode: 200}})
	rates := &fakeRates{name: "app", recent: []model.RateSample{podRate("api-7d9f-a", 50, 0.3)}, base: []model.RateSample{podRate("api-7d9f-a", 10, 0)}}
	logs := &fakeLogs{perMinute: func(time.Time) int { return 1 }}
	var mu sync.Mutex
	var leading []bool
	var signals atomic.Int64
	kick := make(chan struct{}, 1)
	r, err := NewRunner(Config{
		Store: NewMemoryStore(), View: cur.Load, Kick: kick,
		Rates: []RateSource{rates}, Series: fakeSeries{}, Logs: []LogSource{logs}, Audit: st,
		EventSource: &fakeEvents{batch: []model.KubeEvent{kev("e1", "Pod", "shop", "api-7d9f-a", "OOMKilling", 1, now, now)}},
		CloudTrail: &fakeTrail{evs: []CloudTrailEvent{{ID: "ct1", Time: now.Add(-5 * time.Minute), Name: "AuthorizeSecurityGroupIngress",
			Source: "ec2.amazonaws.com", Actor: "erin", Resources: []string{"sg-0abc"}}}},
		Alerts: func() []alerts.Finding { return nil },
		Options: Options{Now: func() time.Time { return now }, CommitEvery: 10 * time.Millisecond, Interval: 20 * time.Millisecond,
			AuditEvery: 20 * time.Millisecond, CloudTrailEvery: 20 * time.Millisecond, LogsEvery: 20 * time.Millisecond, AlertsEvery: 20 * time.Millisecond},
		Hooks: Hooks{
			OnLeader:  func(on bool) { mu.Lock(); leading = append(leading, on); mu.Unlock() },
			OnSignals: func(_ string, n int) { signals.Add(int64(n)) },
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	want := []string{TypeAuditChange, TypeCloudTrailChange, TypeCrashLoop, TypeErrorRate, TypeKubeEvent, TypeRequestSpike}
	var id string
	eventually(t, "one incident with every signal", func() bool {
		ins, _ := r.Board().Snapshot()
		if len(ins) != 1 {
			return false
		}
		id = ins[0].ID
		return strings.Join(ins[0].Types, ",") == strings.Join(want, ",")
	})
	if !r.Leader() || signals.Load() == 0 {
		t.Errorf("leader %v, %d signals counted", r.Leader(), signals.Load())
	}
	if src := r.Sources(); src["requests:app"] != "ok" || src["cloudtrail"] != "ok" || src["logs:kubernetes"] != "ok" || src["memory"] != "absent" {
		t.Errorf("sources = %v", src)
	}
	d, ok, err := r.Detail(context.Background(), id, DetailOptions{})
	if err != nil || !ok {
		t.Fatalf("detail: %v %v", ok, err)
	}
	if d.Incident.Severity != Critical || len(d.Events) != 1 || len(d.Series) != 1 || d.Sources["series"] != "ok" || len(d.Thresholds) == 0 {
		t.Errorf("detail: %+v", d)
	}
	if !d.From.Equal(d.Incident.Start.Add(-DefaultLogLead)) {
		t.Errorf("window from %s", d.From)
	}
	lr, err := r.Logs(context.Background(), id, LogRequest{Pods: []string{"api-7d9f-a", "not-ours"}, Level: "error"})
	if err != nil || len(lr.Lines) == 0 || lr.Source != "kubernetes" {
		t.Fatalf("logs: %+v %v", lr, err)
	}
	logs.mu.Lock()
	last := logs.queries[len(logs.queries)-1]
	logs.mu.Unlock()
	if len(last.Pods) != 1 || last.Pods[0] != "api-7d9f-a" || !last.Previous || last.Limit != 2000 {
		t.Errorf("log query %+v", last)
	}
	if _, err := r.Logs(context.Background(), id, LogRequest{Source: "cloudwatch"}); !errors.Is(err, ErrNoLogSource) {
		t.Errorf("cloudwatch logs: %v", err)
	}
	if _, err := r.Logs(context.Background(), "nope", LogRequest{}); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown incident: %v", err)
	}
	b, err := r.Bundle(context.Background(), id, BundleRequest{Omitted: map[string]string{SectionCloudTrail: "forbidden"}})
	if err != nil {
		t.Fatal(err)
	}
	if b.Complete || len(b.CloudTrail) != 0 || len(b.Audit) != 1 || len(b.Logs) == 0 || len(b.Events) != 1 || len(b.Metrics) != 1 {
		t.Errorf("bundle: %+v", b.BundleHeader)
	}
	var buf bytes.Buffer
	if err := b.WriteNDJSON(&buf); err != nil || !strings.Contains(buf.String(), `"kind":"log"`) {
		t.Errorf("ndjson: %v", err)
	}
	// A kick with a new view runs the differ: the crash loop ends.
	ok2 := withPod(inv, "api-7d9f-b", func(p *model.Pod) { p.Containers[0].State, p.Containers[0].Reason = "running", "" })
	cur.Store(view(ok2, now))
	kick <- struct{}{}
	eventually(t, "the crash loop to end", func() bool {
		ss, _ := r.Signals(id)
		for _, s := range ss {
			if s.Type == TypeCrashLoop {
				return s.End != nil
			}
		}
		return false
	})
}

// Once its lease is lost the runner stops leading and serves the board
// from the store.
func TestRunnerFollowsAfterLosingTheLease(t *testing.T) {
	store := NewMemoryStore()
	lease := &fakeLease{lost: make(chan struct{}), store: store}
	var elections atomic.Int32
	now := t0.Add(time.Minute)
	v := view(withPod(fixture(), "api-7d9f-b", func(p *model.Pod) { p.Containers[0].State, p.Containers[0].Reason = "waiting", "CrashLoopBackOff" }), now)
	r, err := NewRunner(Config{
		Store: store, View: func() *snapshot.View { return v },
		Elect: func(context.Context) (Lease, bool, error) {
			if elections.Add(1) == 1 {
				return lease, true, nil
			}
			return nil, false, nil
		},
		Options: Options{Now: func() time.Time { return now }, CommitEvery: 5 * time.Millisecond, Refresh: 5 * time.Millisecond, Retry: 20 * time.Millisecond},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	eventually(t, "a committed incident", func() bool {
		ins, _ := r.Board().Snapshot()
		_, leader, _ := r.Board().Status()
		return len(ins) == 1 && leader
	})
	close(lease.lost)
	eventually(t, "the lease released", func() bool { return lease.released.Load() && !r.Leader() })
	eventually(t, "a follower board", func() bool {
		ins, _ := r.Board().Snapshot()
		_, leader, ready := r.Board().Status()
		return ready && !leader && len(ins) == 1
	})
}

func TestNewRunnerRefusesBadOptions(t *testing.T) {
	if _, err := NewRunner(Config{}); err == nil {
		t.Error("no store accepted")
	}
	if _, err := NewRunner(Config{Store: NewMemoryStore(), Options: Options{MaxRange: 48 * time.Hour}}); err == nil {
		t.Error("48h range accepted")
	}
}

func TestSeriesStep(t *testing.T) {
	for _, c := range []struct {
		span, want time.Duration
	}{{10 * time.Minute, 15 * time.Second}, {2 * time.Hour, 30 * time.Second}, {24 * time.Hour, 5 * time.Minute}, {6 * time.Hour, 90 * time.Second}} {
		if got := SeriesStep(t0, t0.Add(c.span)); got != c.want {
			t.Errorf("step for %s = %s, want %s", c.span, got, c.want)
		}
	}
}
