package incidents

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
)

// t0 is the tests' clock origin.
var t0 = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

// fakeClock is a settable clock.
type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time          { return c.t }
func (c *fakeClock) Set(t time.Time)         { c.t = t }
func (c *fakeClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

var api = Subject{Kind: "Deployment", Namespace: "shop", Name: "api"}

func at(m float64) time.Time { return t0.Add(time.Duration(m * float64(time.Minute))) }

// trig is a trigger signal at minute m; cond makes it a condition (End nil
// until ended).
func trig(id, typ string, sev Severity, m float64) Signal {
	return Signal{ID: id, Type: typ, Source: SourceMetrics, Role: Trigger, Severity: sev, Start: at(m), Subject: api,
		Object: model.ObjectRef{Kind: "Deployment", Namespace: "shop", Name: "api"}, Title: typ}
}

func ctxSig(id, typ string, m float64) Signal {
	return Signal{ID: id, Type: typ, Source: SourceView, Role: Context, Start: at(m), Subject: api,
		Object: model.ObjectRef{Kind: "Deployment", Namespace: "shop", Name: "api"}, Title: typ}
}

func ended(s Signal, m float64) Signal {
	s.End = timePtr(at(m))
	return s
}

type harness struct {
	t     *testing.T
	clock *fakeClock
	store *MemoryStore
	board *MemBoard
	e     *Engine
}

func newHarness(t *testing.T, o Options) *harness {
	t.Helper()
	h := &harness{t: t, clock: &fakeClock{t: t0}, store: NewMemoryStore(), board: NewBoard(0)}
	o.Now = h.clock.Now
	h.e = NewEngine(h.store, h.board, o)
	if err := h.e.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	return h
}

// step moves the clock to minute m, adds the signals, ticks and flushes.
func (h *harness) step(m float64, sigs ...Signal) {
	h.t.Helper()
	h.clock.Set(at(m))
	h.e.Add(sigs...)
	h.e.Tick()
	if err := h.e.Flush(context.Background()); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) all() []Incident {
	h.t.Helper()
	ins, err := h.store.List(context.Background(), Query{})
	if err != nil {
		h.t.Fatal(err)
	}
	return ins
}

func (h *harness) only() Incident {
	h.t.Helper()
	ins := h.all()
	if len(ins) != 1 {
		h.t.Fatalf("%d incidents, want 1: %s", len(ins), describe(ins))
	}
	return ins[0]
}

func (h *harness) signals(id string) []Signal {
	h.t.Helper()
	_, ss, ok, err := h.store.Get(context.Background(), id)
	if err != nil || !ok {
		h.t.Fatalf("get %s: %v %v", id, ok, err)
	}
	return ss
}

func describe(ins []Incident) string {
	var b strings.Builder
	for _, in := range ins {
		end := "-"
		if in.End != nil {
			end = in.End.Format("15:04")
		}
		fmt.Fprintf(&b, "\n  %s %s/%s %s %s..%s sev=%s peak=%s capped=%v prev=%s types=%v",
			in.ID, in.Subject.Kind, in.Subject.Name, in.State, in.Start.Format("01-02 15:04"), end, in.Severity, in.PeakSeverity, in.Capped, in.Previous, in.Types)
	}
	return b.String()
}

func ids(ss []Signal) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = s.ID
	}
	return out
}

// The user's example: more requests and a memory spike on one app are one
// incident with both triggers; a deploy 20 minutes earlier attaches through
// the lookbehind.
func TestRequestAndMemorySpikeAreOneIncident(t *testing.T) {
	h := newHarness(t, Options{})
	h.step(-20, ctxSig("deploy-1", TypeDeploy, -20))
	if n := len(h.all()); n != 0 {
		t.Fatalf("a deploy alone opened %d incidents", n)
	}
	h.step(0, trig("req-1", TypeRequestSpike, Warning, 0))
	h.step(2, trig("mem-1", TypeMemorySpike, Critical, 2))
	in := h.only()
	if in.Start != at(0) || in.State != Open || in.Severity != Critical || in.PeakSeverity != Critical {
		t.Fatalf("incident %s", describe([]Incident{in}))
	}
	if want := []string{TypeDeploy, TypeMemorySpike, TypeRequestSpike}; !reflect.DeepEqual(in.Types, want) {
		t.Errorf("types = %v, want %v", in.Types, want)
	}
	if in.Title != "api: memory spike, request spike" {
		t.Errorf("title = %q", in.Title)
	}
	if got := ids(h.signals(in.ID)); !reflect.DeepEqual(got, []string{"deploy-1", "req-1", "mem-1"}) {
		t.Errorf("signals = %v", got)
	}
	if in.ID != IncidentID(api, at(0)) || !strings.HasPrefix(in.ID, "20261015T120000Z-") {
		t.Errorf("id = %s", in.ID)
	}
	// A deploy older than the lookbehind does not attach.
	h2 := newHarness(t, Options{})
	h2.step(-31, ctxSig("deploy-old", TypeDeploy, -31))
	h2.step(0, trig("req-1", TypeRequestSpike, Warning, 0))
	if got := ids(h2.signals(h2.only().ID)); !reflect.DeepEqual(got, []string{"req-1"}) {
		t.Errorf("signals with an old deploy = %v", got)
	}
}

// An incident resolves once no trigger is active and the last ended Quiet
// ago; it ends when the last trigger did.
func TestQuietClose(t *testing.T) {
	cases := []struct {
		name    string
		steps   func(h *harness)
		open    bool
		end     float64
		quietAt float64 // minute at which it must have resolved
	}{
		{"condition ends", func(h *harness) {
			h.step(0, trig("req", TypeRequestSpike, Warning, 0))
			h.step(10, ended(trig("req", TypeRequestSpike, Warning, 0), 10))
			h.step(24.9)
		}, true, 0, 0},
		{"condition ends, quiet passes", func(h *harness) {
			h.step(0, trig("req", TypeRequestSpike, Warning, 0))
			h.step(10, ended(trig("req", TypeRequestSpike, Warning, 0), 10))
			h.step(25)
		}, false, 10, 25},
		{"point triggers", func(h *harness) {
			h.step(0, trig("oom-1", TypeOOMKill, Critical, 0))
			h.step(5, trig("oom-2", TypeOOMKill, Critical, 5))
			h.step(20)
		}, false, 5, 20},
		{"an active condition keeps it open", func(h *harness) {
			h.step(0, trig("req", TypeRequestSpike, Warning, 0))
			h.step(5, trig("oom-1", TypeOOMKill, Critical, 5))
			h.step(25, trig("req", TypeRequestSpike, Warning, 0)) // still reported, still active
		}, true, 0, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, Options{})
			c.steps(h)
			in := h.only()
			if c.open {
				if in.State != Open || in.End != nil {
					t.Fatalf("want open: %s", describe([]Incident{in}))
				}
				return
			}
			if in.State != Resolved || in.End == nil || !in.End.Equal(at(c.end)) {
				t.Fatalf("want resolved at minute %v: %s", c.end, describe([]Incident{in}))
			}
		})
	}
}

// Severity is the worst active trigger; the peak never goes down.
func TestEscalationAndPeak(t *testing.T) {
	h := newHarness(t, Options{})
	type want struct{ sev, peak Severity }
	check := func(w want) {
		t.Helper()
		in := h.only()
		if in.Severity != w.sev || in.PeakSeverity != w.peak {
			t.Fatalf("severity %s peak %s, want %s %s", in.Severity, in.PeakSeverity, w.sev, w.peak)
		}
	}
	h.step(0, trig("req", TypeRequestSpike, Warning, 0))
	check(want{Warning, Warning})
	h.step(1, trig("req", TypeRequestSpike, Critical, 0)) // the spike grows to x4
	check(want{Critical, Critical})
	h.step(3, trig("req", TypeRequestSpike, Warning, 0)) // and calms to x2
	check(want{Warning, Critical})
	h.step(4, trig("oom", TypeOOMKill, Critical, 4))
	check(want{Critical, Critical})
	h.step(19.5) // the OOM kill counts for Quiet after it happened
	check(want{Warning, Critical})
	h.step(30, ended(trig("req", TypeRequestSpike, Warning, 0), 30))
	h.step(50)
	in := h.only()
	if in.State != Resolved || in.Severity != Warning || in.PeakSeverity != Critical {
		t.Fatalf("after resolving: %s", describe([]Incident{in}))
	}
}

// Logs are written after the fact: an error-log burst found after the
// incident resolved still attaches while inside the lag, and the padded
// window covers it.
func TestLogsAfterTheFactLandInTheLag(t *testing.T) {
	h := newHarness(t, Options{})
	h.step(0, trig("oom", TypeOOMKill, Critical, 0))
	h.step(16)
	in := h.only()
	if in.State != Resolved || !in.End.Equal(at(0)) {
		t.Fatalf("not resolved: %s", describe([]Incident{in}))
	}
	logs := ctxSig("logs-1", TypeLogErrors, 8) // counted at minute 18, lines from minute 8
	logs.Source = SourceLogs
	late := ctxSig("logs-2", TypeLogErrors, 11) // past end+lag (10m)
	late.Source = SourceLogs
	h.step(18, logs, late)
	if got := ids(h.signals(in.ID)); !reflect.DeepEqual(got, []string{"oom", "logs-1"}) {
		t.Errorf("signals = %v, want the OOM kill and the burst inside the lag", got)
	}
	in = h.only()
	from, to := in.Window(DefaultLogLead, DefaultLogLag, at(30))
	if !from.Equal(at(-5)) || !to.Equal(at(10)) {
		t.Errorf("window = %s..%s", from, to)
	}
	if in.State != Resolved {
		t.Errorf("context reopened the incident")
	}
}

// CloudTrail delivers up to ~15 minutes late: a change from before the
// incident started (inside the lookbehind) attaches to the resolved
// incident when it finally arrives.
func TestLateCloudTrailAttachesToResolved(t *testing.T) {
	h := newHarness(t, Options{})
	h.step(0, trig("req", TypeRequestSpike, Critical, 0))
	h.step(5, ended(trig("req", TypeRequestSpike, Critical, 0), 5))
	h.step(21)
	in := h.only()
	if in.State != Resolved {
		t.Fatalf("not resolved: %s", describe([]Incident{in}))
	}
	ct := ctxSig("ct-1", TypeCloudTrailChange, -12)
	ct.Source = SourceCloudTrail
	ct.Object = model.ObjectRef{Kind: "AWS::EC2::SecurityGroup", Name: "sg-0abc"}
	h.step(26, ct)
	if got := ids(h.signals(in.ID)); !reflect.DeepEqual(got, []string{"ct-1", "req"}) {
		t.Fatalf("signals = %v", got)
	}
	got := h.only()
	if got.State != Resolved || !reflect.DeepEqual(got.Types, []string{TypeCloudTrailChange, TypeRequestSpike}) {
		t.Errorf("after the late signal: %s", describe([]Incident{got}))
	}
	// Re-reading the same CloudTrail event changes nothing.
	v := h.board.version
	h.step(28, ct)
	if h.board.version != v {
		t.Errorf("a repeated signal republished the board")
	}
	// Past the late window the engine lets the incident go; the store
	// keeps it.
	h.step(5 + 10 + 61)
	if _, _, ok := h.e.Incident(in.ID); ok {
		t.Errorf("still tracked past the late window")
	}
	if len(h.all()) != 1 {
		t.Errorf("store lost the incident")
	}
}

// At MaxRange an incident closes, capped, and continues in a new one that
// carries the active conditions; a failover rebuilds the same IDs.
func TestCapSplitsAndContinues(t *testing.T) {
	h := newHarness(t, Options{})
	h.step(0, trig("mem", TypeMemorySpike, Critical, 0))
	day := 24 * 60.0
	h.step(day-1, trig("mem", TypeMemorySpike, Critical, 0))
	h.step(day+0.5, trig("mem", TypeMemorySpike, Critical, 0))
	ins := h.all()
	if len(ins) != 2 {
		t.Fatalf("incidents: %s", describe(ins))
	}
	next, first := ins[0], ins[1]
	if !first.Capped || first.State != Resolved || !first.End.Equal(at(day)) {
		t.Errorf("first: %s", describe([]Incident{first}))
	}
	if next.Previous != first.ID || next.State != Open || !next.Start.Equal(at(day)) || next.Severity != Critical ||
		next.ID != IncidentID(api, at(day)) {
		t.Errorf("continuation: %s", describe([]Incident{next}))
	}
	fs := h.signals(first.ID)
	if len(fs) != 1 || fs[0].End == nil || !fs[0].End.Equal(at(day)) {
		t.Errorf("the capped incident's condition: %+v", fs)
	}
	ns := h.signals(next.ID)
	if len(ns) != 1 || ns[0].ID != "mem" || ns[0].End != nil || !ns[0].Start.Equal(at(day)) {
		t.Errorf("the carried condition: %+v", ns)
	}
	if w0, w1 := first.Window(DefaultLogLead, DefaultLogLag, at(day+1)); w1.Sub(w0) > MaxRange {
		t.Errorf("window %s..%s is longer than the cap", w0, w1)
	}
	// The condition ends: the continuation resolves on its own.
	h.step(day+10, ended(trig("mem", TypeMemorySpike, Critical, 0), day+10))
	h.step(day + 30)
	if got := h.all()[0]; got.State != Resolved || !got.End.Equal(at(day+10)) || got.Capped {
		t.Errorf("continuation after the end: %s", describe([]Incident{got}))
	}
}

// A new lease holder loads the open incidents and carries on with the same
// IDs; its producers resume the active conditions.
func TestFailoverReloadKeepsIDs(t *testing.T) {
	h := newHarness(t, Options{})
	h.step(0, trig("req", TypeRequestSpike, Warning, 0))
	h.step(1, ctxSig("deploy", TypeDeploy, 1))
	before := h.only()

	// Another replica takes over: same store, a fresh engine.
	clock := &fakeClock{t: at(2)}
	board := NewBoard(0)
	e2 := NewEngine(h.store, board, Options{Now: clock.Now})
	if err := e2.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if act := e2.Active(SourceMetrics); len(act) != 1 || act[0].ID != "req" {
		t.Fatalf("active conditions = %+v", act)
	}
	clock.Set(at(3))
	e2.Add(trig("req", TypeRequestSpike, Critical, 0), trig("mem", TypeMemorySpike, Warning, 3))
	e2.Tick()
	if err := e2.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	after := h.only()
	if after.ID != before.ID || after.Severity != Critical {
		t.Fatalf("after failover: %s", describe([]Incident{after}))
	}
	if got := ids(h.signals(after.ID)); !reflect.DeepEqual(got, []string{"req", "deploy", "mem"}) {
		t.Errorf("signals = %v", got)
	}
	// An incident opened independently by either replica from the same
	// trigger gets the same ID.
	other := Subject{Kind: "StatefulSet", Namespace: "shop", Name: "db"}
	s := trig("db-oom", TypeOOMKill, Critical, 3)
	s.Subject = other
	e2.Add(s)
	e2.Tick()
	_ = e2.Flush(context.Background())
	got, _, ok, _ := h.store.Get(context.Background(), IncidentID(other, at(3)))
	if !ok || got.Subject != other {
		t.Errorf("incident for %v not under its derived ID", other)
	}
}

// Point signals of the same type and object coalesce by count within a
// minute; repeats of a coalesced signal are not counted twice.
func TestCoalescing(t *testing.T) {
	h := newHarness(t, Options{})
	r := func(id string, m float64) Signal {
		s := trig(id, TypeRestart, Warning, m)
		s.Source = SourceView
		s.Object = model.ObjectRef{Kind: "Pod", Namespace: "shop", Name: "api-1"}
		s.Attrs = map[string]string{"container": "app"}
		return s
	}
	h.step(0, r("r1", 0))
	h.step(0.3, r("r2", 0.3), r("r3", 0.5))
	h.step(0.6, r("r2", 0.3)) // seen again
	h.step(1.5, r("r4", 1.5)) // more than a minute after r1
	other := r("r5", 1.6)
	other.Attrs = map[string]string{"container": "sidecar"}
	h.step(1.6, other)
	in := h.only()
	ss := h.signals(in.ID)
	if got := ids(ss); !reflect.DeepEqual(got, []string{"r1", "r4", "r5"}) {
		t.Fatalf("signals = %v", got)
	}
	if ss[0].Count != 3 || ss[0].End == nil || !ss[0].End.Equal(at(0.5)) {
		t.Errorf("coalesced = count %d end %v", ss[0].Count, ss[0].End)
	}
	if in.Counts[TypeRestart] != 5 {
		t.Errorf("counts = %v, want 5 restarts", in.Counts)
	}
}

// An incident keeps MaxSignals; beyond, signals coalesce into the latest of
// their kind, and the counts still add up.
func TestSignalCap(t *testing.T) {
	h := newHarness(t, Options{MaxSignals: 5})
	var sigs []Signal
	sigs = append(sigs, trig("req", TypeRequestSpike, Warning, 0))
	for i := 0; i < 10; i++ {
		s := ctxSig(fmt.Sprint("audit-", i), TypeAuditChange, float64(i)*2)
		s.Object = model.ObjectRef{Kind: "ConfigMap", Namespace: "shop", Name: fmt.Sprint("cm-", i)}
		sigs = append(sigs, s)
	}
	h.step(20, sigs...)
	in := h.only()
	ss := h.signals(in.ID)
	if len(ss) != 5 {
		t.Fatalf("%d signals kept, want 5", len(ss))
	}
	if in.Counts[TypeAuditChange] != 10 || in.Counts[TypeRequestSpike] != 1 {
		t.Errorf("counts = %v", in.Counts)
	}
	// A new kind of signal at the cap is counted, not kept.
	h.step(21, trig("oom", TypeOOMKill, Critical, 21))
	in = h.only()
	if len(h.signals(in.ID)) != 5 || in.Counts[TypeOOMKill] != 1 {
		t.Errorf("at the cap: %d signals, counts %v", len(h.signals(in.ID)), in.Counts)
	}
	// A reload keeps the dropped counts.
	e2 := NewEngine(h.store, NewBoard(0), Options{Now: h.clock.Now, MaxSignals: 5})
	if err := e2.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, _, _ := e2.Incident(in.ID)
	if !reflect.DeepEqual(got.Counts, in.Counts) {
		t.Errorf("reloaded counts %v, want %v", got.Counts, in.Counts)
	}
}

// Namespace-level context joins every incident in the namespace; cluster
// context every incident; neither opens one.
func TestScopedContext(t *testing.T) {
	h := newHarness(t, Options{})
	db := Subject{Kind: "StatefulSet", Namespace: "shop", Name: "db"}
	web := Subject{Kind: "Deployment", Namespace: "web", Name: "front"}
	s1 := trig("a", TypeOOMKill, Critical, 0)
	s2 := trig("b", TypeOOMKill, Critical, 0)
	s2.Subject = db
	s3 := trig("c", TypeOOMKill, Critical, 0)
	s3.Subject = web
	cm := ctxSig("cm", TypeAuditChange, -5)
	cm.Subject = Subject{Kind: KindNamespace, Name: "shop"}
	h.step(-5, cm)
	h.step(0, s1, s2, s3)
	eks := ctxSig("eks", TypeCloudTrailChange, 1)
	eks.Subject = Subject{Kind: KindCluster, Name: "prod"}
	eks.Role, eks.Severity = Trigger, Critical // cluster context cannot trigger
	h.step(1, eks)
	for _, in := range h.all() {
		got := ids(h.signals(in.ID))
		want := []string{"cm", "a", "eks"}
		switch in.Subject {
		case db:
			want = []string{"cm", "b", "eks"}
		case web:
			want = []string{"c", "eks"}
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: signals %v, want %v", in.Subject.Name, got, want)
		}
	}
	if n := len(h.all()); n != 3 {
		t.Errorf("%d incidents", n)
	}
}

// A commit that fails publishes nothing and is retried.
func TestCommitThenPublish(t *testing.T) {
	h := newHarness(t, Options{})
	fs := &failingStore{MemoryStore: h.store, fail: true}
	h.e.store = fs
	h.clock.Set(at(0))
	h.e.Add(trig("req", TypeRequestSpike, Warning, 0))
	h.e.Tick()
	if err := h.e.Flush(context.Background()); err == nil {
		t.Fatal("flush succeeded")
	}
	if ins, _ := h.board.Snapshot(); len(ins) != 0 {
		t.Fatalf("published before the commit: %s", describe(ins))
	}
	fs.fail = false
	if err := h.e.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	ins, v := h.board.Snapshot()
	if len(ins) != 1 || v == 0 {
		t.Fatalf("board after the retry: %s", describe(ins))
	}
	if ss, ok := h.board.Signals(ins[0].ID); !ok || len(ss) != 1 {
		t.Errorf("board signals = %v %v", ss, ok)
	}
}

type failingStore struct {
	*MemoryStore
	fail bool
}

func (f *failingStore) Commit(ctx context.Context, c Commit) error {
	if f.fail {
		return errors.New("lost the lease")
	}
	return f.MemoryStore.Commit(ctx, c)
}

// A condition nobody reports any more ends at its last report.
func TestStaleConditionEnds(t *testing.T) {
	h := newHarness(t, Options{StaleAfter: 10 * time.Minute})
	h.step(0, trig("crash", TypeCrashLoop, Critical, 0))
	h.step(5, trig("crash", TypeCrashLoop, Critical, 0))
	h.step(14)
	if ss := h.signals(h.only().ID); ss[0].End != nil {
		t.Fatalf("ended early: %v", ss[0].End)
	}
	h.step(15)
	if ss := h.signals(h.only().ID); ss[0].End == nil || !ss[0].End.Equal(at(5)) {
		t.Fatalf("end = %v, want minute 5", ss[0].End)
	}
	h.step(31)
	if in := h.only(); in.State != Resolved || !in.End.Equal(at(5)) {
		t.Errorf("%s", describe([]Incident{in}))
	}
}

// A late trigger from before a resolved incident ended joins it; a later
// one opens a new incident.
func TestLateTrigger(t *testing.T) {
	h := newHarness(t, Options{})
	h.step(0, trig("a", TypeOOMKill, Critical, 0))
	h.step(10, trig("b", TypeOOMKill, Critical, 10))
	h.step(26)
	first := h.only()
	if first.State != Resolved || !first.End.Equal(at(10)) {
		t.Fatalf("%s", describe([]Incident{first}))
	}
	h.step(27, trig("late", TypeEviction, Warning, 5)) // happened at minute 5
	if got := h.only(); got.State != Resolved || !got.End.Equal(at(10)) || got.Counts[TypeEviction] != 1 {
		t.Errorf("after the late trigger: %s", describe([]Incident{got}))
	}
	h.step(40, trig("new", TypeOOMKill, Critical, 40))
	if ins := h.all(); len(ins) != 2 || ins[0].Start != at(40) || ins[0].State != Open {
		t.Errorf("a new trigger: %s", describe(ins))
	}
}

func TestQueryMatches(t *testing.T) {
	end := at(30)
	in := Incident{ID: "b", Subject: api, State: Resolved, Severity: Warning, PeakSeverity: Critical, Start: at(0), End: &end,
		Owner: "payments", Tags: map[string]string{TagApp: "api", "app": "api"}, Services: []string{"api", "api-canary"},
		Types: []string{TypeOOMKill, TypeRestart}}
	node := Incident{ID: "n", Subject: Subject{Kind: KindNode, Name: "n1"}, State: Open, PeakSeverity: Warning, Start: at(0)}
	cases := []struct {
		q    Query
		in   *Incident
		want bool
	}{
		{Query{}, &in, true},
		{Query{From: at(31)}, &in, false},
		{Query{From: at(30)}, &in, true},
		{Query{To: at(-1)}, &in, false},
		{Query{Severity: Critical}, &in, true},
		{Query{Severity: Warning}, &in, false},
		{Query{Types: []string{TypeDeploy, TypeRestart}}, &in, true},
		{Query{Types: []string{TypeDeploy}}, &in, false},
		{Query{State: Open}, &in, false},
		{Query{Namespaces: map[string]bool{"shop": true}}, &in, true},
		{Query{Namespaces: map[string]bool{}}, &in, false},
		{Query{Namespaces: map[string]bool{}}, &node, false},
		{Query{Namespaces: map[string]bool{}, ClusterScoped: true}, &node, true},
		{Query{Owner: "payments"}, &in, true},
		{Query{App: "api"}, &in, true},
		{Query{App: "web"}, &in, false},
		{Query{Service: "api-canary"}, &in, true},
		{Query{Tags: map[string]string{"app": "api"}}, &in, true},
		{Query{Tags: map[string]string{"app": "web"}}, &in, false},
		{Query{Before: &Cursor{Start: at(0), ID: "c"}}, &in, true},
		{Query{Before: &Cursor{Start: at(0), ID: "b"}}, &in, false},
		{Query{Before: &Cursor{Start: at(1), ID: "a"}}, &in, true},
		{Query{From: at(100)}, &node, true}, // open: no end
	}
	for i, c := range cases {
		if got := c.q.Matches(c.in); got != c.want {
			t.Errorf("case %d: %+v matches %s = %v", i, c.q, c.in.ID, got)
		}
	}
}
