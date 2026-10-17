package investigate_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/incidents"
	"github.com/ByronGary/kubesentry/internal/investigate"
	"github.com/ByronGary/kubesentry/internal/investigate/investigatetest"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// clock is a settable time source.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type counts struct {
	mu      sync.Mutex
	results map[string]int
	tools   map[string]int
}

func (c *counts) get(k string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.results[k]
}

func (c *counts) tool(k string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.tools[k]
}

type svcOpts struct {
	store                       investigate.Store
	perHour, total, concurrency int
	options                     investigate.Options
	clock                       *clock
	counts                      *counts
}

func newService(t *testing.T, llm investigate.LLM, src investigate.Source, o *svcOpts) *investigate.Service {
	t.Helper()
	if o == nil {
		o = &svcOpts{}
	}
	if o.store == nil {
		o.store = investigate.NewMemoryStore(0)
	}
	if o.clock == nil {
		o.clock = &clock{t: now()}
	}
	if o.counts == nil {
		o.counts = &counts{}
	}
	o.counts.results, o.counts.tools = map[string]int{}, map[string]int{}
	svc, err := investigate.NewService(investigate.Config{LLM: llm, Source: src, Store: o.store, Options: o.options,
		PerHour: o.perHour, PerHourTotal: o.total, Concurrency: o.concurrency, Cluster: "prod", Now: o.clock.Now, Logger: quiet,
		Hooks: investigate.Hooks{
			OnResult: func(_, r string) { o.counts.mu.Lock(); o.counts.results[r]++; o.counts.mu.Unlock() },
			OnToolCall: func(tool, r string) {
				o.counts.mu.Lock()
				o.counts.tools[tool+"/"+r]++
				o.counts.mu.Unlock()
			},
		}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = svc.Shutdown(ctx)
	})
	return svc
}

func waitDone(t *testing.T, svc *investigate.Service, id string, reader investigate.Access) *investigate.Investigation {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		inv, err := svc.Get(context.Background(), "inc-1", id, reader)
		if err != nil {
			t.Fatal(err)
		}
		if inv.Status != investigate.Running {
			return inv
		}
		if time.Now().After(deadline) {
			t.Fatalf("investigation %s still running: %+v", id, inv.Steps)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func startAndWait(t *testing.T, svc *investigate.Service, a investigate.Access) *investigate.Investigation {
	t.Helper()
	inv, cached, err := svc.Start(context.Background(), investigate.StartRequest{IncidentID: "inc-1", RequestedBy: "alice", Access: a})
	if err != nil || cached || inv.Status != investigate.Running {
		t.Fatalf("start: %+v cached %v err %v", inv, cached, err)
	}
	return waitDone(t, svc, inv.ID, a)
}

func happyScript() *investigatetest.ScriptedLLM {
	return investigatetest.New(
		investigatetest.Tools(investigatetest.Call{Name: investigate.ToolGetLogs, Input: map[string]any{"level": "error"}}),
		investigatetest.SubmitFromRefs(func(refs []string) any { return investigatetest.Report(refs...) }),
	)
}

// A run starts at once, runs in the background, and is stored with its
// steps, report, evidence and usage; the JSON matches web/src/types.ts.
func TestServiceRunsAnInvestigation(t *testing.T) {
	llm := happyScript()
	cnt := &counts{}
	svc := newService(t, llm, source(), &svcOpts{counts: cnt})
	inv := startAndWait(t, svc, allAccess)
	if inv.Status != investigate.Completed || inv.Report == nil || inv.Turns != 2 || inv.ToolCalls != 2 ||
		inv.Usage != (investigate.Usage{Input: 200, Output: 100}) || inv.FinishedAt == nil {
		t.Fatalf("investigation %+v", inv)
	}
	if inv.Provider != "demo" || inv.Model != investigate.DefaultModel || inv.Effort != "high" || inv.Access != allAccess {
		t.Errorf("identity %+v", inv)
	}
	if cnt.get(investigate.ResultCompleted) != 1 || cnt.tool("get_logs/ok") != 1 || cnt.tool("submit_report/ok") != 1 {
		t.Errorf("hooks %v %v", cnt.results, cnt.tools)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(mustJSON(t, inv)), &doc); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"id", "incidentId", "status", "requestedBy", "createdAt", "finishedAt", "provider", "model", "effort",
		"outcome", "confidence", "access", "steps", "report", "evidence", "usage", "turns", "toolCalls"} {
		if _, ok := doc[k]; !ok {
			t.Errorf("JSON lacks %q", k)
		}
	}
	for _, k := range []string{"namespace", "inputSha256", "InputSHA256", "updatedAt", "promptVersion"} {
		if _, ok := doc[k]; ok {
			t.Errorf("JSON carries %q", k)
		}
	}
	if doc["outcome"] != "likely_cause" || doc["confidence"] != "medium" {
		t.Errorf("outcome %v confidence %v", doc["outcome"], doc["confidence"])
	}
	usage := doc["usage"].(map[string]any)
	for _, k := range []string{"input", "output", "cacheRead", "cacheWrite"} {
		if _, ok := usage[k]; !ok {
			t.Errorf("usage lacks %s", k)
		}
	}
	step := doc["steps"].([]any)[0].(map[string]any)
	if step["kind"] != "turn" || step["at"] == nil || step["text"] == nil {
		t.Errorf("step %v", step)
	}
	items, hidden, err := svc.List(context.Background(), "inc-1", allAccess)
	if err != nil || hidden != 0 || len(items) != 1 || items[0].Outcome != "likely_cause" || items[0].Confidence != "medium" {
		t.Errorf("list %+v %d %v", items, hidden, err)
	}
	if _, err := svc.Get(context.Background(), "other-incident", inv.ID, allAccess); !errors.Is(err, investigate.ErrNotFound) {
		t.Errorf("another incident's path: %v", err)
	}
	if _, _, err := svc.Start(context.Background(), investigate.StartRequest{IncidentID: "nope", RequestedBy: "alice"}); !errors.Is(err, investigate.ErrIncidentNotFound) {
		t.Errorf("unknown incident: %v", err)
	}
}

func seedRun(t *testing.T, st investigate.Store, id, who string, created time.Time, status investigate.Status, hash string) *investigate.Investigation {
	t.Helper()
	inv := &investigate.Investigation{ID: id, IncidentID: "inc-1", Status: status, RequestedBy: who, CreatedAt: created, UpdatedAt: created,
		Provider: "demo", Model: investigate.DefaultModel, Effort: "high", InputSHA256: hash, Access: allAccess, Steps: []investigate.Step{}}
	if status == investigate.Completed {
		inv.Report = &investigate.Report{Summary: "s", Status: investigate.Inconclusive, RootCause: investigate.RootCause{Confidence: "low"}}
		inv.FinishedAt = &created
	}
	if err := st.Create(context.Background(), inv); err != nil {
		t.Fatal(err)
	}
	return inv
}

// Both hourly quotas count stored runs (not cache hits) and say when to
// retry.
func TestServiceQuotas(t *testing.T) {
	st := investigate.NewMemoryStore(0)
	clk := &clock{t: now()}
	cnt := &counts{}
	svc := newService(t, investigatetest.New(), source(), &svcOpts{store: st, perHour: 2, total: 3, clock: clk, counts: cnt})
	seedRun(t, st, "old", "alice", now().Add(-2*time.Hour), investigate.Failed, "h0")
	seedRun(t, st, "r1", "alice", now().Add(-50*time.Minute), investigate.Failed, "h1")
	seedRun(t, st, "r2", "alice", now().Add(-10*time.Minute), investigate.Failed, "h2")
	seedRun(t, st, "c1", "alice", now().Add(-5*time.Minute), investigate.Completed, "h3")
	// A cache copy does not count.
	cc := &investigate.Investigation{ID: "c2", IncidentID: "inc-1", Status: investigate.Completed, RequestedBy: "alice",
		CreatedAt: now().Add(-4 * time.Minute), CachedFrom: "c1", InputSHA256: "h3", Access: allAccess}
	if err := st.Create(context.Background(), cc); err != nil {
		t.Fatal(err)
	}
	start := func(who string) error {
		_, _, err := svc.Start(context.Background(), investigate.StartRequest{IncidentID: "inc-1", RequestedBy: who, Access: allAccess, Fresh: true})
		return err
	}
	var q *investigate.QuotaError
	if err := start("alice"); !errors.As(err, &q) || q.Scope != "user" || q.Limit != 2 || q.RetryAfter != 10*time.Minute {
		t.Fatalf("alice: %v", err)
	}
	if cnt.get(investigate.ResultQuota) != 1 {
		t.Error("quota not counted")
	}
	// Total: alice's three runs in the hour (not the cache copy) reach the
	// total of three, so bob is turned away too.
	if err := start("bob"); !errors.As(err, &q) || q.Scope != "total" || q.RetryAfter != 10*time.Minute {
		t.Fatalf("bob: %v", err)
	}
	clk.Add(11 * time.Minute) // r1 leaves the hour
	if err := start("bob"); err != nil {
		t.Fatalf("bob after an hour: %v", err)
	}
}

// One running run per replica slot; one running run per incident.
func TestServiceBusyAndConflict(t *testing.T) {
	release := make(chan struct{})
	llm := investigatetest.New(investigatetest.Gate(release, investigatetest.Submit(investigatetest.Report())))
	src := source()
	cnt := &counts{}
	svc := newService(t, llm, src, &svcOpts{concurrency: 1, counts: cnt})
	first, _, err := svc.Start(context.Background(), investigate.StartRequest{IncidentID: "inc-1", RequestedBy: "alice", Access: allAccess})
	if err != nil {
		t.Fatal(err)
	}
	var conflict *investigate.ConflictError
	if _, _, err := svc.Start(context.Background(), investigate.StartRequest{IncidentID: "inc-1", RequestedBy: "bob", Access: allAccess}); !errors.As(err, &conflict) || conflict.RunningID != first.ID {
		t.Errorf("second run on the incident: %v", err)
	}
	// Another incident: this replica has no slot left.
	src2 := source()
	src2.in.ID = "inc-2"
	multi := &multiSource{byID: map[string]*fakeSource{"inc-1": src, "inc-2": src2}}
	svcM := newService(t, investigatetest.New(investigatetest.Hang()), multi, &svcOpts{concurrency: 1, counts: cnt})
	if _, _, err := svcM.Start(context.Background(), investigate.StartRequest{IncidentID: "inc-1", RequestedBy: "alice", Access: allAccess}); err != nil {
		t.Fatal(err)
	}
	var busy *investigate.BusyError
	if _, _, err := svcM.Start(context.Background(), investigate.StartRequest{IncidentID: "inc-2", RequestedBy: "alice", Access: allAccess}); !errors.As(err, &busy) || busy.RetryAfter != 30*time.Second {
		t.Errorf("a second run on a full replica: %v", err)
	}
	if cnt.get(investigate.ResultBusy) != 1 {
		t.Error("busy not counted")
	}
	close(release)
	if inv := waitDone(t, svc, first.ID, allAccess); inv.Status != investigate.Completed {
		t.Errorf("first run: %s %s", inv.Status, inv.Error)
	}
}

// multiSource serves several incidents.
type multiSource struct{ byID map[string]*fakeSource }

func (m *multiSource) src(id string) *fakeSource {
	if s, ok := m.byID[id]; ok {
		return s
	}
	return m.byID["inc-1"]
}

func (m *multiSource) Get(ctx context.Context, id string) (incidents.Incident, []incidents.Signal, bool, error) {
	return m.src(id).Get(ctx, id)
}
func (m *multiSource) Bundle(ctx context.Context, id string, req incidents.BundleRequest) (*incidents.Bundle, error) {
	return m.src(id).Bundle(ctx, id, req)
}
func (m *multiSource) Logs(ctx context.Context, id string, req incidents.LogRequest) (incidents.LogResponse, error) {
	return m.src(id).Logs(ctx, id, req)
}
func (m *multiSource) Series(ctx context.Context, id string, from, to time.Time) ([]incidents.Series, error) {
	return m.src(id).Series(ctx, id, from, to)
}
func (m *multiSource) Events(ctx context.Context, q incidents.EventQuery) ([]incidents.StoredEvent, error) {
	return m.byID["inc-1"].Events(ctx, q)
}
func (m *multiSource) AuditEvents(ctx context.Context, in *incidents.Incident, limit int) ([]audit.Event, error) {
	return m.src(in.ID).AuditEvents(ctx, in, limit)
}
func (m *multiSource) WorkloadState(ctx context.Context, in *incidents.Incident) (*investigate.WorkloadState, error) {
	return m.src(in.ID).WorkloadState(ctx, in)
}

// A completed run with the same input answers again: no model call, no
// quota; fresh asks the model anyway.
func TestServiceCache(t *testing.T) {
	llm := happyScript()
	st := investigate.NewMemoryStore(0)
	cnt := &counts{}
	svc := newService(t, llm, source(), &svcOpts{store: st, perHour: 1, counts: cnt})
	orig := startAndWait(t, svc, allAccess)
	if orig.Status != investigate.Completed {
		t.Fatalf("first run %s", orig.Error)
	}
	calls := llm.Calls()
	// alice's quota (1) is spent, but a cache hit is free.
	inv, cached, err := svc.Start(context.Background(), investigate.StartRequest{IncidentID: "inc-1", RequestedBy: "alice", Access: allAccess})
	if err != nil || !cached || inv.CachedFrom != orig.ID || inv.Status != investigate.Completed || inv.ID == orig.ID ||
		inv.Report == nil || inv.Report.Summary != orig.Report.Summary || inv.Usage != (investigate.Usage{}) {
		t.Fatalf("cache hit: %+v %v %v", inv, cached, err)
	}
	if llm.Calls() != calls || cnt.get(investigate.ResultCached) != 1 {
		t.Errorf("the cache hit called the model (%d → %d) or was not counted", calls, llm.Calls())
	}
	if n, _, _ := st.CountSince(context.Background(), "alice", now().Add(-time.Hour)); n != 1 {
		t.Errorf("the cache hit counted against the quota: %d", n)
	}
	// Another access set is another input.
	logsOnly := investigate.Access{Logs: true}
	bobs, cached, err := svc.Start(context.Background(), investigate.StartRequest{IncidentID: "inc-1", RequestedBy: "bob", Access: logsOnly})
	if cached || err != nil {
		t.Fatalf("another access set hit the cache: %v %v", cached, err)
	}
	waitDone(t, svc, bobs.ID, logsOnly)
	if got := mustJSON(t, bobs.Omitted); got != `{"audit":"forbidden","cloudtrail":"forbidden","nodes":"forbidden"}` {
		t.Errorf("omitted %s", got)
	}
	// Fresh skips the cache (and so meets alice's quota).
	var q *investigate.QuotaError
	if _, _, err := svc.Start(context.Background(), investigate.StartRequest{IncidentID: "inc-1", RequestedBy: "alice", Access: allAccess, Fresh: true}); !errors.As(err, &q) {
		t.Errorf("fresh: %v", err)
	}
}

// A running row whose heartbeat stopped reads as interrupted, and does not
// block a new run.
func TestServiceStaleHeartbeat(t *testing.T) {
	st := investigate.NewMemoryStore(0)
	clk := &clock{t: now()}
	svc := newService(t, happyScript(), source(), &svcOpts{store: st, clock: clk})
	seedRun(t, st, "ghost", "carol", now().Add(-3*time.Minute), investigate.Running, "hx")
	inv, err := svc.Get(context.Background(), "inc-1", "ghost", allAccess)
	if err != nil || inv.Status != investigate.Failed || inv.Error != "interrupted" || inv.FinishedAt == nil {
		t.Fatalf("stale run reads as %+v %v", inv, err)
	}
	items, _, _ := svc.List(context.Background(), "inc-1", allAccess)
	if len(items) != 1 || items[0].Status != investigate.Failed {
		t.Errorf("list %+v", items)
	}
	if _, err := svc.Cancel(context.Background(), "inc-1", "ghost", "carol"); !errors.Is(err, investigate.ErrNotRunning) {
		t.Errorf("cancel a stale run: %v", err)
	}
	got := startAndWait(t, svc, allAccess)
	if got.Status != investigate.Completed {
		t.Errorf("new run %s", got.Error)
	}
	if g, _ := st.Get(context.Background(), "ghost"); g.Status != investigate.Failed || g.Error != "interrupted" {
		t.Errorf("the stale row was not marked: %+v", g)
	}
}

// Shutdown marks this replica's running jobs failed, interrupted, with the
// steps so far.
func TestServiceShutdown(t *testing.T) {
	st := investigate.NewMemoryStore(0)
	llm := investigatetest.New(
		investigatetest.Tools(investigatetest.Call{Name: investigate.ToolGetWorkloadState}),
		investigatetest.Hang(),
	)
	svc, err := investigate.NewService(investigate.Config{LLM: llm, Source: source(), Store: st, Now: now, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	inv, _, err := svc.Start(context.Background(), investigate.StartRequest{IncidentID: "inc-1", RequestedBy: "alice", Access: allAccess})
	if err != nil {
		t.Fatal(err)
	}
	for llm.Calls() < 2 {
		time.Sleep(time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := svc.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	got, _ := st.Get(context.Background(), inv.ID)
	if got.Status != investigate.Failed || got.Error != "interrupted" || len(got.Steps) < 2 {
		t.Errorf("after shutdown: %+v", got)
	}
	var busy *investigate.BusyError
	if _, _, err := svc.Start(context.Background(), investigate.StartRequest{IncidentID: "inc-1", RequestedBy: "alice", Access: allAccess}); !errors.As(err, &busy) {
		t.Errorf("a start after shutdown: %v", err)
	}
}

// Only the starter cancels; a run on this replica stops at once with its
// steps; one on another replica is marked and stops at its next write.
func TestServiceCancel(t *testing.T) {
	st := investigate.NewMemoryStore(0)
	cnt := &counts{}
	llm := investigatetest.New(investigatetest.Hang())
	svc := newService(t, llm, source(), &svcOpts{store: st, counts: cnt})
	inv, _, err := svc.Start(context.Background(), investigate.StartRequest{IncidentID: "inc-1", RequestedBy: "alice", Access: allAccess})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Cancel(context.Background(), "inc-1", inv.ID, "bob"); !errors.Is(err, investigate.ErrForbidden) {
		t.Errorf("bob cancels: %v", err)
	}
	if _, err := svc.Cancel(context.Background(), "inc-1", "nope", "alice"); !errors.Is(err, investigate.ErrNotFound) {
		t.Errorf("unknown run: %v", err)
	}
	got, err := svc.Cancel(context.Background(), "inc-1", inv.ID, "alice")
	if err != nil || got.Status != investigate.Cancelled || got.FinishedAt == nil {
		t.Fatalf("alice cancels: %+v %v", got, err)
	}
	if !strings.Contains(mustJSON(t, got.Steps), "cancelled by the starter") || cnt.get(investigate.ResultCancelled) != 1 {
		t.Errorf("steps %+v, results %v", got.Steps, cnt.results)
	}
	if _, err := svc.Cancel(context.Background(), "inc-1", inv.ID, "alice"); !errors.Is(err, investigate.ErrNotRunning) {
		t.Errorf("cancel twice: %v", err)
	}

	// A run another replica holds: the row is marked; that replica's job,
	// at its next write, finds it finished and stops.
	other := seedRun(t, st, "remote", "alice", now(), investigate.Running, "")
	got, err = svc.Cancel(context.Background(), "inc-1", other.ID, "alice")
	if err != nil || got.Status != investigate.Cancelled {
		t.Fatalf("remote cancel: %+v %v", got, err)
	}
	if err := st.Update(context.Background(), other); !errors.Is(err, investigate.ErrNotRunning) {
		t.Errorf("the remote job's next write: %v", err)
	}
}

// The job stops when its row was finished elsewhere (marked interrupted,
// or cancelled from another replica), and leaves the row as it found it.
func TestServiceStopsWhenFinishedElsewhere(t *testing.T) {
	st := investigate.NewMemoryStore(0)
	proceed := make(chan struct{})
	tools := investigatetest.Tools(investigatetest.Call{Name: investigate.ToolGetWorkloadState})
	llm := investigatetest.New(tools, tools, investigatetest.Gate(proceed, tools))
	llm.After = tools
	svc := newService(t, llm, source(), &svcOpts{store: st, options: investigate.Options{MaxTurns: 100, MaxToolCalls: 100}})
	inv, _, err := svc.Start(context.Background(), investigate.StartRequest{IncidentID: "inc-1", RequestedBy: "alice", Access: allAccess})
	if err != nil {
		t.Fatal(err)
	}
	for llm.Calls() < 3 {
		time.Sleep(time.Millisecond)
	}
	c, _ := st.Get(context.Background(), inv.ID)
	c.Status, c.Error = investigate.Failed, "interrupted"
	if err := st.Update(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	close(proceed)
	time.Sleep(200 * time.Millisecond)
	if n := llm.Calls(); n > 4 {
		t.Errorf("the job went on for %d turns", n)
	}
	if got, _ := st.Get(context.Background(), inv.ID); got.Status != investigate.Failed || got.Error != "interrupted" {
		t.Errorf("the row was overwritten: %+v", got)
	}
	// The incident is free again.
	if _, _, err := svc.Start(context.Background(), investigate.StartRequest{IncidentID: "inc-1", RequestedBy: "alice", Access: allAccess, Fresh: true}); err != nil {
		t.Errorf("a new run: %v", err)
	}
}

// A reader must hold every capability the run's access recorded as true.
func TestServiceReadAuthorization(t *testing.T) {
	st := investigate.NewMemoryStore(0)
	svc := newService(t, happyScript(), source(), &svcOpts{store: st})
	full := startAndWait(t, svc, allAccess)
	n2 := &investigate.Investigation{ID: "logs-only", IncidentID: "inc-1", Status: investigate.Completed, RequestedBy: "bob",
		CreatedAt: now().Add(-2 * time.Minute), Access: investigate.Access{Logs: true}, Steps: []investigate.Step{}}
	if err := st.Create(context.Background(), n2); err != nil {
		t.Fatal(err)
	}
	reader := investigate.Access{Logs: true, Nodes: true}
	if _, err := svc.Get(context.Background(), "inc-1", full.ID, reader); !errors.Is(err, investigate.ErrNotFound) {
		t.Errorf("a reader without audit and CloudTrail reads a full run: %v", err)
	}
	if got, err := svc.Get(context.Background(), "inc-1", "logs-only", reader); err != nil || got.ID != "logs-only" {
		t.Errorf("logs-only run: %v", err)
	}
	items, hidden, err := svc.List(context.Background(), "inc-1", reader)
	if err != nil || len(items) != 1 || items[0].ID != "logs-only" || hidden != 1 {
		t.Errorf("list: %+v hidden %d %v", items, hidden, err)
	}
	for _, c := range []struct {
		run, reader investigate.Access
		want        bool
	}{
		{investigate.Access{}, investigate.Access{}, true},
		{allAccess, allAccess, true},
		{investigate.Access{Audit: true}, investigate.Access{Logs: true}, false},
		{investigate.Access{Logs: true}, allAccess, true},
		{investigate.Access{Nodes: true}, investigate.Access{CloudTrail: true}, false},
	} {
		if got := investigate.CanRead(c.run, c.reader); got != c.want {
			t.Errorf("CanRead(%+v, %+v) = %v", c.run, c.reader, got)
		}
	}
}

func TestMemoryStore(t *testing.T) {
	st := investigate.NewMemoryStore(3)
	ctx := context.Background()
	seedRun(t, st, "a", "u", now().Add(-4*time.Minute), investigate.Completed, "h")
	seedRun(t, st, "b", "u", now().Add(-3*time.Minute), investigate.Running, "h")
	var conflict *investigate.ConflictError
	if err := st.Create(ctx, &investigate.Investigation{ID: "b2", IncidentID: "inc-1", Status: investigate.Running}); !errors.As(err, &conflict) || conflict.RunningID != "b" {
		t.Errorf("second running run: %v", err)
	}
	seedRun(t, st, "c", "u", now().Add(-2*time.Minute), investigate.Failed, "h")
	seedRun(t, st, "d", "u", now().Add(-1*time.Minute), investigate.Completed, "h")
	if _, err := st.Get(ctx, "a"); !errors.Is(err, investigate.ErrNotFound) {
		t.Error("the oldest finished run was kept past the cap")
	}
	list, _ := st.List(ctx, "inc-1", 0)
	if len(list) != 3 || list[0].ID != "d" || list[2].ID != "b" {
		t.Errorf("list %v", list)
	}
	if c, err := st.Cached(ctx, "h", now().Add(-time.Hour)); err != nil || c.ID != "d" {
		t.Errorf("cached %+v %v", c, err)
	}
	if r, err := st.Running(ctx, "inc-1"); err != nil || r.ID != "b" {
		t.Errorf("running %v", err)
	}
	// Updates only while running; a copy out never aliases the store.
	r, _ := st.Get(ctx, "b")
	r.Steps = append(r.Steps, investigate.Step{Text: "x"})
	if g, _ := st.Get(ctx, "b"); len(g.Steps) != 0 {
		t.Error("the store aliases its rows")
	}
	r.Status = investigate.Completed
	if err := st.Update(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := st.Update(ctx, r); !errors.Is(err, investigate.ErrNotRunning) {
		t.Errorf("update a finished run: %v", err)
	}
	if err := st.Update(ctx, &investigate.Investigation{ID: "zz"}); !errors.Is(err, investigate.ErrNotFound) {
		t.Errorf("update a missing run: %v", err)
	}
}
