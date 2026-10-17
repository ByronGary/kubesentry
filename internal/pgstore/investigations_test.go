package pgstore

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/investigate"
)

var invBase = time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC)

// addIncidents stores minimal incident rows the investigations reference.
func addIncidents(tb testing.TB, s *Store, ids ...string) {
	tb.Helper()
	for _, id := range ids {
		_, err := s.pool.Exec(context.Background(), `INSERT INTO incidents (id, subject_kind, namespace, subject_name, title, severity,
  peak_severity, state, started_at, last_signal_at) VALUES ($1, 'Deployment', 'team-a', $1, 'checkout errors', 'warning', 'warning', 'open', $2, $2)`,
			id, invBase)
		if err != nil {
			tb.Fatal(err)
		}
	}
}

func randomReport(rng *rand.Rand) *investigate.Report {
	r := &investigate.Report{Summary: "The deploy at 09:02 raised the error rate.", Status: investigate.LikelyCause,
		RootCause: investigate.RootCause{Statement: "A bad image.", Confidence: "medium", Evidence: []string{"signal:deploy:1"}},
		Impact:    "5xx for 4 minutes", OpenQuestions: []string{}, DataGaps: []string{"logs: forbidden"},
		Timeline: []investigate.TimelineEntry{{Time: "2026-10-16T09:02:00Z", Event: "deploy", Evidence: []string{"signal:deploy:1"}}},
	}
	if rng.Intn(2) == 0 {
		r.ContributingFactors = []investigate.Factor{{Statement: "no canary", Evidence: []string{}}}
		r.SuggestedChecks = []investigate.Check{{Description: "rollout history", Command: "kubectl rollout history deploy/checkout -n team-a"}}
		r.RemediationIdeas = []investigate.Remediation{{Description: "roll back", Risk: "low"}}
		r.Unverified = []string{"signal:invented"}
	}
	return r
}

// randomRun is a run as the service writes them: running, finished or a
// cache copy, at a time with nanoseconds (both stores keep microseconds).
func randomRun(rng *rand.Rand, id, incident string, at time.Time) *investigate.Investigation {
	who := []string{"alice", "bob", "carol"}[rng.Intn(3)]
	inv := &investigate.Investigation{ID: id, IncidentID: incident, Namespace: "team-a", Status: investigate.Running, RequestedBy: who,
		CreatedAt: at, UpdatedAt: at, Provider: "anthropic", Model: "claude-opus-5-5", Effort: "high", PromptVersion: "investigate/1",
		InputSHA256: fmt.Sprintf("hash-%d", rng.Intn(3)),
		Access:      investigate.Access{Logs: rng.Intn(2) == 0, Audit: rng.Intn(2) == 0, CloudTrail: rng.Intn(3) == 0, Nodes: rng.Intn(2) == 0},
		Steps:       []investigate.Step{}}
	if rng.Intn(2) == 0 {
		inv.Omitted = map[string]string{"logs": "forbidden", "nodes": "forbidden"}
	}
	if rng.Intn(2) == 0 {
		inv.Steps = []investigate.Step{{At: at.Add(time.Duration(rng.Intn(1e9))), Kind: investigate.StepTurn, Text: "turn 1: 1 tool call (500 tokens)"},
			{At: at.Add(time.Second), Kind: investigate.StepTool, Tool: investigate.ToolGetLogs, Text: "get_logs: 12 lines", Result: investigate.ResultOK}}
	}
	switch rng.Intn(4) {
	case 0: // running
	case 1:
		finish(rng, inv, investigate.Completed, at)
	case 2:
		finish(rng, inv, []investigate.Status{investigate.Refused, investigate.Failed, investigate.Cancelled}[rng.Intn(3)], at)
	case 3:
		finish(rng, inv, investigate.Completed, at)
		inv.CachedFrom = "orig-" + id
		inv.Usage = investigate.Usage{}
	}
	return inv
}

func finish(rng *rand.Rand, inv *investigate.Investigation, st investigate.Status, at time.Time) {
	end := at.Add(time.Duration(rng.Intn(600e9)))
	inv.Status, inv.UpdatedAt, inv.FinishedAt = st, end, &end
	inv.Usage = investigate.Usage{Input: rng.Int63n(1e5), Output: rng.Int63n(1e4), CacheRead: rng.Int63n(1e6), CacheWrite: rng.Int63n(1e5)}
	inv.Turns, inv.ToolCalls = rng.Intn(16), rng.Intn(24)
	switch st {
	case investigate.Completed:
		inv.Report = randomReport(rng)
		if rng.Intn(2) == 0 {
			inv.Evidence = []investigate.Evidence{{Ref: "signal:deploy:1", Kind: "signal", Time: at.Add(123456789), Object: "Deployment/checkout",
				Snippet: "image checkout:1.4.2"}, {Ref: "logtpl:1", Kind: "logtpl"}}
		}
	case investigate.Refused:
		inv.Refusal = &investigate.Refusal{Category: "cyber", Explanation: "declined"}
	case investigate.Failed:
		inv.Error = []string{"timeout", "interrupted", "HTTP 529 overloaded"}[rng.Intn(3)]
	}
}

// TestPGInvestigationsMatchMemory is the investigation store's parity
// test: the same random creates and updates against
// investigate.MemoryStore and the Postgres store give the same errors
// (conflicts name the same running run) and the same reads.
func TestPGInvestigationsMatchMemory(t *testing.T) {
	testDSN(t)
	ctx := context.Background()
	incs := []string{"inc-a", "inc-b", "inc-c"}
	for seed := int64(1); seed <= 3; seed++ {
		t.Run(fmt.Sprint("seed", seed), func(t *testing.T) {
			rng := rand.New(rand.NewSource(seed))
			s := openTest(t, Options{})
			addIncidents(t, s, incs...)
			pg, mem := s.Investigations(), investigate.NewMemoryStore(0)
			var ids []string
			at := invBase
			conflicts, notRunning := 0, 0
			for step := 0; step < 200; step++ {
				at = at.Add(time.Duration(rng.Intn(3000)) * time.Microsecond / 2) // ties at microsecond precision
				if len(ids) == 0 || rng.Intn(3) > 0 {
					id := fmt.Sprintf("2026%06x", rng.Intn(1<<24))
					inv := randomRun(rng, id, incs[rng.Intn(len(incs))], at)
					me, pe := mem.Create(ctx, inv), pg.Create(ctx, inv)
					if !sameErr(me, pe) {
						t.Fatalf("step %d create %s (%s): memory %v, postgres %v", step, id, inv.Status, me, pe)
					}
					var ce *investigate.ConflictError
					if errors.As(me, &ce) {
						conflicts++
					}
					if me == nil {
						ids = append(ids, id)
					}
				} else {
					id := ids[rng.Intn(len(ids))]
					if rng.Intn(10) == 0 {
						id = "missing"
					}
					cur, err := mem.Get(ctx, id)
					if err != nil {
						cur = &investigate.Investigation{ID: id}
					}
					upd := cur.Clone()
					upd.UpdatedAt = at
					switch rng.Intn(3) {
					case 0: // progress
						upd.Steps = append(upd.Steps, investigate.Step{At: at, Kind: investigate.StepNote, Text: "budget spent: turns"})
						upd.Turns++
						upd.Usage.Add(investigate.Usage{Input: 10, Output: 5})
					default:
						finish(rng, upd, []investigate.Status{investigate.Completed, investigate.Failed, investigate.Cancelled, investigate.Refused}[rng.Intn(4)], at)
					}
					// Immutable fields are not written.
					upd.RequestedBy, upd.Model = "mallory", "other-model"
					me, pe := mem.Update(ctx, upd), pg.Update(ctx, upd)
					if !sameErr(me, pe) {
						t.Fatalf("step %d update %s: memory %v, postgres %v", step, id, me, pe)
					}
					if errors.Is(me, investigate.ErrNotRunning) {
						notRunning++
					}
				}
				if step%5 == 4 {
					compareInvestigations(t, mem, pg, ids, incs, rng, at)
				}
			}
			compareInvestigations(t, mem, pg, ids, incs, rng, at)
			if conflicts == 0 || notRunning == 0 {
				t.Errorf("%d conflicts, %d updates of finished runs: the test checks too little", conflicts, notRunning)
			}
		})
	}
}

// sameErr: both nil, both the same sentinel, both conflicts naming the same
// run, or both some other error.
func sameErr(a, b error) bool {
	var ca, cb *investigate.ConflictError
	switch {
	case a == nil || b == nil:
		return a == nil && b == nil
	case errors.As(a, &ca) || errors.As(b, &cb):
		return errors.As(a, &ca) && errors.As(b, &cb) && ca.RunningID == cb.RunningID
	}
	for _, s := range []error{investigate.ErrNotFound, investigate.ErrNotRunning, investigate.ErrIncidentNotFound} {
		if errors.Is(a, s) || errors.Is(b, s) {
			return errors.Is(a, s) && errors.Is(b, s)
		}
	}
	return true
}

func compareInvestigations(t *testing.T, mem, pg investigate.Store, ids, incs []string, rng *rand.Rand, at time.Time) {
	t.Helper()
	ctx := context.Background()
	sorted := append([]string{"missing"}, ids...)
	sort.Strings(sorted)
	for _, id := range sorted {
		w, we := mem.Get(ctx, id)
		g, ge := pg.Get(ctx, id)
		if !sameErr(we, ge) || !reflect.DeepEqual(g, w) {
			t.Fatalf("get %s:\npostgres %+v (%v)\nmemory   %+v (%v)", id, g, ge, w, we)
		}
	}
	for _, inc := range append(incs, "inc-none") {
		for _, limit := range []int{0, 3} {
			w, _ := mem.List(ctx, inc, limit)
			g, err := pg.List(ctx, inc, limit)
			if err != nil || !reflect.DeepEqual(g, w) {
				t.Fatalf("list %s limit %d: %v\npostgres %d %v\nmemory   %d %v", inc, limit, err, len(g), runIDs(g), len(w), runIDs(w))
			}
		}
		w, we := mem.Running(ctx, inc)
		g, ge := pg.Running(ctx, inc)
		if !sameErr(we, ge) || !reflect.DeepEqual(g, w) {
			t.Fatalf("running %s: postgres %+v (%v), memory %+v (%v)", inc, g, ge, w, we)
		}
	}
	for _, who := range []string{"", "alice", "bob", "nobody"} {
		since := invBase.Add(time.Duration(rng.Int63n(int64(at.Sub(invBase) + 1))))
		wn, wo, _ := mem.CountSince(ctx, who, since)
		gn, gold, err := pg.CountSince(ctx, who, since)
		if err != nil || wn != gn || !wo.Equal(gold) || wo.Location() != gold.Location() {
			t.Fatalf("count %q since %s: postgres %d %s (%v), memory %d %s", who, since, gn, gold, err, wn, wo)
		}
	}
	for h := 0; h < 4; h++ {
		hash := fmt.Sprintf("hash-%d", h)
		since := invBase.Add(time.Duration(rng.Int63n(int64(at.Sub(invBase) + 1))))
		w, we := mem.Cached(ctx, hash, since)
		g, ge := pg.Cached(ctx, hash, since)
		if !sameErr(we, ge) || !reflect.DeepEqual(g, w) {
			t.Fatalf("cached %s since %s: postgres %+v (%v), memory %+v (%v)", hash, since, g, ge, w, we)
		}
	}
}

func runIDs(l []*investigate.Investigation) []string {
	out := make([]string, len(l))
	for i, r := range l {
		out[i] = r.ID + "@" + r.CreatedAt.Format(time.RFC3339Nano)
	}
	return out
}

// A run needs its incident, and goes with it; a second running run of an
// incident is a conflict naming the first, on any replica.
func TestPGInvestigationsIncidentAndReplicas(t *testing.T) {
	testDSN(t)
	ctx := context.Background()
	s := openTest(t, Options{})
	addIncidents(t, s, "inc-1")
	a := s.Investigations()
	replica, err := Open(ctx, testDSN(t), s.o) // a second replica on the same schema
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { replica.Close(context.Background()) })
	other := replica.Investigations()
	rng := rand.New(rand.NewSource(7))
	run := randomRun(rng, "run-1", "inc-1", invBase)
	run.Status, run.FinishedAt, run.CachedFrom = investigate.Running, nil, ""
	if err := a.Create(ctx, run); err != nil {
		t.Fatal(err)
	}
	second := randomRun(rng, "run-2", "inc-1", invBase.Add(time.Second))
	second.Status, second.FinishedAt, second.CachedFrom = investigate.Running, nil, ""
	var ce *investigate.ConflictError
	if err := other.Create(ctx, second); !errors.As(err, &ce) || ce.RunningID != "run-1" {
		t.Fatalf("second running run: %v", err)
	}
	// The other replica cancels it; the job's next progress write fails.
	got, err := other.Get(ctx, "run-1")
	if err != nil {
		t.Fatal(err)
	}
	now := invBase.Add(time.Minute)
	got.Status, got.UpdatedAt, got.FinishedAt = investigate.Cancelled, now, &now
	if err := other.Update(ctx, got); err != nil {
		t.Fatal(err)
	}
	run.Turns = 3
	if err := a.Update(ctx, run); !errors.Is(err, investigate.ErrNotRunning) {
		t.Errorf("progress after a cancel: %v", err)
	}
	if err := other.Create(ctx, second); err != nil {
		t.Errorf("a new run after the cancel: %v", err)
	}
	orphan := randomRun(rng, "run-3", "inc-gone", invBase)
	if err := a.Create(ctx, orphan); !errors.Is(err, investigate.ErrIncidentNotFound) {
		t.Errorf("a run of an unknown incident: %v", err)
	}
	if _, err := s.pool.Exec(ctx, `DELETE FROM incidents WHERE id = 'inc-1'`); err != nil {
		t.Fatal(err)
	}
	if l, err := a.List(ctx, "inc-1", 0); err != nil || len(l) != 0 {
		t.Errorf("runs outlived their incident: %d %v", len(l), err)
	}
}
