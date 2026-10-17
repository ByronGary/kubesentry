package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/auth"
	"github.com/ByronGary/kubesentry/internal/incidents"
	"github.com/ByronGary/kubesentry/internal/investigate"
	"github.com/ByronGary/kubesentry/internal/investigate/investigatetest"
)

// invSource is the investigator's source over the incidents runner, as
// cmd/server builds it (with an empty workload state here).
type invSource struct{ *incidents.Runner }

func (invSource) WorkloadState(context.Context, *incidents.Incident) (*investigate.WorkloadState, error) {
	return &investigate.WorkloadState{At: now}, nil
}

// askLog records every authorization question the reviewer is asked.
type askLog struct {
	mu    sync.Mutex
	g     grantReviewer
	asked []string
}

func (a *askLog) Review(ctx context.Context, user string, groups []string, verb, group, resource, sub, ns string) (bool, error) {
	a.mu.Lock()
	r := resource
	if sub != "" {
		r += "/" + sub
	}
	a.asked = append(a.asked, user+"|"+verb+"|"+group+"|"+r+"|"+ns)
	a.mu.Unlock()
	return a.g.Review(ctx, user, groups, verb, group, resource, sub, ns)
}

func (a *askLog) reset() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.asked = nil
}

func (a *askLog) list() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.asked...)
}

// submitting is a script that reads the logs, then submits a report citing
// what it saw; once used up, it submits again.
func submitting() *investigatetest.ScriptedLLM {
	submit := investigatetest.SubmitFromRefs(func(refs []string) any { return investigatetest.Report(refs...) })
	llm := investigatetest.New(
		investigatetest.Tools(investigatetest.Call{Name: investigate.ToolGetLogs, Input: map[string]any{"level": "error"}}),
		submit)
	llm.After = submit
	return llm
}

type invOpts struct {
	perHour, concurrency int
}

// investigatorServer is the tenant server with its incidents and a real
// investigator over llm, with the tenant grants plus extra; the reviewer
// records what it is asked.
func investigatorServer(t *testing.T, llm investigate.LLM, o invOpts, extra ...string) (*Server, *askLog, *fakeLogs) {
	t.Helper()
	s, logs := incidentsServer(t)
	g := tenantGrants()
	for _, k := range extra {
		g[k] = true
	}
	asks := &askLog{g: g}
	s.Authorizer = &auth.SARAuthorizer{Reviewer: asks, Candidates: s.Authorizer.(*auth.SARAuthorizer).Candidates}
	svc, err := investigate.NewService(investigate.Config{LLM: llm, Source: invSource{s.Incidents.(*incidents.Runner)},
		Store: investigate.NewMemoryStore(0), Now: func() time.Time { return now }, PerHour: o.perHour, Concurrency: o.concurrency})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Shutdown(context.Background()) })
	s.Investigations = svc
	return s, asks, logs
}

func invPath(incident string, rest ...string) string {
	return "/api/v1/incidents/" + incident + "/investigations" + strings.Join(rest, "")
}

// waitFinished polls a run as user until it is no longer running.
func waitFinished(t *testing.T, h http.Handler, user, incident, id string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var inv map[string]any
		rec := getAs(t, h, user, invPath(incident, "/", id), &inv)
		if rec.Code != 200 {
			t.Fatalf("poll %s as %s = %d %s", id, user, rec.Code, rec.Body)
		}
		if inv["status"] != "running" {
			return inv
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("investigation %s still running", id)
	return nil
}

func startAs(t *testing.T, h http.Handler, user, incident, body string) (*httptest.ResponseRecorder, investigationStartResponseJSON) {
	t.Helper()
	rec := postAs(t, h, user, invPath(incident), body, nil)
	var out investigationStartResponseJSON
	if rec.Code == 200 || rec.Code == 202 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode start: %v", err)
		}
	}
	return rec, out
}

type investigationStartResponseJSON struct {
	Investigation map[string]any `json:"investigation"`
	Cached        bool           `json:"cached"`
}

func TestInvestigationRoutes(t *testing.T) {
	llm := submitting()
	s, asks, _ := investigatorServer(t, llm, invOpts{perHour: 3},
		grant("alice", auth.InvestigateIncidents, "team-a"), grant("alice", auth.ViewPodLogs, "team-a"))
	h := s.Handler()
	inc := incidentID("team-a")

	// Start: 202 with the running run, the starter's access frozen in it.
	rec, start := startAs(t, h, "alice", inc, "")
	if rec.Code != http.StatusAccepted || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("start = %d %s (cache-control %q)", rec.Code, rec.Body, rec.Header().Get("Cache-Control"))
	}
	run := start.Investigation
	if run["status"] != "running" || run["requestedBy"] != "alice" || run["incidentId"] != inc || run["provider"] != "demo" || start.Cached {
		t.Errorf("started %v", run)
	}
	access := run["access"].(map[string]any)
	if access["logs"] != true || access["audit"] != true || access["cloudtrail"] != false || access["nodes"] != false {
		t.Errorf("access %v", access)
	}
	id := run["id"].(string)
	done := waitFinished(t, h, "alice", inc, id)
	if done["status"] != "completed" || done["report"] == nil || done["outcome"] != "likely_cause" {
		t.Errorf("finished %v", done)
	}
	if rec := getAs(t, h, "alice", invPath(inc, "/", id), nil); rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("detail cache-control %q", rec.Header().Get("Cache-Control"))
	}

	// The same input again: the completed run answers, without a model
	// call; fresh starts a new one.
	calls := llm.Calls()
	rec, again := startAs(t, h, "alice", inc, "{}")
	if rec.Code != http.StatusOK || !again.Cached || again.Investigation["cachedFrom"] != id || llm.Calls() != calls {
		t.Errorf("same input = %d cached %v (%v), %d new model calls", rec.Code, again.Cached, again.Investigation["cachedFrom"], llm.Calls()-calls)
	}
	rec, fresh := startAs(t, h, "alice", inc, `{"fresh":true}`)
	if rec.Code != http.StatusAccepted || fresh.Cached {
		t.Fatalf("fresh = %d %s", rec.Code, rec.Body)
	}
	waitFinished(t, h, "alice", inc, fresh.Investigation["id"].(string))

	// The list: newest first, nothing hidden from the starter.
	var list investigationsResponse
	rec = getAs(t, h, "alice", invPath(inc), &list)
	listed := map[string]bool{}
	for _, it := range list.Items {
		listed[it.ID] = true
	}
	if rec.Code != 200 || len(list.Items) != 3 || list.Hidden != 0 || rec.Header().Get("Cache-Control") != "no-store" ||
		!listed[id] || !listed[again.Investigation["id"].(string)] || !listed[fresh.Investigation["id"].(string)] {
		t.Errorf("list = %d %+v", rec.Code, list)
	}

	// The hourly quota (3 here) counts the fresh runs, not the cached one.
	rec, _ = startAs(t, h, "alice", inc, `{"fresh":true}`)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("third run = %d %s", rec.Code, rec.Body)
	}
	var third investigationStartResponseJSON
	_ = json.Unmarshal(rec.Body.Bytes(), &third)
	waitFinished(t, h, "alice", inc, third.Investigation["id"].(string))
	rec, _ = startAs(t, h, "alice", inc, `{"fresh":true}`)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Errorf("over the quota = %d (Retry-After %q) %s", rec.Code, rec.Header().Get("Retry-After"), rec.Body)
	}

	// Unknown runs and malformed IDs are not found.
	for _, p := range []string{invPath(inc, "/20261016T000000Z-00000000"), invPath(inc, "/bad..id"), invPath("no-such-incident")} {
		if rec := getAs(t, h, "alice", p, nil); rec.Code != 404 {
			t.Errorf("GET %s = %d", p, rec.Code)
		}
	}

	// Body and origin rules.
	if rec := postAs(t, h, "alice", invPath(inc), `{"fresh":true}`, map[string]string{"Content-Type": "text/plain"}); rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("text/plain = %d", rec.Code)
	}
	if rec := postAs(t, h, "alice", invPath(inc), `{"fresh":true,"model":"x"}`, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown field = %d", rec.Code)
	}
	asks.reset()
	if rec := postAs(t, h, "alice", invPath(inc), `{}`, map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"}); rec.Code != http.StatusForbidden ||
		!strings.Contains(rec.Body.String(), "cross-origin") {
		t.Errorf("cross-origin = %d %s", rec.Code, rec.Body)
	}
	if len(asks.list()) != 0 {
		t.Errorf("a cross-origin request was reviewed: %v", asks.list())
	}

	// /info names the investigator and the capability (true where an RBAC
	// binding proposes it and a review confirms it; the tenant inventory
	// binds no investigations rule, so only an unrestricted caller holds it).
	var info infoResponse
	getAs(t, h, "alice", "/api/v1/info", &info)
	if _, ok := info.Capabilities["investigate"]; info.Investigator == nil || !info.Investigator.Enabled || info.Investigator.Provider != "demo" ||
		info.Investigator.Model != investigate.DefaultModel || info.Investigator.Effort != "high" || info.Investigator.PerHour != 3 || !ok {
		t.Errorf("info investigator %+v, capabilities %v", info.Investigator, info.Capabilities)
	}
	s.Authenticator = nil
	var open infoResponse
	getAs(t, s.Handler(), "", "/api/v1/info", &open)
	if !open.Capabilities["investigate"] {
		t.Errorf("unrestricted capabilities %v", open.Capabilities)
	}
	var carolInfo infoResponse
	getAs(t, h, "carol", "/api/v1/info", &carolInfo)
	if carolInfo.Capabilities["investigate"] {
		t.Error("carol may investigate")
	}
}

// An incident the caller may not see is not found before any other
// review; seeing it without InvestigateIncidents is 403; node incidents
// need the capability cluster-wide.
func TestInvestigationAuthorization(t *testing.T) {
	s, asks, _ := investigatorServer(t, submitting(), invOpts{}, grant("bob", auth.InvestigateIncidents, "team-b"))
	h := s.Handler()
	investigates := func() bool {
		for _, q := range asks.list() {
			if strings.Contains(q, "|create|kubesentry.io|investigations|") {
				return true
			}
		}
		return false
	}

	asks.reset()
	if rec := postAs(t, h, "alice", invPath("no-such-incident"), "{}", nil); rec.Code != 404 || len(asks.list()) != 0 {
		t.Errorf("unknown incident = %d after reviews %v", rec.Code, asks.list())
	}
	asks.reset()
	if rec := postAs(t, h, "alice", invPath(incidentID("team-b")), "{}", nil); rec.Code != 404 || investigates() {
		t.Errorf("team-b's incident as alice = %d after reviews %v", rec.Code, asks.list())
	}
	if rec := getAs(t, h, "alice", invPath(incidentID("team-b")), nil); rec.Code != 404 {
		t.Errorf("team-b's investigations as alice = %d", rec.Code)
	}
	asks.reset()
	rec := postAs(t, h, "alice", invPath(incidentID("team-a")), "{}", nil)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "investigations.kubesentry.io") || !investigates() {
		t.Errorf("without the capability = %d %s", rec.Code, rec.Body)
	}
	// bob sees node incidents (ViewNodes) but may investigate only in team-b.
	if rec := postAs(t, h, "bob", invPath(nodeIncidentID), "{}", nil); rec.Code != http.StatusForbidden ||
		!strings.Contains(rec.Body.String(), "cluster-wide") {
		t.Errorf("node incident without the capability cluster-wide = %d %s", rec.Code, rec.Body)
	}
	if rec := postAs(t, h, "alice", invPath(nodeIncidentID), "{}", nil); rec.Code != 404 {
		t.Errorf("node incident as alice (no ViewNodes) = %d", rec.Code)
	}
	rec, started := startAs(t, h, "bob", incidentID("team-b"), "")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("bob in team-b = %d %s", rec.Code, rec.Body)
	}
	waitFinished(t, h, "bob", incidentID("team-b"), started.Investigation["id"].(string))

	regrant2 := func(extra ...string) {
		g := tenantGrants()
		for _, k := range extra {
			g[k] = true
		}
		asks.mu.Lock()
		asks.g = g
		asks.mu.Unlock()
		s.Authorizer = &auth.SARAuthorizer{Reviewer: asks, Candidates: s.Authorizer.(*auth.SARAuthorizer).Candidates}
	}
	regrant2(grant("bob", auth.InvestigateIncidents, ""))
	h = s.Handler()
	if rec, _ := startAs(t, h, "bob", nodeIncidentID, ""); rec.Code != http.StatusAccepted {
		t.Errorf("node incident with the capability cluster-wide = %d %s", rec.Code, rec.Body)
	}
}

// A starter without pod logs: the digest leaves the logs out, the run
// records them as omitted, and the logs tool answers "not permitted"
// without reading the source.
func TestInvestigationWithoutLogs(t *testing.T) {
	llm := submitting()
	s, _, logs := investigatorServer(t, llm, invOpts{}, grant("alice", auth.InvestigateIncidents, "team-a"))
	h := s.Handler()
	inc := incidentID("team-a")
	rec, start := startAs(t, h, "alice", inc, "")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("start = %d %s", rec.Code, rec.Body)
	}
	if access := start.Investigation["access"].(map[string]any); access["logs"] != false || access["audit"] != true {
		t.Errorf("access %v", access)
	}
	done := waitFinished(t, h, "alice", inc, start.Investigation["id"].(string))
	if omitted, _ := done["omitted"].(map[string]any); omitted["logs"] != "forbidden" {
		t.Errorf("omitted %v", done["omitted"])
	}
	denied := false
	for _, st := range done["steps"].([]any) {
		step := st.(map[string]any)
		if step["tool"] == investigate.ToolGetLogs {
			denied = step["result"] == investigate.ResultDenied
		}
	}
	if !denied {
		t.Errorf("get_logs was not denied: %v", done["steps"])
	}
	if n := logs.calls.Load(); n != 0 {
		t.Errorf("the log source was read %d times", n)
	}
	results := investigatetest.ToolResults(llm.Requests()[1])
	if len(results) != 1 || !results[0].IsError || !strings.Contains(results[0].Content, "not permitted for the requesting user") {
		t.Errorf("tool results %+v", results)
	}
	if strings.Contains(investigatetest.RequestText(llm.Requests()[0]), "hunter2") {
		t.Error("the digest carries log text")
	}
}

// A run used access a reader lacks: it is not found for them, and lists
// count it as hidden. Only the starter may cancel; a finished run cannot.
func TestInvestigationReadersAndCancel(t *testing.T) {
	release := make(chan struct{})
	submit := investigatetest.SubmitFromRefs(func(refs []string) any { return investigatetest.Report(refs...) })
	llm := investigatetest.New(investigatetest.Gate(release, submit))
	llm.After = submit
	s, _, _ := investigatorServer(t, llm, invOpts{concurrency: 1},
		grant("alice", auth.InvestigateIncidents, "team-a"), grant("alice", auth.ViewPodLogs, "team-a"),
		grant("dave", auth.ViewNamespace, "team-a"), grant("dave", auth.ViewAudit, "team-a"), grant("dave", auth.ViewPodLogs, "team-a"),
		grant("frank", auth.ViewNamespace, "team-a"), grant("frank", auth.ViewAudit, "team-a"),
		grant("bob", auth.InvestigateIncidents, ""))
	h := s.Handler()
	inc := incidentID("team-a")
	rec, start := startAs(t, h, "alice", inc, "")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("start = %d %s", rec.Code, rec.Body)
	}
	id := start.Investigation["id"].(string)

	// While it runs: a second start is a conflict naming it, and another
	// incident finds this replica busy.
	rec = postAs(t, h, "alice", invPath(inc), `{"fresh":true}`, nil)
	var conflict map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &conflict)
	if rec.Code != http.StatusConflict || conflict["runningId"] != id {
		t.Errorf("second start = %d %s", rec.Code, rec.Body)
	}
	rec = postAs(t, h, "bob", invPath(nodeIncidentID), `{}`, nil)
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") != "30" {
		t.Errorf("busy = %d (Retry-After %q) %s", rec.Code, rec.Header().Get("Retry-After"), rec.Body)
	}

	// frank lacks the logs the run may read: not found, and hidden.
	if rec := getAs(t, h, "frank", invPath(inc, "/", id), nil); rec.Code != 404 {
		t.Errorf("frank reads the run: %d", rec.Code)
	}
	var list investigationsResponse
	getAs(t, h, "frank", invPath(inc), &list)
	if len(list.Items) != 0 || list.Hidden != 1 {
		t.Errorf("frank's list %+v", list)
	}
	if rec := postAs(t, h, "frank", invPath(inc, "/", id, "/cancel"), "", nil); rec.Code != 404 {
		t.Errorf("frank cancels a run he cannot read: %d", rec.Code)
	}
	// dave may read it, but not cancel it.
	if rec := getAs(t, h, "dave", invPath(inc, "/", id), nil); rec.Code != 200 {
		t.Errorf("dave reads the run: %d", rec.Code)
	}
	getAs(t, h, "dave", invPath(inc), &list)
	if len(list.Items) != 1 || list.Hidden != 0 {
		t.Errorf("dave's list %+v", list)
	}
	if rec := postAs(t, h, "dave", invPath(inc, "/", id, "/cancel"), "", nil); rec.Code != http.StatusForbidden {
		t.Errorf("dave cancels = %d %s", rec.Code, rec.Body)
	}
	// The starter cancels it; then it is not running any more.
	rec = postAs(t, h, "alice", invPath(inc, "/", id, "/cancel"), "", nil)
	var cancelled investigationStartResponseJSON
	_ = json.Unmarshal(rec.Body.Bytes(), &cancelled)
	if rec.Code != 200 || cancelled.Investigation["status"] != "cancelled" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("cancel = %d %s", rec.Code, rec.Body)
	}
	if rec := postAs(t, h, "alice", invPath(inc, "/", id, "/cancel"), "", nil); rec.Code != http.StatusConflict {
		t.Errorf("cancel again = %d %s", rec.Code, rec.Body)
	}
	if rec := postAs(t, h, "alice", invPath(inc, "/", id, "/cancel"), "x", map[string]string{"Content-Type": "text/plain"}); rec.Code != http.StatusUnsupportedMediaType {
		t.Errorf("cancel with a text body = %d", rec.Code)
	}
	close(release)
}

// seedInvestigations gives s an investigator whose store holds one
// finished run of each open incident (team-a's, team-b's, the node's),
// started by erin with no access beyond the incident itself, and returns
// their IDs by incident.
func seedInvestigations(t *testing.T, s *Server) map[string]string {
	t.Helper()
	ctx := context.Background()
	st := investigate.NewMemoryStore(0)
	runs := map[string]string{}
	for i, inc := range []string{incidentID("team-a"), incidentID("team-b"), nodeIncidentID} {
		id := fmt.Sprintf("20261016T080000Z-%08x", i)
		fin := now
		if err := st.Create(ctx, &investigate.Investigation{ID: id, IncidentID: inc, Status: investigate.Completed, RequestedBy: "erin",
			CreatedAt: now, UpdatedAt: now, FinishedAt: &fin, Provider: "demo", Model: investigate.DefaultModel, Effort: "high"}); err != nil {
			t.Fatal(err)
		}
		runs[inc] = id
	}
	svc, err := investigate.NewService(investigate.Config{LLM: investigatetest.New(), Source: invSource{s.Incidents.(*incidents.Runner)},
		Store: st, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = svc.Shutdown(context.Background()) })
	s.Investigations = svc
	return runs
}
