package investigate_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/incidents"
	"github.com/ByronGary/kubesentry/internal/investigate"
	"github.com/ByronGary/kubesentry/internal/investigate/investigatetest"
)

func run(t *testing.T, llm *investigatetest.ScriptedLLM, src *fakeSource, a investigate.Access, o investigate.Options) investigate.AgentResult {
	t.Helper()
	return investigate.RunAgent(context.Background(), llm, src, bundleOf(t, src, a), a, o, now)
}

func submitRefs() investigatetest.Turn {
	return investigatetest.SubmitFromRefs(func(refs []string) any { return investigatetest.Report(refs...) })
}

func stepTexts(steps []investigate.Step) string {
	var l []string
	for _, s := range steps {
		l = append(l, s.Kind+":"+s.Text)
	}
	return strings.Join(l, "\n")
}

// The happy path: the digest, a tool call, a report citing what was shown;
// requests carry the model, effort, system prompt, tools and the cache
// breakpoints, and the conversation only grows.
func TestLoopHappyPath(t *testing.T) {
	src := source()
	llm := investigatetest.New(
		investigatetest.Tools(investigatetest.Call{Name: investigate.ToolGetLogs, Input: map[string]any{"pods": []string{"api-1"}, "level": "error"}}),
		submitRefs(),
	)
	res := run(t, llm, src, allAccess, investigate.Options{Effort: "max"})
	if res.Status != investigate.Completed || res.Report == nil || res.Turns != 2 || res.ToolCalls != 2 {
		t.Fatalf("result %+v\n%s", res, stepTexts(res.Steps))
	}
	if len(res.Report.Unverified) != 0 || len(res.Evidence) == 0 {
		t.Errorf("unverified %v, evidence %d", res.Report.Unverified, len(res.Evidence))
	}
	if !res.Ledger.Has("log:1") || !res.Ledger.Has("log:2") || res.Ledger.Has("log:3") {
		t.Error("the log lines' refs are not in the ledger")
	}
	reqs := llm.Requests()
	for i, r := range reqs {
		if r.Model != investigate.DefaultModel || r.Effort != "max" || r.System != investigate.SystemPrompt() || !r.CacheSystem ||
			len(r.Tools) != 8 || r.MaxTokens != investigate.DefaultMaxOutputTokens || r.ToolChoiceNone || r.OutputSchema != nil {
			t.Errorf("request %d: %+v", i, r)
		}
		last := r.Messages[len(r.Messages)-1]
		if last.Role != investigate.RoleUser {
			t.Errorf("request %d ends with %s", i, last.Role)
		}
		// One moving breakpoint: the last block of the newest user message.
		for mi, m := range r.Messages {
			for bi, b := range m.Content {
				want := mi == len(r.Messages)-1 && bi == len(m.Content)-1
				if b.Cache != want {
					t.Errorf("request %d message %d block %d: cache %v", i, mi, bi, b.Cache)
				}
			}
		}
	}
	first := reqs[0].Messages[0].Content[0].Text
	if !strings.HasPrefix(first, "Investigate this incident") || !strings.Contains(first, "<incident_digest>\n{") ||
		!strings.HasSuffix(first, "}\n</incident_digest>") {
		t.Errorf("first message %.200s", first)
	}
	// Append-only: the second request starts with the first's messages.
	if len(reqs[1].Messages) != 3 || reqs[1].Messages[0].Content[0].Text != first {
		t.Errorf("history %+v", reqs[1].Messages)
	}
	results := investigatetest.ToolResults(reqs[1])
	if len(results) != 1 || results[0].IsError || !strings.HasPrefix(results[0].Content, `<untrusted source="get_logs">{`) ||
		!strings.Contains(results[0].Content, "</untrusted>\n[tool calls left: 23 of 24; turns left: 15 of 16]") {
		t.Errorf("tool result %+v", results)
	}
	steps := stepTexts(res.Steps)
	for _, want := range []string{"turn:turn 1: 1 tool call", "tool:get_logs api-1 error 11:55–12:30: 2 lines", "tool:submit_report: report submitted"} {
		if !strings.Contains(steps, want) {
			t.Errorf("steps lack %q:\n%s", want, steps)
		}
	}
}

// Parallel calls each get exactly one result, in one message, in order.
func TestLoopParallelToolCalls(t *testing.T) {
	src := source()
	llm := investigatetest.New(
		investigatetest.Tools(
			investigatetest.Call{Name: investigate.ToolListSignals, Input: map[string]any{"role": "trigger"}},
			investigatetest.Call{Name: investigate.ToolGetK8sEvents, Input: map[string]any{"type": "Warning"}},
			investigatetest.Call{Name: investigate.ToolGetMetricSeries, Input: map[string]any{"metric": "memory", "max_points": 10}},
			investigatetest.Call{Name: "get_secrets", Input: map[string]any{}},
		),
		submitRefs(),
	)
	res := run(t, llm, src, allAccess, investigate.Options{})
	if res.Status != investigate.Completed {
		t.Fatalf("%s %s", res.Status, res.Err)
	}
	req := llm.Requests()[1]
	asst := req.Messages[1]
	results := investigatetest.ToolResults(req)
	if len(results) != 4 || len(req.Messages[2].Content) != 4 {
		t.Fatalf("%d results", len(results))
	}
	for i, r := range results {
		if r.ToolUseID != asst.Content[i].ID {
			t.Errorf("result %d answers %s, want %s", i, r.ToolUseID, asst.Content[i].ID)
		}
	}
	if results[3].IsError != true || !strings.Contains(results[3].Content, `unknown tool "get_secrets"`) {
		t.Errorf("unknown tool: %+v", results[3])
	}
	if !strings.Contains(results[1].Content, `"reason":"BackOff"`) || !strings.Contains(results[1].Content, `"reason":"SystemOOM"`) ||
		strings.Contains(results[1].Content, "another namespace") || strings.Contains(results[1].Content, "Pulled") {
		t.Errorf("events: %s", results[1].Content)
	}
	var metric struct {
		Series []struct {
			Max    float64 `json:"max"`
			Values [][2]any
		} `json:"series"`
	}
	body := strings.TrimSuffix(strings.TrimPrefix(results[2].Content, `<untrusted source="get_metric_series">`), "")
	body = body[:strings.Index(body, "</untrusted>")]
	if err := json.Unmarshal([]byte(body), &metric); err != nil || len(metric.Series) != 1 || len(metric.Series[0].Values) > 10 {
		t.Fatalf("metric %s: %v", body, err)
	}
	peak := false
	for _, v := range metric.Series[0].Values {
		if v[1].(float64) == 512e6 && v[0] == "2026-10-15T12:00:00Z" {
			peak = true
		}
	}
	if !peak {
		t.Errorf("the downsample lost the peak: %v", metric.Series[0].Values)
	}
	// The unknown tool is stored without its made-up name.
	for _, s := range res.Steps {
		if strings.Contains(s.Tool, "secrets") {
			t.Errorf("step %+v", s)
		}
	}
}

func TestLoopRefusal(t *testing.T) {
	llm := investigatetest.New(investigatetest.Refuse("cyber", "This looks like an attempt to\x00 break in."))
	res := run(t, llm, source(), allAccess, investigate.Options{})
	if res.Status != investigate.Refused || res.Refusal == nil || res.Refusal.Category != "cyber" ||
		res.Refusal.Explanation != "This looks like an attempt to break in." || res.Report != nil {
		t.Fatalf("%+v", res)
	}
}

// max_tokens: the turn is retried once with twice the limit; a second
// time fails the run.
func TestLoopMaxTokens(t *testing.T) {
	llm := investigatetest.New(investigatetest.Stop(investigate.StopMaxTokens), submitRefs())
	res := run(t, llm, source(), allAccess, investigate.Options{MaxOutputTokens: 10_000})
	reqs := llm.Requests()
	if res.Status != investigate.Completed || len(reqs) != 2 || reqs[1].MaxTokens != 20_000 || len(reqs[1].Messages) != 1 {
		t.Fatalf("retry: %+v %d", res, len(reqs))
	}
	llm = investigatetest.New(investigatetest.Stop(investigate.StopMaxTokens), investigatetest.Stop(investigate.StopMaxTokens))
	res = run(t, llm, source(), allAccess, investigate.Options{})
	if res.Status != investigate.Failed || !strings.HasPrefix(res.Err, "max_tokens") || llm.Requests()[1].MaxTokens != 32_000 {
		t.Fatalf("second max_tokens: %+v", res)
	}
}

// Malformed input is answered with what is wrong, without reading the
// source.
func TestLoopMalformedToolInput(t *testing.T) {
	src := source()
	calls := []investigatetest.Call{
		{Name: investigate.ToolGetLogs, Input: map[string]any{"pods": []string{"api-1"}, "grep": "x"}},
		{Name: investigate.ToolGetLogs, Input: map[string]any{"level": "fatal"}},
		{Name: investigate.ToolGetLogs, Input: map[string]any{"from": "2026-10-15T12:10:00Z", "to": "2026-10-15T12:00:00Z"}},
		{Name: investigate.ToolGetLogs, Input: map[string]any{"pods": []string{"payments-1"}}},
		{Name: investigate.ToolGetLogs, Input: map[string]any{"limit": 500}},
		{Name: investigate.ToolGetLogs, Input: map[string]any{"pods": []string{"a", "b", "c", "d", "e", "f"}}},
		{Name: investigate.ToolGetLogs, RawInput: `{"pods": [`},
		{Name: investigate.ToolGetMetricSeries, Input: map[string]any{}},
		{Name: investigate.ToolGetMetricSeries, Input: map[string]any{"metric": "memory", "label": "nope"}},
		{Name: investigate.ToolGetK8sEvents, Input: map[string]any{"object_kind": "Node", "object_name": "node-9"}},
		{Name: investigate.ToolListSignals, Input: map[string]any{"from": "yesterday"}},
		{Name: investigate.ToolGetWorkloadState, Input: map[string]any{"pod": "api-1"}},
	}
	llm := investigatetest.New(investigatetest.Tools(calls...), submitRefs())
	res := run(t, llm, src, allAccess, investigate.Options{})
	if res.Status != investigate.Completed {
		t.Fatalf("%s %s", res.Status, res.Err)
	}
	results := investigatetest.ToolResults(llm.Requests()[1])
	wants := []string{
		`unknown field "grep"`, "level: must be one of error, warn, info, debug", "from is after to",
		`pod "payments-1" is not one of the incident's pods (api-1, api-2)`, "limit: at most 200", "pods: at most 5 items",
		"not valid JSON", "metric: required", `no memory series has label "nope"; labels: api-1/app`,
		`node "node-9" is not one of the incident's nodes (node-1)`, "from: must be an RFC 3339 time", `unknown field "pod"`,
	}
	for i, r := range results {
		if !r.IsError || !strings.Contains(r.Content, "invalid input: ") || !strings.Contains(r.Content, wants[i]) {
			t.Errorf("call %d: %q, want %q", i, r.Content, wants[i])
		}
	}
	// Only the label lookup reached a source (it needs the series to say
	// which labels exist).
	if src.Calls("Logs") != 0 || src.Calls("Events") != 0 || src.Calls("WorkloadState") != 0 || src.Calls("Get") != 0 || src.Calls("Series") != 1 {
		t.Errorf("source calls %v", src.calls)
	}
	for _, s := range res.Steps {
		if s.Kind == investigate.StepTool && s.Tool != investigate.ToolSubmitReport && s.Result != investigate.ResultInvalid {
			t.Errorf("step %+v", s)
		}
		if strings.Contains(s.Text, "payments-1") || strings.Contains(s.Text, "grep") {
			t.Errorf("a step repeats raw input: %+v", s)
		}
	}
}

// Times are clamped to the padded window; an open incident's window runs
// to now. A source error is an error result, not a failed run.
func TestToolTimesAndErrors(t *testing.T) {
	src := source()
	src.logErr = errors.New("pods/log: connection refused")
	llm := investigatetest.New(
		investigatetest.Tools(investigatetest.Call{Name: investigate.ToolGetLogs,
			Input: map[string]any{"from": "2026-10-14T00:00:00Z", "to": "2026-10-16T00:00:00Z", "contains": "cache", "limit": 7}}),
		submitRefs(),
	)
	res := run(t, llm, src, allAccess, investigate.Options{})
	if res.Status != investigate.Completed {
		t.Fatalf("%+v", res)
	}
	q := src.lastLogs
	if !q.From.Equal(at(-5)) || !q.To.Equal(at(30)) || q.Text != "cache" || q.Limit != 7 {
		t.Errorf("log request %+v", q)
	}
	r := investigatetest.ToolResults(llm.Requests()[1])
	if !r[0].IsError || !strings.HasPrefix(r[0].Content, "error: pods/log: connection refused") {
		t.Errorf("result %+v", r)
	}

	src = source()
	src.in.State, src.in.End = incidents.Open, nil
	llm = investigatetest.New(
		investigatetest.Tools(investigatetest.Call{Name: investigate.ToolGetLogs, Input: map[string]any{"to": "2026-10-16T00:00:00Z"}}),
		submitRefs(),
	)
	run(t, llm, src, allAccess, investigate.Options{})
	if q := src.lastLogs; !q.To.Equal(now()) {
		t.Errorf("open incident: log request to %s", q.To)
	}
}

// A tool the starter may not use is still offered, answers "not
// permitted" and never touches its source.
func TestLoopDeniedTools(t *testing.T) {
	src := source()
	llm := investigatetest.New(
		investigatetest.Tools(
			investigatetest.Call{Name: investigate.ToolGetLogs, Input: map[string]any{}},
			investigatetest.Call{Name: investigate.ToolGetAuditEvents, Input: map[string]any{}},
			investigatetest.Call{Name: investigate.ToolGetCloudTrailEvents, Input: map[string]any{}},
			investigatetest.Call{Name: investigate.ToolGetK8sEvents, Input: map[string]any{"object_kind": "Node"}},
			investigatetest.Call{Name: investigate.ToolListSignals, Input: map[string]any{"type": "audit-change"}},
			investigatetest.Call{Name: investigate.ToolGetK8sEvents, Input: map[string]any{}},
			investigatetest.Call{Name: investigate.ToolGetWorkloadState, Input: map[string]any{}},
			investigatetest.Call{Name: investigate.ToolListSignals, Input: map[string]any{}},
		),
		submitRefs(),
	)
	res := run(t, llm, src, investigate.Access{}, investigate.Options{})
	req := llm.Requests()[1]
	if len(req.Tools) != 8 {
		t.Errorf("%d tools offered", len(req.Tools))
	}
	results := investigatetest.ToolResults(req)
	for i := 0; i < 5; i++ {
		if !results[i].IsError || !strings.HasPrefix(results[i].Content, "not permitted for the requesting user") {
			t.Errorf("call %d: %s", i, results[i].Content)
		}
	}
	if src.Calls("Logs") != 0 || src.Calls("AuditEvents") != 0 {
		t.Errorf("a denied tool read its source: %v", src.calls)
	}
	// Allowed tools leave out what the access does not cover.
	ev, ws, sigs := results[5].Content, results[6].Content, results[7].Content
	if results[5].IsError || strings.Contains(ev, "SystemOOM") || !strings.Contains(ev, "events about nodes: not permitted") {
		t.Errorf("events: %s", ev)
	}
	if strings.Contains(ws, "MemoryPressure") || !strings.Contains(ws, "node conditions: not permitted") || !strings.Contains(ws, "OOMKilled") {
		t.Errorf("workload state: %s", ws)
	}
	if strings.Contains(sigs, "audit-change") || strings.Contains(sigs, "cloudtrail-change") || !strings.Contains(sigs, "deploy") {
		t.Errorf("signals: %s", sigs)
	}
	denied := 0
	for _, s := range res.Steps {
		if s.Result == investigate.ResultDenied {
			denied++
		}
	}
	if denied != 5 {
		t.Errorf("%d denied steps", denied)
	}
	// The digest named the gaps.
	first := llm.Requests()[0].Messages[0].Content[0].Text
	if !strings.Contains(first, `"omitted":{"audit":"forbidden","cloudtrail":"forbidden","logs":"forbidden","nodes":"forbidden"}`) {
		t.Errorf("digest omitted: %.600s", first)
	}
}

// Each budget runs out the same way: pending calls answer "budget
// exhausted", one turn for submit_report, then the final turn.
func TestLoopBudgets(t *testing.T) {
	logs := investigatetest.Call{Name: investigate.ToolGetLogs, Input: map[string]any{}}
	t.Run("tool calls", func(t *testing.T) {
		llm := investigatetest.New(investigatetest.Tools(logs, logs, logs), submitRefs())
		res := run(t, llm, source(), allAccess, investigate.Options{MaxToolCalls: 2})
		results := investigatetest.ToolResults(llm.Requests()[1])
		last := llm.Requests()[1].Messages[2]
		if res.Status != investigate.Completed || res.Budget != "tool calls" || results[0].IsError || results[1].IsError ||
			results[2].Content != "budget exhausted: call submit_report now" ||
			!strings.Contains(last.Content[len(last.Content)-1].Text, "budget is spent (tool calls)") {
			t.Fatalf("%+v %+v", res, results)
		}
	})
	t.Run("turns", func(t *testing.T) {
		llm := investigatetest.New(investigatetest.Tools(logs), investigatetest.Tools(logs), investigatetest.Tools(logs),
			investigatetest.Final(investigatetest.Report("signal:oom:api-1")))
		res := run(t, llm, source(), allAccess, investigate.Options{MaxTurns: 2})
		reqs := llm.Requests()
		if res.Status != investigate.Completed || res.Budget != "turns" || len(reqs) != 4 || !reqs[3].ToolChoiceNone ||
			reqs[3].OutputSchema == nil || reqs[2].ToolChoiceNone || len(reqs[3].Tools) != 8 {
			t.Fatalf("%+v, %d requests\n%s", res, len(reqs), stepTexts(res.Steps))
		}
		if r := investigatetest.ToolResults(reqs[3]); len(r) != 1 || r[0].Content != "budget exhausted: call submit_report now" {
			t.Errorf("wrap-up turn's call: %+v", r)
		}
		if res.Report.RootCause.Evidence[0] != "signal:oom:api-1" || len(res.Report.Unverified) != 0 {
			t.Errorf("final report %+v", res.Report)
		}
	})
	t.Run("tokens", func(t *testing.T) {
		big := investigate.Usage{Input: 900_000, CacheRead: 700_000}
		llm := investigatetest.New(investigatetest.WithUsage(investigatetest.Tools(logs), big), submitRefs())
		res := run(t, llm, source(), allAccess, investigate.Options{})
		results := investigatetest.ToolResults(llm.Requests()[1])
		if res.Status != investigate.Completed || res.Budget != "tokens" || results[0].Content != "budget exhausted: call submit_report now" {
			t.Fatalf("%+v %+v", res, results)
		}
	})
	t.Run("no report after the budget", func(t *testing.T) {
		llm := investigatetest.New(investigatetest.Tools(logs, logs), investigatetest.Text("done"), investigatetest.Text("not json"))
		res := run(t, llm, source(), allAccess, investigate.Options{MaxToolCalls: 1})
		if res.Status != investigate.Failed || res.Err != "budget: tool calls" {
			t.Fatalf("%+v", res)
		}
	})
}

// A model that never submits is reminded once, then asked for the report
// with tools off and the report schema as structured output.
func TestLoopNeverSubmits(t *testing.T) {
	llm := investigatetest.New(investigatetest.Text("I think it is the deploy."), investigatetest.Text("Still the deploy."),
		investigatetest.Final(investigatetest.Report("signal:deploy:api:2", "signal:invented")))
	res := run(t, llm, source(), allAccess, investigate.Options{})
	reqs := llm.Requests()
	if res.Status != investigate.Completed || len(reqs) != 3 || reqs[1].ToolChoiceNone || !reqs[2].ToolChoiceNone ||
		string(reqs[2].OutputSchema) != string(investigate.ReportSchema()) {
		t.Fatalf("%+v", res)
	}
	if !strings.Contains(reqs[1].Messages[2].Content[0].Text, "without calling submit_report") ||
		!strings.Contains(reqs[2].Messages[4].Content[0].Text, "No tools are available") {
		t.Errorf("nudge and final messages: %+v", reqs[2].Messages)
	}
	if strings.Join(res.Report.Unverified, ",") != "signal:invented" {
		t.Errorf("unverified %v", res.Report.Unverified)
	}
	// An invalid final report fails the run.
	llm = investigatetest.New(investigatetest.Text("a"), investigatetest.Text("b"), investigatetest.Text("{not json"))
	if res := run(t, llm, source(), allAccess, investigate.Options{}); res.Status != investigate.Failed || res.Err != "no valid report" {
		t.Errorf("%+v", res)
	}
}

// The context window running out goes straight to the final turn.
func TestLoopContextWindowExceeded(t *testing.T) {
	llm := investigatetest.New(investigatetest.Stop(investigate.StopContextExceeded), investigatetest.Final(investigatetest.Report()))
	res := run(t, llm, source(), allAccess, investigate.Options{})
	if reqs := llm.Requests(); res.Status != investigate.Completed || !reqs[1].ToolChoiceNone || reqs[1].Messages[len(reqs[1].Messages)-1].Role != "user" {
		t.Fatalf("%+v", res)
	}
}

// Invalid reports are answered with the validation error, twice; then a
// valid one completes the run. A third invalid one goes to the final turn.
func TestLoopInvalidThenValidReport(t *testing.T) {
	bad := investigatetest.Report()
	delete(bad, "impact")
	llm := investigatetest.New(investigatetest.Submit(bad), investigatetest.Submit(map[string]any{"summary": "x"}), submitRefs())
	res := run(t, llm, source(), allAccess, investigate.Options{})
	reqs := llm.Requests()
	if res.Status != investigate.Completed || len(reqs) != 3 {
		t.Fatalf("%+v", res)
	}
	r := investigatetest.ToolResults(reqs[1])
	if len(r) != 1 || !r[0].IsError || !strings.Contains(r[0].Content, "invalid report: impact: required") {
		t.Errorf("first answer %+v", r)
	}
	llm = investigatetest.New(investigatetest.Submit(bad), investigatetest.Submit(bad), investigatetest.Submit(bad),
		investigatetest.Final(investigatetest.Report()))
	res = run(t, llm, source(), allAccess, investigate.Options{})
	if reqs := llm.Requests(); res.Status != investigate.Completed || len(reqs) != 4 || !reqs[3].ToolChoiceNone {
		t.Fatalf("third invalid report: %+v", res)
	}
}

// A run that runs out of time fails, keeping the steps it took.
func TestLoopTimeoutKeepsSteps(t *testing.T) {
	llm := investigatetest.New(investigatetest.Tools(investigatetest.Call{Name: investigate.ToolGetWorkloadState}), investigatetest.Hang())
	res := run(t, llm, source(), allAccess, investigate.Options{Timeout: 100 * time.Millisecond})
	if res.Status != investigate.Failed || res.Err != "timeout" {
		t.Fatalf("%+v", res)
	}
	steps := stepTexts(res.Steps)
	if !strings.Contains(steps, "get_workload_state: 1 pod") || !strings.Contains(steps, "ran out of time") {
		t.Errorf("steps:\n%s", steps)
	}
}

// Thinking blocks (and every other assistant block) go back byte for byte.
func TestLoopThinkingRoundTrip(t *testing.T) {
	raw := `{"type":"thinking","thinking":"","signature":"EqQBCkgIBxABGAIiQL\u002b/x  ==","display":"omitted"}`
	llm := investigatetest.New(
		investigatetest.WithThinking(investigatetest.Tools(investigatetest.Call{Name: investigate.ToolGetWorkloadState}), raw),
		investigatetest.WithThinking(submitRefs(), raw),
	)
	res := run(t, llm, source(), allAccess, investigate.Options{})
	if res.Status != investigate.Completed {
		t.Fatalf("%+v", res)
	}
	asst := llm.Requests()[1].Messages[1]
	if asst.Role != investigate.RoleAssistant || asst.Content[0].Type != investigate.BlockThinking || string(asst.Content[0].Raw) != raw ||
		asst.Content[1].Type != investigate.BlockToolUse || asst.Content[0].Cache || asst.Content[1].Cache {
		t.Errorf("assistant message %+v", asst)
	}
}

// Provider errors fail the run with a short reason, never a body.
func TestLoopProviderError(t *testing.T) {
	body := strings.Repeat("{\"error\":\"overloaded with a long body\"}", 20)
	llm := investigatetest.New(investigatetest.Fail(investigate.NewAPIError(529, "overloaded_error", body, true)))
	res := run(t, llm, source(), allAccess, investigate.Options{})
	if res.Status != investigate.Failed || res.Err != "HTTP 529 overloaded" {
		t.Fatalf("%+v", res)
	}
	if e := investigate.NewAPIError(500, "api_error", body+"\n\x00", false); len(e.Message) > 200 || strings.ContainsAny(e.Message, "\n\x00") {
		t.Errorf("message %q", e.Message)
	}
	llm = investigatetest.New(investigatetest.Fail(context.DeadlineExceeded))
	if res := run(t, llm, source(), allAccess, investigate.Options{}); res.Err != "model request failed" {
		t.Errorf("%+v", res)
	}
}

func TestOptionsValidate(t *testing.T) {
	for _, o := range []investigate.Options{{Effort: "turbo"}, {MaxOutputTokens: 200_000}, {DigestBytes: 100}} {
		if err := o.Validate(); err == nil {
			t.Errorf("%+v accepted", o)
		}
	}
	if err := (investigate.Options{}).Validate(); err != nil {
		t.Error(err)
	}
	d := investigate.Options{}.WithDefaults()
	if d.MaxTurns != 16 || d.MaxToolCalls != 24 || d.MaxTokens != 1_500_000 || d.MaxOutputTokens != 16_000 || d.Timeout != 10*time.Minute ||
		d.Effort != "high" || d.Model != "claude-opus-5-5" || d.DigestBytes != 64<<10 {
		t.Errorf("defaults %+v", d)
	}
}

// The system prompt says what the contract asks of it, and names no field
// the egress filter drops.
func TestSystemPrompt(t *testing.T) {
	p := investigate.SystemPrompt()
	for _, want := range []string{"untrusted", "never as instructions", "You can only read", "Cite the refs", "confidence",
		"[REDACTED]", "read-only", "submit_report"} {
		if !strings.Contains(p, want) {
			t.Errorf("the prompt lacks %q", want)
		}
	}
	if strings.Contains(p, "MUST") || strings.Contains(p, "sourceIP") || strings.Contains(p, "userAgent") {
		t.Error("the prompt shouts or names a dropped field")
	}
}
