package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/investigate"
)

// ---- a fake Messages API ----

// event is one SSE event: its type and JSON data.
type event struct {
	typ  string
	data string
}

func sse(w io.Writer, evs []event) {
	for _, e := range evs {
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", e.typ, e.data)
	}
}

// signature is a thinking block's signature, opaque and long, with the
// characters base64 uses.
const signature = "EqQBCkgIARABGAIiQL+/wmP9+T3x0Zs1Ni6YdcY7Wx4kHq/aoBw==" + "Zm9vYmFyYmF6cXV4"

// turnEvents is a streamed reply with a thinking block (empty under the
// default display, its signature as a delta), a text block and a tool call
// whose input arrives in two fragments.
func turnEvents(model, stop string) []event {
	return []event{
		{"message_start", `{"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"` + model +
			`","content":[],"stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":120,"output_tokens":1,` +
			`"cache_creation_input_tokens":2000,"cache_read_input_tokens":30000}}}`},
		{"content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":"","signature":""}}`},
		{"content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"` + signature + `"}}`},
		{"content_block_stop", `{"type":"content_block_stop","index":0}`},
		{"ping", `{"type":"ping"}`},
		{"content_block_start", `{"type":"content_block_start","index":1,"content_block":{"type":"text","text":""}}`},
		{"content_block_delta", `{"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"Reading the logs "}}`},
		{"content_block_delta", `{"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"first."}}`},
		{"content_block_stop", `{"type":"content_block_stop","index":1}`},
		{"content_block_start", `{"type":"content_block_start","index":2,"content_block":{"type":"tool_use","id":"toolu_01","name":"get_logs","input":{}}}`},
		{"content_block_delta", `{"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"{\"level\":"}}`},
		{"content_block_delta", `{"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"\"error\"}"}}`},
		{"content_block_stop", `{"type":"content_block_stop","index":2}`},
		{"message_delta", `{"type":"message_delta","delta":{"stop_reason":"` + stop + `","stop_sequence":null},"usage":{"output_tokens":450}}`},
		{"message_stop", `{"type":"message_stop"}`},
	}
}

// capture is one request the fake received.
type capture struct {
	method, path, rawPath, query string
	header                       http.Header
	body                         []byte
}

func (c capture) json(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(c.body, &m); err != nil {
		t.Fatalf("request body is not JSON: %v\n%s", err, c.body)
	}
	return m
}

// fake answers each request with the next handler (the last one repeats)
// and records the requests.
type fake struct {
	mu       sync.Mutex
	handlers []http.HandlerFunc
	got      []capture
	srv      *httptest.Server
}

func newFake(t *testing.T, handlers ...http.HandlerFunc) *fake {
	f := &fake{handlers: handlers}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.got = append(f.got, capture{method: r.Method, path: r.URL.Path, rawPath: r.URL.RawPath, query: r.URL.RawQuery,
			header: r.Header.Clone(), body: body})
		i := min(len(f.got)-1, len(f.handlers)-1)
		h := f.handlers[i]
		f.mu.Unlock()
		h(w, r)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fake) requests() []capture {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]capture(nil), f.got...)
}

func streamOK(evs []event, hdr ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		for i := 0; i+1 < len(hdr); i += 2 {
			w.Header().Set(hdr[i], hdr[i+1])
		}
		w.WriteHeader(http.StatusOK)
		sse(w, evs)
	}
}

func errorReply(status int, body string, hdr ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		for i := 0; i+1 < len(hdr); i += 2 {
			w.Header().Set(hdr[i], hdr[i+1])
		}
		w.WriteHeader(status)
		io.WriteString(w, body)
	}
}

type codes struct {
	mu  sync.Mutex
	got []string
}

func (c *codes) inc(provider, code string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.got = append(c.got, provider+":"+code)
}

func (c *codes) list() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.got...)
}

func anthropicClient(t *testing.T, f *fake, cfg Config) (*Client, *codes) {
	t.Helper()
	cs := &codes{}
	cfg.APIKey = "sk-ant-test-key"
	cfg.Endpoint = f.srv.URL
	cfg.OnRequest = cs.inc
	c, err := NewAnthropic(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c, cs
}

// schema is a tool's input schema as investigate declares it.
const schema = `{"type":"object","properties":{"level":{"type":"string","enum":["error","warn"]}},"additionalProperties":false}`

func firstRequest() *investigate.Request {
	return &investigate.Request{
		Model: "claude-opus-5-5", Effort: "high", System: "You investigate incidents.", CacheSystem: true, MaxTokens: 16000,
		Tools: []investigate.ToolDef{
			{Name: "get_logs", Description: "Read container logs.", InputSchema: json.RawMessage(schema)},
			{Name: "submit_report", Description: "Submit the report.", InputSchema: json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`), Strict: true},
		},
		Messages: []investigate.Message{{Role: investigate.RoleUser, Content: []investigate.Block{
			{Type: investigate.BlockText, Text: "Investigate this incident: <digest>", Cache: true}}}},
		Conversation: "20261016T120000Z-0001",
	}
}

func TestAnthropicRequestShape(t *testing.T) {
	f := newFake(t, streamOK(turnEvents("claude-opus-5-5", "tool_use"), "request-id", "req_011"))
	c, cs := anthropicClient(t, f, Config{EagerInputStreaming: true})
	resp, err := c.Send(context.Background(), firstRequest())
	if err != nil {
		t.Fatal(err)
	}
	reqs := f.requests()
	if len(reqs) != 1 {
		t.Fatalf("%d requests", len(reqs))
	}
	r := reqs[0]
	if r.method != http.MethodPost || r.path != "/v1/messages" || r.query != "beta=true" {
		t.Errorf("sent %s %s?%s", r.method, r.path, r.query)
	}
	for k, want := range map[string]string{"X-Api-Key": "sk-ant-test-key", "Anthropic-Version": "2023-06-01", "Accept": "application/json",
		"Content-Type": "application/json", "Anthropic-Beta": "server-side-fallback-2026-07-01"} {
		if got := r.header.Get(k); got != want {
			t.Errorf("header %s = %q, want %q", k, got, want)
		}
	}
	if r.header.Get("Authorization") != "" {
		t.Error("an Authorization header besides the API key")
	}
	body := r.json(t)
	if body["model"] != "claude-opus-5-5" || body["max_tokens"] != float64(16000) || body["stream"] != true {
		t.Errorf("model %v, max_tokens %v, stream %v", body["model"], body["max_tokens"], body["stream"])
	}
	if _, ok := body["thinking"]; ok {
		t.Error("a thinking field is sent: Claude Opus 5.5 always thinks, and disabling or budgeting it is a 400")
	}
	if body["fallbacks"] != "default" {
		t.Errorf("fallbacks = %v, want the server-side default", body["fallbacks"])
	}
	oc, _ := body["output_config"].(map[string]any)
	if oc["effort"] != "high" || oc["format"] != nil {
		t.Errorf("output_config = %v", oc)
	}
	sys := body["system"].([]any)
	if len(sys) != 1 || sys[0].(map[string]any)["text"] != "You investigate incidents." ||
		sys[0].(map[string]any)["cache_control"].(map[string]any)["type"] != "ephemeral" {
		t.Errorf("system = %v", sys)
	}
	tools := body["tools"].([]any)
	if len(tools) != 2 {
		t.Fatalf("tools = %v", tools)
	}
	logs, submit := tools[0].(map[string]any), tools[1].(map[string]any)
	if logs["name"] != "get_logs" || logs["description"] != "Read container logs." || logs["eager_input_streaming"] != true {
		t.Errorf("get_logs = %v", logs)
	}
	if _, ok := logs["strict"]; ok {
		t.Error("get_logs is not strict")
	}
	if submit["strict"] != true || submit["eager_input_streaming"] != true {
		t.Errorf("submit_report = %v", submit)
	}
	if !bytes.Contains(r.body, []byte(`"input_schema":`+schema)) {
		t.Errorf("the input schema is not sent as given:\n%s", r.body)
	}
	if tc := body["tool_choice"].(map[string]any); tc["type"] != "auto" {
		t.Errorf("tool_choice = %v", tc)
	}
	msgs := body["messages"].([]any)
	first := msgs[0].(map[string]any)["content"].([]any)[0].(map[string]any)
	if first["type"] != "text" || first["cache_control"].(map[string]any)["type"] != "ephemeral" {
		t.Errorf("first user block = %v", first)
	}
	if strings.Contains(string(r.body), "Conversation") || strings.Contains(string(r.body), "20261016T120000Z-0001") {
		t.Error("the conversation key is sent")
	}

	// The stream accumulated into the reply.
	if resp.StopReason != investigate.StopToolUse || resp.RequestID != "req_011" || resp.ServedBy != "" || resp.Refusal != nil {
		t.Errorf("stop %q, request id %q, served by %q, refusal %v", resp.StopReason, resp.RequestID, resp.ServedBy, resp.Refusal)
	}
	want := investigate.Usage{Input: 120, Output: 450, CacheRead: 30000, CacheWrite: 2000}
	if resp.Usage != want {
		t.Errorf("usage = %+v, want %+v", resp.Usage, want)
	}
	if len(resp.Content) != 3 {
		t.Fatalf("content = %+v", resp.Content)
	}
	th, tx, tu := resp.Content[0], resp.Content[1], resp.Content[2]
	if th.Type != investigate.BlockThinking || !strings.Contains(string(th.Raw), `"signature":"`+signature+`"`) {
		t.Errorf("thinking block %+v", th)
	}
	if tx.Type != investigate.BlockText || tx.Text != "Reading the logs first." || len(tx.Raw) == 0 {
		t.Errorf("text block %+v", tx)
	}
	if tu.Type != investigate.BlockToolUse || tu.ID != "toolu_01" || tu.Name != "get_logs" || string(tu.Input) != `{"level":"error"}` {
		t.Errorf("tool_use block %+v (input %s)", tu, tu.Input)
	}
	if got := cs.list(); len(got) != 1 || got[0] != "anthropic:200" {
		t.Errorf("counted %v", got)
	}
}

// The assistant's blocks go back unchanged on the next turn: the thinking
// block byte for byte, with the tool result (is_error, cache_control) after.
func TestRawBlocksRoundTrip(t *testing.T) {
	f := newFake(t, streamOK(turnEvents("claude-opus-5-5", "tool_use")))
	c, _ := anthropicClient(t, f, Config{})
	req := firstRequest()
	resp, err := c.Send(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	next := firstRequest()
	next.Messages[0].Content[0].Cache = false
	next.Messages = append(next.Messages,
		investigate.Message{Role: investigate.RoleAssistant, Content: resp.Content},
		investigate.Message{Role: investigate.RoleUser, Content: []investigate.Block{
			{Type: investigate.BlockToolResult, ToolUseID: "toolu_01", Content: "not permitted for the requesting user", IsError: true, Cache: true}}})
	if _, err := c.Send(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	r := f.requests()[1]
	if !bytes.Contains(r.body, resp.Content[0].Raw) {
		t.Fatalf("the thinking block is not sent back byte for byte:\nraw  %s\nbody %s", resp.Content[0].Raw, r.body)
	}
	msgs := r.json(t)["messages"].([]any)
	if len(msgs) != 3 {
		t.Fatalf("%d messages", len(msgs))
	}
	if first := msgs[0].(map[string]any)["content"].([]any)[0].(map[string]any); first["cache_control"] != nil {
		t.Error("the earlier user message keeps its cache breakpoint")
	}
	asst := msgs[1].(map[string]any)
	blocks := asst["content"].([]any)
	if asst["role"] != "assistant" || len(blocks) != 3 {
		t.Fatalf("assistant message = %v", asst)
	}
	th := blocks[0].(map[string]any)
	if th["type"] != "thinking" || th["signature"] != signature || th["thinking"] != "" {
		t.Errorf("thinking = %v", th)
	}
	if tx := blocks[1].(map[string]any); tx["type"] != "text" || tx["text"] != "Reading the logs first." || tx["cache_control"] != nil {
		t.Errorf("text = %v", tx)
	}
	tu := blocks[2].(map[string]any)
	if tu["type"] != "tool_use" || tu["id"] != "toolu_01" || tu["name"] != "get_logs" || tu["input"].(map[string]any)["level"] != "error" {
		t.Errorf("tool_use = %v", tu)
	}
	res := msgs[2].(map[string]any)["content"].([]any)[0].(map[string]any)
	content := res["content"].([]any)[0].(map[string]any)
	if res["type"] != "tool_result" || res["tool_use_id"] != "toolu_01" || res["is_error"] != true ||
		res["cache_control"].(map[string]any)["type"] != "ephemeral" || content["text"] != "not permitted for the requesting user" {
		t.Errorf("tool_result = %v", res)
	}
}

// The final turn keeps the tools declared, calls none and asks for the
// report as structured output.
func TestFinalTurnShape(t *testing.T) {
	f := newFake(t, streamOK([]event{
		{"message_start", `{"type":"message_start","message":{"id":"msg_2","type":"message","role":"assistant","model":"claude-opus-5-5","content":[],"stop_reason":null,"usage":{"input_tokens":5,"output_tokens":0}}}`},
		{"content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`},
		{"content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"{\"summary\":\"x\"}"}}`},
		{"content_block_stop", `{"type":"content_block_stop","index":0}`},
		{"message_delta", `{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":7}}`},
		{"message_stop", `{"type":"message_stop"}`},
	}))
	c, _ := anthropicClient(t, f, Config{})
	req := firstRequest()
	req.ToolChoiceNone = true
	req.OutputSchema = json.RawMessage(`{"type":"object","properties":{"summary":{"type":"string"}},"required":["summary"],"additionalProperties":false}`)
	resp, err := c.Send(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StopReason != investigate.StopEndTurn || resp.Content[0].Text != `{"summary":"x"}` {
		t.Errorf("reply %+v", resp)
	}
	r := f.requests()[0]
	body := r.json(t)
	if tc := body["tool_choice"].(map[string]any); tc["type"] != "none" {
		t.Errorf("tool_choice = %v", tc)
	}
	if tools := body["tools"].([]any); len(tools) != 2 {
		t.Errorf("tools are not kept declared: %v", tools)
	}
	oc := body["output_config"].(map[string]any)
	format := oc["format"].(map[string]any)
	if oc["effort"] != "high" || format["type"] != "json_schema" || !bytes.Contains(r.body, []byte(`"schema":`+string(req.OutputSchema))) {
		t.Errorf("output_config = %v", oc)
	}
	if _, ok := body["thinking"]; ok {
		t.Error("a thinking field is sent")
	}
}

func TestRefusalAndStopDetails(t *testing.T) {
	f := newFake(t, streamOK([]event{
		{"message_start", `{"type":"message_start","message":{"id":"msg_3","type":"message","role":"assistant","model":"claude-opus-5-5","content":[],"stop_reason":null,"usage":{"input_tokens":900,"output_tokens":0}}}`},
		{"message_delta", `{"type":"message_delta","delta":{"stop_reason":"refusal","stop_sequence":null,"stop_details":{"type":"refusal","category":"cyber","explanation":"This request was declined."}},"usage":{"output_tokens":0}}`},
		{"message_stop", `{"type":"message_stop"}`},
	}))
	c, _ := anthropicClient(t, f, Config{})
	resp, err := c.Send(context.Background(), firstRequest())
	if err != nil {
		t.Fatal(err)
	}
	if resp.StopReason != investigate.StopRefusal || resp.Refusal == nil || resp.Refusal.Category != "cyber" ||
		resp.Refusal.Explanation != "This request was declined." || len(resp.Content) != 0 || resp.ServedBy != "" {
		t.Errorf("refusal reply %+v (refusal %+v)", resp, resp.Refusal)
	}
}

// A refusal the server-side fallback served: the seam block and what the
// declining model left before it (thinking, an unanswered tool call) are
// dropped, the reply names the model that answered, and the usage counts
// every attempt.
func TestServerSideFallbackServed(t *testing.T) {
	f := newFake(t, streamOK([]event{
		{"message_start", `{"type":"message_start","message":{"id":"msg_4","type":"message","role":"assistant","model":"claude-opus-5-5","content":[],"stop_reason":null,"usage":{"input_tokens":10,"output_tokens":0}}}`},
		{"content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":"","signature":""}}`},
		{"content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"sigA"}}`},
		{"content_block_stop", `{"type":"content_block_stop","index":0}`},
		{"content_block_start", `{"type":"content_block_start","index":1,"content_block":{"type":"text","text":"Partial "}}`},
		{"content_block_stop", `{"type":"content_block_stop","index":1}`},
		{"content_block_start", `{"type":"content_block_start","index":2,"content_block":{"type":"tool_use","id":"toolu_cut","name":"get_logs","input":{}}}`},
		{"content_block_stop", `{"type":"content_block_stop","index":2}`},
		{"content_block_start", `{"type":"content_block_start","index":3,"content_block":{"type":"fallback","from":{"model":"claude-opus-5-5"},"to":{"model":"claude-opus-5"},"trigger":{"type":"refusal"}}}`},
		{"content_block_stop", `{"type":"content_block_stop","index":3}`},
		{"content_block_start", `{"type":"content_block_start","index":4,"content_block":{"type":"tool_use","id":"toolu_02","name":"get_logs","input":{}}}`},
		{"content_block_delta", `{"type":"content_block_delta","index":4,"delta":{"type":"input_json_delta","partial_json":"{}"}}`},
		{"content_block_stop", `{"type":"content_block_stop","index":4}`},
		{"message_delta", `{"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":40,"iterations":[` +
			`{"type":"message","model":"claude-opus-5-5","input_tokens":10,"output_tokens":5,"cache_read_input_tokens":100,"cache_creation_input_tokens":0},` +
			`{"type":"fallback_message","model":"claude-opus-5","input_tokens":12,"output_tokens":40,"cache_read_input_tokens":0,"cache_creation_input_tokens":300}]}}`},
		{"message_stop", `{"type":"message_stop"}`},
	}))
	c, _ := anthropicClient(t, f, Config{})
	resp, err := c.Send(context.Background(), firstRequest())
	if err != nil {
		t.Fatal(err)
	}
	if resp.ServedBy != "claude-opus-5" {
		t.Errorf("served by %q", resp.ServedBy)
	}
	var types []string
	for _, b := range resp.Content {
		types = append(types, b.Type+":"+b.ID)
	}
	if strings.Join(types, ",") != "text:,tool_use:toolu_02" {
		t.Errorf("content after trimming = %v", types)
	}
	if want := (investigate.Usage{Input: 22, Output: 45, CacheRead: 100, CacheWrite: 300}); resp.Usage != want {
		t.Errorf("usage = %+v, want %+v", resp.Usage, want)
	}
}

func TestFallbackSettings(t *testing.T) {
	for _, tc := range []struct {
		fallback, beta, fallbacks string
	}{
		{"off", "", ""},
		{"claude-opus-4-8", "server-side-fallback-2026-06-01", `[{"model":"claude-opus-4-8"}]`},
		{"auto", "server-side-fallback-2026-07-01", `"default"`},
	} {
		t.Run(tc.fallback, func(t *testing.T) {
			f := newFake(t, streamOK(turnEvents("claude-opus-5-5", "end_turn")))
			c, _ := anthropicClient(t, f, Config{Fallback: tc.fallback})
			if _, err := c.Send(context.Background(), firstRequest()); err != nil {
				t.Fatal(err)
			}
			r := f.requests()[0]
			if got := r.header.Get("Anthropic-Beta"); got != tc.beta {
				t.Errorf("anthropic-beta = %q, want %q", got, tc.beta)
			}
			var body map[string]json.RawMessage
			_ = json.Unmarshal(r.body, &body)
			if got := string(body["fallbacks"]); got != tc.fallbacks {
				t.Errorf("fallbacks = %s, want %s", got, tc.fallbacks)
			}
			if _, ok := body["eager_input_streaming"]; ok {
				t.Error("eager input streaming is a tool field")
			}
			if bytes.Contains(r.body, []byte("eager_input_streaming")) {
				t.Error("eager_input_streaming sent without being asked for")
			}
		})
	}
}

func TestRetriesHonourRetryAfter(t *testing.T) {
	f := newFake(t,
		errorReply(http.StatusTooManyRequests, `{"type":"error","error":{"type":"rate_limit_error","message":"Rate limited"}}`, "Retry-After", "1"),
		errorReply(529, `{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}`, "Retry-After", "0"),
		streamOK(turnEvents("claude-opus-5-5", "end_turn")))
	c, cs := anthropicClient(t, f, Config{})
	start := time.Now()
	resp, err := c.Send(context.Background(), firstRequest())
	if err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took < 900*time.Millisecond {
		t.Errorf("retried after %s: Retry-After: 1 was not honoured", took)
	}
	if resp.StopReason != investigate.StopEndTurn {
		t.Errorf("stop %q", resp.StopReason)
	}
	reqs := f.requests()
	if len(reqs) != 3 {
		t.Fatalf("%d requests, want 3", len(reqs))
	}
	if !bytes.Equal(reqs[0].body, reqs[2].body) {
		t.Error("a retry sent another body")
	}
	if got := strings.Join(cs.list(), ","); got != "anthropic:429,anthropic:529,anthropic:200" {
		t.Errorf("counted %s", got)
	}
}

func TestErrorsCarryNoBodies(t *testing.T) {
	const secret = "sk-ant-api03-SECRET-IN-BODY"
	f := newFake(t, errorReply(http.StatusBadRequest,
		`{"type":"error","error":{"type":"invalid_request_error","message":"messages.1: tool_use ids must be unique"},"echo":"`+secret+`"}`,
		"request-id", "req_bad"))
	c, cs := anthropicClient(t, f, Config{})
	_, err := c.Send(context.Background(), firstRequest())
	var ae *investigate.APIError
	if !errors.As(err, &ae) {
		t.Fatalf("err = %v (%T)", err, err)
	}
	if ae.Status != 400 || ae.Type != "invalid_request_error" || ae.Message != "messages.1: tool_use ids must be unique" || ae.Retryable {
		t.Errorf("api error %+v", ae)
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "echo") {
		t.Errorf("the error carries the body: %v", err)
	}
	if ae.Short() != "HTTP 400 invalid request" {
		t.Errorf("short = %q", ae.Short())
	}
	if n := len(f.requests()); n != 1 {
		t.Errorf("a 400 was retried: %d requests", n)
	}
	if got := cs.list(); len(got) != 1 || got[0] != "anthropic:400" {
		t.Errorf("counted %v", got)
	}
}

// An error event inside a stream that had started is sent again (the SDK
// retries only error statuses); the second failure is the answer.
func TestMidStreamErrorRetried(t *testing.T) {
	old := streamBackoff
	streamBackoff = time.Millisecond
	t.Cleanup(func() { streamBackoff = old })
	overloaded := streamOK([]event{
		{"message_start", `{"type":"message_start","message":{"id":"msg_5","type":"message","role":"assistant","model":"claude-opus-5-5","content":[],"stop_reason":null,"usage":{"input_tokens":1,"output_tokens":0}}}`},
		{"error", `{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}`},
	})
	f := newFake(t, overloaded, streamOK(turnEvents("claude-opus-5-5", "end_turn")))
	c, _ := anthropicClient(t, f, Config{})
	resp, err := c.Send(context.Background(), firstRequest())
	if err != nil {
		t.Fatal(err)
	}
	if resp.StopReason != investigate.StopEndTurn || len(f.requests()) != 2 {
		t.Errorf("stop %q after %d requests", resp.StopReason, len(f.requests()))
	}

	// Always overloaded: three attempts, then the error.
	f = newFake(t, overloaded)
	c, _ = anthropicClient(t, f, Config{})
	_, err = c.Send(context.Background(), firstRequest())
	var ae *investigate.APIError
	if !errors.As(err, &ae) || ae.Status != 529 || ae.Type != "overloaded_error" || !ae.Retryable {
		t.Fatalf("err = %v", err)
	}
	if n := len(f.requests()); n != 1+streamRetries {
		t.Errorf("%d attempts", n)
	}

	// A stream cut before message_stop is not a reply.
	cutShort := streamOK(turnEvents("claude-opus-5-5", "end_turn")[:4])
	f = newFake(t, cutShort)
	c, _ = anthropicClient(t, f, Config{})
	if _, err = c.Send(context.Background(), firstRequest()); !errors.Is(err, errStreamEnded) {
		t.Errorf("err = %v", err)
	}
}

func TestContextEnds(t *testing.T) {
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	f := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-block:
		case <-r.Context().Done():
		}
	})
	c, _ := anthropicClient(t, f, Config{})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := c.Send(ctx, firstRequest()); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v", err)
	}
}

func TestConfigChecks(t *testing.T) {
	if _, err := NewAnthropic(Config{}); err == nil {
		t.Error("no API key accepted")
	}
	if _, err := NewAnthropic(Config{APIKey: "k", Endpoint: "ftp://x"}); err == nil {
		t.Error("an ftp endpoint accepted")
	}
	c, err := NewAnthropic(Config{APIKey: "k"})
	if err != nil || c.Provider() != ProviderAnthropic || c.Fallback() != "server-side, default" {
		t.Errorf("client %v %v", c, err)
	}
	if _, err := c.Send(context.Background(), &investigate.Request{Model: "m", MaxTokens: 1,
		Messages: []investigate.Message{{Role: investigate.RoleAssistant, Content: []investigate.Block{{Type: "thinking"}}}}}); err == nil {
		t.Error("a thinking block without its raw JSON was sent")
	}
}

func TestPinsExpire(t *testing.T) {
	p := &pins{}
	now := time.Unix(1_760_000_000, 0)
	a := p.get("run-a", now)
	if p.get("run-a", now.Add(time.Minute)) != a {
		t.Error("a run gets another state")
	}
	p.get("run-b", now.Add(3*time.Hour))
	if p.count() != 1 || p.get("run-a", now.Add(3*time.Hour)) == a {
		t.Error("an idle pin was kept")
	}
}
