// Package investigatetest provides ScriptedLLM, a deterministic model for
// tests and the demo: it replays scripted turns, can build its report from
// the refs the tool results showed it, records every request it was sent,
// and can refuse, run out of output tokens, fail or send malformed tool
// input on cue.
package investigatetest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/ByronGary/kubesentry/internal/investigate"
)

// Turn produces one reply to a request.
type Turn func(ctx context.Context, req *investigate.Request) (*investigate.Response, error)

// ScriptedLLM replays its turns in order. It is safe for concurrent use.
type ScriptedLLM struct {
	// Name is the provider it reports ("demo" when empty).
	Name string
	// After answers once the script is used up (nil: an error).
	After Turn

	mu       sync.Mutex
	turns    []Turn
	next     int
	ids      int
	requests []*investigate.Request
}

// New returns a model that replays turns.
func New(turns ...Turn) *ScriptedLLM { return &ScriptedLLM{turns: turns} }

// Provider implements investigate.LLM.
func (s *ScriptedLLM) Provider() string {
	if s.Name == "" {
		return "demo"
	}
	return s.Name
}

// ErrScriptDone is returned once the script is used up and After is nil.
var ErrScriptDone = errors.New("investigatetest: the script has no more turns")

// Send implements investigate.LLM: it records a copy of req and plays the
// next turn.
func (s *ScriptedLLM) Send(ctx context.Context, req *investigate.Request) (*investigate.Response, error) {
	cp := CloneRequest(req)
	s.mu.Lock()
	s.requests = append(s.requests, cp)
	var t Turn
	if s.next < len(s.turns) {
		t = s.turns[s.next]
		s.next++
	} else {
		t = s.After
	}
	s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if t == nil {
		return nil, ErrScriptDone
	}
	resp, err := t(ctx, cp)
	if resp != nil {
		s.mu.Lock()
		for i := range resp.Content {
			if b := &resp.Content[i]; b.Type == investigate.BlockToolUse && b.ID == "" {
				s.ids++
				b.ID = fmt.Sprintf("toolu_%03d", s.ids)
			}
		}
		s.mu.Unlock()
	}
	return resp, err
}

// Requests returns copies of the requests sent so far.
func (s *ScriptedLLM) Requests() []*investigate.Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*investigate.Request(nil), s.requests...)
}

// Calls is how many requests were sent.
func (s *ScriptedLLM) Calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requests)
}

// DefaultUsage is what each scripted reply reports unless WithUsage says.
var DefaultUsage = investigate.Usage{Input: 100, Output: 50}

// Call is one tool call of a scripted reply.
type Call struct {
	Name string
	// Input is marshalled as the call's input; RawInput, when set, is sent
	// as is (malformed input).
	Input    any
	RawInput string
}

func reply(stop string, blocks ...investigate.Block) *investigate.Response {
	return &investigate.Response{Content: blocks, StopReason: stop, Usage: DefaultUsage, RequestID: "req_scripted"}
}

func toolUse(c Call) investigate.Block {
	raw := []byte(c.RawInput)
	if c.RawInput == "" {
		in := c.Input
		if in == nil {
			in = map[string]any{}
		}
		raw, _ = json.Marshal(in)
	}
	return investigate.Block{Type: investigate.BlockToolUse, Name: c.Name, Input: raw}
}

// Tools replies with tool calls (in parallel when there are several).
func Tools(calls ...Call) Turn {
	return func(context.Context, *investigate.Request) (*investigate.Response, error) {
		var blocks []investigate.Block
		for _, c := range calls {
			blocks = append(blocks, toolUse(c))
		}
		return reply(investigate.StopToolUse, blocks...), nil
	}
}

// Text ends the turn with text and no tool call.
func Text(s string) Turn {
	return func(context.Context, *investigate.Request) (*investigate.Response, error) {
		return reply(investigate.StopEndTurn, investigate.Block{Type: investigate.BlockText, Text: s}), nil
	}
}

// Submit calls submit_report with report.
func Submit(report any) Turn {
	return Tools(Call{Name: investigate.ToolSubmitReport, Input: report})
}

// SubmitFromRefs calls submit_report with the report build makes from the
// refs the conversation has shown so far (see RefsIn).
func SubmitFromRefs(build func(refs []string) any) Turn {
	return func(ctx context.Context, req *investigate.Request) (*investigate.Response, error) {
		return Submit(build(RefsIn(req)))(ctx, req)
	}
}

// Final answers the final turn (tools off, report schema) with the report
// as JSON text.
func Final(report any) Turn {
	return func(context.Context, *investigate.Request) (*investigate.Response, error) {
		b, err := json.Marshal(report)
		if err != nil {
			return nil, err
		}
		return reply(investigate.StopEndTurn, investigate.Block{Type: investigate.BlockText, Text: string(b)}), nil
	}
}

// Refuse declines, as a safety classifier would.
func Refuse(category, explanation string) Turn {
	return func(context.Context, *investigate.Request) (*investigate.Response, error) {
		r := reply(investigate.StopRefusal)
		r.Refusal = &investigate.Refusal{Category: category, Explanation: explanation}
		return r, nil
	}
}

// Stop replies with no content and the given stop reason (max_tokens,
// model_context_window_exceeded, …).
func Stop(reason string) Turn {
	return func(context.Context, *investigate.Request) (*investigate.Response, error) {
		return reply(reason, investigate.Block{Type: investigate.BlockText, Text: "…"}), nil
	}
}

// Fail returns err.
func Fail(err error) Turn {
	return func(context.Context, *investigate.Request) (*investigate.Response, error) { return nil, err }
}

// Hang waits for the context to end (a slow model, for timeouts and
// cancellation).
func Hang() Turn {
	return func(ctx context.Context, _ *investigate.Request) (*investigate.Response, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
}

// Gate waits for release (or the context) before playing t.
func Gate(release <-chan struct{}, t Turn) Turn {
	return func(ctx context.Context, req *investigate.Request) (*investigate.Response, error) {
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return t(ctx, req)
	}
}

// WithUsage makes t report u.
func WithUsage(t Turn, u investigate.Usage) Turn {
	return func(ctx context.Context, req *investigate.Request) (*investigate.Response, error) {
		r, err := t(ctx, req)
		if r != nil {
			r.Usage = u
		}
		return r, err
	}
}

// WithThinking puts a thinking block before t's content, as the API returns
// it: raw is the block's JSON, which must come back byte for byte.
func WithThinking(t Turn, raw string) Turn {
	return func(ctx context.Context, req *investigate.Request) (*investigate.Response, error) {
		r, err := t(ctx, req)
		if r != nil {
			b := investigate.Block{Type: investigate.BlockThinking, Raw: json.RawMessage(raw)}
			r.Content = append([]investigate.Block{b}, r.Content...)
		}
		return r, err
	}
}

var refRe = regexp.MustCompile(`"ref":"([^"\\]+)"`)

// RefsIn returns the refs the conversation showed the model (in the user
// messages: the digest and the tool results), first seen first.
func RefsIn(req *investigate.Request) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range req.Messages {
		if m.Role != investigate.RoleUser {
			continue
		}
		for _, b := range m.Content {
			for _, s := range []string{b.Text, b.Content} {
				for _, mm := range refRe.FindAllStringSubmatch(s, -1) {
					if !seen[mm[1]] {
						seen[mm[1]] = true
						out = append(out, mm[1])
					}
				}
			}
		}
	}
	return out
}

// ToolResults returns the tool_result blocks of the newest user message.
func ToolResults(req *investigate.Request) []investigate.Block {
	var out []investigate.Block
	if n := len(req.Messages); n > 0 && req.Messages[n-1].Role == investigate.RoleUser {
		for _, b := range req.Messages[n-1].Content {
			if b.Type == investigate.BlockToolResult {
				out = append(out, b)
			}
		}
	}
	return out
}

// RequestText is every string a request carries, for leak checks: the
// system prompt, the tool declarations, every block's text, input, result
// and raw bytes.
func RequestText(req *investigate.Request) string {
	var b strings.Builder
	w := func(s string) { b.WriteString(s); b.WriteByte('\n') }
	w(req.Model)
	w(req.System)
	w(string(req.OutputSchema))
	for _, t := range req.Tools {
		w(t.Name)
		w(t.Description)
		w(string(t.InputSchema))
	}
	for _, m := range req.Messages {
		for _, bl := range m.Content {
			w(bl.Text)
			w(bl.Name)
			w(string(bl.Input))
			w(bl.Content)
			w(string(bl.Raw))
		}
	}
	return b.String()
}

// CloneRequest copies a request deeply; byte fields are copied as bytes
// (never re-encoded), so raw blocks compare byte for byte.
func CloneRequest(req *investigate.Request) *investigate.Request {
	cp := *req
	bytesOf := func(b []byte) []byte {
		if b == nil {
			return nil
		}
		return append([]byte{}, b...)
	}
	cp.OutputSchema = bytesOf(req.OutputSchema)
	cp.Tools = make([]investigate.ToolDef, len(req.Tools))
	for i, t := range req.Tools {
		t.InputSchema = bytesOf(t.InputSchema)
		cp.Tools[i] = t
	}
	cp.Messages = make([]investigate.Message, len(req.Messages))
	for i, m := range req.Messages {
		c := make([]investigate.Block, len(m.Content))
		for j, b := range m.Content {
			b.Input = bytesOf(b.Input)
			b.Raw = bytesOf(b.Raw)
			c[j] = b
		}
		cp.Messages[i] = investigate.Message{Role: m.Role, Content: c}
	}
	return &cp
}

// Report is a valid report whose root cause cites refs.
func Report(refs ...string) map[string]any {
	ev := append([]string{}, refs...)
	timeline := []any{}
	return map[string]any{
		"summary":              "The api container ran out of memory after the 12:00 deploy.",
		"status":               investigate.LikelyCause,
		"root_cause":           map[string]any{"statement": "A memory leak in the new release.", "confidence": "medium", "evidence": ev},
		"contributing_factors": []any{},
		"timeline":             timeline,
		"impact":               "Requests failed for about ten minutes.",
		"suggested_checks":     []any{map[string]any{"description": "Look at the pods.", "command": "kubectl get pods -n shop"}},
		"remediation_ideas":    []any{map[string]any{"description": "Roll back the deploy.", "risk": "Loses the new features."}},
		"open_questions":       []any{},
		"data_gaps":            []any{},
	}
}
