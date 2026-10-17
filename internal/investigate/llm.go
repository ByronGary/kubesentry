package investigate

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"
)

// LLM is a model the investigator talks to through the Messages API shape.
// internal/llm implements it over the Anthropic SDK (Anthropic API and
// Amazon Bedrock); investigatetest.ScriptedLLM replays scripted turns.
//
// Send is one request and one complete (non-streamed, or stream-accumulated)
// response. Implementations retry rate limits and overloads themselves and
// return *APIError for a response with an error status.
type LLM interface {
	// Provider names the backend: "anthropic", "bedrock" or "demo".
	Provider() string
	Send(ctx context.Context, req *Request) (*Response, error)
}

// Block types the loop reads and writes. Assistant replies may carry other
// types (thinking, redacted_thinking, …); they are kept and sent back as
// their Raw bytes.
const (
	BlockText       = "text"
	BlockToolUse    = "tool_use"
	BlockToolResult = "tool_result"
	BlockThinking   = "thinking"
)

// Roles.
const (
	RoleUser      = "user"
	RoleAssistant = "assistant"
)

// Stop reasons, as the Messages API names them.
const (
	StopEndTurn         = "end_turn"
	StopToolUse         = "tool_use"
	StopMaxTokens       = "max_tokens"
	StopRefusal         = "refusal"
	StopContextExceeded = "model_context_window_exceeded"
	StopPauseTurn       = "pause_turn"
	StopSequence        = "stop_sequence"
)

// Request is one Messages API call.
//
// The adapter maps it 1:1: Model; MaxTokens; System as one text block, with
// cache_control {type: ephemeral} when CacheSystem; Tools in order, each with
// input_schema and strict; tool_choice {type: auto}, or {type: none} when
// ToolChoiceNone; output_config.effort = Effort and, when OutputSchema is
// set, output_config.format = {type: json_schema, schema: OutputSchema}.
// No thinking field is sent (Claude Opus 5.5 always thinks adaptively) and
// the conversation never ends with an assistant message (no prefill).
type Request struct {
	Model       string    `json:"model"`
	Effort      string    `json:"effort,omitempty"`
	System      string    `json:"system"`
	CacheSystem bool      `json:"cacheSystem,omitempty"`
	Tools       []ToolDef `json:"tools"`
	Messages    []Message `json:"messages"`
	MaxTokens   int       `json:"maxTokens"`
	// ToolChoiceNone keeps the tools declared (changing them would break
	// the cache and the thinking blocks already sent) but lets the model
	// call none: the fallback final turn.
	ToolChoiceNone bool `json:"toolChoiceNone,omitempty"`
	// OutputSchema asks for a JSON reply matching it (structured output);
	// only on the fallback final turn.
	OutputSchema json.RawMessage `json:"outputSchema,omitempty"`
}

// ToolDef declares one tool.
type ToolDef struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
	// Strict asks the API to guarantee the input matches InputSchema.
	Strict bool `json:"strict,omitempty"`
}

// Message is one turn.
type Message struct {
	Role    string  `json:"role"`
	Content []Block `json:"content"`
}

// Block is one content block.
type Block struct {
	Type string `json:"type"`
	// Text of a text block.
	Text string `json:"text,omitempty"`
	// ID, Name and Input of a tool_use block.
	ID    string          `json:"id,omitempty"`
	Name  string          `json:"name,omitempty"`
	Input json.RawMessage `json:"input,omitempty"`
	// ToolUseID, Content and IsError of a tool_result block (Content is
	// sent as the block's string content).
	ToolUseID string `json:"tool_use_id,omitempty"`
	Content   string `json:"content,omitempty"`
	IsError   bool   `json:"is_error,omitempty"`
	// Raw is an assistant block exactly as the API returned it. When set,
	// the adapter sends these bytes back unchanged (thinking blocks carry a
	// signature that must round-trip byte for byte); the other fields are
	// then only what the loop reads.
	Raw json.RawMessage `json:"raw,omitempty"`
	// Cache puts a cache breakpoint (cache_control {type: ephemeral}) on
	// this block. The loop sets it on the last block of the newest user
	// message only; it never appears on assistant blocks.
	Cache bool `json:"cache,omitempty"`
}

// Response is the model's reply.
type Response struct {
	Content    []Block `json:"content"`
	StopReason string  `json:"stopReason"`
	// Refusal is set when StopReason is "refusal" (from stop_details).
	Refusal   *Refusal `json:"refusal,omitempty"`
	Usage     Usage    `json:"usage"`
	RequestID string   `json:"requestId,omitempty"`
}

// Refusal is the model declining (stop_reason "refusal", stop_details).
type Refusal struct {
	Category    string `json:"category"`
	Explanation string `json:"explanation"`
}

// Usage counts tokens. Input is uncached input; CacheRead and CacheWrite
// are the cache_read_input_tokens and cache_creation_input_tokens.
type Usage struct {
	Input      int64 `json:"input"`
	Output     int64 `json:"output"`
	CacheRead  int64 `json:"cacheRead"`
	CacheWrite int64 `json:"cacheWrite"`
}

// Total sums every kind, as the token budget counts them.
func (u Usage) Total() int64 { return u.Input + u.Output + u.CacheRead + u.CacheWrite }

// Add adds v to u.
func (u *Usage) Add(v Usage) {
	u.Input += v.Input
	u.Output += v.Output
	u.CacheRead += v.CacheRead
	u.CacheWrite += v.CacheWrite
}

// APIError is an error status from the provider. Message is at most 200
// bytes and never a response body: adapters build it from the status and
// the error type.
type APIError struct {
	Status    int
	Type      string // e.g. "overloaded_error", "rate_limit_error"
	Message   string
	Retryable bool
}

// NewAPIError returns an APIError with the message cleaned and cut to 200
// bytes.
func NewAPIError(status int, typ, msg string, retryable bool) *APIError {
	return &APIError{Status: status, Type: cut(clean(typ), 64), Message: cut(clean(msg), 200), Retryable: retryable}
}

func (e *APIError) Error() string {
	s := fmt.Sprintf("llm: HTTP %d", e.Status)
	if e.Type != "" {
		s += " " + e.Type
	}
	if e.Message != "" {
		s += ": " + e.Message
	}
	return s
}

// Short is the stored failure reason: "HTTP 529 overloaded".
func (e *APIError) Short() string {
	t := strings.TrimSuffix(e.Type, "_error")
	if t == "" {
		return fmt.Sprintf("HTTP %d", e.Status)
	}
	return fmt.Sprintf("HTTP %d %s", e.Status, strings.ReplaceAll(t, "_", " "))
}

// clean drops control characters and invalid UTF-8.
func clean(s string) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return -1
		}
		return r
	}, s)
}

// cut returns s cut to at most max bytes on a rune boundary.
func cut(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	i := max
	for i > 0 && !utf8.RuneStart(s[i]) {
		i--
	}
	return s[:i]
}
