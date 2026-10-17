// Package llm is the AI investigator's model adapter: it implements
// investigate.LLM over the official Anthropic Go SDK, on the Anthropic API
// (NewAnthropic) and on Amazon Bedrock (NewBedrock: the bedrock-mantle
// Messages API or bedrock-runtime InvokeModel). It is the only package that
// imports github.com/anthropics/anthropic-sdk-go (and, with internal/aws/**,
// internal/awsauth and internal/cloudwatch, the AWS SDK).
//
// Every request is streamed and its events are accumulated into the final
// message, so long effort-high turns never sit on an idle connection. The
// SDK retries 408, 409, 429, 5xx and 529 answers, honouring Retry-After;
// an error that arrives mid-stream is retried here. Prompts, tool results
// and response bodies are never logged, and errors carry only the status,
// the error type and the API's short message.
package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/lib/betafallback"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/anthropics/anthropic-sdk-go/packages/param"
	"github.com/anthropics/anthropic-sdk-go/shared/constant"

	"github.com/ByronGary/kubesentry/internal/investigate"
	"github.com/ByronGary/kubesentry/internal/metrics"
)

// Providers, Bedrock APIs and fallback settings (docs/contracts.md "AI
// investigator": -investigator, -investigator-bedrock-api,
// -investigator-fallback).
const (
	ProviderAnthropic = "anthropic"
	ProviderBedrock   = "bedrock"

	// BedrockMantle is the Messages API on bedrock-mantle.<region>.api.aws
	// (IAM bedrock-mantle:CreateInference); BedrockRuntime is InvokeModel
	// on bedrock-runtime.<region>.amazonaws.com (IAM
	// bedrock:InvokeModelWithResponseStream).
	BedrockMantle  = "mantle"
	BedrockRuntime = "runtime"

	// FallbackAuto retries a refused turn on the model Anthropic
	// recommends: the server-side "default" fallback on the Anthropic API,
	// and on Bedrock the SDK's client-side middleware with Claude Opus 5
	// (the model ID derived from a Claude Opus 5.5 one). FallbackOff
	// stores a refusal as it is. Any other value names the fallback model.
	FallbackAuto = "auto"
	FallbackOff  = "off"

	DefaultAnthropicModel = "claude-opus-5-5"
	DefaultBedrockModel   = "anthropic.claude-opus-5-5"

	// DefaultTimeout bounds one HTTP attempt, the whole stream included;
	// the investigation has its own deadline.
	DefaultTimeout = 10 * time.Minute
	// DefaultMaxRetries is how often the SDK retries an attempt.
	DefaultMaxRetries = 3
	// streamRetries is how often a turn whose stream failed part-way
	// (overloaded, ended early) is sent again.
	streamRetries = 2
)

// Config configures a Client.
type Config struct {
	// APIKey is the Anthropic API key (NewAnthropic; ANTHROPIC_API_KEY,
	// read by cmd/server from the environment only).
	APIKey string
	// Endpoint replaces the base URL: a proxy, a VPC endpoint or a test
	// server. For Bedrock Mantle it includes the /anthropic path.
	Endpoint string
	// Region is the Bedrock region (NewBedrock).
	Region string
	// BedrockAPI is BedrockMantle (default) or BedrockRuntime.
	BedrockAPI string
	// Model is the model the investigator asks for; on Bedrock it decides
	// the automatic fallback model.
	Model string
	// Fallback is FallbackAuto (""), FallbackOff or a model ID.
	Fallback string
	// EagerInputStreaming sets eager_input_streaming on every tool, so tool
	// inputs stream as they are generated. Only for the Anthropic API
	// itself (not a proxy, not Bedrock's Claude Opus 5.5 serving stack).
	EagerInputStreaming bool
	// Timeout bounds one HTTP attempt (DefaultTimeout); MaxRetries is the
	// SDK's retries of one (DefaultMaxRetries; negative: none).
	Timeout    time.Duration
	MaxRetries int
	// HTTPClient sends the requests; nil uses a client whose transport
	// honours HTTPS_PROXY and NO_PROXY.
	HTTPClient *http.Client
	// OnRequest counts every HTTP attempt (kubesentry_llm_requests_total);
	// nil uses internal/metrics. code is the status, or "error".
	OnRequest func(provider, code string)
}

func (c Config) timeout() time.Duration {
	if c.Timeout <= 0 {
		return DefaultTimeout
	}
	return c.Timeout
}

func (c Config) retries() int {
	switch {
	case c.MaxRetries < 0:
		return 0
	case c.MaxRetries == 0:
		return DefaultMaxRetries
	}
	return c.MaxRetries
}

func (c Config) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	// No client-wide timeout: it would cut streams. Each attempt has
	// its own (Timeout), the run its deadline.
	return &http.Client{Transport: http.DefaultTransport.(*http.Transport).Clone()}
}

// common are the options both providers share: the HTTP client, the
// retries and timeout, and the middlewares in order (outermost first).
func (c Config) common(mws ...option.Middleware) []option.RequestOption {
	return []option.RequestOption{
		option.WithHTTPClient(c.httpClient()),
		option.WithMaxRetries(c.retries()),
		option.WithRequestTimeout(c.timeout()),
		option.WithMiddleware(mws...),
	}
}

// counter counts every attempt that reaches the transport, retries and
// fallback hops included.
func counter(provider string, inc func(provider, code string)) option.Middleware {
	if inc == nil {
		inc = func(p, code string) { metrics.LLMRequests.With(p, code).Inc() }
	}
	return func(r *http.Request, next option.MiddlewareNext) (*http.Response, error) {
		res, err := next(r)
		code := "error"
		if res != nil {
			code = strconv.Itoa(res.StatusCode)
		}
		inc(provider, code)
		return res, err
	}
}

// Client is investigate.LLM over the SDK's beta Messages API (the surface
// the refusal fallbacks are on).
type Client struct {
	provider string
	msgs     *anthropic.BetaMessageService
	eager    bool
	// fallbacks and betas are the server-side fallback (Anthropic API).
	fallbacks anthropic.BetaFallbacksParamUnion
	betas     []anthropic.AnthropicBeta
	// pins keeps each run on the model that accepted it when the fallback
	// is the client-side middleware (Bedrock).
	pins     *pins
	fallback string // what Describe says about it
	now      func() time.Time
}

var _ investigate.LLM = (*Client)(nil)

// NewAnthropic returns a client of the Anthropic API.
func NewAnthropic(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, errors.New("llm: the Anthropic API needs an API key (ANTHROPIC_API_KEY)")
	}
	opts := append([]option.RequestOption{option.WithoutEnvironmentDefaults(), option.WithAPIKey(cfg.APIKey)},
		cfg.common(counter(ProviderAnthropic, cfg.OnRequest))...)
	if cfg.Endpoint != "" {
		if err := checkEndpoint(cfg.Endpoint); err != nil {
			return nil, err
		}
		opts = append(opts, option.WithBaseURL(cfg.Endpoint))
	}
	client := anthropic.NewClient(opts...)
	c := &Client{provider: ProviderAnthropic, msgs: &client.Beta.Messages, eager: cfg.EagerInputStreaming, now: time.Now}
	switch fb := strings.TrimSpace(cfg.Fallback); fb {
	case "", FallbackAuto:
		c.fallbacks = anthropic.BetaFallbacksParamUnion{OfDefault: constant.ValueOf[constant.Default]()}
		c.betas = []anthropic.AnthropicBeta{anthropic.AnthropicBetaServerSideFallback2026_07_01}
		c.fallback = "server-side, default"
	case FallbackOff:
		c.fallback = FallbackOff
	default:
		c.fallbacks = anthropic.BetaFallbacksParamUnion{OfBetaFallbackArray: []anthropic.BetaFallbackParam{{Model: anthropic.Model(fb)}}}
		c.betas = []anthropic.AnthropicBeta{anthropic.AnthropicBetaServerSideFallback2026_06_01}
		c.fallback = "server-side, " + fb
	}
	return c, nil
}

// checkEndpoint accepts an http(s) URL.
func checkEndpoint(s string) error {
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Errorf("llm: endpoint %q: want an http(s) URL", s)
	}
	return nil
}

// Provider implements investigate.LLM.
func (c *Client) Provider() string { return c.provider }

// Fallback describes the refusal fallback in force, for the startup log.
func (c *Client) Fallback() string { return c.fallback }

// Send implements investigate.LLM: one streamed request, accumulated.
func (c *Client) Send(ctx context.Context, req *investigate.Request) (*investigate.Response, error) {
	params, err := c.params(req)
	if err != nil {
		return nil, err
	}
	var opts []option.RequestOption
	if c.pins != nil && req.Conversation != "" {
		opts = append(opts, betafallback.WithBetaFallbackState(c.pins.get(req.Conversation, c.now())))
	}
	for attempt := 0; ; attempt++ {
		resp, err := c.stream(ctx, params, opts)
		if err == nil || attempt >= streamRetries || !retryStream(err) || ctx.Err() != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return resp, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(attempt+1) * streamBackoff):
		}
	}
}

// streamBackoff is the wait before the first resend of a failed stream
// (twice as long before the second).
var streamBackoff = 2 * time.Second

// errStreamEnded is a stream that stopped before message_stop.
var errStreamEnded = errors.New("llm: the response stream ended early")

// streamError is an error event inside a stream that had started.
type streamError struct{ *investigate.APIError }

func (e *streamError) Unwrap() error { return e.APIError }

func retryStream(err error) bool {
	var se *streamError
	return errors.Is(err, errStreamEnded) || (errors.As(err, &se) && se.Retryable)
}

func (c *Client) stream(ctx context.Context, params anthropic.BetaMessageNewParams, opts []option.RequestOption) (*investigate.Response, error) {
	var res *http.Response
	opts = append(opts[:len(opts):len(opts)], option.WithResponseInto(&res))
	s := c.msgs.NewStreaming(ctx, params, opts...)
	defer s.Close()
	var msg anthropic.BetaMessage
	for s.Next() {
		if err := msg.Accumulate(s.Current()); err != nil {
			return nil, errors.New("llm: the response stream was malformed")
		}
	}
	if err := s.Err(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, apiError(err)
	}
	if msg.StopReason == "" {
		return nil, errStreamEnded
	}
	return response(&msg, requestID(res)), nil
}

func requestID(res *http.Response) string {
	if res == nil {
		return ""
	}
	for _, h := range []string{"request-id", "x-amzn-requestid"} {
		if v := res.Header.Get(h); v != "" {
			return cut(v, 128)
		}
	}
	return ""
}

// ---- request ----

// params maps a request to the SDK's: one system block (cached when asked),
// the tools with their schemas as given, tool_choice auto (none on the
// final turn), output_config with the effort and the report schema, and
// no thinking field (Claude Opus 5.5 always thinks adaptively).
func (c *Client) params(req *investigate.Request) (anthropic.BetaMessageNewParams, error) {
	p := anthropic.BetaMessageNewParams{Model: anthropic.Model(req.Model), MaxTokens: int64(req.MaxTokens),
		Fallbacks: c.fallbacks, Betas: c.betas}
	if req.System != "" {
		sys := anthropic.BetaTextBlockParam{Text: req.System}
		if req.CacheSystem {
			sys.CacheControl = anthropic.NewBetaCacheControlEphemeralParam()
		}
		p.System = []anthropic.BetaTextBlockParam{sys}
	}
	for _, t := range req.Tools {
		if !json.Valid(t.InputSchema) {
			return p, fmt.Errorf("llm: tool %s: the input schema is not JSON", t.Name)
		}
		tp := anthropic.BetaToolParam{Name: t.Name,
			InputSchema: param.Override[anthropic.BetaToolInputSchemaParam](json.RawMessage(t.InputSchema))}
		if t.Description != "" {
			tp.Description = anthropic.String(t.Description)
		}
		if t.Strict {
			tp.Strict = anthropic.Bool(true)
		}
		if c.eager {
			tp.EagerInputStreaming = anthropic.Bool(true)
		}
		p.Tools = append(p.Tools, anthropic.BetaToolUnionParam{OfTool: &tp})
	}
	if len(p.Tools) > 0 {
		if req.ToolChoiceNone {
			p.ToolChoice = anthropic.BetaToolChoiceUnionParam{OfNone: &anthropic.BetaToolChoiceNoneParam{}}
		} else {
			p.ToolChoice = anthropic.BetaToolChoiceUnionParam{OfAuto: &anthropic.BetaToolChoiceAutoParam{}}
		}
	}
	if req.Effort != "" {
		p.OutputConfig.Effort = anthropic.BetaOutputConfigEffort(req.Effort)
	}
	if len(req.OutputSchema) > 0 {
		if !json.Valid(req.OutputSchema) {
			return p, errors.New("llm: the output schema is not JSON")
		}
		p.OutputConfig.Format = anthropic.BetaJSONOutputFormatParam{Schema: json.RawMessage(req.OutputSchema)}
	}
	for i, m := range req.Messages {
		mp := anthropic.BetaMessageParam{Role: anthropic.BetaMessageParamRole(m.Role)}
		for j, b := range m.Content {
			bp, err := block(b)
			if err != nil {
				return p, fmt.Errorf("llm: message %d block %d: %w", i, j, err)
			}
			mp.Content = append(mp.Content, bp)
		}
		p.Messages = append(p.Messages, mp)
	}
	return p, nil
}

// block maps one content block. An assistant block with Raw goes back as
// the API returned it: thinking and redacted thinking byte for byte (their
// signature binds them), text and tool use through the SDK's own round
// trip (ToParam, which leaves out response-only fields).
func block(b investigate.Block) (anthropic.BetaContentBlockParamUnion, error) {
	if len(b.Raw) > 0 {
		var u anthropic.BetaContentBlockUnion
		if err := u.UnmarshalJSON(b.Raw); err != nil {
			return anthropic.BetaContentBlockParamUnion{}, errors.New("the raw block is not JSON")
		}
		switch u.Type {
		case "thinking", "redacted_thinking":
			return param.Override[anthropic.BetaContentBlockParamUnion](json.RawMessage(b.Raw)), nil
		}
		return u.ToParam(), nil
	}
	var cc anthropic.BetaCacheControlEphemeralParam
	if b.Cache {
		cc = anthropic.NewBetaCacheControlEphemeralParam()
	}
	switch b.Type {
	case investigate.BlockText:
		return anthropic.BetaContentBlockParamUnion{OfText: &anthropic.BetaTextBlockParam{Text: b.Text, CacheControl: cc}}, nil
	case investigate.BlockToolUse:
		input := b.Input
		if len(input) == 0 {
			input = json.RawMessage(`{}`)
		}
		if !json.Valid(input) {
			return anthropic.BetaContentBlockParamUnion{}, errors.New("the tool input is not JSON")
		}
		return anthropic.BetaContentBlockParamUnion{OfToolUse: &anthropic.BetaToolUseBlockParam{ID: b.ID, Name: b.Name, Input: input}}, nil
	case investigate.BlockToolResult:
		tr := anthropic.BetaToolResultBlockParam{ToolUseID: b.ToolUseID, CacheControl: cc}
		if b.Content != "" {
			tr.Content = []anthropic.BetaToolResultBlockParamContentUnion{{OfText: &anthropic.BetaTextBlockParam{Text: b.Content}}}
		}
		if b.IsError {
			tr.IsError = anthropic.Bool(true)
		}
		return anthropic.BetaContentBlockParamUnion{OfToolResult: &tr}, nil
	}
	return anthropic.BetaContentBlockParamUnion{}, fmt.Errorf("a %q block needs its raw JSON", b.Type)
}

// ---- response ----

// response maps the accumulated message: its blocks (each with its raw
// JSON, refusal-fallback seams trimmed), the stop reason and refusal, the
// usage of every attempt, and the model that answered when a fallback did.
func response(msg *anthropic.BetaMessage, reqID string) *investigate.Response {
	blocks, seam := trimFallback(msg.Content)
	out := &investigate.Response{StopReason: string(msg.StopReason), RequestID: reqID, Content: []investigate.Block{}}
	for _, b := range blocks {
		ib := investigate.Block{Type: b.Type}
		if raw := b.RawJSON(); raw != "" {
			ib.Raw = json.RawMessage(raw)
		}
		switch b.Type {
		case investigate.BlockText:
			ib.Text = b.Text
		case investigate.BlockToolUse:
			ib.ID, ib.Name = b.ID, b.Name
			ib.Input = append(json.RawMessage(nil), b.Input...)
		}
		out.Content = append(out.Content, ib)
	}
	if msg.StopReason == anthropic.BetaStopReasonRefusal {
		out.Refusal = &investigate.Refusal{Category: string(msg.StopDetails.Category), Explanation: msg.StopDetails.Explanation}
	}
	u := msg.Usage
	out.Usage = investigate.Usage{Input: u.InputTokens, Output: u.OutputTokens, CacheRead: u.CacheReadInputTokens,
		CacheWrite: u.CacheCreationInputTokens}
	served := seam
	if len(u.Iterations) > 0 {
		// Every attempt of a fallback chain: the top-level usage covers
		// only the one that produced the message.
		var sum investigate.Usage
		for _, it := range u.Iterations {
			sum.Add(investigate.Usage{Input: it.InputTokens, Output: it.OutputTokens, CacheRead: it.CacheReadInputTokens,
				CacheWrite: it.CacheCreationInputTokens})
			if it.Type == "fallback_message" {
				served = true
			}
		}
		out.Usage = sum
	}
	if served && msg.StopReason != anthropic.BetaStopReasonRefusal {
		out.ServedBy = string(msg.Model)
	}
	return out
}

// trimFallback drops what a refusal fallback leaves in a message that
// must not go back to the API: the fallback seam blocks, and before the
// last seam everything of the model that declined but its text (thinking,
// and tool calls that will never get a result). It reports whether there
// was a seam.
func trimFallback(content []anthropic.BetaContentBlockUnion) ([]anthropic.BetaContentBlockUnion, bool) {
	last := -1
	for i, b := range content {
		if b.Type == "fallback" {
			last = i
		}
	}
	if last < 0 {
		return content, false
	}
	var out []anthropic.BetaContentBlockUnion
	for i, b := range content {
		switch {
		case b.Type == "fallback":
		case i < last && b.Type != investigate.BlockText:
		default:
			out = append(out, b)
		}
	}
	return out, true
}

// ---- errors ----

// apiError maps an SDK error to *investigate.APIError (an error status, or
// an error event inside the stream, then wrapped in *streamError), and
// anything else to an error without response bodies.
func apiError(err error) error {
	var ae *anthropic.Error
	if errors.As(err, &ae) {
		typ := string(ae.Type())
		msg := shortMessage(ae.RawJSON())
		if typ == "" && ae.Response != nil {
			typ, _, _ = strings.Cut(ae.Response.Header.Get("X-Amzn-Errortype"), ":")
		}
		status := ae.StatusCode
		if status < 400 { // an error event in a stream that had started
			status = statusOf(typ)
			return &streamError{investigate.NewAPIError(status, typ, msg, retryable(status))}
		}
		return investigate.NewAPIError(status, typ, msg, retryable(status))
	}
	if raw, ok := strings.CutPrefix(err.Error(), "received error while streaming: "); ok {
		var env struct {
			Error struct{ Type string } `json:"error"`
		}
		_ = json.Unmarshal([]byte(raw), &env)
		status := statusOf(env.Error.Type)
		return &streamError{investigate.NewAPIError(status, env.Error.Type, shortMessage(raw), retryable(status))}
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("llm: %s %s: %w", ue.Op, redactURL(ue.URL), ue.Err)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return errors.New("llm: the request failed")
}

// redactURL keeps the scheme, host and path of a request URL.
func redactURL(s string) string {
	u, err := url.Parse(s)
	if err != nil {
		return "the provider"
	}
	return u.Scheme + "://" + u.Host + u.Path
}

// shortMessage is the error's message from an error body, nothing else:
// {"error": {"message"}} (Anthropic) or {"message"} (AWS).
func shortMessage(body string) string {
	var env struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
		Message string `json:"message"`
	}
	if json.Unmarshal([]byte(body), &env) != nil {
		return ""
	}
	if env.Error.Message != "" {
		return env.Error.Message
	}
	return env.Message
}

// statusOf is the status an error type of a stream stands for.
func statusOf(typ string) int {
	t := strings.ToLower(typ)
	switch {
	case t == "overloaded_error":
		return 529
	case t == "rate_limit_error", strings.Contains(t, "throttl"):
		return http.StatusTooManyRequests
	case t == "invalid_request_error", strings.Contains(t, "validation"):
		return http.StatusBadRequest
	case t == "authentication_error":
		return http.StatusUnauthorized
	case t == "permission_error", strings.Contains(t, "accessdenied"):
		return http.StatusForbidden
	case t == "not_found_error":
		return http.StatusNotFound
	case t == "request_too_large":
		return http.StatusRequestEntityTooLarge
	case t == "timeout_error", strings.Contains(t, "timeout"):
		return http.StatusGatewayTimeout
	case strings.Contains(t, "serviceunavailable"):
		return http.StatusServiceUnavailable
	}
	return http.StatusInternalServerError
}

func retryable(status int) bool {
	return status == http.StatusRequestTimeout || status == http.StatusConflict || status == http.StatusTooManyRequests || status >= 500
}

func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// ---- client-side fallback pins ----

// pinIdle is how long a run's pin is kept after its last request (a run
// lasts at most -investigator-timeout).
const pinIdle = 2 * time.Hour

// pins keeps one fallback state per run, so a run that a fallback model
// served stays on it, as the server-side fallback's sticky routing does.
type pins struct {
	mu sync.Mutex
	m  map[string]*pin
}

type pin struct {
	state *betafallback.BetaFallbackState
	used  time.Time
}

func (p *pins) get(conv string, now time.Time) *betafallback.BetaFallbackState {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.m == nil {
		p.m = map[string]*pin{}
	}
	for k, v := range p.m {
		if now.Sub(v.used) > pinIdle {
			delete(p.m, k)
		}
	}
	e := p.m[conv]
	if e == nil {
		e = &pin{state: &betafallback.BetaFallbackState{}}
		p.m[conv] = e
	}
	e.used = now
	return e.state
}

func (p *pins) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.m)
}
