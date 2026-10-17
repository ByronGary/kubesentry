package investigate

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Defaults (docs/contracts.md "AI investigator": the -investigator-* flags).
const (
	DefaultModel           = "claude-opus-5-5"
	DefaultEffort          = "high"
	DefaultMaxTurns        = 16
	DefaultMaxToolCalls    = 24
	DefaultMaxTokens       = 1_500_000
	DefaultMaxOutputTokens = 16_000
	DefaultTimeout         = 10 * time.Minute
	// maxOutputRetry caps the doubled output budget of a retried turn.
	maxOutputRetry = 32_000
	// maxInvalidReports is how many invalid reports are answered with the
	// validation error before the final turn.
	maxInvalidReports = 2
	// maxSteps bounds a run's progress list.
	maxSteps = 200
)

// Efforts the model takes.
var Efforts = []string{"low", "medium", "high", "xhigh", "max"}

// Options tune runs; zero values take the defaults.
type Options struct {
	Model  string
	Effort string
	// MaxTurns, MaxToolCalls and MaxTokens (every usage kind summed over
	// the run) are budgets: when one runs out, pending tool calls answer
	// "budget exhausted", the model gets one turn to submit its report, then
	// a final turn without tools and with the report schema as structured
	// output. So a run makes at most MaxTurns + 2 model calls (+1 for a
	// retried turn).
	MaxTurns     int
	MaxToolCalls int
	MaxTokens    int64
	// MaxOutputTokens caps each reply; a reply that hits it is retried once
	// with twice the cap (at most 32,000).
	MaxOutputTokens int
	// Timeout bounds a run; ToolTimeout each tool call.
	Timeout     time.Duration
	ToolTimeout time.Duration
	// DigestBytes is the digest budget.
	DigestBytes int
}

// WithDefaults fills in the zero values.
func (o Options) WithDefaults() Options {
	if o.Model == "" {
		o.Model = DefaultModel
	}
	if o.Effort == "" {
		o.Effort = DefaultEffort
	}
	if o.MaxTurns <= 0 {
		o.MaxTurns = DefaultMaxTurns
	}
	if o.MaxToolCalls <= 0 {
		o.MaxToolCalls = DefaultMaxToolCalls
	}
	if o.MaxTokens <= 0 {
		o.MaxTokens = DefaultMaxTokens
	}
	if o.MaxOutputTokens <= 0 {
		o.MaxOutputTokens = DefaultMaxOutputTokens
	}
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
	if o.ToolTimeout <= 0 {
		o.ToolTimeout = DefaultToolTimeout
	}
	if o.DigestBytes <= 0 {
		o.DigestBytes = DefaultDigestBytes
	}
	return o
}

// Validate reports options a run cannot use.
func (o Options) Validate() error {
	o = o.WithDefaults()
	if !contains(Efforts, o.Effort) {
		return fmt.Errorf("investigate: effort %q: want one of %s", o.Effort, strings.Join(Efforts, ", "))
	}
	if o.MaxOutputTokens > 128_000 {
		return fmt.Errorf("investigate: max output tokens %d: at most 128000", o.MaxOutputTokens)
	}
	if o.DigestBytes < 4<<10 || o.DigestBytes > 1<<20 {
		return fmt.Errorf("investigate: digest budget %d bytes: want 4 KiB to 1 MiB", o.DigestBytes)
	}
	return nil
}

// progress is a run's state as it is persisted: shared by the loop, the
// service's heartbeat and the final write.
type progress struct {
	mu        sync.Mutex
	steps     []Step
	usage     Usage
	turns     int
	toolCalls int
}

func (p *progress) step(s Step) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.steps) >= maxSteps {
		return
	}
	if len(p.steps) == maxSteps-1 {
		s = Step{At: s.At, Kind: StepNote, Text: "further steps are not recorded"}
	}
	p.steps = append(p.steps, s)
}

// snapshot copies the progress into inv.
func (p *progress) snapshot(inv *Investigation) {
	p.mu.Lock()
	defer p.mu.Unlock()
	inv.Steps = append([]Step(nil), p.steps...)
	inv.Usage, inv.Turns, inv.ToolCalls = p.usage, p.turns, p.toolCalls
}

// agentHooks feed metrics; any may be nil.
type agentHooks struct {
	onTokens func(Usage)
	onTool   func(tool, result string)
	// onTurn runs after each turn and each round of tool calls (the
	// service persists the progress).
	onTurn func()
}

// agent runs one investigation's loop.
type agent struct {
	llm    LLM
	tb     *toolbox
	o      Options
	now    func() time.Time
	p      *progress
	hooks  agentHooks
	defs   []ToolDef
	msgs   []Message
	calls  int // tool calls counted against the budget (submit_report excluded)
	digest []byte
}

// outcome is how a run ended.
type outcome struct {
	status   Status
	err      string
	refusal  *Refusal
	report   *Report
	evidence []Evidence
	// budget names the budget that ran out ("turns", "tool calls",
	// "tokens"), if one did.
	budget string
}

type phase int

const (
	phaseNormal phase = iota // tools allowed
	phaseWrapUp              // a budget ran out: one turn for submit_report
	phaseFinal               // no tools; the report as structured output
)

// Causes a run's context is cancelled with.
var (
	errCancelled = errors.New("investigate: cancelled by the starter")
	errShutdown  = errors.New("investigate: server shutting down")
	errStopped   = errors.New("investigate: the run was finished elsewhere")
	errTimeout   = errors.New("investigate: timeout")
)

func (a *agent) note(format string, args ...any) {
	a.p.step(Step{At: a.now(), Kind: StepNote, Text: fmt.Sprintf(format, args...)})
}

// request builds a request from the conversation, with cache breakpoints on
// the system block and on the last block of the newest user message (the
// stored conversation never carries them, so earlier messages are sent
// unchanged).
func (a *agent) request(ph phase, maxTokens int) *Request {
	msgs := make([]Message, len(a.msgs))
	copy(msgs, a.msgs)
	last := &msgs[len(msgs)-1]
	last.Content = append([]Block(nil), last.Content...)
	last.Content[len(last.Content)-1].Cache = true
	req := &Request{Model: a.o.Model, Effort: a.o.Effort, System: systemPrompt, CacheSystem: true, Tools: a.defs, Messages: msgs,
		MaxTokens: maxTokens}
	if ph == phaseFinal {
		req.ToolChoiceNone = true
		req.OutputSchema = ReportSchema()
	}
	return req
}

func userText(s string) Message {
	return Message{Role: RoleUser, Content: []Block{{Type: BlockText, Text: s}}}
}

// budgetSpent names the turn or token budget that is spent, if any.
func (a *agent) budgetSpent() string {
	a.p.mu.Lock()
	defer a.p.mu.Unlock()
	switch {
	case a.p.turns >= a.o.MaxTurns:
		return "turns"
	case a.p.usage.Total() >= a.o.MaxTokens:
		return "tokens"
	}
	return ""
}

func (a *agent) footer() string {
	a.p.mu.Lock()
	turns := a.p.turns
	a.p.mu.Unlock()
	return fmt.Sprintf("\n[tool calls left: %d of %d; turns left: %d of %d]", max(a.o.MaxToolCalls-a.calls, 0), a.o.MaxToolCalls,
		max(a.o.MaxTurns-turns, 0), a.o.MaxTurns)
}

// run drives the conversation until a report, a refusal, a failure or the
// context's end.
func (a *agent) run(ctx context.Context) outcome {
	a.defs = ToolDefs()
	a.msgs = []Message{userText(firstMessage(a.digest, a.o))}
	ph := phaseNormal
	nudged := false
	invalidReports := 0
	maxTokens := a.o.MaxOutputTokens
	retried := false
	budget := ""
	for {
		if ctx.Err() != nil {
			return a.stopped(ctx, budget)
		}
		resp, err := a.send(ctx, a.request(ph, maxTokens))
		if err != nil {
			if ctx.Err() != nil {
				return a.stopped(ctx, budget)
			}
			var ae *APIError
			if errors.As(err, &ae) {
				return outcome{status: Failed, err: ae.Short(), budget: budget}
			}
			return outcome{status: Failed, err: "model request failed", budget: budget}
		}
		switch resp.StopReason {
		case StopRefusal:
			r := resp.Refusal
			if r == nil {
				r = &Refusal{}
			}
			r = &Refusal{Category: cut(clean(r.Category), 64), Explanation: defaultEgress.Line(r.Explanation, 1000)}
			a.note("the model declined to continue (%s)", orDash(r.Category))
			return outcome{status: Refused, refusal: r, budget: budget}
		case StopMaxTokens:
			if !retried && maxTokens < maxOutputRetry {
				retried = true
				maxTokens = min(2*maxTokens, maxOutputRetry)
				a.note("the reply hit the output limit; retrying the turn with %d tokens", maxTokens)
				continue
			}
			a.note("the reply hit the output limit of %d tokens again", maxTokens)
			return outcome{status: Failed, err: "max_tokens: the reply exceeded the output limit", budget: budget}
		case StopContextExceeded:
			if ph == phaseFinal {
				return outcome{status: Failed, err: "context window exceeded", budget: budget}
			}
			a.note("the conversation reached the context window; asking for the final report")
			ph = phaseFinal
			a.msgs = append(a.msgs, userText(finalText))
			continue
		}
		retried = false

		if ph == phaseFinal {
			var text strings.Builder
			for _, b := range resp.Content {
				if b.Type == BlockText {
					text.WriteString(b.Text)
				}
			}
			r, err := parseReport([]byte(text.String()))
			if err != nil {
				a.note("the final report was not valid: %s", defaultEgress.Line(err.Error(), 200))
				msg := "no valid report"
				if budget != "" {
					msg = "budget: " + budget
				}
				return outcome{status: Failed, err: msg, budget: budget}
			}
			return a.complete(r, "final report received", budget)
		}

		a.msgs = append(a.msgs, Message{Role: RoleAssistant, Content: resp.Content})
		var uses []Block
		for _, b := range resp.Content {
			if b.Type == BlockToolUse {
				uses = append(uses, b)
			}
		}
		if len(uses) == 0 {
			switch {
			case ph == phaseNormal && a.budgetSpent() != "":
				budget = a.budgetSpent()
				a.note("budget spent: %s; asking for the report", budget)
				ph = phaseWrapUp
				a.msgs = append(a.msgs, userText(fmt.Sprintf(budgetText, budget)))
			case ph == phaseWrapUp || nudged:
				a.note("no report submitted; asking for the final report without tools")
				ph = phaseFinal
				a.msgs = append(a.msgs, userText(finalText))
			default:
				nudged = true
				a.note("the model stopped without a report; reminding it to submit one")
				a.msgs = append(a.msgs, userText(nudgeText))
			}
			a.persist()
			continue
		}

		// Submitted reports first: a valid one ends the run.
		results := make([]Block, len(uses))
		done := make([]bool, len(uses))
		for i, u := range uses {
			if u.Name != ToolSubmitReport {
				continue
			}
			a.countCall(false)
			r, err := parseReport(u.Input)
			if err == nil {
				a.toolStep(ToolSubmitReport, ResultOK, "submit_report: report submitted")
				return a.complete(r, "", budget)
			}
			invalidReports++
			msg := defaultEgress.Line(err.Error(), 1000)
			a.toolStep(ToolSubmitReport, ResultInvalid, "submit_report: invalid report")
			results[i] = Block{Type: BlockToolResult, ToolUseID: u.ID, Content: "invalid report: " + msg + a.footer(), IsError: true}
			done[i] = true
		}

		// Then the other calls, in parallel, within the budgets.
		spent := ""
		if ph == phaseNormal {
			spent = a.budgetSpent()
		}
		type pending struct {
			i int
			u Block
		}
		var run []pending
		for i, u := range uses {
			if done[i] {
				continue
			}
			if ph != phaseNormal || spent != "" || a.calls >= a.o.MaxToolCalls {
				if ph == phaseNormal && spent == "" {
					spent = "tool calls"
				}
				a.countCall(false)
				name := u.Name
				if toolsByName[name] == nil {
					name = "unknown tool"
				}
				a.toolStep(u.Name, ResultError, name+": budget exhausted")
				results[i] = Block{Type: BlockToolResult, ToolUseID: u.ID, Content: budgetExhausted, IsError: true}
				continue
			}
			a.countCall(true)
			run = append(run, pending{i, u})
		}
		res := make([]toolResult, len(run))
		var wg sync.WaitGroup
		for k, pc := range run {
			wg.Add(1)
			go func() {
				defer wg.Done()
				res[k] = a.tb.run(ctx, pc.u.Name, pc.u.Input)
			}()
		}
		wg.Wait()
		for k, pc := range run {
			r := res[k]
			a.toolStep(pc.u.Name, r.result, r.step)
			results[pc.i] = Block{Type: BlockToolResult, ToolUseID: pc.u.ID, Content: r.content + a.footer(), IsError: r.isError}
		}
		if ctx.Err() != nil {
			return a.stopped(ctx, budget)
		}

		next := Message{Role: RoleUser, Content: results}
		switch {
		case ph == phaseNormal && spent != "":
			budget = spent
			a.note("budget spent: %s; asking for the report", spent)
			ph = phaseWrapUp
			next.Content = append(next.Content, Block{Type: BlockText, Text: fmt.Sprintf(budgetText, spent)})
		case ph == phaseWrapUp:
			a.note("no valid report after the budget ran out; asking for the final report without tools")
			ph = phaseFinal
			next.Content = append(next.Content, Block{Type: BlockText, Text: finalText})
		case invalidReports > maxInvalidReports:
			a.note("%d invalid reports; asking for the final report without tools", invalidReports)
			ph = phaseFinal
			next.Content = append(next.Content, Block{Type: BlockText, Text: finalText})
		}
		a.msgs = append(a.msgs, next)
		a.persist()
	}
}

func orDash(s string) string {
	if s == "" {
		return "no category"
	}
	return s
}

// send makes one model call and accounts for it.
func (a *agent) send(ctx context.Context, req *Request) (*Response, error) {
	resp, err := a.llm.Send(ctx, req)
	a.p.mu.Lock()
	a.p.turns++
	n := a.p.turns
	if resp != nil {
		a.p.usage.Add(resp.Usage)
	}
	a.p.mu.Unlock()
	if resp != nil && a.hooks.onTokens != nil {
		a.hooks.onTokens(resp.Usage)
	}
	if err != nil {
		a.p.step(Step{At: a.now(), Kind: StepTurn, Text: fmt.Sprintf("turn %d: model request failed", n), Result: ResultError})
		return nil, err
	}
	what := "no tool call"
	calls := 0
	for _, b := range resp.Content {
		if b.Type == BlockToolUse {
			calls++
		}
	}
	switch {
	case resp.StopReason == StopRefusal:
		what = "declined"
	case resp.StopReason == StopMaxTokens:
		what = "hit the output limit"
	case resp.StopReason == StopContextExceeded:
		what = "reached the context window"
	case req.ToolChoiceNone:
		what = "final report"
	case calls > 0:
		what = plural(calls, "tool call", "tool calls")
	}
	a.p.step(Step{At: a.now(), Kind: StepTurn, Text: fmt.Sprintf("turn %d: %s (%d tokens)", n, what, resp.Usage.Total())})
	a.persist()
	return resp, nil
}

func (a *agent) countCall(budgeted bool) {
	a.p.mu.Lock()
	a.p.toolCalls++
	a.p.mu.Unlock()
	if budgeted {
		a.calls++
	}
}

func (a *agent) toolStep(tool, result, text string) {
	if toolsByName[tool] == nil { // a name the model made up is not stored
		tool = ""
	}
	a.p.step(Step{At: a.now(), Kind: StepTool, Tool: tool, Text: defaultEgress.Line(text, 200), Result: result})
	if a.hooks.onTool != nil {
		t := tool
		if t == "" {
			t = "unknown"
		}
		a.hooks.onTool(t, result)
	}
}

func (a *agent) persist() {
	if a.hooks.onTurn != nil {
		a.hooks.onTurn()
	}
}

// complete validates and caps the report and builds the evidence index.
func (a *agent) complete(r *Report, note, budget string) outcome {
	rep, ev := finishReport(r, a.tb.ledger, a.tb.egress, a.tb.from, a.tb.to)
	if note != "" {
		a.note("%s", note)
	}
	return outcome{status: Completed, report: rep, evidence: ev, budget: budget}
}

// stopped is the outcome of a run whose context ended.
func (a *agent) stopped(ctx context.Context, budget string) outcome {
	cause := context.Cause(ctx)
	switch {
	case errors.Is(cause, errCancelled):
		a.note("cancelled by the starter")
		return outcome{status: Cancelled, budget: budget}
	case errors.Is(cause, errTimeout), errors.Is(cause, context.DeadlineExceeded):
		a.note("the investigation ran out of time")
		return outcome{status: Failed, err: "timeout", budget: budget}
	}
	return outcome{status: Failed, err: "interrupted", budget: budget}
}
