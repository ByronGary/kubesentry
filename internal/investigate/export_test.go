package investigate

import (
	"context"
	"time"

	"github.com/ByronGary/kubesentry/internal/incidents"
)

// Internals for the external tests (package investigate_test, which may
// import investigatetest).

var (
	ParseReport  = parseReport
	FinishReport = finishReport
	LogTemplate  = logTemplate
	Untrusted    = untrusted
	InputHash    = inputHash
	GateBundle   = gateBundle
)

// DigestStable is Egress.digest: the digest, the digest the cache key
// hashes, the ledger.
func DigestStable(e *Egress, b *incidents.Bundle, budget int) ([]byte, []byte, *Ledger) {
	return e.digest(b, budget)
}

// AgentResult is one loop run's outcome and progress.
type AgentResult struct {
	Status    Status
	Err       string
	Refusal   *Refusal
	Report    *Report
	Evidence  []Evidence
	Budget    string
	Steps     []Step
	Usage     Usage
	Turns     int
	ToolCalls int
	Ledger    *Ledger
}

// RunAgent runs the loop once without a service: the bundle gated by
// access, its digest, the tools over src.
func RunAgent(ctx context.Context, llm LLM, src Source, b *incidents.Bundle, access Access, o Options, now func() time.Time) AgentResult {
	o = o.WithDefaults()
	gateBundle(b, access)
	digest, _, led := defaultEgress.digest(b, o.DigestBytes)
	tb := &toolbox{src: src, egress: defaultEgress, access: access, inc: b.Incident, from: b.Window.From, to: b.Window.To,
		open: b.Incident.State == incidents.Open, now: now, ledger: led, timeout: o.ToolTimeout, bundleCT: b.CloudTrail}
	p := &progress{steps: []Step{}}
	a := &agent{llm: llm, tb: tb, o: o, now: now, p: p, digest: digest}
	ctx, cancel := context.WithTimeoutCause(ctx, o.Timeout, errTimeout)
	defer cancel()
	out := a.run(ctx)
	inv := &Investigation{}
	p.snapshot(inv)
	return AgentResult{Status: out.status, Err: out.err, Refusal: out.refusal, Report: out.report, Evidence: out.evidence,
		Budget: out.budget, Steps: inv.Steps, Usage: inv.Usage, Turns: inv.Turns, ToolCalls: inv.ToolCalls, Ledger: led}
}
