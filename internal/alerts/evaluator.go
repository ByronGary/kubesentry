package alerts

import (
	"context"
	"fmt"
	"maps"
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/snapshot"
	"github.com/ByronGary/kubesentry/internal/uilink"
)

// DefaultRunbookURL is where each alert's runbook_url points, plus
// "#<alert name in lower case>".
const DefaultRunbookURL = "https://github.com/ByronGary/kubesentry/blob/main/docs/alerts.md"

// BoardWindow is how long resolved findings stay on the board (and in GET
// /api/v1/alerts).
const BoardWindow = 24 * time.Hour

// Options configures an Evaluator. Zero values take the defaults shown.
type Options struct {
	// Resend: an open alert is posted again this often, with endsAt this
	// many times 4 ahead, so Alertmanager keeps it while kubesentry runs and
	// lets it expire if kubesentry stops. Default 1m.
	Resend time.Duration
	// ResolveGrace: a finding that has not been seen for this long resolves
	// (and Alertmanager gets endsAt=now). It keeps one that blinks out of a
	// single view from flapping. Default 5m.
	ResolveGrace time.Duration
	// MaxNew: when more new alerts than this would fire in one evaluation,
	// they go out as one digest alert per owner instead. Default 50. It also
	// bounds how many digested findings that turned critical leave their
	// digest in one evaluation.
	MaxNew int
	// OwnerMaxNew and OwnerWindow: one owner gets at most OwnerMaxNew new
	// alerts on their own in any OwnerWindow (a sliding window, in the
	// leader's memory); further new findings join that owner's digest.
	// Defaults 20 and 15m.
	OwnerMaxNew int
	OwnerWindow time.Duration
	// MaxSilence is the longest silence Runner.Act sets. Default
	// DefaultMaxSilence; never more than MaxSilenceCap.
	MaxSilence time.Duration
	// DefaultOwner owns findings whose namespace names no owner, and
	// cluster-scoped ones. Default "platform".
	DefaultOwner string
	// LeakCritHours: a leak reaching its memory limit sooner is critical.
	// Zero uses the view's policy (-leak-crit-hours).
	LeakCritHours float64
	// ExternalURL is kubesentry's address as users reach it; each alert links
	// to its finding's page there (kubesentry_url). Empty leaves the link out.
	ExternalURL string
	// RunbookURL is the runbook page; default DefaultRunbookURL.
	RunbookURL string
	// Cluster, when set, labels every alert (cluster), so one Alertmanager
	// can serve several clusters without merging their alerts.
	Cluster string
	// DriftHold is how long an RBAC drift alert stays open while the new
	// object exists; it then resolves and the object counts as standing
	// state. Default 24h.
	DriftHold time.Duration
	// IncidentOf returns the ID of the incident the finding's current
	// episode (its Key and FirstSeen) has joined, or "". With ExternalURL,
	// the alert then links to it (the incident_url annotation). Nil links
	// nothing; Runner.SetIncidentLookup sets it late.
	IncidentOf func(f *Finding) string
	// Disabled checks are not run (-alerts-disable-checks; cmd/server adds
	// the audit checks -alerts-audit leaves out, and agent-missing when it is
	// off): their findings resolve, and a change-based check keeps its
	// baseline as it was.
	Disabled map[string]bool
	// Audit configures the audit checks (Input.Audit reads the store).
	Audit AuditOptions
	// AgentDaemonSet is the agent DaemonSet, "namespace/name"
	// (-agent-daemonset), whose nodes the agent-missing check expects
	// reports from (Input.Agents); "" runs no agent check.
	AgentDaemonSet string
	// Digests schedules the standing-state digests; off by default.
	Digests DigestOptions
	// Now is the clock; default time.Now.
	Now func() time.Time
}

// AnnotationIncidentURL is the annotation linking an alert to the incident
// its episode joined. It is an annotation, never a label: a label change
// would retire the alert in Alertmanager.
const AnnotationIncidentURL = "incident_url"

// Annotations an acknowledged or silenced finding's alerts carry (added when
// sent, never stored with the finding).
const (
	AnnotationAckBy         = "acknowledged_by"
	AnnotationAckAt         = "acknowledged_at"
	AnnotationSilencedBy    = "silenced_by"
	AnnotationSilencedUntil = "silenced_until"
	AnnotationSilenceReason = "silence_reason"
)

// Why storm protection put a finding in its owner's digest
// (Result.Digested, kubesentry_alerts_digested_total{reason}).
const (
	DigestMaxNew      = "max_new"      // more than MaxNew new alerts at once
	DigestOwnerBudget = "owner_budget" // the owner's OwnerMaxNew per OwnerWindow is spent
)

func (o *Options) defaults() {
	if o.Resend <= 0 {
		o.Resend = time.Minute
	}
	if o.ResolveGrace < 0 {
		o.ResolveGrace = 0
	} else if o.ResolveGrace == 0 {
		o.ResolveGrace = 5 * time.Minute
	}
	if o.MaxNew <= 0 {
		o.MaxNew = 50
	}
	if o.OwnerMaxNew <= 0 {
		o.OwnerMaxNew = 20
	}
	if o.OwnerWindow <= 0 {
		o.OwnerWindow = 15 * time.Minute
	}
	if o.MaxSilence <= 0 {
		o.MaxSilence = DefaultMaxSilence
	}
	o.MaxSilence = min(o.MaxSilence, MaxSilenceCap)
	if o.DefaultOwner == "" {
		o.DefaultOwner = "platform"
	}
	if o.RunbookURL == "" {
		o.RunbookURL = DefaultRunbookURL
	}
	if o.DriftHold <= 0 {
		o.DriftHold = 24 * time.Hour
	}
	o.Audit.defaults()
	o.Digests.defaults()
	if o.Now == nil {
		o.Now = time.Now
	}
}

// Alert is one alert as Alertmanager's v2 API takes it (postableAlert).
type Alert struct {
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations,omitempty"`
	StartsAt     time.Time         `json:"startsAt"`
	EndsAt       time.Time         `json:"endsAt"`
	GeneratorURL string            `json:"generatorURL,omitempty"`
}

// Sink delivers alerts. Send must not block: it queues, and drops what does
// not fit.
type Sink interface {
	Send(alerts []Alert)
	// Drop forgets everything queued: leadership was lost, so another
	// replica notifies now.
	Drop()
	Status() SinkStatus
}

// SinkStatus describes a sink for /info and metrics.
type SinkStatus struct {
	Name      string // "alertmanager" or "none"
	LastSent  time.Time
	LastError string // why the latest delivery failed, while it still fails
	Queued    int
}

// NopSink sends nothing: alerts are tracked (and listed by the API) but
// nobody is notified.
type NopSink struct{}

func (NopSink) Send([]Alert)       {}
func (NopSink) Drop()              {}
func (NopSink) Status() SinkStatus { return SinkStatus{Name: "none"} }

// Result describes one evaluation.
type Result struct {
	Candidates int
	New        int // findings opened
	Resolved   int
	Open       int // findings not resolved after the evaluation
	Sent       int // alerts handed to the sink
	// Digest is set when storm protection put new findings in a digest;
	// Digested counts them by reason (DigestMaxNew, DigestOwnerBudget), and
	// Promoted the digested findings that turned critical and left it.
	Digest   bool
	Digested map[string]int
	Promoted int
	// Baselined lists the change-based checks that recorded their first
	// baseline (and so notified nothing).
	Baselined []string
	// OpenBy counts the findings not resolved by check and severity.
	OpenBy map[[2]string]int
	// StandingDigests counts the standing digest alerts sent, by kind (one
	// per owner).
	StandingDigests map[string]int
	// Warnings are problems that did not stop the evaluation (an audit read
	// failed: those checks were skipped).
	Warnings []string
}

// Evaluator diffs each view's findings against the stored ones and
// notifies. It holds the findings in memory between evaluations: one
// Evaluator serves one leadership term (Load reads the store when it
// starts). It is not safe for concurrent use.
type Evaluator struct {
	o     Options
	store Store
	sink  Sink

	loaded    bool
	state     map[string]*Finding
	persisted map[string]time.Time // LastSeen as last written
	baselines map[string]map[string]bool
	pending   map[string]time.Time   // candidates waiting out their check's pending time
	digests   map[string]digestState // by owner: the digests firing
	// log is the actions log, read from the store at every evaluation (the
	// runner shares its own, so Act and the API see the same).
	log *actionLog
	// fired holds, per owner, when each new alert went out on its own
	// within OwnerWindow (the per-owner budget).
	fired map[string][]time.Time
	// promote holds digested findings that turned critical, waiting to
	// leave their digest (at most MaxNew per evaluation).
	promote map[string]bool
	// audit runs the audit checks for this leadership term.
	audit *AuditWatch
	// digestRuns is when each standing digest was last sent (the store's);
	// digestSince is when this evaluator first loaded: a digest never sent
	// waits for the first scheduled time after it.
	digestRuns  map[string]time.Time
	digestSince time.Time
}

// digestState is one owner's digest while it fires.
type digestState struct{ sent, start time.Time }

// NewEvaluator returns an evaluator writing to store and notifying sink.
func NewEvaluator(store Store, sink Sink, o Options) *Evaluator {
	o.defaults()
	if sink == nil {
		sink = NopSink{}
	}
	return &Evaluator{o: o, store: store, sink: sink, pending: map[string]time.Time{}, digests: map[string]digestState{},
		log: newActionLog(), fired: map[string][]time.Time{}, promote: map[string]bool{}, audit: NewAuditWatch(o.Audit),
		digestRuns: map[string]time.Time{}}
}

// enabledAudit is the audit checks this evaluator runs.
func (e *Evaluator) enabledAudit() map[string]bool {
	out := map[string]bool{}
	for _, c := range AuditChecks() {
		if !e.o.Disabled[c] {
			out[c] = true
		}
	}
	return out
}

// runChecks runs every check over in: the view's (run), then the audit
// checks, whose events the evaluator's AuditWatch remembers; disabled
// checks are left out.
func (e *Evaluator) runChecks(ctx context.Context, in Input, res *Result) Found {
	ro := runOptions{leakCritHours: e.o.LeakCritHours, agentDaemonSet: e.o.AgentDaemonSet}
	if e.o.Digests.has(DigestCertificates) {
		ro.quietCertDays = e.o.Digests.CertDays
	}
	if e.o.Disabled[CheckAgentMissing] {
		ro.agentDaemonSet = ""
	}
	found := run(in, ro)
	if enabled := e.enabledAudit(); len(enabled) > 0 {
		if in.Audit == nil {
			for c := range enabled {
				found.Skipped[c] = true
			}
		} else {
			nss := namespaceInfo(in.View)
			failed, err := e.audit.Poll(ctx, in.Audit, enabled, func(ns string) bool { return nss[ns].production }, in.Now)
			if err != nil {
				res.Warnings = append(res.Warnings, err.Error())
			}
			for c := range failed {
				found.Skipped[c] = true
			}
			found.Candidates = append(found.Candidates, e.audit.Candidates(in.Now, failed)...)
		}
	}
	if len(e.o.Disabled) > 0 {
		kept := found.Candidates[:0]
		for _, c := range found.Candidates {
			if !e.o.Disabled[c.Check] {
				kept = append(kept, c)
			}
		}
		found.Candidates = kept
	}
	sortCandidates(found.Candidates)
	return found
}

// Load reads the stored findings and baselines. Evaluate calls it when
// needed; a failed commit makes the next evaluation load again.
func (e *Evaluator) Load(ctx context.Context) error {
	fs, err := e.store.Load(ctx, e.o.Now().Add(-BoardWindow))
	if err != nil {
		return err
	}
	bl, err := e.store.Baselines(ctx)
	if err != nil {
		return err
	}
	runs, err := e.store.DigestRuns(ctx)
	if err != nil {
		return err
	}
	e.digestRuns = runs
	if e.digestRuns == nil {
		e.digestRuns = map[string]time.Time{}
	}
	e.state = make(map[string]*Finding, len(fs))
	e.persisted = make(map[string]time.Time, len(fs))
	for i := range fs {
		f := fs[i]
		e.state[f.Key] = &f
		e.persisted[f.Key] = f.LastSeen
	}
	e.digests = map[string]digestState{} // re-post the digests at once
	e.baselines = make(map[string]map[string]bool, len(bl))
	for check, keys := range bl {
		set := make(map[string]bool, len(keys))
		for _, k := range keys {
			set[k] = true
		}
		e.baselines[check] = set
	}
	e.loaded = true
	return nil
}

// Evaluate runs the checks over in and moves every finding along its
// lifecycle: new ones open and fire (or go into a digest when there are
// more than MaxNew, or their owner's budget is spent), open and
// acknowledged ones are posted again every Resend, silenced ones are ended
// once and then left alone until the silence ends, gone ones resolve after
// ResolveGrace. The actions log is read first, so an action any replica
// recorded applies here. Writes are committed before anything is sent, so a
// replica whose commit fails (it lost the lock) notifies nothing.
func (e *Evaluator) Evaluate(ctx context.Context, in Input) (Result, error) {
	if in.Now.IsZero() {
		in.Now = e.o.Now()
	}
	now := in.Now
	loaded := false
	if !e.loaded {
		if err := e.Load(ctx); err != nil {
			return Result{}, fmt.Errorf("alerts: load: %w", err)
		}
		loaded = true
	}
	if e.digestSince.IsZero() {
		e.digestSince = now
	}
	if err := e.log.sync(ctx, e.store, now); err != nil {
		return Result{}, fmt.Errorf("alerts: read actions: %w", err)
	}
	if loaded {
		// The store keeps states, not who acknowledged: take the
		// acknowledgements as they stand, so a new leader does not re-post
		// every acknowledged alert at once. Transitions into and out of a
		// silence still compare with the stored state.
		for k, f := range e.state {
			g := *f
			applyMarks(&g, e.log.mark(k), now)
			f.AckBy, f.AckAt = g.AckBy, g.AckAt
		}
	}
	res := Result{OpenBy: map[[2]string]int{}, Digested: map[string]int{}, StandingDigests: map[string]int{}}
	found := e.runChecks(ctx, in, &res)
	nss := namespaceInfo(in.View)
	owners := objectOwners(in.View)
	res.Candidates = len(found.Candidates)

	// What every finding was before this evaluation: transitions into and
	// out of a silence, and acknowledgements, notify.
	prevState := make(map[string]State, len(e.state))
	prevAck := make(map[string]string, len(e.state))
	for k, f := range e.state {
		prevState[k], prevAck[k] = f.State, ackSig(f)
	}

	// Change-based checks: only what is not in the baseline fires; what
	// fired stays open for DriftHold while it exists.
	current := map[string]map[string]bool{}
	for check, info := range checkInfos {
		if info.changeBased && !found.Skipped[check] && !e.o.Disabled[check] {
			current[check] = map[string]bool{}
		}
	}
	var present []Candidate
	for _, c := range found.Candidates {
		info := checkInfos[c.Check]
		if !info.changeBased {
			present = append(present, c)
			continue
		}
		k := c.Key()
		current[c.Check][k] = true
		base, recorded := e.baselines[c.Check]
		if !recorded {
			continue // the first baseline is recorded, not notified
		}
		f := e.state[k]
		held := f != nil && !f.Resolved() && now.Sub(f.FirstSeen) < e.o.DriftHold
		if base[k] && !held {
			continue
		}
		present = append(present, c)
	}
	newBaselines := map[string][]string{}
	for check, set := range current {
		if _, recorded := e.baselines[check]; !recorded {
			res.Baselined = append(res.Baselined, check)
		} else if maps.Equal(set, e.baselines[check]) {
			continue
		}
		keys := make([]string, 0, len(set))
		for k := range set {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		newBaselines[check] = keys
	}
	sort.Strings(res.Baselined)

	// Pending: a candidate must be seen for its check's pending time first.
	seen := map[string]bool{}
	var active []Candidate
	firstSeen := map[string]time.Time{}
	for _, c := range present {
		k := c.Key()
		seen[k] = true
		if f := e.state[k]; f != nil && !f.Resolved() {
			active = append(active, c)
			continue
		}
		since := now
		if p := checkInfos[c.Check].pending; p > 0 {
			s, ok := e.pending[k]
			if !ok {
				e.pending[k] = now
				s = now
			}
			if now.Sub(s) < p {
				continue
			}
			since = s
		}
		// As Postgres keeps it, so the episode (key@firstSeen) reads the same
		// on every replica, whether from this memory or from the store.
		firstSeen[k] = NormalTime(since)
		active = append(active, c)
	}
	for k := range e.pending {
		if !seen[k] {
			delete(e.pending, k)
		}
	}

	// Diff against the findings.
	dirty := map[string]bool{}
	fireNow := map[string]bool{}
	var out []Alert
	var opened, unquiet []*Finding
	activeKeys := make(map[string]bool, len(active))
	for _, c := range active {
		k := c.Key()
		activeKeys[k] = true
		nf := e.build(c, nss, owners, in.View)
		f := e.state[k]
		if f == nil || f.Resolved() {
			nf.State, nf.FirstSeen, nf.LastSeen = StateOpen, firstSeen[k], now
			e.linkIncident(&nf, nil)
			e.state[k] = &nf
			dirty[k] = true
			opened = append(opened, &nf)
			continue
		}
		// Before the comparison below, so a link that stays the same is no
		// change.
		nf.FirstSeen = f.FirstSeen
		e.linkIncident(&nf, f)
		if f.Digest && f.Severity != SeverityCritical && nf.Severity == SeverityCritical {
			e.promote[k] = true // turned critical: it leaves the digest (below)
		}
		if f.Quiet && !nf.Quiet && f.LastNotified == nil && !f.Digest {
			unquiet = append(unquiet, f) // crossed the threshold: new to Alertmanager, so storm protection counts it
		}
		// Is it firing on its own in Alertmanager now?
		alone := f.LastNotified != nil && !f.Digest && !f.Quiet && f.State != StateSilenced
		if !maps.Equal(f.Labels, nf.Labels) {
			// Alertmanager knows an alert by its labels: retire the old set.
			if alone {
				out = append(out, e.alertOf(f, now))
			}
			fireNow[k] = true
		} else if alone && nf.Quiet {
			out = append(out, e.alertOf(f, now)) // quiet from now on: end it
		}
		if f.Alert != nf.Alert || f.Kind != nf.Kind || f.Severity != nf.Severity || f.Title != nf.Title || f.Owner != nf.Owner ||
			f.Production != nf.Production || f.Link != nf.Link || f.Quiet != nf.Quiet ||
			!maps.Equal(f.Labels, nf.Labels) || !maps.Equal(f.Annotations, nf.Annotations) {
			f.Alert, f.Kind, f.Severity, f.Title, f.Owner, f.Production = nf.Alert, nf.Kind, nf.Severity, nf.Title, nf.Owner, nf.Production
			f.Labels, f.Annotations, f.Link, f.Quiet = nf.Labels, nf.Annotations, nf.Link, nf.Quiet
			dirty[k] = true
		}
		f.LastSeen = now
		if now.Sub(e.persisted[k]) >= e.o.Resend {
			dirty[k] = true
		}
	}
	var resolved []*Finding
	for k, f := range e.state {
		if f.Resolved() || activeKeys[k] || found.Skipped[f.Check] {
			continue
		}
		if now.Sub(f.LastSeen) >= e.o.ResolveGrace {
			f.State, f.ResolvedAt = StateResolved, timePtr(now)
			dirty[k] = true
			resolved = append(resolved, f)
		}
	}
	res.New, res.Resolved = len(opened), len(resolved)

	// Acknowledgements and silences, from the actions log. A finding that
	// is silenced now but fired before is ended once (with who silenced it,
	// until when and why); one whose silence ended fires again at once; an
	// ack or unack goes out at once, so the annotations follow.
	silenceNow := map[string]bool{}
	for k, f := range e.state {
		state, until := f.State, f.SilencedUntil
		applyMarks(f, e.log.mark(k), now)
		if f.State != state || !sameTime(f.SilencedUntil, until) {
			dirty[k] = true
		}
		if f.Resolved() {
			continue
		}
		was := prevState[k] // "" for a key new to this evaluator
		switch {
		case f.State == StateSilenced && was != StateSilenced:
			if f.LastNotified != nil && !f.Digest && !f.Quiet {
				silenceNow[k] = true
			}
		case f.State != StateSilenced && was == StateSilenced:
			fireNow[k] = true
		case was != "" && was != StateResolved && ackSig(f) != prevAck[k]:
			fireNow[k] = true
		}
	}

	// Storm protection, in order: more than MaxNew new alerts at once all go
	// into their owners' digests; otherwise each owner gets OwnerMaxNew in
	// any OwnerWindow on their own and the rest join their digest; then
	// digested findings that turned critical leave it (MaxNew at most).
	// Quiet and silenced findings never count.
	newDigest := map[string]bool{}
	var eligible []*Finding
	for _, f := range slices.Concat(opened, unquiet) {
		if !f.Quiet && f.State != StateSilenced {
			eligible = append(eligible, f)
		}
	}
	sort.Slice(eligible, func(i, j int) bool {
		a, b := eligible[i], eligible[j]
		if severityRank(a.Severity) != severityRank(b.Severity) {
			return severityRank(a.Severity) < severityRank(b.Severity)
		}
		return a.Key < b.Key
	})
	toDigest := func(f *Finding, reason string) {
		f.Digest = true
		newDigest[f.Owner] = true
		res.Digested[reason]++
		res.Digest = true
	}
	if len(eligible) > e.o.MaxNew {
		for _, f := range eligible {
			toDigest(f, DigestMaxNew)
		}
	} else {
		for _, f := range eligible {
			if !e.spend(f.Owner, now, false) {
				toDigest(f, DigestOwnerBudget)
			}
		}
	}
	promote := make([]string, 0, len(e.promote))
	for k := range e.promote {
		promote = append(promote, k)
	}
	sort.Strings(promote)
	for _, k := range promote {
		f := e.state[k]
		switch {
		case f == nil || f.Resolved() || !f.Digest || f.Quiet || f.Severity != SeverityCritical:
			delete(e.promote, k)
			continue
		case f.State == StateSilenced || res.Promoted == e.o.MaxNew:
			continue // later: once the silence ends, or at the next evaluation
		}
		f.Digest = false
		fireNow[k], dirty[k] = true, true
		res.Promoted++
		delete(e.promote, k)
		e.spend(f.Owner, now, true)
	}

	// Notify: new and changed alerts now, open and acknowledged ones every
	// Resend, newly silenced ones ended once, resolved ones once.
	ends := now.Add(4 * e.o.Resend)
	keys := make([]string, 0, len(e.state))
	for k := range e.state {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	digestOf := map[string][]*Finding{}
	for _, k := range keys {
		f := e.state[k]
		switch {
		case f.Resolved(), f.Quiet:
			continue
		case f.State == StateSilenced:
			if silenceNow[k] {
				out = append(out, e.alertOf(f, now))
				f.LastNotified = timePtr(now)
				dirty[k] = true
			}
			continue
		case f.Digest:
			digestOf[f.Owner] = append(digestOf[f.Owner], f)
			continue
		}
		if f.LastNotified == nil || fireNow[k] || now.Sub(*f.LastNotified) >= e.o.Resend {
			a := e.alertOf(f, ends)
			out = append(out, a)
			f.LastNotified = timePtr(now)
			dirty[k] = true
		}
	}
	sort.Slice(resolved, func(i, j int) bool { return resolved[i].Key < resolved[j].Key })
	for _, f := range resolved {
		// A silenced finding's alert already ended when it was silenced.
		if f.LastNotified != nil && !f.Digest && !f.Quiet && prevState[f.Key] != StateSilenced {
			out = append(out, e.alertOf(f, now))
			f.LastNotified = timePtr(now)
		}
	}
	digestOwners := make([]string, 0, len(digestOf))
	for o := range digestOf {
		digestOwners = append(digestOwners, o)
	}
	sort.Strings(digestOwners)
	for _, o := range digestOwners {
		if d, ok := e.digests[o]; !ok || newDigest[o] || now.Sub(d.sent) >= e.o.Resend {
			a := e.digestAlert(o, digestOf[o], ends)
			out = append(out, a)
			e.digests[o] = digestState{sent: now, start: a.StartsAt}
		}
	}
	gone := []string{}
	for o := range e.digests {
		if digestOf[o] == nil {
			gone = append(gone, o)
		}
	}
	sort.Strings(gone)
	for _, o := range gone {
		a := e.digestAlert(o, nil, now)
		a.StartsAt = e.digests[o].start
		out = append(out, a)
		delete(e.digests, o)
	}

	// The standing digests due now: sent once, after the commit that
	// records their run.
	standing, runs := e.dueDigests(in, found, now, &res)
	out = append(out, standing...)

	// Commit, then send.
	c := Commit{Baselines: newBaselines, DigestRuns: runs}
	for _, k := range keys {
		if dirty[k] {
			c.Findings = append(c.Findings, e.state[k].Clone())
		}
	}
	if len(newBaselines) == 0 {
		c.Baselines = nil
	}
	if err := e.store.Commit(ctx, c); err != nil {
		// Memory may be ahead of the store: start again from it. Pending
		// timers stay, so what waited out its pending time fires next time.
		e.loaded = false
		return res, fmt.Errorf("alerts: commit: %w", err)
	}
	for _, f := range opened {
		delete(e.pending, f.Key)
	}
	for _, f := range c.Findings {
		e.persisted[f.Key] = f.LastSeen
	}
	for kind, t := range runs {
		e.digestRuns[kind] = NormalTime(t)
	}
	for check, keys := range newBaselines {
		set := make(map[string]bool, len(keys))
		for _, k := range keys {
			set[k] = true
		}
		e.baselines[check] = set
	}
	if len(out) > 0 {
		e.sink.Send(out)
	}
	res.Sent = len(out)

	// Forget what left the board.
	cutoff := now.Add(-BoardWindow)
	for k, f := range e.state {
		if f.Resolved() && f.ResolvedAt != nil && f.ResolvedAt.Before(cutoff) {
			delete(e.state, k)
			delete(e.persisted, k)
		}
	}
	for _, f := range e.state {
		if !f.Resolved() {
			res.Open++
			res.OpenBy[[2]string{f.Check, f.Severity}]++
		}
	}
	return res, nil
}

// LastDigest is when a standing digest was last sent (zero for never).
func (e *Evaluator) LastDigest() time.Time { return latestRun(e.digestRuns) }

func latestRun(runs map[string]time.Time) time.Time {
	var last time.Time
	for _, t := range runs {
		if t.After(last) {
			last = t
		}
	}
	return last
}

// Findings returns a copy of the findings the evaluator holds: every one
// not resolved, and those resolved within BoardWindow.
func (e *Evaluator) Findings() []Finding {
	out := make([]Finding, 0, len(e.state))
	for _, f := range e.state {
		out = append(out, f.Clone())
	}
	return out
}

// build turns a candidate into a finding's descriptive fields: owner,
// labels, annotations and link. The lifecycle fields are left zero.
//
// The owner is the object's own (its owner annotation), else its
// namespace's, else DefaultOwner. The namespace's routing hints
// (kubesentry_* labels) are copied only when the namespace's owner is the
// finding's: they route that team's alerts.
func (e *Evaluator) build(c Candidate, nss map[string]nsInfo, owners map[detectors.ObjectRef]string, v *snapshot.View) Finding {
	info := checkInfos[c.Check]
	ns := nss[c.Namespace]
	own := owners[detectors.ObjectRef{Kind: c.Kind, Namespace: c.Namespace, Name: c.Name}]
	owner := e.ownerOf(c.Kind, c.Namespace, c.Name, nss, owners, v)
	hints := ns.hints
	if own != "" && own != ns.owner {
		hints = nil
	}
	f := Finding{
		Key: c.Key(), Alert: info.alert, Check: c.Check, Kind: c.Kind, Namespace: c.Namespace, Name: c.Name,
		Severity: c.Severity, Title: clean(c.Title), Owner: owner, Production: ns.production,
		Link: c.Link, Quiet: c.Quiet,
	}
	l := map[string]string{
		"alertname": info.alert, "severity": c.Severity, "check": c.Check, "owner": owner,
		"production": strconv.FormatBool(ns.production),
	}
	if c.Namespace != "" {
		l["namespace"] = c.Namespace
	}
	if info.object {
		l["object"] = c.Kind + "/" + c.Name
	} else {
		l["workload"] = c.Kind + "/" + c.Name
	}
	if c.Node != "" {
		l["node"] = c.Node
	}
	if e.o.Cluster != "" {
		l["cluster"] = e.o.Cluster
	}
	for _, h := range hints {
		if _, taken := l[h[0]]; !taken {
			l[h[0]] = h[1]
		}
	}
	a := map[string]string{
		"summary":     clean(c.Title),
		"description": clean(c.Description),
		"runbook_url": e.o.RunbookURL + "#" + strings.ToLower(info.alert),
		"dedupe_key":  f.Key,
	}
	if u := uilink.Absolute(e.o.ExternalURL, c.Link); u != "" {
		a["kubesentry_url"] = u
	}
	for k, v := range c.Extra {
		if _, taken := a[k]; !taken {
			a[k] = clean(v)
		}
	}
	f.Labels, f.Annotations = l, a
	return f
}

// ownerOf is the owner of an object: its own owner annotation, else its
// namespace's, else DefaultOwner.
func (e *Evaluator) ownerOf(kind, ns, name string, nss map[string]nsInfo, owners map[detectors.ObjectRef]string, v *snapshot.View) string {
	own := owners[detectors.ObjectRef{Kind: kind, Namespace: ns, Name: name}]
	if owner := v.Policy.ObjectOwner(own, nss[ns].ns); owner != "" {
		return owner
	}
	return e.o.DefaultOwner
}

// linkIncident sets nf's incident_url annotation when there is an external
// URL and its episode has joined an incident. A link once made stays while
// the lookup knows no incident (the incident left the board, or a replica
// is still reading it), so it does not come and go; prev is the episode's
// finding so far (nil for a new episode).
func (e *Evaluator) linkIncident(nf, prev *Finding) {
	if e.o.ExternalURL == "" {
		return
	}
	id := ""
	if e.o.IncidentOf != nil {
		id = e.o.IncidentOf(nf)
	}
	if id != "" {
		nf.Annotations[AnnotationIncidentURL] = uilink.Absolute(e.o.ExternalURL, uilink.Incident(id))
	} else if u := prev.incidentURL(); u != "" {
		nf.Annotations[AnnotationIncidentURL] = u
	}
}

// alertOf is f as Alertmanager takes it, ending at ends: with who
// acknowledged it and when, and who silenced it, until when and why.
func (e *Evaluator) alertOf(f *Finding, ends time.Time) Alert {
	ann := maps.Clone(f.Annotations)
	if ann == nil {
		ann = map[string]string{}
	}
	if f.AckBy != "" && f.AckAt != nil {
		ann[AnnotationAckBy] = clean(f.AckBy)
		ann[AnnotationAckAt] = f.AckAt.UTC().Format(time.RFC3339)
	}
	if f.SilencedBy != "" && f.SilencedUntil != nil {
		ann[AnnotationSilencedBy] = clean(f.SilencedBy)
		ann[AnnotationSilencedUntil] = f.SilencedUntil.UTC().Format(time.RFC3339)
		ann[AnnotationSilenceReason] = clean(f.SilenceReason)
	}
	return Alert{
		Labels: maps.Clone(f.Labels), Annotations: ann,
		StartsAt: f.FirstSeen, EndsAt: ends, GeneratorURL: f.Annotations["kubesentry_url"],
	}
}

// spend takes one new alert from owner's budget (OwnerMaxNew per sliding
// OwnerWindow) and reports whether there was one; force takes it anyway (a
// promotion: it counts, but is never held back).
func (e *Evaluator) spend(owner string, now time.Time, force bool) bool {
	ts := e.fired[owner]
	cut := now.Add(-e.o.OwnerWindow)
	i := 0
	for i < len(ts) && !ts[i].After(cut) {
		i++
	}
	ts = ts[i:]
	if len(ts) >= e.o.OwnerMaxNew && !force {
		e.fired[owner] = ts
		return false
	}
	e.fired[owner] = append(ts, now)
	return true
}

// ackSig identifies f's acknowledgement, so a change notifies.
func ackSig(f *Finding) string {
	if f.AckBy == "" || f.AckAt == nil {
		return ""
	}
	return f.AckBy + "\x00" + f.AckAt.UTC().Format(time.RFC3339Nano)
}

// sameTime reports whether two optional times are equal.
func sameTime(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equal(*b)
}

// maxDigestLines bounds the findings a digest names.
const maxDigestLines = 10

// digestAlert is one owner's digest: the findings storm protection held
// back, counted by alert and with the worst few named. With no findings it
// ends the digest (ends is then now).
func (e *Evaluator) digestAlert(owner string, fs []*Finding, ends time.Time) Alert {
	l := map[string]string{
		"alertname": AlertFindingsDigest, "severity": SeverityWarning, "check": CheckDigest, "owner": owner,
		"kubesentry_digest": "true",
	}
	if e.o.Cluster != "" {
		l["cluster"] = e.o.Cluster
	}
	a := Alert{Labels: l, EndsAt: ends, Annotations: map[string]string{
		"runbook_url": e.o.RunbookURL + "#" + strings.ToLower(AlertFindingsDigest),
	}}
	if u := uilink.Absolute(e.o.ExternalURL, uilink.Owner(owner)); u != "" {
		a.Annotations["kubesentry_url"] = u
		a.GeneratorURL = u
	}
	if len(fs) == 0 {
		a.StartsAt = ends
		a.Annotations["summary"] = "kubesentry findings digest for " + owner + ": all resolved"
		return a
	}
	byAlert := map[string]int{}
	start := fs[0].FirstSeen
	sorted := append([]*Finding(nil), fs...)
	sort.Slice(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if severityRank(a.Severity) != severityRank(b.Severity) {
			return severityRank(a.Severity) < severityRank(b.Severity)
		}
		return a.Key < b.Key
	})
	for _, f := range fs {
		byAlert[f.Alert]++
		if f.FirstSeen.Before(start) {
			start = f.FirstSeen
		}
	}
	names := make([]string, 0, len(byAlert))
	for n := range byAlert {
		names = append(names, n)
	}
	sort.Strings(names)
	var counts []string
	for _, n := range names {
		counts = append(counts, fmt.Sprintf("%s ×%d", n, byAlert[n]))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "More new findings appeared than kubesentry alerts on one by one (-alerts-max-new at once, -alerts-owner-max-new per owner in -alerts-owner-window), so they are summed up here: %s.", strings.Join(counts, ", "))
	for i, f := range sorted {
		if i == maxDigestLines {
			fmt.Fprintf(&b, "\n… and %d more.", len(sorted)-maxDigestLines)
			break
		}
		fmt.Fprintf(&b, "\n- [%s] %s", f.Severity, f.Title)
	}
	a.StartsAt = start
	a.Annotations["summary"] = fmt.Sprintf("%d kubesentry %s for %s, sent as a digest", len(fs), plural(len(fs), "finding", "findings"), owner)
	a.Annotations["description"] = b.String()
	a.Annotations["findings"] = strconv.Itoa(len(fs))
	return a
}

// SortKey orders findings as the API lists them: open, acknowledged,
// silenced, then resolved; critical first; newest first; then by key.
func SortKey(f *Finding) string {
	t := f.FirstSeen
	if f.Resolved() && f.ResolvedAt != nil {
		t = *f.ResolvedAt
	}
	return fmt.Sprintf("%d\x00%d\x00%019d\x00%s", stateRank(f.State), severityRank(f.Severity), math.MaxInt64-max(t.UnixNano(), 0), f.Key)
}
