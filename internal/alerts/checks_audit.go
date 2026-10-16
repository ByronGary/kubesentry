package alerts

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/uilink"
)

// AuditQuerier reads audit events, newest first: audit.Store's Query.
type AuditQuerier interface {
	Query(ctx context.Context, q audit.Query) ([]audit.Event, error)
}

// AuditOptions configures the audit checks. Zero values take the defaults
// shown.
type AuditOptions struct {
	// ProductionOnly are the audit checks that count events in production
	// namespaces only (-alerts-audit-production-only). Nil means
	// DefaultAuditProductionOnly; an empty map, none.
	ProductionOnly map[string]bool
	// Hold: a finding stays open while its newest event is younger than
	// this. Default 1h.
	Hold time.Duration
	// DeniedBurst denied requests by one actor within DeniedWindow make a
	// burst. Defaults 20 and 10m.
	DeniedBurst  int
	DeniedWindow time.Duration
	// Redact removes secrets from the examples (cmd/server passes the
	// incidents redactor). Nil leaves exec commands out of them altogether.
	Redact func(string) string
}

// DefaultAuditProductionOnly are the audit checks that count only events in
// production namespaces by default: exec and the like, and secret reads,
// are routine elsewhere.
var DefaultAuditProductionOnly = []string{CheckAuditExec, CheckAuditSecretRead}

func (o *AuditOptions) defaults() {
	if o.ProductionOnly == nil {
		o.ProductionOnly = map[string]bool{}
		for _, c := range DefaultAuditProductionOnly {
			o.ProductionOnly[c] = true
		}
	}
	if o.Hold <= 0 {
		o.Hold = time.Hour
	}
	if o.DeniedBurst <= 0 {
		o.DeniedBurst = 20
	}
	if o.DeniedWindow <= 0 {
		o.DeniedWindow = 10 * time.Minute
	}
}

// auditSpec is one audit check: the audit tags it reads (one query each),
// and whose events count.
type auditSpec struct {
	check string
	tags  []string
	// humans: only people (audit actor kind "user") count.
	humans bool
	// allowed: only requests that were allowed count (denied ones are the
	// denied-burst check's).
	allowed bool
	// link is the Activity page's tag filter ("" for several tags).
	link string
	// lead says what the actor did: "<actor> <lead> <where>".
	lead string
}

var auditSpecs = []auditSpec{
	{check: CheckAuditExec, tags: []string{audit.TagExec, audit.TagPortForward, audit.TagDebug}, humans: true, allowed: true,
		lead: "used exec, attach, port-forward or a debug container"},
	{check: CheckAuditSecretRead, tags: []string{audit.TagSecretAccess}, humans: true, allowed: true, link: audit.TagSecretAccess,
		lead: "read Secrets"},
	{check: CheckAuditRBACChange, tags: []string{audit.TagRBACChange}, humans: true, allowed: true, link: audit.TagRBACChange,
		lead: "changed roles or role bindings"},
	{check: CheckAuditImpersonation, tags: []string{audit.TagImpersonate}, allowed: true, link: audit.TagImpersonate,
		lead: "acted as other users (impersonation)"},
	{check: CheckAuditDeniedBurst, tags: []string{audit.TagDenied}, link: audit.TagDenied,
		lead: "was denied"},
	{check: CheckAuditAnonymous, tags: []string{audit.TagAnonymous}, allowed: true, link: audit.TagAnonymous,
		lead: "made requests without credentials that the API server allowed"},
}

// AuditChecks lists the audit checks.
func AuditChecks() []string {
	out := make([]string, len(auditSpecs))
	for i, s := range auditSpecs {
		out[i] = s.check
	}
	return out
}

// The audit poll's bounds, as the incidents' audit poll keeps them: each
// poll re-reads an overlap (events are stored a little late), the
// checkpoint never lags more than auditMaxLag behind, and each tag reads at
// most auditPages pages of auditPage events.
const (
	auditOverlap = 5 * time.Minute
	auditMaxLag  = 10 * time.Minute
	auditPage    = 1000
	auditPages   = 10
	// maxAuditSeen bounds the audit IDs kept for deduplication, and
	// maxAuditFindings the findings held at once.
	maxAuditSeen     = 200_000
	maxAuditFindings = 10_000
	// maxAuditExamples is how many examples a finding names; maxAuditVerbs
	// how many verbs.
	maxAuditExamples = 3
	maxAuditVerbs    = 10
	maxExampleBytes  = 300
)

// AuditWatch runs the audit checks on the leader: it polls the audit store
// for the tags the enabled checks read, from an in-memory checkpoint with
// an overlap for late events (deduplicated by audit ID), and aggregates the
// events per check, namespace and actor. A finding stays while its newest
// event is within Hold. The first poll of a leadership term (a new
// AuditWatch) reads the whole hold window, so findings outlive a failover.
// It is not safe for concurrent use.
type AuditWatch struct {
	o      AuditOptions
	polled bool
	since  time.Time
	seen   map[string]time.Time // check + "\x00" + audit ID → event time
	aggs   map[auditKey]*auditAgg
	denied map[string][]auditLine // actor → the newest DeniedBurst denied events, oldest first
}

type auditKey struct{ check, ns, actor string }

// auditAgg is one finding's events.
type auditAgg struct {
	count       int
	first, last time.Time
	actorKind   string
	verbs       map[string]bool
	examples    []auditLine // the newest, oldest first
}

// auditLine is one event as a finding keeps it.
type auditLine struct {
	at              time.Time
	id              string
	actorKind, verb string // verb: "create pods/exec"
	text            string // the example
}

// NewAuditWatch returns a watch with nothing read yet.
func NewAuditWatch(o AuditOptions) *AuditWatch {
	o.defaults()
	return &AuditWatch{o: o, seen: map[string]time.Time{}, aggs: map[auditKey]*auditAgg{}, denied: map[string][]auditLine{}}
}

// Poll reads the events of the enabled checks since the checkpoint and
// aggregates them; production says whether a namespace is production. It
// returns the checks whose reads failed (with the first error): their
// findings must neither refresh nor resolve, and the checkpoint stays, so
// the next poll reads the events again (the seen IDs are not counted
// twice).
func (w *AuditWatch) Poll(ctx context.Context, q AuditQuerier, enabled map[string]bool, production func(ns string) bool, now time.Time) (map[string]bool, error) {
	from := now.Add(-w.o.Hold)
	if w.polled {
		if f := w.since.Add(-auditOverlap); f.After(from) {
			from = f
		}
	}
	failed := map[string]bool{}
	var firstErr error
	newest := w.since
	for i := range auditSpecs {
		sp := &auditSpecs[i]
		if !enabled[sp.check] {
			continue
		}
		for _, tag := range sp.tags {
			evs, err := readAudit(ctx, q, sp, tag, from)
			if err != nil {
				failed[sp.check] = true
				if firstErr == nil {
					firstErr = fmt.Errorf("alerts: audit %s: %w", tag, err)
				}
				break
			}
			for j := len(evs) - 1; j >= 0; j-- { // oldest first
				e := &evs[j]
				if e.Time.After(newest) {
					newest = e.Time
				}
				k := sp.check + "\x00" + e.AuditID
				if _, dup := w.seen[k]; dup {
					continue
				}
				w.seen[k] = e.Time
				w.add(sp, e, production, now)
			}
		}
	}
	if len(failed) == 0 {
		if floor := now.Add(-auditMaxLag); newest.Before(floor) {
			newest = floor
		}
		w.since, w.polled = newest, true
	}
	// Forget the IDs the next poll cannot read again.
	next := now.Add(-w.o.Hold)
	if w.polled {
		if f := w.since.Add(-auditOverlap); f.After(next) {
			next = f
		}
	}
	for k, t := range w.seen {
		if t.Before(next) {
			delete(w.seen, k)
		}
	}
	if len(w.seen) > maxAuditSeen {
		w.seen = map[string]time.Time{} // a flood: some events may count twice
	}
	return failed, firstErr
}

// readAudit reads the events with tag since from, newest first, page by
// page (at most auditPages).
func readAudit(ctx context.Context, q AuditQuerier, sp *auditSpec, tag string, from time.Time) ([]audit.Event, error) {
	// Tagged reads (secret access) match without IncludeReads, which keeps
	// the store on its default-view indexes.
	qq := audit.Query{Since: from, Tag: tag, Limit: auditPage}
	if sp.humans {
		qq.Actors = map[string]bool{"user": true}
	}
	var out []audit.Event
	for page := 0; page < auditPages; page++ {
		got, err := q.Query(ctx, qq)
		if err != nil {
			return nil, err
		}
		out = append(out, got...)
		if len(got) < auditPage {
			break
		}
		last := got[len(got)-1]
		qq.Before = audit.Cursor{Time: last.Time, AuditID: last.AuditID}
	}
	return out, nil
}

// add counts one event towards its check's finding.
func (w *AuditWatch) add(sp *auditSpec, e *audit.Event, production func(string) bool, now time.Time) {
	if strings.TrimSpace(clean(e.Username)) == "" || e.Time.Before(now.Add(-w.o.Hold)) {
		return
	}
	if sp.allowed && (e.StatusCode >= 400 || e.Decision == "forbid") {
		return
	}
	if sp.humans && e.ActorKind != "user" {
		return
	}
	if w.o.ProductionOnly[sp.check] && (e.Namespace == "" || production == nil || !production(e.Namespace)) {
		return
	}
	if sp.check == CheckAuditAnonymous && publicEndpoint(e) {
		return
	}
	l := w.line(e)
	if sp.check == CheckAuditDeniedBurst {
		w.addDenied(e.Username, l)
		return
	}
	w.aggregate(auditKey{sp.check, e.Namespace, e.Username}, l)
}

// addDenied keeps the actor's newest DeniedBurst denied events; once they
// fall within DeniedWindow, a finding opens with them, and later denied
// events join it while it holds. Denied bursts are counted per actor
// across the cluster, so the finding is cluster-scoped.
func (w *AuditWatch) addDenied(actor string, l auditLine) {
	k := auditKey{CheckAuditDeniedBurst, "", actor}
	if w.aggs[k] != nil {
		w.aggregate(k, l)
		return
	}
	ls := insertLine(w.denied[actor], l)
	if len(ls) > w.o.DeniedBurst {
		ls = ls[len(ls)-w.o.DeniedBurst:]
	}
	w.denied[actor] = ls
	if len(ls) == w.o.DeniedBurst && ls[len(ls)-1].at.Sub(ls[0].at) <= w.o.DeniedWindow {
		for _, x := range ls {
			w.aggregate(k, x)
		}
		delete(w.denied, actor)
	}
}

func (w *AuditWatch) aggregate(k auditKey, l auditLine) {
	a := w.aggs[k]
	if a == nil {
		if len(w.aggs) >= maxAuditFindings {
			return
		}
		a = &auditAgg{first: l.at, last: l.at, actorKind: l.actorKind, verbs: map[string]bool{}}
		w.aggs[k] = a
	}
	a.count++
	if l.at.Before(a.first) {
		a.first = l.at
	}
	if !l.at.Before(a.last) {
		a.last, a.actorKind = l.at, l.actorKind
	}
	if len(a.verbs) < maxAuditVerbs || a.verbs[l.verb] {
		a.verbs[l.verb] = true
	}
	a.examples = insertLine(a.examples, l)
	if len(a.examples) > maxAuditExamples {
		a.examples = a.examples[len(a.examples)-maxAuditExamples:]
	}
}

// insertLine adds l to ls, which is sorted oldest first (by time, then
// audit ID).
func insertLine(ls []auditLine, l auditLine) []auditLine {
	i := sort.Search(len(ls), func(i int) bool {
		if !ls[i].at.Equal(l.at) {
			return ls[i].at.After(l.at)
		}
		return ls[i].id > l.id
	})
	ls = append(ls, auditLine{})
	copy(ls[i+1:], ls[i:])
	ls[i] = l
	return ls
}

// Candidates returns a candidate per finding whose newest event is within
// Hold of now, leaving out the checks in skip, and forgets the others.
func (w *AuditWatch) Candidates(now time.Time, skip map[string]bool) []Candidate {
	cut := now.Add(-w.o.Hold)
	for actor, ls := range w.denied {
		if len(ls) == 0 || ls[len(ls)-1].at.Before(now.Add(-w.o.DeniedWindow)) {
			delete(w.denied, actor)
		}
	}
	var out []Candidate
	for k, a := range w.aggs {
		if a.last.Before(cut) {
			delete(w.aggs, k)
			continue
		}
		if !skip[k.check] {
			out = append(out, w.candidate(k, a))
		}
	}
	sortCandidates(out)
	return out
}

func (w *AuditWatch) candidate(k auditKey, a *auditAgg) Candidate {
	var sp *auditSpec
	for i := range auditSpecs {
		if auditSpecs[i].check == k.check {
			sp = &auditSpecs[i]
		}
	}
	where := "cluster-wide"
	if k.ns != "" {
		where = "in namespace " + k.ns
	}
	times := fmt.Sprintf("%d %s", a.count, plural(a.count, "time", "times"))
	sev := SeverityWarning
	if k.check == CheckAuditAnonymous {
		sev = SeverityCritical
	}
	verbs := make([]string, 0, len(a.verbs))
	for v := range a.verbs {
		verbs = append(verbs, v)
	}
	sort.Strings(verbs)
	examples := make([]string, len(a.examples))
	for i, l := range a.examples {
		examples[i] = l.text
	}
	first, last := a.first.UTC().Format(time.RFC3339), a.last.UTC().Format(time.RFC3339)
	title := fmt.Sprintf("Audit: %s %s %s (%s)", k.actor, sp.lead, where, times)
	desc := fmt.Sprintf("%s (%s) %s %s, %s between %s and %s (%s). The finding stays open until %s passes without another such request.",
		k.actor, a.actorKind, sp.lead, where, times, first, last, strings.Join(verbs, ", "), roughly(w.o.Hold))
	switch k.check {
	case CheckAuditDeniedBurst:
		title = fmt.Sprintf("Audit: %s was denied %d requests, at least %d within %s", k.actor, a.count, w.o.DeniedBurst, roughly(w.o.DeniedWindow))
		desc = fmt.Sprintf("%s (%s) was denied at least %d requests within %s, %d between %s and %s (%s). A credential probing what it may do, or a misconfigured client; the finding stays open until %s passes without another denied request.",
			k.actor, a.actorKind, w.o.DeniedBurst, roughly(w.o.DeniedWindow), a.count, first, last, strings.Join(verbs, ", "), roughly(w.o.Hold))
	case CheckAuditAnonymous:
		desc += " Requests without credentials should be refused: look for a binding to system:anonymous or system:unauthenticated."
	}
	return Candidate{
		// The actor goes into the key and a label: valid UTF-8 without NUL,
		// which Alertmanager and Postgres both need.
		Check: k.check, Kind: "User", Namespace: k.ns, Name: clean(k.actor), Severity: sev,
		Title: title, Description: desc, Link: uilink.Activity(sp.link, k.actor),
		Extra: map[string]string{
			"actor": k.actor, "actor_kind": a.actorKind, "count": strconv.Itoa(a.count), "first_at": first, "last_at": last,
			"verbs": strings.Join(verbs, ", "), "examples": strings.Join(examples, "\n"),
		},
	}
}

// line describes e for a finding: when, the verb on what, the object, and
// for exec the command (redacted; left out without a redactor), for
// impersonation whom, for a denial the status. Source IPs and user agents
// are never included.
func (w *AuditWatch) line(e *audit.Event) auditLine {
	what := e.Resource
	if e.Subresource != "" {
		what += "/" + e.Subresource
	}
	if what == "" {
		what = requestPath(e.RequestURI)
	}
	verb := strings.TrimSpace(e.Verb + " " + what)
	var b strings.Builder
	b.WriteString(e.Time.UTC().Format(time.RFC3339))
	b.WriteString(" ")
	b.WriteString(verb)
	if obj := e.Name; obj != "" {
		if e.Namespace != "" {
			obj = e.Namespace + "/" + obj
		}
		b.WriteString(" ")
		b.WriteString(obj)
	} else if e.Namespace != "" {
		b.WriteString(" in ")
		b.WriteString(e.Namespace)
	}
	if e.ImpersonatedUser != "" {
		b.WriteString(" as ")
		b.WriteString(e.ImpersonatedUser)
	}
	if e.StatusCode >= 400 || e.Decision == "forbid" {
		fmt.Fprintf(&b, " (denied, %d)", e.StatusCode)
	}
	if w.o.Redact != nil && e.Resource == "pods" && (e.Subresource == "exec" || e.Subresource == "attach") {
		if cmd := execCommand(e.RequestURI); cmd != "" {
			b.WriteString(": ")
			b.WriteString(cmd)
		}
	}
	text := b.String()
	if w.o.Redact != nil {
		text = w.o.Redact(text)
	}
	return auditLine{at: e.Time, id: e.AuditID, actorKind: e.ActorKind, verb: verb, text: truncate(clean(text), maxExampleBytes)}
}

// execCommand is the command of an exec request ("sh -c env"), from its
// request URI's command parameters.
func execCommand(uri string) string {
	u, err := url.Parse(uri)
	if err != nil {
		return ""
	}
	return strings.Join(u.Query()["command"], " ")
}

// requestPath is a request URI without its query.
func requestPath(uri string) string {
	p, _, _ := strings.Cut(uri, "?")
	return p
}

// publicEndpoint reports whether e is an anonymous read of what Kubernetes
// lets anyone read by default (system:public-info-viewer, service account
// issuer discovery): health checks, the version, OIDC discovery.
func publicEndpoint(e *audit.Event) bool {
	if e.Resource != "" {
		return false
	}
	p := requestPath(e.RequestURI)
	switch p {
	case "/healthz", "/livez", "/readyz", "/version", "/version/", "/.well-known/openid-configuration", "/openid/v1/jwks":
		return true
	}
	for _, pre := range []string{"/healthz/", "/livez/", "/readyz/"} {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}
