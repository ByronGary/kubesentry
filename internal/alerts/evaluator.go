package alerts

import (
	"context"
	"fmt"
	"maps"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

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
	// they go out as one digest alert per owner instead. Default 50.
	MaxNew int
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
	// Now is the clock; default time.Now.
	Now func() time.Time
}

// AnnotationIncidentURL is the annotation linking an alert to the incident
// its episode joined. It is an annotation, never a label: a label change
// would retire the alert in Alertmanager.
const AnnotationIncidentURL = "incident_url"

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
	if o.DefaultOwner == "" {
		o.DefaultOwner = "platform"
	}
	if o.RunbookURL == "" {
		o.RunbookURL = DefaultRunbookURL
	}
	if o.DriftHold <= 0 {
		o.DriftHold = 24 * time.Hour
	}
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
	Digest     bool
	// Baselined lists the change-based checks that recorded their first
	// baseline (and so notified nothing).
	Baselined []string
	// OpenBy counts the findings not resolved by check and severity.
	OpenBy map[[2]string]int
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
}

// digestState is one owner's digest while it fires.
type digestState struct{ sent, start time.Time }

// NewEvaluator returns an evaluator writing to store and notifying sink.
func NewEvaluator(store Store, sink Sink, o Options) *Evaluator {
	o.defaults()
	if sink == nil {
		sink = NopSink{}
	}
	return &Evaluator{o: o, store: store, sink: sink, pending: map[string]time.Time{}, digests: map[string]digestState{}}
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
// more than MaxNew), open ones are posted again every Resend, gone ones
// resolve after ResolveGrace. Writes are committed before anything is
// sent, so a replica whose commit fails (it lost the lock) notifies
// nothing.
func (e *Evaluator) Evaluate(ctx context.Context, in Input) (Result, error) {
	if in.Now.IsZero() {
		in.Now = e.o.Now()
	}
	now := in.Now
	if !e.loaded {
		if err := e.Load(ctx); err != nil {
			return Result{}, fmt.Errorf("alerts: load: %w", err)
		}
	}
	found := Run(in, e.o.LeakCritHours)
	nss := namespaceInfo(in.View)
	res := Result{Candidates: len(found.Candidates), OpenBy: map[[2]string]int{}}

	// Change-based checks: only what is not in the baseline fires; what
	// fired stays open for DriftHold while it exists.
	current := map[string]map[string]bool{}
	for check, info := range checkInfos {
		if info.changeBased && !found.Skipped[check] {
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
	var opened []*Finding
	activeKeys := make(map[string]bool, len(active))
	for _, c := range active {
		k := c.Key()
		activeKeys[k] = true
		nf := e.build(c, nss)
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
		if f.State == StateSilenced && f.SilencedUntil != nil && !now.Before(*f.SilencedUntil) {
			f.State, f.SilencedUntil = StateOpen, nil
			dirty[k], fireNow[k] = true, true
		}
		if !maps.Equal(f.Labels, nf.Labels) {
			// Alertmanager knows an alert by its labels: retire the old set.
			if f.LastNotified != nil && !f.Digest {
				out = append(out, e.alertOf(f, now))
			}
			fireNow[k] = true
		}
		if f.Alert != nf.Alert || f.Kind != nf.Kind || f.Severity != nf.Severity || f.Title != nf.Title || f.Owner != nf.Owner ||
			f.Production != nf.Production || !maps.Equal(f.Labels, nf.Labels) || !maps.Equal(f.Annotations, nf.Annotations) {
			f.Alert, f.Kind, f.Severity, f.Title, f.Owner, f.Production = nf.Alert, nf.Kind, nf.Severity, nf.Title, nf.Owner, nf.Production
			f.Labels, f.Annotations = nf.Labels, nf.Annotations
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

	// Storm protection: too many new alerts at once go out as digests.
	newDigest := map[string]bool{}
	if len(opened) > e.o.MaxNew {
		res.Digest = true
		for _, f := range opened {
			f.Digest = true
			newDigest[f.Owner] = true
		}
	}

	// Notify: new and changed alerts now, open ones every Resend, resolved
	// ones once.
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
		case f.Resolved():
			continue
		case f.Digest:
			digestOf[f.Owner] = append(digestOf[f.Owner], f)
			continue
		case f.State == StateSilenced:
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
		if f.LastNotified != nil && !f.Digest {
			out = append(out, e.alertOf(f, now))
			f.LastNotified = timePtr(now)
		}
	}
	owners := make([]string, 0, len(digestOf))
	for o := range digestOf {
		owners = append(owners, o)
	}
	sort.Strings(owners)
	for _, o := range owners {
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

	// Commit, then send.
	c := Commit{Baselines: newBaselines}
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
// labels and annotations. The lifecycle fields are left zero.
func (e *Evaluator) build(c Candidate, nss map[string]nsInfo) Finding {
	info := checkInfos[c.Check]
	ns := nss[c.Namespace]
	owner := ns.owner
	if owner == "" {
		owner = e.o.DefaultOwner
	}
	f := Finding{
		Key: c.Key(), Alert: info.alert, Check: c.Check, Kind: c.Kind, Namespace: c.Namespace, Name: c.Name,
		Severity: c.Severity, Title: clean(c.Title), Owner: owner, Production: ns.production,
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
	for _, h := range ns.hints {
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

// alertOf is f as Alertmanager takes it, ending at ends.
func (e *Evaluator) alertOf(f *Finding, ends time.Time) Alert {
	return Alert{
		Labels: maps.Clone(f.Labels), Annotations: maps.Clone(f.Annotations),
		StartsAt: f.FirstSeen, EndsAt: ends, GeneratorURL: f.Annotations["kubesentry_url"],
	}
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
	fmt.Fprintf(&b, "More new findings appeared at once than kubesentry alerts on one by one (-alerts-max-new), so they are summed up here: %s.", strings.Join(counts, ", "))
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
