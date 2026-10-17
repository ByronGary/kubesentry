package investigate

import (
	"bytes"
	"encoding/json"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/incidents"
)

// DigestSchema names the digest format.
const DigestSchema = "kubesentry.io/incident-digest/v1"

// DefaultDigestBytes is the digest budget (-investigator-digest-bytes).
const DefaultDigestBytes = 64 << 10

// Digest limits.
const (
	digestMaxListed     = 20  // pods, services, nodes in the header
	digestBuckets       = 30  // max-preserving downsample per series
	digestMaxEvents     = 50  // event groups
	digestMaxTemplates  = 40  // log templates
	digestSamples       = 2   // samples per template
	digestMaxAudit      = 100 // audit records
	digestMaxCloudTrail = 50  // CloudTrail summaries
)

// Digest returns the compact, redacted JSON summary of an incident that is
// the investigator's first message, at most budget bytes (0:
// DefaultDigestBytes), and the ledger of every ref it shows. It applies the
// built-in redaction rules; Egress.Digest applies the configured ones.
//
// The digest holds a header (incident, window, cluster, now, omitted and
// truncated sections, totals), every trigger signal, the context signals
// (condensed to the first and last per type when they would take more than
// a third of the budget), per-series metric statistics with a 30-bucket
// max-preserving downsample, Kubernetes events grouped by reason, type and
// object (top 50, warnings first), log templates with digits, hex, UUIDs,
// IPs and timestamps stripped (top 40, errors first, two samples nearest a
// trigger), up to 100 audit writes and tagged events without IPs or user
// agents, and up to 50 CloudTrail summaries without the raw record. When it
// does not fit, it gives up log templates first, then events, audit and
// CloudTrail records, context signals and metric detail; triggers are
// condensed only as a last resort.
func Digest(b *incidents.Bundle, budget int) ([]byte, *Ledger) {
	return defaultEgress.Digest(b, budget)
}

// Digest is the package Digest with this filter's redaction.
func (e *Egress) Digest(b *incidents.Bundle, budget int) ([]byte, *Ledger) {
	data, _, led := e.digest(b, budget)
	return data, led
}

// digest also returns the digest without its "now" field, which the cache
// key hashes (the same incident digested a minute later is the same input).
func (e *Egress) digest(b *incidents.Bundle, budget int) (data, stable []byte, led *Ledger) {
	if budget <= 0 {
		budget = DefaultDigestBytes
	}
	d := e.build(b, budget)
	data = d.fit(budget)
	led = NewLedger()
	d.record(led)
	stable = data
	if d.Now != "" {
		stable = bytes.Replace(data, []byte(`"now":"`+d.Now+`",`), nil, 1)
	}
	return data, stable, led
}

// num is a float rounded to 4 significant digits in JSON (null for NaN and
// infinities).
type num float64

func (n num) MarshalJSON() ([]byte, error) {
	f := float64(n)
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return []byte("null"), nil
	}
	return strconv.AppendFloat(nil, f, 'g', 4, 64), nil
}

func numPtr(f *float64) *num {
	if f == nil {
		return nil
	}
	n := num(*f)
	return &n
}

func ts(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

type digestDoc struct {
	Schema    string            `json:"schema"`
	Now       string            `json:"now,omitempty"`
	Cluster   string            `json:"cluster,omitempty"`
	Window    dWindow           `json:"window"`
	Incident  dIncident         `json:"incident"`
	Omitted   map[string]string `json:"omitted,omitempty"`
	Truncated map[string]string `json:"truncated,omitempty"`
	// Totals count what the bundle held before the digest chose.
	Totals        map[string]int `json:"totals"`
	Triggers      []dSignal      `json:"triggers"`
	TriggerGroups []dGroup       `json:"trigger_groups,omitempty"`
	Context       []dSignal      `json:"context,omitempty"`
	ContextGroups []dGroup       `json:"context_groups,omitempty"`
	Metrics       []dMetric      `json:"metrics,omitempty"`
	Events        []dEvent       `json:"events,omitempty"`
	LogTemplates  []dLogTpl      `json:"log_templates,omitempty"`
	Audit         []dAudit       `json:"audit,omitempty"`
	CloudTrail    []dCloudTrail  `json:"cloudtrail,omitempty"`

	incStart time.Time
	// trigLevel is how far the triggers were condensed (0: not at all).
	trigLevel int
}

type dWindow struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type dIncident struct {
	ID           string            `json:"id"`
	Title        string            `json:"title"`
	Subject      string            `json:"subject"`
	Severity     string            `json:"severity"`
	PeakSeverity string            `json:"peak_severity"`
	State        string            `json:"state"`
	Start        string            `json:"start"`
	End          string            `json:"end,omitempty"`
	LastSignal   string            `json:"last_signal"`
	Capped       bool              `json:"capped,omitempty"`
	Previous     string            `json:"previous,omitempty"`
	Owner        string            `json:"owner,omitempty"`
	Production   bool              `json:"production,omitempty"`
	Tags         map[string]string `json:"tags,omitempty"`
	Services     []string          `json:"services,omitempty"`
	Pods         []string          `json:"pods,omitempty"`
	PodsTotal    int               `json:"pods_total,omitempty"`
	Nodes        []string          `json:"nodes,omitempty"`
	Types        []string          `json:"types"`
	Counts       map[string]int    `json:"counts,omitempty"`
}

type dSignal struct {
	Ref       string            `json:"ref"`
	Type      string            `json:"type"`
	Severity  string            `json:"severity,omitempty"`
	Start     string            `json:"start"`
	End       string            `json:"end,omitempty"`
	Ongoing   bool              `json:"ongoing,omitempty"`
	Object    string            `json:"object,omitempty"`
	Title     string            `json:"title,omitempty"`
	Value     *num              `json:"value,omitempty"`
	Baseline  *num              `json:"baseline,omitempty"`
	Threshold *num              `json:"threshold,omitempty"`
	Count     int               `json:"count,omitempty"`
	Attrs     map[string]string `json:"attrs,omitempty"`

	at time.Time
}

// dGroup condenses the signals of one type: how many, the first and the last.
type dGroup struct {
	Type  string   `json:"type"`
	Count int      `json:"count"`
	First dSignal  `json:"first"`
	Last  *dSignal `json:"last,omitempty"`
}

type dMetric struct {
	Ref    string  `json:"ref"`
	Metric string  `json:"metric"`
	Label  string  `json:"label"`
	Unit   string  `json:"unit,omitempty"`
	Points int     `json:"points"`
	Min    num     `json:"min"`
	Max    num     `json:"max"`
	Mean   num     `json:"mean"`
	First  num     `json:"first"`
	Last   num     `json:"last"`
	PeakAt string  `json:"peak_at"`
	Bucket *bucket `json:"max_per_bucket,omitempty"`

	peak   time.Time
	raw    [][2]float64
	from   time.Time
	to     time.Time
	nbucks int
}

// bucket is a max-preserving downsample: Max[i] is the largest value in
// [From + i*Step, From + (i+1)*Step), null when the bucket is empty.
type bucket struct {
	From string `json:"from"`
	Step int64  `json:"step_s"`
	Max  []*num `json:"max"`
}

type dEvent struct {
	Ref    string `json:"ref"`
	Type   string `json:"type"`
	Reason string `json:"reason"`
	Object string `json:"object"`
	Count  int    `json:"count"`
	Events int    `json:"events,omitempty"`
	First  string `json:"first"`
	Last   string `json:"last"`
	Source string `json:"source,omitempty"`
	Sample string `json:"sample,omitempty"`

	last time.Time
	warn bool
}

type dLogTpl struct {
	Ref       string       `json:"ref"`
	Template  string       `json:"template"`
	Level     string       `json:"level,omitempty"`
	Count     int          `json:"count"`
	Pods      []string     `json:"pods,omitempty"`
	PodsTotal int          `json:"pods_total,omitempty"`
	First     string       `json:"first"`
	Last      string       `json:"last"`
	Samples   []dLogSample `json:"samples,omitempty"`

	first time.Time
}

type dLogSample struct {
	Time      string `json:"time"`
	Pod       string `json:"pod"`
	Container string `json:"container,omitempty"`
	Text      string `json:"text"`
}

type dAudit struct {
	Ref       string   `json:"ref"`
	Time      string   `json:"time"`
	User      string   `json:"user"`
	ActorKind string   `json:"actor_kind,omitempty"`
	Verb      string   `json:"verb"`
	Resource  string   `json:"resource"`
	Namespace string   `json:"namespace,omitempty"`
	Name      string   `json:"name,omitempty"`
	Status    int      `json:"status,omitempty"`
	Decision  string   `json:"decision,omitempty"`
	Tags      []string `json:"tags,omitempty"`
	URI       string   `json:"uri,omitempty"`

	at time.Time
}

type dCloudTrail struct {
	Ref       string   `json:"ref"`
	Time      string   `json:"time"`
	Name      string   `json:"name"`
	Source    string   `json:"source"`
	Region    string   `json:"region,omitempty"`
	Actor     string   `json:"actor"`
	Resources []string `json:"resources,omitempty"`

	at time.Time
}

func subjectString(s incidents.Subject) string {
	if s.Namespace == "" {
		return s.Kind + "/" + s.Name
	}
	return s.Kind + "/" + s.Namespace + "/" + s.Name
}

// objectString names an object, leaving out the incident's own namespace.
func objectString(kind, ns, name, incNS string) string {
	if kind == "" && name == "" {
		return ""
	}
	if ns == "" || ns == incNS {
		return kind + "/" + name
	}
	return kind + "/" + ns + "/" + name
}

func capList(l []string, n int, e *Egress) (out []string, total int) {
	for i, s := range l {
		if i >= n {
			break
		}
		out = append(out, e.Line(s, 128))
	}
	if len(l) > n {
		total = len(l)
	}
	return out, total
}

func (e *Egress) build(b *incidents.Bundle, budget int) *digestDoc {
	in := b.Incident
	ns := in.Subject.Namespace
	d := &digestDoc{Schema: DigestSchema, Now: ts(b.GeneratedAt), Cluster: e.Line(b.Cluster, 128),
		Window: dWindow{From: ts(b.Window.From), To: ts(b.Window.To)}, Totals: map[string]int{}, incStart: in.Start,
		Truncated: map[string]string{}}
	di := dIncident{ID: in.ID, Title: e.Line(in.Title, 300), Subject: e.Line(subjectString(in.Subject), 300),
		Severity: string(in.Severity), PeakSeverity: string(in.PeakSeverity), State: string(in.State), Start: ts(in.Start),
		LastSignal: ts(in.LastSignal), Capped: in.Capped, Previous: in.Previous, Owner: e.Line(in.Owner, 128), Production: in.Production,
		Tags: e.Map(in.Tags, 16, 128), Types: append([]string{}, in.Types...), Counts: in.Counts}
	if in.End != nil {
		di.End = ts(*in.End)
	}
	di.Services, _ = capList(in.Services, digestMaxListed, e)
	di.Pods, di.PodsTotal = capList(in.Pods, digestMaxListed, e)
	di.Nodes, _ = capList(in.Nodes, digestMaxListed, e)
	d.Incident = di
	if len(b.Omitted) > 0 {
		d.Omitted = map[string]string{}
		for k, v := range b.Omitted {
			d.Omitted[k] = e.Line(v, 160)
		}
	}
	for k, v := range b.Truncated {
		if v {
			d.Truncated[k] = "bundle cap"
		}
	}

	// Signals.
	var triggerTimes []time.Time
	var ctx []dSignal
	d.Triggers = []dSignal{}
	for i := range b.Signals {
		s := &b.Signals[i]
		if s.Role == incidents.Trigger {
			d.Triggers = append(d.Triggers, e.signalRecord(s, ns, true))
			triggerTimes = append(triggerTimes, s.Start)
		} else {
			ctx = append(ctx, e.signalRecord(s, ns, false))
		}
	}
	d.Totals["triggers"], d.Totals["context"] = len(d.Triggers), len(ctx)
	sort.SliceStable(d.Triggers, func(i, j int) bool { return d.Triggers[i].at.Before(d.Triggers[j].at) })
	if len(triggerTimes) == 0 {
		triggerTimes = []time.Time{in.Start}
	}
	// Context: closest to the incident start first (what trimming keeps).
	sortByDistance(ctx, func(s dSignal) time.Time { return s.at }, in.Start)
	d.Context = ctx
	if jsonLen(ctx) > budget/3 {
		d.condenseContext()
	}

	// Metrics.
	wf, wt := b.Window.From, b.Window.To
	for _, s := range b.Metrics {
		if m, ok := e.metricRecord(s, wf, wt); ok {
			d.Metrics = append(d.Metrics, m)
		}
	}
	d.Totals["metric_series"] = len(b.Metrics)

	// Events, logs, audit, CloudTrail.
	d.Events = e.eventGroups(b.Events, ns)
	d.Totals["events"] = len(b.Events)
	d.LogTemplates = e.logTemplates(b.Logs, triggerTimes)
	d.Totals["log_lines"] = len(b.Logs)
	d.Audit = e.auditRecords(b.Audit, ns, in.Start)
	d.Totals["audit"] = len(b.Audit)
	d.CloudTrail = e.cloudTrailRecords(b.CloudTrail, in.Start)
	d.Totals["cloudtrail"] = len(b.CloudTrail)
	return d
}

func (e *Egress) signalRecord(s *incidents.BundleSignal, incNS string, trigger bool) dSignal {
	titleMax, keys, valMax := 200, 6, 160
	if trigger {
		titleMax, keys, valMax = 300, 10, 200
	}
	attrs := make(map[string]string, len(s.Attrs))
	for k, v := range s.Attrs {
		if k != "raw" { // the raw CloudTrail record only through get_cloudtrail_events
			attrs[k] = v
		}
	}
	r := dSignal{Ref: KindSignal + ":" + s.ID, Type: s.Type, Severity: string(s.Severity), Start: ts(s.Start),
		Object: e.Line(objectString(s.Object.Kind, s.Object.Namespace, s.Object.Name, incNS), 200), Title: e.Line(s.Title, titleMax),
		Value: numPtr(s.Value), Baseline: numPtr(s.Baseline), Threshold: numPtr(s.Threshold), Count: s.Count,
		Attrs: e.Map(attrs, keys, valMax), at: s.Start}
	if s.End != nil {
		r.End = ts(*s.End)
	} else if incidents.IsCondition(s.Type) {
		r.Ongoing = true
	}
	return r
}

func sortByDistance[T any](l []T, at func(T) time.Time, ref time.Time) {
	dist := func(t time.Time) time.Duration {
		d := t.Sub(ref)
		if d < 0 {
			return -d
		}
		return d
	}
	sort.SliceStable(l, func(i, j int) bool { return dist(at(l[i])) < dist(at(l[j])) })
}

// condenseContext replaces the context signals with the first and last of
// each type and the count.
func (d *digestDoc) condenseContext() {
	byType := map[string][]dSignal{}
	var types []string
	for _, s := range d.Context {
		if _, ok := byType[s.Type]; !ok {
			types = append(types, s.Type)
		}
		byType[s.Type] = append(byType[s.Type], s)
	}
	d.ContextGroups = groupSignals(types, byType)
	// Biggest groups last, so trimming drops the noisiest type first.
	sort.SliceStable(d.ContextGroups, func(i, j int) bool { return d.ContextGroups[i].Count < d.ContextGroups[j].Count })
	d.Context = nil
	d.Truncated["context"] = "condensed: first and last per type"
}

func groupSignals(types []string, byType map[string][]dSignal) []dGroup {
	var out []dGroup
	for _, t := range types {
		l := byType[t]
		sort.SliceStable(l, func(i, j int) bool { return l[i].at.Before(l[j].at) })
		g := dGroup{Type: t, Count: len(l), First: l[0]}
		if len(l) > 1 {
			last := l[len(l)-1]
			g.Last = &last
		}
		out = append(out, g)
	}
	return out
}

func (e *Egress) metricRecord(s incidents.Series, from, to time.Time) (dMetric, bool) {
	label := e.Line(s.Label, 200)
	m := dMetric{Ref: KindMetric + ":" + s.Metric + ":" + label, Metric: s.Metric, Label: label, Unit: s.Unit, from: from, to: to,
		nbucks: digestBuckets}
	var sum float64
	n := 0
	for _, p := range s.Points {
		v := p[1]
		if math.IsNaN(v) || math.IsInf(v, 0) {
			continue
		}
		m.raw = append(m.raw, p)
		if n == 0 {
			m.Min, m.Max, m.First = num(v), num(v), num(v)
			m.peak = time.UnixMilli(int64(p[0]))
		}
		if v < float64(m.Min) {
			m.Min = num(v)
		}
		if v > float64(m.Max) {
			m.Max = num(v)
			m.peak = time.UnixMilli(int64(p[0]))
		}
		m.Last = num(v)
		sum += v
		n++
	}
	if n == 0 {
		return m, false
	}
	m.Points = n
	m.Mean = num(sum / float64(n))
	m.PeakAt = ts(m.peak)
	m.Bucket = downsample(m.raw, from, to, m.nbucks)
	return m, true
}

// downsample folds points into n equal buckets over [from, to], keeping
// each bucket's maximum, so peaks survive.
func downsample(points [][2]float64, from, to time.Time, n int) *bucket {
	if n <= 0 || len(points) == 0 {
		return nil
	}
	if !to.After(from) {
		from = time.UnixMilli(int64(points[0][0]))
		to = time.UnixMilli(int64(points[len(points)-1][0]))
	}
	step := int64(math.Ceil(to.Sub(from).Seconds() / float64(n)))
	if step < 1 {
		step = 1
	}
	b := &bucket{From: ts(from), Step: step, Max: make([]*num, n)}
	start := from.UnixMilli()
	for _, p := range points {
		i := int((int64(p[0]) - start) / (step * 1000))
		if i < 0 {
			i = 0
		}
		if i >= n {
			i = n - 1
		}
		if b.Max[i] == nil || num(p[1]) > *b.Max[i] {
			v := num(p[1])
			b.Max[i] = &v
		}
	}
	return b
}

// eventGroups folds events by reason, type and object: the 50 biggest,
// warnings first.
func (e *Egress) eventGroups(evs []incidents.BundleEvent, incNS string) []dEvent {
	type agg struct {
		g      dEvent
		first  time.Time
		latest *incidents.BundleEvent
	}
	groups := map[string]*agg{}
	var order []string
	for i := range evs {
		ev := &evs[i]
		obj := objectString(ev.Regarding.Kind, ev.Regarding.Namespace, ev.Regarding.Name, incNS)
		k := ev.Reason + "\x00" + ev.Type + "\x00" + obj
		a, ok := groups[k]
		if !ok {
			a = &agg{g: dEvent{Type: ev.Type, Reason: e.Line(ev.Reason, 128), Object: e.Line(obj, 200), warn: ev.Type == "Warning"},
				first: ev.FirstSeen}
			groups[k] = a
			order = append(order, k)
		}
		c := int(ev.Count)
		if c < 1 {
			c = 1
		}
		a.g.Count += c
		a.g.Events++
		if ev.FirstSeen.Before(a.first) {
			a.first = ev.FirstSeen
		}
		if a.latest == nil || ev.LastSeen.After(a.latest.LastSeen) {
			a.latest = ev
		}
	}
	out := make([]dEvent, 0, len(order))
	for _, k := range order {
		a := groups[k]
		g := a.g
		g.Ref = KindEvent + ":" + a.latest.UID
		g.First, g.Last, g.last = ts(a.first), ts(a.latest.LastSeen), a.latest.LastSeen
		g.Source = e.Line(a.latest.Source, 64)
		g.Sample = e.Line(a.latest.Message, 300)
		if g.Events == 1 {
			g.Events = 0
		}
		out = append(out, g)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].warn != out[j].warn {
			return out[i].warn
		}
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].last.After(out[j].last)
	})
	if len(out) > digestMaxEvents {
		out = out[:digestMaxEvents]
	}
	return out
}

var (
	reTimestamp = regexp.MustCompile(`\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?|\b\d{2}:\d{2}:\d{2}(?:\.\d+)?\b|\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [ \d]\d\b|\b[IWEF]\d{4}\b`)
	reUUID      = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	reIPv4      = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b`)
	reIPv6      = regexp.MustCompile(`(?i)\b[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}`)
	reHex       = regexp.MustCompile(`(?i)\b0x[0-9a-f]+\b|\b[0-9a-f]{8,}\b`)
	reDigits    = regexp.MustCompile(`\d+`)
	reSpaces    = regexp.MustCompile(`\s+`)
)

// logTemplate strips what varies between lines of the same kind:
// timestamps, UUIDs, IP addresses, hex strings and numbers.
// Only the start of a line decides its template.
func logTemplate(s string) string {
	s = cut(s, 512)
	digits := strings.ContainsAny(s, "0123456789")
	if digits {
		s = reTimestamp.ReplaceAllString(s, "{ts}")
		if strings.Contains(s, "-") {
			s = reUUID.ReplaceAllString(s, "{uuid}")
		}
		if strings.Contains(s, ".") {
			s = reIPv4.ReplaceAllString(s, "{ip}")
		}
		if strings.Count(s, ":") >= 2 {
			s = reIPv6.ReplaceAllStringFunc(s, func(m string) string {
				if strings.Count(m, ":") >= 2 && strings.ContainsAny(m, "0123456789") {
					return "{ip}"
				}
				return m
			})
		}
		s = reHex.ReplaceAllStringFunc(s, func(m string) string {
			if strings.HasPrefix(strings.ToLower(m), "0x") || strings.ContainsAny(m, "0123456789") {
				return "{hex}"
			}
			return m
		})
		s = reDigits.ReplaceAllString(s, "{n}")
	}
	return strings.TrimSpace(reSpaces.ReplaceAllString(s, " "))
}

func levelRank(l string) int {
	switch strings.ToLower(l) {
	case "error", "fatal", "critical", "panic", "err", "crit", "emerg", "alert":
		return 0
	case "warn", "warning":
		return 1
	}
	return 2
}

// logTemplates groups log lines by template: the 40 biggest, errors first,
// each with two samples nearest a trigger.
func (e *Egress) logTemplates(lines []incidents.LogLine, triggers []time.Time) []dLogTpl {
	type cand struct {
		dist time.Duration
		l    *incidents.LogLine
	}
	type agg struct {
		t       dLogTpl
		rank    int
		pods    map[string]bool
		podList []string
		last    time.Time
		samples []cand
	}
	nearest := func(t time.Time) time.Duration {
		best := time.Duration(math.MaxInt64)
		for _, tr := range triggers {
			d := t.Sub(tr)
			if d < 0 {
				d = -d
			}
			if d < best {
				best = d
			}
		}
		return best
	}
	groups := map[string]*agg{}
	var order []string
	for i := range lines {
		l := &lines[i]
		text := e.Line(l.Text, 2048)
		key := cut(logTemplate(text), 300)
		a, ok := groups[key]
		if !ok {
			a = &agg{t: dLogTpl{Template: key, Level: l.Level, first: l.Time}, rank: levelRank(l.Level), pods: map[string]bool{}}
			groups[key] = a
			order = append(order, key)
		}
		a.t.Count++
		if r := levelRank(l.Level); r < a.rank {
			a.rank, a.t.Level = r, l.Level
		}
		if !a.pods[l.Pod] {
			a.pods[l.Pod] = true
			a.podList = append(a.podList, l.Pod)
		}
		if l.Time.Before(a.t.first) {
			a.t.first = l.Time
		}
		if l.Time.After(a.last) {
			a.last = l.Time
		}
		c := cand{dist: nearest(l.Time), l: l}
		dup := false
		for j, s := range a.samples {
			if s.l.Text == l.Text {
				dup = true
				if c.dist < s.dist {
					a.samples[j] = c
				}
			}
		}
		if !dup {
			a.samples = append(a.samples, c)
			sort.SliceStable(a.samples, func(i, j int) bool { return a.samples[i].dist < a.samples[j].dist })
			if len(a.samples) > digestSamples {
				a.samples = a.samples[:digestSamples]
			}
		}
	}
	out := make([]dLogTpl, 0, len(order))
	ranks := map[string]int{}
	for _, k := range order {
		a := groups[k]
		t := a.t
		t.Level = strings.ToLower(t.Level)
		t.First, t.Last = ts(t.first), ts(a.last)
		t.Pods, t.PodsTotal = capList(a.podList, 3, e)
		sort.SliceStable(a.samples, func(i, j int) bool { return a.samples[i].l.Time.Before(a.samples[j].l.Time) })
		for _, s := range a.samples {
			t.Samples = append(t.Samples, dLogSample{Time: ts(s.l.Time), Pod: e.Line(s.l.Pod, 128), Container: e.Line(s.l.Container, 64),
				Text: e.Text(s.l.Text, 400)})
		}
		ranks[k] = a.rank
		out = append(out, t)
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := ranks[out[i].Template], ranks[out[j].Template]
		if ri != rj {
			return ri < rj
		}
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].first.Before(out[j].first)
	})
	if len(out) > digestMaxTemplates {
		out = out[:digestMaxTemplates]
	}
	for i := range out {
		out[i].Ref = KindLogTpl + ":" + strconv.Itoa(i+1)
	}
	return out
}

var writeVerbs = map[string]bool{"create": true, "update": true, "patch": true, "delete": true, "deletecollection": true}

var sessionSubresources = map[string]bool{"exec": true, "attach": true, "portforward": true, "proxy": true, "ephemeralcontainers": true}

// auditRecords keeps writes, tagged events and interactive sessions: the
// 100 nearest the incident start, without source IPs or user agents.
func (e *Egress) auditRecords(evs []audit.Event, incNS string, start time.Time) []dAudit {
	var out []dAudit
	for i := range evs {
		ev := &evs[i]
		if !writeVerbs[ev.Verb] && len(ev.Tags) == 0 && !sessionSubresources[ev.Subresource] {
			continue
		}
		out = append(out, e.auditRecord(ev, incNS))
	}
	sortByDistance(out, func(a dAudit) time.Time { return a.at }, start)
	if len(out) > digestMaxAudit {
		out = out[:digestMaxAudit]
	}
	return out
}

// auditRecord is an audit event as the model sees it: no source IPs, no
// user agent; the request URI only for subresource requests (an exec's
// command), redacted.
func (e *Egress) auditRecord(ev *audit.Event, incNS string) dAudit {
	res := ev.Resource
	if ev.Subresource != "" {
		res += "/" + ev.Subresource
	}
	if ev.APIGroup != "" {
		res += "." + ev.APIGroup
	}
	r := dAudit{Ref: KindAudit + ":" + ev.AuditID, Time: ts(ev.Time), User: e.Line(ev.Username, 200), ActorKind: ev.ActorKind,
		Verb: e.Line(ev.Verb, 32), Resource: e.Line(res, 128), Name: e.Line(ev.Name, 200), Status: ev.StatusCode, Decision: ev.Decision,
		at: ev.Time}
	if ev.Namespace != incNS {
		r.Namespace = e.Line(ev.Namespace, 128)
	}
	for _, t := range ev.Tags {
		r.Tags = append(r.Tags, e.Line(t, 64))
	}
	if ev.Subresource != "" {
		r.URI = e.Line(ev.RequestURI, 300)
	}
	return r
}

func (e *Egress) cloudTrailRecords(cts []incidents.BundleCloudTrail, start time.Time) []dCloudTrail {
	out := make([]dCloudTrail, 0, len(cts))
	for i := range cts {
		out = append(out, e.cloudTrailRecord(&cts[i], 5))
	}
	sortByDistance(out, func(c dCloudTrail) time.Time { return c.at }, start)
	if len(out) > digestMaxCloudTrail {
		out = out[:digestMaxCloudTrail]
	}
	return out
}

func (e *Egress) cloudTrailRecord(c *incidents.BundleCloudTrail, maxRes int) dCloudTrail {
	r := dCloudTrail{Ref: KindCloudTrail + ":" + c.ID, Time: ts(c.Time), Name: e.Line(c.Name, 128), Source: e.Line(c.Source, 128),
		Region: e.Line(c.Region, 32), Actor: e.Line(c.Actor, 300), at: c.Time}
	for i, res := range c.Resources {
		if i >= maxRes {
			break
		}
		r.Resources = append(r.Resources, e.Line(res, 300))
	}
	return r
}

func jsonLen(v any) int {
	b, err := json.Marshal(v)
	if err != nil {
		return 0
	}
	return len(b)
}

// marshal renders the digest with audit, CloudTrail and context records in
// time order (they are kept nearest-first for trimming).
func (d *digestDoc) marshal() []byte {
	c := *d
	c.Audit = append([]dAudit(nil), d.Audit...)
	sort.SliceStable(c.Audit, func(i, j int) bool { return c.Audit[i].at.Before(c.Audit[j].at) })
	c.CloudTrail = append([]dCloudTrail(nil), d.CloudTrail...)
	sort.SliceStable(c.CloudTrail, func(i, j int) bool { return c.CloudTrail[i].at.Before(c.CloudTrail[j].at) })
	c.Context = append([]dSignal(nil), d.Context...)
	sort.SliceStable(c.Context, func(i, j int) bool { return c.Context[i].at.Before(c.Context[j].at) })
	if len(c.Truncated) == 0 {
		c.Truncated = nil
	}
	b, err := json.Marshal(&c)
	if err != nil {
		return []byte(`{}`)
	}
	return b
}

// trimTail drops elements from the end of l until over bytes are freed;
// it reports how many it dropped.
func trimTail[T any](l *[]T, over int) int {
	n := 0
	for len(*l) > 0 && over > 0 {
		last := (*l)[len(*l)-1]
		over -= jsonLen(last) + 1
		*l = (*l)[:len(*l)-1]
		n++
	}
	return n
}

// fit trims the digest until it is at most budget bytes.
func (d *digestDoc) fit(budget int) []byte {
	stages := []func(over int) bool{
		func(over int) bool { return d.trimSection("log_templates", &d.LogTemplates, over) },
		func(over int) bool { return d.trimSection("events", &d.Events, over) },
		func(over int) bool { return d.trimSection("audit", &d.Audit, over) },
		func(over int) bool { return d.trimSection("cloudtrail", &d.CloudTrail, over) },
		func(over int) bool {
			if len(d.Context) > 0 {
				d.condenseContext()
				return true
			}
			return d.trimSection("context", &d.ContextGroups, over)
		},
		d.trimMetrics,
		d.trimHeader,
		d.condenseTriggers,
		d.collapse,
	}
	for {
		data := d.marshal()
		over := len(data) - budget
		if over <= 0 {
			return data
		}
		trimmed := false
		for _, st := range stages {
			if st(over) {
				trimmed = true
				break
			}
		}
		if !trimmed {
			return data // nothing left to give up (a budget below the header)
		}
	}
}

func (d *digestDoc) trimSection(name string, l any, over int) bool {
	var n int
	switch t := l.(type) {
	case *[]dLogTpl:
		n = trimTail(t, over)
	case *[]dEvent:
		n = trimTail(t, over)
	case *[]dAudit:
		n = trimTail(t, over)
	case *[]dCloudTrail:
		n = trimTail(t, over)
	case *[]dGroup:
		n = trimTail(t, over)
	}
	if n > 0 {
		d.Truncated[name] = "digest budget"
	}
	return n > 0
}

// trimMetrics halves the downsample resolution (30, 15, 8, 4 buckets), then
// drops the downsamples, then whole series from the end.
func (d *digestDoc) trimMetrics(over int) bool {
	if len(d.Metrics) == 0 {
		return false
	}
	d.Truncated["metrics"] = "digest budget"
	if n := d.Metrics[0].nbucks; n > 4 {
		n = (n + 1) / 2
		for i := range d.Metrics {
			m := &d.Metrics[i]
			m.nbucks = n
			m.Bucket = downsample(m.raw, m.from, m.to, n)
		}
		return true
	}
	if d.Metrics[0].Bucket != nil {
		for i := range d.Metrics {
			d.Metrics[i].Bucket, d.Metrics[i].nbucks = nil, 0
		}
		return true
	}
	return trimTail(&d.Metrics, over) > 0
}

// condenseTriggers is the last resort: drop the triggers' attributes, then
// cut their titles, then fold them by type.
func (d *digestDoc) condenseTriggers(int) bool {
	switch d.trigLevel {
	case 0:
		for i := range d.Triggers {
			d.Triggers[i].Attrs = nil
		}
	case 1:
		for i := range d.Triggers {
			d.Triggers[i].Title = cutText(d.Triggers[i].Title, 80)
			d.Triggers[i].Object = cutText(d.Triggers[i].Object, 80)
		}
	case 2:
		byType := map[string][]dSignal{}
		var types []string
		for _, s := range d.Triggers {
			if _, ok := byType[s.Type]; !ok {
				types = append(types, s.Type)
			}
			byType[s.Type] = append(byType[s.Type], s)
		}
		d.TriggerGroups = groupSignals(types, byType)
		d.Triggers = []dSignal{}
	case 3, 4:
		// Then only the first of each type, shorter, then bare.
		for i := range d.TriggerGroups {
			g := &d.TriggerGroups[i]
			g.Last = nil
			if d.trigLevel == 3 {
				g.First.Title, g.First.Object = cutText(g.First.Title, 60), cutText(g.First.Object, 60)
			} else {
				g.First.Title, g.First.Object, g.First.End = "", "", ""
				g.First.Value, g.First.Baseline, g.First.Threshold = nil, nil, nil
			}
		}
	default:
		return false
	}
	d.trigLevel++
	d.Truncated["triggers"] = "condensed"
	return true
}

// trimHeader shortens the header's lists and tags.
func (d *digestDoc) trimHeader(int) bool {
	in := &d.Incident
	if len(in.Pods) <= 3 && len(in.Services) <= 3 && len(in.Nodes) <= 3 && in.Tags == nil && len(in.Title) <= 120 {
		return false
	}
	if len(in.Pods) > 3 {
		if in.PodsTotal == 0 {
			in.PodsTotal = len(in.Pods)
		}
		in.Pods = in.Pods[:3]
	}
	if len(in.Services) > 3 {
		in.Services = in.Services[:3]
	}
	if len(in.Nodes) > 3 {
		in.Nodes = in.Nodes[:3]
	}
	in.Tags = nil
	in.Title = cutText(in.Title, 120)
	d.Truncated["incident"] = "digest budget"
	return true
}

// collapse is the end of the line: the header's essentials and the trigger
// types only (a budget this small is refused by Options.Validate).
func (d *digestDoc) collapse(int) bool {
	if d.Truncated["digest"] != "" {
		return false
	}
	d.Context, d.ContextGroups, d.Metrics, d.Events, d.LogTemplates, d.Audit, d.CloudTrail = nil, nil, nil, nil, nil, nil, nil
	in := &d.Incident
	in.Title, in.Subject = cutText(in.Title, 60), cutText(in.Subject, 120)
	in.Pods, in.Services, in.Nodes, in.Tags, in.Counts, in.Owner, in.Previous = nil, nil, nil, nil, nil, "", ""
	d.Cluster = cutText(d.Cluster, 40)
	for k, v := range d.Omitted {
		d.Omitted[k] = cutText(v, 20)
	}
	d.Truncated = map[string]string{"digest": "budget too small: header and trigger types only"}
	return true
}

// record adds every ref the digest shows to the ledger.
func (d *digestDoc) record(l *Ledger) {
	sig := func(s dSignal) {
		l.Add(Evidence{Ref: s.Ref, Kind: KindSignal, Time: s.at, Object: s.Object, Snippet: s.Title})
	}
	for _, s := range d.Triggers {
		sig(s)
	}
	for _, g := range append(append([]dGroup{}, d.TriggerGroups...), d.ContextGroups...) {
		sig(g.First)
		if g.Last != nil {
			sig(*g.Last)
		}
	}
	for _, s := range d.Context {
		sig(s)
	}
	for _, m := range d.Metrics {
		l.Add(Evidence{Ref: m.Ref, Kind: KindMetric, Time: m.peak, Object: m.Label,
			Snippet: "max " + strconv.FormatFloat(float64(m.Max), 'g', 4, 64) + " " + m.Unit + " at " + m.PeakAt})
	}
	for _, ev := range d.Events {
		l.Add(Evidence{Ref: ev.Ref, Kind: KindEvent, Time: ev.last, Object: ev.Object, Snippet: ev.Reason + ": " + ev.Sample})
	}
	for _, t := range d.LogTemplates {
		l.Add(Evidence{Ref: t.Ref, Kind: KindLogTpl, Time: t.first, Object: strings.Join(t.Pods, ", "), Snippet: t.Template})
	}
	for _, a := range d.Audit {
		l.Add(Evidence{Ref: a.Ref, Kind: KindAudit, Time: a.at, Object: a.Resource + " " + a.Name,
			Snippet: a.User + " " + a.Verb + " " + a.Resource + " " + a.Name})
	}
	for _, c := range d.CloudTrail {
		obj := ""
		if len(c.Resources) > 0 {
			obj = c.Resources[0]
		}
		l.Add(Evidence{Ref: c.Ref, Kind: KindCloudTrail, Time: c.at, Object: obj, Snippet: c.Actor + " called " + c.Name})
	}
}
