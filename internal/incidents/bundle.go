package incidents

import (
	"bufio"
	"encoding/json"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/model"
)

// BundleSchema names the bundle format.
const BundleSchema = "kubesentry.io/incident-bundle/v1"

// Bundle sections, as named in omitted and truncated.
const (
	SectionSignals    = "signals"
	SectionMetrics    = "metrics"
	SectionEvents     = "events"
	SectionLogs       = "logs"
	SectionAudit      = "audit"
	SectionCloudTrail = "cloudtrail"
)

// Bundle caps.
const (
	BundleMaxLogLines   = 2000
	BundleMaxLogBytes   = 1 << 20
	BundleMaxEvents     = 2000
	BundleMaxAudit      = 1000
	BundleMaxCloudTrail = 500
	BundleMaxBytes      = 4 << 20
)

// BundleWindow is the padded range the bundle covers.
type BundleWindow struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

// BundleHeader is the first NDJSON record and the top of the JSON form
// (web/src/types.ts IncidentBundleHeader).
type BundleHeader struct {
	Schema      string       `json:"schema"`
	GeneratedAt time.Time    `json:"generatedAt"`
	Cluster     string       `json:"cluster,omitempty"`
	Incident    Incident     `json:"incident"`
	Window      BundleWindow `json:"window"`
	// Complete is false when sections were left out (Omitted).
	Complete bool `json:"complete"`
	// Omitted lists the sections left out, with why ("forbidden", "absent").
	Omitted map[string]string `json:"omitted,omitempty"`
	// Truncated marks the sections cut at their cap.
	Truncated map[string]bool `json:"truncated,omitempty"`
}

// BundleObject names a Kubernetes or AWS object.
type BundleObject struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	UID       string `json:"uid,omitempty"`
}

func bundleObject(o model.ObjectRef) BundleObject {
	return BundleObject{Kind: o.Kind, Namespace: o.Namespace, Name: o.Name, UID: o.UID}
}

// BundleSignal is a signal record (web/src/types.ts IncidentSignal).
type BundleSignal struct {
	ID        string            `json:"id"`
	Type      string            `json:"type"`
	Source    string            `json:"source"`
	Role      Role              `json:"role"`
	Severity  Severity          `json:"severity,omitempty"`
	Start     time.Time         `json:"start"`
	End       *time.Time        `json:"end,omitempty"`
	Subject   Subject           `json:"subject"`
	Object    BundleObject      `json:"object"`
	Title     string            `json:"title"`
	Value     *float64          `json:"value,omitempty"`
	Baseline  *float64          `json:"baseline,omitempty"`
	Threshold *float64          `json:"threshold,omitempty"`
	Count     int               `json:"count,omitempty"`
	Tags      map[string]string `json:"tags,omitempty"`
	Attrs     map[string]string `json:"attrs,omitempty"`
}

// BundleSignalOf converts a signal to its record.
func BundleSignalOf(s Signal) BundleSignal {
	return BundleSignal{ID: s.ID, Type: s.Type, Source: s.Source, Role: s.Role, Severity: s.Severity, Start: s.Start, End: s.End,
		Subject: s.Subject, Object: bundleObject(s.Object), Title: s.Title, Value: s.Value, Baseline: s.Baseline, Threshold: s.Threshold,
		Count: s.Count, Tags: s.Tags, Attrs: s.Attrs}
}

// BundleEvent is a Kubernetes event record (web/src/types.ts IncidentKubeEvent).
type BundleEvent struct {
	UID       string       `json:"uid"`
	Namespace string       `json:"namespace,omitempty"`
	Type      string       `json:"type"`
	Reason    string       `json:"reason"`
	Message   string       `json:"message"`
	Count     int32        `json:"count"`
	FirstSeen time.Time    `json:"firstSeen"`
	LastSeen  time.Time    `json:"lastSeen"`
	Regarding BundleObject `json:"regarding"`
	Source    string       `json:"source,omitempty"`
	Subject   *Subject     `json:"subject,omitempty"`
}

// BundleEventOf converts a stored event to its record.
func BundleEventOf(e StoredEvent) BundleEvent {
	return BundleEvent{UID: e.UID, Namespace: e.Namespace, Type: e.Type, Reason: e.Reason, Message: e.Message, Count: e.Count,
		FirstSeen: e.FirstSeen, LastSeen: e.LastSeen, Regarding: bundleObject(e.Regarding), Source: e.Source, Subject: e.Subject}
}

// BundleCloudTrail is a CloudTrail record, from a cloudtrail-change signal.
type BundleCloudTrail struct {
	ID        string    `json:"id"`
	Time      time.Time `json:"time"`
	Name      string    `json:"name"`
	Source    string    `json:"source"`
	Region    string    `json:"region,omitempty"`
	Actor     string    `json:"actor"`
	Resources []string  `json:"resources,omitempty"`
	Matched   []string  `json:"matched,omitempty"`
	// Raw is the redacted event, cut to MaxAttrLen bytes.
	Raw string `json:"raw,omitempty"`
}

// Bundle is everything known about one incident, for an agent to read.
type Bundle struct {
	BundleHeader
	Signals    []BundleSignal     `json:"signals"`
	Metrics    []Series           `json:"metrics"`
	Events     []BundleEvent      `json:"events"`
	Logs       []LogLine          `json:"logs"`
	Audit      []audit.Event      `json:"audit"`
	CloudTrail []BundleCloudTrail `json:"cloudtrail"`
}

// BundleInput is what a bundle is made of. Sections the caller may not see
// are named in Omitted (with the reason) and their data left nil.
type BundleInput struct {
	Cluster       string
	Incident      Incident
	From, To      time.Time
	Signals       []Signal
	Metrics       []Series
	Events        []StoredEvent
	Logs          []LogLine
	LogsTruncated bool
	Audit         []audit.Event
	Omitted       map[string]string
	GeneratedAt   time.Time
}

// BuildBundle assembles and redacts a bundle, applying the caps: logs 2,000
// lines and 1 MiB, events 2,000, audit 1,000, CloudTrail 500, and 4 MiB in
// all (logs give way first, then events, audit, CloudTrail and metrics).
// Signals of an omitted audit or CloudTrail section are left out too.
func BuildBundle(in BundleInput, red *Redactor) *Bundle {
	b := &Bundle{BundleHeader: BundleHeader{Schema: BundleSchema, GeneratedAt: NormalTime(in.GeneratedAt), Cluster: in.Cluster,
		Window: BundleWindow{From: in.From, To: in.To}, Truncated: map[string]bool{}}}
	inc := CloneIncident(in.Incident)
	inc.Title = red.String(inc.Title)
	b.Incident = inc
	if len(in.Omitted) > 0 {
		b.Omitted = make(map[string]string, len(in.Omitted))
		for k, v := range in.Omitted {
			b.Omitted[k] = v
		}
	}
	omitted := func(s string) bool { _, ok := b.Omitted[s]; return ok }
	b.Complete = len(b.Omitted) == 0

	b.Signals = []BundleSignal{}
	b.CloudTrail = []BundleCloudTrail{}
	seenCT := map[string]bool{}
	for _, s := range in.Signals {
		if (s.Type == TypeAuditChange && omitted(SectionAudit)) || (s.Type == TypeCloudTrailChange && omitted(SectionCloudTrail)) {
			continue
		}
		s = red.Signal(s)
		b.Signals = append(b.Signals, BundleSignalOf(s))
		if s.Type == TypeCloudTrailChange && !seenCT[s.ID] {
			seenCT[s.ID] = true
			b.CloudTrail = append(b.CloudTrail, cloudTrailRecord(&s))
		}
	}
	if len(b.CloudTrail) > BundleMaxCloudTrail {
		b.CloudTrail = b.CloudTrail[len(b.CloudTrail)-BundleMaxCloudTrail:]
		b.Truncated[SectionCloudTrail] = true
	}

	b.Metrics = []Series{}
	if !omitted(SectionMetrics) {
		b.Metrics = append(b.Metrics, in.Metrics...)
	}

	b.Events = []BundleEvent{}
	if !omitted(SectionEvents) {
		evs := append([]StoredEvent(nil), in.Events...)
		sort.Slice(evs, func(i, j int) bool {
			if !evs[i].FirstSeen.Equal(evs[j].FirstSeen) {
				return evs[i].FirstSeen.Before(evs[j].FirstSeen)
			}
			return evs[i].UID < evs[j].UID
		})
		if len(evs) > BundleMaxEvents {
			evs = evs[len(evs)-BundleMaxEvents:]
			b.Truncated[SectionEvents] = true
		}
		for _, e := range evs {
			e.Message = red.String(e.Message)
			b.Events = append(b.Events, BundleEventOf(e))
		}
	}

	b.Logs = []LogLine{}
	if !omitted(SectionLogs) {
		size := 0
		for i, l := range in.Logs {
			l.Text = red.String(l.Text)
			size += len(l.Text) + len(l.Pod) + len(l.Container) + 64
			if i >= BundleMaxLogLines || size > BundleMaxLogBytes {
				b.Truncated[SectionLogs] = true
				break
			}
			b.Logs = append(b.Logs, l)
		}
		if in.LogsTruncated {
			b.Truncated[SectionLogs] = true
		}
	}

	b.Audit = []audit.Event{}
	if !omitted(SectionAudit) {
		evs := in.Audit
		if len(evs) > BundleMaxAudit {
			evs = evs[:BundleMaxAudit]
			b.Truncated[SectionAudit] = true
		}
		for _, e := range evs {
			e.RequestURI = red.String(e.RequestURI)
			e.UserAgent = red.String(e.UserAgent)
			b.Audit = append(b.Audit, e)
		}
	}
	b.fit(BundleMaxBytes)
	if len(b.Truncated) == 0 {
		b.Truncated = nil
	}
	return b
}

func cloudTrailRecord(s *Signal) BundleCloudTrail {
	split := func(v string) []string {
		if v == "" {
			return nil
		}
		return strings.Split(v, ",")
	}
	return BundleCloudTrail{ID: s.Attrs["eventID"], Time: s.Start, Name: s.Attrs["eventName"], Source: s.Attrs["eventSource"],
		Region: s.Attrs["region"], Actor: s.Attrs["actor"], Resources: split(s.Attrs["resources"]), Matched: split(s.Attrs["matched"]),
		Raw: s.Attrs["raw"]}
}

func jsonSize(v any) int {
	b, err := json.Marshal(v)
	if err != nil {
		return 0
	}
	return len(b) + 1
}

// fit trims sections, last records first, until the bundle is at most max
// bytes of JSON.
func (b *Bundle) fit(max int) {
	sizes := func() (logs, events, aud, ct, metrics []int, total int) {
		total = jsonSize(b.BundleHeader) + jsonSize(b.Signals)
		for _, l := range b.Logs {
			n := jsonSize(l)
			logs = append(logs, n)
			total += n
		}
		for _, e := range b.Events {
			n := jsonSize(e)
			events = append(events, n)
			total += n
		}
		for _, e := range b.Audit {
			n := jsonSize(e)
			aud = append(aud, n)
			total += n
		}
		for _, c := range b.CloudTrail {
			n := jsonSize(c)
			ct = append(ct, n)
			total += n
		}
		for _, m := range b.Metrics {
			n := jsonSize(m)
			metrics = append(metrics, n)
			total += n
		}
		return
	}
	logs, events, aud, ct, metrics, total := sizes()
	if total <= max {
		return
	}
	trim := func(section string, ns []int, cut func(n int)) {
		k := len(ns)
		for k > 0 && total > max {
			k--
			total -= ns[k]
		}
		if k < len(ns) {
			cut(k)
			b.Truncated[section] = true
		}
	}
	trim(SectionLogs, logs, func(n int) { b.Logs = b.Logs[:n] })
	trim(SectionEvents, events, func(n int) { b.Events = b.Events[:n] })
	trim(SectionAudit, aud, func(n int) { b.Audit = b.Audit[:n] })
	trim(SectionCloudTrail, ct, func(n int) { b.CloudTrail = b.CloudTrail[:n] })
	trim(SectionMetrics, metrics, func(n int) { b.Metrics = b.Metrics[:n] })
}

// WriteJSON writes the bundle as one JSON document.
func (b *Bundle) WriteJSON(w io.Writer) error {
	return json.NewEncoder(w).Encode(b)
}

// WriteNDJSON writes the header, then one record per line:
// {"kind":"signal"|"metric"|"event"|"log"|"audit"|"cloudtrail", …fields}.
func (b *Bundle) WriteNDJSON(w io.Writer) error {
	bw := bufio.NewWriter(w)
	enc := func(kind string, v any) error {
		data, err := json.Marshal(v)
		if err != nil {
			return err
		}
		if kind != "" {
			bw.WriteString(`{"kind":"` + kind + `"`)
			if len(data) > 2 {
				bw.WriteByte(',')
				bw.Write(data[1:])
			} else {
				bw.WriteByte('}')
			}
		} else {
			bw.Write(data)
		}
		return bw.WriteByte('\n')
	}
	if err := enc("", b.BundleHeader); err != nil {
		return err
	}
	for _, s := range b.Signals {
		if err := enc("signal", s); err != nil {
			return err
		}
	}
	for _, m := range b.Metrics {
		if err := enc("metric", m); err != nil {
			return err
		}
	}
	for _, e := range b.Events {
		if err := enc("event", e); err != nil {
			return err
		}
	}
	for _, l := range b.Logs {
		if err := enc("log", l); err != nil {
			return err
		}
	}
	for _, a := range b.Audit {
		if err := enc("audit", a); err != nil {
			return err
		}
	}
	for _, c := range b.CloudTrail {
		if err := enc("cloudtrail", c); err != nil {
			return err
		}
	}
	return bw.Flush()
}
