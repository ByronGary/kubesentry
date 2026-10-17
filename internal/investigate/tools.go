package investigate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/incidents"
	"github.com/ByronGary/kubesentry/internal/model"
)

// IncidentSource is what the tools read about an incident.
// *incidents.Runner implements it as is.
type IncidentSource interface {
	// Get returns an incident and its signals (live, as the board has them).
	Get(ctx context.Context, id string) (incidents.Incident, []incidents.Signal, bool, error)
	// Bundle assembles the incident's bundle without the sections in
	// req.Omitted (the starting digest).
	Bundle(ctx context.Context, id string, req incidents.BundleRequest) (*incidents.Bundle, error)
	// Logs reads container logs in the padded window, redacted.
	Logs(ctx context.Context, id string, req incidents.LogRequest) (incidents.LogResponse, error)
	// Series returns the metric series in [from, to] within the window.
	Series(ctx context.Context, id string, from, to time.Time) ([]incidents.Series, error)
	// Events reads stored Kubernetes events.
	Events(ctx context.Context, q incidents.EventQuery) ([]incidents.StoredEvent, error)
	// AuditEvents returns the audit events of the incident's window, in its
	// namespace (or about its node).
	AuditEvents(ctx context.Context, in *incidents.Incident, limit int) ([]audit.Event, error)
}

// Source is everything the investigator reads: the incident (IncidentSource,
// from *incidents.Runner) and the current workload state (from the
// snapshot view). cmd/server implements it; tests use fakes. The
// investigator gates every call by the run's Access and never asks for more
// than the incident's own namespace, pods, nodes and window.
type Source interface {
	IncidentSource
	// WorkloadState returns the current state of the incident's subject:
	// its workload, its pods and the nodes they run on (or the node itself).
	WorkloadState(ctx context.Context, in *incidents.Incident) (*WorkloadState, error)
}

// WorkloadState is the current snapshot of an incident's subject.
type WorkloadState struct {
	// At is when the snapshot was read.
	At time.Time
	// Workload is the subject's workload; nil for a node or cluster
	// incident, or when it is gone.
	Workload *model.Workload
	Pods     []model.Pod
	Nodes    []model.Node
}

// Tool names.
const (
	ToolListSignals         = "list_signals"
	ToolGetLogs             = "get_logs"
	ToolGetMetricSeries     = "get_metric_series"
	ToolGetK8sEvents        = "get_k8s_events"
	ToolGetAuditEvents      = "get_audit_events"
	ToolGetCloudTrailEvents = "get_cloudtrail_events"
	ToolGetWorkloadState    = "get_workload_state"
	ToolSubmitReport        = "submit_report"
)

// Tool limits.
const (
	DefaultToolTimeout = 30 * time.Second
	maxLogLine         = 2 << 10
	maxEventMessage    = 500
	maxCloudTrailRaw   = 1 << 10
)

// errNotPermitted is the answer of a tool the starter may not use.
const errNotPermitted = "not permitted for the requesting user"

var signalTypes = []string{incidents.TypeRequestSpike, incidents.TypeErrorRate, incidents.TypeMemorySpike, incidents.TypeOOMKill,
	incidents.TypeRestart, incidents.TypeCrashLoop, incidents.TypeEviction, incidents.TypeKubeEvent, incidents.TypeAlert,
	incidents.TypeDeploy, incidents.TypeScale, incidents.TypeAuditChange, incidents.TypeCloudTrailChange, incidents.TypeLogErrors}

func timeProp(what string) *schema {
	return &schema{Type: "string", Format: "date-time", Description: what + " (RFC 3339, UTC). Clamped to the incident's padded window; omit for its edge."}
}

func limitProp(def, max int64) *schema {
	return &schema{Type: "integer", Min: i64(1), Max: i64(max), Description: fmt.Sprintf("Most records to return (default %d, at most %d).", def, max)}
}

// tool is one tool: its declaration, the access it needs, and what it does.
type tool struct {
	name   string
	desc   string
	in     *schema
	strict bool
	cap    int
	// needs reports whether the access permits the tool at all.
	needs func(Access) bool
	exec  func(t *toolbox, ctx context.Context, raw json.RawMessage) (*toolOutput, error)
}

func (tl *tool) def() ToolDef {
	return ToolDef{Name: tl.name, Description: tl.desc, InputSchema: tl.in.JSON(tl.strict), Strict: tl.strict}
}

var tools = []*tool{
	{
		name: ToolListSignals,
		desc: "List the incident's signals: triggers (request, error-rate and memory spikes, OOM kills, restarts, crash loops, evictions, " +
			"warning events, alerts, error-log bursts) and context (deploys, scaling, audit and CloudTrail changes). Filter by type, role " +
			"and time. Use it for signals the digest condensed or left out, or to see new ones on an open incident. Refs: signal:<id>.",
		in: &schema{Type: "object", Props: []prop{
			{"type", &schema{Type: "string", Enum: signalTypes, Description: "Only this signal type."}},
			{"role", &schema{Type: "string", Enum: []string{"trigger", "context"}, Description: "Only triggers or only context."}},
			{"from", timeProp("Signals active at or after this time")},
			{"to", timeProp("Signals that started at or before this time")},
			{"limit", limitProp(50, 200)},
		}},
		cap:  32 << 10,
		exec: (*toolbox).listSignals,
	},
	{
		name: ToolGetLogs,
		desc: "Read container log lines from the incident's pods within its window, redacted. Filter by pods (names from the digest), " +
			"containers, level, a substring and time; lines longer than 2 KiB are cut. Prefer narrow time ranges and a level or substring " +
			"over reading everything. Refs: log:<n>.",
		in: &schema{Type: "object", Props: []prop{
			{"pods", &schema{Type: "array", MaxItems: 5, Items: &schema{Type: "string"}, Description: "Up to 5 of the incident's pods (default: up to 10 of them)."}},
			{"containers", &schema{Type: "array", MaxItems: 5, Items: &schema{Type: "string"}, Description: "Up to 5 container names (default: all)."}},
			{"from", timeProp("Start")},
			{"to", timeProp("End")},
			{"level", &schema{Type: "string", Enum: []string{"error", "warn", "info", "debug"}, Description: "Only lines at this level."}},
			{"contains", &schema{Type: "string", MaxLength: 200, Description: "Only lines containing this text (case-sensitive)."}},
			{"limit", limitProp(100, 200)},
		}},
		cap:   48 << 10,
		needs: func(a Access) bool { return a.Logs },
		exec:  (*toolbox).getLogs,
	},
	{
		name: ToolGetMetricSeries,
		desc: "Read the incident's metric series (memory working set per container, request rate, error ratio) with statistics and up " +
			"to max_points points, downsampled so that peaks are kept. Narrow from and to for finer resolution. Refs: metric:<metric>:<label>.",
		in: &schema{Type: "object", Required: []string{"metric"}, Props: []prop{
			{"metric", &schema{Type: "string", Enum: []string{"memory", "requests", "errors"}, Description: "Which metric."}},
			{"label", &schema{Type: "string", MaxLength: 200, Description: "Only the series with this label (from the digest)."}},
			{"from", timeProp("Start")},
			{"to", timeProp("End")},
			{"max_points", &schema{Type: "integer", Min: i64(2), Max: i64(120), Description: "Points per series (default 60, at most 120)."}},
		}},
		cap:  24 << 10,
		exec: (*toolbox).getMetricSeries,
	},
	{
		name: ToolGetK8sEvents,
		desc: "Read Kubernetes events in the incident's namespace (and about its nodes, when permitted) within its window, newest first. " +
			"Filter by involved object kind and name, reason, type and time. Messages are cut to 500 characters. Refs: event:<uid>.",
		in: &schema{Type: "object", Props: []prop{
			{"object_kind", &schema{Type: "string", MaxLength: 64, Description: "Involved object kind, e.g. Pod, Deployment, Node."}},
			{"object_name", &schema{Type: "string", MaxLength: 253, Description: "Involved object name."}},
			{"reason", &schema{Type: "string", MaxLength: 128, Description: "Event reason, e.g. BackOff, OOMKilling, FailedScheduling."}},
			{"type", &schema{Type: "string", Enum: []string{"Normal", "Warning"}, Description: "Event type."}},
			{"from", timeProp("Start")},
			{"to", timeProp("End")},
			{"limit", limitProp(50, 200)},
		}},
		cap:  32 << 10,
		exec: (*toolbox).getK8sEvents,
	},
	{
		name: ToolGetAuditEvents,
		desc: "Read Kubernetes audit events (who did what) in the incident's namespace, or about its node, within its window. Filter by " +
			"verb, resource, user (substring), tag and time. Source addresses and client names are not included. Refs: audit:<id>.",
		in: &schema{Type: "object", Props: []prop{
			{"verb", &schema{Type: "string", MaxLength: 32, Description: "e.g. create, update, patch, delete, get."}},
			{"resource", &schema{Type: "string", MaxLength: 128, Description: "e.g. deployments, configmaps, pods/exec."}},
			{"user", &schema{Type: "string", MaxLength: 200, Description: "Part of the user name."}},
			{"tag", &schema{Type: "string", MaxLength: 64, Description: "Only events with this tag."}},
			{"from", timeProp("Start")},
			{"to", timeProp("End")},
			{"limit", limitProp(50, 100)},
		}},
		cap:   32 << 10,
		needs: func(a Access) bool { return a.Audit },
		exec:  (*toolbox).getAuditEvents,
	},
	{
		name: ToolGetCloudTrailEvents,
		desc: "Read the AWS CloudTrail write events kubesentry matched to this incident's resources (no new AWS calls), with the raw " +
			"record cut to 1 KiB. Filter by event name and time. Refs: cloudtrail:<id>.",
		in: &schema{Type: "object", Props: []prop{
			{"event_name", &schema{Type: "string", MaxLength: 128, Description: "e.g. AuthorizeSecurityGroupIngress."}},
			{"from", timeProp("Start")},
			{"to", timeProp("End")},
			{"limit", limitProp(20, 50)},
		}},
		cap:   32 << 10,
		needs: func(a Access) bool { return a.CloudTrail },
		exec:  (*toolbox).getCloudTrailEvents,
	},
	{
		name: ToolGetWorkloadState,
		desc: "Read the current state of the incident's workload from the latest cluster snapshot: replicas, conditions, images, pods " +
			"with container states, restarts and last terminations, and their nodes' conditions when permitted. This is the state now, " +
			"which can differ from the state during the incident.",
		in:   &schema{Type: "object"},
		cap:  16 << 10,
		exec: (*toolbox).getWorkloadState,
	},
	{
		name: ToolSubmitReport,
		desc: "Submit the investigation report. Call it once, at the end; it ends the investigation. Every evidence list holds refs " +
			"shown in the digest or in tool results. Commands in suggested_checks must be read-only.",
		in:     reportSchema,
		strict: true,
	},
}

var toolsByName = func() map[string]*tool {
	m := map[string]*tool{}
	for _, t := range tools {
		m[t.name] = t
	}
	return m
}()

// ToolDefs returns the tools as declared to the model, in a fixed order
// (the declaration is part of the cached prompt prefix).
func ToolDefs() []ToolDef {
	out := make([]ToolDef, 0, len(tools))
	for _, t := range tools {
		out = append(out, t.def())
	}
	return out
}

func toolNames() string {
	names := make([]string, 0, len(tools))
	for _, t := range tools {
		names = append(names, t.name)
	}
	return strings.Join(names, ", ")
}

// toolbox runs the tools of one investigation.
type toolbox struct {
	src     Source
	egress  *Egress
	access  Access
	inc     incidents.Incident
	from    time.Time
	to      time.Time
	open    bool
	now     func() time.Time
	ledger  *Ledger
	timeout time.Duration
	// bundleCT are the CloudTrail records of the starting bundle, used when
	// the live signals cannot be read.
	bundleCT []incidents.BundleCloudTrail
}

// toolOutput is a tool's answer before it is capped: a head (window,
// counts, notes) and a list of records, each with its ledger entry.
type toolOutput struct {
	head  map[string]any
	key   string
	items []shown
	step  string
}

type shown struct {
	rec any
	ev  Evidence
}

// toolResult is what one call answers.
type toolResult struct {
	content string
	isError bool
	result  string // ResultOK, ResultError, ResultDenied, ResultInvalid
	step    string
}

// invalidInput is a tool input that fails validation.
type invalidInput struct{ msg string }

func (e *invalidInput) Error() string { return e.msg }

func invalid(format string, a ...any) error { return &invalidInput{msg: fmt.Sprintf(format, a...)} }

// run executes one call. Submit_report is the agent's; it never gets here.
func (t *toolbox) run(ctx context.Context, name string, raw json.RawMessage) toolResult {
	tl, ok := toolsByName[name]
	if !ok || tl.exec == nil {
		return toolResult{content: fmt.Sprintf("unknown tool %q; the tools are: %s", cut(clean(name), 64), toolNames()), isError: true,
			result: ResultInvalid, step: "unknown tool"}
	}
	if tl.needs != nil && !tl.needs(t.access) {
		return toolResult{content: errNotPermitted, isError: true, result: ResultDenied, step: name + ": not permitted for the requesting user"}
	}
	if err := tl.in.check(raw, true); err != nil {
		return toolResult{content: "invalid input: " + err.Error(), isError: true, result: ResultInvalid, step: name + ": invalid input"}
	}
	timeout := t.timeout
	if timeout <= 0 {
		timeout = DefaultToolTimeout
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, err := tl.exec(t, cctx, raw)
	var inv *invalidInput
	switch {
	case errors.As(err, &inv):
		return toolResult{content: "invalid input: " + inv.msg, isError: true, result: ResultInvalid, step: name + ": invalid input"}
	case errors.Is(err, errDenied):
		return toolResult{content: errNotPermitted, isError: true, result: ResultDenied, step: name + ": not permitted for the requesting user"}
	case err != nil && cctx.Err() != nil && ctx.Err() == nil:
		return toolResult{content: fmt.Sprintf("timed out after %s", timeout), isError: true, result: ResultError, step: name + ": timed out"}
	case err != nil:
		return toolResult{content: "error: " + t.egress.Line(err.Error(), 300), isError: true, result: ResultError, step: name + ": failed"}
	}
	return toolResult{content: t.render(name, tl.cap, out), result: ResultOK, step: t.egress.Line(out.step, 200)}
}

// errDenied is a part of a tool the access does not cover (Node events).
var errDenied = errors.New(errNotPermitted)

// render caps the output at max bytes (dropping records from the end),
// wraps it as untrusted data and records the refs it shows.
func (t *toolbox) render(name string, max int, out *toolOutput) string {
	if out.head == nil {
		out.head = map[string]any{}
	}
	items := out.items
	build := func(n int) string {
		recs := make([]any, n)
		for i := range recs {
			recs[i] = items[i].rec
		}
		out.head[out.key] = recs
		return untrusted(name, out.head)
	}
	s := build(len(items))
	if len(s) > max && len(items) > 0 {
		out.head["truncated"] = true
		n := len(items)
		over := len(s) - max
		for n > 0 && over > 0 {
			n--
			over -= jsonLen(items[n].rec) + 1
		}
		s = build(n)
		for len(s) > max && n > 0 {
			n--
			s = build(n)
		}
		items = items[:n]
	}
	for _, it := range items {
		t.ledger.Add(it.ev)
	}
	return s
}

// window returns the range a tool may read: the padded window, extended to
// now while the incident is open.
func (t *toolbox) window() (time.Time, time.Time) {
	to := t.to
	if t.open {
		if now := t.now(); now.After(to) {
			to = now
		}
	}
	return t.from, to
}

// times parses and clamps a tool's from and to. Either may be empty.
func (t *toolbox) times(from, to string) (time.Time, time.Time, error) {
	wf, wt := t.window()
	var f, e time.Time
	var err error
	if from != "" {
		if f, err = time.Parse(time.RFC3339, from); err != nil {
			return f, e, invalid("from: not an RFC 3339 time")
		}
	}
	if to != "" {
		if e, err = time.Parse(time.RFC3339, to); err != nil {
			return f, e, invalid("to: not an RFC 3339 time")
		}
	}
	if !f.IsZero() && !e.IsZero() && f.After(e) {
		return f, e, invalid("from is after to")
	}
	if f.IsZero() || f.Before(wf) {
		f = wf
	}
	if e.IsZero() || e.After(wt) {
		e = wt
	}
	return f.UTC(), e.UTC(), nil
}

// span is "12:01–12:20" for step texts (with the date when they differ).
func span(f, e time.Time) string {
	if f.YearDay() != e.YearDay() || f.Year() != e.Year() {
		return f.Format("Jan 2 15:04") + "–" + e.Format("Jan 2 15:04")
	}
	return f.Format("15:04") + "–" + e.Format("15:04")
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

func decode(raw json.RawMessage, v any) error {
	if err := json.Unmarshal(raw, v); err != nil {
		return invalid("%s", cut(err.Error(), 120))
	}
	return nil
}

func limitOr(l, def int) int {
	if l <= 0 {
		return def
	}
	return l
}

func (t *toolbox) emptyWindow(f, e time.Time) bool { return !e.After(f) }

// ---- list_signals ----

type listSignalsIn struct {
	Type  string `json:"type"`
	Role  string `json:"role"`
	From  string `json:"from"`
	To    string `json:"to"`
	Limit int    `json:"limit"`
}

// signalVisible gates a signal by its source, as the incident page does.
func (a Access) signalVisible(typ string) bool {
	switch typ {
	case incidents.TypeAuditChange:
		return a.Audit
	case incidents.TypeCloudTrailChange:
		return a.CloudTrail
	}
	return true
}

func (t *toolbox) listSignals(ctx context.Context, raw json.RawMessage) (*toolOutput, error) {
	var in listSignalsIn
	if err := decode(raw, &in); err != nil {
		return nil, err
	}
	f, e, err := t.times(in.From, in.To)
	if err != nil {
		return nil, err
	}
	if in.Type != "" && !t.access.signalVisible(in.Type) {
		return nil, errDenied
	}
	_, sigs, ok, err := t.src.Get(ctx, t.inc.ID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("the incident is no longer stored")
	}
	var match []incidents.Signal
	for _, s := range sigs {
		if !t.access.signalVisible(s.Type) || (in.Type != "" && s.Type != in.Type) || (in.Role != "" && string(s.Role) != in.Role) {
			continue
		}
		if s.Start.After(e) {
			continue
		}
		if end, active := signalEnd(&s); !active && end.Before(f) {
			continue
		}
		match = append(match, s)
	}
	sort.SliceStable(match, func(i, j int) bool { return match[i].Start.Before(match[j].Start) })
	total := len(match)
	if l := limitOr(in.Limit, 50); len(match) > l {
		match = match[:l]
	}
	out := &toolOutput{key: "signals", head: map[string]any{"from": ts(f), "to": ts(e), "total": total}}
	for i := range match {
		bs := incidents.BundleSignalOf(match[i])
		r := t.egress.signalRecord(&bs, t.inc.Subject.Namespace, true)
		r.Severity = string(bs.Severity)
		rec := struct {
			Role string `json:"role"`
			dSignal
		}{Role: string(bs.Role), dSignal: r}
		out.items = append(out.items, shown{rec: rec, ev: Evidence{Ref: r.Ref, Kind: KindSignal, Time: bs.Start, Object: r.Object, Snippet: r.Title}})
	}
	what := in.Role
	if in.Type != "" {
		what = in.Type
	}
	if what != "" {
		what = " " + what
	}
	out.step = fmt.Sprintf("list_signals%s %s: %s", what, span(f, e), plural(len(out.items), "signal", "signals"))
	return out, nil
}

func signalEnd(s *incidents.Signal) (time.Time, bool) {
	if s.End != nil {
		return *s.End, false
	}
	if incidents.IsCondition(s.Type) {
		return time.Time{}, true
	}
	return s.Start, false
}

// ---- get_logs ----

type getLogsIn struct {
	Pods       []string `json:"pods"`
	Containers []string `json:"containers"`
	From       string   `json:"from"`
	To         string   `json:"to"`
	Level      string   `json:"level"`
	Contains   string   `json:"contains"`
	Limit      int      `json:"limit"`
}

func (t *toolbox) checkPods(pods []string) error {
	for _, p := range pods {
		if !contains(t.inc.Pods, p) {
			names := t.inc.Pods
			if len(names) > 10 {
				names = names[:10]
			}
			if len(names) == 0 {
				return invalid("the incident names no pods")
			}
			return invalid("pod %q is not one of the incident's pods (%s)", cut(clean(p), 80), strings.Join(names, ", "))
		}
	}
	return nil
}

func (t *toolbox) getLogs(ctx context.Context, raw json.RawMessage) (*toolOutput, error) {
	var in getLogsIn
	if err := decode(raw, &in); err != nil {
		return nil, err
	}
	f, e, err := t.times(in.From, in.To)
	if err != nil {
		return nil, err
	}
	if err := t.checkPods(in.Pods); err != nil {
		return nil, err
	}
	who := "all pods"
	if len(in.Pods) > 0 {
		who = in.Pods[0]
		if len(in.Pods) > 1 {
			who += fmt.Sprintf(" +%d", len(in.Pods)-1)
		}
	}
	lvl := ""
	if in.Level != "" {
		lvl = " " + in.Level
	}
	out := &toolOutput{key: "lines", head: map[string]any{"from": ts(f), "to": ts(e)}}
	if t.inc.Subject.Namespace == "" || len(t.inc.Pods) == 0 {
		out.head["note"] = "the incident names no pods, so there are no container logs"
		out.step = "get_logs: no pods"
		return out, nil
	}
	if t.emptyWindow(f, e) {
		out.head["note"] = "the range is outside the incident window"
		out.step = "get_logs: empty range"
		return out, nil
	}
	res, err := t.src.Logs(ctx, t.inc.ID, incidents.LogRequest{From: f, To: e, Pods: in.Pods, Containers: in.Containers, Level: in.Level,
		Text: in.Contains, Limit: limitOr(in.Limit, 100)})
	if errors.Is(err, incidents.ErrNoLogSource) {
		out.head["note"] = "no log source is configured"
		out.step = "get_logs: no log source"
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	if res.Truncated {
		out.head["source_truncated"] = true
	}
	if len(res.Warnings) > 0 {
		var ws []string
		for _, w := range res.Warnings {
			ws = append(ws, t.egress.Line(w, 200))
		}
		out.head["warnings"] = ws
	}
	first := t.ledger.logRefs(len(res.Lines))
	type rec struct {
		Ref       string `json:"ref"`
		Time      string `json:"time"`
		Pod       string `json:"pod"`
		Container string `json:"container,omitempty"`
		Level     string `json:"level,omitempty"`
		Text      string `json:"text"`
	}
	for i, l := range res.Lines {
		r := rec{Ref: KindLog + ":" + strconv.Itoa(first+i), Time: ts(l.Time), Pod: t.egress.Line(l.Pod, 128),
			Container: t.egress.Line(l.Container, 64), Level: l.Level, Text: t.egress.Text(l.Text, maxLogLine)}
		obj := r.Pod
		if r.Container != "" {
			obj += "/" + r.Container
		}
		out.items = append(out.items, shown{rec: r, ev: Evidence{Ref: r.Ref, Kind: KindLog, Time: l.Time, Object: obj, Snippet: r.Text}})
	}
	out.step = fmt.Sprintf("get_logs %s%s %s: %s", who, lvl, span(f, e), plural(len(out.items), "line", "lines"))
	return out, nil
}

// ---- get_metric_series ----

type getMetricIn struct {
	Metric    string `json:"metric"`
	Label     string `json:"label"`
	From      string `json:"from"`
	To        string `json:"to"`
	MaxPoints int    `json:"max_points"`
}

func (t *toolbox) getMetricSeries(ctx context.Context, raw json.RawMessage) (*toolOutput, error) {
	var in getMetricIn
	if err := decode(raw, &in); err != nil {
		return nil, err
	}
	f, e, err := t.times(in.From, in.To)
	if err != nil {
		return nil, err
	}
	out := &toolOutput{key: "series", head: map[string]any{"metric": in.Metric, "from": ts(f), "to": ts(e)}}
	if t.emptyWindow(f, e) {
		out.head["note"] = "the range is outside the incident window"
		out.step = "get_metric_series: empty range"
		return out, nil
	}
	ss, err := t.src.Series(ctx, t.inc.ID, f, e)
	if err != nil {
		return nil, err
	}
	var labels []string
	var match []incidents.Series
	for _, s := range ss {
		if s.Metric != in.Metric {
			continue
		}
		label := t.egress.Line(s.Label, 200)
		labels = append(labels, label)
		if in.Label == "" || in.Label == label || in.Label == s.Label {
			match = append(match, s)
		}
	}
	if in.Label != "" && len(match) == 0 {
		if len(labels) == 0 {
			return nil, invalid("no %s series in this range", in.Metric)
		}
		if len(labels) > 10 {
			labels = labels[:10]
		}
		return nil, invalid("no %s series has label %q; labels: %s", in.Metric, cut(clean(in.Label), 80), strings.Join(labels, ", "))
	}
	maxPts := limitOr(in.MaxPoints, 60)
	type rec struct {
		dMetric
		Pts [][2]any `json:"values"`
	}
	for _, s := range match {
		m, ok := t.egress.metricRecord(s, f, e)
		if !ok {
			continue
		}
		m.Bucket = nil
		r := rec{dMetric: m, Pts: peakPoints(m.raw, f, e, maxPts)}
		out.items = append(out.items, shown{rec: r, ev: Evidence{Ref: m.Ref, Kind: KindMetric, Time: m.peak, Object: m.Label,
			Snippet: "max " + strconv.FormatFloat(float64(m.Max), 'g', 4, 64) + " " + m.Unit + " at " + m.PeakAt}})
	}
	out.step = fmt.Sprintf("get_metric_series %s %s: %s", in.Metric, span(f, e), plural(len(out.items), "series", "series"))
	return out, nil
}

// peakPoints downsamples to at most n [time, value] points: per equal
// bucket, the point with the largest value, at its own time.
func peakPoints(points [][2]float64, from, to time.Time, n int) [][2]any {
	if len(points) == 0 {
		return [][2]any{}
	}
	if len(points) <= n {
		out := make([][2]any, 0, len(points))
		for _, p := range points {
			out = append(out, [2]any{ts(time.UnixMilli(int64(p[0]))), num(p[1])})
		}
		return out
	}
	span := to.Sub(from).Milliseconds()
	if span <= 0 {
		span = 1
	}
	best := make([]int, n)
	for i := range best {
		best[i] = -1
	}
	for i, p := range points {
		b := int((int64(p[0]) - from.UnixMilli()) * int64(n) / span)
		if b < 0 {
			b = 0
		}
		if b >= n {
			b = n - 1
		}
		if best[b] < 0 || p[1] > points[best[b]][1] {
			best[b] = i
		}
	}
	var out [][2]any
	for _, i := range best {
		if i >= 0 {
			out = append(out, [2]any{ts(time.UnixMilli(int64(points[i][0]))), num(points[i][1])})
		}
	}
	return out
}

// ---- get_k8s_events ----

type getEventsIn struct {
	ObjectKind string `json:"object_kind"`
	ObjectName string `json:"object_name"`
	Reason     string `json:"reason"`
	Type       string `json:"type"`
	From       string `json:"from"`
	To         string `json:"to"`
	Limit      int    `json:"limit"`
}

// incidentNodes are the nodes whose events a run may read: the incident's
// nodes (at most 10), or its node.
func (t *toolbox) incidentNodes() []string {
	if t.inc.Subject.Kind == incidents.KindNode {
		return []string{t.inc.Subject.Name}
	}
	n := t.inc.Nodes
	if len(n) > 10 {
		n = n[:10]
	}
	return n
}

func (t *toolbox) getK8sEvents(ctx context.Context, raw json.RawMessage) (*toolOutput, error) {
	var in getEventsIn
	if err := decode(raw, &in); err != nil {
		return nil, err
	}
	f, e, err := t.times(in.From, in.To)
	if err != nil {
		return nil, err
	}
	nodeKind := strings.EqualFold(in.ObjectKind, "Node")
	if nodeKind && !t.access.Nodes {
		return nil, errDenied
	}
	ns := t.inc.Subject.Namespace
	nodes := t.incidentNodes()
	if nodeKind && in.ObjectName != "" {
		if !contains(nodes, in.ObjectName) {
			return nil, invalid("node %q is not one of the incident's nodes (%s)", cut(clean(in.ObjectName), 80), strings.Join(nodes, ", "))
		}
		nodes = []string{in.ObjectName}
	}
	out := &toolOutput{key: "events", head: map[string]any{"from": ts(f), "to": ts(e)}}
	if !t.access.Nodes {
		out.head["omitted"] = "events about nodes: not permitted for the requesting user"
	}
	if t.emptyWindow(f, e) {
		out.head["note"] = "the range is outside the incident window"
		out.step = "get_k8s_events: empty range"
		return out, nil
	}
	var evs []incidents.StoredEvent
	if ns != "" && !nodeKind {
		q := incidents.EventQuery{Namespace: ns, From: f, To: e, Limit: 2000}
		if in.ObjectKind != "" && in.ObjectName != "" {
			q.Object = &model.ObjectRef{Kind: in.ObjectKind, Namespace: ns, Name: in.ObjectName}
		}
		got, err := t.src.Events(ctx, q)
		if err != nil {
			return nil, err
		}
		evs = append(evs, got...)
	}
	if t.access.Nodes && (in.ObjectKind == "" || nodeKind) {
		for _, n := range nodes {
			got, err := t.src.Events(ctx, incidents.EventQuery{Object: &model.ObjectRef{Kind: "Node", Name: n}, From: f, To: e, Limit: 500})
			if err != nil {
				return nil, err
			}
			evs = append(evs, got...)
		}
	}
	seen := map[string]bool{}
	var match []incidents.StoredEvent
	for _, ev := range evs {
		isNode := ev.Regarding.Kind == "Node"
		switch {
		case seen[ev.UID]:
			continue
		case isNode && (!t.access.Nodes || !contains(t.incidentNodes(), ev.Regarding.Name)):
			continue
		case !isNode && (ns == "" || ev.Namespace != ns):
			continue
		case in.ObjectKind != "" && !strings.EqualFold(ev.Regarding.Kind, in.ObjectKind):
			continue
		case in.ObjectName != "" && ev.Regarding.Name != in.ObjectName:
			continue
		case in.Reason != "" && !strings.EqualFold(ev.Reason, in.Reason):
			continue
		case in.Type != "" && ev.Type != in.Type:
			continue
		case ev.LastSeen.Before(f) || ev.FirstSeen.After(e):
			continue
		}
		seen[ev.UID] = true
		match = append(match, ev)
	}
	sort.SliceStable(match, func(i, j int) bool { return incidents.EventNewer(&match[i], &match[j]) })
	total := len(match)
	if l := limitOr(in.Limit, 50); len(match) > l {
		match = match[:l]
	}
	out.head["total"] = total
	type rec struct {
		Ref     string `json:"ref"`
		Type    string `json:"type"`
		Reason  string `json:"reason"`
		Object  string `json:"object"`
		Count   int32  `json:"count"`
		First   string `json:"first"`
		Last    string `json:"last"`
		Source  string `json:"source,omitempty"`
		Message string `json:"message"`
	}
	for _, ev := range match {
		r := rec{Ref: KindEvent + ":" + ev.UID, Type: ev.Type, Reason: t.egress.Line(ev.Reason, 128),
			Object: t.egress.Line(objectString(ev.Regarding.Kind, ev.Regarding.Namespace, ev.Regarding.Name, ns), 300), Count: ev.Count,
			First: ts(ev.FirstSeen), Last: ts(ev.LastSeen), Source: t.egress.Line(ev.Source, 64), Message: t.egress.Line(ev.Message, maxEventMessage)}
		out.items = append(out.items, shown{rec: r, ev: Evidence{Ref: r.Ref, Kind: KindEvent, Time: ev.LastSeen, Object: r.Object,
			Snippet: r.Reason + ": " + r.Message}})
	}
	what := in.Type
	if in.Reason != "" {
		what = in.Reason
	}
	if what != "" {
		what = " " + what
	}
	out.step = fmt.Sprintf("get_k8s_events%s %s: %s", what, span(f, e), plural(len(out.items), "event", "events"))
	return out, nil
}

// ---- get_audit_events ----

type getAuditIn struct {
	Verb     string `json:"verb"`
	Resource string `json:"resource"`
	User     string `json:"user"`
	Tag      string `json:"tag"`
	From     string `json:"from"`
	To       string `json:"to"`
	Limit    int    `json:"limit"`
}

func (t *toolbox) getAuditEvents(ctx context.Context, raw json.RawMessage) (*toolOutput, error) {
	var in getAuditIn
	if err := decode(raw, &in); err != nil {
		return nil, err
	}
	f, e, err := t.times(in.From, in.To)
	if err != nil {
		return nil, err
	}
	out := &toolOutput{key: "events", head: map[string]any{"from": ts(f), "to": ts(e)}}
	if t.emptyWindow(f, e) {
		out.head["note"] = "the range is outside the incident window"
		out.step = "get_audit_events: empty range"
		return out, nil
	}
	inc := t.inc
	evs, err := t.src.AuditEvents(ctx, &inc, 1000)
	if err != nil {
		return nil, err
	}
	var match []audit.Event
	for _, ev := range evs {
		res := ev.Resource
		if ev.Subresource != "" {
			res += "/" + ev.Subresource
		}
		switch {
		case ev.Time.Before(f) || ev.Time.After(e):
			continue
		case in.Verb != "" && !strings.EqualFold(ev.Verb, in.Verb):
			continue
		case in.Resource != "" && !strings.EqualFold(ev.Resource, in.Resource) && !strings.EqualFold(res, in.Resource):
			continue
		case in.User != "" && !strings.Contains(strings.ToLower(ev.Username), strings.ToLower(in.User)):
			continue
		case in.Tag != "" && !contains(ev.Tags, in.Tag):
			continue
		}
		match = append(match, ev)
	}
	sort.SliceStable(match, func(i, j int) bool { return match[i].Time.Before(match[j].Time) })
	out.head["total"] = len(match)
	if l := limitOr(in.Limit, 50); len(match) > l {
		match = match[len(match)-l:]
		out.head["note"] = "the latest events are shown"
	}
	for i := range match {
		r := t.egress.auditRecord(&match[i], t.inc.Subject.Namespace)
		r.URI = t.egress.Line(match[i].RequestURI, 300)
		out.items = append(out.items, shown{rec: r, ev: Evidence{Ref: r.Ref, Kind: KindAudit, Time: r.at, Object: r.Resource + " " + r.Name,
			Snippet: r.User + " " + r.Verb + " " + r.Resource + " " + r.Name}})
	}
	what := ""
	if in.Verb != "" {
		what = " " + in.Verb
	}
	out.step = fmt.Sprintf("get_audit_events%s %s: %s", what, span(f, e), plural(len(out.items), "event", "events"))
	return out, nil
}

// ---- get_cloudtrail_events ----

type getCloudTrailIn struct {
	EventName string `json:"event_name"`
	From      string `json:"from"`
	To        string `json:"to"`
	Limit     int    `json:"limit"`
}

func (t *toolbox) getCloudTrailEvents(ctx context.Context, raw json.RawMessage) (*toolOutput, error) {
	var in getCloudTrailIn
	if err := decode(raw, &in); err != nil {
		return nil, err
	}
	f, e, err := t.times(in.From, in.To)
	if err != nil {
		return nil, err
	}
	// The incident's own CloudTrail signals (live), else the bundle's.
	recs := t.bundleCT
	if _, sigs, ok, err := t.src.Get(ctx, t.inc.ID); err == nil && ok {
		recs = nil
		seen := map[string]bool{}
		for i := range sigs {
			s := &sigs[i]
			if s.Type == incidents.TypeCloudTrailChange && !seen[s.ID] {
				seen[s.ID] = true
				recs = append(recs, incidents.CloudTrailOf(s))
			}
		}
	}
	var match []incidents.BundleCloudTrail
	for _, c := range recs {
		if c.Time.Before(f) || c.Time.After(e) || (in.EventName != "" && !strings.EqualFold(c.Name, in.EventName)) {
			continue
		}
		match = append(match, c)
	}
	sort.SliceStable(match, func(i, j int) bool { return match[i].Time.Before(match[j].Time) })
	out := &toolOutput{key: "events", head: map[string]any{"from": ts(f), "to": ts(e), "total": len(match)}}
	if l := limitOr(in.Limit, 20); len(match) > l {
		match = match[len(match)-l:]
	}
	type rec struct {
		dCloudTrail
		Matched []string `json:"matched,omitempty"`
		Raw     string   `json:"raw,omitempty"`
	}
	for i := range match {
		c := &match[i]
		r := rec{dCloudTrail: t.egress.cloudTrailRecord(c, 10), Raw: t.egress.CloudTrailRaw(c.Raw, maxCloudTrailRaw)}
		for _, m := range c.Matched {
			r.Matched = append(r.Matched, t.egress.Line(m, 200))
		}
		obj := ""
		if len(r.Resources) > 0 {
			obj = r.Resources[0]
		}
		out.items = append(out.items, shown{rec: r, ev: Evidence{Ref: r.Ref, Kind: KindCloudTrail, Time: c.Time, Object: obj,
			Snippet: r.Actor + " called " + r.Name}})
	}
	out.step = fmt.Sprintf("get_cloudtrail_events %s: %s", span(f, e), plural(len(out.items), "event", "events"))
	return out, nil
}

// ---- get_workload_state ----

func (t *toolbox) getWorkloadState(ctx context.Context, raw json.RawMessage) (*toolOutput, error) {
	inc := t.inc
	st, err := t.src.WorkloadState(ctx, &inc)
	if err != nil {
		return nil, err
	}
	out := &toolOutput{key: "pods", head: map[string]any{
		"note": "the current state from the latest cluster snapshot, not the state during the incident"}}
	if st == nil {
		st = &WorkloadState{}
	}
	if !st.At.IsZero() {
		out.head["as_of"] = ts(st.At)
	}
	eg := t.egress
	conds := func(cs []model.Condition, onlyBad bool) []map[string]string {
		var l []map[string]string
		for _, c := range cs {
			if onlyBad && ((c.Type == "Ready" && c.Status == "True") || (c.Type != "Ready" && c.Status == "False")) {
				continue
			}
			m := map[string]string{"type": eg.Line(c.Type, 64), "status": c.Status}
			if c.Reason != "" {
				m["reason"] = eg.Line(c.Reason, 128)
			}
			if c.Message != "" {
				m["message"] = eg.Line(c.Message, 300)
			}
			if !c.LastTransition.IsZero() {
				m["since"] = ts(c.LastTransition)
			}
			l = append(l, m)
		}
		return l
	}
	if w := st.Workload; w != nil {
		wm := map[string]any{"kind": w.Kind, "name": eg.Line(w.Name, 253), "desired": w.Desired, "ready": w.Ready,
			"updated": w.Updated, "available": w.Available}
		if w.Revision != "" {
			wm["revision"] = eg.Line(w.Revision, 64)
		}
		if w.Paused {
			wm["paused"] = true
		}
		var imgs []string
		for _, im := range w.Images {
			imgs = append(imgs, eg.Line(im, 300))
		}
		if len(imgs) > 0 {
			wm["images"] = imgs
		}
		if c := conds(w.Conditions, false); len(c) > 0 {
			wm["conditions"] = c
		}
		if w.Kind == "Job" || w.Kind == "CronJob" {
			wm["succeeded"], wm["failed"], wm["active"] = w.Succeeded, w.Failed, w.Active
		}
		if w.Kind == "CronJob" {
			wm["schedule"], wm["suspended"] = eg.Line(w.Schedule, 64), w.Suspended
		}
		out.head["workload"] = wm
	}
	pods := st.Pods
	if len(pods) > 20 {
		out.head["pods_total"] = len(pods)
		pods = pods[:20]
	}
	for _, p := range pods {
		pm := map[string]any{"name": eg.Line(p.Name, 253), "phase": p.Phase, "ready": p.Ready, "node": eg.Line(p.NodeName, 253)}
		if p.Reason != "" {
			pm["reason"] = eg.Line(p.Reason, 128)
		}
		if p.Message != "" {
			pm["message"] = eg.Line(p.Message, 300)
		}
		if p.Unschedulable != "" {
			pm["unschedulable"] = eg.Line(p.Unschedulable, 300)
		}
		if !p.DeletedAt.IsZero() {
			pm["deleting_since"] = ts(p.DeletedAt)
		}
		if !p.Created.IsZero() {
			pm["created"] = ts(p.Created)
		}
		if p.QOSClass != "" {
			pm["qos"] = p.QOSClass
		}
		limits := map[string]int64{}
		for _, s := range p.Specs {
			limits[s.Name] = s.MemoryLimitBytes
		}
		var cs []map[string]any
		for _, c := range p.Containers {
			cm := map[string]any{"name": eg.Line(c.Name, 64), "state": c.State, "ready": c.Ready, "restarts": c.RestartCount}
			if c.Init {
				cm["init"] = true
			}
			if c.Reason != "" {
				cm["reason"] = eg.Line(c.Reason, 128)
			}
			if c.Message != "" {
				cm["message"] = eg.Line(c.Message, 300)
			}
			if c.LastTerminatedReason != "" {
				cm["last_terminated"] = map[string]any{"reason": eg.Line(c.LastTerminatedReason, 64), "at": ts(c.LastTerminatedAt),
					"exit_code": c.LastExitCode}
			}
			lim := c.MemoryLimitBytes
			if lim == 0 {
				lim = limits[c.Name]
			}
			if lim > 0 {
				cm["memory_limit_bytes"] = lim
			}
			cs = append(cs, cm)
		}
		pm["containers"] = cs
		out.items = append(out.items, shown{rec: pm})
	}
	if t.access.Nodes {
		var nodes []map[string]any
		for i, n := range st.Nodes {
			if i >= 10 {
				break
			}
			nm := map[string]any{"name": eg.Line(n.Name, 253), "ready": n.Ready}
			if n.Unschedulable {
				nm["unschedulable"] = true
			}
			if c := conds(n.Conditions, true); len(c) > 0 {
				nm["conditions"] = c
			}
			var taints []string
			for _, tn := range n.Taints {
				taints = append(taints, eg.Line(tn, 200))
			}
			if len(taints) > 0 {
				nm["taints"] = taints
			}
			if it := n.Labels["node.kubernetes.io/instance-type"]; it != "" {
				nm["instance_type"] = eg.Line(it, 64)
			}
			nodes = append(nodes, nm)
		}
		if len(nodes) > 0 {
			out.head["nodes"] = nodes
		}
	} else if len(st.Nodes) > 0 {
		out.head["omitted"] = "node conditions: not permitted for the requesting user"
	}
	out.step = "get_workload_state: " + plural(len(out.items), "pod", "pods")
	return out, nil
}
