package cloudwatch

// Container logs for incidents, read on demand from a CloudWatch Logs group
// that Fluent Bit (Container Insights, the CloudWatch Observability add-on)
// or Fluentd fills. Nothing is stored: each view reads the window again.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"

	"github.com/ByronGary/kubesentry/internal/incidents"
)

// LogSourceName is the name LogLookup reports, and LogLine.Source.
const LogSourceName = "cloudwatch"

// Defaults and limits of a LogLookup.
const (
	DefaultLogMaxCalls = 10
	DefaultLogMaxLines = 2000
	DefaultLogMaxBytes = 1 << 20
	// MaxFilterPattern is the service's limit on a filter pattern.
	MaxFilterPattern = 1024
)

// DefaultApplicationLogGroup is the Container Insights application log group
// of an EKS cluster.
func DefaultApplicationLogGroup(cluster string) string {
	return "/aws/containerinsights/" + cluster + "/application"
}

// LogLookup reads a namespace's container logs from one log group with
// FilterLogEvents. It implements incidents.LogSource. Set API and LogGroup.
//
// By default it selects records with a JSON filter pattern on the
// kubernetes.namespace_name and kubernetes.pod_name fields Fluent Bit adds,
// split into as many patterns as needed to stay under the 1 KiB limit. When
// the group's stream names start with the namespace and pod, StreamPrefix
// (a template with {namespace} and {pod}) reads each pod's streams by
// prefix instead.
type LogLookup struct {
	API      FilterAPI
	LogGroup string
	// StreamPrefix is a log stream name prefix template, e.g.
	// "{namespace}.{pod}" (-incident-logs-stream-prefix); empty uses the
	// JSON filter pattern.
	StreamPrefix string
	MaxCalls     int   // FilterLogEvents calls per lookup; default 10
	MaxLines     int   // lines per lookup, and the cap on LogQuery.Limit; default 2000
	MaxBytes     int64 // text bytes per lookup, and the cap on LogQuery.MaxBytes; default 1 MiB
	PageLimit    int32 // events per call; 0 is the service maximum (10,000)
	// Pacer waits out throttling; share the audit Reader's to pace the
	// account's calls together. nil makes one with a 1s backoff.
	Pacer *Pacer
}

var _ incidents.LogSource = (*LogLookup)(nil)

// Name is LogSourceName.
func (l *LogLookup) Name() string { return LogSourceName }

// k8sName matches Kubernetes object names (DNS-1123 subdomains), the only
// names placed in filter patterns and stream prefixes.
var k8sName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`)

func validK8sName(s string) bool { return len(s) <= 253 && k8sName.MatchString(s) }

// filterRequest is one paginated FilterLogEvents read.
type filterRequest struct {
	pattern string // JSON filter pattern, or ""
	prefix  string // log stream name prefix, or ""
	pod     string // the pod a prefix reads, when it names one
}

// Logs reads the query's window, oldest first. Lines are filtered by pod,
// container, level (that level and more severe; lines of unknown level
// count as info) and text (case-insensitive substring). It stops at MaxCalls
// calls, the line limit or the byte limit and then sets Truncated.
func (l *LogLookup) Logs(ctx context.Context, q incidents.LogQuery) (incidents.LogResult, error) {
	var res incidents.LogResult
	if !validK8sName(q.Namespace) {
		return res, fmt.Errorf("cloudwatch logs: invalid namespace %q", q.Namespace)
	}
	if !q.To.After(q.From) {
		return res, errors.New("cloudwatch logs: empty time range")
	}
	pods, bad := splitValid(q.Pods)
	containers, badC := splitValid(q.Containers)
	if bad+badC > 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf("skipped %d invalid pod or container names", bad+badC))
	}
	if len(q.Pods) > 0 && len(pods) == 0 {
		return res, nil
	}
	maxCalls := positive(l.MaxCalls, DefaultLogMaxCalls)
	maxLines := positive(l.MaxLines, DefaultLogMaxLines)
	if q.Limit > 0 && q.Limit < maxLines {
		maxLines = q.Limit
	}
	maxBytes := int64(positive(int(l.MaxBytes), DefaultLogMaxBytes))
	if q.MaxBytes > 0 && q.MaxBytes < maxBytes {
		maxBytes = q.MaxBytes
	}
	level := ""
	if q.Level != "" {
		if level = NormalizeLevel(q.Level); level == "" {
			return res, fmt.Errorf("cloudwatch logs: unknown level %q", q.Level)
		}
	}
	minRank := levelRanks[level]
	text := strings.ToLower(q.Text)
	podSet, ctrSet := toSet(pods), toSet(containers)

	var reqs []filterRequest
	if l.StreamPrefix != "" {
		prefixes := streamPrefixes(l.StreamPrefix, q.Namespace, pods)
		for i, p := range prefixes {
			rq := filterRequest{prefix: p}
			if len(prefixes) == len(pods) {
				rq.pod = pods[i]
			}
			reqs = append(reqs, rq)
		}
	} else {
		patterns, err := podPatterns(q.Namespace, pods, containers)
		if err != nil {
			return res, err
		}
		for _, p := range patterns {
			reqs = append(reqs, filterRequest{pattern: p})
		}
	}

	pacer := l.pacer()
	calls := 0
	var bytes int64
	full := false
	for ri, rq := range reqs {
		in := &cloudwatchlogs.FilterLogEventsInput{
			LogGroupName: aws.String(l.LogGroup),
			StartTime:    aws.Int64(q.From.UnixMilli()),
			EndTime:      aws.Int64(q.To.UnixMilli()),
		}
		if rq.pattern != "" {
			in.FilterPattern = aws.String(rq.pattern)
		}
		if rq.prefix != "" {
			in.LogStreamNamePrefix = aws.String(rq.prefix)
		}
		if l.PageLimit > 0 {
			in.Limit = aws.Int32(l.PageLimit)
		}
		for {
			if calls >= maxCalls {
				res.Truncated = true
				res.Warnings = append(res.Warnings, fmt.Sprintf("stopped after %d CloudWatch Logs calls; %d of %d pod groups read", maxCalls, ri, len(reqs)))
				return finish(res), nil
			}
			calls++
			out, err := l.filter(ctx, pacer, in)
			if err != nil {
				return res, err
			}
			for _, ev := range out.Events {
				if ev.Message == nil {
					continue
				}
				line := ParseContainerLog(*ev.Message, aws.ToInt64(ev.Timestamp))
				if line.Pod == "" {
					line.Pod = rq.pod
				}
				if len(podSet) > 0 && line.Pod != "" && !podSet[line.Pod] {
					continue // a prefix also matches longer pod names
				}
				if len(ctrSet) > 0 && line.Container != "" && !ctrSet[line.Container] {
					continue
				}
				if minRank > 0 && levelRank(line.Level) < minRank {
					continue
				}
				if text != "" && !strings.Contains(strings.ToLower(line.Text), text) {
					continue
				}
				if len(res.Lines) >= maxLines || bytes+int64(len(line.Text)) > maxBytes {
					full = true
					break
				}
				bytes += int64(len(line.Text))
				res.Lines = append(res.Lines, line)
			}
			if full {
				res.Truncated = true
				return finish(res), nil
			}
			if out.NextToken == nil || *out.NextToken == "" {
				break
			}
			in.NextToken = out.NextToken
		}
	}
	return finish(res), nil
}

// finish sorts the lines by time; FilterLogEvents interleaves streams, and
// several patterns read the window more than once.
func finish(res incidents.LogResult) incidents.LogResult {
	sort.SliceStable(res.Lines, func(i, j int) bool { return res.Lines[i].Time.Before(res.Lines[j].Time) })
	return res
}

// Probe reports whether the log group can be read: ProbeOK, ProbeAbsent
// (no such group) or "error: …".
func (l *LogLookup) Probe(ctx context.Context) string {
	now := time.Now()
	in := &cloudwatchlogs.FilterLogEventsInput{
		LogGroupName: aws.String(l.LogGroup),
		StartTime:    aws.Int64(now.Add(-time.Hour).UnixMilli()),
		EndTime:      aws.Int64(now.UnixMilli()),
		Limit:        aws.Int32(1),
	}
	_, err := l.filter(ctx, l.pacer(), in)
	return probeResult(err)
}

// Probe results.
const (
	ProbeOK     = "ok"
	ProbeAbsent = "absent"
)

func probeResult(err error) string {
	switch {
	case err == nil:
		return ProbeOK
	case errors.Is(err, ErrLogGroupNotFound):
		return ProbeAbsent
	}
	return "error: " + err.Error()
}

func (l *LogLookup) pacer() *Pacer {
	if l.Pacer != nil {
		return l.Pacer
	}
	return NewPacer(time.Second)
}

func (l *LogLookup) filter(ctx context.Context, p *Pacer, in *cloudwatchlogs.FilterLogEventsInput) (*cloudwatchlogs.FilterLogEventsOutput, error) {
	return pacedFilter(ctx, l.API, p, in, l.LogGroup)
}

// pacedFilter calls FilterLogEvents through the pacer and names the
// not-found and access errors.
func pacedFilter(ctx context.Context, api FilterAPI, p *Pacer, in *cloudwatchlogs.FilterLogEventsInput, group string) (*cloudwatchlogs.FilterLogEventsOutput, error) {
	var out *cloudwatchlogs.FilterLogEventsOutput
	err := p.Do(ctx, func() error {
		var err error
		out, err = api.FilterLogEvents(ctx, in)
		return err
	}, isThrottled, nil)
	if err == nil {
		return out, nil
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	switch code := errorCode(err); {
	case code == "ResourceNotFoundException":
		return nil, fmt.Errorf("%w: %s: %v", ErrLogGroupNotFound, group, err)
	case isAccessDenied(code):
		return nil, fmt.Errorf("%w: logs:FilterLogEvents on %s: %v", ErrAccessDenied, group, err)
	}
	return nil, err
}

// podPatterns returns JSON filter patterns selecting the namespace's pods
// (all of them when pods is empty) and containers, each at most
// MaxFilterPattern bytes:
//
//	{ $.kubernetes.namespace_name = "shop" && ($.kubernetes.pod_name = "web-0" || $.kubernetes.pod_name = "web-1") }
func podPatterns(ns string, pods, containers []string) ([]string, error) {
	head := `{ $.kubernetes.namespace_name = ` + strconv.Quote(ns)
	if len(containers) > 0 {
		head += " && (" + alternatives("$.kubernetes.container_name", containers) + ")"
	}
	if len(pods) == 0 {
		p := head + " }"
		if len(p) > MaxFilterPattern {
			return nil, errors.New("cloudwatch logs: container list too long for a filter pattern")
		}
		return []string{p}, nil
	}
	const tail = ") }"
	var out []string
	var chunk []string
	size := len(head) + len(" && (") + len(tail)
	for _, p := range pods {
		term := len(`$.kubernetes.pod_name = ""`) + len(p)
		if len(chunk) > 0 {
			term += len(" || ")
		}
		if size+term > MaxFilterPattern {
			if len(chunk) == 0 {
				return nil, errors.New("cloudwatch logs: container list too long for a filter pattern")
			}
			out = append(out, head+" && ("+alternatives("$.kubernetes.pod_name", chunk)+tail)
			chunk = nil
			size = len(head) + len(" && (") + len(tail)
			term -= len(" || ")
		}
		chunk = append(chunk, p)
		size += term
	}
	out = append(out, head+" && ("+alternatives("$.kubernetes.pod_name", chunk)+tail)
	return out, nil
}

func alternatives(selector string, names []string) string {
	terms := make([]string, len(names))
	for i, n := range names {
		terms[i] = selector + " = " + strconv.Quote(n)
	}
	return strings.Join(terms, " || ")
}

// streamPrefixes expands the template once per pod; without pods, the
// template is cut at {pod}.
func streamPrefixes(tmpl, ns string, pods []string) []string {
	expand := func(pod string) string {
		return strings.ReplaceAll(strings.ReplaceAll(tmpl, "{namespace}", ns), "{pod}", pod)
	}
	if len(pods) == 0 || !strings.Contains(tmpl, "{pod}") {
		cut := tmpl
		if i := strings.Index(cut, "{pod}"); i >= 0 {
			cut = cut[:i]
		}
		return []string{strings.ReplaceAll(cut, "{namespace}", ns)}
	}
	out := make([]string, len(pods))
	for i, p := range pods {
		out[i] = expand(p)
	}
	return out
}

func splitValid(names []string) (valid []string, bad int) {
	seen := map[string]bool{}
	for _, n := range names {
		if !validK8sName(n) {
			bad++
			continue
		}
		if !seen[n] {
			seen[n] = true
			valid = append(valid, n)
		}
	}
	sort.Strings(valid)
	return valid, bad
}

func toSet(names []string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

func positive(v, def int) int {
	if v > 0 {
		return v
	}
	return def
}

// Log levels, normalised.
const (
	LevelError = "error"
	LevelWarn  = "warn"
	LevelInfo  = "info"
	LevelDebug = "debug"
)

// levelRanks orders the levels a query may ask for; a query for a level
// returns that level and more severe ones.
var levelRanks = map[string]int{"": 0, LevelDebug: 0, LevelInfo: 1, LevelWarn: 2, LevelError: 3}

// levelRank ranks a line's level; unknown counts as info.
func levelRank(level string) int {
	if r, ok := levelRanks[level]; ok && level != "" {
		return r
	}
	return 1
}

// NormalizeLevel maps a level word or number (bunyan/pino: 10 to 60) to
// LevelError, LevelWarn, LevelInfo, LevelDebug, or "" when unknown.
func NormalizeLevel(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "error", "err", "e", "fatal", "f", "critical", "crit", "panic", "alert", "emerg", "emergency", "severe":
		return LevelError
	case "warn", "warning", "w":
		return LevelWarn
	case "info", "information", "informational", "notice", "i":
		return LevelInfo
	case "debug", "trace", "verbose", "d", "t":
		return LevelDebug
	}
	if n, err := strconv.Atoi(s); err == nil {
		switch {
		case n >= 50:
			return LevelError
		case n >= 40:
			return LevelWarn
		case n >= 30:
			return LevelInfo
		case n > 0:
			return LevelDebug
		}
	}
	return ""
}

var (
	levelField = regexp.MustCompile(`(?i)\b(?:level|lvl|severity)\s*[=:]\s*"?([A-Za-z]+)`)
	levelWord  = regexp.MustCompile(`\b(FATAL|PANIC|CRITICAL|ERROR|WARNING|WARN|INFO|DEBUG|TRACE)\b`)
	levelTag   = regexp.MustCompile(`(?i)\[(fatal|panic|critical|crit|error|err|warning|warn|info|debug|trace)\]`)
	klogHeader = regexp.MustCompile(`^([IWEF])\d{4} \d{2}:\d{2}:\d{2}`)
)

// DetectLevel finds a log line's level in its text: a level=/level: field,
// a klog header (E1015 …), a bracketed level ([warning]), or an upper-case
// level word. "" when none.
func DetectLevel(text string) string {
	if m := levelField.FindStringSubmatch(text); m != nil {
		if l := NormalizeLevel(m[1]); l != "" {
			return l
		}
	}
	if m := klogHeader.FindStringSubmatch(text); m != nil {
		return NormalizeLevel(m[1])
	}
	if m := levelTag.FindStringSubmatch(text); m != nil {
		return NormalizeLevel(m[1])
	}
	if m := levelWord.FindStringSubmatch(text); m != nil {
		return NormalizeLevel(m[1])
	}
	return ""
}

// levelKeys are the JSON fields that carry a level.
var levelKeys = []string{"level", "lvl", "severity", "log_level", "loglevel", "levelname"}

// ParseContainerLog turns one CloudWatch log event into a log line. It reads
// Fluent Bit and Fluentd records (log, stream, kubernetes.pod_name and
// container_name, time or @timestamp), including records whose application
// JSON was merged in (message or msg, and a level field); anything else is
// kept as raw text at the event's timestamp. The level comes from a JSON
// field (of the record, or of the application's own JSON line), then from
// the text.
func ParseContainerLog(message string, timestampMs int64) incidents.LogLine {
	line := incidents.LogLine{Time: time.UnixMilli(timestampMs).UTC(), Text: message, Source: LogSourceName}
	trimmed := strings.TrimSpace(message)
	var rec map[string]json.RawMessage
	if !strings.HasPrefix(trimmed, "{") || json.Unmarshal([]byte(trimmed), &rec) != nil {
		line.Level = DetectLevel(message)
		return line
	}
	str := func(m map[string]json.RawMessage, key string) (string, bool) {
		raw, ok := m[key]
		if !ok {
			return "", false
		}
		var s string
		if json.Unmarshal(raw, &s) == nil {
			return s, true
		}
		var n json.Number
		if json.Unmarshal(raw, &n) == nil {
			return n.String(), true
		}
		return "", false
	}
	if k, ok := rec["kubernetes"]; ok {
		var meta struct {
			Pod       string `json:"pod_name"`
			Container string `json:"container_name"`
		}
		if json.Unmarshal(k, &meta) == nil {
			line.Pod, line.Container = meta.Pod, meta.Container
		}
	}
	text, ok := str(rec, "log")
	if !ok {
		if text, ok = str(rec, "message"); !ok {
			text, ok = str(rec, "msg")
		}
	}
	if ok {
		line.Text = strings.TrimRight(text, "\r\n")
	}
	if t, ok := str(rec, "time"); ok {
		if ts, err := time.Parse(time.RFC3339Nano, t); err == nil {
			line.Time = ts.UTC()
		}
	} else if t, ok := str(rec, "@timestamp"); ok {
		if ts, err := time.Parse(time.RFC3339Nano, t); err == nil {
			line.Time = ts.UTC()
		} else if f, err := strconv.ParseFloat(t, 64); err == nil && f > 0 {
			line.Time = time.UnixMilli(int64(f * 1000)).UTC()
		}
	}
	for _, k := range levelKeys {
		if v, ok := str(rec, k); ok {
			if l := NormalizeLevel(v); l != "" {
				line.Level = l
				return line
			}
		}
	}
	// The application's own JSON line inside "log".
	if inner := strings.TrimSpace(line.Text); strings.HasPrefix(inner, "{") {
		var app map[string]json.RawMessage
		if json.Unmarshal([]byte(inner), &app) == nil {
			for _, k := range levelKeys {
				if v, ok := str(app, k); ok {
					if l := NormalizeLevel(v); l != "" {
						line.Level = l
						return line
					}
				}
			}
		}
	}
	line.Level = DetectLevel(line.Text)
	return line
}
