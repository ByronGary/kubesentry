package kube

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/ByronGary/kubesentry/internal/incidents"
	"github.com/ByronGary/kubesentry/internal/model"
)

// Defaults for PodLogsOptions.
const (
	DefaultLogMaxPods       = 10
	DefaultLogMaxContainers = 3
	DefaultLogLimitBytes    = 256 << 10 // per container stream
	DefaultLogMaxLines      = 2000
	DefaultLogMaxBytes      = 1 << 20
	DefaultLogParallel      = 4
)

// LogSourceKubernetes is PodLogs' source name.
const LogSourceKubernetes = "kubernetes"

// PodLogsOptions configures PodLogs. Zero values take the defaults.
type PodLogsOptions struct {
	MaxPods       int   // pods read per query (10)
	MaxContainers int   // containers read per pod (3)
	LimitBytes    int64 // bytes asked of the API server per container stream (256 KiB)
	MaxLines      int   // lines returned when the query sets no Limit (2000)
	MaxBytes      int64 // bytes of text returned when the query sets no MaxBytes (1 MiB)
	Parallel      int   // streams read at once (4)
}

// PodGetter looks a pod up, for its containers and restarts: the Cache
// (no API call) or the Source.
type PodGetter interface {
	GetPod(ctx context.Context, namespace, name string) (*model.Pod, error)
}

// PodLogs reads container logs from the API server (pods/log), as
// kubesentry's service account. It implements incidents.LogSource. It
// neither stores nor redacts: callers authorize the user (ViewPodLogs) and
// redact what they return.
type PodLogs struct {
	cs   kubernetes.Interface
	pods PodGetter
	opts PodLogsOptions
}

// NewPodLogs builds a PodLogs. pods finds each pod's containers; nil looks
// them up with a GET per pod.
func NewPodLogs(c *Clients, pods PodGetter, o PodLogsOptions) *PodLogs {
	if o.MaxPods <= 0 {
		o.MaxPods = DefaultLogMaxPods
	}
	if o.MaxContainers <= 0 {
		o.MaxContainers = DefaultLogMaxContainers
	}
	if o.LimitBytes <= 0 {
		o.LimitBytes = DefaultLogLimitBytes
	}
	if o.MaxLines <= 0 {
		o.MaxLines = DefaultLogMaxLines
	}
	if o.MaxBytes <= 0 {
		o.MaxBytes = DefaultLogMaxBytes
	}
	if o.Parallel <= 0 {
		o.Parallel = DefaultLogParallel
	}
	if pods == nil {
		pods = NewSource(c.CS, nil)
	}
	return &PodLogs{cs: c.CS, pods: pods, opts: o}
}

// Name implements incidents.LogSource.
func (p *PodLogs) Name() string { return LogSourceKubernetes }

// Probe reports whether kubesentry may read pod logs: "ok", or why not.
func (p *PodLogs) Probe(ctx context.Context) string {
	if ok, reason := permitted(ctx, p.cs, access{resource: "pods", subresource: "log"}, "get"); !ok {
		return reason
	}
	return "ok"
}

// logStream is one container instance to read.
type logStream struct {
	pod, container string
	previous       bool
}

// streamResult is what one stream yielded.
type streamResult struct {
	lines     []incidents.LogLine
	truncated bool
	warning   string
	err       error // aborts the query (forbidden, cancelled)
}

// Logs implements incidents.LogSource. It reads at most MaxPods pods and
// MaxContainers containers per pod (app containers first), from q.From
// (SinceTime) until a line is later than q.To, at most LimitBytes per
// stream. With q.Previous it also reads the previous instance of containers
// that restarted inside the window. Lines are merged by time, filtered by
// level (q.Level and worse) and text (case-insensitive), and capped at
// q.Limit lines and q.MaxBytes bytes of text, with Truncated set whenever
// something was left out. A pod that no longer exists is a warning, not an
// error; so is a container that has not started.
func (p *PodLogs) Logs(ctx context.Context, q incidents.LogQuery) (incidents.LogResult, error) {
	var res incidents.LogResult
	if q.Namespace == "" {
		return res, errors.New("pod logs: no namespace")
	}
	if q.To.IsZero() {
		q.To = time.Now()
	}
	if !q.From.IsZero() && q.To.Before(q.From) {
		return res, fmt.Errorf("pod logs: window ends (%s) before it starts (%s)", q.To.Format(time.RFC3339), q.From.Format(time.RFC3339))
	}
	pods := dedupe(q.Pods)
	if len(pods) > p.opts.MaxPods {
		res.Warnings = append(res.Warnings, fmt.Sprintf("only the first %d of %d pods are read", p.opts.MaxPods, len(pods)))
		res.Truncated = true
		pods = pods[:p.opts.MaxPods]
	}
	var streams []logStream
	for _, name := range pods {
		s, warn, truncated := p.streams(ctx, q, name)
		streams = append(streams, s...)
		if warn != "" {
			res.Warnings = append(res.Warnings, warn)
		}
		res.Truncated = res.Truncated || truncated
	}

	results := make([]streamResult, len(streams))
	next := make(chan int)
	var wg sync.WaitGroup
	for range min(p.opts.Parallel, len(streams)) {
		wg.Go(func() {
			for i := range next {
				results[i] = p.read(ctx, q, streams[i])
			}
		})
	}
	for i := range streams {
		next <- i
	}
	close(next)
	wg.Wait()

	var lines []incidents.LogLine
	for _, r := range results {
		if r.err != nil {
			return incidents.LogResult{}, r.err
		}
		if r.warning != "" {
			res.Warnings = append(res.Warnings, r.warning)
		}
		res.Truncated = res.Truncated || r.truncated
		lines = append(lines, r.lines...)
	}
	// Streams are in time order each; a stable sort keeps their order for
	// equal times (the previous instance before the current one).
	slices.SortStableFunc(lines, func(a, b incidents.LogLine) int { return a.Time.Compare(b.Time) })
	limit, maxBytes := p.limits(q)
	var size int64
	for i, l := range lines {
		if i >= limit || size+int64(len(l.Text)) > maxBytes {
			res.Truncated = true
			lines = lines[:i]
			break
		}
		size += int64(len(l.Text))
	}
	res.Lines = lines
	return res, nil
}

func (p *PodLogs) limits(q incidents.LogQuery) (int, int64) {
	limit, maxBytes := q.Limit, q.MaxBytes
	if limit <= 0 {
		limit = p.opts.MaxLines
	}
	if maxBytes <= 0 {
		maxBytes = p.opts.MaxBytes
	}
	return limit, maxBytes
}

func dedupe(names []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, n := range names {
		if n != "" && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

// streams picks the container instances of one pod to read.
func (p *PodLogs) streams(ctx context.Context, q incidents.LogQuery, name string) (out []logStream, warning string, truncated bool) {
	pod, err := p.pods.GetPod(ctx, q.Namespace, name)
	switch {
	case errors.Is(err, model.ErrNotFound):
		return nil, fmt.Sprintf("pod %s/%s not found; it may have been deleted", q.Namespace, name), false
	case err != nil && len(q.Containers) == 0:
		return nil, fmt.Sprintf("pod %s/%s: cannot list its containers: %v", q.Namespace, name, err), false
	case err != nil:
		pod = nil // read the named containers blind
	}
	var containers []string
	if pod == nil {
		containers = dedupe(q.Containers)
	} else {
		names := podContainers(pod)
		if len(q.Containers) > 0 {
			names = slices.DeleteFunc(names, func(c string) bool { return !slices.Contains(q.Containers, c) })
		}
		containers = names
	}
	if len(containers) > p.opts.MaxContainers {
		warning = fmt.Sprintf("pod %s/%s: only %d of %d containers are read", q.Namespace, name, p.opts.MaxContainers, len(containers))
		truncated = true
		containers = containers[:p.opts.MaxContainers]
	}
	for _, c := range containers {
		if q.Previous && restartedSince(pod, c, q.From) {
			out = append(out, logStream{pod: name, container: c, previous: true})
		}
		out = append(out, logStream{pod: name, container: c})
	}
	return out, warning, truncated
}

// podContainers lists a pod's containers, app containers first.
func podContainers(pod *model.Pod) []string {
	var app, init []string
	for _, s := range pod.Specs {
		if s.Init {
			init = append(init, s.Name)
		} else {
			app = append(app, s.Name)
		}
	}
	if len(app)+len(init) == 0 {
		for _, s := range pod.Containers {
			if s.Init {
				init = append(init, s.Name)
			} else {
				app = append(app, s.Name)
			}
		}
	}
	return append(app, init...)
}

// restartedSince reports whether the container's previous instance may hold
// logs from the window: it restarted, and not before from. Unknown pods are
// tried.
func restartedSince(pod *model.Pod, container string, from time.Time) bool {
	if pod == nil {
		return true
	}
	for _, s := range pod.Containers {
		if s.Name == container {
			return s.RestartCount > 0 && (s.LastTerminatedAt.IsZero() || !s.LastTerminatedAt.Before(from))
		}
	}
	return false
}

// read fetches and filters one stream.
func (p *PodLogs) read(ctx context.Context, q incidents.LogQuery, s logStream) streamResult {
	if err := ctx.Err(); err != nil {
		return streamResult{err: err}
	}
	limit := p.opts.LimitBytes
	opts := &corev1.PodLogOptions{Container: s.container, Timestamps: true, LimitBytes: &limit, Previous: s.previous}
	if !q.From.IsZero() {
		since := metav1.NewTime(q.From)
		opts.SinceTime = &since
	}
	rc, err := p.cs.CoreV1().Pods(q.Namespace).GetLogs(s.pod, opts).Stream(ctx)
	if err != nil {
		return streamError(q.Namespace, s, err)
	}
	defer rc.Close()
	maxLines, maxBytes := p.limits(q)
	f := newLogFilter(q)
	lines, truncated, err := readLogStream(rc, f, limit, maxLines, maxBytes, func(t time.Time, level, text string) incidents.LogLine {
		return incidents.LogLine{Time: t, Pod: s.pod, Container: s.container, Level: level, Text: text, Source: LogSourceKubernetes}
	})
	if err != nil {
		if ctx.Err() != nil {
			return streamResult{err: ctx.Err()}
		}
		return streamResult{lines: lines, truncated: true, warning: fmt.Sprintf("%s: reading logs: %v", s.name(q.Namespace), err)}
	}
	return streamResult{lines: lines, truncated: truncated}
}

func (s logStream) name(ns string) string {
	n := ns + "/" + s.pod + "/" + s.container
	if s.previous {
		n += " (previous)"
	}
	return n
}

// streamError turns a failed GetLogs into a warning, or an error for what
// fails every stream alike (forbidden, cancelled).
func streamError(ns string, s logStream, err error) streamResult {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return streamResult{err: err}
	case apierrors.IsForbidden(err):
		return streamResult{err: fmt.Errorf("pod logs: %w", err)}
	case s.previous && apierrors.IsBadRequest(err):
		return streamResult{} // no previous instance: nothing to read
	case apierrors.IsNotFound(err):
		return streamResult{warning: fmt.Sprintf("pod %s/%s not found; it may have been deleted", ns, s.pod)}
	}
	msg := err.Error()
	var st apierrors.APIStatus
	if errors.As(err, &st) && st.Status().Message != "" {
		msg = st.Status().Message // "container \"web\" in pod \"web-0\" is waiting to start: ..."
	}
	return streamResult{warning: s.name(ns) + ": " + msg}
}

// logFilter is a query's line filter.
type logFilter struct {
	from, to time.Time
	minRank  int
	text     string // lower case
}

func newLogFilter(q incidents.LogQuery) logFilter {
	return logFilter{from: q.From, to: q.To, minRank: levelRank(q.Level), text: strings.ToLower(q.Text)}
}

func (f logFilter) match(level, text string) bool {
	if f.minRank > 0 && levelRank(level) < f.minRank {
		return false
	}
	return f.text == "" || strings.Contains(strings.ToLower(text), f.text)
}

// readLogStream reads "<RFC3339Nano> <text>" lines from r, as GetLogs with
// Timestamps returns them, until a line is later than f.to. Lines before
// f.from or failing the filter are skipped. At most maxLines lines and
// maxBytes bytes of text are kept: no more can survive the merge. truncated
// is set when the stream was cut: the API server stopped at limitBytes
// (whose last, partial line is dropped) or a cap was reached before f.to.
func readLogStream(r io.Reader, f logFilter, limitBytes int64, maxLines int, maxBytes int64, mk func(t time.Time, level, text string) incidents.LogLine) (lines []incidents.LogLine, truncated bool, err error) {
	br := bufio.NewReaderSize(r, 64<<10)
	var read, kept int64
	last := f.from
	for {
		raw, rerr := br.ReadString('\n')
		read += int64(len(raw))
		if rerr != nil && rerr != io.EOF {
			return lines, true, rerr
		}
		complete := strings.HasSuffix(raw, "\n")
		if rerr == io.EOF && !complete && raw != "" && limitBytes > 0 && read >= limitBytes {
			return lines, true, nil // cut mid-line by LimitBytes
		}
		if raw != "" {
			t, text, ok := parseLogLine(strings.TrimRight(raw, "\r\n"))
			if !ok {
				t = last // a line without a timestamp continues the one before
			}
			last = t
			if !f.to.IsZero() && t.After(f.to) {
				return lines, false, nil
			}
			if f.from.IsZero() || !t.Before(f.from) {
				if level := detectLevel(text); f.match(level, text) {
					if len(lines) >= maxLines || kept+int64(len(text)) > maxBytes {
						return lines, true, nil
					}
					kept += int64(len(text))
					lines = append(lines, mk(t, level, text))
				}
			}
		}
		if rerr == io.EOF {
			return lines, limitBytes > 0 && read >= limitBytes, nil
		}
	}
}

// parseLogLine splits the RFC3339Nano timestamp GetLogs prefixes to each
// line from the text.
func parseLogLine(line string) (time.Time, string, bool) {
	ts, text, found := strings.Cut(line, " ")
	if !found {
		ts, text = line, ""
	}
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return time.Time{}, line, false
	}
	return t, text, true
}

// Log levels, by rank.
const (
	LevelDebug = "debug"
	LevelInfo  = "info"
	LevelWarn  = "warn"
	LevelError = "error"
)

// levelRank orders levels; "" (no filter) and unknown words rank 0.
func levelRank(level string) int {
	switch level {
	case LevelDebug:
		return 1
	case LevelInfo:
		return 2
	case LevelWarn:
		return 3
	case LevelError:
		return 4
	}
	return 0
}

var (
	// levelWords are severity words in plain-text logs.
	levelWords = regexp.MustCompile(`\b(FATAL|PANIC|ERROR|WARN(ING)?)\b`)
	// logfmtLevel is a logfmt level=... pair.
	logfmtLevel = regexp.MustCompile(`(?:^|\s)(?:level|lvl)="?([A-Za-z]+)`)
	// klogHeader is the klog prefix Kubernetes components write, e.g.
	// "E1015 12:00:00.000000 1 controller.go:42] ...".
	klogHeader = regexp.MustCompile(`^([IWEF])\d{4} \d{2}:\d{2}:\d{2}\.\d{6}`)
)

// detectLevel classifies a log line: a structured level first (a JSON
// "level" field, logfmt level=, a klog header), else a FATAL, PANIC, ERROR
// or WARN(ING) word, else info.
func detectLevel(text string) string {
	if l, ok := jsonLevel(text); ok {
		return l
	}
	if m := logfmtLevel.FindStringSubmatch(text); m != nil {
		if l := normalizeLevel(m[1]); l != "" {
			return l
		}
	}
	if m := klogHeader.FindStringSubmatch(text); m != nil {
		switch m[1] {
		case "E", "F":
			return LevelError
		case "W":
			return LevelWarn
		}
		return LevelInfo
	}
	if m := levelWords.FindString(text); m != "" {
		if strings.HasPrefix(m, "WARN") {
			return LevelWarn
		}
		return LevelError
	}
	return LevelInfo
}

// jsonLevel reads the level of a JSON log line: "level" (or "lvl",
// "severity"), as a word or a pino/bunyan number.
func jsonLevel(text string) (string, bool) {
	s := strings.TrimSpace(text)
	if !strings.HasPrefix(s, "{") {
		return "", false
	}
	var v struct {
		Level    any `json:"level"`
		Lvl      any `json:"lvl"`
		Severity any `json:"severity"`
	}
	if json.Unmarshal([]byte(s), &v) != nil {
		return "", false
	}
	for _, x := range []any{v.Level, v.Lvl, v.Severity} {
		switch l := x.(type) {
		case string:
			if n := normalizeLevel(l); n != "" {
				return n, true
			}
		case float64:
			switch {
			case l >= 50:
				return LevelError, true
			case l >= 40:
				return LevelWarn, true
			case l >= 30:
				return LevelInfo, true
			default:
				return LevelDebug, true
			}
		}
	}
	return "", false
}

// normalizeLevel maps a level word to error, warn, info or debug; "" when
// it is not one.
func normalizeLevel(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "fatal", "panic", "critical", "crit", "alert", "emerg", "emergency", "error", "err", "dpanic":
		return LevelError
	case "warn", "warning":
		return LevelWarn
	case "info", "information", "informational", "notice":
		return LevelInfo
	case "debug", "trace", "verbose":
		return LevelDebug
	}
	return ""
}
