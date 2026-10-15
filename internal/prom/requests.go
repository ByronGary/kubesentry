package prom

// Request-rate sources for incidents. A request profile names a request
// counter and the labels that carry the namespace, the subject (a Service or a
// pod) and the HTTP status; the PromQL is always built here, through sel(), so
// -prometheus-selector applies and no profile can smuggle in free PromQL.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ByronGary/kubesentry/internal/incidents"
	"github.com/ByronGary/kubesentry/internal/model"
)

// Built-in request profiles (-incident-request-sources).
const (
	// ProfileNginx reads ingress-nginx's per-request counter, per backend
	// Service.
	ProfileNginx = "nginx"
	// ProfileApp reads the conventional http_requests_total of the
	// application itself, per pod.
	ProfileApp = "app"
)

// Probe results, as /info incidents.sources reports them; errors are
// "error: <message>".
const (
	ProbeOK     = "ok"
	ProbeAbsent = "absent"
)

// DefaultErrorRegex matches 5xx status codes.
const DefaultErrorRegex = "5.."

// The labels the rate queries write their results to. Profiles may not use
// them as source labels.
const (
	outNamespace = "ns"
	outSubject   = "subj"
	outError     = "err"
)

// RequestProfile describes one request counter. Exactly one of ServiceLabel
// and PodLabel is set: it says whether the samples are per Service or per pod.
type RequestProfile struct {
	Name   string `json:"name"`
	Metric string `json:"metric"`
	// NamespaceLabel holds the subject's namespace.
	NamespaceLabel string `json:"namespaceLabel"`
	// NamespaceFallbackLabel is read for series where NamespaceLabel is
	// empty or missing. ingress-nginx's own namespace label becomes
	// exported_namespace when the scrape adds the controller's namespace,
	// and stays namespace when it does not.
	NamespaceFallbackLabel string `json:"namespaceFallbackLabel,omitempty"`
	ServiceLabel           string `json:"serviceLabel,omitempty"`
	PodLabel               string `json:"podLabel,omitempty"`
	// StatusLabel holds the HTTP status code; empty when the counter has
	// none (the error ratio is then unknown, -1).
	StatusLabel string `json:"statusLabel,omitempty"`
	// ErrorRegex matches failed requests' status codes (anchored, RE2);
	// default DefaultErrorRegex.
	ErrorRegex string `json:"errorRegex,omitempty"`
}

var builtinProfiles = map[string]RequestProfile{
	ProfileNginx: {
		Name:                   ProfileNginx,
		Metric:                 "nginx_ingress_controller_requests",
		NamespaceLabel:         "exported_namespace",
		NamespaceFallbackLabel: "namespace",
		ServiceLabel:           "service",
		StatusLabel:            "status",
		ErrorRegex:             DefaultErrorRegex,
	},
	ProfileApp: {
		Name:           ProfileApp,
		Metric:         "http_requests_total",
		NamespaceLabel: "namespace",
		PodLabel:       "pod",
		StatusLabel:    "code",
		ErrorRegex:     DefaultErrorRegex,
	},
}

// BuiltinRequestProfile returns the built-in profile with that name.
func BuiltinRequestProfile(name string) (RequestProfile, bool) {
	p, ok := builtinProfiles[name]
	return p, ok
}

// BuiltinRequestProfileNames lists the built-in profiles, sorted.
func BuiltinRequestProfileNames() []string {
	out := make([]string, 0, len(builtinProfiles))
	for n := range builtinProfiles {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// PodLevel reports whether the profile's samples are per pod (otherwise per
// Service).
func (p RequestProfile) PodLevel() bool { return p.PodLabel != "" }

func (p RequestProfile) subjectLabel() string {
	if p.PodLabel != "" {
		return p.PodLabel
	}
	return p.ServiceLabel
}

var (
	profileName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)
	metricName  = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*$`)
)

// reservedSourceNames are taken by other request sources.
var reservedSourceNames = map[string]bool{"alb": true}

// Validate checks the profile and fills in the default error regex. Label
// names must be plain Prometheus label names (no __ prefix, not ns, subj or
// err, which the queries write); the error regex must compile.
func (p *RequestProfile) Validate() error {
	if !profileName.MatchString(p.Name) {
		return fmt.Errorf("request profile name %q: want 1 to 63 lower-case letters, digits and hyphens", p.Name)
	}
	if reservedSourceNames[p.Name] {
		return fmt.Errorf("request profile name %q is reserved", p.Name)
	}
	if !metricName.MatchString(p.Metric) {
		return fmt.Errorf("request profile %s: invalid metric name %q", p.Name, p.Metric)
	}
	if (p.ServiceLabel == "") == (p.PodLabel == "") {
		return fmt.Errorf("request profile %s: set exactly one of serviceLabel and podLabel", p.Name)
	}
	if p.NamespaceLabel == "" {
		return fmt.Errorf("request profile %s: namespaceLabel is required", p.Name)
	}
	labels := map[string]string{
		"namespaceLabel": p.NamespaceLabel, "namespaceFallbackLabel": p.NamespaceFallbackLabel,
		"serviceLabel": p.ServiceLabel, "podLabel": p.PodLabel, "statusLabel": p.StatusLabel,
	}
	for _, field := range []string{"namespaceLabel", "namespaceFallbackLabel", "serviceLabel", "podLabel", "statusLabel"} {
		v := labels[field]
		if v == "" {
			continue
		}
		if !labelName.MatchString(v) || strings.HasPrefix(v, "__") {
			return fmt.Errorf("request profile %s: %s %q is not a usable label name", p.Name, field, v)
		}
		if v == outNamespace || v == outSubject || v == outError {
			return fmt.Errorf("request profile %s: %s %q is reserved", p.Name, field, v)
		}
	}
	if p.NamespaceFallbackLabel == p.NamespaceLabel {
		p.NamespaceFallbackLabel = ""
	}
	if p.StatusLabel == "" {
		if p.ErrorRegex != "" {
			return fmt.Errorf("request profile %s: errorRegex needs statusLabel", p.Name)
		}
		return nil
	}
	if p.ErrorRegex == "" {
		p.ErrorRegex = DefaultErrorRegex
	}
	// Prometheus anchors regexes and uses RE2 syntax, as Go does.
	if _, err := regexp.Compile("^(?:" + p.ErrorRegex + ")$"); err != nil {
		return fmt.Errorf("request profile %s: errorRegex: %v", p.Name, err)
	}
	return nil
}

// ParseRequestProfiles reads profiles from JSON: an array of profiles, or an
// object {"profiles": [...]}. Unknown fields are refused, so a typo is not
// silently ignored. Every profile is validated; names must be unique.
func ParseRequestProfiles(data []byte) ([]RequestProfile, error) {
	trimmed := bytes.TrimSpace(data)
	var out []RequestProfile
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	if len(trimmed) > 0 && trimmed[0] == '[' {
		if err := dec.Decode(&out); err != nil {
			return nil, fmt.Errorf("request profiles: %w", err)
		}
	} else {
		var wrapped struct {
			Profiles []RequestProfile `json:"profiles"`
		}
		if err := dec.Decode(&wrapped); err != nil {
			return nil, fmt.Errorf("request profiles: %w", err)
		}
		out = wrapped.Profiles
	}
	seen := map[string]bool{}
	for i := range out {
		if err := out[i].Validate(); err != nil {
			return nil, err
		}
		if seen[out[i].Name] {
			return nil, fmt.Errorf("request profile %s defined twice", out[i].Name)
		}
		seen[out[i].Name] = true
	}
	return out, nil
}

// LoadRequestProfiles reads a profiles file (-incident-request-profiles-file).
func LoadRequestProfiles(path string) ([]RequestProfile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	ps, err := ParseRequestProfiles(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return ps, nil
}

// SelectRequestProfiles returns the profiles to run: the built-ins named in
// names (-incident-request-sources), then every profile from the file. A file
// profile with a built-in's name replaces it. Unknown names are an error.
func SelectRequestProfiles(names []string, file []RequestProfile) ([]RequestProfile, error) {
	fromFile := map[string]RequestProfile{}
	for _, p := range file {
		fromFile[p.Name] = p
	}
	var out []RequestProfile
	used := map[string]bool{}
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" || used[n] {
			continue
		}
		p, ok := fromFile[n]
		if !ok {
			if p, ok = builtinProfiles[n]; !ok {
				return nil, fmt.Errorf("unknown request source %q (built-in: %s, or a name from the profiles file)", n, strings.Join(BuiltinRequestProfileNames(), ", "))
			}
		}
		if err := p.Validate(); err != nil {
			return nil, err
		}
		out = append(out, p)
		used[n] = true
	}
	for _, p := range file {
		if used[p.Name] {
			continue
		}
		if err := p.Validate(); err != nil {
			return nil, err
		}
		out = append(out, p)
		used[p.Name] = true
	}
	return out, nil
}

// RequestSource reads one request profile from Prometheus. It implements
// incidents.RateSource.
type RequestSource struct {
	c *Client
	p RequestProfile
}

var _ incidents.RateSource = (*RequestSource)(nil)

// RequestSource returns a source for the profile, which it validates.
func (c *Client) RequestSource(p RequestProfile) (*RequestSource, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &RequestSource{c: c, p: p}, nil
}

// RequestSources returns a source per profile.
func (c *Client) RequestSources(ps []RequestProfile) ([]*RequestSource, error) {
	out := make([]*RequestSource, 0, len(ps))
	for _, p := range ps {
		s, err := c.RequestSource(p)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// Name is the profile name, used as RateSample.Source.
func (s *RequestSource) Name() string { return s.p.Name }

// Profile returns the validated profile.
func (s *RequestSource) Profile() RequestProfile { return s.p }

// Rates returns each subject's average request rate over [at-offset-window,
// at-offset] and its error ratio. namespaces nil queries every namespace (the
// caller drops excluded ones); an empty non-nil list queries nothing. Long
// namespace lists are split so each query stays under ~8 KiB.
func (s *RequestSource) Rates(ctx context.Context, at time.Time, window, offset time.Duration, namespaces []string) ([]model.RateSample, error) {
	var out []model.RateSample
	for _, q := range s.rateQueries(window, offset, namespaces) {
		res, err := s.c.Query(ctx, q, at)
		if err != nil {
			return nil, fmt.Errorf("%s request rates: %w", s.p.Name, err)
		}
		out = append(out, s.samples(res)...)
	}
	return out, nil
}

// Probe reports whether Prometheus has the profile's metric: ProbeOK,
// ProbeAbsent, or "error: …".
func (s *RequestSource) Probe(ctx context.Context) string {
	res, err := s.c.query(ctx, s.probeQuery(), s.c.clock(), nil)
	if err != nil {
		return "error: " + err.Error()
	}
	for _, r := range res {
		if n := len(r.Samples); n > 0 && r.Samples[n-1].V > 0 {
			return ProbeOK
		}
	}
	return ProbeAbsent
}

func (s *RequestSource) probeQuery() string { return "count(" + s.c.sel(s.p.Metric) + ")" }

// rateQueries builds the instant queries for Rates, one per namespace chunk.
func (s *RequestSource) rateQueries(window, offset time.Duration, namespaces []string) []string {
	if window <= 0 {
		window = 5 * time.Minute
	}
	if namespaces == nil {
		return []string{s.expr(s.selectors(nil, nil), window, offset)}
	}
	// The namespace list appears once per selector.
	copies := 1
	if s.p.NamespaceFallbackLabel != "" {
		copies = 2
	}
	budget := (maxNamespaceQuery - len(s.expr(s.selectors([]string{}, nil), window, offset))) / copies
	var out []string
	for _, chunk := range chunkNames(validNames(namespaces), budget) {
		out = append(out, s.expr(s.selectors(chunk, nil), window, offset))
	}
	return out
}

// selectors returns the series selectors for a namespace chunk (nil: every
// namespace) and, when subjects is non-nil, those subjects only. With a
// namespace fallback label, a restricted query needs a second selector for
// the series whose primary namespace label is empty.
func (s *RequestSource) selectors(nsChunk, subjects []string) []string {
	p := s.p
	subj := p.subjectLabel()
	var base []string
	if subjects != nil {
		base = []string{nameMatcher(subj, subjects)}
	} else {
		base = []string{subj + `!=""`}
	}
	if nsChunk == nil {
		return []string{s.c.sel(p.Metric, base...)}
	}
	out := []string{s.c.sel(p.Metric, append([]string{nameMatcher(p.NamespaceLabel, nsChunk)}, base...)...)}
	if p.NamespaceFallbackLabel != "" {
		out = append(out, s.c.sel(p.Metric, append([]string{
			p.NamespaceLabel + `=""`, nameMatcher(p.NamespaceFallbackLabel, nsChunk),
		}, base...)...))
	}
	return out
}

// expr is sum by (ns, subj[, err]) of the selectors' rates, with the
// namespace, subject and error flag copied into the output labels:
//
//	sum by (ns, subj, err) (label_replace(label_replace(label_replace(
//	  rate(metric{…}[5m] offset 5m), "ns", "$1", "namespace", "(.+)"),
//	  "subj", "$1", "service", "(.+)"), "err", "1", "status", "5.."))
//
// Series whose status matches the error regex carry err="1"; the others
// carry no err label.
func (s *RequestSource) expr(sels []string, window, offset time.Duration) string {
	rng := "[" + promDuration(window) + "]"
	if offset > 0 {
		rng += " offset " + promDuration(offset)
	}
	rates := make([]string, len(sels))
	for i, sel := range sels {
		rates[i] = "rate(" + sel + rng + ")"
	}
	x := strings.Join(rates, " or ")
	p := s.p
	if p.NamespaceFallbackLabel != "" {
		x = labelReplace(x, outNamespace, "$1", p.NamespaceFallbackLabel, "(.+)")
	}
	x = labelReplace(x, outNamespace, "$1", p.NamespaceLabel, "(.+)")
	x = labelReplace(x, outSubject, "$1", p.subjectLabel(), "(.+)")
	by := outNamespace + ", " + outSubject
	if p.StatusLabel != "" {
		x = labelReplace(x, outError, "1", p.StatusLabel, p.ErrorRegex)
		by += ", " + outError
	}
	return "sum by (" + by + ") (" + x + ")"
}

func labelReplace(x, dst, repl, src, re string) string {
	return "label_replace(" + x + ", " + strconv.Quote(dst) + ", " + strconv.Quote(repl) + ", " +
		strconv.Quote(src) + ", " + strconv.Quote(re) + ")"
}

// samples folds an instant result into one sample per subject.
func (s *RequestSource) samples(res []Series) []model.RateSample {
	type key struct{ ns, subj string }
	type acc struct{ total, errs float64 }
	sums := map[key]*acc{}
	var keys []key
	for _, r := range res {
		n := len(r.Samples)
		if n == 0 {
			continue
		}
		k := key{r.Labels[outNamespace], r.Labels[outSubject]}
		if !validName(k.ns) || !validName(k.subj) {
			continue
		}
		a := sums[k]
		if a == nil {
			a = &acc{}
			sums[k] = a
			keys = append(keys, k)
		}
		v := r.Samples[n-1].V
		a.total += v
		if r.Labels[outError] == "1" {
			a.errs += v
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].ns != keys[j].ns {
			return keys[i].ns < keys[j].ns
		}
		return keys[i].subj < keys[j].subj
	})
	out := make([]model.RateSample, 0, len(keys))
	for _, k := range keys {
		a := sums[k]
		rs := model.RateSample{Source: s.p.Name, Namespace: k.ns, PerSecond: a.total, ErrorRatio: -1}
		if s.p.PodLevel() {
			rs.Pod = k.subj
		} else {
			rs.Service = k.subj
		}
		if s.p.StatusLabel != "" {
			rs.ErrorRatio = 0
			if a.total > 0 {
				rs.ErrorRatio = a.errs / a.total
			}
		}
		out = append(out, rs)
	}
	return out
}

var _ incidents.MemorySource = (*Client)(nil)

// MemoryUsage returns every container's working set at the given instant.
// namespaces nil queries every namespace; an empty non-nil list queries
// nothing; long lists are split as in ContainerMemoryIn.
func (c *Client) MemoryUsage(ctx context.Context, at time.Time, namespaces []string) ([]model.MemorySample, error) {
	var nsMatchers []string
	switch {
	case namespaces == nil:
		nsMatchers = []string{""}
	default:
		nsMatchers = c.namespaceMatchers(namespaces, len(memMetric)+96)
	}
	var out []model.MemorySample
	for _, m := range nsMatchers {
		parts := []string{`container!=""`, `container!="POD"`}
		if m != "" {
			parts = append([]string{m}, parts...)
		}
		q := `max by (namespace, pod, container) (` + c.sel(memMetric, parts...) + `)`
		res, err := c.Query(ctx, q, at)
		if err != nil {
			return nil, fmt.Errorf("memory usage: %w", err)
		}
		for _, r := range res {
			k := keyFrom(r.Labels)
			if n := len(r.Samples); n > 0 && validKey(k) {
				out = append(out, model.MemorySample{Namespace: k.Namespace, Pod: k.Pod, Container: k.Container, Bytes: r.Samples[n-1].V})
			}
		}
	}
	return out, nil
}

// SeriesSource draws an incident's detail charts from Prometheus: memory per
// container of the incident's pods, and request rate and error ratio per pod
// or Service from each request profile. It implements incidents.SeriesSource.
type SeriesSource struct {
	c        *Client
	requests []*RequestSource
}

var _ incidents.SeriesSource = (*SeriesSource)(nil)

// DefaultMaxSeries is the number of lines per metric and source when the
// query does not say; the rest fold into "others".
const DefaultMaxSeries = 12

// maxSubjects bounds the pods or Services named in one series query.
const maxSubjects = 200

// SeriesSourceLabel is Series.Source for memory series.
const SeriesSourceLabel = "prometheus"

// OthersLabel is the label of the line the smaller series fold into.
const OthersLabel = "others"

// NewSeriesSource returns a series source over c and the request sources.
func NewSeriesSource(c *Client, requests ...*RequestSource) *SeriesSource {
	return &SeriesSource{c: c, requests: requests}
}

// SubjectSeries runs range queries over [From, To] at Step (default
// (To-From)/240, 15s to 5m) and returns, per metric and source, the
// MaxSeries lines with the highest peak plus an "others" line for the rest:
// memory in bytes, requests per second, and the error ratio (lines ranked by
// their peak error rate). When some queries fail it returns the series of
// the others along with an error naming the failures.
func (s *SeriesSource) SubjectSeries(ctx context.Context, q incidents.SeriesQuery) ([]incidents.Series, error) {
	if !validName(q.Namespace) {
		return nil, fmt.Errorf("series: invalid namespace %q", q.Namespace)
	}
	if !q.To.After(q.From) {
		return nil, errors.New("series: empty time range")
	}
	step := q.Step
	if step <= 0 {
		step = min(max(q.To.Sub(q.From)/240, 15*time.Second), 5*time.Minute).Round(time.Second)
	}
	n := q.MaxSeries
	if n <= 0 {
		n = DefaultMaxSeries
	}
	var out []incidents.Series
	var errs []error
	if pods := capNames(q.Pods); len(pods) > 0 {
		got, err := s.memorySeries(ctx, q.Namespace, pods, q.From, q.To, step, n)
		if err != nil {
			errs = append(errs, err)
		}
		out = append(out, got...)
	}
	for _, rs := range s.requests {
		subjects := q.Services
		if rs.p.PodLevel() {
			subjects = q.Pods
		}
		subjects = capNames(subjects)
		if len(subjects) == 0 {
			continue
		}
		got, err := rs.subjectSeries(ctx, q.Namespace, subjects, q.From, q.To, step, n)
		if err != nil {
			errs = append(errs, err)
		}
		out = append(out, got...)
	}
	return out, errors.Join(errs...)
}

func capNames(names []string) []string {
	v := validNames(names)
	if len(v) > maxSubjects {
		v = v[:maxSubjects]
	}
	return v
}

// memoryQuery is the range query for the memory of the pods' containers.
func (s *SeriesSource) memoryQuery(ns string, pods []string) string {
	return `max by (namespace, pod, container) (` + s.c.sel(memMetric,
		`namespace=`+strconv.Quote(ns), nameMatcher("pod", pods), `container!=""`, `container!="POD"`) + `)`
}

func (s *SeriesSource) memorySeries(ctx context.Context, ns string, pods []string, from, to time.Time, step time.Duration, n int) ([]incidents.Series, error) {
	raw, err := s.c.QueryRange(ctx, s.memoryQuery(ns, pods), from, to, step)
	if err != nil {
		return nil, fmt.Errorf("memory series: %w", err)
	}
	var lines []line
	for _, r := range raw {
		k := keyFrom(r.Labels)
		if !validKey(k) || k.Namespace != ns {
			continue
		}
		l := line{label: k.Pod + "/" + k.Container, vals: pointMap{}}
		for _, smp := range r.Samples {
			l.vals[smp.T.UnixMilli()] += smp.V
		}
		lines = append(lines, l)
	}
	keep, rest := topLines(lines, n, func(l line) float64 { return l.vals.peak() })
	out := make([]incidents.Series, 0, len(keep)+1)
	for _, l := range keep {
		out = append(out, incidents.Series{Metric: "memory", Label: l.label, Unit: "bytes", Source: SeriesSourceLabel, Points: l.vals.points()})
	}
	if len(rest) > 0 {
		sum := pointMap{}
		for _, l := range rest {
			sum.add(l.vals)
		}
		out = append(out, incidents.Series{Metric: "memory", Label: OthersLabel, Unit: "bytes", Source: SeriesSourceLabel, Points: sum.points()})
	}
	return out, nil
}

// seriesQuery is the range query for the subjects' request rates in one
// namespace.
func (s *RequestSource) seriesQuery(ns string, subjects []string, step time.Duration) string {
	return s.expr(s.selectors([]string{ns}, subjects), rateWindow(step), 0)
}

// rateWindow is the rate() range for a chart step: two steps, at least a
// minute, so a sparse scrape still yields two samples.
func rateWindow(step time.Duration) time.Duration {
	return max(2*step, time.Minute).Round(time.Second)
}

func (s *RequestSource) subjectSeries(ctx context.Context, ns string, subjects []string, from, to time.Time, step time.Duration, n int) ([]incidents.Series, error) {
	raw, err := s.c.QueryRange(ctx, s.seriesQuery(ns, subjects, step), from, to, step)
	if err != nil {
		return nil, fmt.Errorf("%s request series: %w", s.p.Name, err)
	}
	bySubj := map[string]*line{}
	var lines []*line
	for _, r := range raw {
		subj := r.Labels[outSubject]
		if r.Labels[outNamespace] != ns || !validName(subj) {
			continue
		}
		l := bySubj[subj]
		if l == nil {
			l = &line{label: subj, vals: pointMap{}, errs: pointMap{}}
			bySubj[subj] = l
			lines = append(lines, l)
		}
		isErr := r.Labels[outError] == "1"
		for _, smp := range r.Samples {
			ms := smp.T.UnixMilli()
			l.vals[ms] += smp.V
			if isErr {
				l.errs[ms] += smp.V
			} else if _, ok := l.errs[ms]; !ok {
				l.errs[ms] = 0
			}
		}
	}
	flat := make([]line, len(lines))
	for i, l := range lines {
		flat[i] = *l
	}

	var out []incidents.Series
	keep, rest := topLines(flat, n, func(l line) float64 { return l.vals.peak() })
	for _, l := range keep {
		out = append(out, incidents.Series{Metric: "requests", Label: l.label, Unit: "rps", Source: s.p.Name, Points: l.vals.points()})
	}
	if len(rest) > 0 {
		sum := pointMap{}
		for _, l := range rest {
			sum.add(l.vals)
		}
		out = append(out, incidents.Series{Metric: "requests", Label: OthersLabel, Unit: "rps", Source: s.p.Name, Points: sum.points()})
	}
	if s.p.StatusLabel == "" {
		return out, nil
	}
	keep, rest = topLines(flat, n, func(l line) float64 { return l.errs.peak() })
	for _, l := range keep {
		out = append(out, incidents.Series{Metric: "errors", Label: l.label, Unit: "ratio", Source: s.p.Name, Points: ratioPoints(l.errs, l.vals)})
	}
	if len(rest) > 0 {
		errSum, totSum := pointMap{}, pointMap{}
		for _, l := range rest {
			errSum.add(l.errs)
			totSum.add(l.vals)
		}
		out = append(out, incidents.Series{Metric: "errors", Label: OthersLabel, Unit: "ratio", Source: s.p.Name, Points: ratioPoints(errSum, totSum)})
	}
	return out, nil
}

// line is one chart line being assembled: values (and, for requests, error
// rates) by Unix millisecond.
type line struct {
	label string
	vals  pointMap
	errs  pointMap
}

// topLines returns the n lines ranked highest (ties by label) and the rest.
func topLines(lines []line, n int, rank func(line) float64) (keep, rest []line) {
	sorted := append([]line(nil), lines...)
	ranks := make(map[string]float64, len(sorted))
	for _, l := range sorted {
		ranks[l.label] = rank(l)
	}
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := ranks[sorted[i].label], ranks[sorted[j].label]
		if a != b {
			return a > b
		}
		return sorted[i].label < sorted[j].label
	})
	if len(sorted) <= n {
		return sorted, nil
	}
	return sorted[:n], sorted[n:]
}

// pointMap holds a series' values by Unix millisecond.
type pointMap map[int64]float64

func (m pointMap) peak() float64 {
	p := 0.0
	for _, v := range m {
		p = max(p, v)
	}
	return p
}

func (m pointMap) add(o pointMap) {
	for t, v := range o {
		m[t] += v
	}
}

func (m pointMap) points() [][2]float64 {
	ts := make([]int64, 0, len(m))
	for t := range m {
		ts = append(ts, t)
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i] < ts[j] })
	out := make([][2]float64, len(ts))
	for i, t := range ts {
		out[i] = [2]float64{float64(t), m[t]}
	}
	return out
}

// ratioPoints divides errs by totals at each time with requests; times
// without requests are left out (the ratio is undefined there).
func ratioPoints(errs, totals pointMap) [][2]float64 {
	r := pointMap{}
	for t, tot := range totals {
		if tot > 0 {
			r[t] = errs[t] / tot
		}
	}
	return r.points()
}
