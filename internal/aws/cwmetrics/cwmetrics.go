// Package cwmetrics reads Application Load Balancer request metrics from
// CloudWatch for incidents: requests per second and the share of target 5xx
// answers per Service, through the target groups that
// TargetGroupBindings tie to Services. It calls GetMetricData over the AWS
// JSON 1.0 protocol, signed by awsauth, so no CloudWatch SDK module is
// needed.
package cwmetrics

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/ByronGary/kubesentry/internal/aws/awsjson"
	"github.com/ByronGary/kubesentry/internal/awsauth"
	"github.com/ByronGary/kubesentry/internal/incidents"
	"github.com/ByronGary/kubesentry/internal/model"
)

// Name is the source name in RateSample.Source, Series.Source and /info.
const Name = "alb"

// Protocol constants of CloudWatch's AWS JSON 1.0 API.
const (
	// SigningName is CloudWatch's SigV4 service name.
	SigningName = "monitoring"
	// TargetPrefix is the X-Amz-Target prefix of CloudWatch operations.
	TargetPrefix = "GraniteServiceVersion20100801"
)

// Metric names.
const (
	metricRequests = "RequestCount"
	metric5xx      = "HTTPCode_Target_5XX_Count"
)

// Defaults.
const (
	DefaultLag      = 2 * time.Minute
	DefaultCacheTTL = time.Minute
	// targetsPerCall keeps a call at 100 SEARCH expressions, two per target
	// group.
	targetsPerCall = 50
	period         = 60 // seconds; ALB metrics are per minute
)

// Target ties an ALB target group to the Service behind it.
type Target struct {
	TargetGroupARN string
	Namespace      string
	Service        string
}

// TargetsFrom maps TargetGroupBindings to targets.
func TargetsFrom(bindings []model.TargetGroupBinding) []Target {
	out := make([]Target, 0, len(bindings))
	for _, b := range bindings {
		out = append(out, Target{TargetGroupARN: b.TargetGroupARN, Namespace: b.Namespace, Service: b.ServiceName})
	}
	return out
}

// tgARN matches an ELBv2 target group ARN and captures the TargetGroup
// dimension value, "targetgroup/<name>/<id>".
var tgARN = regexp.MustCompile(`^arn:aws[a-z-]*:elasticloadbalancing:[a-z0-9-]+:[0-9]{12}:(targetgroup/[A-Za-z0-9-]{1,32}/[0-9a-f]{16})$`)

var k8sName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`)

// Dimension returns the TargetGroup dimension of a target group ARN.
func Dimension(arn string) (string, bool) {
	m := tgARN.FindStringSubmatch(arn)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// Options configures New.
type Options struct {
	// Region of the load balancers (-aws-region); empty uses the SDK's
	// default configuration.
	Region  string
	Profile string
	// Endpoint overrides the CloudWatch endpoint (a VPC endpoint, tests).
	Endpoint string
	// Credentials replaces the SDK's default chain (tests).
	Credentials aws.CredentialsProvider
	// Base sends the signed requests (tests); default http.DefaultTransport.
	Base http.RoundTripper
	// Targets returns the current target groups, usually from the snapshot
	// view's TargetGroupBindings; required.
	Targets func() []Target
	// Lag shifts every window back, because ALB metrics arrive 1 to 3
	// minutes late; default DefaultLag.
	Lag time.Duration
	// CacheTTL keeps a GetMetricData answer; default DefaultCacheTTL.
	CacheTTL time.Duration
	// Now is the clock; default time.Now.
	Now func() time.Time
	// Sleep replaces the retry backoff's wait (tests).
	Sleep func(ctx context.Context, d time.Duration) bool
	// OnThrottle, if set, is told of each throttled call.
	OnThrottle func()
}

// Source is the ALB request-rate source. It implements incidents.RateSource
// and incidents.SeriesSource.
type Source struct {
	api     *awsjson.Client
	targets func() []Target
	lag     time.Duration
	ttl     time.Duration
	now     func() time.Time

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	samples []model.RateSample
	expires time.Time
}

var (
	_ incidents.RateSource   = (*Source)(nil)
	_ incidents.SeriesSource = (*Source)(nil)
)

// New returns a source. Like awsauth.New it only reads local configuration;
// credentials are fetched by the first call.
func New(ctx context.Context, o Options) (*Source, error) {
	if o.Targets == nil {
		return nil, errors.New("alb metrics: no target provider")
	}
	t, err := awsauth.New(ctx, o.Endpoint, awsauth.Options{
		Region: o.Region, Profile: o.Profile, Service: SigningName, Base: o.Base, Credentials: o.Credentials, Now: o.Now,
	})
	if err != nil {
		return nil, fmt.Errorf("alb metrics: %w", err)
	}
	endpoint := o.Endpoint
	if endpoint == "" {
		endpoint = awsjson.Endpoint(SigningName, t.Region())
	}
	s := &Source{
		api: &awsjson.Client{
			Endpoint: endpoint, Target: TargetPrefix, ContentType: awsjson.JSON10,
			HTTP: &http.Client{Transport: t, Timeout: 30 * time.Second}, Sleep: o.Sleep, OnThrottle: o.OnThrottle,
		},
		targets: o.Targets, lag: o.Lag, ttl: o.CacheTTL, now: o.Now,
		cache: map[string]cacheEntry{},
	}
	if s.lag <= 0 {
		s.lag = DefaultLag
	}
	if s.ttl <= 0 {
		s.ttl = DefaultCacheTTL
	}
	if s.now == nil {
		s.now = time.Now
	}
	return s, nil
}

// Name is "alb".
func (s *Source) Name() string { return Name }

// target is a validated Target with its dimension value.
type target struct {
	dim, ns, svc string
}

// current returns the valid targets in the namespaces (nil: all), sorted.
func (s *Source) current(namespaces []string) []target {
	var allow map[string]bool
	if namespaces != nil {
		allow = map[string]bool{}
		for _, n := range namespaces {
			allow[n] = true
		}
	}
	seen := map[target]bool{}
	var out []target
	for _, t := range s.targets() {
		dim, ok := Dimension(t.TargetGroupARN)
		if !ok || !k8sName.MatchString(t.Namespace) || !k8sName.MatchString(t.Service) {
			continue
		}
		if allow != nil && !allow[t.Namespace] {
			continue
		}
		tg := target{dim: dim, ns: t.Namespace, svc: t.Service}
		if !seen[tg] {
			seen[tg] = true
			out = append(out, tg)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.ns != b.ns {
			return a.ns < b.ns
		}
		if a.svc != b.svc {
			return a.svc < b.svc
		}
		return a.dim < b.dim
	})
	return out
}

// Search is the expression for one metric of one target group: the
// per-minute Sum, summed over the load balancers the group is attached to,
// so each query ID answers with exactly one series.
func Search(metric, dim string, periodSeconds int) string {
	return fmt.Sprintf(`SUM(SEARCH('{AWS/ApplicationELB,LoadBalancer,TargetGroup} MetricName="%s" TargetGroup="%s"', 'Sum', %d))`, metric, dim, periodSeconds)
}

// Rates returns each Service's average request rate over
// [at-offset-window, at-offset], shifted back by the lag, with its target
// 5xx ratio. Services without traffic report 0. Answers are cached for the
// cache TTL.
func (s *Source) Rates(ctx context.Context, at time.Time, window, offset time.Duration, namespaces []string) ([]model.RateSample, error) {
	if window <= 0 {
		window = 5 * time.Minute
	}
	targets := s.current(namespaces)
	if len(targets) == 0 {
		return nil, nil
	}
	end := at.Add(-offset - s.lag).Truncate(time.Minute)
	start := end.Add(-window).Truncate(time.Minute)
	if !end.After(start) {
		return nil, errors.New("alb metrics: window shorter than a minute")
	}
	key := cacheKey(start, end, targets)
	now := s.now()
	s.mu.Lock()
	if e, ok := s.cache[key]; ok && now.Before(e.expires) {
		s.mu.Unlock()
		return append([]model.RateSample(nil), e.samples...), nil
	}
	s.mu.Unlock()

	sums, err := s.fetch(ctx, targets, start, end, period)
	if err != nil {
		return nil, err
	}
	type subj struct{ ns, svc string }
	type acc struct{ reqs, errs float64 }
	per := map[subj]*acc{}
	var order []subj
	for i, t := range targets {
		k := subj{t.ns, t.svc}
		a := per[k]
		if a == nil {
			a = &acc{}
			per[k] = a
			order = append(order, k)
		}
		for _, v := range sums[i].reqs {
			a.reqs += v
		}
		for _, v := range sums[i].errs {
			a.errs += v
		}
	}
	secs := end.Sub(start).Seconds()
	out := make([]model.RateSample, 0, len(order))
	for _, k := range order {
		a := per[k]
		rs := model.RateSample{Source: Name, Namespace: k.ns, Service: k.svc, PerSecond: a.reqs / secs}
		if a.reqs > 0 {
			rs.ErrorRatio = a.errs / a.reqs
		}
		out = append(out, rs)
	}

	s.mu.Lock()
	for k, e := range s.cache {
		if !now.Before(e.expires) {
			delete(s.cache, k)
		}
	}
	s.cache[key] = cacheEntry{samples: out, expires: now.Add(s.ttl)}
	s.mu.Unlock()
	return append([]model.RateSample(nil), out...), nil
}

func cacheKey(start, end time.Time, targets []target) string {
	h := sha256.New()
	for _, t := range targets {
		fmt.Fprintf(h, "%s\x00%s\x00%s\n", t.dim, t.ns, t.svc)
	}
	return fmt.Sprintf("%d-%d-%s", start.Unix(), end.Unix(), hex.EncodeToString(h.Sum(nil)))
}

// Probe reports ProbeOK when a target group had requests in the last hour,
// "absent" when there are no target groups or none had any, and "error: …"
// when CloudWatch could not be read.
func (s *Source) Probe(ctx context.Context) string {
	targets := s.current(nil)
	if len(targets) == 0 {
		return "absent"
	}
	if len(targets) > targetsPerCall {
		targets = targets[:targetsPerCall]
	}
	end := s.now().Add(-s.lag).Truncate(time.Minute)
	sums, err := s.fetch(ctx, targets, end.Add(-time.Hour), end, period)
	if err != nil {
		return "error: " + err.Error()
	}
	for _, sm := range sums {
		for _, v := range sm.reqs {
			if v > 0 {
				return "ok"
			}
		}
	}
	return "absent"
}

// sums are one target group's per-period request and 5xx counts by Unix
// second.
type sums struct {
	reqs, errs map[int64]float64
}

// metricDataQuery is a GetMetricData query; only expressions are sent.
type metricDataQuery struct {
	ID         string `json:"Id"`
	Expression string `json:"Expression"`
	Label      string `json:"Label,omitempty"`
	Period     int    `json:"Period,omitempty"`
	ReturnData bool   `json:"ReturnData"`
}

type getMetricDataInput struct {
	StartTime         awsjson.Seconds   `json:"StartTime"`
	EndTime           awsjson.Seconds   `json:"EndTime"`
	MetricDataQueries []metricDataQuery `json:"MetricDataQueries"`
	ScanBy            string            `json:"ScanBy"`
	NextToken         string            `json:"NextToken,omitempty"`
}

type message struct {
	Code  string `json:"Code"`
	Value string `json:"Value"`
}

type getMetricDataOutput struct {
	MetricDataResults []struct {
		ID         string            `json:"Id"`
		Label      string            `json:"Label"`
		StatusCode string            `json:"StatusCode"`
		Timestamps []awsjson.Seconds `json:"Timestamps"`
		Values     []float64         `json:"Values"`
		Messages   []message         `json:"Messages"`
	} `json:"MetricDataResults"`
	Messages  []message `json:"Messages"`
	NextToken string    `json:"NextToken"`
}

// maxPages bounds the NextToken loop of one GetMetricData query.
const maxPages = 20

// fetch returns per-period sums for each target, in order, calling
// GetMetricData for at most targetsPerCall targets at a time.
func (s *Source) fetch(ctx context.Context, targets []target, start, end time.Time, periodSec int) ([]sums, error) {
	out := make([]sums, len(targets))
	for i := range out {
		out[i] = sums{reqs: map[int64]float64{}, errs: map[int64]float64{}}
	}
	for lo := 0; lo < len(targets); lo += targetsPerCall {
		hi := min(lo+targetsPerCall, len(targets))
		in := getMetricDataInput{StartTime: awsjson.At(start), EndTime: awsjson.At(end), ScanBy: "TimestampAscending"}
		for i := lo; i < hi; i++ {
			n := strconv.Itoa(i)
			in.MetricDataQueries = append(in.MetricDataQueries,
				metricDataQuery{ID: "r" + n, Expression: Search(metricRequests, targets[i].dim, periodSec), Period: periodSec, ReturnData: true},
				metricDataQuery{ID: "e" + n, Expression: Search(metric5xx, targets[i].dim, periodSec), Period: periodSec, ReturnData: true})
		}
		for page := 0; ; page++ {
			if page >= maxPages {
				return nil, errors.New("alb metrics: GetMetricData kept paging")
			}
			var resp getMetricDataOutput
			if err := s.api.Do(ctx, "GetMetricData", in, &resp); err != nil {
				return nil, fmt.Errorf("alb metrics: %w", err)
			}
			for _, r := range resp.MetricDataResults {
				if r.StatusCode == "Forbidden" || r.StatusCode == "InternalError" {
					return nil, fmt.Errorf("alb metrics: query %s: %s %s", r.ID, r.StatusCode, joinMessages(r.Messages))
				}
				if len(r.ID) < 2 {
					continue
				}
				idx, err := strconv.Atoi(r.ID[1:])
				if err != nil || idx < lo || idx >= hi {
					continue
				}
				dst := out[idx].reqs
				if r.ID[0] == 'e' {
					dst = out[idx].errs
				}
				for j, ts := range r.Timestamps {
					if j < len(r.Values) {
						dst[ts.Time().Unix()] += r.Values[j]
					}
				}
			}
			if resp.NextToken == "" {
				break
			}
			in.NextToken = resp.NextToken
		}
	}
	return out, nil
}

func joinMessages(ms []message) string {
	parts := make([]string, 0, len(ms))
	for _, m := range ms {
		parts = append(parts, m.Code+": "+m.Value)
	}
	return strings.Join(parts, "; ")
}

// DefaultMaxSeries is the lines per metric when the query does not say.
const DefaultMaxSeries = 12

// SubjectSeries returns, for the query's Services, requests per second and
// the target 5xx ratio per Service on CloudWatch's minute grid (the step is
// rounded up to whole minutes). Beyond MaxSeries, Services fold into
// "others".
func (s *Source) SubjectSeries(ctx context.Context, q incidents.SeriesQuery) ([]incidents.Series, error) {
	want := map[string]bool{}
	for _, svc := range q.Services {
		want[svc] = true
	}
	var targets []target
	for _, t := range s.current([]string{q.Namespace}) {
		if want[t.svc] {
			targets = append(targets, t)
		}
	}
	if len(targets) == 0 {
		return nil, nil
	}
	if !q.To.After(q.From) {
		return nil, errors.New("alb metrics: empty time range")
	}
	periodSec := max(int((q.Step+time.Minute-1)/time.Minute), 1) * 60
	start := q.From.Truncate(time.Minute)
	end := q.To.Truncate(time.Minute)
	if !end.After(start) {
		end = start.Add(time.Minute)
	}
	got, err := s.fetch(ctx, targets, start, end, periodSec)
	if err != nil {
		return nil, err
	}
	type line struct {
		svc        string
		reqs, errs map[int64]float64
	}
	bySvc := map[string]*line{}
	var lines []*line
	for i, t := range targets {
		l := bySvc[t.svc]
		if l == nil {
			l = &line{svc: t.svc, reqs: map[int64]float64{}, errs: map[int64]float64{}}
			bySvc[t.svc] = l
			lines = append(lines, l)
		}
		for ts, v := range got[i].reqs {
			l.reqs[ts] += v
		}
		for ts, v := range got[i].errs {
			l.errs[ts] += v
		}
	}
	peak := func(m map[int64]float64) float64 {
		p := 0.0
		for _, v := range m {
			p = max(p, v)
		}
		return p
	}
	sort.SliceStable(lines, func(i, j int) bool {
		a, b := peak(lines[i].reqs), peak(lines[j].reqs)
		if a != b {
			return a > b
		}
		return lines[i].svc < lines[j].svc
	})
	n := q.MaxSeries
	if n <= 0 {
		n = DefaultMaxSeries
	}
	if len(lines) > n {
		others := &line{svc: "others", reqs: map[int64]float64{}, errs: map[int64]float64{}}
		for _, l := range lines[n:] {
			for ts, v := range l.reqs {
				others.reqs[ts] += v
			}
			for ts, v := range l.errs {
				others.errs[ts] += v
			}
		}
		lines = append(lines[:n:n], others)
	}
	ps := float64(periodSec)
	var out []incidents.Series
	for _, l := range lines {
		out = append(out, incidents.Series{Metric: "requests", Label: l.svc, Unit: "rps", Source: Name, Points: points(l.reqs, func(ts int64, v float64) (float64, bool) { return v / ps, true })})
	}
	for _, l := range lines {
		out = append(out, incidents.Series{Metric: "errors", Label: l.svc, Unit: "ratio", Source: Name, Points: points(l.reqs, func(ts int64, v float64) (float64, bool) {
			if v <= 0 {
				return 0, false
			}
			return l.errs[ts] / v, true
		})})
	}
	return out, nil
}

// points renders values by Unix second as sorted [unixMs, value] pairs.
func points(m map[int64]float64, f func(ts int64, v float64) (float64, bool)) [][2]float64 {
	ts := make([]int64, 0, len(m))
	for t := range m {
		ts = append(ts, t)
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i] < ts[j] })
	out := make([][2]float64, 0, len(ts))
	for _, t := range ts {
		if v, ok := f(t, m[t]); ok {
			out = append(out, [2]float64{float64(t * 1000), v})
		}
	}
	return out
}
