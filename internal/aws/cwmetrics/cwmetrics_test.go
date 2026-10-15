package cwmetrics

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/credentials"

	"github.com/ByronGary/kubesentry/internal/incidents"
	"github.com/ByronGary/kubesentry/internal/model"
)

var at = time.Date(2026, 10, 15, 10, 7, 30, 0, time.UTC)

const (
	tgWebA = "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/k8s-shop-weba-1a2b3c4d5e/0123456789abcdef"
	tgWebB = "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/k8s-shop-webb-1a2b3c4d5e/1123456789abcdef"
	tgAPI  = "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/k8s-shop-api-9f8e7d6c5b/2123456789abcdef"
	tgPay  = "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/k8s-pay-api-9f8e7d6c5b/3123456789abcdef"
)

// fakeCW is an httptest CloudWatch GetMetricData endpoint.
type fakeCW struct {
	t      *testing.T
	mu     sync.Mutex
	bodies []getMetricDataInput
	// answer returns the status, extra headers and body for request n (0-based).
	answer func(n int, in getMetricDataInput) (int, map[string]string, string)
}

func (f *fakeCW) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/" {
		f.t.Errorf("%s %s", r.Method, r.URL.Path)
	}
	if got := r.Header.Get("Content-Type"); got != "application/x-amz-json-1.0" {
		f.t.Errorf("Content-Type = %q", got)
	}
	if got := r.Header.Get("X-Amz-Target"); got != "GraniteServiceVersion20100801.GetMetricData" {
		f.t.Errorf("X-Amz-Target = %q", got)
	}
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=AKIDTEST/20261015/us-east-1/monitoring/aws4_request, SignedHeaders=") {
		f.t.Errorf("Authorization = %q", auth)
	}
	if !strings.Contains(auth, "x-amz-target") || !strings.Contains(auth, "content-type") || r.Header.Get("X-Amz-Date") == "" {
		f.t.Errorf("target and content type must be signed: %q", auth)
	}
	b, _ := io.ReadAll(r.Body)
	var in getMetricDataInput
	if err := json.Unmarshal(b, &in); err != nil {
		f.t.Errorf("body %s: %v", b, err)
	}
	f.mu.Lock()
	n := len(f.bodies)
	f.bodies = append(f.bodies, in)
	f.mu.Unlock()
	status, hdr, body := http.StatusOK, map[string]string(nil), `{"MetricDataResults":[],"Messages":[]}`
	if f.answer != nil {
		status, hdr, body = f.answer(n, in)
	}
	for k, v := range hdr {
		w.Header().Set(k, v)
	}
	w.Header().Set("Content-Type", "application/x-amz-json-1.0")
	w.WriteHeader(status)
	w.Write([]byte(body))
}

func (f *fakeCW) requests() []getMetricDataInput {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]getMetricDataInput(nil), f.bodies...)
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type harness struct {
	f       *fakeCW
	clk     *clock
	src     *Source
	targets []Target
	sleeps  []time.Duration
	throttl int
}

func newHarness(t *testing.T, answer func(n int, in getMetricDataInput) (int, map[string]string, string)) *harness {
	t.Helper()
	h := &harness{f: &fakeCW{t: t, answer: answer}, clk: &clock{t: at}}
	srv := httptest.NewServer(h.f)
	t.Cleanup(srv.Close)
	h.targets = []Target{
		{TargetGroupARN: tgWebA, Namespace: "shop", Service: "web"},
		{TargetGroupARN: tgWebB, Namespace: "shop", Service: "web"},
		{TargetGroupARN: tgAPI, Namespace: "shop", Service: "api"},
		{TargetGroupARN: tgPay, Namespace: "pay", Service: "api"},
		{TargetGroupARN: "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/x/0123456789abcdef", Namespace: "shop", Service: "lb"},
		{TargetGroupARN: tgAPI, Namespace: "Bad_NS", Service: "api"},
	}
	src, err := New(context.Background(), Options{
		Region: "us-east-1", Endpoint: srv.URL,
		Credentials: credentials.NewStaticCredentialsProvider("AKIDTEST", "secret", ""),
		Targets:     func() []Target { return h.targets },
		Now:         h.clk.Now,
		Sleep: func(ctx context.Context, d time.Duration) bool {
			h.sleeps = append(h.sleeps, d)
			return true
		},
		OnThrottle: func() { h.throttl++ },
	})
	if err != nil {
		t.Fatal(err)
	}
	h.src = src
	return h
}

// result renders one MetricDataResult with points every minute from start.
func result(id string, start time.Time, vals ...float64) string {
	var ts []string
	var vs []string
	for i, v := range vals {
		ts = append(ts, fmt.Sprint(start.Add(time.Duration(i)*time.Minute).Unix()))
		vs = append(vs, fmt.Sprint(v))
	}
	return fmt.Sprintf(`{"Id":%q,"Label":"x","StatusCode":"Complete","Timestamps":[%s],"Values":[%s]}`, id, strings.Join(ts, ","), strings.Join(vs, ","))
}

func TestDimension(t *testing.T) {
	for arn, want := range map[string]string{
		tgWebA: "targetgroup/k8s-shop-weba-1a2b3c4d5e/0123456789abcdef",
		"arn:aws-cn:elasticloadbalancing:cn-north-1:123456789012:targetgroup/tg/0123456789abcdef": "targetgroup/tg/0123456789abcdef",
		"arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg\"x/0123456789abcdef":  "",
		"arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg/0123456789ABCDEF":     "",
		"targetgroup/tg/0123456789abcdef": "",
	} {
		got, ok := Dimension(arn)
		if got != want || ok != (want != "") {
			t.Errorf("Dimension(%s) = %q, %v", arn, got, ok)
		}
	}
	got := TargetsFrom([]model.TargetGroupBinding{{Namespace: "shop", Name: "web-tgb", TargetGroupARN: tgWebA, ServiceName: "web", ServicePort: "80"}})
	if len(got) != 1 || got[0] != (Target{TargetGroupARN: tgWebA, Namespace: "shop", Service: "web"}) {
		t.Errorf("TargetsFrom = %+v", got)
	}
}

func TestRatesQueryParsingAndCache(t *testing.T) {
	start := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC) // at − 2m lag, truncated, − 5m
	h := newHarness(t, func(n int, in getMetricDataInput) (int, map[string]string, string) {
		return 200, nil, `{"MetricDataResults":[` + strings.Join([]string{
			result("r0", start, 60, 120, 0, 60, 60), // pay/api
			result("e0", start, 0, 0, 0, 0, 0),
			result("r1", start, 30, 30, 30, 30, 30), // shop/api
			result("e1", start),
			result("r2", start, 100, 100, 100, 100, 100), // shop/web, two target groups
			result("e2", start, 10, 10, 0, 0, 0),
			result("r3", start, 50, 50, 50, 50, 50),
			result("e3", start, 0, 0, 5, 5, 0),
		}, ",") + `],"Messages":[]}`
	})
	got, err := h.src.Rates(context.Background(), at, 5*time.Minute, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []model.RateSample{
		{Source: "alb", Namespace: "pay", Service: "api", PerSecond: 1, ErrorRatio: 0},
		{Source: "alb", Namespace: "shop", Service: "api", PerSecond: 0.5, ErrorRatio: 0},
		{Source: "alb", Namespace: "shop", Service: "web", PerSecond: 2.5, ErrorRatio: 30.0 / 750},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("rates:\n got %+v\nwant %+v", got, want)
	}

	reqs := h.f.requests()
	if len(reqs) != 1 {
		t.Fatalf("%d requests", len(reqs))
	}
	in := reqs[0]
	if in.StartTime.Time() != start || in.EndTime.Time() != start.Add(5*time.Minute) || in.ScanBy != "TimestampAscending" {
		t.Errorf("window %v..%v scan %s", in.StartTime.Time(), in.EndTime.Time(), in.ScanBy)
	}
	if len(in.MetricDataQueries) != 8 {
		t.Fatalf("%d queries, want 2 per valid target group", len(in.MetricDataQueries))
	}
	q := in.MetricDataQueries[0]
	wantExpr := `SUM(SEARCH('{AWS/ApplicationELB,LoadBalancer,TargetGroup} MetricName="RequestCount" TargetGroup="targetgroup/k8s-pay-api-9f8e7d6c5b/3123456789abcdef"', 'Sum', 60))`
	if q.ID != "r0" || q.Expression != wantExpr || q.Period != 60 || !q.ReturnData {
		t.Errorf("first query = %+v\nwant expression %s", q, wantExpr)
	}
	if e := in.MetricDataQueries[1].Expression; !strings.Contains(e, `MetricName="HTTPCode_Target_5XX_Count"`) || in.MetricDataQueries[1].ID != "e0" {
		t.Errorf("second query = %+v", in.MetricDataQueries[1])
	}

	// Cached for a minute, per window and target set.
	h.clk.Advance(30 * time.Second)
	if _, err := h.src.Rates(context.Background(), at, 5*time.Minute, 0, nil); err != nil || len(h.f.requests()) != 1 {
		t.Errorf("not served from the cache: %d requests, %v", len(h.f.requests()), err)
	}
	if _, err := h.src.Rates(context.Background(), at, time.Hour, 5*time.Minute, nil); err != nil || len(h.f.requests()) != 2 {
		t.Errorf("baseline window shared the recent window's entry: %d requests", len(h.f.requests()))
	}
	if b := h.f.requests()[1]; b.EndTime.Time() != time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC) || b.StartTime.Time() != time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC) {
		t.Errorf("baseline window %v..%v", b.StartTime.Time(), b.EndTime.Time())
	}
	h.clk.Advance(31 * time.Second)
	if _, err := h.src.Rates(context.Background(), at, 5*time.Minute, 0, nil); err != nil || len(h.f.requests()) != 3 {
		t.Errorf("expired entry reused: %d requests", len(h.f.requests()))
	}

	// Namespaces restrict the target groups asked for.
	got, _ = h.src.Rates(context.Background(), at, 5*time.Minute, 0, []string{"pay"})
	if last := h.f.requests()[len(h.f.requests())-1]; len(last.MetricDataQueries) != 2 || len(got) != 1 || got[0].Namespace != "pay" {
		t.Errorf("restricted: %d queries, %+v", len(last.MetricDataQueries), got)
	}
	if got, err := h.src.Rates(context.Background(), at, 5*time.Minute, 0, []string{}); err != nil || got != nil {
		t.Errorf("no namespaces: %v %v", got, err)
	}
}

func TestPaginationThrottlingAndErrors(t *testing.T) {
	start := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	h := newHarness(t, func(n int, in getMetricDataInput) (int, map[string]string, string) {
		switch n {
		case 0:
			return 400, map[string]string{"x-amzn-query-error": "Throttling;Sender"},
				`{"__type":"com.amazonaws.cloudwatch#ThrottlingException","message":"Rate exceeded"}`
		case 1:
			if in.NextToken != "" {
				t.Errorf("first page with a token")
			}
			return 200, nil, `{"MetricDataResults":[` + result("r0", start, 60, 60) + `],"NextToken":"page2"}`
		case 2:
			if in.NextToken != "page2" {
				t.Errorf("second page token = %q", in.NextToken)
			}
			return 200, nil, `{"MetricDataResults":[` + result("r0", start.Add(2*time.Minute), 60, 60, 60) + `]}`
		case 3:
			return 400, nil, `{"__type":"AccessDeniedException","Message":"User is not authorized to perform: cloudwatch:GetMetricData"}`
		default:
			return 200, nil, `{"MetricDataResults":[{"Id":"r0","StatusCode":"Forbidden","Messages":[{"Code":"Forbidden","Value":"cross-account"}]}]}`
		}
	})
	h.targets = h.targets[3:4] // pay/api
	got, err := h.src.Rates(context.Background(), at, 5*time.Minute, 0, nil)
	if err != nil || len(got) != 1 || got[0].PerSecond != 1 {
		t.Fatalf("paged rates: %+v %v", got, err)
	}
	if h.throttl != 1 || len(h.sleeps) != 1 || h.sleeps[0] != time.Second {
		t.Errorf("throttled %d, sleeps %v", h.throttl, h.sleeps)
	}
	h.clk.Advance(2 * time.Minute)
	if _, err := h.src.Rates(context.Background(), at, 5*time.Minute, 0, nil); err == nil || !strings.Contains(err.Error(), "AccessDeniedException") || !strings.Contains(err.Error(), "not authorized") {
		t.Errorf("denied: %v", err)
	}
	if got := h.src.Probe(context.Background()); !strings.HasPrefix(got, "error: ") || !strings.Contains(got, "Forbidden") {
		t.Errorf("probe of a forbidden metric = %q", got)
	}
}

func TestBatchesOf50TargetGroups(t *testing.T) {
	h := newHarness(t, nil)
	h.targets = nil
	for i := 0; i < 120; i++ {
		h.targets = append(h.targets, Target{
			TargetGroupARN: fmt.Sprintf("arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/tg-%d/%016x", i, i),
			Namespace:      "shop", Service: fmt.Sprintf("svc-%03d", i),
		})
	}
	got, err := h.src.Rates(context.Background(), at, 5*time.Minute, 0, nil)
	if err != nil || len(got) != 120 {
		t.Fatalf("%d samples, %v", len(got), err)
	}
	var sizes []int
	for _, r := range h.f.requests() {
		sizes = append(sizes, len(r.MetricDataQueries))
	}
	if fmt.Sprint(sizes) != "[100 100 40]" {
		t.Errorf("queries per call = %v", sizes)
	}
	for _, s := range got {
		if s.PerSecond != 0 || s.ErrorRatio != 0 {
			t.Errorf("no data should read as no traffic: %+v", s)
			break
		}
	}
	if got := h.src.Probe(context.Background()); got != "absent" {
		t.Errorf("probe without requests = %q", got)
	}
	h.targets = nil
	if got := h.src.Probe(context.Background()); got != "absent" {
		t.Errorf("probe without target groups = %q", got)
	}
}

func TestSubjectSeriesPerService(t *testing.T) {
	from := time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)
	h := newHarness(t, func(n int, in getMetricDataInput) (int, map[string]string, string) {
		if in.StartTime.Time() != from || in.EndTime.Time() != from.Add(time.Hour) {
			t.Errorf("window %v..%v", in.StartTime.Time(), in.EndTime.Time())
		}
		if !strings.Contains(in.MetricDataQueries[0].Expression, `'Sum', 120))`) || in.MetricDataQueries[0].Period != 120 {
			t.Errorf("period not rounded up to 2 minutes: %+v", in.MetricDataQueries[0])
		}
		// shop/api is r0, shop/web's target groups r1 and r2.
		return 200, nil, `{"MetricDataResults":[` + strings.Join([]string{
			result("r0", from, 240, 240),
			result("e0", from, 0, 24),
			result("r1", from, 120, 0),
			result("e1", from, 12, 0),
			result("r2", from, 120, 0),
			result("e2", from),
		}, ",") + `]}`
	})
	got, err := h.src.SubjectSeries(context.Background(), incidents.SeriesQuery{
		Namespace: "shop", Services: []string{"web", "api", "lb"}, From: from.Add(30 * time.Second), To: from.Add(time.Hour), Step: 90 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, s := range got {
		var pts []string
		for _, p := range s.Points {
			pts = append(pts, fmt.Sprintf("%s=%g", time.UnixMilli(int64(p[0])).UTC().Format("15:04"), math.Round(p[1]*1000)/1000))
		}
		lines = append(lines, fmt.Sprintf("%s %s %s %s %s", s.Metric, s.Source, s.Unit, s.Label, strings.Join(pts, ",")))
	}
	want := []string{
		"requests alb rps api 09:00=2,09:01=2",
		"requests alb rps web 09:00=2,09:01=0",
		"errors alb ratio api 09:00=0,09:01=0.1",
		"errors alb ratio web 09:00=0.05",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Errorf("series:\n%s\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
	if got, err := h.src.SubjectSeries(context.Background(), incidents.SeriesQuery{Namespace: "shop", Services: []string{"nope"}, From: from, To: from.Add(time.Hour)}); err != nil || got != nil {
		t.Errorf("no target groups: %v %v", got, err)
	}
}
