package prom

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/incidents"
	"github.com/ByronGary/kubesentry/internal/model"
)

func TestBuiltinRequestProfilesValidate(t *testing.T) {
	for _, n := range BuiltinRequestProfileNames() {
		p, _ := BuiltinRequestProfile(n)
		if err := p.Validate(); err != nil {
			t.Errorf("built-in %s: %v", n, err)
		}
	}
	if got := strings.Join(BuiltinRequestProfileNames(), ","); got != "app,nginx" {
		t.Errorf("built-ins = %s", got)
	}
	nginx, _ := BuiltinRequestProfile(ProfileNginx)
	if nginx.PodLevel() || nginx.NamespaceLabel != "exported_namespace" || nginx.NamespaceFallbackLabel != "namespace" {
		t.Errorf("nginx profile = %+v", nginx)
	}
	app, _ := BuiltinRequestProfile(ProfileApp)
	if !app.PodLevel() || app.StatusLabel != "code" {
		t.Errorf("app profile = %+v", app)
	}
}

func TestRequestProfileValidation(t *testing.T) {
	good := func() RequestProfile {
		return RequestProfile{Name: "grpc", Metric: "grpc_server_handled_total", NamespaceLabel: "namespace", PodLabel: "pod", StatusLabel: "grpc_code", ErrorRegex: "Internal|Unavailable"}
	}
	p := good()
	if err := p.Validate(); err != nil {
		t.Fatalf("good profile: %v", err)
	}
	p = good()
	p.ErrorRegex = ""
	if err := p.Validate(); err != nil || p.ErrorRegex != DefaultErrorRegex {
		t.Errorf("default error regex: %q, %v", p.ErrorRegex, err)
	}
	p = good()
	p.StatusLabel, p.ErrorRegex = "", ""
	if err := p.Validate(); err != nil {
		t.Errorf("no status label: %v", err)
	}
	p = good()
	p.NamespaceFallbackLabel = "namespace"
	if err := p.Validate(); err != nil || p.NamespaceFallbackLabel != "" {
		t.Errorf("fallback equal to the primary label should be dropped: %+v %v", p, err)
	}

	bad := map[string]func(*RequestProfile){
		"bad name":                 func(p *RequestProfile) { p.Name = "Bad_Name" },
		"empty name":               func(p *RequestProfile) { p.Name = "" },
		"reserved name":            func(p *RequestProfile) { p.Name = "alb" },
		"bad metric":               func(p *RequestProfile) { p.Metric = `up{x="1"}` },
		"both subjects":            func(p *RequestProfile) { p.ServiceLabel = "service" },
		"no subject":               func(p *RequestProfile) { p.PodLabel = "" },
		"no namespace label":       func(p *RequestProfile) { p.NamespaceLabel = "" },
		"reserved __ label":        func(p *RequestProfile) { p.NamespaceLabel = "__name__" },
		"injection in label":       func(p *RequestProfile) { p.PodLabel = `pod="x"}` },
		"output label ns":          func(p *RequestProfile) { p.PodLabel = "ns" },
		"output label err":         func(p *RequestProfile) { p.StatusLabel = "err" },
		"output label subj":        func(p *RequestProfile) { p.NamespaceFallbackLabel = "subj" },
		"bad regex":                func(p *RequestProfile) { p.ErrorRegex = "5(" },
		"regex without status":     func(p *RequestProfile) { p.StatusLabel = "" },
		"dash in fallback label":   func(p *RequestProfile) { p.NamespaceFallbackLabel = "k8s-namespace" },
		"digit-leading pod label":  func(p *RequestProfile) { p.PodLabel = "1pod" },
		"too long name (64 chars)": func(p *RequestProfile) { p.Name = strings.Repeat("a", 64) },
	}
	for name, mutate := range bad {
		p := good()
		mutate(&p)
		if err := p.Validate(); err == nil {
			t.Errorf("%s: accepted %+v", name, p)
		}
	}
}

func TestParseAndSelectRequestProfiles(t *testing.T) {
	arr := `[{"name":"grpc","metric":"grpc_server_handled_total","namespaceLabel":"namespace","podLabel":"pod","statusLabel":"grpc_code","errorRegex":"Internal|Unavailable"}]`
	ps, err := ParseRequestProfiles([]byte(arr))
	if err != nil || len(ps) != 1 || ps[0].Name != "grpc" {
		t.Fatalf("array: %+v %v", ps, err)
	}
	wrapped := `{"profiles":[{"name":"app","metric":"myapp_requests_total","namespaceLabel":"namespace","podLabel":"pod","statusLabel":"code"}]}`
	ws, err := ParseRequestProfiles([]byte("\n  " + wrapped))
	if err != nil || len(ws) != 1 || ws[0].ErrorRegex != DefaultErrorRegex {
		t.Fatalf("wrapped: %+v %v", ws, err)
	}
	for name, doc := range map[string]string{
		"unknown field": `[{"name":"x","metric":"m","namespaceLabel":"namespace","podLabel":"pod","query":"up"}]`,
		"duplicate":     `[{"name":"x","metric":"m","namespaceLabel":"namespace","podLabel":"pod"},{"name":"x","metric":"m","namespaceLabel":"namespace","podLabel":"pod"}]`,
		"invalid":       `[{"name":"x","metric":"m","namespaceLabel":"namespace"}]`,
		"not json":      `profiles: []`,
	} {
		if _, err := ParseRequestProfiles([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	path := filepath.Join(t.TempDir(), "profiles.json")
	if err := os.WriteFile(path, []byte(arr), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := LoadRequestProfiles(path); err != nil || len(got) != 1 {
		t.Fatalf("load: %+v %v", got, err)
	}
	if _, err := LoadRequestProfiles(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("missing file accepted")
	}

	// Built-ins by name, then every file profile; a file profile replaces the
	// built-in of the same name.
	sel, err := SelectRequestProfiles([]string{"nginx", " app ", "nginx", ""}, append(ws, ps...))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, p := range sel {
		names = append(names, p.Name+":"+p.Metric)
	}
	if got := strings.Join(names, ","); got != "nginx:nginx_ingress_controller_requests,app:myapp_requests_total,grpc:grpc_server_handled_total" {
		t.Errorf("selected = %s", got)
	}
	if _, err := SelectRequestProfiles([]string{"haproxy"}, nil); err == nil {
		t.Error("unknown source accepted")
	}
}

func newProfileSource(t *testing.T, c *Client, name string) *RequestSource {
	t.Helper()
	p, ok := BuiltinRequestProfile(name)
	if !ok {
		t.Fatalf("no built-in %s", name)
	}
	s, err := c.RequestSource(p)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The PromQL each profile sends, exactly. A change here changes what
// Prometheus is asked; check it against a real server before updating.
func TestRequestQueriesGolden(t *testing.T) {
	m, _ := ParseMatchers(`cluster="prod"`)
	c, _ := NewClient("http://prom:9090", Options{Selector: m})
	nginx := newProfileSource(t, c, ProfileNginx)
	app := newProfileSource(t, c, ProfileApp)
	series := NewSeriesSource(c, nginx, app)

	cases := []struct{ name, got, want string }{
		{"nginx all namespaces", nginx.rateQueries(5*time.Minute, 5*time.Minute, nil)[0],
			`sum by (ns, subj, err) (label_replace(label_replace(label_replace(label_replace(` +
				`rate(nginx_ingress_controller_requests{service!="",cluster="prod"}[5m] offset 5m), ` +
				`"ns", "$1", "namespace", "(.+)"), "ns", "$1", "exported_namespace", "(.+)"), ` +
				`"subj", "$1", "service", "(.+)"), "err", "1", "status", "5.."))`},
		{"nginx some namespaces", strings.Join(nginx.rateQueries(5*time.Minute, 0, []string{"web.prod", "shop", "Bad_NS"}), "\n"),
			`sum by (ns, subj, err) (label_replace(label_replace(label_replace(label_replace(` +
				`rate(nginx_ingress_controller_requests{exported_namespace=~"shop|web\\.prod",service!="",cluster="prod"}[5m]) or ` +
				`rate(nginx_ingress_controller_requests{exported_namespace="",namespace=~"shop|web\\.prod",service!="",cluster="prod"}[5m]), ` +
				`"ns", "$1", "namespace", "(.+)"), "ns", "$1", "exported_namespace", "(.+)"), ` +
				`"subj", "$1", "service", "(.+)"), "err", "1", "status", "5.."))`},
		{"app baseline", app.rateQueries(time.Hour, 5*time.Minute, nil)[0],
			`sum by (ns, subj, err) (label_replace(label_replace(label_replace(` +
				`rate(http_requests_total{pod!="",cluster="prod"}[1h] offset 5m), ` +
				`"ns", "$1", "namespace", "(.+)"), "subj", "$1", "pod", "(.+)"), "err", "1", "code", "5.."))`},
		{"app series", app.seriesQuery("shop", []string{"web-1", "web-0"}, time.Minute),
			`sum by (ns, subj, err) (label_replace(label_replace(label_replace(` +
				`rate(http_requests_total{namespace="shop",pod=~"web-0|web-1",cluster="prod"}[2m]), ` +
				`"ns", "$1", "namespace", "(.+)"), "subj", "$1", "pod", "(.+)"), "err", "1", "code", "5.."))`},
		{"nginx series", nginx.seriesQuery("shop", []string{"web"}, 15*time.Second),
			`sum by (ns, subj, err) (label_replace(label_replace(label_replace(label_replace(` +
				`rate(nginx_ingress_controller_requests{exported_namespace="shop",service="web",cluster="prod"}[1m]) or ` +
				`rate(nginx_ingress_controller_requests{exported_namespace="",namespace="shop",service="web",cluster="prod"}[1m]), ` +
				`"ns", "$1", "namespace", "(.+)"), "ns", "$1", "exported_namespace", "(.+)"), ` +
				`"subj", "$1", "service", "(.+)"), "err", "1", "status", "5.."))`},
		{"probe", nginx.probeQuery(), `count(nginx_ingress_controller_requests{cluster="prod"})`},
		{"memory series", series.memoryQuery("shop", []string{"web-0", "web-1"}),
			`max by (namespace, pod, container) (container_memory_working_set_bytes{namespace="shop",pod=~"web-0|web-1",container!="",container!="POD",cluster="prod"})`},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s:\n got %s\nwant %s", tc.name, tc.got, tc.want)
		}
	}

	// Without a status label there is no error flag.
	p := RequestProfile{Name: "plain", Metric: "requests_total", NamespaceLabel: "namespace", ServiceLabel: "service"}
	plain, err := c.RequestSource(p)
	if err != nil {
		t.Fatal(err)
	}
	want := `sum by (ns, subj) (label_replace(label_replace(rate(requests_total{service!="",cluster="prod"}[5m]), "ns", "$1", "namespace", "(.+)"), "subj", "$1", "service", "(.+)"))`
	if got := plain.rateQueries(0, 0, nil)[0]; got != want {
		t.Errorf("plain:\n got %s\nwant %s", got, want)
	}
}

// selectorProm is an httptest Prometheus that records every query and checks
// that every series selector in it carries the extra selector.
type selectorProm struct {
	t        *testing.T
	selector string
	answer   func(path, query string) string
	mu       sync.Mutex
	queries  []string
}

var selectorRE = regexp.MustCompile(`[a-zA-Z_:][a-zA-Z0-9_:]*\{[^{}]*\}`)

func (f *selectorProm) handler(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	q := r.PostForm.Get("query")
	f.mu.Lock()
	f.queries = append(f.queries, q)
	f.mu.Unlock()
	sels := selectorRE.FindAllString(q, -1)
	if len(sels) == 0 {
		f.t.Errorf("query without a series selector: %s", q)
	}
	for _, s := range sels {
		if !strings.Contains(s, f.selector) {
			f.t.Errorf("selector %s lacks %s in query %s", s, f.selector, q)
		}
	}
	if len(q) > maxNamespaceQuery {
		f.t.Errorf("query of %d bytes", len(q))
	}
	body := ""
	if f.answer != nil {
		body = f.answer(r.URL.Path, q)
	}
	if body == "" {
		kind := "vector"
		if r.URL.Path == "/api/v1/query_range" {
			kind = "matrix"
		}
		body = `{"status":"success","data":{"resultType":"` + kind + `","result":[]}}`
	}
	w.Write([]byte(body))
}

func (f *selectorProm) all() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.queries...)
}

func newSelectorProm(t *testing.T, answer func(path, query string) string) (*selectorProm, *Client) {
	t.Helper()
	f := &selectorProm{t: t, selector: `cluster="prod",env=~"p.*"`, answer: answer}
	srv := httptest.NewServer(http.HandlerFunc(f.handler))
	t.Cleanup(srv.Close)
	m, err := ParseMatchers(f.selector)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewClient(srv.URL, Options{Selector: m})
	if err != nil {
		t.Fatal(err)
	}
	return f, c
}

func vector(results ...string) string {
	return `{"status":"success","data":{"resultType":"vector","result":[` + strings.Join(results, ",") + `]}}`
}

func matrix(results ...string) string {
	return `{"status":"success","data":{"resultType":"matrix","result":[` + strings.Join(results, ",") + `]}}`
}

// Every query the incident sources send carries -prometheus-selector, in
// every selector of the query, and restricted queries name only valid
// namespaces.
func TestEveryIncidentQueryCarriesSelector(t *testing.T) {
	f, c := newSelectorProm(t, nil)
	ctx := context.Background()
	now := time.Now()
	var sources []*RequestSource
	for _, n := range BuiltinRequestProfileNames() {
		sources = append(sources, newProfileSource(t, c, n))
	}
	var nss []string
	for i := 0; i < 400; i++ {
		nss = append(nss, fmt.Sprintf("team-%03d.payments-production-eu-west-1", i))
	}
	nss = append(nss, "Bad_Namespace", `x"}or{y`)
	for _, s := range sources {
		if _, err := s.Rates(ctx, now, 5*time.Minute, 0, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Rates(ctx, now, time.Hour, 5*time.Minute, nss); err != nil {
			t.Fatal(err)
		}
		if got := s.Probe(ctx); got != ProbeAbsent {
			t.Errorf("probe of an empty Prometheus = %q", got)
		}
	}
	if _, err := c.MemoryUsage(ctx, now, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.MemoryUsage(ctx, now, nss); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSeriesSource(c, sources...).SubjectSeries(ctx, incidents.SeriesQuery{
		Namespace: "shop", Pods: []string{"web-0", "web-1"}, Services: []string{"web"},
		From: now.Add(-time.Hour), To: now,
	}); err != nil {
		t.Fatal(err)
	}

	qs := f.all()
	if len(qs) < 12 {
		t.Fatalf("only %d queries", len(qs))
	}
	seen := map[string]int{}
	for _, q := range qs {
		if strings.Contains(q, "Bad_Namespace") || strings.Contains(q, "or{y") {
			t.Errorf("invalid namespace reached PromQL: %.200s", q)
		}
		for _, ns := range nss[:400] {
			if strings.Contains(q, strings.ReplaceAll(regexp.QuoteMeta(ns), `\`, `\\`)) {
				seen[ns]++
			}
		}
	}
	// Restricted: nginx, app and memory each name every namespace once.
	for _, ns := range nss[:400] {
		if seen[ns] != 3 {
			t.Errorf("%s named in %d queries, want 3", ns, seen[ns])
			break
		}
	}

	// An empty, non-nil namespace list sends nothing.
	before := len(f.all())
	for _, s := range sources {
		if got, err := s.Rates(ctx, now, time.Hour, 0, []string{}); err != nil || len(got) != 0 {
			t.Errorf("no namespaces: %v %v", got, err)
		}
	}
	if got, err := c.MemoryUsage(ctx, now, []string{}); err != nil || len(got) != 0 {
		t.Errorf("no namespaces: %v %v", got, err)
	}
	if after := len(f.all()); after != before {
		t.Errorf("an empty namespace list sent %d queries", after-before)
	}
}

func TestRatesFoldStatusesIntoErrorRatio(t *testing.T) {
	_, c := newSelectorProm(t, func(path, q string) string {
		switch {
		case strings.Contains(q, "nginx_ingress_controller_requests"):
			return vector(
				`{"metric":{"ns":"shop","subj":"web","err":"1"},"value":[1760000000,"2"]}`,
				`{"metric":{"ns":"shop","subj":"web"},"value":[1760000000,"18"]}`,
				`{"metric":{"ns":"shop","subj":"api"},"value":[1760000000,"5"]}`,
				`{"metric":{"ns":"shop","subj":"idle","err":"1"},"value":[1760000000,"0"]}`,
				`{"metric":{"ns":"Bad_NS","subj":"x"},"value":[1760000000,"1"]}`,
				`{"metric":{"ns":"shop"},"value":[1760000000,"1"]}`,
				`{"metric":{"ns":"shop","subj":"nan"},"value":[1760000000,"NaN"]}`,
			)
		case strings.Contains(q, "http_requests_total"):
			return vector(`{"metric":{"ns":"shop","subj":"web-0"},"value":[1760000000,"4"]}`)
		case strings.Contains(q, "requests_total"):
			return vector(`{"metric":{"ns":"shop","subj":"web"},"value":[1760000000,"7"]}`)
		}
		return ""
	})
	ctx := context.Background()
	got, err := newProfileSource(t, c, ProfileNginx).Rates(ctx, time.Now(), 5*time.Minute, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []model.RateSample{
		{Source: "nginx", Namespace: "shop", Service: "api", PerSecond: 5, ErrorRatio: 0},
		{Source: "nginx", Namespace: "shop", Service: "idle", PerSecond: 0, ErrorRatio: 0},
		{Source: "nginx", Namespace: "shop", Service: "web", PerSecond: 20, ErrorRatio: 0.1},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("nginx rates:\n got %+v\nwant %+v", got, want)
	}

	got, err = newProfileSource(t, c, ProfileApp).Rates(ctx, time.Now(), 5*time.Minute, 0, []string{"shop"})
	if err != nil || len(got) != 1 || got[0].Pod != "web-0" || got[0].Service != "" || got[0].ErrorRatio != 0 || got[0].Source != "app" {
		t.Errorf("app rates: %+v %v", got, err)
	}

	plain, _ := c.RequestSource(RequestProfile{Name: "plain", Metric: "requests_total", NamespaceLabel: "namespace", ServiceLabel: "service"})
	got, err = plain.Rates(ctx, time.Now(), 5*time.Minute, 0, nil)
	if err != nil || len(got) != 1 || got[0].ErrorRatio != -1 || got[0].PerSecond != 7 {
		t.Errorf("no status label: want error ratio -1, got %+v %v", got, err)
	}
}

func TestProbeAndMemoryUsage(t *testing.T) {
	fail := false
	_, c := newSelectorProm(t, func(path, q string) string {
		switch {
		case fail:
			return `{"status":"error","errorType":"execution","error":"boom"}`
		case strings.HasPrefix(q, "count(nginx"):
			return vector(`{"metric":{},"value":[1760000000,"3"]}`)
		case strings.Contains(q, memMetric):
			return vector(
				`{"metric":{"namespace":"shop","pod":"web-0","container":"app"},"value":[1760000000,"104857600"]}`,
				`{"metric":{"namespace":"shop","pod":"web-0","container":"Bad_Name"},"value":[1760000000,"1"]}`,
			)
		}
		return ""
	})
	ctx := context.Background()
	if got := newProfileSource(t, c, ProfileNginx).Probe(ctx); got != ProbeOK {
		t.Errorf("probe = %q", got)
	}
	if got := newProfileSource(t, c, ProfileApp).Probe(ctx); got != ProbeAbsent {
		t.Errorf("probe without the metric = %q", got)
	}
	mem, err := c.MemoryUsage(ctx, time.Now(), nil)
	want := []model.MemorySample{{Namespace: "shop", Pod: "web-0", Container: "app", Bytes: 104857600}}
	if err != nil || fmt.Sprint(mem) != fmt.Sprint(want) {
		t.Errorf("memory = %+v %v", mem, err)
	}
	fail = true
	if got := newProfileSource(t, c, ProfileApp).Probe(ctx); !strings.HasPrefix(got, "error: ") || !strings.Contains(got, "boom") {
		t.Errorf("failing probe = %q", got)
	}
}

func TestSubjectSeriesKeepsTopAndFoldsOthers(t *testing.T) {
	const t0 = 1760000000
	pts := func(vals ...float64) string {
		var ps []string
		for i, v := range vals {
			ps = append(ps, fmt.Sprintf(`[%d,"%g"]`, t0+60*i, v))
		}
		return "[" + strings.Join(ps, ",") + "]"
	}
	var memoryFails bool
	_, c := newSelectorProm(t, func(path, q string) string {
		if path != "/api/v1/query_range" {
			return ""
		}
		switch {
		case strings.Contains(q, memMetric):
			if memoryFails {
				return `{"status":"error","errorType":"timeout","error":"too slow"}`
			}
			return matrix(
				`{"metric":{"namespace":"shop","pod":"web-0","container":"app"},"values":`+pts(100, 400, 200)+`}`,
				`{"metric":{"namespace":"shop","pod":"web-1","container":"app"},"values":`+pts(300, 300, 300)+`}`,
				`{"metric":{"namespace":"shop","pod":"web-0","container":"proxy"},"values":`+pts(10, 20, 30)+`}`,
				`{"metric":{"namespace":"shop","pod":"web-1","container":"proxy"},"values":`+pts(5, 5, 5)+`}`,
				`{"metric":{"namespace":"other","pod":"web-1","container":"proxy"},"values":`+pts(9, 9, 9)+`}`,
			)
		case strings.Contains(q, "http_requests_total"):
			return matrix(
				`{"metric":{"ns":"shop","subj":"web-0"},"values":`+pts(10, 10, 10)+`}`,
				`{"metric":{"ns":"shop","subj":"web-0","err":"1"},"values":`+pts(0, 5, 10)+`}`,
				`{"metric":{"ns":"shop","subj":"web-1"},"values":`+pts(30, 30, 0)+`}`,
				`{"metric":{"ns":"shop","subj":"web-1","err":"1"},"values":`+pts(0, 0, 0)+`}`,
				`{"metric":{"ns":"shop","subj":"web-2"},"values":`+pts(1, 1, 1)+`}`,
				`{"metric":{"ns":"shop","subj":"web-2","err":"1"},"values":`+pts(1, 1, 1)+`}`,
			)
		}
		return ""
	})
	app := newProfileSource(t, c, ProfileApp)
	nginx := newProfileSource(t, c, ProfileNginx)
	src := NewSeriesSource(c, app, nginx)
	q := incidents.SeriesQuery{
		Namespace: "shop", Pods: []string{"web-0", "web-1", "web-2"},
		From: time.Unix(t0, 0), To: time.Unix(t0+120, 0), Step: time.Minute, MaxSeries: 2,
	}
	got, err := src.SubjectSeries(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, s := range got {
		var vals []string
		for _, p := range s.Points {
			vals = append(vals, fmt.Sprintf("%g", math.Round(p[1]*1000)/1000))
		}
		lines = append(lines, fmt.Sprintf("%s %s %s %s %s", s.Metric, s.Source, s.Unit, s.Label, strings.Join(vals, ",")))
	}
	want := []string{
		"memory prometheus bytes web-0/app 100,400,200",
		"memory prometheus bytes web-1/app 300,300,300",
		"memory prometheus bytes others 15,25,35",
		"requests app rps web-1 30,30,0",
		"requests app rps web-0 10,15,20",
		"requests app rps others 2,2,2",
		"errors app ratio web-0 0,0.333,0.5",
		"errors app ratio web-2 0.5,0.5,0.5",
		"errors app ratio others 0,0",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Errorf("series:\n%s\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
	if got[0].Points[0][0] != float64(t0)*1000 {
		t.Errorf("timestamps are not Unix milliseconds: %v", got[0].Points[0])
	}

	// A failing query costs only its own series.
	memoryFails = true
	got, err = src.SubjectSeries(context.Background(), q)
	if err == nil || !strings.Contains(err.Error(), "memory series") {
		t.Errorf("want the memory failure reported, got %v", err)
	}
	if len(got) != 6 || got[0].Metric != "requests" {
		t.Errorf("want the request series despite the failure, got %d", len(got))
	}

	if _, err := src.SubjectSeries(context.Background(), incidents.SeriesQuery{Namespace: `x"}`, From: q.From, To: q.To}); err == nil {
		t.Error("invalid namespace accepted")
	}
	if _, err := src.SubjectSeries(context.Background(), incidents.SeriesQuery{Namespace: "shop", From: q.To, To: q.From}); err == nil {
		t.Error("empty range accepted")
	}
}
