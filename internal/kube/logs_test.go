package kube

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/ByronGary/kubesentry/internal/incidents"
)

var logBase = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

// at is a GetLogs timestamp prefix, sec seconds after logBase.
func at(sec float64) string {
	return logBase.Add(time.Duration(sec * float64(time.Second))).Format(time.RFC3339Nano)
}

func TestParseLogLine(t *testing.T) {
	ts, text, ok := parseLogLine("2026-10-15T12:00:01.123456789Z GET /healthz 200")
	if !ok || text != "GET /healthz 200" || !ts.Equal(logBase.Add(time.Second+123456789)) {
		t.Errorf("parsed %v %q %v", ts, text, ok)
	}
	if ts, text, ok := parseLogLine("2026-10-15T12:00:01Z"); !ok || text != "" || !ts.Equal(logBase.Add(time.Second)) {
		t.Errorf("timestamp only: %v %q %v", ts, text, ok)
	}
	if _, text, ok := parseLogLine("\tat com.example.Main(Main.java:42)"); ok || text != "\tat com.example.Main(Main.java:42)" {
		t.Errorf("no timestamp: %q %v", text, ok)
	}
}

func TestDetectLevel(t *testing.T) {
	for _, c := range []struct{ line, want string }{
		{`{"level":"error","msg":"db down"}`, "error"},
		{`{"level":"WARNING","msg":"slow"}`, "warn"},
		{`{"level":"debug","msg":"ERROR in text does not win"}`, "debug"},
		{`{"level":50,"msg":"pino error"}`, "error"},
		{`{"level":40}`, "warn"},
		{`{"level":30}`, "info"},
		{`{"level":20}`, "debug"},
		{`{"severity":"CRITICAL","message":"x"}`, "error"},
		{`{"lvl":"info"}`, "info"},
		{`{"msg":"FATAL boom"}`, "error"}, // no level field: the words decide
		{`{"level":"error"`, "info"},      // not JSON, and the word is lower case
		{`ts=2026-10-15T12:00:00Z level=warn msg="disk 91%"`, "warn"},
		{`time="..." level=error msg="x"`, "error"},
		{`level="info" msg=x`, "info"},
		{`E1015 12:00:00.000000       1 controller.go:42] sync failed`, "error"},
		{`W1015 12:00:00.000000       1 reflector.go:1] watch closed`, "warn"},
		{`I1015 12:00:00.000000       1 main.go:1] started; ERROR words do not matter`, "info"},
		{`F1015 12:00:00.000000       1 main.go:1] fatal`, "error"},
		{`2026/10/15 ERROR connection refused`, "error"},
		{`[WARN] retrying`, "warn"},
		{`WARNING: deprecated flag`, "warn"},
		{`panic: runtime error: index out of range`, "info"}, // lowercase is not a level word
		{`PANIC in handler`, "error"},
		{`ERRORS=0 WARNINGS=0`, "info"},
		{`GET /healthz 200`, "info"},
		{``, "info"},
	} {
		if got := detectLevel(c.line); got != c.want {
			t.Errorf("detectLevel(%q) = %q, want %q", c.line, got, c.want)
		}
	}
}

func lineTexts(ls []incidents.LogLine) string {
	var out []string
	for _, l := range ls {
		out = append(out, l.Text)
	}
	return strings.Join(out, "|")
}

func mkLine(t time.Time, level, text string) incidents.LogLine {
	return incidents.LogLine{Time: t, Level: level, Text: text}
}

func TestReadLogStream(t *testing.T) {
	body := strings.Join([]string{
		at(0) + " before the window",
		at(10) + " start",
		at(11) + " ERROR first failure",
		"\tcontinuation without a timestamp",
		at(12) + ` {"level":"warn","msg":"slow"}`,
		at(13) + " ok",
		at(60) + " after the window",
		at(61) + " never read",
	}, "\n") + "\n"
	f := logFilter{from: logBase.Add(10 * time.Second), to: logBase.Add(30 * time.Second)}

	lines, truncated, err := readLogStream(strings.NewReader(body), f, 0, 100, 1<<20, mkLine)
	if err != nil || truncated {
		t.Fatalf("read: %v truncated %v", err, truncated)
	}
	if got := lineTexts(lines); got != `start|ERROR first failure|	continuation without a timestamp|{"level":"warn","msg":"slow"}|ok` {
		t.Errorf("lines: %s", got)
	}
	if !lines[2].Time.Equal(lines[1].Time) || lines[1].Level != "error" || lines[3].Level != "warn" || lines[4].Level != "info" {
		t.Errorf("times and levels: %+v", lines)
	}

	// Level is a minimum; text is a case-insensitive substring.
	f.minRank = levelRank("warn")
	lines, _, _ = readLogStream(strings.NewReader(body), f, 0, 100, 1<<20, mkLine)
	if got := lineTexts(lines); got != `ERROR first failure|{"level":"warn","msg":"slow"}` {
		t.Errorf("warn and worse: %s", got)
	}
	f.minRank, f.text = 0, "failure"
	lines, _, _ = readLogStream(strings.NewReader(body), f, 0, 100, 1<<20, mkLine)
	if got := lineTexts(lines); got != "ERROR first failure" {
		t.Errorf("text filter: %s", got)
	}

	// Caps: a stream stops once it holds as many lines (or bytes) as the
	// query can return.
	f.text = ""
	lines, truncated, _ = readLogStream(strings.NewReader(body), f, 0, 2, 1<<20, mkLine)
	if len(lines) != 2 || !truncated {
		t.Errorf("line cap: %d lines, truncated %v", len(lines), truncated)
	}
	lines, truncated, _ = readLogStream(strings.NewReader(body), f, 0, 100, 10, mkLine)
	if got := lineTexts(lines); got != "start" || !truncated {
		t.Errorf("byte cap: %q, truncated %v", got, truncated)
	}

	// The API server cut the stream at LimitBytes: the partial last line is
	// dropped and the result is truncated.
	cut := body[:strings.Index(body, " ok")+2]
	lines, truncated, _ = readLogStream(strings.NewReader(cut), f, int64(len(cut)), 100, 1<<20, mkLine)
	if strings.Contains(lineTexts(lines), "|o") || !truncated || len(lines) != 4 {
		t.Errorf("cut stream: %q, truncated %v", lineTexts(lines), truncated)
	}
	// A stream that ends before the window does is complete.
	short := strings.Join([]string{at(10) + " a", at(11) + " b"}, "\n")
	if lines, truncated, _ := readLogStream(strings.NewReader(short), f, 1<<18, 100, 1<<20, mkLine); len(lines) != 2 || truncated {
		t.Errorf("short stream: %d lines, truncated %v", len(lines), truncated)
	}
}

// logFakes serves pod logs from a table keyed "pod/container" (with
// "/previous" for the previous instance), and records the options.
type logFakes struct {
	cs   *fake.Clientset
	mu   sync.Mutex
	opts map[string]corev1.PodLogOptions
	logs map[string]any // string body or error
}

func newLogFakes(pods ...runtime.Object) *logFakes {
	f := &logFakes{cs: fake.NewClientset(pods...), opts: map[string]corev1.PodLogOptions{}, logs: map[string]any{}}
	f.cs.PrependReactor("get", "pods", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if a.GetSubresource() != "log" {
			return false, nil, nil
		}
		ga := a.(k8stesting.GenericAction)
		o := *ga.GetValue().(*corev1.PodLogOptions)
		// GenericActionImpl has no name; the container and the pod name in
		// the options table identify the stream.
		key := o.Container
		if o.Previous {
			key += "/previous"
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		f.opts[key] = o
		switch v := f.logs[key].(type) {
		case error:
			return true, nil, v
		case string:
			return true, &runtime.Unknown{Raw: []byte(v)}, nil
		}
		return true, &runtime.Unknown{Raw: nil}, nil
	})
	return f
}

func logPod(name string, containers ...string) *corev1.Pod {
	p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "app", Name: name}}
	for _, c := range containers {
		p.Spec.Containers = append(p.Spec.Containers, corev1.Container{Name: c})
		p.Status.ContainerStatuses = append(p.Status.ContainerStatuses, corev1.ContainerStatus{Name: c})
	}
	return p
}

func TestPodLogs(t *testing.T) {
	// Container names are unique across pods so the fake can tell streams apart.
	web := logPod("web-0", "web", "metrics", "debug", "extra")
	web.Spec.InitContainers = []corev1.Container{{Name: "migrate"}}
	web.Status.ContainerStatuses[0].RestartCount = 2
	web.Status.ContainerStatuses[0].LastTerminationState.Terminated = &corev1.ContainerStateTerminated{
		Reason: "OOMKilled", FinishedAt: metav1.NewTime(logBase.Add(20 * time.Second))}
	api := logPod("api-0", "api")
	waiting := logPod("starting-0", "starting")
	racing := logPod("racing-0", "racing")
	f := newLogFakes(web, api, waiting, racing)
	f.logs["web"] = strings.Join([]string{at(21) + " restarted", at(25) + ` {"level":"error","msg":"OOM again"}`, at(40) + " late"}, "\n")
	f.logs["web/previous"] = strings.Join([]string{at(5) + " before", at(15) + " ERROR allocating", at(19) + " WARN heap 95%"}, "\n")
	f.logs["metrics"] = at(22) + " scrape ok\n"
	f.logs["api"] = strings.Join([]string{at(12) + " GET /orders 500", at(24) + " GET /orders 200"}, "\n")
	f.logs["starting"] = apierrors.NewBadRequest(`container "starting" in pod "starting-0" is waiting to start: ContainerCreating`)
	f.logs["racing"] = apierrors.NewNotFound(schema.GroupResource{Resource: "pods"}, "racing-0")

	p := NewPodLogs(&Clients{CS: f.cs}, nil, PodLogsOptions{})
	if p.Name() != "kubernetes" {
		t.Errorf("name %q", p.Name())
	}
	q := incidents.LogQuery{Namespace: "app", Pods: []string{"web-0", "api-0", "gone-0", "starting-0", "racing-0", "web-0"},
		From: logBase.Add(10 * time.Second), To: logBase.Add(30 * time.Second), Previous: true}
	res, err := p.Logs(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	want := `GET /orders 500|ERROR allocating|WARN heap 95%|restarted|scrape ok|GET /orders 200|{"level":"error","msg":"OOM again"}`
	if got := lineTexts(res.Lines); got != want {
		t.Errorf("lines:\n got %s\nwant %s", got, want)
	}
	for _, l := range res.Lines {
		if l.Source != "kubernetes" || l.Pod == "" || l.Container == "" || l.Time.Before(q.From) || l.Time.After(q.To) {
			t.Errorf("line %+v", l)
		}
	}
	if l := res.Lines[6]; l.Pod != "web-0" || l.Container != "web" || l.Level != "error" {
		t.Errorf("last line %+v", l)
	}
	// web-0 has five containers: three are read, app containers first.
	warnings := strings.Join(res.Warnings, "\n")
	for _, w := range []string{
		"pod app/gone-0 not found; it may have been deleted",
		"pod app/racing-0 not found; it may have been deleted",
		`app/starting-0/starting: container "starting" in pod "starting-0" is waiting to start`,
		"pod app/web-0: only 3 of 5 containers are read",
	} {
		if !strings.Contains(warnings, w) {
			t.Errorf("warnings %q: missing %q", res.Warnings, w)
		}
	}
	if !res.Truncated {
		t.Error("containers left out, but not truncated")
	}

	f.mu.Lock()
	o := f.opts["web"]
	_, extra := f.opts["extra"]
	_, migrate := f.opts["migrate"]
	_, metricsPrev := f.opts["metrics/previous"]
	_, prev := f.opts["web/previous"]
	f.mu.Unlock()
	if !o.Timestamps || o.SinceTime == nil || !o.SinceTime.Time.Equal(q.From) || o.LimitBytes == nil || *o.LimitBytes != 256<<10 || o.Previous {
		t.Errorf("GetLogs options: %+v", o)
	}
	if extra || migrate || !prev || metricsPrev {
		t.Errorf("streams read: extra %v migrate %v web/previous %v metrics/previous %v", extra, migrate, prev, metricsPrev)
	}

	// Limits: lines and bytes, merged across streams.
	q.Limit = 3
	res, _ = p.Logs(context.Background(), q)
	if got := lineTexts(res.Lines); got != "GET /orders 500|ERROR allocating|WARN heap 95%" || !res.Truncated {
		t.Errorf("limit 3: %s truncated %v", got, res.Truncated)
	}
	q.Limit, q.MaxBytes = 0, int64(len("GET /orders 500")+len("ERROR allocating"))
	if res, _ = p.Logs(context.Background(), q); len(res.Lines) != 2 || !res.Truncated {
		t.Errorf("max bytes: %s truncated %v", lineTexts(res.Lines), res.Truncated)
	}

	// Level and text filters; named containers only; no previous instances.
	q = incidents.LogQuery{Namespace: "app", Pods: []string{"web-0", "api-0"}, Containers: []string{"web", "api"},
		From: logBase.Add(10 * time.Second), To: logBase.Add(30 * time.Second), Level: "error"}
	res, _ = p.Logs(context.Background(), q)
	if got := lineTexts(res.Lines); got != `{"level":"error","msg":"OOM again"}` || res.Truncated || len(res.Warnings) != 0 {
		t.Errorf("errors only: %s truncated %v warnings %v", got, res.Truncated, res.Warnings)
	}
	q.Level, q.Text = "", "ORDERS"
	if res, _ = p.Logs(context.Background(), q); lineTexts(res.Lines) != "GET /orders 500|GET /orders 200" {
		t.Errorf("text: %s", lineTexts(res.Lines))
	}
}

func TestPodLogsLimitsAndErrors(t *testing.T) {
	var pods []runtime.Object
	var names []string
	for i := range 12 {
		name := fmt.Sprintf("p%02d", i)
		pods = append(pods, logPod(name, "c"+name))
		names = append(names, name)
	}
	f := newLogFakes(pods...)
	p := NewPodLogs(&Clients{CS: f.cs}, nil, PodLogsOptions{})
	res, err := p.Logs(context.Background(), incidents.LogQuery{Namespace: "app", Pods: names, From: logBase, To: logBase.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	n := len(f.opts)
	f.mu.Unlock()
	if n != 10 || !res.Truncated || !slices.Contains(res.Warnings, "only the first 10 of 12 pods are read") {
		t.Errorf("pod cap: %d streams, truncated %v, warnings %v", n, res.Truncated, res.Warnings)
	}

	// kubesentry itself may not read logs: an error, not a warning.
	f.logs["cp00"] = apierrors.NewForbidden(schema.GroupResource{Resource: "pods"}, "p00", errors.New("RBAC"))
	if _, err := p.Logs(context.Background(), incidents.LogQuery{Namespace: "app", Pods: []string{"p00"}, From: logBase}); !apierrors.IsForbidden(err) {
		t.Errorf("forbidden: %v", err)
	}
	for _, q := range []incidents.LogQuery{{Pods: []string{"p00"}}, {Namespace: "app", Pods: []string{"p00"}, From: logBase, To: logBase.Add(-time.Second)}} {
		if _, err := p.Logs(context.Background(), q); err == nil {
			t.Errorf("invalid query %+v accepted", q)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.Logs(ctx, incidents.LogQuery{Namespace: "app", Pods: []string{"p01"}, From: logBase}); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: %v", err)
	}
}

func TestPodLogsProbe(t *testing.T) {
	cs, _ := newFakes(nil, nil, nil)
	if p := NewPodLogs(&Clients{CS: cs}, nil, PodLogsOptions{}).Probe(context.Background()); p != "ok" {
		t.Errorf("probe: %q", p)
	}
	cs, _ = newFakes(nil, nil, func(a *authorizationv1.ResourceAttributes) bool { return a.Subresource == "log" })
	if p := NewPodLogs(&Clients{CS: cs}, nil, PodLogsOptions{}).Probe(context.Background()); p != "forbidden: cannot get pods/log (RBAC: no rule)" {
		t.Errorf("forbidden probe: %q", p)
	}
}
