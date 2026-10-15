package cloudwatch

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/smithy-go"

	"github.com/ByronGary/kubesentry/internal/incidents"
)

// stubLogs is a FilterAPI over a fixed list of events. It understands the
// namespace and pod terms of LogLookup's JSON patterns and stream name
// prefixes, pages by pageSize, and can throttle every Nth call.
type stubLogs struct {
	mu            sync.Mutex
	events        []stubEvent // sorted by ts
	pageSize      int
	throttleEvery int
	err           error
	calls         []cloudwatchlogs.FilterLogEventsInput
}

type stubEvent struct {
	ts       int64
	ns, pod  string
	stream   string
	message  string
	eventID  string
	noPodTag bool // the pattern cannot see the pod (prefix mode records)
}

var (
	nsTerm  = regexp.MustCompile(`\$\.kubernetes\.namespace_name = "([^"]+)"`)
	podTerm = regexp.MustCompile(`\$\.kubernetes\.pod_name = "([^"]+)"`)
)

func (s *stubLogs) FilterLogEvents(_ context.Context, in *cloudwatchlogs.FilterLogEventsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.FilterLogEventsOutput, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, *in)
	if s.err != nil {
		return nil, s.err
	}
	if s.throttleEvery > 0 && len(s.calls)%s.throttleEvery == 0 {
		return nil, &smithy.GenericAPIError{Code: "ThrottlingException", Message: "Rate exceeded"}
	}
	pattern := aws.ToString(in.FilterPattern)
	wantNS := ""
	if m := nsTerm.FindStringSubmatch(pattern); m != nil {
		wantNS = m[1]
	}
	pods := map[string]bool{}
	for _, m := range podTerm.FindAllStringSubmatch(pattern, -1) {
		pods[m[1]] = true
	}
	start := 0
	if in.NextToken != nil {
		start, _ = strconv.Atoi(*in.NextToken)
	}
	out := &cloudwatchlogs.FilterLogEventsOutput{}
	size := s.pageSize
	if size <= 0 {
		size = 10000
	}
	if in.Limit != nil && int(*in.Limit) < size {
		size = int(*in.Limit)
	}
	for i := start; i < len(s.events); i++ {
		ev := s.events[i]
		if ev.ts < aws.ToInt64(in.StartTime) || ev.ts > aws.ToInt64(in.EndTime) {
			continue
		}
		if p := aws.ToString(in.LogStreamNamePrefix); p != "" && !strings.HasPrefix(ev.stream, p) {
			continue
		}
		if pattern == "{ $.readOnly IS FALSE }" && !strings.Contains(ev.message, `"readOnly":false`) {
			continue
		}
		if wantNS != "" && ev.ns != wantNS {
			continue
		}
		if len(pods) > 0 && !pods[ev.pod] {
			continue
		}
		if len(out.Events) == size {
			out.NextToken = aws.String(strconv.Itoa(i))
			break
		}
		out.Events = append(out.Events, types.FilteredLogEvent{
			EventId: aws.String(ev.eventID), Timestamp: aws.Int64(ev.ts),
			LogStreamName: aws.String(ev.stream), Message: aws.String(ev.message),
		})
	}
	return out, nil
}

func (s *stubLogs) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

// noSleepPacer records waits instead of sleeping.
func noSleepPacer(waits *[]time.Duration) *Pacer {
	p := NewPacer(time.Second)
	var mu sync.Mutex
	p.sleep = func(ctx context.Context, d time.Duration) bool {
		mu.Lock()
		*waits = append(*waits, d)
		mu.Unlock()
		return ctx.Err() == nil
	}
	return p
}

var lt0 = time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)

// fluent is a Fluent Bit / Container Insights record.
func fluent(ns, pod, ctr, stream, log string, at time.Time) string {
	return fmt.Sprintf(`{"time":%q,"stream":%q,"_p":"F","log":%s,"kubernetes":{"pod_name":%q,"namespace_name":%q,"container_name":%q,"host":"ip-10-0-1-2.ec2.internal"}}`,
		at.Format(time.RFC3339Nano), stream, strconv.Quote(log), pod, ns, ctr)
}

func TestPodPatternsChunkUnder1KiB(t *testing.T) {
	got, err := podPatterns("shop", []string{"web-0", "web-1"}, nil)
	want := `{ $.kubernetes.namespace_name = "shop" && ($.kubernetes.pod_name = "web-0" || $.kubernetes.pod_name = "web-1") }`
	if err != nil || len(got) != 1 || got[0] != want {
		t.Errorf("patterns = %q, %v\nwant %q", got, err, want)
	}
	got, _ = podPatterns("shop", nil, []string{"app"})
	if want := `{ $.kubernetes.namespace_name = "shop" && ($.kubernetes.container_name = "app") }`; len(got) != 1 || got[0] != want {
		t.Errorf("namespace only = %q", got)
	}

	var pods []string
	for i := 0; i < 120; i++ {
		pods = append(pods, fmt.Sprintf("checkout-api-7d9f8b6c4d-%05d", i))
	}
	got, err = podPatterns("payments-production", pods, []string{"app", "envoy"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) < 4 {
		t.Fatalf("120 pods fit in %d patterns", len(got))
	}
	seen := map[string]int{}
	for _, p := range got {
		if len(p) > MaxFilterPattern {
			t.Errorf("pattern of %d bytes", len(p))
		}
		if !strings.HasPrefix(p, `{ $.kubernetes.namespace_name = "payments-production" && ($.kubernetes.container_name = "app" || $.kubernetes.container_name = "envoy") && (`) || !strings.HasSuffix(p, ") }") {
			t.Errorf("pattern shape: %s", p)
		}
		for _, m := range podTerm.FindAllStringSubmatch(p, -1) {
			seen[m[1]]++
		}
	}
	for _, p := range pods {
		if seen[p] != 1 {
			t.Errorf("%s in %d patterns", p, seen[p])
		}
	}
	// The chunks are full: merging the first two would cross the limit.
	if len(got[0])+len(" || ")+len(`$.kubernetes.pod_name = "checkout-api-7d9f8b6c4d-00000"`) <= MaxFilterPattern {
		t.Errorf("first pattern (%d bytes) had room for another pod", len(got[0]))
	}
}

func TestLogLookupReadsAndFilters(t *testing.T) {
	stub := &stubLogs{pageSize: 2}
	add := func(sec int, ns, pod, ctr, log string) {
		at := lt0.Add(time.Duration(sec) * time.Second)
		// CloudWatch's own timestamp lags the record's a little.
		stub.events = append(stub.events, stubEvent{
			ts: at.Add(300 * time.Millisecond).UnixMilli(), ns: ns, pod: pod, stream: "ip-10-0-1-2-application.var.log.containers." + pod,
			message: fluent(ns, pod, ctr, "stdout", log, at), eventID: fmt.Sprint(sec),
		})
	}
	add(1, "shop", "web-0", "app", "level=info msg=\"started\"\n")
	add(2, "shop", "web-1", "app", `{"level":"warn","msg":"upstream timeout, retrying"}`)
	add(3, "shop", "web-0", "envoy", "[2026-10-15 10:00:03][WARNING] upstream Timeout")
	add(4, "other", "web-0", "app", "ERROR timeout in another namespace")
	add(5, "shop", "web-2", "app", "ERROR timeout on a pod not asked for")
	add(6, "shop", "web-0", "app", "E1015 10:00:06.000000       1 main.go:42] request timeout")
	add(7, "shop", "web-1", "app", "INFO timeout budget is 2s")
	add(30*60, "shop", "web-0", "app", "ERROR timeout after the window")

	var waits []time.Duration
	l := &LogLookup{API: stub, LogGroup: DefaultApplicationLogGroup("prod"), Pacer: noSleepPacer(&waits)}
	if l.LogGroup != "/aws/containerinsights/prod/application" || l.Name() != "cloudwatch" {
		t.Fatalf("group %s, name %s", l.LogGroup, l.Name())
	}
	q := incidents.LogQuery{
		Namespace: "shop", Pods: []string{"web-1", "web-0", "web-0"}, From: lt0, To: lt0.Add(10 * time.Minute),
		Level: "warning", Text: "TIMEOUT",
	}
	res, err := l.Logs(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, ln := range res.Lines {
		got = append(got, fmt.Sprintf("%s %s/%s %s %s %s", ln.Time.Format("15:04:05"), ln.Pod, ln.Container, ln.Level, ln.Source, ln.Text))
	}
	want := []string{
		`10:00:02 web-1/app warn cloudwatch {"level":"warn","msg":"upstream timeout, retrying"}`,
		`10:00:03 web-0/envoy warn cloudwatch [2026-10-15 10:00:03][WARNING] upstream Timeout`,
		`10:00:06 web-0/app error cloudwatch E1015 10:00:06.000000       1 main.go:42] request timeout`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("lines:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if res.Truncated || len(res.Warnings) != 0 {
		t.Errorf("truncated %v, warnings %v", res.Truncated, res.Warnings)
	}
	first := stub.calls[0]
	if p := aws.ToString(first.FilterPattern); p != `{ $.kubernetes.namespace_name = "shop" && ($.kubernetes.pod_name = "web-0" || $.kubernetes.pod_name = "web-1") }` {
		t.Errorf("pattern = %s", p)
	}
	if aws.ToString(first.LogGroupName) != "/aws/containerinsights/prod/application" || aws.ToInt64(first.StartTime) != lt0.UnixMilli() || aws.ToInt64(first.EndTime) != lt0.Add(10*time.Minute).UnixMilli() || first.LogStreamNamePrefix != nil {
		t.Errorf("first call = %+v", first)
	}
	if len(stub.calls) != 3 { // 5 matching events, 2 per page
		t.Errorf("%d calls, want 3 pages", len(stub.calls))
	}

	// Unknown levels count as info; a container filter applies.
	res, err = l.Logs(context.Background(), incidents.LogQuery{Namespace: "shop", Pods: []string{"web-0"}, Containers: []string{"app"}, From: lt0, To: lt0.Add(time.Minute), Level: "info"})
	if err != nil || len(res.Lines) != 2 || res.Lines[0].Level != LevelInfo || res.Lines[1].Level != LevelError {
		t.Errorf("info and above in web-0/app: %+v %v", res.Lines, err)
	}
	if _, err := l.Logs(context.Background(), incidents.LogQuery{Namespace: "shop", From: lt0, To: lt0.Add(time.Minute), Level: "loud"}); err == nil {
		t.Error("unknown level accepted")
	}
	if _, err := l.Logs(context.Background(), incidents.LogQuery{Namespace: `shop" || $.x = "y`, From: lt0, To: lt0.Add(time.Minute)}); err == nil {
		t.Error("namespace that would break the pattern accepted")
	}
	res, err = l.Logs(context.Background(), incidents.LogQuery{Namespace: "shop", Pods: []string{`web-0" || 1 = "1`}, From: lt0, To: lt0.Add(time.Minute)})
	if err != nil || len(res.Lines) != 0 || len(res.Warnings) != 1 {
		t.Errorf("invalid pod: want nothing read and a warning, got %+v %v", res, err)
	}
}

func TestLogLookupCaps(t *testing.T) {
	stub := &stubLogs{pageSize: 10}
	for i := 0; i < 500; i++ {
		at := lt0.Add(time.Duration(i) * time.Second)
		stub.events = append(stub.events, stubEvent{ts: at.UnixMilli(), ns: "shop", pod: "web-0", stream: "s",
			message: fluent("shop", "web-0", "app", "stderr", fmt.Sprintf("line %03d %s", i, strings.Repeat("x", 90)), at)})
	}
	var waits []time.Duration
	l := &LogLookup{API: stub, LogGroup: "g", Pacer: noSleepPacer(&waits)}
	q := incidents.LogQuery{Namespace: "shop", Pods: []string{"web-0"}, From: lt0, To: lt0.Add(time.Hour)}

	// Calls: the default 10 calls of 10 events.
	res, err := l.Logs(context.Background(), q)
	if err != nil || !res.Truncated || len(res.Lines) != 100 || stub.callCount() != 10 || len(res.Warnings) != 1 {
		t.Errorf("call cap: %d lines, truncated %v, %d calls, warnings %v, %v", len(res.Lines), res.Truncated, stub.callCount(), res.Warnings, err)
	}
	// Lines: the query's limit, under the lookup's.
	stub.calls = nil
	q.Limit = 25
	res, _ = l.Logs(context.Background(), q)
	if !res.Truncated || len(res.Lines) != 25 || !strings.HasPrefix(res.Lines[0].Text, "line 000") || stub.callCount() != 3 {
		t.Errorf("line cap: %d lines, truncated %v, %d calls", len(res.Lines), res.Truncated, stub.callCount())
	}
	l.MaxLines = 7
	res, _ = l.Logs(context.Background(), q)
	if !res.Truncated || len(res.Lines) != 7 {
		t.Errorf("lookup line cap: %d lines", len(res.Lines))
	}
	// Bytes: 99 bytes a line.
	l.MaxLines = 0
	q.Limit, q.MaxBytes = 0, 1000
	res, _ = l.Logs(context.Background(), q)
	if !res.Truncated || len(res.Lines) != 10 {
		t.Errorf("byte cap: %d lines", len(res.Lines))
	}
	// Everything fits: not truncated.
	q.MaxBytes, q.To = 0, lt0.Add(20*time.Second)
	res, _ = l.Logs(context.Background(), q)
	if res.Truncated || len(res.Lines) != 21 {
		t.Errorf("small window: %d lines, truncated %v", len(res.Lines), res.Truncated)
	}
}

func TestLogLookupStreamPrefix(t *testing.T) {
	stub := &stubLogs{}
	at := lt0.Add(time.Second)
	stub.events = []stubEvent{
		{ts: at.UnixMilli(), stream: "shop.web-1", message: "plain line from web-1"},
		{ts: at.UnixMilli() + 1, stream: "shop.web-10", message: fluent("shop", "web-10", "app", "stdout", "from web-10", at)},
		{ts: at.UnixMilli() + 2, stream: "shop.web-2", message: "WARN from web-2"},
		{ts: at.UnixMilli() + 3, stream: "shop.api-0", message: "from api-0"},
	}
	var waits []time.Duration
	l := &LogLookup{API: stub, LogGroup: "g", StreamPrefix: "{namespace}.{pod}", Pacer: noSleepPacer(&waits)}
	res, err := l.Logs(context.Background(), incidents.LogQuery{Namespace: "shop", Pods: []string{"web-2", "web-1"}, From: lt0, To: lt0.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, ln := range res.Lines {
		got = append(got, ln.Pod+":"+ln.Level+":"+ln.Text)
	}
	if want := "web-1:info:plain line from web-1,web-2:warn:WARN from web-2"; strings.Join(got, ",") != want {
		t.Errorf("lines = %s, want %s", strings.Join(got, ","), want)
	}
	var prefixes []string
	for _, c := range stub.calls {
		prefixes = append(prefixes, aws.ToString(c.LogStreamNamePrefix))
		if c.FilterPattern != nil {
			t.Errorf("prefix mode sent a pattern: %s", *c.FilterPattern)
		}
	}
	if strings.Join(prefixes, ",") != "shop.web-1,shop.web-2" {
		t.Errorf("prefixes = %v", prefixes)
	}
	if got := streamPrefixes("{namespace}/{pod}/", "shop", nil); len(got) != 1 || got[0] != "shop/" {
		t.Errorf("no pods: %v", got)
	}
}

func TestParseContainerLog(t *testing.T) {
	ts := lt0.Add(time.Second).UnixMilli()
	cases := []struct {
		name, msg                       string
		pod, ctr, level, text, timeWant string
	}{
		{"fluent bit", fluent("shop", "web-0", "app", "stderr", "ERROR boom\n", lt0.Add(500*time.Millisecond)),
			"web-0", "app", "error", "ERROR boom", "10:00:00.5"},
		{"merged application JSON", `{"@timestamp":"2026-10-15T10:00:02Z","message":"payment declined","level":"WARNING","kubernetes":{"pod_name":"pay-0","container_name":"api"}}`,
			"pay-0", "api", "warn", "payment declined", "10:00:02"},
		{"application JSON inside log", fluent("shop", "web-0", "app", "stdout", `{"lvl":"debug","msg":"cache hit"}`, lt0),
			"web-0", "app", "debug", `{"lvl":"debug","msg":"cache hit"}`, "10:00:00"},
		{"numeric JSON level is not a level word", `{"log":"{\"level\":50,\"msg\":\"db down\"}","kubernetes":{"pod_name":"a"}}`,
			"a", "", "info", `{"level":50,"msg":"db down"}`, "10:00:01"},
		{"severity field", `{"severity":"ERROR","message":"payment failed"}`,
			"", "", "error", "payment failed", "10:00:01"},
		{"epoch @timestamp", `{"@timestamp":1792058403.25,"msg":"tick","kubernetes":{"pod_name":"a"}}`,
			"a", "", "info", "tick", "10:00:03.25"},
		{"logfmt", `{"log":"time=x level=Error msg=\"no route\"","kubernetes":{"pod_name":"a"}}`,
			"a", "", "error", `time=x level=Error msg="no route"`, "10:00:01"},
		{"plain text", "WARN disk at 91%", "", "", "warn", "WARN disk at 91%", "10:00:01"},
		{"broken JSON", `{"log": "unterminated`, "", "", "info", `{"log": "unterminated`, "10:00:01"},
		{"lower-case words are not levels", "no error here", "", "", "info", "no error here", "10:00:01"},
		{"lower-case tags are not levels", "[warning] slow upstream", "", "", "info", "[warning] slow upstream", "10:00:01"},
		{"klog warning", "W1015 10:00:01.000000       1 reflector.go:1] watch closed", "", "", "warn", "W1015 10:00:01.000000       1 reflector.go:1] watch closed", "10:00:01"},
		{"upper-case PANIC", "PANIC: nil map", "", "", "error", "PANIC: nil map", "10:00:01"},
		{"upper-case DEBUG is not detected", "DEBUG cache miss", "", "", "info", "DEBUG cache miss", "10:00:01"},
	}
	for _, tc := range cases {
		ln := ParseContainerLog(tc.msg, ts)
		if ln.Pod != tc.pod || ln.Container != tc.ctr || ln.Level != tc.level || ln.Text != tc.text || ln.Source != "cloudwatch" {
			t.Errorf("%s: got pod=%q ctr=%q level=%q text=%q", tc.name, ln.Pod, ln.Container, ln.Level, ln.Text)
		}
		if got := ln.Time.Format("15:04:05.999"); got != tc.timeWant {
			t.Errorf("%s: time %s, want %s", tc.name, got, tc.timeWant)
		}
	}
}

func TestLogLookupErrorsAndThrottling(t *testing.T) {
	var waits []time.Duration
	stub := &stubLogs{err: &smithy.GenericAPIError{Code: "ResourceNotFoundException", Message: "The specified log group does not exist."}}
	l := &LogLookup{API: stub, LogGroup: "/aws/containerinsights/prod/application", Pacer: noSleepPacer(&waits)}
	q := incidents.LogQuery{Namespace: "shop", From: lt0, To: lt0.Add(time.Minute)}
	if _, err := l.Logs(context.Background(), q); !errors.Is(err, ErrLogGroupNotFound) {
		t.Errorf("missing group: %v", err)
	}
	if got := l.Probe(context.Background()); got != ProbeAbsent {
		t.Errorf("probe of a missing group = %q", got)
	}
	stub.err = &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "no"}
	if _, err := l.Logs(context.Background(), q); !errors.Is(err, ErrAccessDenied) {
		t.Errorf("denied: %v", err)
	}
	if got := l.Probe(context.Background()); !strings.HasPrefix(got, "error: ") {
		t.Errorf("probe when denied = %q", got)
	}
	stub.err = nil
	if got := l.Probe(context.Background()); got != ProbeOK {
		t.Errorf("probe = %q", got)
	}

	// Throttled calls are retried after the backoff; they do not count
	// against the call cap.
	stub = &stubLogs{pageSize: 1, throttleEvery: 2}
	for i := 0; i < 4; i++ {
		stub.events = append(stub.events, stubEvent{ts: lt0.Add(time.Duration(i) * time.Second).UnixMilli(), ns: "shop", pod: "web-0", message: "x"})
	}
	waits = nil
	l = &LogLookup{API: stub, LogGroup: "g", Pacer: noSleepPacer(&waits), MaxCalls: 4}
	res, err := l.Logs(context.Background(), incidents.LogQuery{Namespace: "shop", Pods: []string{"web-0"}, From: lt0, To: lt0.Add(time.Minute)})
	if err != nil || len(res.Lines) != 4 || res.Truncated {
		t.Fatalf("throttled read: %d lines, truncated %v, %v", len(res.Lines), res.Truncated, err)
	}
	if stub.callCount() != 7 || len(waits) == 0 || waits[0] != time.Second {
		t.Errorf("%d calls, waits %v", stub.callCount(), waits)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	stub.err = &smithy.GenericAPIError{Code: "ThrottlingException"}
	if _, err := l.Logs(ctx, incidents.LogQuery{Namespace: "shop", From: lt0, To: lt0.Add(time.Minute)}); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: %v", err)
	}
}

func TestPacerBacksOffAndRelaxes(t *testing.T) {
	var waits []time.Duration
	p := noSleepPacer(&waits)
	throttle := &smithy.GenericAPIError{Code: "Throttling"}
	results := []error{throttle, throttle, throttle, nil}
	var throttled int
	err := p.Do(context.Background(), func() error {
		e := results[0]
		results = results[1:]
		return e
	}, isThrottled, func(error) { throttled++ })
	if err != nil || throttled != 3 {
		t.Fatalf("err %v, throttled %d", err, throttled)
	}
	// backoff 1s, 2s, 4s; pace 1s, 2s, 4s waited before each retry.
	want := []time.Duration{time.Second, time.Second, 2 * time.Second, 2 * time.Second, 4 * time.Second, 4 * time.Second}
	if fmt.Sprint(waits) != fmt.Sprint(want) {
		t.Errorf("waits = %v, want %v", waits, want)
	}
	if got := p.Pace(); got != 2*time.Second {
		t.Errorf("pace after a success = %v, want halved to 2s", got)
	}
	for i := 0; i < 5; i++ { // 1s, 0.5s, 0.25s, 0.125s, then below an eighth of the backoff
		p.Do(context.Background(), func() error { return nil }, isThrottled, nil)
	}
	if got := p.Pace(); got != 0 {
		t.Errorf("pace after successes = %v, want 0", got)
	}
	other := errors.New("boom")
	if err := p.Do(context.Background(), func() error { return other }, isThrottled, nil); err != other {
		t.Errorf("non-throttle error = %v", err)
	}
}

func TestRawReader(t *testing.T) {
	stub := &stubLogs{pageSize: 3}
	for i := 0; i < 10; i++ {
		ro := i%2 == 1
		stub.events = append(stub.events, stubEvent{ts: lt0.Add(time.Duration(i) * time.Second).UnixMilli(), stream: "123456789012_CloudTrail_us-east-1",
			eventID: fmt.Sprint("ev", i), message: fmt.Sprintf(`{"eventID":"e%d","readOnly":%v}`, i, ro)})
	}
	var waits []time.Duration
	r := &RawReader{API: stub, LogGroup: "aws-cloudtrail-logs", FilterPattern: "{ $.readOnly IS FALSE }", Pacer: noSleepPacer(&waits)}
	evs, more, err := r.Read(context.Background(), lt0, lt0.Add(time.Minute))
	if err != nil || more || len(evs) != 5 {
		t.Fatalf("read: %d events, more %v, %v", len(evs), more, err)
	}
	if evs[0].ID != "ev0" || evs[0].Message != `{"eventID":"e0","readOnly":false}` || !evs[0].Time.Equal(lt0) || evs[4].ID != "ev8" {
		t.Errorf("events = %+v", evs)
	}
	if p := aws.ToString(stub.calls[0].FilterPattern); p != "{ $.readOnly IS FALSE }" {
		t.Errorf("pattern = %s", p)
	}
	r.MaxEvents = 4
	evs, more, _ = r.Read(context.Background(), lt0, lt0.Add(time.Minute))
	if !more || len(evs) != 4 {
		t.Errorf("event cap: %d events, more %v", len(evs), more)
	}
	r.MaxEvents, r.MaxCalls = 0, 1
	evs, more, _ = r.Read(context.Background(), lt0, lt0.Add(time.Minute))
	if !more || len(evs) != 3 {
		t.Errorf("call cap: %d events, more %v", len(evs), more)
	}
	if got := r.Probe(context.Background()); got != ProbeOK {
		t.Errorf("probe = %q", got)
	}
	if _, _, err := r.Read(context.Background(), lt0, lt0); err == nil {
		t.Error("empty range accepted")
	}
}
