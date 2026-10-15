package cloudtrail

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"

	"github.com/ByronGary/kubesentry/internal/cloudwatch"
	"github.com/ByronGary/kubesentry/internal/incidents"
)

var t0 = time.Date(2026, 10, 15, 10, 20, 0, 0, time.UTC)

// rec is a CloudTrail record with the given fields merged into a base.
func rec(id string, at time.Time, name, source string, readOnly bool, extra string) string {
	s := fmt.Sprintf(`{"eventVersion":"1.09","userIdentity":{"type":"AssumedRole","principalId":"AROAEXAMPLE:alice","arn":"arn:aws:sts::123456789012:assumed-role/Admin/alice","accountId":"123456789012","sessionContext":{"sessionIssuer":{"type":"Role","arn":"arn:aws:iam::123456789012:role/Admin","userName":"Admin"}}},"eventTime":%q,"eventSource":%q,"eventName":%q,"awsRegion":"us-east-1","sourceIPAddress":"203.0.113.10","eventID":%q,"readOnly":%v,"eventType":"AwsApiCall","managementEvent":true,"recipientAccountId":"123456789012"`,
		at.Format(time.RFC3339), source, name, id, readOnly)
	if extra != "" {
		s += "," + extra
	}
	return s + "}"
}

func TestParseRecordResources(t *testing.T) {
	at := t0.Add(-10 * time.Minute)
	cases := []struct {
		name, raw                      string
		resources, actor, errCode, src string
	}{
		{"security group ingress",
			rec("ev-sg", at, "AuthorizeSecurityGroupIngress", "ec2.amazonaws.com", false,
				`"requestParameters":{"groupId":"sg-0123456789abcdef0","ipPermissions":{"items":[{"ipProtocol":"tcp","fromPort":443,"ipRanges":{"items":[{"cidrIp":"0.0.0.0/0"}]}}]}},"responseElements":{"_return":true}`),
			"sg-0123456789abcdef0", "arn:aws:sts::123456789012:assumed-role/Admin/alice", "", "ec2.amazonaws.com"},
		{"register targets",
			rec("ev-tg", at, "RegisterTargets", "elasticloadbalancing.amazonaws.com", false,
				`"requestParameters":{"targetGroupArn":"arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/k8s-shop-web-1a2b3c4d5e/0123456789abcdef","targets":[{"id":"i-0abc12345def67890","port":8080},{"id":"10.0.1.7"}]}`),
			"arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/k8s-shop-web-1a2b3c4d5e/0123456789abcdef,i-0abc12345def67890", "", "", ""},
		{"EKS node group, failed",
			`{"eventID":"ev-eks","eventTime":"2026-10-15T10:10:00Z","eventSource":"eks.amazonaws.com","eventName":"UpdateNodegroupConfig","readOnly":false,"errorCode":"InvalidParameterException","userIdentity":{"type":"IAMUser","userName":"bob","arn":"arn:aws:iam::123456789012:user/bob"},"requestParameters":{"name":"prod","nodegroupName":"ng-1","scalingConfig":{"desiredSize":5}}}`,
			"cluster/prod,nodegroup/prod/ng-1", "arn:aws:iam::123456789012:user/bob", "InvalidParameterException", "eks.amazonaws.com"},
		{"IAM role policy, by a service",
			`{"eventID":"ev-iam","eventTime":"2026-10-15T10:10:00Z","eventSource":"iam.amazonaws.com","eventName":"AttachRolePolicy","readOnly":false,"userIdentity":{"type":"AWSService","invokedBy":"cloudformation.amazonaws.com"},"requestParameters":{"roleName":"shop-web-irsa","policyArn":"arn:aws:iam::aws:policy/AmazonS3FullAccess"},"resources":[{"ARN":"arn:aws:iam::123456789012:role/shop-web-irsa","type":"AWS::IAM::Role"}]}`,
			"arn:aws:iam::123456789012:role/shop-web-irsa,arn:aws:iam::aws:policy/AmazonS3FullAccess,role/shop-web-irsa", "cloudformation.amazonaws.com", "", ""},
	}
	for _, tc := range cases {
		ev, err := ParseRecord([]byte(tc.raw))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got := strings.Join(ev.Resources, ","); got != tc.resources {
			t.Errorf("%s: resources\n got %s\nwant %s", tc.name, got, tc.resources)
		}
		if tc.actor != "" && ev.Actor != tc.actor {
			t.Errorf("%s: actor %q", tc.name, ev.Actor)
		}
		if ev.ErrorCode != tc.errCode || ev.ReadOnly || !ev.Time.Equal(at) || ev.ID == "" || ev.Name == "" {
			t.Errorf("%s: %+v", tc.name, ev)
		}
		if tc.src != "" && ev.Source != tc.src {
			t.Errorf("%s: source %q", tc.name, ev.Source)
		}
		if !json.Valid([]byte(ev.Raw)) || strings.Contains(ev.Raw, "\n") {
			t.Errorf("%s: raw is not compact JSON: %s", tc.name, ev.Raw)
		}
	}
	if _, err := ParseRecord([]byte(`{"hello":"world"}`)); err == nil {
		t.Error("a non-CloudTrail record parsed")
	}
	if _, err := ParseRecord([]byte(`not json`)); err == nil {
		t.Error("garbage parsed")
	}
}

func TestRawIsCapped(t *testing.T) {
	big := rec("ev-big", t0, "PutBucketPolicy", "s3.amazonaws.com", false,
		`"requestParameters":{"bucketName":"b"},"responseElements":{"blob":"`+strings.Repeat("x", 20000)+`"}`)
	ev, err := ParseRecord([]byte(big))
	if err != nil {
		t.Fatal(err)
	}
	if len(ev.Raw) > MaxRaw || !json.Valid([]byte(ev.Raw)) || strings.Contains(ev.Raw, "responseElements") || !strings.Contains(ev.Raw, `"eventID":"ev-big"`) {
		t.Errorf("raw of %d bytes without responseElements expected, got %.200s", len(ev.Raw), ev.Raw)
	}
	huge := rec("ev-huge", t0, "PutBucketPolicy", "s3.amazonaws.com", false,
		`"requestParameters":{"policy":"`+strings.Repeat("é", 10000)+`"}`)
	ev, _ = ParseRecord([]byte(huge))
	if len(ev.Raw) > MaxRaw || !strings.HasPrefix(ev.Raw, `{"eventVersion"`) || !utf8Valid(ev.Raw) {
		t.Errorf("raw of %d bytes", len(ev.Raw))
	}
}

func utf8Valid(s string) bool { return strings.ToValidUTF8(s, "�") == s }

// fakeTrail is an httptest CloudTrail LookupEvents endpoint on a fake clock.
type fakeTrail struct {
	t      *testing.T
	clk    *clock
	mu     sync.Mutex
	inputs []lookupEventsInput
	times  []time.Time
	answer func(n int, in lookupEventsInput) (int, string)
}

func (f *fakeTrail) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if got := r.Header.Get("X-Amz-Target"); got != "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.LookupEvents" {
		f.t.Errorf("X-Amz-Target = %q", got)
	}
	if got := r.Header.Get("Content-Type"); got != "application/x-amz-json-1.1" {
		f.t.Errorf("Content-Type = %q", got)
	}
	auth := r.Header.Get("Authorization")
	if !strings.Contains(auth, "Credential=AKIDTEST/20261015/us-east-1/cloudtrail/aws4_request") || !strings.Contains(auth, "x-amz-target") {
		f.t.Errorf("Authorization = %q", auth)
	}
	b, _ := io.ReadAll(r.Body)
	var in lookupEventsInput
	if err := json.Unmarshal(b, &in); err != nil {
		f.t.Errorf("body %s: %v", b, err)
	}
	if len(in.LookupAttributes) != 1 || in.LookupAttributes[0] != (lookupAttribute{"ReadOnly", "false"}) {
		f.t.Errorf("lookup attributes = %+v", in.LookupAttributes)
	}
	f.mu.Lock()
	n := len(f.inputs)
	f.inputs = append(f.inputs, in)
	f.times = append(f.times, f.clk.Now())
	f.mu.Unlock()
	status, body := 200, `{"Events":[]}`
	if f.answer != nil {
		status, body = f.answer(n, in)
	}
	w.WriteHeader(status)
	w.Write([]byte(body))
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

func (c *clock) Set(t time.Time) {
	c.mu.Lock()
	c.t = t
	c.mu.Unlock()
}

func (c *clock) Sleep(ctx context.Context, d time.Duration) bool {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
	return ctx.Err() == nil
}

// lookupEntry is one LookupEvents entry embedding rec.
func lookupEntry(id string, at time.Time, readOnly bool, extra string) string {
	r := rec(id, at, "ModifyInstanceAttribute", "ec2.amazonaws.com", readOnly, extra)
	return fmt.Sprintf(`{"EventId":%q,"EventName":"ModifyInstanceAttribute","EventSource":"ec2.amazonaws.com","EventTime":%d,"ReadOnly":%q,"Username":"alice","Resources":[{"ResourceType":"AWS::EC2::Instance","ResourceName":"i-0abc12345def67890"},{"ResourceType":"AWS::IAM::Role","ResourceName":"node-role"}],"CloudTrailEvent":%s}`,
		id, at.Unix(), strconv.FormatBool(readOnly), strconv.Quote(r))
}

func newLookup(t *testing.T, f *fakeTrail, o LookupOptions) *LookupSource {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	o.Region, o.Endpoint = "us-east-1", srv.URL
	o.Credentials = credentials.NewStaticCredentialsProvider("AKIDTEST", "secret", "")
	o.Now, o.Sleep = f.clk.Now, f.clk.Sleep
	s, err := NewLookup(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func ids(evs []incidents.CloudTrailEvent) string {
	var out []string
	for _, e := range evs {
		out = append(out, e.ID)
	}
	return strings.Join(out, ",")
}

func TestLookupPagesPacesAndDedupesTheOverlap(t *testing.T) {
	clk := &clock{t: t0}
	f := &fakeTrail{t: t, clk: clk}
	f.answer = func(n int, in lookupEventsInput) (int, string) {
		switch n {
		case 0:
			return 400, `{"__type":"ThrottlingException","message":"Rate exceeded"}`
		case 1: // newest first
			return 200, `{"Events":[` + lookupEntry("ev-3", t0.Add(-5*time.Minute), false, "") + `,` +
				lookupEntry("ev-2", t0.Add(-10*time.Minute), false, `"requestParameters":{"instanceId":"i-0abc12345def67890","groupSet":{"items":[{"groupId":"sg-0123456789abcdef0"}]}}`) +
				`],"NextToken":"page-2"}`
		case 2:
			if in.NextToken != "page-2" {
				t.Errorf("second page token = %q", in.NextToken)
			}
			return 200, `{"Events":[` + lookupEntry("ev-ro", t0.Add(-20*time.Minute), true, "") + `,` + lookupEntry("ev-1", t0.Add(-50*time.Minute), false, "") + `]}`
		case 3: // the second poll: the overlap again, plus a late and a new event
			return 200, `{"Events":[` + lookupEntry("ev-4", t0.Add(time.Minute), false, "") + `,` +
				lookupEntry("ev-3", t0.Add(-5*time.Minute), false, "") + `,` +
				lookupEntry("ev-late", t0.Add(-12*time.Minute), false, "") + `,` +
				lookupEntry("ev-2", t0.Add(-10*time.Minute), false, "") + `]}`
		}
		return 200, `{"Events":[]}`
	}
	counts := map[string]int{}
	s := newLookup(t, f, LookupOptions{OnResult: func(r string, n int) { counts[r] += n }})
	if s.Name() != "lookup" {
		t.Errorf("name %s", s.Name())
	}

	evs, cpb, err := s.Changes(context.Background(), time.Time{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(evs); got != "ev-1,ev-2,ev-3" {
		t.Errorf("first poll = %s", got)
	}
	in := f.inputs[0]
	if in.StartTime.Time() != t0.Add(-time.Hour) || in.EndTime.Time() != t0 || in.MaxResults != 50 {
		t.Errorf("first window %v..%v, max %d", in.StartTime.Time(), in.EndTime.Time(), in.MaxResults)
	}
	ev2 := evs[1]
	if got := strings.Join(ev2.Resources, ","); got != "sg-0123456789abcdef0,i-0abc12345def67890,role/node-role" {
		t.Errorf("resources = %s", got)
	}
	if ev2.Actor != "arn:aws:sts::123456789012:assumed-role/Admin/alice" || ev2.Region != "us-east-1" || !ev2.Time.Equal(t0.Add(-10*time.Minute)) || ev2.Raw == "" {
		t.Errorf("event = %+v", ev2)
	}
	// Pacing: one call a second, the throttled one included, after a 1s backoff.
	for i := 1; i < len(f.times); i++ {
		if d := f.times[i].Sub(f.times[i-1]); d < time.Second {
			t.Errorf("call %d came %v after the previous", i, d)
		}
	}
	if counts[ResultThrottled] != 1 || counts[ResultFetched] != 3 {
		t.Errorf("results = %v", counts)
	}
	var cp checkpoint
	if err := json.Unmarshal(cpb, &cp); err != nil || !cp.Last.Equal(t0) || cp.Partial {
		t.Fatalf("checkpoint %s: %v", cpb, err)
	}
	if len(cp.Seen) != 2 || cp.Seen["ev-2"] == 0 || cp.Seen["ev-3"] == 0 {
		t.Errorf("seen = %v, want the events of the last 15 minutes", cp.Seen)
	}

	clk.Set(t0.Add(2 * time.Minute))
	evs, cpb, err = s.Changes(context.Background(), t0.Add(-time.Hour), cpb)
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(evs); got != "ev-late,ev-4" {
		t.Errorf("second poll = %s", got)
	}
	if in := f.inputs[3]; in.StartTime.Time() != t0.Add(-15*time.Minute) || in.EndTime.Time() != t0.Add(2*time.Minute) {
		t.Errorf("second window %v..%v, want the 15 minute overlap", in.StartTime.Time(), in.EndTime.Time())
	}
	if counts[ResultDuplicate] != 2 {
		t.Errorf("duplicates = %d", counts[ResultDuplicate])
	}
	_ = json.Unmarshal(cpb, &cp)
	if _, ok := cp.Seen["ev-late"]; !ok || len(cp.Seen) != 4 {
		t.Errorf("seen after the second poll = %v", cp.Seen)
	}

	// A failed poll keeps the checkpoint.
	f.answer = func(int, lookupEventsInput) (int, string) {
		return 400, `{"__type":"InvalidTimeRangeException","message":"bad"}`
	}
	_, same, err := s.Changes(context.Background(), time.Time{}, cpb)
	if err == nil || string(same) != string(cpb) {
		t.Errorf("failed poll: %v, checkpoint changed: %v", err, string(same) != string(cpb))
	}
}

func TestLookupStopsAtThePageCap(t *testing.T) {
	clk := &clock{t: t0}
	f := &fakeTrail{t: t, clk: clk}
	f.answer = func(n int, in lookupEventsInput) (int, string) {
		return 200, `{"Events":[` + lookupEntry(fmt.Sprint("ev-", n), t0.Add(-time.Duration(n)*time.Minute), false, "") + `],"NextToken":"more"}`
	}
	counts := map[string]int{}
	s := newLookup(t, f, LookupOptions{MaxPages: 3, QPS: 2, OnResult: func(r string, n int) { counts[r] += n }})
	evs, _, err := s.Changes(context.Background(), time.Time{}, nil)
	if err != nil || len(evs) != 3 || len(f.inputs) != 3 || counts[ResultTruncated] != 1 {
		t.Errorf("%d events, %d calls, results %v, %v", len(evs), len(f.inputs), counts, err)
	}
	if d := f.times[2].Sub(f.times[1]); d != 500*time.Millisecond {
		t.Errorf("at 2 QPS calls came %v apart", d)
	}
}

func TestLookupProbe(t *testing.T) {
	clk := &clock{t: t0}
	f := &fakeTrail{t: t, clk: clk}
	s := newLookup(t, f, LookupOptions{})
	if got := s.Probe(context.Background()); got != "ok" {
		t.Errorf("probe = %q", got)
	}
	if f.inputs[0].MaxResults != 1 {
		t.Errorf("probe asked for %d events", f.inputs[0].MaxResults)
	}
	f.answer = func(int, lookupEventsInput) (int, string) {
		return 400, `{"__type":"AccessDeniedException","message":"not authorized to perform: cloudtrail:LookupEvents"}`
	}
	if got := s.Probe(context.Background()); !strings.HasPrefix(got, "error: access denied") {
		t.Errorf("denied probe = %q", got)
	}
}

func TestCheckpointWindow(t *testing.T) {
	now := t0
	cases := []struct {
		name  string
		since time.Time
		cp    checkpoint
		want  time.Time
	}{
		{"first poll", time.Time{}, checkpoint{}, now.Add(-time.Hour)},
		{"since", now.Add(-30 * time.Minute), checkpoint{}, now.Add(-30 * time.Minute)},
		{"overlap", time.Time{}, checkpoint{Last: now.Add(-2 * time.Minute)}, now.Add(-17 * time.Minute)},
		{"since later than the overlap", now.Add(-5 * time.Minute), checkpoint{Last: now.Add(-2 * time.Minute)}, now.Add(-5 * time.Minute)},
		{"partial resumes exactly", time.Time{}, checkpoint{Last: now.Add(-2 * time.Minute), Partial: true}, now.Add(-2 * time.Minute)},
		{"long pause", time.Time{}, checkpoint{Last: now.Add(-72 * time.Hour)}, now.Add(-24 * time.Hour)},
	}
	for _, tc := range cases {
		if got := from(now, tc.since, tc.cp, DefaultOverlap, DefaultStart); !got.Equal(tc.want) {
			t.Errorf("%s: from %v, want %v", tc.name, got, tc.want)
		}
	}
	if cp := decodeCheckpoint([]byte(`garbage`)); !cp.Last.IsZero() {
		t.Error("garbage checkpoint read")
	}
	seen := map[string]int64{}
	for i := 0; i < maxSeen+10; i++ {
		seen[fmt.Sprint(i)] = now.Unix() + int64(i)
	}
	if got := remember(seen, nil, now); len(got) != maxSeen || got["0"] != 0 || got[fmt.Sprint(maxSeen+9)] == 0 {
		t.Errorf("remember kept %d, oldest kept %v", len(got), got["0"] != 0)
	}
}

// stubLogs is a FilterAPI over CloudTrail records.
type stubLogs struct {
	events []types.FilteredLogEvent
	calls  []cloudwatchlogs.FilterLogEventsInput
}

func (s *stubLogs) FilterLogEvents(_ context.Context, in *cloudwatchlogs.FilterLogEventsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.FilterLogEventsOutput, error) {
	s.calls = append(s.calls, *in)
	out := &cloudwatchlogs.FilterLogEventsOutput{}
	for _, e := range s.events {
		ts := aws.ToInt64(e.Timestamp)
		if ts < aws.ToInt64(in.StartTime) || ts > aws.ToInt64(in.EndTime) {
			continue
		}
		if aws.ToString(in.FilterPattern) == LogsFilterPattern && !strings.Contains(aws.ToString(e.Message), `"readOnly":false`) {
			continue
		}
		out.Events = append(out.Events, e)
	}
	return out, nil
}

func logEvent(id string, at time.Time, msg string) types.FilteredLogEvent {
	return types.FilteredLogEvent{EventId: aws.String(id), Timestamp: aws.Int64(at.UnixMilli()), LogStreamName: aws.String("123456789012_CloudTrail_us-east-1_1"), Message: aws.String(msg)}
}

func TestLogsModeDedupesAndResumes(t *testing.T) {
	stub := &stubLogs{events: []types.FilteredLogEvent{
		logEvent("c1", t0.Add(-50*time.Minute), rec("ev-1", t0.Add(-50*time.Minute), "CreateSecurityGroup", "ec2.amazonaws.com", false, "")),
		logEvent("c2", t0.Add(-10*time.Minute), rec("ev-2", t0.Add(-10*time.Minute), "RevokeSecurityGroupIngress", "ec2.amazonaws.com", false, `"requestParameters":{"groupId":"sg-0123456789abcdef0"}`)),
		logEvent("c3", t0.Add(-8*time.Minute), rec("ev-ro", t0.Add(-8*time.Minute), "DescribeInstances", "ec2.amazonaws.com", true, "")),
		logEvent("c4", t0.Add(-7*time.Minute), `{"readOnly":false,"note":"not a CloudTrail record"}`),
	}}
	clk := &clock{t: t0}
	counts := map[string]int{}
	r := &cloudwatch.RawReader{API: stub, LogGroup: "aws-cloudtrail-logs-123456789012"}
	s, err := NewLogs(r, LogsOptions{Now: clk.Now, OnResult: func(res string, n int) { counts[res] += n }})
	if err != nil {
		t.Fatal(err)
	}
	if s.Name() != "logs" || r.FilterPattern != "{ $.readOnly IS FALSE }" {
		t.Errorf("name %s, pattern %q", s.Name(), r.FilterPattern)
	}
	evs, cpb, err := s.Changes(context.Background(), time.Time{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(evs); got != "ev-1,ev-2" {
		t.Errorf("first poll = %s", got)
	}
	if evs[1].Resources[0] != "sg-0123456789abcdef0" || counts[ResultUnparsed] != 1 {
		t.Errorf("event %+v, results %v", evs[1], counts)
	}
	if got := aws.ToInt64(stub.calls[0].StartTime); got != t0.Add(-time.Hour).UnixMilli() {
		t.Errorf("first start %v", time.UnixMilli(got).UTC())
	}

	// The second poll re-reads the overlap; the late ev-late arrives.
	stub.events = append(stub.events,
		logEvent("c5", t0.Add(-9*time.Minute), rec("ev-late", t0.Add(-9*time.Minute), "ModifyInstanceAttribute", "ec2.amazonaws.com", false, "")),
		logEvent("c6", t0.Add(time.Minute), rec("ev-3", t0.Add(time.Minute), "ModifyInstanceAttribute", "ec2.amazonaws.com", false, "")))
	clk.Set(t0.Add(2 * time.Minute))
	evs, cpb, err = s.Changes(context.Background(), time.Time{}, cpb)
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(evs); got != "ev-late,ev-3" || counts[ResultDuplicate] != 1 {
		t.Errorf("second poll = %s, results %v", got, counts)
	}
	if got := aws.ToInt64(stub.calls[1].StartTime); got != t0.Add(-15*time.Minute).UnixMilli() {
		t.Errorf("second start %v", time.UnixMilli(got).UTC())
	}

	// Stopped at the reader's cap: the next poll resumes at the last event
	// read, without the overlap.
	r.MaxEvents = 1
	clk.Set(t0.Add(30 * time.Minute))
	evs, cpb, _ = s.Changes(context.Background(), time.Time{}, nil)
	var cp checkpoint
	_ = json.Unmarshal(cpb, &cp)
	if len(evs) != 1 || !cp.Partial || !cp.Last.Equal(t0.Add(-10*time.Minute)) {
		t.Errorf("capped poll: %s, checkpoint %s", ids(evs), cpb)
	}
	_, _, _ = s.Changes(context.Background(), time.Time{}, cpb)
	if got := aws.ToInt64(stub.calls[len(stub.calls)-1].StartTime); got != cp.Last.UnixMilli() {
		t.Errorf("resumed at %v, want %v", time.UnixMilli(got).UTC(), cp.Last)
	}
	if got := s.Probe(context.Background()); got != "ok" {
		t.Errorf("probe = %q", got)
	}
	if _, err := NewLogs(&cloudwatch.RawReader{}, LogsOptions{}); err == nil {
		t.Error("a reader without API accepted")
	}
}
