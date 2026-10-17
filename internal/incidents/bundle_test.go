package incidents

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/model"
)

func TestRedactor(t *testing.T) {
	r, err := NewRedactor([]string{`acct-[0-9]{6}`})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct{ in, want string }{
		{"key AKIAABCDEFGHIJKLMNOP used", "key [REDACTED] used"},
		{"session ASIAZZZZZZZZZZZZZZZZ.", "session [REDACTED]."},
		{"password=hunter2 next", "password=[REDACTED] next"},
		{`{"password": "hunter2", "user": "bob"}`, `{"password": "[REDACTED]", "user": "bob"}`},
		{"client_secret: s3cr3t", "client_secret: [REDACTED]"},
		{"X-API-Key: abc123", "X-API-Key: [REDACTED]"},
		{"api_key=abc&x=1", "api_key=[REDACTED]&x=1"},
		{"Authorization: Bearer abc.def-ghi", "Authorization: Bearer [REDACTED]"},
		{"token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig", "token=[REDACTED]"},
		{"jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln here", "jwt [REDACTED] here"},
		{"db postgres://app:pa55@db:5432/x", "db postgres://[REDACTED]@db:5432/x"},
		{"-----BEGIN RSA PRIVATE KEY-----\nMIIE\nabc\n-----END RSA PRIVATE KEY-----\ndone", "[REDACTED]\ndone"},
		{"-----BEGIN PRIVATE KEY-----\nMIIE...cut", "[REDACTED]"},
		{"account acct-123456 billed", "account [REDACTED] billed"},
		{"tokens: 5, secretName: tls", "tokens: 5, secretName: tls"},
		{"nothing to see", "nothing to see"},
		// GitHub, Slack, Anthropic and Stripe tokens, named AWS secret keys.
		{"git ghp_abcdefghijklmnopqrstuvwxyz0123456789 ok", "git [REDACTED] ok"},
		{"oauth gho_ABCDEFGHIJKLMNOPQRSTuvwx done", "oauth [REDACTED] done"},
		{"pat github_pat_11ABCDEFG0123456789_abcdefghijkl end", "pat [REDACTED] end"},
		{"slack xoxb-1234567890-abcdefghij posted", "slack [REDACTED] posted"},
		{"slack xoxp-123-456-789-abcdef0123", "slack [REDACTED]"},
		{"key sk-ant-api03-AbCdEf_GhIj-KlMn used", "key [REDACTED] used"},
		{"stripe sk_live_51Habcdefghij charged", "stripe [REDACTED] charged"},
		{"aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY x", "aws_secret_access_key=[REDACTED] x"},
		{`AWS_SECRET_ACCESS_KEY: "wJalrXUtnFEMI/K7MDENG"`, `AWS_SECRET_ACCESS_KEY: "[REDACTED]"`},
		// Prefixes alone, and words that only start alike, stay.
		{"ghp_short sk_live_ xoxz-abcdefghijkl sk-ant-", "ghp_short sk_live_ xoxz-abcdefghijkl sk-ant-"},
	}
	for _, c := range cases {
		if got := r.String(c.in); got != c.want {
			t.Errorf("%q → %q, want %q", c.in, got, c.want)
		}
	}
	if (*Redactor)(nil).String("password=x") != "password=[REDACTED]" {
		t.Error("a nil redactor does not redact")
	}
	if _, err := NewRedactor([]string{"("}); err == nil {
		t.Error("a bad pattern was accepted")
	}
	if err := (Options{RedactPatterns: []string{"("}}).Validate(); err == nil {
		t.Error("Validate accepted a bad pattern")
	}
	if err := (Options{MaxRange: 25 * time.Hour}).Validate(); err == nil {
		t.Error("Validate accepted a range over 24h")
	}
}

func bundleInput() BundleInput {
	in := Incident{ID: "inc", Subject: apiSubject, Title: "api: OOM kill", State: Open, Severity: Critical, PeakSeverity: Critical,
		Start: at(0), LastSignal: at(1), Types: []string{TypeOOMKill}, Counts: map[string]int{TypeOOMKill: 1}}
	sigs := []Signal{
		{ID: "oom", Type: TypeOOMKill, Source: SourceView, Role: Trigger, Severity: Critical, Start: at(0), Subject: apiSubject,
			Object: model.ObjectRef{Kind: "Pod", Namespace: "shop", Name: "api-1"}, Title: "api-1 was OOM killed",
			Attrs: map[string]string{"message": "env DB_PASSWORD=hunter2"}},
		{ID: "audit:1", Type: TypeAuditChange, Source: SourceAudit, Role: Context, Start: at(-5), Subject: apiSubject, Title: "alice patched"},
		{ID: "cloudtrail:ct1", Type: TypeCloudTrailChange, Source: SourceCloudTrail, Role: Context, Start: at(-10), Subject: apiSubject,
			Object: model.ObjectRef{Kind: "AWS::EC2", Name: "sg-1"}, Title: "erin called ec2:AuthorizeSecurityGroupIngress",
			Attrs: map[string]string{"eventID": "ct1", "eventName": "AuthorizeSecurityGroupIngress", "eventSource": "ec2.amazonaws.com",
				"actor": "arn:aws:iam::1:user/erin", "resources": "sg-1,i-0aaa", "matched": "security-group:sg-1", "raw": "{}"}},
	}
	return BundleInput{Cluster: "prod", Incident: in, From: at(-5), To: at(10), Signals: sigs, GeneratedAt: at(11),
		Metrics: []Series{{Metric: "memory", Label: "api-1/app", Unit: "bytes", Points: [][2]float64{{1, 2}}}},
		Events: []StoredEvent{{KubeEvent: model.KubeEvent{UID: "e1", Namespace: "shop", Type: "Warning", Reason: "BackOff",
			Message: "token=abc", Count: 3, FirstSeen: at(0), LastSeen: at(1), Regarding: model.ObjectRef{Kind: "Pod", Namespace: "shop", Name: "api-1"}}}},
		Logs:  []LogLine{{Time: at(1), Pod: "api-1", Container: "app", Level: "error", Text: "login with password=hunter2", Source: "kubernetes"}},
		Audit: []audit.Event{{AuditID: "1", Time: at(-5), Verb: "patch", Username: "alice", RequestURI: "/apis/x?token=abc"}},
	}
}

func TestBundle(t *testing.T) {
	b := BuildBundle(bundleInput(), nil)
	if b.Schema != BundleSchema || !b.Complete || b.Omitted != nil || b.Truncated != nil || b.Cluster != "prod" {
		t.Fatalf("header: %+v", b.BundleHeader)
	}
	if len(b.Signals) != 3 || len(b.CloudTrail) != 1 || b.CloudTrail[0].Name != "AuthorizeSecurityGroupIngress" ||
		len(b.CloudTrail[0].Resources) != 2 || len(b.Events) != 1 || len(b.Logs) != 1 || len(b.Audit) != 1 || len(b.Metrics) != 1 {
		t.Fatalf("sections: %+v", b)
	}
	var buf bytes.Buffer
	if err := b.WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	doc := buf.String()
	for _, secret := range []string{"hunter2", "token=abc"} {
		if strings.Contains(doc, secret) {
			t.Errorf("bundle leaks %q", secret)
		}
	}
	var top map[string]any
	if err := json.Unmarshal(buf.Bytes(), &top); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"schema", "generatedAt", "incident", "window", "complete", "signals", "metrics", "events", "logs", "audit", "cloudtrail"} {
		if _, ok := top[k]; !ok {
			t.Errorf("JSON lacks %q", k)
		}
	}
	sig := top["signals"].([]any)[0].(map[string]any)
	if obj := sig["object"].(map[string]any); obj["kind"] != "Pod" || obj["name"] != "api-1" {
		t.Errorf("signal object = %v", obj)
	}
	if ev := top["events"].([]any)[0].(map[string]any); ev["reason"] != "BackOff" || ev["regarding"].(map[string]any)["kind"] != "Pod" {
		t.Errorf("event = %v", ev)
	}

	buf.Reset()
	if err := b.WriteNDJSON(&buf); err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(&buf)
	var kinds []string
	for sc.Scan() {
		var rec map[string]any
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			t.Fatalf("line %q: %v", sc.Text(), err)
		}
		if len(kinds) == 0 {
			if rec["schema"] != BundleSchema {
				t.Fatalf("first record = %v", rec)
			}
			kinds = append(kinds, "header")
			continue
		}
		kinds = append(kinds, rec["kind"].(string))
	}
	if got := strings.Join(kinds, ","); got != "header,signal,signal,signal,metric,event,log,audit,cloudtrail" {
		t.Errorf("records = %s", got)
	}
}

// Signal tags, incident tags and metric series labels are redacted too
// (a tag or label can carry anything); the input is left alone.
func TestBundleRedactsTagsAndLabels(t *testing.T) {
	in := bundleInput()
	in.Incident.Tags = map[string]string{"team": "xoxb-1234567890-incidenttag"}
	in.Signals[0].Tags = map[string]string{"app": "api", "deploy-token": "sk-ant-api03-signaltag0001"}
	in.Metrics = []Series{{Metric: "requests", Label: "api?key=ghp_abcdefghijklmnopqrstuvwxyz0123456789", Unit: "rps", Points: [][2]float64{{1, 2}}}}
	b := BuildBundle(in, nil)
	var buf bytes.Buffer
	if err := b.WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"incidenttag", "signaltag0001", "ghp_abcdefghij"} {
		if strings.Contains(buf.String(), secret) {
			t.Errorf("bundle leaks %q", secret)
		}
	}
	if b.Signals[0].Tags["app"] != "api" || b.Metrics[0].Label != "api?key=[REDACTED]" || b.Incident.Tags["team"] != Redacted {
		t.Errorf("tags %v, label %q, incident tags %v", b.Signals[0].Tags, b.Metrics[0].Label, b.Incident.Tags)
	}
	if !strings.Contains(in.Metrics[0].Label, "ghp_") || !strings.Contains(in.Signals[0].Tags["deploy-token"], "sk-ant-") {
		t.Error("the input was changed")
	}
	if (*Redactor)(nil).Series(nil) != nil {
		t.Error("Series(nil) is not nil")
	}
}

// Sections the caller may not see are omitted (with their signals); caps
// cut each section and the whole.
func TestBundleOmissionsAndCaps(t *testing.T) {
	in := bundleInput()
	in.Omitted = map[string]string{SectionAudit: "forbidden", SectionCloudTrail: "forbidden"}
	in.Audit = nil
	b := BuildBundle(in, nil)
	if b.Complete || b.Omitted[SectionAudit] != "forbidden" || len(b.CloudTrail) != 0 || len(b.Audit) != 0 {
		t.Fatalf("omitted: %+v", b.BundleHeader)
	}
	for _, s := range b.Signals {
		if s.Type == TypeAuditChange || s.Type == TypeCloudTrailChange {
			t.Errorf("signal of an omitted section: %s", s.ID)
		}
	}

	in = bundleInput()
	in.Logs = nil
	for i := 0; i < 2500; i++ {
		in.Logs = append(in.Logs, LogLine{Time: at(1), Pod: "api-1", Container: "app", Text: fmt.Sprint("line ", i)})
	}
	for i := 0; i < 2100; i++ {
		in.Events = append(in.Events, StoredEvent{KubeEvent: model.KubeEvent{UID: fmt.Sprintf("u%05d", i), Reason: "BackOff", FirstSeen: at(float64(i) / 100)}})
	}
	b = BuildBundle(in, nil)
	if len(b.Logs) != BundleMaxLogLines || !b.Truncated[SectionLogs] || len(b.Events) != BundleMaxEvents || !b.Truncated[SectionEvents] {
		t.Fatalf("caps: %d logs, %d events, truncated %v", len(b.Logs), len(b.Events), b.Truncated)
	}
	if b.Events[len(b.Events)-1].UID != "u02099" {
		t.Errorf("the newest events should stay: last %s", b.Events[len(b.Events)-1].UID)
	}

	// Big lines: the 1 MiB log cap, then the 4 MiB total.
	in = bundleInput()
	in.Logs = nil
	long := strings.Repeat("x", 4000)
	for i := 0; i < 1000; i++ {
		in.Logs = append(in.Logs, LogLine{Text: long})
	}
	b = BuildBundle(in, nil)
	if n := len(b.Logs); n >= 1000 || n < 200 || !b.Truncated[SectionLogs] {
		t.Errorf("1 MiB log cap kept %d lines", n)
	}
	in = bundleInput()
	in.Logs = nil
	for i := 0; i < 1000; i++ {
		in.Audit = append(in.Audit, audit.Event{AuditID: fmt.Sprint(i), RequestURI: "/" + long})
	}
	for i := 0; i < 2000; i++ {
		in.Events = append(in.Events, StoredEvent{KubeEvent: model.KubeEvent{UID: fmt.Sprint(i), Message: long[:1000]}})
	}
	b = BuildBundle(in, nil)
	var buf bytes.Buffer
	_ = b.WriteJSON(&buf)
	if buf.Len() > BundleMaxBytes || !b.Truncated[SectionEvents] {
		t.Errorf("total %d bytes, truncated %v", buf.Len(), b.Truncated)
	}
}
