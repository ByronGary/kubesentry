package cwfake_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/cloudwatch/cwfake"
)

var start = time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)

func TestRangeAndMessages(t *testing.T) {
	f := cwfake.New(cwfake.Options{Seed: 3, Start: start, Rate: 7, Events: 1_000_000})
	// Range is exact at the boundaries.
	for _, c := range []struct{ from, to time.Time }{
		{start, start}, {start.Add(-time.Hour), start.Add(time.Second)}, {start.Add(1234567 * time.Microsecond), start.Add(time.Hour)},
		{start.Add(100 * 24 * time.Hour), start.Add(101 * 24 * time.Hour)},
	} {
		lo, hi := f.Range(c.from, c.to)
		if lo < hi && (f.Time(lo).Before(c.from) || f.Time(hi-1).After(c.to)) {
			t.Errorf("Range(%s, %s) = [%d,%d) includes events outside it", c.from, c.to, lo, hi)
		}
		if lo > 0 && lo < 1_000_000 && !f.Time(lo-1).Before(c.from) {
			t.Errorf("Range(%s, %s) misses event %d", c.from, c.to, lo-1)
		}
		if hi < 1_000_000 && !f.Time(hi).After(c.to) {
			t.Errorf("Range(%s, %s) misses event %d", c.from, c.to, hi)
		}
	}
	if lo, hi := f.Range(start, start.Add(365*24*time.Hour)); lo != 0 || hi != 1_000_000 {
		t.Errorf("full range = [%d,%d)", lo, hi)
	}

	// Every message is one audit event, deterministic, matching its index.
	ids := map[string]bool{}
	for _, i := range []int64{0, 1, 2, 999_999, 123_456} {
		m := f.Message(i)
		if !bytes.Equal(m, cwfake.New(cwfake.Options{Seed: 3, Start: start, Rate: 7}).Message(i)) {
			t.Errorf("message %d is not deterministic", i)
		}
		events, err := audit.Parse(bytes.NewReader(m))
		if err != nil || len(events) != 1 {
			t.Fatalf("message %d: %d events, %v: %s", i, len(events), err, m)
		}
		e := events[0]
		if e.AuditID != f.AuditID(i) || !e.Time.Equal(f.Time(i)) || e.Verb == "" || e.Username == "" {
			t.Errorf("message %d decodes to %+v", i, e)
		}
		ids[e.AuditID] = true
	}
	if len(ids) != 5 {
		t.Error("auditIDs collide")
	}
}

func post(t *testing.T, url string, body map[string]any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	req.Header.Set("X-Amz-Target", "Logs_20140328.FilterLogEvents")
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=test")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestServerPagesAndErrors(t *testing.T) {
	now := start.Add(time.Hour)
	srv, f := cwfake.NewServer(cwfake.Options{Start: start, Rate: 2, Events: 1000, PageSize: 64, DuplicateFraction: 0.1, Now: func() time.Time { return now }})
	defer srv.Close()
	q := map[string]any{"logGroupName": "/aws/eks/fake/cluster", "logStreamNamePrefix": "kube-apiserver-audit",
		"startTime": start.UnixMilli(), "endTime": start.Add(time.Hour).UnixMilli()}
	seen := map[string]bool{}
	audits := map[string]bool{}
	for pages := 0; ; pages++ {
		code, out := post(t, srv.URL, q)
		if code != 200 {
			t.Fatalf("status %d: %v", code, out)
		}
		for _, e := range out["events"].([]any) {
			ev := e.(map[string]any)
			id := ev["eventId"].(string)
			if seen[id] {
				t.Fatalf("eventId %s served twice", id)
			}
			seen[id] = true
			if !strings.HasPrefix(ev["logStreamName"].(string), "kube-apiserver-audit-") {
				t.Fatalf("stream %v ignores the prefix", ev["logStreamName"])
			}
			var w struct{ AuditID string }
			json.Unmarshal([]byte(ev["message"].(string)), &w)
			audits[w.AuditID] = true
		}
		tok, _ := out["nextToken"].(string)
		if tok == "" {
			break
		}
		q["nextToken"] = tok
		if pages > 100 {
			t.Fatal("paging does not end")
		}
	}
	dups := 0
	for i := int64(0); i < 1000; i++ {
		if f.Duplicated(i) {
			dups++
		}
	}
	if len(audits) != 1000 || len(seen) != 1000+dups {
		t.Errorf("served %d log events for %d audit events; want %d and 1000", len(seen), len(audits), 1000+dups)
	}

	code, out := post(t, srv.URL, map[string]any{"logGroupName": "/aws/eks/other/cluster"})
	if code != 400 || out["__type"] != "ResourceNotFoundException" {
		t.Errorf("unknown group: %d %v", code, out)
	}
	q["nextToken"] = "garbage"
	if code, out := post(t, srv.URL, q); code != 400 || out["__type"] != "InvalidParameterException" {
		t.Errorf("bad token: %d %v", code, out)
	}
}
