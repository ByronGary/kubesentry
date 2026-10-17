package investigate_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/incidents"
	"github.com/ByronGary/kubesentry/internal/investigate"
	"github.com/ByronGary/kubesentry/internal/model"
)

type digestJSON struct {
	Schema    string            `json:"schema"`
	Now       string            `json:"now"`
	Omitted   map[string]string `json:"omitted"`
	Truncated map[string]string `json:"truncated"`
	Totals    map[string]int    `json:"totals"`
	Incident  struct {
		ID    string   `json:"id"`
		Pods  []string `json:"pods"`
		Types []string `json:"types"`
	} `json:"incident"`
	Triggers      []map[string]any `json:"triggers"`
	TriggerGroups []map[string]any `json:"trigger_groups"`
	Context       []map[string]any `json:"context"`
	ContextGroups []struct {
		Type  string         `json:"type"`
		Count int            `json:"count"`
		First map[string]any `json:"first"`
		Last  map[string]any `json:"last"`
	} `json:"context_groups"`
	Metrics []struct {
		Ref    string  `json:"ref"`
		Max    float64 `json:"max"`
		PeakAt string  `json:"peak_at"`
		Bucket *struct {
			Step int64      `json:"step_s"`
			Max  []*float64 `json:"max"`
		} `json:"max_per_bucket"`
	} `json:"metrics"`
	Events       []map[string]any `json:"events"`
	LogTemplates []struct {
		Ref      string `json:"ref"`
		Template string `json:"template"`
		Level    string `json:"level"`
		Count    int    `json:"count"`
		Samples  []struct {
			Time string `json:"time"`
			Text string `json:"text"`
		} `json:"samples"`
	} `json:"log_templates"`
	Audit      []map[string]any `json:"audit"`
	CloudTrail []map[string]any `json:"cloudtrail"`
}

func parseDigest(t *testing.T, data []byte) digestJSON {
	t.Helper()
	var d digestJSON
	if err := json.Unmarshal(data, &d); err != nil {
		t.Fatalf("digest is not valid JSON: %v", err)
	}
	return d
}

func TestDigestOfAnIncident(t *testing.T) {
	src := source()
	b := bundleOf(t, src, allAccess)
	investigate.GateBundle(b, allAccess)
	data, led := investigate.Digest(b, 0)
	d := parseDigest(t, data)
	if d.Schema != investigate.DigestSchema || d.Now != "2026-10-15T12:40:00Z" || d.Incident.ID != "inc-1" || len(d.Triggers) != 2 {
		t.Fatalf("digest header or triggers: %s", data)
	}
	if d.Triggers[0]["ref"] != "signal:mem:api-1" || d.Triggers[1]["ref"] != "signal:oom:api-1" {
		t.Errorf("triggers in time order: %v", d.Triggers)
	}
	if len(d.Context) != 3 || d.Context[0]["ref"] != "signal:cloudtrail:ct1" {
		t.Errorf("context in time order: %v", d.Context)
	}
	if len(d.Metrics) != 1 || d.Metrics[0].Ref != "metric:memory:api-1/app" || d.Metrics[0].Max != 512e6 || d.Metrics[0].PeakAt != "2026-10-15T12:00:00Z" {
		t.Errorf("metrics: %+v", d.Metrics)
	}
	if len(d.LogTemplates) != 3 || d.LogTemplates[0].Template != "cache grew to {n} entries" || d.LogTemplates[0].Count != 2 ||
		d.LogTemplates[0].Level != "error" || d.LogTemplates[1].Level != "warn" {
		t.Errorf("log templates: %+v", d.LogTemplates)
	}
	// Events: warnings first; the node's event is there (with node access),
	// the other namespace's is not.
	if len(d.Events) != 3 || d.Events[0]["reason"] != "BackOff" || d.Events[0]["count"] != float64(7) ||
		d.Events[1]["reason"] != "SystemOOM" || d.Events[2]["reason"] != "Pulled" {
		t.Errorf("events: %v", d.Events)
	}
	// Audit keeps the write, drops the read; no IPs or user agents anywhere.
	if len(d.Audit) != 1 || d.Audit[0]["ref"] != "audit:a1" {
		t.Errorf("audit: %v", d.Audit)
	}
	if len(d.CloudTrail) != 1 || d.CloudTrail[0]["ref"] != "cloudtrail:ct1" || d.CloudTrail[0]["raw"] != nil {
		t.Errorf("cloudtrail: %v", d.CloudTrail)
	}
	for _, leak := range []string{"198.51.100", "kubectl/v1.36", "aws-cli", "sourceIP", "userAgent", "sourceIPAddress"} {
		if strings.Contains(string(data), leak) {
			t.Errorf("digest carries %q", leak)
		}
	}
	// Every ref shown is in the ledger.
	for _, ref := range []string{"signal:oom:api-1", "signal:deploy:api:2", "metric:memory:api-1/app", "event:e1", "logtpl:1", "audit:a1", "cloudtrail:ct1"} {
		if !led.Has(ref) {
			t.Errorf("ledger lacks %s", ref)
		}
		if !strings.Contains(string(data), `"ref":"`+ref+`"`) {
			t.Errorf("digest lacks %s", ref)
		}
	}
	if e, _ := led.Get("event:e1"); e.Kind != "event" || e.Object != "Pod/api-1" || !strings.HasPrefix(e.Snippet, "BackOff: ") {
		t.Errorf("ledger entry %+v", e)
	}
}

// Without access, sections and their signals are left out, and named.
func TestDigestGatedByAccess(t *testing.T) {
	src := source()
	b := bundleOf(t, src, investigate.Access{})
	investigate.GateBundle(b, investigate.Access{})
	data, _ := investigate.Digest(b, 0)
	d := parseDigest(t, data)
	for _, s := range []string{"logs", "audit", "cloudtrail", "nodes"} {
		if d.Omitted[s] != "forbidden" {
			t.Errorf("omitted[%s] = %q", s, d.Omitted[s])
		}
	}
	if len(d.LogTemplates) != 0 || len(d.Audit) != 0 || len(d.CloudTrail) != 0 || len(d.Context) != 1 || len(d.Events) != 2 {
		t.Errorf("gated digest: %s", data)
	}
	for _, typ := range d.Incident.Types {
		if typ == incidents.TypeAuditChange || typ == incidents.TypeCloudTrailChange {
			t.Errorf("incident types keep %s", typ)
		}
	}
}

// adversarial is an incident at every cap: 500 signals, 2,000 log lines of
// 2 KiB, 2,000 events, 1,000 audit events, 36 series.
func adversarial(triggers int) *incidents.Bundle {
	in := incidents.Incident{ID: "big", Subject: apiSubject, Title: strings.Repeat("t", 600), State: incidents.Open, Start: t0,
		LastSignal: at(10), Severity: incidents.Critical, PeakSeverity: incidents.Critical}
	for i := 0; i < 50; i++ {
		in.Pods = append(in.Pods, fmt.Sprintf("api-%02d", i))
	}
	// Built directly, past the bundle's own caps, to load the digest.
	b := &incidents.Bundle{BundleHeader: incidents.BundleHeader{Schema: incidents.BundleSchema, GeneratedAt: at(120), Cluster: "prod",
		Incident: in, Window: incidents.BundleWindow{From: at(-5), To: at(120)}}}
	types := []string{incidents.TypeDeploy, incidents.TypeScale, incidents.TypeAuditChange, incidents.TypeKubeEvent, incidents.TypeLogErrors}
	for i := 0; i < 500; i++ {
		s := incidents.Signal{ID: fmt.Sprintf("s%03d", i), Type: types[i%len(types)], Role: incidents.Context, Start: at(float64(i) / 5),
			Subject: apiSubject, Object: model.ObjectRef{Kind: "Pod", Namespace: "shop", Name: in.Pods[i%50]}, Title: strings.Repeat("x", 400),
			Attrs: map[string]string{}}
		for k := 0; k < 16; k++ {
			s.Attrs[fmt.Sprintf("k%02d", k)] = strings.Repeat("v", 500)
		}
		if i < triggers {
			trig := []string{incidents.TypeOOMKill, incidents.TypeRestart, incidents.TypeCrashLoop, incidents.TypeEviction, incidents.TypeAlert,
				incidents.TypeMemorySpike, incidents.TypeRequestSpike, incidents.TypeErrorRate, incidents.TypeKubeEvent, incidents.TypeLogErrors}
			s.Role, s.Severity, s.Type = incidents.Trigger, incidents.Critical, trig[i%len(trig)]
		}
		b.Signals = append(b.Signals, incidents.BundleSignalOf(s))
	}
	line := strings.Repeat("y", 2000)
	for i := 0; i < 2000; i++ {
		b.Logs = append(b.Logs, incidents.LogLine{Time: at(float64(i) / 20), Pod: in.Pods[i%50], Container: "app", Level: []string{"error", "info"}[i%2],
			Text: fmt.Sprintf("variant %c%c failed %s", 'a'+i%26, 'a'+(i/26)%26, line)})
	}
	for i := 0; i < 2000; i++ {
		b.Events = append(b.Events, incidents.BundleEventOf(kev(fmt.Sprintf("u%04d", i), "shop", "Pod", in.Pods[i%50], []string{"Warning", "Normal"}[i%2],
			fmt.Sprintf("Reason%d", i%60), strings.Repeat("m", 900), at(float64(i)/20), at(float64(i)/20))))
	}
	for i := 0; i < 1000; i++ {
		b.Audit = append(b.Audit, audit.Event{AuditID: fmt.Sprint("a", i), Time: at(float64(i) / 10), Verb: "patch", Username: "u" + fmt.Sprint(i%7),
			Resource: "deployments", Namespace: "shop", Name: "api", Tags: []string{"rbac"}, SourceIPs: []string{"203.0.113.5"}})
	}
	for i := 0; i < 500; i++ {
		b.CloudTrail = append(b.CloudTrail, incidents.BundleCloudTrail{ID: fmt.Sprint("ct", i), Time: at(float64(i) / 5), Name: "PutRolePolicy",
			Source: "iam.amazonaws.com", Actor: strings.Repeat("arn", 100), Resources: []string{"r1", "r2", "r3", "r4", "r5", "r6", "r7"}, Raw: line})
	}
	for m, metric := range []string{"memory", "requests", "errors"} {
		for k := 0; k < 12; k++ {
			s := incidents.Series{Metric: metric, Label: fmt.Sprintf("api-%02d/app", k), Unit: "bytes"}
			for i := 0; i < 500; i++ {
				s.Points = append(s.Points, [2]float64{float64(at(float64(i) / 4).UnixMilli()), float64(m*1000 + k*10 + i%7)})
			}
			b.Metrics = append(b.Metrics, s)
		}
	}
	return b
}

// An adversarial bundle fits any budget as valid JSON, and the triggers
// are always kept.
func TestDigestFitsAdversarialBundles(t *testing.T) {
	for _, c := range []struct {
		triggers, budget int
	}{{20, 0}, {20, 16 << 10}, {5, 8 << 10}, {500, 0}, {500, 8 << 10}, {500, 4 << 10}} {
		t.Run(fmt.Sprintf("%d triggers in %d bytes", c.triggers, c.budget), func(t *testing.T) {
			b := adversarial(c.triggers)
			data, led := investigate.Digest(b, c.budget)
			budget := c.budget
			if budget == 0 {
				budget = investigate.DefaultDigestBytes
			}
			if len(data) > budget {
				t.Fatalf("digest is %d bytes, budget %d", len(data), budget)
			}
			d := parseDigest(t, data)
			if d.Totals["log_lines"] != 2000 || d.Totals["events"] != 2000 {
				t.Errorf("totals %v", d.Totals)
			}
			if c.triggers <= 20 {
				if len(d.Triggers) != c.triggers {
					t.Fatalf("%d of %d triggers kept: %v", len(d.Triggers), c.triggers, d.Truncated)
				}
				for i := 0; i < c.triggers; i++ {
					ref := fmt.Sprintf("signal:s%03d", i)
					if !led.Has(ref) || !strings.Contains(string(data), `"ref":"`+ref+`"`) {
						t.Errorf("trigger %s missing", ref)
					}
				}
			} else if len(d.Triggers)+len(d.TriggerGroups) == 0 {
				t.Errorf("no triggers at all: %v", d.Truncated)
			}
			if d.Truncated["log_templates"] == "" && len(d.LogTemplates) < 40 {
				t.Errorf("log templates cut without saying so: %v", d.Truncated)
			}
			if c.triggers < 500 && (len(d.Context) > 0 || d.Truncated["context"] == "") {
				t.Errorf("context not condensed: %v", d.Truncated)
			}
			if d.Totals["cloudtrail"] != 500 || d.Totals["audit"] != 1000 || d.Totals["metric_series"] != 36 {
				t.Errorf("totals %v", d.Totals)
			}
			for _, g := range d.ContextGroups {
				if g.Count == 0 || g.First["ref"] == nil {
					t.Errorf("group %+v", g)
				}
			}
			if led.Len() == 0 {
				t.Error("empty ledger")
			}
		})
	}
}

// A spike survives the 30-bucket downsample, and the coarser ones the fit
// loop falls back to.
func TestDigestPeaksSurvive(t *testing.T) {
	src := source()
	src.series[0].Points = nil
	for i := 0; i < 240; i++ {
		v := 100.0
		if i == 137 {
			v = 900
		}
		src.series[0].Points = append(src.series[0].Points, [2]float64{float64(at(-5).Add(time.Duration(i) * 8 * time.Second).UnixMilli()), v})
	}
	// Shrink the budget until the fit loop has halved the downsample.
	seen := map[int]bool{}
	full, _ := investigate.Digest(bundleOf(t, src, allAccess), 0)
	for budget := len(full); budget > 600 && len(seen) < 3; budget -= 20 {
		data, _ := investigate.Digest(bundleOf(t, src, allAccess), budget)
		if len(data) > budget && budget < len(full) {
			t.Fatalf("budget %d: %d bytes", budget, len(data))
		}
		d := parseDigest(t, data)
		if len(d.Metrics) != 1 || d.Metrics[0].Bucket == nil {
			break
		}
		m := d.Metrics[0]
		if m.Max != 900 || m.PeakAt != at(-5).Add(137*8*time.Second).Format(time.RFC3339) {
			t.Errorf("budget %d: stats %+v", budget, m)
		}
		peak := 0.0
		for _, v := range m.Bucket.Max {
			if v != nil && *v > peak {
				peak = *v
			}
		}
		if peak != 900 {
			t.Errorf("budget %d: the downsample (%d buckets) lost the peak: %v", budget, len(m.Bucket.Max), m.Bucket.Max)
		}
		seen[len(m.Bucket.Max)] = true
	}
	if !seen[30] || !seen[15] {
		t.Errorf("bucket counts seen: %v", seen)
	}
}

// Lines that differ only in numbers, IDs, addresses and times share a
// template; the samples are the lines nearest a trigger.
func TestLogTemplatesGroupVariants(t *testing.T) {
	for in, want := range map[string]string{
		"2026-10-15T12:00:01.123Z connect to 10.0.0.5:5432 failed after 120ms": "{ts} connect to {ip} failed after {n}ms",
		"request 3f2a8c1e-9b7d-4e2a-8f1c-0d9e8b7a6c5d took 0x1f3a":             "request {uuid} took {hex}",
		"E1015 12:00:00.000000 1 controller.go:42] sync failed":                "{ts} {ts} {n} controller.go:{n}] sync failed",
		"digest deadbeefcafe0123 at fe80::1ff:fe23:4567:890a":                  "digest {hex} at {ip}",
		"plain   words\twith space":                                            "plain words with space",
	} {
		if got := investigate.LogTemplate(in); got != want {
			t.Errorf("%q → %q, want %q", in, got, want)
		}
	}
	src := source()
	src.logs = nil
	for i := 0; i < 30; i++ {
		src.logs = append(src.logs, incidents.LogLine{Time: at(float64(i) - 15), Pod: fmt.Sprintf("api-%d", i%2+1), Container: "app", Level: "info",
			Text: fmt.Sprintf("GET /orders/%d 200 %dms from 10.1.0.%d", i*7, i, i)})
	}
	src.logs = append(src.logs, incidents.LogLine{Time: at(10), Pod: "api-1", Container: "app", Level: "error", Text: "panic: nil map"})
	data, led := investigate.Digest(bundleOf(t, src, allAccess), 0)
	d := parseDigest(t, data)
	if len(d.LogTemplates) != 2 || d.LogTemplates[0].Level != "error" || d.LogTemplates[1].Count != 30 ||
		d.LogTemplates[1].Template != "GET /orders/{n} {n} {n}ms from {ip}" {
		t.Fatalf("templates: %+v", d.LogTemplates)
	}
	// The triggers are at t0-1m and t0: the samples are the lines then
	// (i = 14 and 15), in time order.
	s := d.LogTemplates[1].Samples
	if len(s) != 2 || s[0].Time != "2026-10-15T11:59:00Z" || s[1].Time != "2026-10-15T12:00:00Z" {
		t.Errorf("samples: %+v", s)
	}
	if !led.Has("logtpl:1") || !led.Has("logtpl:2") || led.Has("logtpl:3") {
		t.Error("template refs")
	}
}

// The cache key ignores when the digest was taken.
func TestDigestStableWithoutNow(t *testing.T) {
	src := source()
	b1 := bundleOf(t, src, allAccess)
	b2 := bundleOf(t, src, allAccess)
	b2.GeneratedAt = b2.GeneratedAt.Add(time.Minute)
	d1, s1, _ := investigate.DigestStable(&investigate.Egress{}, b1, 0)
	d2, s2, _ := investigate.DigestStable(&investigate.Egress{}, b2, 0)
	if string(d1) == string(d2) || string(s1) != string(s2) || strings.Contains(string(s1), `"now"`) {
		t.Errorf("stable digests differ or keep now:\n%s\n%s", s1, s2)
	}
	if json.Valid(s1) == false {
		t.Error("the stable digest is not valid JSON")
	}
	h := func(a investigate.Access) string { return investigate.InputHash(s1, "m", "high", a) }
	if h(allAccess) == h(investigate.Access{}) || h(allAccess) != investigate.InputHash(s2, "m", "high", allAccess) ||
		h(allAccess) == investigate.InputHash(s1, "m", "max", allAccess) {
		t.Error("the input hash does not follow the access or the effort")
	}
}
