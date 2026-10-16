package demo

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/incidents"
)

type demoIncidentList struct {
	Counts struct {
		Open, Resolved, Critical, Warning int
		ByType                            map[string]int
	} `json:"counts"`
	Items []incidents.Incident `json:"items"`
}

type demoIncidentDetail struct {
	Incident incidents.Incident        `json:"incident"`
	Window   struct{ From, To string } `json:"window"`
	Signals  []incidents.BundleSignal  `json:"signals"`
	Events   []incidents.BundleEvent   `json:"events"`
	Audit    []json.RawMessage         `json:"audit"`
	Series   []incidents.Series        `json:"series"`
	Related  []struct{ ID, Title string }
	Sources  map[string]string `json:"sources"`
}

func logJSON(t *testing.T, h http.Handler, path string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	var pretty bytes.Buffer
	_ = json.Indent(&pretty, rec.Body.Bytes(), "", "  ")
	t.Logf("GET %s (%d bytes):\n%s", path, rec.Body.Len(), pretty.String())
}

func TestDemoIncidents(t *testing.T) {
	srv, err := NewServer(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()
	logJSON(t, h, "/api/v1/incidents")

	var list demoIncidentList
	getJSON(t, h, "/api/v1/incidents", &list)
	byName := map[string]incidents.Incident{}
	for _, in := range list.Items {
		byName[in.Subject.Name] = in
	}
	web, recs, cat := byName["checkout-web"], byName["recommendations"], byName["catalog-api"]
	if len(list.Items) != 3 || web.State != incidents.Open || web.PeakSeverity != incidents.Critical || recs.State != incidents.Open ||
		recs.PeakSeverity != incidents.Critical || cat.State != incidents.Resolved || cat.PeakSeverity != incidents.Warning {
		t.Fatalf("incidents = %+v", list.Items)
	}
	if list.Counts.Open != 2 || list.Counts.Resolved != 1 || list.Counts.Critical != 2 || list.Counts.Warning != 1 {
		t.Errorf("counts = %+v", list.Counts)
	}
	if web.Owner != "team-shop" || !web.Production || web.Tags["app.kubernetes.io/part-of"] != "shop" || web.Tags["service"] != "checkout-web" ||
		len(web.Pods) == 0 || len(web.Services) == 0 {
		t.Errorf("checkout-web incident = %+v", web)
	}
	// The release came 20 minutes before the spike; the logs run past it.
	if got := time.Since(web.Start).Round(time.Minute); got < 39*time.Minute || got > 41*time.Minute {
		t.Errorf("checkout-web started %s ago", got)
	}

	logJSON(t, h, "/api/v1/incidents/"+web.ID)
	var d demoIncidentDetail
	getJSON(t, h, "/api/v1/incidents/"+web.ID, &d)
	types := map[string]bool{}
	for _, s := range d.Signals {
		types[s.Type] = true
	}
	for _, typ := range []string{"deploy", "audit-change", "request-spike", "memory-spike", "k8s-event", "cloudtrail-change", "log-errors"} {
		if !types[typ] {
			t.Errorf("checkout-web lacks a %s signal: %v", typ, types)
		}
	}
	metrics := map[string]bool{}
	for _, s := range d.Series {
		metrics[s.Metric] = true
		if len(s.Points) < 20 {
			t.Errorf("series %s/%s has %d points", s.Metric, s.Label, len(s.Points))
		}
	}
	if !metrics["memory"] || !metrics["requests"] || !metrics["errors"] {
		t.Errorf("checkout-web charts = %v", metrics)
	}
	if len(d.Events) < 2 || len(d.Audit) == 0 || len(d.Related) == 0 || d.Sources["series"] != "ok" || d.Sources["cloudtrail"] != "ok" {
		t.Errorf("detail: %d events, %d audit, related %+v, sources %v", len(d.Events), len(d.Audit), d.Related, d.Sources)
	}
	var recsDetail demoIncidentDetail
	getJSON(t, h, "/api/v1/incidents/"+recs.ID, &recsDetail)
	nodeEvent := false
	for _, e := range recsDetail.Events {
		nodeEvent = nodeEvent || e.Regarding.Kind == "Node"
	}
	if !nodeEvent || recsDetail.Incident.Counts["oom-kill"] == 0 || recsDetail.Incident.Counts["crashloop"] == 0 {
		t.Errorf("recommendations: node event %v, counts %v", nodeEvent, recsDetail.Incident.Counts)
	}

	// Error logs written after the spike began, a leaked token redacted.
	var logs struct {
		Lines []incidents.LogLine `json:"lines"`
	}
	getJSON(t, h, "/api/v1/incidents/"+web.ID+"/logs?level=error", &logs)
	if len(logs.Lines) < 10 {
		t.Fatalf("checkout-web error logs = %d lines", len(logs.Lines))
	}
	after, leaked := 0, false
	for _, l := range logs.Lines {
		if l.Level != "error" {
			t.Errorf("level filter let %+v through", l)
		}
		if l.Time.After(web.Start) {
			after++
		}
		leaked = leaked || strings.Contains(l.Text, "eyJhbGci")
	}
	if after == 0 || leaked {
		t.Errorf("%d error lines after the start, token leaked %v", after, leaked)
	}
	// The resolved incident's logs run past its end, inside the lag.
	var catLogs struct {
		Lines []incidents.LogLine `json:"lines"`
	}
	getJSON(t, h, "/api/v1/incidents/"+cat.ID+"/logs?level=error", &catLogs)
	past := 0
	for _, l := range catLogs.Lines {
		if l.Time.After(*cat.End) {
			past++
		}
	}
	if len(catLogs.Lines) == 0 || past == 0 {
		t.Errorf("catalog-api: %d error lines, %d after its end", len(catLogs.Lines), past)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/incidents/"+web.ID+"/bundle?format=ndjson", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"kind":"cloudtrail"`) || !strings.Contains(rec.Body.String(), `"kind":"log"`) ||
		!strings.Contains(rec.Body.String(), `"complete":true`) {
		t.Errorf("bundle = %d %.400s", rec.Code, rec.Body.String())
	}

	// The Overview and /info.
	var info struct {
		Incidents *struct {
			Enabled, Leader bool
			Sources         map[string]string
		} `json:"incidents"`
	}
	getJSON(t, h, "/api/v1/info", &info)
	if info.Incidents == nil || !info.Incidents.Enabled || !info.Incidents.Leader || info.Incidents.Sources["logs:kubernetes"] != "ok" {
		t.Errorf("info incidents = %+v", info.Incidents)
	}
	var diag struct {
		Incidents []struct{ ID string } `json:"incidents"`
	}
	getJSON(t, h, "/api/v1/pods/prod/"+recsPod+"/diagnostics", &diag)
	if len(diag.Incidents) != 1 || diag.Incidents[0].ID != recs.ID {
		t.Errorf("recommendations pod's incidents = %+v", diag.Incidents)
	}
}
