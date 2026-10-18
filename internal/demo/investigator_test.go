package demo

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/investigate"
)

type demoRun struct {
	investigate.Investigation
	Outcome    string `json:"outcome"`
	Confidence string `json:"confidence"`
}

// waitRun polls a run until it is no longer running.
func waitRun(t *testing.T, h http.Handler, incident, id string) demoRun {
	t.Helper()
	path := "/api/v1/incidents/" + url.PathEscape(incident) + "/investigations/" + id
	deadline := time.Now().Add(30 * time.Second)
	for {
		var run demoRun
		getJSON(t, h, path, &run)
		if run.Status != investigate.Running {
			return run
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s still running after 30s: %+v", id, run.Steps)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Every demo incident's investigation runs through the real service, tools
// and report validation, and completes with a report whose refs were all
// shown to the scripted model (but the one the catalog-api report cites on
// purpose).
func TestDemoInvestigations(t *testing.T) {
	srv, err := NewServerWith(t.Context(), nil, Options{InvestigatorDelay: 5 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()

	var info struct {
		Investigator *struct {
			Enabled                 bool
			Provider, Model, Effort string
			PerHour                 int
		} `json:"investigator"`
	}
	getJSON(t, h, "/api/v1/info", &info)
	if inv := info.Investigator; inv == nil || !inv.Enabled || inv.Provider != DemoProvider || inv.Model != DemoModel || inv.Effort != "high" {
		t.Fatalf("/info.investigator = %+v", info.Investigator)
	}

	var list demoIncidentList
	getJSON(t, h, "/api/v1/incidents", &list)
	if len(list.Items) != 3 {
		t.Fatalf("%d incidents", len(list.Items))
	}
	wantTools := map[string][]string{
		"checkout-web":    {investigate.ToolGetMetricSeries, investigate.ToolGetLogs, investigate.ToolGetK8sEvents, investigate.ToolSubmitReport},
		"recommendations": {investigate.ToolGetLogs, investigate.ToolGetK8sEvents, investigate.ToolGetMetricSeries, investigate.ToolSubmitReport},
		"catalog-api":     {investigate.ToolGetLogs, investigate.ToolGetMetricSeries, investigate.ToolGetK8sEvents, investigate.ToolSubmitReport},
	}
	for _, in := range list.Items {
		t.Run(in.Subject.Name, func(t *testing.T) {
			base := "/api/v1/incidents/" + url.PathEscape(in.ID) + "/investigations"
			rec := postJSON(t, h, base, "")
			code, body := rec.Code, rec.Body.Bytes()
			if code != http.StatusAccepted {
				t.Fatalf("POST = %d %s", code, body)
			}
			var start struct {
				Investigation demoRun `json:"investigation"`
				Cached        bool    `json:"cached"`
			}
			if err := json.Unmarshal(body, &start); err != nil || start.Investigation.Status != investigate.Running || start.Cached {
				t.Fatalf("start = %s (%v)", body, err)
			}
			run := waitRun(t, h, in.ID, start.Investigation.ID)
			var pretty bytes.Buffer
			b, _ := json.Marshal(run)
			_ = json.Indent(&pretty, b, "", "  ")
			t.Logf("%s:\n%s", in.Subject.Name, pretty.String())

			if run.Status != investigate.Completed || run.Report == nil || run.Provider != DemoProvider || run.Model != DemoModel {
				t.Fatalf("run = %s, %q, report %v", run.Status, run.Error, run.Report != nil)
			}
			var tools []string
			for _, s := range run.Steps {
				if s.Kind == investigate.StepTool {
					tools = append(tools, s.Tool)
					if s.Result != investigate.ResultOK {
						t.Errorf("step %q: %s", s.Text, s.Result)
					}
				}
			}
			if strings.Join(tools, ",") != strings.Join(wantTools[in.Subject.Name], ",") {
				t.Errorf("tools = %v, want %v", tools, wantTools[in.Subject.Name])
			}
			rep := run.Report
			wantUnverified := ""
			if in.Subject.Name == "catalog-api" {
				wantUnverified = unverifiedDemoRef
			}
			if strings.Join(rep.Unverified, ",") != wantUnverified {
				t.Errorf("unverified = %v, want %q", rep.Unverified, wantUnverified)
			}
			// The root cause, each factor and each timeline entry cite
			// evidence the run showed; the evidence index covers them all.
			index := map[string]bool{}
			for _, e := range run.Evidence {
				index[e.Ref] = true
			}
			cited := append([]string{}, rep.RootCause.Evidence...)
			if len(rep.RootCause.Evidence) < 3 {
				t.Errorf("root cause cites %v", rep.RootCause.Evidence)
			}
			for _, f := range rep.ContributingFactors {
				cited = append(cited, f.Evidence...)
			}
			if len(rep.Timeline) < 4 {
				t.Errorf("timeline has %d entries", len(rep.Timeline))
			}
			for _, e := range rep.Timeline {
				if len(e.Evidence) == 0 {
					t.Errorf("timeline entry %q cites nothing", e.Event)
				}
				cited = append(cited, e.Evidence...)
			}
			kinds := map[string]bool{}
			for _, ref := range cited {
				if ref == wantUnverified {
					continue
				}
				if !index[ref] {
					t.Errorf("cited ref %s is not in the evidence index", ref)
				}
				k, _, _ := strings.Cut(ref, ":")
				kinds[k] = true
			}
			for _, k := range []string{"signal", "log", "metric"} {
				if !kinds[k] {
					t.Errorf("no %s ref cited (kinds %v)", k, kinds)
				}
			}
			removed := 0
			for _, c := range rep.SuggestedChecks {
				switch {
				case c.Command == "":
					removed++
					if !strings.HasSuffix(c.Description, "(command removed: not read-only)") {
						t.Errorf("removed check %q", c.Description)
					}
				case strings.Contains(c.Description, "command removed"):
					t.Errorf("check %q keeps its command %q", c.Description, c.Command)
				}
			}
			wantRemoved := 1
			if in.Subject.Name == "catalog-api" {
				wantRemoved = 0
			}
			if removed != wantRemoved || len(rep.SuggestedChecks) < 2 {
				t.Errorf("%d checks, %d removed, want %d removed", len(rep.SuggestedChecks), removed, wantRemoved)
			}
			if run.Turns != 3 || run.ToolCalls != 4 || run.Usage.Total() == 0 || run.Outcome != rep.Status || run.Confidence != rep.RootCause.Confidence {
				t.Errorf("turns %d, tool calls %d, usage %+v, outcome %q/%q", run.Turns, run.ToolCalls, run.Usage, run.Outcome, run.Confidence)
			}

			var runs struct {
				Items  []investigate.Summary `json:"items"`
				Hidden int                   `json:"hidden"`
			}
			getJSON(t, h, base, &runs)
			if len(runs.Items) != 1 || runs.Items[0].ID != run.ID || runs.Items[0].Outcome != rep.Status {
				t.Errorf("list = %+v", runs)
			}
		})
	}

	// The resolved incident's input does not change, so a second start is
	// answered from the first run; fresh runs the model again.
	var cat string
	for _, in := range list.Items {
		if in.Subject.Name == "catalog-api" {
			cat = in.ID
		}
	}
	base := "/api/v1/incidents/" + url.PathEscape(cat) + "/investigations"
	rec := postJSON(t, h, base, "{}")
	code, body := rec.Code, rec.Body.Bytes()
	var again struct {
		Investigation demoRun `json:"investigation"`
		Cached        bool    `json:"cached"`
	}
	if err := json.Unmarshal(body, &again); err != nil || code != http.StatusOK || !again.Cached || again.Investigation.CachedFrom == "" ||
		again.Investigation.Status != investigate.Completed {
		t.Fatalf("second start = %d %s", code, body)
	}
	rec = postJSON(t, h, base, `{"fresh":true}`)
	code, body = rec.Code, rec.Body.Bytes()
	again.Cached = false
	if err := json.Unmarshal(body, &again); err != nil || code != http.StatusAccepted || again.Cached {
		t.Fatalf("fresh start = %d %s", code, body)
	}
	if run := waitRun(t, h, cat, again.Investigation.ID); run.Status != investigate.Completed {
		t.Errorf("fresh run = %s %q", run.Status, run.Error)
	}
}
