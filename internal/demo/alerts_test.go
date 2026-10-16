package demo

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ByronGary/kubesentry/internal/alerts"
)

type demoAlertItem struct {
	alerts.Finding
	IncidentID string `json:"incidentId"`
	Actionable bool   `json:"actionable"`
}

type demoAlertList struct {
	Items  []demoAlertItem `json:"items"`
	Counts map[string]int  `json:"counts"`
}

func postJSON(t *testing.T, h http.Handler, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// The demo serves alerts in every state, tied to the incidents where they
// belong, and acknowledging and silencing work.
func TestDemoAlerts(t *testing.T) {
	srv, err := NewServer(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()

	var info struct {
		Alerts *struct {
			Enabled           bool
			Sink              string
			Leader            bool
			MaxSilenceSeconds int64
		} `json:"alerts"`
	}
	getJSON(t, h, "/api/v1/info", &info)
	if a := info.Alerts; a == nil || !a.Enabled || a.Sink != "none" || !a.Leader || a.MaxSilenceSeconds != 7*24*3600 {
		t.Fatalf("info.alerts = %+v", info.Alerts)
	}

	var list demoAlertList
	getJSON(t, h, "/api/v1/alerts", &list)
	byKey := map[string]demoAlertItem{}
	checks := map[string]bool{}
	for _, f := range list.Items {
		byKey[f.Key] = f
		checks[f.Check] = true
		if !f.Actionable {
			t.Errorf("%s is not actionable in the demo", f.Key)
		}
	}
	if list.Counts["open"] != 7 || list.Counts["acknowledged"] != 1 || list.Counts["silenced"] != 1 || list.Counts["resolved"] != 1 {
		t.Errorf("counts = %v", list.Counts)
	}
	for _, c := range []string{alerts.CheckNodePort, alerts.CheckPrivileged, alerts.CheckAuditExec, alerts.CheckAgentMissing, alerts.CheckClusterAdmin} {
		if !checks[c] {
			t.Errorf("no %s finding: %v", c, checks)
		}
	}

	var incs demoIncidentList
	getJSON(t, h, "/api/v1/incidents", &incs)
	recsIncident := ""
	for _, in := range incs.Items {
		if in.Subject.Name == "recommendations" {
			recsIncident = in.ID
		}
	}
	if recs := byKey[recsAlertKey]; recs.State != alerts.StateAcknowledged || recs.AckBy != "dave" || recs.AckAt == nil ||
		recs.IncidentID == "" || recs.IncidentID != recsIncident {
		t.Errorf("recommendations = %+v (incident %s)", recs, recsIncident)
	}
	if ix := byKey[indexerAlertKey]; ix.State != alerts.StateSilenced || ix.SilencedBy != "erin" || ix.SilenceReason == "" || ix.SilencedUntil == nil {
		t.Errorf("search-indexer = %+v", ix)
	}
	if c := byKey[certQuietKey]; !c.Quiet || c.State != alerts.StateOpen {
		t.Errorf("quiet certificate = %+v", c)
	}
	if b := byKey[bobRBACKey]; b.State != alerts.StateResolved || b.ResolvedAt == nil || b.Namespace != "" {
		t.Errorf("bob's RBAC changes = %+v", b)
	}

	// The recommendations incident lists the alert's episode.
	var d demoIncidentDetail
	getJSON(t, h, "/api/v1/incidents/"+recsIncident, &d)
	found := false
	for _, s := range d.Signals {
		found = found || (s.Type == "alert" && s.Attrs["key"] == recsAlertKey)
	}
	if !found {
		t.Errorf("the recommendations incident holds no alert signal for %s", recsAlertKey)
	}

	var acts struct {
		Items []alerts.Action `json:"items"`
	}
	getJSON(t, h, "/api/v1/alerts/actions?key="+recsAlertKey, &acts)
	if len(acts.Items) != 1 || acts.Items[0].Actor != "dave" || acts.Items[0].Action != alerts.ActionAck {
		t.Errorf("recommendations actions = %+v", acts.Items)
	}

	// The Overview's widget and the sidebar badge: open findings, the quiet
	// certificate left out of the badge.
	var ov struct {
		Alerts *struct {
			Open, Acknowledged, Silenced int
			ByOwner                      map[string]int
		} `json:"alerts"`
		Badges map[string]struct {
			Count    int
			Severity string
		} `json:"badges"`
	}
	getJSON(t, h, "/api/v1/overview", &ov)
	if a := ov.Alerts; a == nil || a.Open != 7 || a.Acknowledged != 1 || a.Silenced != 1 || a.ByOwner["team-shop"] != 5 {
		t.Errorf("overview alerts = %+v", ov.Alerts)
	}
	if b := ov.Badges["alerts"]; b.Count != 6 || b.Severity != "crit" {
		t.Errorf("alerts badge = %+v", b)
	}

	// Acknowledge, then silence, as the UI does.
	grafana := alerts.Key(alerts.CheckNodePort, "Service", "monitoring", "grafana")
	rec := postJSON(t, h, "/api/v1/alerts/actions", `{"keys":["`+grafana+`","nope/X//y"],"action":"ack"}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"ok":true`) || !strings.Contains(rec.Body.String(), `"error":"not found"`) {
		t.Fatalf("ack = %d %s", rec.Code, rec.Body.String())
	}
	rec = postJSON(t, h, "/api/v1/alerts/actions", `{"keys":["`+grafana+`"],"action":"silence","for":"4h","reason":"grafana moves behind the ingress on Monday"}`)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"ok":true`) {
		t.Fatalf("silence = %d %s", rec.Code, rec.Body.String())
	}
	list = demoAlertList{}
	getJSON(t, h, "/api/v1/alerts?state=silenced", &list)
	got := map[string]demoAlertItem{}
	for _, f := range list.Items {
		got[f.Key] = f
	}
	if g := got[grafana]; g.State != alerts.StateSilenced || g.AckBy == "" || g.SilenceReason != "grafana moves behind the ingress on Monday" {
		t.Errorf("grafana after ack and silence = %+v", g)
	}
	if rec := postJSON(t, h, "/api/v1/alerts/actions", `{"keys":["`+bobRBACKey+`"],"action":"ack"}`); !strings.Contains(rec.Body.String(), `"error":"resolved"`) {
		t.Errorf("ack on a resolved finding = %s", rec.Body.String())
	}
}
