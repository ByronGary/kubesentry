package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/alerts"
	"github.com/ByronGary/kubesentry/internal/auth"
	"github.com/ByronGary/kubesentry/internal/metrics"
)

// extraCandidates proposes more namespaces per user than the RBAC index
// does, for every capability (the reviewer still decides).
type extraCandidates struct {
	auth.Candidates
	extra map[string][]string
}

func (e extraCandidates) Namespaces(user string, groups []string, c auth.Capability) []string {
	return append(e.Candidates.Namespaces(user, groups, c), e.extra[user]...)
}

// actionsServer is tenantServer where alice may act in team-a (which she
// sees); bob may act in team-a (which he does not see) and sees team-b and
// cluster-scoped RBAC; erin sees and may act on everything; dave and frank
// see what alice sees but may not act.
func actionsServer(t *testing.T) *Server {
	t.Helper()
	s := tenantServer(t)
	g := tenantGrants()
	for k, v := range map[string]bool{
		grant("alice", auth.UpdateAlerts, "team-a"):    true,
		grant("bob", auth.UpdateAlerts, "team-a"):      true,
		grant("bob", auth.ViewClusterRBAC, ""):         true,
		grant("erin", auth.ViewNamespace, ""):          true,
		grant("erin", auth.ViewRBAC, ""):               true,
		grant("erin", auth.ViewClusterRBAC, ""):        true,
		grant("erin", auth.UpdateAlerts, ""):           true,
		grant("dave", auth.ViewNamespace, "team-a"):    true,
		grant("dave", auth.ViewAudit, "team-a"):        true,
		grant("frank", auth.ViewNamespace, "team-a"):   true,
		grant("frank", auth.ViewAudit, "team-a"):       true,
		grant("carol", auth.ViewNamespace, "team-zzz"): true,
	} {
		g[k] = v
	}
	base := s.Authorizer.(*auth.SARAuthorizer).Candidates
	s.Authorizer = &auth.SARAuthorizer{Reviewer: g, Candidates: extraCandidates{base, map[string][]string{
		"alice": {"team-a"}, "bob": {"team-a"}, "dave": {"team-a"}, "frank": {"team-a"}}}}
	return s
}

// postAs sends POST path with a JSON body as user (through the trusted
// proxy); hdr adds headers ("" removes one).
func postAs(t *testing.T, h http.Handler, user, path, body string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if user != "" {
		req.Header.Set("X-Forwarded-Email", user)
	}
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func act(t *testing.T, h http.Handler, user string, req alertActionRequest) (alertActionResponse, *httptest.ResponseRecorder) {
	t.Helper()
	body, _ := json.Marshal(req)
	rec := postAs(t, h, user, "/api/v1/alerts/actions", string(body), nil)
	var resp alertActionResponse
	if rec.Code == 200 {
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
	}
	return resp, rec
}

func resultsByKey(r alertActionResponse) map[string]alertActionResult {
	out := map[string]alertActionResult{}
	for _, x := range r.Results {
		out[x.Key] = x
	}
	return out
}

const (
	aWeb     = "workload-unhealthy/Deployment/team-a/web"
	bWeb     = "workload-unhealthy/Deployment/team-b/web"
	aRBAC    = "cluster-admin/RoleBinding/team-a/ns-admins"
	aEvicted = "pod-evicted/Deployment/team-a/web"
	cluster  = "cluster-admin/ClusterRoleBinding//erin-admin"
)

// POST /api/v1/alerts/actions: a key the caller cannot see is "not found",
// like an unknown one; one they see without UpdateAlerts there is
// "forbidden"; cluster-scoped findings need it cluster-wide; resolved ones
// are "resolved"; an action that does not apply is "invalid".
func TestAlertActionsRoute(t *testing.T) {
	s := actionsServer(t)
	h := s.Handler()

	if _, rec := act(t, h, "carol", alertActionRequest{Keys: []string{aWeb}, Action: "ack"}); rec.Code != 403 {
		t.Fatalf("carol, who may act nowhere: %d %s", rec.Code, rec.Body)
	}
	notFound := metrics.AlertActions.With("ack", "not_found").Value()
	resp, rec := act(t, h, "alice", alertActionRequest{Keys: []string{aWeb, bWeb, "nope/Deployment/team-a/x", aRBAC, cluster, aEvicted, aWeb}, Action: "ack"})
	if rec.Code != 200 || len(resp.Results) != 6 || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("alice: %d %s", rec.Code, rec.Body)
	}
	r := resultsByKey(resp)
	if x := r[aWeb]; !x.OK || x.Finding == nil || x.Finding.State != alerts.StateAcknowledged || x.Finding.AckBy != "alice" || !x.Finding.Actionable {
		t.Errorf("alice acks her own: %+v", x)
	}
	for k, want := range map[string]string{bWeb: "not found", "nope/Deployment/team-a/x": "not found", aRBAC: "not found", cluster: "not found", aEvicted: "resolved"} {
		if x := r[k]; x.OK || x.Error != want || x.Finding != nil {
			t.Errorf("alice on %s: %+v, want %q", k, x, want)
		}
	}
	if n := metrics.AlertActions.With("ack", "not_found").Value() - notFound; n != 4 {
		t.Errorf("not_found counted %v times", n)
	}

	// bob may act in team-a, which he cannot see, and sees team-b and the
	// cluster's RBAC, where he may not act.
	resp, _ = act(t, h, "bob", alertActionRequest{Keys: []string{bWeb, aWeb, cluster}, Action: "ack"})
	r = resultsByKey(resp)
	if r[bWeb].Error != "forbidden" || r[aWeb].Error != "not found" || r[cluster].Error != "forbidden" {
		t.Errorf("bob: %+v", resp)
	}
	// erin acts cluster-wide.
	resp, _ = act(t, h, "erin", alertActionRequest{Keys: []string{cluster}, Action: "silence", For: "4h", Reason: "maintenance window"})
	if x := resp.Results[0]; !x.OK || x.Finding.State != alerts.StateSilenced || !x.Finding.SilencedUntil.Equal(now.Add(4*time.Hour)) ||
		x.Finding.SilencedBy != "erin" || x.Finding.SilenceReason != "maintenance window" {
		t.Errorf("erin silences the cluster finding: %+v", resp)
	}
	// unack: once, then there is nothing to lift.
	resp, _ = act(t, h, "alice", alertActionRequest{Keys: []string{aWeb}, Action: "unack"})
	if x := resp.Results[0]; !x.OK || x.Finding.State != alerts.StateOpen {
		t.Errorf("unack: %+v", resp)
	}
	resp, _ = act(t, h, "alice", alertActionRequest{Keys: []string{aWeb}, Action: "unack"})
	if x := resp.Results[0]; x.OK || x.Error != "invalid" {
		t.Errorf("unack again: %+v", resp)
	}

	// The list carries actionable per item.
	var list alertsResponse
	getAs(t, h, "bob", "/api/v1/alerts", &list)
	for _, f := range list.Items {
		if f.Actionable {
			t.Errorf("bob may not act on %s", f.Key)
		}
	}
	list = alertsResponse{}
	getAs(t, h, "erin", "/api/v1/alerts", &list)
	silenced := false
	for _, f := range list.Items {
		silenced = silenced || (f.Key == cluster && f.State == alerts.StateSilenced)
		if !f.Actionable {
			t.Errorf("erin may act on %s", f.Key)
		}
	}
	if !silenced || list.Counts["silenced"] != 1 {
		t.Errorf("erin's list: %+v", list.Counts)
	}
}

// The /alerts response cache keys on UpdateAlerts too: two callers who see
// the same but differ in where they may act never share a response.
func TestAlertsCacheKeysOnUpdateAlerts(t *testing.T) {
	h := actionsServer(t).Handler()
	get := func(user string) (alertsResponse, string) {
		var r alertsResponse
		rec := getAs(t, h, user, "/api/v1/alerts", &r)
		return r, rec.Header().Get("X-Kubesentry-Cache")
	}
	a, c1 := get("alice")
	_, c2 := get("alice")
	d, c3 := get("dave")
	_, c4 := get("frank")
	if c1 != "miss" || c2 != "hit" || c3 != "miss" || c4 != "hit" {
		t.Fatalf("cache: alice %s, %s; dave %s; frank %s", c1, c2, c3, c4)
	}
	if len(a.Items) == 0 || len(a.Items) != len(d.Items) {
		t.Fatalf("alice %d items, dave %d", len(a.Items), len(d.Items))
	}
	for i := range a.Items {
		if !a.Items[i].Actionable || d.Items[i].Actionable {
			t.Errorf("%s: alice actionable %v, dave %v", a.Items[i].Key, a.Items[i].Actionable, d.Items[i].Actionable)
		}
	}
}

// The request as a whole: 415, 413, 400 for malformed JSON, unknown fields,
// too many or no keys, a bad action, and a silence without a fitting
// duration or reason.
func TestAlertActionsRequestRules(t *testing.T) {
	h := actionsServer(t).Handler()
	many := make([]string, 101)
	for i := range many {
		many[i] = fmt.Sprintf("k%d", i)
	}
	tooMany, _ := json.Marshal(alertActionRequest{Keys: many, Action: "ack"})
	for _, c := range []struct {
		name, body string
		hdr        map[string]string
		want       int
	}{
		{"text body", `{"keys":["x"],"action":"ack"}`, map[string]string{"Content-Type": "text/plain"}, 415},
		{"no content type", `{"keys":["x"],"action":"ack"}`, map[string]string{"Content-Type": ""}, 415},
		{"json with charset", `{"keys":["x"],"action":"ack"}`, map[string]string{"Content-Type": "application/json; charset=utf-8"}, 200},
		{"too large", `{"keys":["` + strings.Repeat("x", 17<<10) + `"],"action":"ack"}`, nil, 413},
		{"malformed", `{"keys":`, nil, 400},
		{"empty", ``, nil, 400},
		{"unknown field", `{"keys":["x"],"action":"ack","force":true}`, nil, 400},
		{"two values", `{"keys":["x"],"action":"ack"} {}`, nil, 400},
		{"bad action", `{"keys":["x"],"action":"delete"}`, nil, 400},
		{"no keys", `{"keys":[],"action":"ack"}`, nil, 400},
		{"101 keys", string(tooMany), nil, 400},
		{"silence without reason", `{"keys":["x"],"action":"silence","for":"1h"}`, nil, 400},
		{"reason too short", `{"keys":["x"],"action":"silence","for":"1h","reason":" ab "}`, nil, 400},
		{"reason too long", `{"keys":["x"],"action":"silence","for":"1h","reason":"` + strings.Repeat("é", 501) + `"}`, nil, 400},
		{"too short", `{"keys":["x"],"action":"silence","for":"4m","reason":"deploy"}`, nil, 400},
		{"too long", `{"keys":["x"],"action":"silence","for":"8d","reason":"deploy"}`, nil, 400},
		{"not a duration", `{"keys":["x"],"action":"silence","for":"soon","reason":"deploy"}`, nil, 400},
		{"for on ack", `{"keys":["x"],"action":"ack","for":"1h"}`, nil, 400},
		{"reason on unack", `{"keys":["x"],"action":"unack","reason":"why"}`, nil, 400},
		{"seven days", `{"keys":["x"],"action":"silence","for":"7d","reason":"deploy"}`, nil, 200},
		{"500 characters", `{"keys":["x"],"action":"silence","for":"1d12h","reason":"` + strings.Repeat("é", 500) + `"}`, nil, 200},
	} {
		if rec := postAs(t, h, "alice", "/api/v1/alerts/actions", c.body, c.hdr); rec.Code != c.want {
			t.Errorf("%s: %d, want %d: %s", c.name, rec.Code, c.want, rec.Body)
		}
	}
}

// GET /api/v1/alerts/actions lists only actions on findings the caller can
// see, newest first, never cached.
func TestAlertActionsList(t *testing.T) {
	h := actionsServer(t).Handler()
	act(t, h, "alice", alertActionRequest{Keys: []string{aWeb}, Action: "ack"})
	act(t, h, "erin", alertActionRequest{Keys: []string{cluster}, Action: "silence", For: "1h", Reason: "known issue"})

	list := func(user, q string) (alertActionsResponse, *httptest.ResponseRecorder) {
		var r alertActionsResponse
		rec := getAs(t, h, user, "/api/v1/alerts/actions"+q, &r)
		return r, rec
	}
	r, rec := list("alice", "")
	if rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-store" || len(r.Items) == 0 {
		t.Fatalf("alice: %d %s", rec.Code, rec.Body)
	}
	// The wire shape of web/src/types.ts AlertAction.
	for _, field := range []string{`"action":"ack"`, `"namespace":"team-a"`, `"actor":"alice"`, `"firstSeen":`, `"severity":"critical"`, `"id":`} {
		if !strings.Contains(rec.Body.String(), field) {
			t.Errorf("no %s in %s", field, rec.Body)
		}
	}
	if first := r.Items[0]; first.Key != aWeb || first.Actor != "alice" || first.Action.Action != alerts.ActionAck || first.Namespace != "team-a" {
		t.Errorf("newest first: %+v", first)
	}
	for _, a := range r.Items {
		if a.Namespace != "team-a" || strings.HasPrefix(a.Key, "cluster-admin/") {
			t.Errorf("alice sees %+v", a)
		}
	}
	if r, _ := list("alice", "?key="+bWeb); len(r.Items) != 0 {
		t.Errorf("alice asks for team-b's: %+v", r.Items)
	}
	if r, _ := list("alice", "?key="+aWeb+"&limit=1"); len(r.Items) != 1 || r.Items[0].Actor != "alice" {
		t.Errorf("alice's own, latest: %+v", r.Items)
	}
	if r, _ := list("erin", "?key="+cluster); len(r.Items) != 2 || r.Items[0].Action.Action != alerts.ActionSilence || r.Items[0].Reason != "known issue" || r.Items[0].Until == nil {
		t.Errorf("erin on the cluster finding: %+v", r.Items)
	}
	if r, _ := list("carol", ""); len(r.Items) != 0 {
		t.Errorf("carol sees %+v", r.Items)
	}
	for _, q := range []string{"?limit=0", "?limit=x"} {
		if _, rec := list("alice", q); rec.Code != 400 {
			t.Errorf("%s = %d", q, rec.Code)
		}
	}
	if r, rec := list("erin", "?limit=5000"); rec.Code != 200 || len(r.Items) > maxActionsLimit {
		t.Errorf("a large limit: %d, %d items", rec.Code, len(r.Items))
	}
}

// Requests that change state from another origin are refused right after
// authentication; same-origin browser requests, non-browser clients
// (no Origin, no Sec-Fetch-Site) and trusted origins pass; reads always do.
func TestCrossOriginWrites(t *testing.T) {
	s := actionsServer(t)
	s.TrustedOrigins = []string{"https://portal.example.com"}
	h := s.Handler()
	body := `{"keys":["` + aWeb + `"],"action":"ack"}`
	rejected := metrics.HTTPRejected.With("cross_origin").Value()
	for _, c := range []struct {
		name string
		hdr  map[string]string
		want int
	}{
		{"evil origin", map[string]string{"Origin": "https://evil.example"}, 403},
		{"cross-site fetch", map[string]string{"Sec-Fetch-Site": "cross-site"}, 403},
		{"same-site fetch", map[string]string{"Sec-Fetch-Site": "same-site", "Origin": "https://other.example.com"}, 403},
		{"same-origin fetch", map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "http://example.com"}, 200},
		{"origin matching the host", map[string]string{"Origin": "http://example.com"}, 200},
		{"curl", nil, 200},
		{"trusted origin", map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://portal.example.com"}, 200},
	} {
		rec := postAs(t, h, "alice", "/api/v1/alerts/actions", body, c.hdr)
		if rec.Code != c.want {
			t.Errorf("%s: %d, want %d: %s", c.name, rec.Code, c.want, rec.Body)
		}
		if c.want == 403 && strings.TrimSpace(rec.Body.String()) != `{"error":"cross-origin request refused"}` {
			t.Errorf("%s: body %s", c.name, rec.Body)
		}
	}
	if n := metrics.HTTPRejected.With("cross_origin").Value() - rejected; n != 3 {
		t.Errorf("cross_origin counted %v times", n)
	}
	// Reads pass whatever their origin.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/alerts", nil)
	req.Header.Set("X-Forwarded-Email", "alice")
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Errorf("cross-site GET = %d", rec.Code)
	}
	// The UI's recheck still works; a cross-site one does not.
	if rec := postAs(t, h, "dave", "/api/v1/auth/recheck", "", map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "http://example.com"}); rec.Code != 200 {
		t.Errorf("recheck from the UI = %d: %s", rec.Code, rec.Body)
	}
	if rec := postAs(t, h, "frank", "/api/v1/auth/recheck", "", map[string]string{"Sec-Fetch-Site": "cross-site"}); rec.Code != 403 {
		t.Errorf("cross-site recheck = %d", rec.Code)
	}
	// Unauthenticated requests are still 401 first.
	if rec := postAs(t, h, "", "/api/v1/alerts/actions", body, map[string]string{"Origin": "https://evil.example"}); rec.Code != 401 {
		t.Errorf("anonymous cross-origin = %d", rec.Code)
	}
}
