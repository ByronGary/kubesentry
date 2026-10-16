package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/auth"
	"github.com/ByronGary/kubesentry/internal/incidents"
)

func TestIncidentsList(t *testing.T) {
	s, _ := incidentsServer(t)
	h := s.Handler()

	// alice: team-a's open and recently resolved incidents, never the node's;
	// no CloudTrail changes in their types (no ViewCloudTrail).
	var r incidentsResponse
	if rec := getAs(t, h, "alice", "/api/v1/incidents", &r); rec.Code != 200 {
		t.Fatalf("list = %d %s", rec.Code, rec.Body.String())
	}
	if strings.Join(ids(r), " ") != incidentID("team-a")+" "+resolvedID("team-a") {
		t.Errorf("alice's incidents = %v", ids(r))
	}
	for _, in := range r.Items {
		if in.Subject.Namespace != "team-a" || hasType(in, incidents.TypeCloudTrailChange) {
			t.Errorf("alice sees %+v", in)
		}
	}
	if len(r.Items) == 0 || !hasType(r.Items[0], incidents.TypeAuditChange) {
		t.Fatalf("alice (audit in team-a) lost the audit change: %+v", r.Items)
	}
	c := r.Counts
	if c.Open != 1 || c.Resolved != 1 || c.Critical != 1 || c.Warning != 1 || c.ByType[incidents.TypeOOMKill] != 1 ||
		c.ByType[incidents.TypeCloudTrailChange] != 0 || c.ByType[incidents.TypeErrorRate] != 1 {
		t.Errorf("alice's counts = %+v", c)
	}

	// Filters narrow the items; severity, type and state not the counts.
	old := "from=" + rfc(now.Add(-80*time.Hour)) + "&to=" + rfc(now.Add(-60*time.Hour))
	for q, want := range map[string]int{
		"severity=critical": 1, "severity=warning": 1, "state=open": 1, "state=resolved": 1, "type=oom-kill": 1,
		"type=error-rate&type=oom-kill": 2, "type=error-rate,oom-kill": 2, "type=cloudtrail-change": 0, "owner=team-alpha": 2,
		"owner=team-beta": 0, "namespace=team-a": 2, "namespace=team-b": 0, "app=web": 2, "app=api": 0, "service=web": 2,
		"tag=app.kubernetes.io/part-of=shop": 2, "tag=app=api": 0, "window=1h": 1, "window=3h": 2, old: 1,
		"from=" + rfc(now.Add(-90*time.Minute)): 1,
	} {
		var f incidentsResponse
		if rec := getAs(t, h, "alice", "/api/v1/incidents?"+q, &f); rec.Code != 200 || len(f.Items) != want {
			t.Errorf("%s: %d, %d items %v, want %d", q, rec.Code, len(f.Items), ids(f), want)
		}
		if strings.HasPrefix(q, "severity") || strings.HasPrefix(q, "state") || strings.HasPrefix(q, "type") {
			if f.Counts.Open != c.Open || f.Counts.Resolved != c.Resolved || f.Counts.Critical != c.Critical {
				t.Errorf("%s changed the counts: %+v", q, f.Counts)
			}
		}
	}
	// The store serves ranges older than the board, scoped: three days ago
	// alice sees team-a's crash loop only.
	var past incidentsResponse
	getAs(t, h, "alice", "/api/v1/incidents?"+old, &past)
	if len(past.Items) != 1 || past.Items[0].Subject.Namespace != "team-a" || past.Items[0].Title != "web: crash loop" {
		t.Errorf("alice's old incidents = %+v", past.Items)
	}

	// bob holds nodes: team-b's and the node's.
	var bob incidentsResponse
	getAs(t, h, "bob", "/api/v1/incidents?state=open", &bob)
	if got := strings.Join(ids(bob), " "); got != nodeIncidentID+" "+incidentID("team-b") {
		t.Errorf("bob's open incidents = %v", got)
	}
	// carol holds nothing.
	var carol incidentsResponse
	if rec := getAs(t, h, "carol", "/api/v1/incidents", &carol); rec.Code != 200 || len(carol.Items) != 0 || carol.Counts.Open+carol.Counts.Resolved != 0 {
		t.Errorf("carol = %d %+v", rec.Code, carol)
	}

	// Unrestricted: everything on the board, CloudTrail included.
	s2, _ := incidentsServer(t)
	s2.Authenticator = nil
	var all incidentsResponse
	get(t, s2, "/api/v1/incidents", &all)
	if len(all.Items) != 7 || all.Counts.Open != 4 || all.Counts.ByType[incidents.TypeCloudTrailChange] != 3 {
		t.Errorf("unrestricted: %d items, counts %+v", len(all.Items), all.Counts)
	}
	// Pages visit every item once, in the list's order.
	seen := map[string]int{}
	var order []string
	for _, page := range allPages(t, s2.Handler(), "", "/api/v1/incidents") {
		var p incidentsResponse
		_ = json.Unmarshal(page, &p)
		for _, in := range p.Items {
			seen[in.ID]++
			order = append(order, in.ID)
		}
	}
	if len(seen) != 7 || strings.Join(order, " ") != strings.Join(ids(all), " ") {
		t.Errorf("paging saw %v in order %v, want %v", seen, order, ids(all))
	}

	for _, q := range []string{"window=30m", "window=25h", "window=x", "from=yesterday", "to=" + rfc(now),
		"from=" + rfc(now.Add(-30*time.Hour)), "from=" + rfc(now.Add(time.Hour)),
		"from=" + rfc(now.Add(-9*24*time.Hour)) + "&to=" + rfc(now.Add(-8*24*time.Hour)),
		"from=" + rfc(now.Add(-time.Hour)) + "&window=1h",
		"from=" + rfc(now.Add(-time.Hour)) + "&to=" + rfc(now.Add(-2*time.Hour)),
		"severity=caution", "state=closed", "type=nope", "namespace=Team_A", "service=a/b", "tag=x", "tag=bad%20key=v", "continue=garbage",
		"continue=" + encodeToken("incidents", "x"), "limit=0"} {
		if rec := getAs(t, h, "alice", "/api/v1/incidents?"+q, nil); rec.Code != 400 {
			t.Errorf("%s = %d, want 400", q, rec.Code)
		}
	}
}

// The gates inside one incident.
func TestIncidentGates(t *testing.T) {
	s, logs := incidentsServer(t)
	h := s.Handler()
	teamA, teamB := incidentID("team-a"), incidentID("team-b")

	// A team-b ID is not found for alice, exactly like an unknown one; an
	// unknown ID is answered before any authorization review.
	var unknownBody string
	for _, id := range []string{"20261010T000000Z-000000000000", "not..valid", teamB, nodeIncidentID} {
		for _, sub := range []string{"", "/logs", "/bundle"} {
			rec := getAs(t, h, "alice", "/api/v1/incidents/"+id+sub, nil)
			if rec.Code != 404 {
				t.Errorf("%s%s as alice = %d, want 404", id, sub, rec.Code)
			}
			if unknownBody == "" {
				unknownBody = rec.Body.String()
			} else if rec.Body.String() != unknownBody {
				t.Errorf("%s%s answers %q, an unknown one %q", id, sub, rec.Body.String(), unknownBody)
			}
		}
	}
	counting := &countingReviewer{grantReviewer: tenantGrants()}
	s.Authorizer = &auth.SARAuthorizer{Reviewer: counting, Candidates: s.Authorizer.(*auth.SARAuthorizer).Candidates}
	for _, sub := range []string{"", "/logs", "/bundle"} {
		getAs(t, s.Handler(), "alice", "/api/v1/incidents/20261010T000000Z-000000000000"+sub, nil)
	}
	if n := counting.n.Load(); n != 0 {
		t.Errorf("unknown IDs cost %d reviews, want none", n)
	}
	regrant(s)
	h = s.Handler()

	// alice's own incident: audit (ViewAudit in team-a), no CloudTrail, no
	// node events (no ViewNodes), related only within team-a, redacted.
	var d incidentDetailResponse
	if rec := getAs(t, h, "alice", "/api/v1/incidents/"+teamA, &d); rec.Code != 200 {
		t.Fatalf("detail = %d %s", rec.Code, rec.Body.String())
	}
	types := map[string]bool{}
	for _, sg := range d.Signals {
		types[sg.Type] = true
	}
	if !types[incidents.TypeAuditChange] || types[incidents.TypeCloudTrailChange] || hasType(d.Incident, incidents.TypeCloudTrailChange) {
		t.Errorf("alice's signals = %v, incident types %v", types, d.Incident.Types)
	}
	if len(d.Events) != 1 || d.Events[0].Regarding.Kind != "Pod" || strings.Contains(d.Events[0].Message, "s3cr3t") {
		t.Errorf("alice's events = %+v", d.Events)
	}
	if len(d.Audit) == 0 {
		t.Errorf("alice's audit = %v", d.Audit)
	}
	for _, e := range d.Audit {
		if e.Namespace != "team-a" {
			t.Errorf("alice's audit event in %q", e.Namespace)
		}
	}
	if d.Sources["cloudtrail"] != "forbidden" || d.Sources["logs:kubernetes"] != "forbidden" || d.Sources["series"] != "ok" || len(d.Series) != 1 {
		t.Errorf("alice's sources = %v, series %d", d.Sources, len(d.Series))
	}
	if len(d.Related) != 0 {
		t.Errorf("alice's related incidents = %+v (team-b's and kube-system's share the tags, but are not hers)", d.Related)
	}
	if !d.Window.To.Equal(now) || !d.Window.From.Equal(now.Add(-time.Hour-5*time.Minute)) || d.Incident.ID != teamA {
		t.Errorf("window %+v incident %s", d.Window, d.Incident.ID)
	}
	var ud incidentDetailResponse
	unrestricted, _ := incidentsServer(t)
	unrestricted.Authenticator = nil
	get(t, unrestricted, "/api/v1/incidents/"+teamA, &ud)
	if len(ud.Related) != 2 || len(ud.Events) != 2 || len(ud.Signals) != 4 {
		t.Errorf("unrestricted detail: %d related, %d events, %d signals", len(ud.Related), len(ud.Events), len(ud.Signals))
	}
	// The JSON is the contract's: lowercase fields throughout.
	rec := getAs(t, h, "alice", "/api/v1/incidents/"+teamA, nil)
	for _, field := range []string{`"regarding":{"kind":"Pod"`, `"object":{"kind":"Pod"`, `"subject":{"kind":"Deployment"`, `"window":{"from":`} {
		if !strings.Contains(rec.Body.String(), field) {
			t.Errorf("detail lacks %s: %s", field, rec.Body.String())
		}
	}

	// bob holds nodes, not audit: node events, no audit, no audit change.
	var bd incidentDetailResponse
	getAs(t, h, "bob", "/api/v1/incidents/"+teamB, &bd)
	if len(bd.Events) != 2 || bd.Audit != nil || bd.Sources["audit"] != "forbidden" || hasType(bd.Incident, incidents.TypeAuditChange) {
		t.Errorf("bob's detail: events %+v audit %v sources %v types %v", bd.Events, bd.Audit, bd.Sources, bd.Incident.Types)
	}
	for _, sg := range bd.Signals {
		if sg.Type == incidents.TypeAuditChange || sg.Type == incidents.TypeCloudTrailChange {
			t.Errorf("bob sees %s", sg.Type)
		}
	}
	if rec := getAs(t, h, "bob", "/api/v1/incidents/"+nodeIncidentID, nil); rec.Code != 200 {
		t.Errorf("bob's node incident = %d", rec.Code)
	}

	// Logs need ViewPodLogs in the incident's namespace.
	if rec := getAs(t, h, "alice", "/api/v1/incidents/"+teamA+"/logs", nil); rec.Code != 403 || logs.calls.Load() != 0 {
		t.Errorf("logs without the grant = %d (%d reads)", rec.Code, logs.calls.Load())
	}
	regrant(s, grant("alice", auth.ViewPodLogs, "team-a"))
	h = s.Handler()
	var lr incidentLogsResponse
	rec = getAs(t, h, "alice", "/api/v1/incidents/"+teamA+"/logs?level=error&pod=web-1", &lr)
	if rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-store" || len(lr.Lines) != 1 || lr.Source != "kubernetes" ||
		strings.Contains(lr.Lines[0].Text, "hunter2") {
		t.Errorf("logs = %d %q %+v", rec.Code, rec.Header().Get("Cache-Control"), lr)
	}
	for _, q := range []string{"level=fatal", "source=s3", "pod=Bad_Pod", "from=now", "limit=-1", "source=cloudwatch"} {
		if rec := getAs(t, h, "alice", "/api/v1/incidents/"+teamA+"/logs?"+q, nil); rec.Code != 400 {
			t.Errorf("logs?%s = %d, want 400", q, rec.Code)
		}
	}

	// The bundle leaves out what the caller may not see, and says so.
	bundle := func(user, id, q string) (incidents.Bundle, *httptest.ResponseRecorder) {
		var b incidents.Bundle
		rec := getAs(t, h, user, "/api/v1/incidents/"+id+"/bundle"+q, &b)
		return b, rec
	}
	b, rec := bundle("bob", teamB, "")
	if rec.Code != 200 || b.Complete || b.Omitted["audit"] != "forbidden" || b.Omitted["cloudtrail"] != "forbidden" || b.Omitted["logs"] != "forbidden" ||
		len(b.Audit) != 0 || len(b.CloudTrail) != 0 || len(b.Logs) != 0 || hasType(b.Incident, incidents.TypeCloudTrailChange) || len(b.Events) != 2 {
		t.Errorf("bob's bundle = %d %+v", rec.Code, b.BundleHeader)
	}
	for _, sg := range b.Signals {
		if sg.Type == incidents.TypeAuditChange || sg.Type == incidents.TypeCloudTrailChange {
			t.Errorf("bob's bundle has %s", sg.Type)
		}
	}
	b, _ = bundle("alice", teamA, "")
	if b.Omitted["audit"] != "" || b.Omitted["cloudtrail"] != "forbidden" || b.Omitted["logs"] != "" || len(b.Logs) == 0 || len(b.Events) != 1 ||
		len(b.Audit) == 0 || b.Cluster != "" || b.Schema != incidents.BundleSchema {
		t.Errorf("alice's bundle = %+v, %d logs, %d events, %d audit", b.BundleHeader, len(b.Logs), len(b.Events), len(b.Audit))
	}
	if _, rec := bundle("alice", teamA, "?require=all"); rec.Code != 403 || !strings.Contains(rec.Body.String(), "cloudtrail") {
		t.Errorf("require=all without CloudTrail = %d %s", rec.Code, rec.Body.String())
	}
	if _, rec := bundle("alice", teamA, "?format=xml"); rec.Code != 400 {
		t.Errorf("format=xml = %d", rec.Code)
	}
	rec = getAs(t, h, "alice", "/api/v1/incidents/"+teamA+"/bundle?format=ndjson", nil)
	lines := strings.Split(strings.TrimSpace(rec.Body.String()), "\n")
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "application/x-ndjson" || len(lines) < 3 ||
		!strings.HasPrefix(lines[0], `{"schema":"kubesentry.io/incident-bundle/v1"`) || !strings.HasPrefix(lines[1], `{"kind":"signal"`) ||
		strings.Contains(rec.Body.String(), "hunter2") || strings.Contains(rec.Body.String(), "s3cr3t") {
		t.Errorf("ndjson bundle = %d %s", rec.Code, rec.Body.String())
	}
	// The bundle names the cluster -cluster-name names.
	s.ClusterInfo.Name = "prod-eu"
	h = s.Handler()
	if b, _ := bundle("alice", teamA, ""); b.Cluster != "prod-eu" {
		t.Errorf("bundle cluster = %q", b.Cluster)
	}

	// The list's cache key differs by the CloudTrail capability: the same
	// caller, granted it, is not served the cached list without it.
	s3, _ := incidentsServer(t)
	h = s3.Handler()
	var before, after incidentsResponse
	getAs(t, h, "alice", "/api/v1/incidents", &before)
	if rec := getAs(t, h, "alice", "/api/v1/incidents", nil); rec.Header().Get("X-Kubesentry-Cache") != "hit" {
		t.Errorf("the list is not cached")
	}
	regrant(s3, grant("alice", auth.ViewCloudTrail, ""))
	h = s3.Handler()
	rec = getAs(t, h, "alice", "/api/v1/incidents", &after)
	if rec.Header().Get("X-Kubesentry-Cache") == "hit" || after.Counts.ByType[incidents.TypeCloudTrailChange] != 1 ||
		before.Counts.ByType[incidents.TypeCloudTrailChange] != 0 {
		t.Errorf("with ViewCloudTrail: cache %q, counts %v (before %v)", rec.Header().Get("X-Kubesentry-Cache"), after.Counts.ByType, before.Counts.ByType)
	}
}

func TestIncidentsElsewhere(t *testing.T) {
	s, _ := incidentsServer(t)
	h := s.Handler()

	var info infoResponse
	getAs(t, h, "alice", "/api/v1/info", &info)
	if info.Incidents == nil || !info.Incidents.Enabled || info.Incidents.MaxRangeHours != 24 || info.Incidents.LogLeadSeconds != 300 ||
		info.Incidents.LogLagSeconds != 600 || info.Incidents.Sources["logs:kubernetes"] != "ok" || info.Incidents.Sources["cloudtrail"] != "absent" {
		t.Errorf("info incidents = %+v", info.Incidents)
	}
	for _, c := range []string{"podLogs", "cloudtrail"} {
		if _, ok := info.Capabilities[c]; !ok {
			t.Errorf("capabilities lack %s: %v", c, info.Capabilities)
		}
	}
	var off infoResponse
	getAs(t, tenantServer(t).Handler(), "alice", "/api/v1/info", &off)
	if off.Incidents != nil {
		t.Errorf("incidents off: %+v", off.Incidents)
	}

	// The Overview: alice's open incident only, folded into her web line.
	var ov overviewResponse
	getAs(t, h, "alice", "/api/v1/overview", &ov)
	if ov.Incidents == nil || ov.Incidents.Open.Critical != 1 || ov.Incidents.Open.Warning != 0 ||
		ov.Badges["incidents"] != (badge{Count: 1, Severity: "crit"}) {
		t.Errorf("alice's overview incidents %+v badge %+v", ov.Incidents, ov.Badges["incidents"])
	}
	found := false
	for _, a := range ov.Attention {
		if a.Kind == "incident" {
			found = true
			if a.Namespace != "team-a" || a.Href != "#/incidents/"+incidentID("team-a") || a.Name != "web" || a.Severity != "crit" || a.Owner != "team-alpha" {
				t.Errorf("alice's incident item = %+v", a)
			}
		}
	}
	if !found {
		t.Errorf("no incident in alice's attention: %+v", ov.Attention)
	}
	var bob overviewResponse
	getAs(t, h, "bob", "/api/v1/overview", &bob)
	if bob.Incidents == nil || bob.Incidents.Open.Critical != 1 || bob.Incidents.Open.Warning != 1 || bob.Badges["incidents"].Count != 2 {
		t.Errorf("bob's overview incidents %+v badges %+v", bob.Incidents, bob.Badges)
	}
	var bobB overviewResponse
	getAs(t, h, "bob", "/api/v1/overview?namespace=team-b", &bobB)
	if bobB.Incidents == nil || bobB.Incidents.Open.Critical != 1 || bobB.Incidents.Open.Warning != 1 {
		t.Errorf("bob's team-b overview incidents %+v (n1 runs team-b pods)", bobB.Incidents)
	}

	// The pod page lists the pod's incidents.
	var diag struct {
		Incidents []incidentRef `json:"incidents"`
	}
	if rec := getAs(t, h, "alice", "/api/v1/pods/team-a/web-0/diagnostics", &diag); rec.Code != 200 {
		t.Fatalf("diagnostics = %d", rec.Code)
	}
	if len(diag.Incidents) != 2 || diag.Incidents[0].ID != incidentID("team-a") || diag.Incidents[0].Severity != "critical" ||
		diag.Incidents[0].State != "open" || diag.Incidents[1].ID != resolvedID("team-a") {
		t.Errorf("web-0's incidents = %+v", diag.Incidents)
	}
}
