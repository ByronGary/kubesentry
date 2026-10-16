package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/alerts"
	"github.com/ByronGary/kubesentry/internal/auth"
)

// staticAlerts serves the board of an alerts runner that is not run: its
// findings are committed to a memory store and read with Reload, as a
// replica that does not lead reads them; actions go through the runner.
type staticAlerts struct {
	*alerts.Runner
	status alerts.Status
}

func (s *staticAlerts) Status() alerts.Status { return s.status }

func newStaticAlerts(fs []alerts.Finding) *staticAlerts {
	s := &staticAlerts{Runner: &alerts.Runner{Options: alerts.Options{Now: func() time.Time { return now }},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}}
	s.set(fs)
	return s
}

// set replaces the stored findings and refreshes the board (a new version).
// Each finding comes with an action on a past episode (an ack that no
// longer applies), so the actions list has something in every namespace.
func (s *staticAlerts) set(fs []alerts.Finding) {
	ctx := context.Background()
	st := alerts.NewMemoryStore()
	if err := st.Commit(ctx, alerts.Commit{Findings: fs}); err != nil {
		panic(err)
	}
	for _, f := range fs {
		if _, err := st.AddAction(ctx, alerts.Action{Key: f.Key, FirstSeen: f.FirstSeen.Add(-24 * time.Hour), Action: alerts.ActionAck,
			Actor: "previous-oncall", Severity: f.Severity, At: now.Add(-3 * time.Hour)}); err != nil {
			panic(err)
		}
	}
	s.Store = st
	s.Reload(ctx)
}

// mkFinding is a finding as the leader stores it, owned as the tenants'
// namespaces are.
func mkFinding(check, alert, kind, ns, name, sev string, state alerts.State, first time.Time) alerts.Finding {
	owner := map[string]string{"team-a": "team-alpha", "team-b": "team-beta"}[ns]
	if owner == "" {
		owner = "platform"
	}
	labels := map[string]string{"alertname": alert, "severity": sev, "check": check, "owner": owner}
	if ns != "" {
		labels["namespace"] = ns
	}
	f := alerts.Finding{Key: alerts.Key(check, kind, ns, name), Alert: alert, Check: check, Kind: kind, Namespace: ns, Name: name,
		Severity: sev, Title: kind + " " + name, Owner: owner, Labels: labels, Annotations: map[string]string{"summary": name},
		State: state, FirstSeen: first, LastSeen: now}
	if state == alerts.StateResolved {
		f.ResolvedAt = &first
	}
	return f
}

// gatedFindings are the findings whose visibility needs more than the
// namespace: audit activity in each tenant namespace (ViewAudit there), a
// cluster-wide RBAC change in the audit log (ViewClusterAudit), and the
// agent DaemonSet's missing nodes (ViewAgents).
func gatedFindings() []alerts.Finding {
	var fs []alerts.Finding
	for _, ns := range tenants {
		fs = append(fs, mkFinding(alerts.CheckAuditExec, alerts.AlertAuditActivity, "User", ns, "dave@example.com", alerts.SeverityWarning,
			alerts.StateOpen, now.Add(-30*time.Minute)))
	}
	return append(fs,
		mkFinding(alerts.CheckAuditRBACChange, alerts.AlertAuditActivity, "User", "", "dave@example.com", alerts.SeverityWarning, alerts.StateOpen, now.Add(-20*time.Minute)),
		mkFinding(alerts.CheckAgentMissing, alerts.AlertAgentMissing, "DaemonSet", "", "kubesentry/kubesentry-agent", alerts.SeverityWarning, alerts.StateOpen, now.Add(-10*time.Minute)),
	)
}

// The audit and agent findings' gates: namespaced audit findings need
// ViewAudit there besides the namespace, cluster-scoped ones
// ViewClusterAudit; the agent finding ViewAgents.
func TestAlertsAuditAndAgentGates(t *testing.T) {
	s := tenantServer(t)
	s.Alerts.(*staticAlerts).set(append(tenantFindings(), gatedFindings()...))
	g := tenantGrants()
	g[grant("gina", auth.ViewClusterAudit, "")] = true
	g[grant("gina", auth.ViewAgents, "")] = true
	g[grant("hank", auth.ViewNamespace, "team-b")] = true
	g[grant("hank", auth.ViewAudit, "team-b")] = true
	s.Authorizer = &auth.SARAuthorizer{Reviewer: g, Candidates: extraCandidates{s.Authorizer.(*auth.SARAuthorizer).Candidates,
		map[string][]string{"hank": {"team-b"}}}}
	h := s.Handler()
	for user, want := range map[string]string{
		// ViewNamespace and ViewAudit in team-a.
		"alice": "workload-unhealthy/Deployment/team-a/web audit-exec/User/team-a/dave@example.com pod-evicted/Deployment/team-a/web",
		// ViewNamespace in team-b, no ViewAudit; ViewNodes.
		"bob": "workload-unhealthy/Deployment/team-b/web pod-evicted/Deployment/team-b/web",
		// Cluster audit and agents, no namespace.
		"gina": "agent-missing/DaemonSet//kubesentry/kubesentry-agent audit-rbac-change/User//dave@example.com",
		"hank": "workload-unhealthy/Deployment/team-b/web audit-exec/User/team-b/dave@example.com pod-evicted/Deployment/team-b/web",
	} {
		var r alertsResponse
		getAs(t, h, user, "/api/v1/alerts", &r)
		if got := strings.Join(alertKeys(r), " "); got != want {
			t.Errorf("%s sees %s\nwant %s", user, got, want)
		}
		var acts alertActionsResponse
		getAs(t, h, user, "/api/v1/alerts/actions?limit=200", &acts)
		seen := map[string]bool{}
		for _, k := range alertKeys(r) {
			seen[k] = true
		}
		for _, a := range acts.Items {
			if strings.Contains(a.Key, "audit-") || strings.Contains(a.Key, "agent-") {
				if !seen[a.Key] && !strings.HasSuffix(a.Key, "/old") {
					t.Errorf("%s sees the action on %s", user, a.Key)
				}
			}
		}
	}
}

// tenantFindings has, in every tenant namespace, an unhealthy workload
// (open), an eviction resolved an hour ago, one resolved 30 hours ago (off
// the list) and namespaced RBAC drift; plus cluster-scoped RBAC drift.
func tenantFindings() []alerts.Finding {
	mk := mkFinding
	var fs []alerts.Finding
	for _, ns := range tenants {
		fs = append(fs,
			mk(alerts.CheckWorkloadUnhealthy, alerts.AlertWorkloadUnhealthy, "Deployment", ns, "web", alerts.SeverityCritical, alerts.StateOpen, now.Add(-time.Hour)),
			mk(alerts.CheckPodEvicted, alerts.AlertPodEvicted, "Deployment", ns, "web", alerts.SeverityWarning, alerts.StateResolved, now.Add(-time.Hour)),
			mk(alerts.CheckPodStuckTerminating, alerts.AlertPodStuckTerminating, "Deployment", ns, "old", alerts.SeverityWarning, alerts.StateResolved, now.Add(-30*time.Hour)),
			mk(alerts.CheckClusterAdmin, alerts.AlertRBACDrift, "RoleBinding", ns, "ns-admins", alerts.SeverityCritical, alerts.StateOpen, now.Add(-2*time.Hour)),
		)
	}
	fs = append(fs, mk(alerts.CheckClusterAdmin, alerts.AlertRBACDrift, "ClusterRoleBinding", "", "erin-admin", alerts.SeverityCritical, alerts.StateOpen, now.Add(-2*time.Hour)))
	return fs
}

func alertKeys(r alertsResponse) []string {
	var out []string
	for _, f := range r.Items {
		out = append(out, f.Key)
	}
	return out
}

func TestAlertsRouteScopeFiltersAndPaging(t *testing.T) {
	s := tenantServer(t)

	// Unrestricted: everything but what resolved more than a day ago.
	all := tenantServer(t)
	all.Authenticator, all.Authorizer = nil, nil
	var got alertsResponse
	getAs(t, all.Handler(), "", "/api/v1/alerts?limit=1000", &got)
	if got.Count != 10 || got.Counts["open"] != 7 || got.Counts["resolved"] != 3 || got.UpdatedAt == nil {
		t.Fatalf("unrestricted: %d items, counts %v: %v", got.Count, got.Counts, alertKeys(got))
	}
	if got.Items[0].Severity != alerts.SeverityCritical || got.Items[len(got.Items)-1].State != alerts.StateResolved {
		t.Errorf("not worst first: %v", alertKeys(got))
	}
	for _, f := range got.Items {
		if f.Name == "old" {
			t.Errorf("a finding resolved 30h ago is listed: %+v", f)
		}
	}
	// Paging returns the same items in the same order.
	var paged []string
	for _, page := range allPages(t, all.Handler(), "", "/api/v1/alerts") {
		var p alertsResponse
		_ = json.Unmarshal(page, &p)
		paged = append(paged, alertKeys(p)...)
	}
	if strings.Join(paged, " ") != strings.Join(alertKeys(got), " ") {
		t.Errorf("paged %v\nwant  %v", paged, alertKeys(got))
	}
	// Filters.
	for q, want := range map[string]int{"?namespace=team-b": 3, "?owner=platform": 4, "?state=resolved": 3, "?state=open&owner=team-beta": 2} {
		var r alertsResponse
		getAs(t, all.Handler(), "", "/api/v1/alerts"+q, &r)
		if r.Count != want {
			t.Errorf("%s: %d items, want %d: %v", q, r.Count, want, alertKeys(r))
		}
	}
	for _, q := range []string{"?state=firing", "?namespace=Bad_NS", "?limit=0", "?continue=nope"} {
		if rec := getAs(t, all.Handler(), "", "/api/v1/alerts"+q, nil); rec.Code != 400 {
			t.Errorf("%s = %d, want 400", q, rec.Code)
		}
	}

	// With ViewRBAC in team-a alice also sees team-a's RBAC drift, but not
	// the cluster's; with ViewClusterRBAC that too.
	g := tenantGrants()
	g[grant("alice", auth.ViewRBAC, "team-a")] = true
	g[grant("bob", auth.ViewClusterRBAC, "")] = true
	s.Authorizer = &auth.SARAuthorizer{Reviewer: g, Candidates: s.Authorizer.(*auth.SARAuthorizer).Candidates}
	h := s.Handler()
	var a alertsResponse
	getAs(t, h, "alice", "/api/v1/alerts", &a)
	if strings.Join(alertKeys(a), " ") != "workload-unhealthy/Deployment/team-a/web cluster-admin/RoleBinding/team-a/ns-admins pod-evicted/Deployment/team-a/web" {
		t.Errorf("alice with ViewRBAC: %v", alertKeys(a))
	}
	var b alertsResponse
	getAs(t, h, "bob", "/api/v1/alerts", &b)
	if strings.Join(alertKeys(b), " ") != "workload-unhealthy/Deployment/team-b/web cluster-admin/ClusterRoleBinding//erin-admin pod-evicted/Deployment/team-b/web" {
		t.Errorf("bob with ViewClusterRBAC (no ViewRBAC in team-b): %v", alertKeys(b))
	}
	var ov overviewResponse
	getAs(t, h, "bob", "/api/v1/overview", &ov)
	if ov.Alerts == nil || ov.Alerts.Open != 2 || ov.Alerts.ByOwner["platform"] != 1 || ov.Alerts.ByOwner["team-beta"] != 1 {
		t.Errorf("bob's overview alerts = %+v", ov.Alerts)
	}
	ov = overviewResponse{}
	getAs(t, h, "bob", "/api/v1/overview?namespace=team-b", &ov)
	if ov.Alerts == nil || ov.Alerts.Open != 1 || ov.Alerts.ByOwner["platform"] != 0 {
		t.Errorf("bob's filtered overview alerts (cluster findings left out) = %+v", ov.Alerts)
	}
}

// The response cache keys on the board's version: a new board is served at
// once, an unchanged one from the cache.
func TestAlertsCacheFollowsTheBoard(t *testing.T) {
	s := tenantServer(t)
	src := s.Alerts.(*staticAlerts)
	h := s.Handler()
	var first alertsResponse
	if rec := getAs(t, h, "alice", "/api/v1/alerts", &first); rec.Header().Get("X-Kubesentry-Cache") != "miss" {
		t.Fatalf("first = %s", rec.Header().Get("X-Kubesentry-Cache"))
	}
	if rec := getAs(t, h, "alice", "/api/v1/alerts", nil); rec.Header().Get("X-Kubesentry-Cache") != "hit" {
		t.Errorf("second = %s", rec.Header().Get("X-Kubesentry-Cache"))
	}
	src.set(nil)
	var after alertsResponse
	if rec := getAs(t, h, "alice", "/api/v1/alerts", &after); rec.Header().Get("X-Kubesentry-Cache") != "miss" || after.Count != 0 {
		t.Errorf("after a new board: %s, %d items", rec.Header().Get("X-Kubesentry-Cache"), after.Count)
	}
}

func TestInfoAlerts(t *testing.T) {
	s := tenantServer(t)
	s.Authenticator = nil
	var info infoResponse
	sent := now.Add(-time.Minute)
	s.Alerts.(*staticAlerts).status = alerts.Status{Sink: "alertmanager", LastSentAt: sent, LastError: "alertmanager 2 of 2: HTTP 503 Service Unavailable", Leader: true}
	getAs(t, s.Handler(), "", "/api/v1/info", &info)
	if a := info.Alerts; a == nil || !a.Enabled || a.Sink != "alertmanager" || a.LastSentAt == nil || !a.LastSentAt.Equal(sent) || !a.Leader ||
		a.LastError != "alertmanager 2 of 2: HTTP 503 Service Unavailable" || a.LastDigestAt != nil || a.NextDigestAt != nil {
		t.Errorf("info.alerts = %+v", info.Alerts)
	}
	// Standing digests: when the last went out and the next is due.
	last, next := now.Add(-3*time.Hour), now.Add(21*time.Hour)
	s.Alerts.(*staticAlerts).status = alerts.Status{Sink: "alertmanager", LastDigestAt: last, NextDigestAt: next}
	s.ResponseCache = nil
	info = infoResponse{}
	getAs(t, s.Handler(), "", "/api/v1/info", &info)
	if a := info.Alerts; a == nil || a.LastDigestAt == nil || !a.LastDigestAt.Equal(last) || a.NextDigestAt == nil || !a.NextDigestAt.Equal(next) {
		t.Errorf("info.alerts with digests = %+v", info.Alerts)
	}
	s.Alerts = nil
	info = infoResponse{}
	getAs(t, s.Handler(), "", "/api/v1/info", &info)
	if a := info.Alerts; a == nil || a.Enabled || a.Sink != "none" {
		t.Errorf("disabled info.alerts = %+v", info.Alerts)
	}
	if rec := getAs(t, s.Handler(), "", "/api/v1/alerts", nil); rec.Code != 404 {
		t.Errorf("/alerts with alerting off = %d, want 404", rec.Code)
	}
	var ov overviewResponse
	getAs(t, s.Handler(), "", "/api/v1/overview", &ov)
	if ov.Alerts != nil {
		t.Errorf("overview alerts with alerting off = %+v", ov.Alerts)
	}
}
