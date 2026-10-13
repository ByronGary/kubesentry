package alerts

import (
	"strings"
	"testing"
	"time"
)

func candidatesByKey(f Found) map[string]Candidate {
	out := map[string]Candidate{}
	for _, c := range f.Candidates {
		out[c.Key()] = c
	}
	return out
}

func TestChecksFindEachProblemOncePerWorkload(t *testing.T) {
	v := view(fixture(), t0)
	f := Run(Input{View: v, Leaks: leakReport(t0), Now: t0}, 0)
	got := candidatesByKey(f)
	want := map[string]string{ // key → severity
		"cert-expiring/Certificate/payments/api-tls":    SeverityCritical,
		"cert-not-ready/Certificate/team-a/lost-tls":    SeverityCritical,
		"workload-unhealthy/Deployment/payments/api":    SeverityCritical,
		"workload-unhealthy/Deployment/team-a/img":      SeverityCritical, // 0 of 1 ready
		"workload-unhealthy/Pod/team-a/huge":            SeverityWarning,
		"pod-evicted/Deployment/payments/batch":         SeverityWarning,
		"pod-stuck-terminating/Deployment/payments/web": SeverityWarning,
		"memory-leak/Deployment/payments/cache":         SeverityCritical,
		"cluster-admin/ClusterRoleBinding//erin-admin":  SeverityCritical,
	}
	for k, sev := range want {
		c, ok := got[k]
		if !ok {
			t.Errorf("missing %s", k)
			continue
		}
		if c.Severity != sev {
			t.Errorf("%s severity = %s, want %s", k, c.Severity, sev)
		}
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("unexpected candidate %s: %+v", k, got[k])
		}
	}
	if len(f.Skipped) != 1 || !f.Skipped[CheckAWSAuthMasters] {
		t.Errorf("skipped = %v, want only aws-auth (not configured)", f.Skipped)
	}

	api := got["workload-unhealthy/Deployment/payments/api"]
	if api.Title != "Deployment payments/api: CrashLoopBackOff ×3" || api.Extra["pods"] != "3" || api.Extra["reasons"] != "CrashLoopBackOff=3" ||
		!strings.Contains(api.Description, "3 of 4 pods") || !strings.Contains(api.Description, "back-off 5m0s") || api.Link != "#/workloads?namespace=payments&q=api" {
		t.Errorf("api = %+v", api)
	}
	if huge := got["workload-unhealthy/Pod/team-a/huge"]; !strings.Contains(huge.Description, "Insufficient memory") || huge.Link != "#/pods/team-a/huge" {
		t.Errorf("huge = %+v", huge)
	}
	if ev := got["pod-evicted/Deployment/payments/batch"]; ev.Node != "" || ev.Extra["pods"] != "2" ||
		ev.Extra["latest_eviction"] != t0.Add(-2*time.Hour).Format(time.RFC3339) || !strings.Contains(ev.Description, "low on resource: memory") {
		t.Errorf("evicted = %+v (pods on two nodes: no node label)", ev)
	}
	if st := got["pod-stuck-terminating/Deployment/payments/web"]; st.Node != "node-1" || st.Extra["oldest_deletion"] != t0.Add(-30*time.Minute).Format(time.RFC3339) {
		t.Errorf("stuck = %+v (both on node-1: node label)", st)
	}
	leak := got["memory-leak/Deployment/payments/cache"]
	if leak.Extra["predicted_oom"] != t0.Add(3*time.Hour).Format(time.RFC3339) || leak.Extra["container"] != "cache" || leak.Link != "#/pods/payments/cache-7d9f-0" ||
		!strings.Contains(leak.Title, "reaches its limit in ~3h") {
		t.Errorf("leak = %+v", leak)
	}
	if c := got["cert-expiring/Certificate/payments/api-tls"]; c.Extra["issuer"] != "ClusterIssuer/le" || !strings.Contains(c.Title, "Expires in 3 days") {
		t.Errorf("cert = %+v", c)
	}
	if c := got["cert-not-ready/Certificate/team-a/lost-tls"]; c.Extra["reason"] != "issuer-missing" {
		t.Errorf("lost-tls = %+v", c)
	}
}

// A short-lived certificate renewing on schedule is always close to expiry
// and stays quiet; once its renewal is overdue by more than the grace, it
// alerts.
func TestCertificateRenewalAware(t *testing.T) {
	inv := fixture()
	at := t0
	if _, ok := candidatesByKey(Run(Input{View: view(inv, at), Now: at}, 0))["cert-expiring/Certificate/payments/fresh-tls"]; ok {
		t.Fatal("fresh-tls renews in 2h but alerts")
	}
	at = t0.Add(3*time.Hour + time.Minute) // renewal time +1h01m, 59 minutes left
	if c, ok := candidatesByKey(Run(Input{View: view(inv, at), Now: at}, 0))["cert-expiring/Certificate/payments/fresh-tls"]; !ok || c.Severity != SeverityCritical {
		t.Fatalf("fresh-tls overdue for renewal: %+v, %v", c, ok)
	}
}

// Data that cannot be read is skipped, not taken as "no problems".
func TestChecksSkipUnreadableSources(t *testing.T) {
	inv := fixture()
	inv.Unavailable = map[string]string{"clusterrolebindings": "forbidden", "pods": "forbidden", "certificates.cert-manager.io": "forbidden"}
	f := Run(Input{View: view(inv, t0), Now: t0}, 0)
	for _, c := range []string{CheckClusterAdmin, CheckWildcardRBAC, CheckAnonymousBinding, CheckWorkloadUnhealthy, CheckPodEvicted,
		CheckPodStuckTerminating, CheckCertExpiring, CheckCertNotReady, CheckMemoryLeak} {
		if !f.Skipped[c] {
			t.Errorf("%s not skipped", c)
		}
	}
	for _, c := range f.Candidates {
		if f.Skipped[c.Check] {
			t.Errorf("candidate of a skipped check: %+v", c)
		}
	}
}

func TestHintLabel(t *testing.T) {
	for in, want := range map[string]string{
		"kubesentry.io/slack-channel":     "kubesentry_slack_channel",
		"kubesentry.io/pagerduty.service": "kubesentry_pagerduty_service",
		"kubesentry.io/Team_ü":            "kubesentry_Team__",
		"example.com/slack":               "",
		"kubesentry.io/":                  "",
	} {
		if got := HintLabel(in); got != want {
			t.Errorf("HintLabel(%q) = %q, want %q", in, got, want)
		}
	}
}
