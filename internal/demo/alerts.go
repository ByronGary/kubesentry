package demo

// The demo's alerts: what the alerting evaluator would have raised over the
// demo cluster in the last hours, committed to a memory store, with what
// people did about them in the actions log:
//
//   - recommendations (prod), critical, acknowledged by dave: its crash
//     loop; the alert joined the recommendations incident.
//   - the security catalog, open: a new NodePort on grafana, a privileged
//     ml-trainer, a new cluster-admin binding for erin, alice's exec into a
//     production pod, a node whose agent stopped reporting, and a
//     certificate that is not ready.
//   - search-indexer (staging), silenced by erin: a known memory leak.
//   - search-staging-tls, quiet: far enough from expiry that only the
//     standing digest reports it.
//   - bob's RBAC changes, resolved: the audit finding closed an hour after
//     his last change.
//
// The runner is never run and has no sink, so nothing is evaluated or sent
// anywhere; acknowledging and silencing work through the real runner (Act),
// as on a replica that does not lead.

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/ByronGary/kubesentry/internal/alerts"
	"github.com/ByronGary/kubesentry/internal/incidents"
	"github.com/ByronGary/kubesentry/internal/model"
	"github.com/ByronGary/kubesentry/internal/uilink"
)

// The demo's cluster name and the owner of cluster-scoped findings
// (-alerts-default-owner).
const (
	demoClusterName   = "demo-eks"
	demoDefaultOwner  = "team-platform"
	demoAgentNS       = "kubesentry"
	demoAgentDS       = "kubesentry-agent"
	searchIndexerPod  = "search-indexer-0"
	recsAckAgo        = 38 * time.Minute
	indexerSilenceAgo = 4 * time.Hour
	indexerSilenceFor = 72 * time.Hour
)

// The keys of the seeded findings the tests and the stories refer to.
var (
	recsAlertKey    = alerts.Key(alerts.CheckWorkloadUnhealthy, "Deployment", "prod", "recommendations")
	indexerAlertKey = alerts.Key(alerts.CheckMemoryLeak, "StatefulSet", "staging", "search-indexer")
	certQuietKey    = alerts.Key(alerts.CheckCertExpiring, "Certificate", "staging", "search-staging-tls")
	bobRBACKey      = alerts.Key(alerts.CheckAuditRBACChange, "User", "", "bob")
)

// alertNames maps each seeded check to its alertname.
var alertNames = map[string]string{
	alerts.CheckWorkloadUnhealthy: alerts.AlertWorkloadUnhealthy,
	alerts.CheckMemoryLeak:        alerts.AlertMemoryLeak,
	alerts.CheckCertExpiring:      alerts.AlertCertificateExpiring,
	alerts.CheckCertNotReady:      alerts.AlertCertificateNotReady,
	alerts.CheckClusterAdmin:      alerts.AlertRBACDrift,
	alerts.CheckNodePort:          alerts.AlertExposureChange,
	alerts.CheckPrivileged:        alerts.AlertPrivilegedWorkload,
	alerts.CheckAuditExec:         alerts.AlertAuditActivity,
	alerts.CheckAuditRBACChange:   alerts.AlertAuditActivity,
	alerts.CheckAgentMissing:      alerts.AlertAgentMissing,
}

// workloadLabel lists the checks whose findings carry a workload label
// rather than an object label (the evaluator's checkInfos).
var workloadLabel = map[string]bool{
	alerts.CheckWorkloadUnhealthy: true, alerts.CheckMemoryLeak: true, alerts.CheckPrivileged: true,
}

// nsOwners are the demo namespaces' owners and routing hints (inventory.go).
var nsOwners = map[string]struct{ owner, slack string }{
	"prod": {"team-shop", "#shop-oncall"}, "staging": {"team-shop", ""}, "data": {"team-data", "#data-eng"},
	"monitoring": {"team-platform", ""}, "ci": {"team-platform", ""},
}

// seed is one finding to seed, in the evaluator's words.
type seed struct {
	check, kind, ns, name, severity string
	title, description, link        string
	first                           time.Duration // first seen this long before t0
	extra                           map[string]string
	quiet                           bool
	resolved                        time.Duration // resolved this long before t0; 0 while open
	node                            string
}

// finding builds the finding the leader would have stored for sd, at t0.
func (sd seed) finding(t0 time.Time) alerts.Finding {
	alert := alertNames[sd.check]
	own := nsOwners[sd.ns]
	owner := own.owner
	if owner == "" {
		owner = demoDefaultOwner
	}
	production := sd.ns == "prod"
	l := map[string]string{
		"alertname": alert, "severity": sd.severity, "check": sd.check, "owner": owner, "cluster": demoClusterName,
		"production": map[bool]string{true: "true", false: "false"}[production],
	}
	if sd.ns != "" {
		l["namespace"] = sd.ns
	}
	if workloadLabel[sd.check] {
		l["workload"] = sd.kind + "/" + sd.name
	} else {
		l["object"] = sd.kind + "/" + sd.name
	}
	if sd.node != "" {
		l["node"] = sd.node
	}
	if own.slack != "" {
		l["kubesentry_slack_channel"] = own.slack
	}
	key := alerts.Key(sd.check, sd.kind, sd.ns, sd.name)
	a := map[string]string{
		"summary": sd.title, "description": sd.description, "dedupe_key": key,
		"runbook_url": alerts.DefaultRunbookURL + "#" + strings.ToLower(alert),
	}
	for k, v := range sd.extra {
		a[k] = v
	}
	f := alerts.Finding{
		Key: key, Alert: alert, Check: sd.check, Kind: sd.kind, Namespace: sd.ns, Name: sd.name, Severity: sd.severity,
		Title: sd.title, Owner: owner, Production: production, Labels: l, Annotations: a, State: alerts.StateOpen,
		FirstSeen: t0.Add(-sd.first), LastSeen: t0, Link: sd.link, Quiet: sd.quiet,
	}
	if sd.resolved > 0 {
		at := t0.Add(-sd.resolved)
		f.State, f.ResolvedAt, f.LastSeen = alerts.StateResolved, &at, at.Add(-30*time.Second)
	}
	return f
}

// alertSeeds are the findings, relative to t0.
func alertSeeds(t0 time.Time) []seed {
	at := func(d time.Duration) string { return t0.Add(-d).UTC().Format(time.RFC3339) }
	h := time.Hour
	const api = "checkout-api-7d9f8b6c4-x2k9p"
	return []seed{
		{check: alerts.CheckWorkloadUnhealthy, kind: "Deployment", ns: "prod", name: "recommendations", severity: alerts.SeverityCritical,
			title: "Deployment prod/recommendations: CrashLoopBackOff ×1",
			description: "1 of 1 pod of Deployment prod/recommendations cannot run: CrashLoopBackOff ×1. " + recsPod +
				": back-off 5m0s restarting failed container=api pod=" + recsPod + "_prod",
			link: uilink.Workload("prod", "recommendations"), first: recsLoopAgo - time.Minute,
			extra: map[string]string{"pods": "1", "reasons": "CrashLoopBackOff"}},
		{check: alerts.CheckMemoryLeak, kind: "StatefulSet", ns: "staging", name: "search-indexer", severity: alerts.SeverityWarning,
			title:       "StatefulSet staging/search-indexer: Memory leak in indexer: 38 MiB/h, no memory limit",
			description: "Container indexer of pod " + searchIndexerPod + " grows 38 MiB/h (R² 0.97, high confidence); it has no memory limit, so nothing stops it growing.",
			link:        uilink.Pod("staging", searchIndexerPod), first: 9 * h,
			extra: map[string]string{"pods": "1", "container": "indexer", "pod": searchIndexerPod, "growth_bytes_per_hour": "39845888"}},
		{check: alerts.CheckCertExpiring, kind: "Certificate", ns: "staging", name: "search-staging-tls", severity: alerts.SeverityWarning,
			title: "Certificate staging/search-staging-tls: expires in 20 days and renewal is not scheduled before then",
			description: "Certificate staging/search-staging-tls for search.staging.example.com (issuer Issuer/selfsigned, secret search-staging-tls): " +
				"expires in 20 days and renewal is not scheduled before then. cert-manager has not renewed it on schedule; check the issuer and the latest CertificateRequest.",
			link: uilink.Certificate("staging", "search-staging-tls"), first: 3 * 24 * h, quiet: true,
			extra: map[string]string{"issuer": "Issuer/selfsigned", "expires_at": t0.Add(20*24*h + 6*h).UTC().Format(time.RFC3339)}},
		{check: alerts.CheckCertNotReady, kind: "Certificate", ns: "prod", name: "api-internal-tls", severity: alerts.SeverityCritical,
			title: "Certificate prod/api-internal-tls is not ready: Issuing certificate as Secret does not exist",
			description: "Certificate prod/api-internal-tls for checkout-api.prod.svc, checkout-api.prod.svc.cluster.local (issuer ClusterIssuer/vault-intermediate, " +
				"secret api-internal-tls) is not ready: Issuing certificate as Secret does not exist",
			link: uilink.Certificate("prod", "api-internal-tls"), first: 2*h + 40*time.Minute,
			extra: map[string]string{"issuer": "ClusterIssuer/vault-intermediate", "reason": "not-ready"}},
		{check: alerts.CheckClusterAdmin, kind: "ClusterRoleBinding", name: "erin-cluster-admin", severity: alerts.SeverityCritical,
			title:       "RBAC drift: new cluster-admin binding: ClusterRoleBinding erin-cluster-admin",
			description: "kubesentry saw this appear since its last evaluation: ClusterRoleBinding erin-cluster-admin: Grants cluster-admin to User erin.",
			link:        uilink.Security(alerts.CheckClusterAdmin, "erin-cluster-admin"), first: 7 * h},
		{check: alerts.CheckNodePort, kind: "Service", ns: "monitoring", name: "grafana", severity: alerts.SeverityWarning,
			title:       "Exposure change: new NodePort service: Service monitoring/grafana",
			description: "kubesentry saw this appear since its last evaluation: Service monitoring/grafana: Opens port 30300/TCP on every node.",
			link:        uilink.Security(alerts.CheckNodePort, "monitoring/grafana"), first: 2*h + 10*time.Minute},
		{check: alerts.CheckPrivileged, kind: "Deployment", ns: "data", name: "ml-trainer", severity: alerts.SeverityCritical,
			title:       "Privileged workload: new privileged container: Deployment data/ml-trainer",
			description: "kubesentry saw this appear since its last evaluation: Deployment data/ml-trainer: Runs privileged, with full access to the node: trainer.",
			link:        uilink.Security(alerts.CheckPrivileged, "data/ml-trainer"), first: 3 * h},
		{check: alerts.CheckAuditExec, kind: "User", ns: "prod", name: "alice", severity: alerts.SeverityWarning,
			title: "Audit: alice used exec, attach, port-forward or a debug container in namespace prod (2 times)",
			description: "alice (user) used exec, attach, port-forward or a debug container in namespace prod, 2 times between " + at(45*time.Minute) +
				" and " + at(22*time.Minute) + " (create pods/exec). The finding stays open until 1 hour passes without another such request.",
			link: uilink.Activity("", "alice"), first: 44 * time.Minute,
			extra: map[string]string{"actor": "alice", "actor_kind": "user", "count": "2", "first_at": at(45 * time.Minute), "last_at": at(22 * time.Minute),
				"verbs":    "create pods/exec",
				"examples": at(45*time.Minute) + " create pods/exec prod/" + api + ": sh\n" + at(22*time.Minute) + " create pods/exec prod/" + api + ": cat /proc/meminfo"}},
		{check: alerts.CheckAgentMissing, kind: "DaemonSet", name: demoAgentNS + "/" + demoAgentDS, severity: alerts.SeverityWarning,
			title: "Agent DaemonSet " + demoAgentNS + "/" + demoAgentDS + ": 1 node is not reporting",
			description: "The kubesentry agent on node " + nodeC + " has not reported for 45s (3 report intervals), though it runs a pod of DaemonSet " +
				demoAgentNS + "/" + demoAgentDS + ": process data for its pods is missing or stale. Check the agent pod there (crash loop, OOM kill, network policy, the ingest token).",
			link: uilink.Agents(), first: 25 * time.Minute, node: nodeC,
			extra: map[string]string{"nodes": nodeC, "count": "1"}},
		{check: alerts.CheckAuditRBACChange, kind: "User", name: "bob", severity: alerts.SeverityWarning,
			title: "Audit: bob changed roles or role bindings cluster-wide (2 times)",
			description: "bob (user) changed roles or role bindings cluster-wide, 2 times between " + at(5*h) + " and " + at(4*h+45*time.Minute) +
				" (create clusterrolebindings, delete clusterrolebindings). The finding stays open until 1 hour passes without another such request.",
			link: uilink.Activity("rbac-change", "bob"), first: 5*h - time.Minute, resolved: 3*h + 45*time.Minute,
			extra: map[string]string{"actor": "bob", "actor_kind": "user", "count": "2", "first_at": at(5 * h), "last_at": at(4*h + 45*time.Minute),
				"verbs":    "create clusterrolebindings, delete clusterrolebindings",
				"examples": at(5*h) + " create clusterrolebindings tmp-admin\n" + at(4*h+45*time.Minute) + " delete clusterrolebindings tmp-admin"}},
	}
}

// seededAlerts are the findings at t0 and the actions people took on them.
func seededAlerts(t0 time.Time) ([]alerts.Finding, []alerts.Action) {
	seeds := alertSeeds(t0)
	fs := make([]alerts.Finding, len(seeds))
	byKey := map[string]*alerts.Finding{}
	for i, sd := range seeds {
		fs[i] = sd.finding(t0)
		byKey[fs[i].Key] = &fs[i]
	}
	act := func(key string, kind alerts.ActionKind, actor string, ago time.Duration) alerts.Action {
		f := byKey[key]
		return alerts.Action{Key: key, FirstSeen: f.FirstSeen, Action: kind, Actor: actor, Severity: f.Severity, At: t0.Add(-ago)}
	}
	silence := act(indexerAlertKey, alerts.ActionSilence, "erin", indexerSilenceAgo)
	until := silence.At.Add(indexerSilenceFor)
	silence.Until = &until
	silence.Reason = "Known leak in indexer 5.1.0; the fix ships with 5.1.1 on Thursday. dave restarts the pod nightly until then."
	return fs, []alerts.Action{
		act(bobRBACKey, alerts.ActionAck, "carol", 4*time.Hour+50*time.Minute),
		silence,
		act(recsAlertKey, alerts.ActionAck, "dave", recsAckAgo),
	}
}

// alertSignals are the alert signals (incidents.AlertEpisodes) of the
// seeded findings that belong to the stories: the evaluator's workload
// alerts join the incident of their workload. Only recommendations has one.
func alertSignals(t0 time.Time) []incidents.Signal {
	fs, _ := seededAlerts(t0)
	var out []incidents.Signal
	for i := range fs {
		f := &fs[i]
		if f.Key != recsAlertKey {
			continue
		}
		sev := incidents.Warning
		if f.Severity == alerts.SeverityCritical {
			sev = incidents.Critical
		}
		sig := incidents.Signal{ID: incidents.EpisodeID(f), Type: incidents.TypeAlert, Source: incidents.SourceAlerts, Role: incidents.Trigger,
			Severity: sev, Start: f.FirstSeen, Subject: incidents.Subject{Kind: f.Kind, Namespace: f.Namespace, Name: f.Name},
			Object: model.ObjectRef{Kind: f.Kind, Namespace: f.Namespace, Name: f.Name}, Title: f.Title,
			Attrs: map[string]string{"alert": f.Alert, "check": f.Check, "key": f.Key, "state": string(alerts.StateOpen), "owner": f.Owner}}
		out = append(out, sig)
	}
	return out
}

// demoAlerts serves the seeded alerts. The evaluator does not run (nothing
// new happens in the demo), so this replica is said to lead, as the demo's
// incidents are.
type demoAlerts struct{ *alerts.Runner }

func (d demoAlerts) Status() alerts.Status {
	s := d.Runner.Status()
	s.Leader = true
	return s
}

// NewAlerts seeds an alerts runner's memory store with the demo's findings
// and actions at t0 (the incidents' t0, whole seconds) and reads them into
// its board.
func NewAlerts(ctx context.Context, t0 time.Time) (*alerts.Runner, error) {
	st := alerts.NewMemoryStore()
	fs, acts := seededAlerts(t0)
	if err := st.Commit(ctx, alerts.Commit{Findings: fs}); err != nil {
		return nil, err
	}
	for _, a := range acts {
		if _, err := st.AddAction(ctx, a); err != nil {
			return nil, err
		}
	}
	r := &alerts.Runner{Store: st, Sink: alerts.NopSink{}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Options: alerts.Options{Cluster: demoClusterName, DefaultOwner: demoDefaultOwner}}
	r.Reload(ctx)
	return r, nil
}
