// Package alertstest generates random store operations for alerts.Store
// implementations. The memory store's tests and the Postgres parity test
// (internal/pgstore TestPGAlertsMatchMemory) share it.
package alertstest

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/ByronGary/kubesentry/internal/alerts"
)

// Base is the reference time random findings are spread after.
var Base = time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)

var (
	checks     = []string{alerts.CheckWorkloadUnhealthy, alerts.CheckCertExpiring, alerts.CheckClusterAdmin, alerts.CheckMemoryLeak}
	kinds      = []string{"Deployment", "Certificate", "ClusterRoleBinding", "StatefulSet"}
	namespaces = []string{"", "payments", "team-a", "kube-system", "zoë"}
	names      = []string{"api", "web", "db-0", "erin-admin", "arn:aws:iam::111122223333:role/ops"}
	states     = []alerts.State{alerts.StateOpen, alerts.StateOpen, alerts.StateAcknowledged, alerts.StateSilenced, alerts.StateResolved}
	owners     = []string{"platform", "payments", "team-alpha"}
	hints      = []string{"", "#payments", "PXYZ123", "ünïcode \"quoted\""}
)

// Commit returns a random commit at about step steps after Base: a few
// findings (some keys repeat across commits, so later ones update earlier
// ones) and sometimes a baseline.
func Commit(rng *rand.Rand, step int) alerts.Commit {
	at := Base.Add(time.Duration(step) * time.Minute).Add(time.Duration(rng.Intn(60_000_000)) * time.Microsecond)
	if rng.Intn(4) == 0 {
		at = at.Add(time.Duration(rng.Intn(1000))) // sub-microsecond noise the stores must drop alike
	}
	var c alerts.Commit
	for n := rng.Intn(6); n > 0; n-- {
		c.Findings = append(c.Findings, Finding(rng, at))
	}
	if rng.Intn(3) == 0 {
		c.Baselines = map[string][]string{}
		for n := 1 + rng.Intn(2); n > 0; n-- {
			ch := checks[rng.Intn(len(checks))]
			var keys []string
			for k := rng.Intn(4); k > 0; k-- {
				keys = append(keys, fmt.Sprintf("%s/%s//%s", ch, kinds[rng.Intn(len(kinds))], names[rng.Intn(len(names))]))
			}
			c.Baselines[ch] = keys // nil sometimes: an empty baseline
		}
	}
	return c
}

// Finding returns a random finding seen at at.
func Finding(rng *rand.Rand, at time.Time) alerts.Finding {
	ch, kind, ns, name := checks[rng.Intn(len(checks))], kinds[rng.Intn(len(kinds))], namespaces[rng.Intn(len(namespaces))], names[rng.Intn(len(names))]
	f := alerts.Finding{
		Key: alerts.Key(ch, kind, ns, name), Alert: "Kubesentry" + kind, Check: ch, Kind: kind, Namespace: ns, Name: name,
		Severity: []string{alerts.SeverityWarning, alerts.SeverityCritical}[rng.Intn(2)],
		Title:    fmt.Sprintf("%s %s/%s", kind, ns, name), Owner: owners[rng.Intn(len(owners))], Production: rng.Intn(3) == 0,
		State: states[rng.Intn(len(states))], Digest: rng.Intn(5) == 0,
		FirstSeen: at.Add(-time.Duration(rng.Intn(3600)) * time.Second), LastSeen: at,
	}
	if rng.Intn(4) > 0 {
		f.Labels = map[string]string{"alertname": f.Alert, "severity": f.Severity, "owner": f.Owner}
		if ns != "" {
			f.Labels["namespace"] = ns
		}
		if h := hints[rng.Intn(len(hints))]; h != "" {
			f.Labels["kubesentry_slack_channel"] = h
		}
	}
	if rng.Intn(4) > 0 {
		f.Annotations = map[string]string{"summary": f.Title, "description": "line one\nline two"}
	}
	if rng.Intn(2) == 0 {
		t := at.Add(-time.Duration(rng.Intn(120)) * time.Second)
		f.LastNotified = &t
	}
	switch f.State {
	case alerts.StateSilenced:
		t := at.Add(time.Hour)
		f.SilencedUntil = &t
	case alerts.StateResolved:
		// Some resolved long ago, so Load's window and Prune have work.
		t := at.Add(-time.Duration(rng.Intn(72)) * time.Hour)
		f.ResolvedAt = &t
	}
	return f
}
