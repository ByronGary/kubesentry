package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/alerts"
	"github.com/ByronGary/kubesentry/internal/incidents"
	"github.com/ByronGary/kubesentry/internal/metrics"
	"github.com/ByronGary/kubesentry/internal/model"
)

// plainLogs is a log source without a probe.
type plainLogs struct{}

func (plainLogs) Name() string { return "kubernetes" }
func (plainLogs) Logs(context.Context, incidents.LogQuery) (incidents.LogResult, error) {
	return incidents.LogResult{}, nil
}

// The alerts' lookup finds a finding's episode on this replica's incidents
// board, whether the finding comes from the evaluator's memory (UTC) or
// from Postgres (the local zone): only the instant matters.
func TestIncidentLookup(t *testing.T) {
	ctx := context.Background()
	first := alerts.NormalTime(time.Now().Add(-time.Hour))
	subj := incidents.Subject{Kind: "Deployment", Namespace: "shop", Name: "api"}
	f := alerts.Finding{Key: alerts.Key(alerts.CheckWorkloadUnhealthy, "Deployment", "shop", "api"), Check: alerts.CheckWorkloadUnhealthy,
		Kind: "Deployment", Namespace: "shop", Name: "api", FirstSeen: first}
	in := incidents.Incident{ID: incidents.IncidentID(subj, first), Subject: subj, State: incidents.Open, Start: first, LastSignal: first,
		Severity: incidents.Critical, PeakSeverity: incidents.Critical, Types: []string{incidents.TypeAlert}, Counts: map[string]int{incidents.TypeAlert: 1}}
	sig := incidents.Signal{ID: incidents.EpisodeID(&f), Type: incidents.TypeAlert, Source: incidents.SourceAlerts, Role: incidents.Trigger,
		Severity: incidents.Critical, Start: first, Subject: subj, Object: model.ObjectRef{Kind: "Deployment", Namespace: "shop", Name: "api"}}
	store := incidents.NewMemoryStore()
	if err := store.Commit(ctx, incidents.Commit{Incidents: []incidents.Incident{in}, Signals: map[string][]incidents.Signal{in.ID: {sig}}}); err != nil {
		t.Fatal(err)
	}
	r, err := incidents.NewRunner(incidents.Config{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Refresh(ctx, store, false); err != nil {
		t.Fatal(err)
	}
	lookup := incidentLookup(r)
	if got := lookup(&f); got != in.ID {
		t.Errorf("lookup = %q, want %s", got, in.ID)
	}
	fromPG := f
	fromPG.FirstSeen = first.In(time.FixedZone("EDT", -4*3600))
	if got := lookup(&fromPG); got != in.ID {
		t.Errorf("lookup of the stored finding = %q", got)
	}
	next := f
	next.FirstSeen = first.Add(time.Minute) // a later episode
	if got := lookup(&next); got != "" {
		t.Errorf("another episode found %q", got)
	}
}

// kubesentry_incident_source_up has a sample per source that is not
// absent; kubesentry_incidents_leader follows the runner.
func TestIncidentSourceMetrics(t *testing.T) {
	for state, want := range map[string]struct {
		v  float64
		ok bool
	}{"ok": {1, true}, "error: kube: events are forbidden": {0, true}, "absent": {0, false}, "": {0, false}} {
		if v, ok := sourceUp(state); v != want.v || ok != want.ok {
			t.Errorf("sourceUp(%q) = %v %v", state, v, ok)
		}
	}
	r, err := incidents.NewRunner(incidents.Config{Store: incidents.NewMemoryStore(), Logs: []incidents.LogSource{plainLogs{}}})
	if err != nil {
		t.Fatal(err)
	}
	incidentMetrics(r)
	var b strings.Builder
	if err := metrics.Default.WriteText(&b); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, `kubesentry_incident_source_up{source="logs:kubernetes"} 1`+"\n") {
		t.Errorf("logs:kubernetes is not up:\n%s", out)
	}
	for _, absent := range []string{"memory", "events", "cloudtrail", "audit", "alerts", "series"} {
		if strings.Contains(out, `kubesentry_incident_source_up{source="`+absent+`"}`) {
			t.Errorf("absent source %s exported", absent)
		}
	}
	if !strings.Contains(out, "kubesentry_incidents_leader 0\n") {
		t.Error("kubesentry_incidents_leader is not 0 on a runner that does not lead")
	}
}
