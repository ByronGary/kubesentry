package api

import (
	"context"
	"strings"
	"testing"

	"github.com/ByronGary/kubesentry/internal/alerts"
	"github.com/ByronGary/kubesentry/internal/auth"
	"github.com/ByronGary/kubesentry/internal/incidents"
	"github.com/ByronGary/kubesentry/internal/model"
)

// linkEpisode puts the episode of ns's unhealthy-workload finding into the
// open web incident of into, as the incidents engine attaches it, and
// refreshes the board. It returns the incident's ID.
func linkEpisode(t *testing.T, s *Server, ns, into string) string {
	t.Helper()
	ctx := context.Background()
	var f alerts.Finding
	for _, x := range s.Alerts.Board().Findings {
		if x.Check == alerts.CheckWorkloadUnhealthy && x.Namespace == ns {
			f = x
		}
	}
	in, _, ok, err := s.IncidentStore.Get(ctx, incidentID(into))
	if err != nil || !ok {
		t.Fatalf("incident in %s: %v %v", into, ok, err)
	}
	sig := incidents.Signal{ID: incidents.EpisodeID(&f), Type: incidents.TypeAlert, Source: incidents.SourceAlerts, Role: incidents.Trigger,
		Severity: incidents.Critical, Start: f.FirstSeen, Subject: in.Subject,
		Object: model.ObjectRef{Kind: f.Kind, Namespace: f.Namespace, Name: f.Name}, Title: f.Title}
	in.Types = append(in.Types, incidents.TypeAlert)
	in.Counts[incidents.TypeAlert]++
	if err := s.IncidentStore.Commit(ctx, incidents.Commit{Incidents: []incidents.Incident{in},
		Signals: map[string][]incidents.Signal{in.ID: {sig}}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Incidents.(*incidents.Runner).Refresh(ctx, s.IncidentStore, true); err != nil {
		t.Fatal(err)
	}
	return in.ID
}

func itemOf(r alertsResponse, key string) *alertItem {
	for i := range r.Items {
		if r.Items[i].Key == key {
			return &r.Items[i]
		}
	}
	return nil
}

// Items name the incident their episode joined, from the incidents board
// as it is when the list is read: the cache follows that board too.
func TestAlertsNameTheirIncident(t *testing.T) {
	s, _ := incidentsServer(t)
	h := s.Handler()
	key := alerts.Key(alerts.CheckWorkloadUnhealthy, "Deployment", "team-a", "web")

	var before alertsResponse
	if rec := getAs(t, h, "alice", "/api/v1/alerts", &before); rec.Header().Get("X-Kubesentry-Cache") != "miss" {
		t.Fatalf("first = %s", rec.Header().Get("X-Kubesentry-Cache"))
	}
	if it := itemOf(before, key); it == nil || it.IncidentID != "" {
		t.Fatalf("before the episode joined: %+v", it)
	}
	if rec := getAs(t, h, "alice", "/api/v1/alerts", nil); rec.Header().Get("X-Kubesentry-Cache") != "hit" {
		t.Errorf("second = %s", rec.Header().Get("X-Kubesentry-Cache"))
	}

	id := linkEpisode(t, s, "team-a", "team-a")
	var after alertsResponse
	rec := getAs(t, h, "alice", "/api/v1/alerts", &after)
	if rec.Header().Get("X-Kubesentry-Cache") != "miss" {
		t.Errorf("after the incidents board changed: %s", rec.Header().Get("X-Kubesentry-Cache"))
	}
	if it := itemOf(after, key); it == nil || it.IncidentID != id {
		t.Errorf("after the episode joined: %+v, want incident %s", it, id)
	}
	if !strings.Contains(rec.Body.String(), `"incidentId":"`+id+`"`) {
		t.Errorf("no incidentId in %s", rec.Body.String())
	}
	for _, it := range after.Items {
		if it.Key != key && it.IncidentID != "" {
			t.Errorf("%s names incident %s", it.Key, it.IncidentID)
		}
	}
	if rec := getAs(t, h, "alice", "/api/v1/alerts", &after); rec.Header().Get("X-Kubesentry-Cache") != "hit" || itemOf(after, key).IncidentID != id {
		t.Errorf("cached: %s %+v", rec.Header().Get("X-Kubesentry-Cache"), itemOf(after, key))
	}
	// bob sees team-b's findings only, and none of them joined an incident.
	var bob alertsResponse
	getAs(t, h, "bob", "/api/v1/alerts", &bob)
	for _, it := range bob.Items {
		if it.IncidentID != "" || it.Namespace == "team-a" {
			t.Errorf("bob's item %s: incident %q", it.Key, it.IncidentID)
		}
	}

	// An incident in another namespace is never named, even to a caller
	// who sees both.
	s2, _ := incidentsServer(t)
	linkEpisode(t, s2, "team-a", "team-b")
	s2.Authenticator, s2.Authorizer = nil, nil
	var all alertsResponse
	getAs(t, s2.Handler(), "", "/api/v1/alerts", &all)
	if it := itemOf(all, key); it == nil || it.IncidentID != "" {
		t.Errorf("an episode in another namespace's incident: %+v", it)
	}
}

// /info lists incidents sources in error under unavailable, with
// CloudTrail's reason masked for callers without the cloudtrail capability.
func TestInfoUnavailableIncidentSources(t *testing.T) {
	s, _ := incidentsServer(t)
	s.Incidents = sourcesOverride{IncidentsSource: s.Incidents, sources: map[string]string{
		"events": "error: kube: events are forbidden: forbidden: cannot watch events", "cloudtrail": "error: access denied (cloudtrail:LookupEvents)",
		"memory": "ok", "requests:nginx": "absent", "logs:kubernetes": "ok",
	}}
	h := s.Handler()
	var info infoResponse
	getAs(t, h, "alice", "/api/v1/info", &info)
	if got := info.Unavailable["incidents:events"]; got != "error: kube: events are forbidden: forbidden: cannot watch events" {
		t.Errorf("incidents:events = %q (all: %v)", got, info.Unavailable)
	}
	if got := info.Unavailable["incidents:cloudtrail"]; got != "error" {
		t.Errorf("incidents:cloudtrail without the capability = %q", got)
	}
	for _, k := range []string{"incidents:memory", "incidents:requests:nginx", "incidents:logs:kubernetes"} {
		if v, ok := info.Unavailable[k]; ok {
			t.Errorf("%s listed: %q", k, v)
		}
	}
	regrant(s, grant("alice", auth.ViewCloudTrail, ""))
	info = infoResponse{}
	getAs(t, s.Handler(), "alice", "/api/v1/info", &info)
	if got := info.Unavailable["incidents:cloudtrail"]; got != "error: access denied (cloudtrail:LookupEvents)" {
		t.Errorf("incidents:cloudtrail with the capability = %q", got)
	}
}

// sourcesOverride reports fixed source states.
type sourcesOverride struct {
	IncidentsSource
	sources map[string]string
}

func (o sourcesOverride) Sources() map[string]string {
	out := make(map[string]string, len(o.sources))
	for k, v := range o.sources {
		out[k] = v
	}
	return out
}
