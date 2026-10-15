package incidents

import (
	"sort"
	"time"

	"github.com/ByronGary/kubesentry/internal/alerts"
	"github.com/ByronGary/kubesentry/internal/model"
)

// workloadChecks are the alert checks about workloads; the others
// (certificates, RBAC) have no workload root to group under.
var workloadChecks = map[string]bool{
	alerts.CheckWorkloadUnhealthy: true, alerts.CheckPodEvicted: true, alerts.CheckPodStuckTerminating: true, alerts.CheckMemoryLeak: true,
}

// AlertEpisodes turns phase B alert findings into alert signals. An episode
// is one firing of a finding: its ID is key@FirstSeen, so a finding that
// resolves and fires again (the alerts store upserts it by key) is a new
// episode, and the alerts code needs no change. An episode is a condition:
// it ends when the finding resolves, or when it leaves the board.
type AlertEpisodes struct {
	active   map[string]*Signal   // episode ID → its signal
	lastSeen map[string]time.Time // episode ID → the finding's LastSeen
}

// NewAlertEpisodes returns an empty tracker.
func NewAlertEpisodes() *AlertEpisodes {
	return &AlertEpisodes{active: map[string]*Signal{}, lastSeen: map[string]time.Time{}}
}

// Resume continues the episodes of open incidents (Engine.Active).
func (p *AlertEpisodes) Resume(active []Signal) {
	for _, s := range active {
		if s.Type == TypeAlert && s.Source == SourceAlerts {
			c := CloneSignal(s)
			p.active[s.ID] = &c
		}
	}
}

// EpisodeID is the signal ID of a finding's current episode.
func EpisodeID(f *alerts.Finding) string {
	return "alert:" + f.Key + "@" + f.FirstSeen.UTC().Format(time.RFC3339Nano)
}

// Scan reads the current findings (the alerts board) and returns the
// signals of the episodes that are firing, or ended since the last scan.
func (p *AlertEpisodes) Scan(findings []alerts.Finding, now time.Time) []Signal {
	now = NormalTime(now)
	var out []Signal
	present := map[string]bool{}
	for i := range findings {
		f := &findings[i]
		if !workloadChecks[f.Check] || f.RBAC() || f.Namespace == "" || f.Name == "" {
			continue
		}
		id := EpisodeID(f)
		present[id] = true
		_, ok := p.active[id]
		if f.Resolved() && !ok {
			continue // ended before we saw it
		}
		sev := Warning
		if f.Severity == alerts.SeverityCritical {
			sev = Critical
		}
		subj := Subject{Kind: f.Kind, Namespace: f.Namespace, Name: f.Name}
		sig := Signal{ID: id, Type: TypeAlert, Source: SourceAlerts, Role: Trigger, Severity: sev, Start: f.FirstSeen,
			Subject: subj, Object: model.ObjectRef{Kind: f.Kind, Namespace: f.Namespace, Name: f.Name}, Title: f.Title,
			Attrs: map[string]string{"alert": f.Alert, "check": f.Check, "key": f.Key, "state": string(f.State), "owner": f.Owner}}
		if f.Resolved() {
			end := f.LastSeen
			if f.ResolvedAt != nil {
				end = *f.ResolvedAt
			}
			sig.End = timePtr(end)
			delete(p.active, id)
			delete(p.lastSeen, id)
		} else {
			c := CloneSignal(sig)
			p.active[id] = &c
			p.lastSeen[id] = f.LastSeen
		}
		out = append(out, sig)
	}
	ids := make([]string, 0, len(p.active))
	for id := range p.active {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if present[id] {
			continue
		}
		s := p.active[id]
		end := now
		if t, ok := p.lastSeen[id]; ok && t.Before(now) && !t.Before(s.Start) {
			end = t
		}
		s.End = timePtr(end)
		out = append(out, *s)
		delete(p.active, id)
		delete(p.lastSeen, id)
	}
	return out
}
