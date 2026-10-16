package incidents

import (
	"context"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/alerts"
	"github.com/ByronGary/kubesentry/internal/model"
)

// boardFixture is three incidents on Deployment shop/api: one capped an
// hour ago, its open continuation (both hold the carried-over alert
// episode), and an older resolved one sharing a deploy with the capped
// one; plus one on shop/web. All are within the board's window.
func boardFixture() (ins []Incident, sigs map[string][]Signal, episode string) {
	api := Subject{Kind: "Deployment", Namespace: "shop", Name: "api"}
	web := Subject{Kind: "Deployment", Namespace: "shop", Name: "web"}
	f := alerts.Finding{Key: alerts.Key(alerts.CheckWorkloadUnhealthy, "Deployment", "shop", "api"),
		FirstSeen: alerts.NormalTime(t0.Add(-22*time.Hour + 123456789*time.Nanosecond))}
	episode = EpisodeID(&f)
	sig := func(id, typ string, role Role, subj Subject, at time.Time) Signal {
		return Signal{ID: id, Type: typ, Source: SourceView, Role: role, Severity: Critical, Start: at, Subject: subj,
			Object: model.ObjectRef{Kind: subj.Kind, Namespace: subj.Namespace, Name: subj.Name}, Title: id}
	}
	mk := func(subj Subject, start time.Time, state State, end *time.Time) Incident {
		return Incident{ID: IncidentID(subj, start), Subject: subj, State: state, Start: start, LastSignal: start, End: end,
			Severity: Critical, PeakSeverity: Critical, Title: subj.Name}
	}
	capAt := t0.Add(-time.Hour)
	oldEnd := t0.Add(-22*time.Hour - 30*time.Minute)
	older := mk(api, t0.Add(-23*time.Hour), Resolved, &oldEnd)
	capped := mk(api, t0.Add(-22*time.Hour), Resolved, &capAt)
	capped.Capped = true
	cont := mk(api, capAt, Open, nil)
	cont.Previous = capped.ID
	other := mk(web, t0.Add(-10*time.Minute), Open, nil)
	deploy := sig("view:deploy:shop/api@3", TypeDeploy, Context, api, t0.Add(-22*time.Hour-10*time.Minute))
	sigs = map[string][]Signal{
		older.ID:  {deploy, sig("view:crashloop:a", TypeCrashLoop, Trigger, api, older.Start)},
		capped.ID: {deploy, sig(episode, TypeAlert, Trigger, api, f.FirstSeen)},
		cont.ID:   {sig(episode, TypeAlert, Trigger, api, capAt)},
		other.ID:  {sig("view:oom-kill:web-1", TypeOOMKill, Trigger, web, other.Start)},
	}
	return []Incident{older, capped, cont, other}, sigs, episode
}

func checkIndex(t *testing.T, what string, of func(string) (string, bool), ins []Incident, episode string) {
	t.Helper()
	older, capped, cont, other := ins[0].ID, ins[1].ID, ins[2].ID, ins[3].ID
	for sid, want := range map[string]string{
		episode:                  cont,   // the open continuation, not the capped incident
		"view:deploy:shop/api@3": capped, // two resolved holders: the newest
		"view:crashloop:a":       older,
		"view:oom-kill:web-1":    other,
	} {
		if got, ok := of(sid); !ok || got != want {
			t.Errorf("%s: IncidentOf(%s) = %q %v, want %q", what, sid, got, ok, want)
		}
	}
	if got, ok := of("view:unknown"); ok || got != "" {
		t.Errorf("%s: an unknown signal maps to %q", what, got)
	}
}

// The board indexes signal IDs to incidents on the leader (each commit it
// applies) and on followers (each refresh from the store).
func TestBoardIncidentOf(t *testing.T) {
	ins, sigs, episode := boardFixture()
	now := t0

	leader := NewBoard(0)
	leader.Apply(ins[:2], map[string][]Signal{ins[0].ID: sigs[ins[0].ID], ins[1].ID: sigs[ins[1].ID]}, now)
	if got, _ := leader.IncidentOf(episode); got != ins[1].ID {
		t.Errorf("before the continuation: %q, want the capped incident", got)
	}
	leader.Apply(ins[2:], map[string][]Signal{ins[2].ID: sigs[ins[2].ID], ins[3].ID: sigs[ins[3].ID]}, now)
	checkIndex(t, "leader", leader.IncidentOf, ins, episode)

	// A follower reads the same incidents from the store.
	store := NewMemoryStore()
	if err := store.Commit(context.Background(), Commit{Incidents: ins, Signals: sigs}); err != nil {
		t.Fatal(err)
	}
	r, err := NewRunner(Config{Store: store, Options: Options{Now: func() time.Time { return now }}})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Refresh(context.Background(), store, false); err != nil {
		t.Fatal(err)
	}
	if _, leading, ready := r.Board().Status(); leading || !ready {
		t.Fatalf("follower board: leader %v ready %v", leading, ready)
	}
	checkIndex(t, "follower", r.IncidentOfSignal, ins, episode)

	// An incident that leaves the board leaves the index.
	end := now.Add(-time.Minute)
	gone := ins[3]
	gone.State, gone.End = Resolved, &end
	later := now.Add(DefaultBoardWindow + time.Hour)
	r2, _ := NewRunner(Config{Store: store, Options: Options{Now: func() time.Time { return later }}})
	if err := store.Commit(context.Background(), Commit{Incidents: []Incident{gone}}); err != nil {
		t.Fatal(err)
	}
	if err := r2.Refresh(context.Background(), store, false); err != nil {
		t.Fatal(err)
	}
	if id, ok := r2.IncidentOfSignal("view:oom-kill:web-1"); ok {
		t.Errorf("a signal of an incident off the board maps to %q", id)
	}
	if id, ok := r2.IncidentOfSignal(episode); !ok || id != ins[2].ID {
		t.Errorf("the open incident stays: %q %v", id, ok)
	}
}
