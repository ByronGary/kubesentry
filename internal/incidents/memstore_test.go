package incidents_test

import (
	"context"
	"fmt"
	"math/rand"
	"reflect"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/incidents"
	"github.com/ByronGary/kubesentry/internal/incidents/incidentstest"
	"github.com/ByronGary/kubesentry/internal/model"
)

// A store is checked against a plain model of it: incidents by ID with
// their signals by ID, normalized; queries evaluated with Query.Matches.
func TestMemoryStoreAgainstModel(t *testing.T) {
	ctx := context.Background()
	for seed := int64(1); seed <= 3; seed++ {
		rng := rand.New(rand.NewSource(seed))
		st := incidents.NewMemoryStore()
		model := map[string]incidents.Incident{}
		sigs := map[string]map[string]incidents.Signal{}
		for step := 0; step < 200; step++ {
			c := incidentstest.Commit(rng, step)
			if err := st.Commit(ctx, c); err != nil {
				t.Fatal(err)
			}
			for _, in := range c.Incidents {
				model[in.ID] = incidents.NormalizeIncident(incidents.CloneIncident(in))
			}
			for id, ss := range c.Signals {
				if sigs[id] == nil {
					sigs[id] = map[string]incidents.Signal{}
				}
				for _, s := range ss {
					sigs[id][s.ID] = incidents.NormalizeSignal(s)
				}
			}
			q := incidentstest.Query(rng, step)
			got, err := st.List(ctx, q)
			if err != nil {
				t.Fatal(err)
			}
			var want []incidents.Incident
			for _, in := range model {
				if q.Matches(&in) {
					want = append(want, in)
				}
			}
			incidents.SortNewest(want)
			if q.Limit > 0 && len(want) > q.Limit {
				want = want[:q.Limit]
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("seed %d step %d: list %+v\ngot  %d\nwant %d", seed, step, q, len(got), len(want))
			}
		}
		for id, in := range model {
			got, ss, ok, err := st.Get(ctx, id)
			if err != nil || !ok || !reflect.DeepEqual(got, in) {
				t.Fatalf("get %s: %v %v\n%+v\n%+v", id, ok, err, got, in)
			}
			var want []incidents.Signal
			for _, s := range sigs[id] {
				want = append(want, s)
			}
			incidents.SortSignals(want)
			if !reflect.DeepEqual(ss, want) {
				t.Fatalf("signals of %s:\n%+v\n%+v", id, ss, want)
			}
		}
		open, osigs, err := st.LoadOpen(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, in := range open {
			if in.State != incidents.Open || len(osigs[in.ID]) != len(sigs[in.ID]) {
				t.Fatalf("load open: %s %s %d signals", in.ID, in.State, len(osigs[in.ID]))
			}
		}
	}
}

func TestMemoryStorePagingPruneAndBounds(t *testing.T) {
	ctx := context.Background()
	st := incidents.NewMemoryStore()
	base := incidentstest.Base
	var c incidents.Commit
	for i := 0; i < 25; i++ {
		s := incidents.Subject{Kind: "Deployment", Namespace: "shop", Name: fmt.Sprint("app-", i%5)}
		start := base.Add(time.Duration(i/2) * time.Minute) // pairs share a start
		in := incidents.Incident{ID: incidents.IncidentID(s, start), Subject: s, State: incidents.Resolved, Start: start,
			Severity: incidents.Warning, PeakSeverity: incidents.Warning}
		end := start.Add(time.Hour)
		in.End = &end
		if i%5 == 0 {
			in.State, in.End = incidents.Open, nil
		}
		c.Incidents = append(c.Incidents, in)
	}
	if err := st.Commit(ctx, c); err != nil {
		t.Fatal(err)
	}
	// Keyset paging walks everything newest first, once.
	var all []string
	q := incidents.Query{Limit: 4}
	for {
		page, err := st.List(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		for _, in := range page {
			all = append(all, in.ID)
		}
		if len(page) < q.Limit {
			break
		}
		q.Before = incidents.CursorOf(&page[len(page)-1])
	}
	full, _ := st.List(ctx, incidents.Query{})
	if len(all) != 25 || len(full) != 25 {
		t.Fatalf("paged %d of %d", len(all), len(full))
	}
	for i := range full {
		if full[i].ID != all[i] {
			t.Fatalf("page order differs at %d", i)
		}
	}
	// Signals need their incident.
	err := st.Commit(ctx, incidents.Commit{Signals: map[string][]incidents.Signal{"nope": {{ID: "x", Type: "deploy", Start: base}}}})
	if err == nil {
		t.Error("signals for an unknown incident were accepted")
	}
	// Prune drops resolved incidents that ended before the cut, never open ones.
	n, err := st.Prune(ctx, base.Add(time.Hour+6*time.Minute))
	if err != nil || n != 9 { // starts before minute 6, less the open ones (0, 5, 10)
		t.Fatalf("pruned %d (%v), want 9", n, err)
	}
	if left, _ := st.List(ctx, incidents.Query{}); len(left) != 16 {
		t.Errorf("%d left", len(left))
	}
	// Checkpoints round-trip.
	_ = st.Commit(ctx, incidents.Commit{Checkpoints: map[string][]byte{"incidents/audit": []byte(`{"t":1}`)}})
	if cp, _ := st.Checkpoint(ctx, "incidents/audit"); string(cp) != `{"t":1}` {
		t.Errorf("checkpoint %s", cp)
	}
	if cp, _ := st.Checkpoint(ctx, "other"); cp != nil {
		t.Errorf("unknown checkpoint %s", cp)
	}
	// Signals of many incidents at once.
	in := full[0]
	_ = st.Commit(ctx, incidents.Commit{Incidents: []incidents.Incident{in}, Signals: map[string][]incidents.Signal{in.ID: {{ID: "s", Type: "deploy", Start: base}}}})
	if m, _ := st.SignalsOf(ctx, []string{in.ID, "nope"}); len(m) != 1 || len(m[in.ID]) != 1 {
		t.Errorf("signals of = %v", m)
	}
}

func TestMemoryStoreBound(t *testing.T) {
	ctx := context.Background()
	st := incidents.NewMemoryStore()
	base := incidentstest.Base
	var c incidents.Commit
	for i := 0; i < incidents.MemoryMaxIncidents+5; i++ {
		s := incidents.Subject{Kind: "Deployment", Namespace: "shop", Name: fmt.Sprint("app-", i)}
		in := incidents.Incident{ID: incidents.IncidentID(s, base), Subject: s, State: incidents.Resolved, Start: base,
			Severity: incidents.Warning, PeakSeverity: incidents.Warning}
		end := base.Add(time.Duration(i) * time.Second)
		in.End = &end
		if i < 3 {
			in.State, in.End = incidents.Open, nil // open ones are never dropped
		}
		c.Incidents = append(c.Incidents, in)
	}
	if err := st.Commit(ctx, c); err != nil {
		t.Fatal(err)
	}
	all, _ := st.List(ctx, incidents.Query{})
	if len(all) != incidents.MemoryMaxIncidents {
		t.Fatalf("%d kept", len(all))
	}
	open, _, _ := st.LoadOpen(ctx)
	if len(open) != 3 {
		t.Errorf("open lost: %d", len(open))
	}
	for _, in := range all {
		if in.Subject.Name == "app-3" || in.Subject.Name == "app-7" {
			t.Errorf("%s should have gone first", in.Subject.Name)
		}
	}
}

func TestMemoryEventStore(t *testing.T) {
	ctx := context.Background()
	st := incidents.NewMemoryEventStore()
	base := incidentstest.Base
	ev := func(uid, reason string, count int32, first, last time.Time, subj *incidents.Subject) incidents.StoredEvent {
		return incidents.StoredEvent{KubeEvent: model.KubeEvent{UID: uid, Namespace: "shop", Type: "Warning", Reason: reason, Count: count,
			FirstSeen: first, LastSeen: last, Regarding: model.ObjectRef{Kind: "Pod", Namespace: "shop", Name: "api-1"}}, Subject: subj}
	}
	api := &incidents.Subject{Kind: "Deployment", Namespace: "shop", Name: "api"}
	if err := st.AddEvents(ctx, []incidents.StoredEvent{
		ev("e1", "BackOff", 3, base, base.Add(2*time.Minute), api),
		ev("e2", "Unhealthy", 1, base.Add(time.Minute), base.Add(time.Minute), nil),
		ev("e1", "BackOff", 2, base, base.Add(time.Minute), api), // older report: ignored
	}); err != nil {
		t.Fatal(err)
	}
	got, _ := st.Events(ctx, incidents.EventQuery{Namespace: "shop"})
	if len(got) != 2 || got[0].UID != "e1" || got[0].Count != 3 || got[1].UID != "e2" {
		t.Fatalf("events: %+v", got)
	}
	if got, _ := st.Events(ctx, incidents.EventQuery{Subject: api}); len(got) != 1 {
		t.Errorf("by subject: %d", len(got))
	}
	if got, _ := st.Events(ctx, incidents.EventQuery{From: base.Add(90 * time.Second)}); len(got) != 1 || got[0].UID != "e1" {
		t.Errorf("from: %+v", got)
	}
	if got, _ := st.Events(ctx, incidents.EventQuery{To: base.Add(30 * time.Second)}); len(got) != 1 || got[0].UID != "e1" {
		t.Errorf("to: %+v", got)
	}
	if got, _ := st.Events(ctx, incidents.EventQuery{Object: &model.ObjectRef{Kind: "Pod", Namespace: "shop", Name: "api-1"}, Limit: 1}); len(got) != 1 {
		t.Errorf("by object with limit: %d", len(got))
	}
	if n, _ := st.PruneEvents(ctx, base.Add(90*time.Second)); n != 1 {
		t.Errorf("pruned %d", n)
	}
}
