package alerts

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// episodeID is incidents.EpisodeID (alerts cannot import incidents).
func episodeID(f *Finding) string { return f.Key + "@" + f.FirstSeen.UTC().Format(time.RFC3339Nano) }

// countingStore counts the commits of each finding.
type countingStore struct {
	Store
	mu      sync.Mutex
	commits map[string]int
}

func (c *countingStore) Commit(ctx context.Context, cm Commit) error {
	c.mu.Lock()
	for _, f := range cm.Findings {
		c.commits[f.Key]++
	}
	c.mu.Unlock()
	return c.Store.Commit(ctx, cm)
}

func (c *countingStore) count(k string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.commits[k]
}

// incidentLookup answers from a map of episode IDs.
type incidentLookup struct {
	mu   sync.Mutex
	ids  map[string]string
	seen []string // episode IDs asked about
}

func (l *incidentLookup) of(f *Finding) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seen = append(l.seen, episodeID(f))
	return l.ids[episodeID(f)]
}

func (l *incidentLookup) set(episode, id string) {
	l.mu.Lock()
	l.ids[episode] = id
	l.mu.Unlock()
}

func findingOf(t *testing.T, e *Evaluator, key string) Finding {
	t.Helper()
	for _, f := range e.Findings() {
		if f.Key == key {
			return f
		}
	}
	t.Fatalf("no finding %s", key)
	return Finding{}
}

func sentFor(as []Alert, key string) *Alert {
	for i := range as {
		if as[i].Annotations["dedupe_key"] == key {
			return &as[i]
		}
	}
	return nil
}

// An alert whose episode joined an incident gains incident_url at the next
// resend. The link is computed before the change check, so an unchanged
// link costs no write; it stays while the lookup knows nothing, follows a
// new incident, and is never a label.
func TestEvaluatorIncidentURL(t *testing.T) {
	const key = "pod-evicted/Deployment/payments/batch"
	lookup := &incidentLookup{ids: map[string]string{}}
	h := newHarness(t, Options{ExternalURL: "https://ks.example.com/", IncidentOf: lookup.of})
	store := &countingStore{Store: h.store, commits: map[string]int{}}
	h.ev = NewEvaluator(store, h.sink, Options{ExternalURL: "https://ks.example.com/", IncidentOf: lookup.of, Now: h.clk.now})

	_, sent := h.at(0)
	if a := sentFor(sent, key); a == nil || a.Annotations[AnnotationIncidentURL] != "" {
		t.Fatalf("first alert: %+v", a)
	}
	first := findingOf(t, h.ev, key)
	episode := episodeID(&first)

	// The incidents engine attaches the episode; the link is stored at once
	// and goes out with the next resend.
	lookup.set(episode, "20261012T115500Z-0a1b2c3d4e5f")
	before := store.count(key)
	_, sent = h.at(20 * time.Second)
	want := "https://ks.example.com/#/incidents/20261012T115500Z-0a1b2c3d4e5f"
	if got := findingOf(t, h.ev, key).Annotations[AnnotationIncidentURL]; got != want {
		t.Errorf("finding's incident_url = %q", got)
	}
	if store.count(key) != before+1 {
		t.Errorf("the new link was not written")
	}
	if a := sentFor(sent, key); a != nil {
		t.Errorf("a new link fired at once: %+v", a)
	}
	_, sent = h.at(time.Minute)
	a := sentFor(sent, key)
	if a == nil || a.Annotations[AnnotationIncidentURL] != want {
		t.Fatalf("resend at +1m: %+v", a)
	}
	if _, isLabel := a.Labels[AnnotationIncidentURL]; isLabel {
		t.Error("incident_url is a label")
	}

	// No flapping: the same link, then a lookup that knows nothing (the
	// incident left the board), change nothing between resends.
	before = store.count(key)
	h.at(time.Minute + 20*time.Second)
	lookup.set(episode, "")
	h.at(time.Minute + 40*time.Second)
	if n := store.count(key) - before; n != 0 {
		t.Errorf("%d writes between resends", n)
	}
	if got := findingOf(t, h.ev, key).Annotations[AnnotationIncidentURL]; got != want {
		t.Errorf("the link went away with the lookup: %q", got)
	}
	// A new incident (a capped one continued) replaces it.
	lookup.set(episode, "20261013T115500Z-ffffffffffff")
	h.at(2 * time.Minute)
	if got := findingOf(t, h.ev, key).Annotations[AnnotationIncidentURL]; got != "https://ks.example.com/#/incidents/20261013T115500Z-ffffffffffff" {
		t.Errorf("after the continuation: %q", got)
	}

	// Without an external URL there is no link, incident or not.
	lookup2 := &incidentLookup{ids: map[string]string{}}
	h2 := newHarness(t, Options{IncidentOf: func(f *Finding) string { lookup2.of(f); return "inc" }})
	h2.at(0)
	_, sent = h2.at(time.Minute)
	for _, a := range sent {
		if u, ok := a.Annotations[AnnotationIncidentURL]; ok {
			t.Errorf("no external URL, yet %s links %q", a.Annotations["dedupe_key"], u)
		}
	}
	// Without an incident there is none either.
	h3 := newHarness(t, Options{ExternalURL: "https://ks.example.com"})
	h3.at(0)
	_, sent = h3.at(time.Minute)
	for _, a := range sent {
		if u, ok := a.Annotations[AnnotationIncidentURL]; ok {
			t.Errorf("no lookup, yet %s links %q", a.Annotations["dedupe_key"], u)
		}
	}
}

// FirstSeen is kept as Postgres keeps it, so an episode's ID is the same
// from the leader's memory, from the store, and after a take-over.
func TestEvaluatorFirstSeenNormalised(t *testing.T) {
	const key = "memory-leak/Deployment/payments/cache"
	lookup := &incidentLookup{ids: map[string]string{}}
	h := newHarness(t, Options{ExternalURL: "https://ks.example.com", IncidentOf: lookup.of})
	at := 1234567891 * time.Nanosecond // t0 + 1.234567891s
	h.at(at)
	mem := findingOf(t, h.ev, key)
	if want := NormalTime(t0.Add(at)); !mem.FirstSeen.Equal(want) || mem.FirstSeen.Nanosecond()%1000 != 0 || mem.FirstSeen.Location() != time.UTC {
		t.Errorf("first seen in memory %s, want %s", mem.FirstSeen.Format(time.RFC3339Nano), want.Format(time.RFC3339Nano))
	}
	stored, err := h.store.Load(context.Background(), t0)
	if err != nil {
		t.Fatal(err)
	}
	var st Finding
	for _, f := range stored {
		if f.Key == key {
			st = f
		}
	}
	if episodeID(&mem) != episodeID(&st) {
		t.Errorf("episode in memory %s, in the store %s", episodeID(&mem), episodeID(&st))
	}
	// The lookup was asked with the stored episode, and a new leader asks
	// with the same one.
	lookup.mu.Lock()
	asked := append([]string(nil), lookup.seen...)
	lookup.mu.Unlock()
	found := false
	for _, s := range asked {
		found = found || s == episodeID(&st)
	}
	if !found {
		t.Errorf("lookup asked %v, not %s", asked, episodeID(&st))
	}
	h.ev = NewEvaluator(h.store, h.sink, Options{ExternalURL: "https://ks.example.com", IncidentOf: lookup.of, Now: h.clk.now})
	h.at(at + 30*time.Second)
	if got := findingOf(t, h.ev, key); episodeID(&got) != episodeID(&mem) {
		t.Errorf("after a take-over the episode is %s, was %s", episodeID(&got), episodeID(&mem))
	}
}

// SetIncidentLookup binds the lookup after the runner started; the next
// evaluation uses it.
func TestRunnerSetIncidentLookupLate(t *testing.T) {
	var clock atomic.Int64
	now := func() time.Time { return t0.Add(time.Duration(clock.Load())) }
	r := &Runner{
		Store: NewMemoryStore(), Interval: 5 * time.Millisecond,
		Input: func() (Input, bool) {
			clock.Add(int64(time.Second))
			return Input{View: view(fixture(), now()), Leaks: leakReport(now()), Now: now()}, true
		},
		Options: Options{ExternalURL: "https://ks.example.com", Now: now},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	eventually(t, "a board", func() bool { b := r.Board(); return b != nil && len(b.Findings) > 0 })
	r.SetIncidentLookup(func(f *Finding) string {
		if f.Check == CheckMemoryLeak {
			return "inc-1"
		}
		return ""
	})
	eventually(t, "the link on the board", func() bool {
		for _, f := range r.Board().Findings {
			if f.Check == CheckMemoryLeak {
				return f.Annotations[AnnotationIncidentURL] == "https://ks.example.com/#/incidents/inc-1"
			}
		}
		return false
	})
}
