package audit_test

import (
	"context"
	"fmt"
	"math/rand"
	"reflect"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/audit/audittest"
)

const span = 2 * time.Hour

// TestIndexedQueryEqualsNaive checks the indexed MemoryStore against a plain
// filter-and-sort over the same records, for random events and queries.
func TestIndexedQueryEqualsNaive(t *testing.T) {
	for seed := int64(1); seed <= 8; seed++ {
		rng := rand.New(rand.NewSource(seed))
		events := audittest.Events(rng, 1500+rng.Intn(1500), span)
		s := audit.NewMemoryStore(1 << 20)
		// Add in uneven chunks, as the webhook would.
		for i := 0; i < len(events); {
			n := 1 + rng.Intn(40)
			if i+n > len(events) {
				n = len(events) - i
			}
			s.Add(events[i : i+n]...)
			i += n
		}
		records := audittest.Records(events)
		if s.Len() != len(records) {
			t.Fatalf("seed %d: store holds %d records, reference %d", seed, s.Len(), len(records))
		}
		for i := 0; i < 400; i++ {
			q := audittest.Query(rng, span)
			got := s.Query(q)
			want := audittest.Naive(records, q)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("seed %d query %d %s:\n got %d events %v\nwant %d events %v", seed, i, audittest.Describe(q), len(got), idsOf(got), len(want), idsOf(want))
			}
			if i%4 == 0 {
				gs, ws := s.Summarize(q), audittest.NaiveSummary(records, q)
				if !reflect.DeepEqual(gs, ws) {
					t.Fatalf("seed %d summary %s:\n got %+v\nwant %+v", seed, audittest.Describe(q), gs, ws)
				}
			}
		}
	}
}

func idsOf(events []audit.Event) []string {
	out := make([]string, len(events))
	for i, e := range events {
		out[i] = e.AuditID + "@" + e.Time.Format("15:04:05.000000")
	}
	if len(out) > 12 {
		out = append(out[:12], "...")
	}
	return out
}

// TestPagingYieldsEveryEventOnce pages through random queries with Before
// cursors and checks the pages concatenate to the unpaged result.
func TestPagingYieldsEveryEventOnce(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	events := audittest.Events(rng, 3000, span)
	s := audit.NewMemoryStore(1 << 20)
	s.Add(events...)
	for i := 0; i < 60; i++ {
		q := audittest.Query(rng, span)
		q.Limit, q.Before = 0, audit.Cursor{}
		all := s.Query(q)
		pageSize := 1 + rng.Intn(25)
		paged := []audit.Event{}
		seen := map[string]bool{}
		pq := q
		pq.Limit = pageSize
		for pages := 0; ; pages++ {
			if pages > len(all)+1 {
				t.Fatalf("paging does not terminate for %s", audittest.Describe(q))
			}
			page := s.Query(pq)
			for _, e := range page {
				k := e.AuditID + e.Time.String()
				if seen[k] {
					t.Fatalf("event %s returned twice", k)
				}
				seen[k] = true
			}
			paged = append(paged, page...)
			if len(page) < pageSize {
				break
			}
			// The cursor goes through its token form, as it does over HTTP.
			c, err := audit.DecodeCursor(audit.CursorOf(page[len(page)-1]).Encode())
			if err != nil {
				t.Fatal(err)
			}
			pq.Before = c
		}
		if !reflect.DeepEqual(paged, all) {
			t.Fatalf("pages of %d != unpaged result (%d vs %d events) for %s", pageSize, len(paged), len(all), audittest.Describe(q))
		}
	}
}

func TestScopeFiltering(t *testing.T) {
	s := audit.NewMemoryStore(100)
	at := func(m int) time.Time { return audittest.Base.Add(time.Duration(m) * time.Minute) }
	s.Add(
		audit.Event{AuditID: "p1", Time: at(1), Verb: "create", Username: "alice", ActorKind: "user", Namespace: "prod", Resource: "pods"},
		audit.Event{AuditID: "s1", Time: at(2), Verb: "create", Username: "alice", ActorKind: "user", Namespace: "staging", Resource: "pods"},
		audit.Event{AuditID: "c1", Time: at(3), Verb: "create", Username: "bob", ActorKind: "user", Resource: "clusterrolebindings"},
		audit.Event{AuditID: "t1", Time: at(4), Verb: "delete", Username: "bob", ActorKind: "user", Namespace: "team-a", Resource: "pods", Tags: []string{audit.TagDelete}},
	)
	ids := func(q audit.Query) string {
		var out []string
		for _, e := range s.Query(q) {
			out = append(out, e.AuditID)
		}
		return fmt.Sprint(out)
	}
	cases := []struct {
		q    audit.Query
		want string
	}{
		{audit.Query{}, "[t1 c1 s1 p1]"},
		{audit.Query{Namespaces: map[string]bool{}}, "[]"},
		{audit.Query{Namespaces: map[string]bool{"prod": true}}, "[p1]"},
		{audit.Query{Namespaces: map[string]bool{"prod": true, "team-a": true}}, "[t1 p1]"},
		{audit.Query{Namespaces: map[string]bool{"prod": true, "staging": false}}, "[p1]"},
		{audit.Query{Namespaces: map[string]bool{"prod": true}, ClusterScoped: true}, "[c1 p1]"},
		{audit.Query{Namespaces: map[string]bool{}, ClusterScoped: true}, "[c1]"},
		// "" in Namespaces does not grant cluster-scoped events; only ClusterScoped does.
		{audit.Query{Namespaces: map[string]bool{"": true}}, "[]"},
		{audit.Query{Namespaces: map[string]bool{"prod": true}, Namespace: "staging"}, "[]"},
		{audit.Query{Namespaces: map[string]bool{"staging": true}, User: "alice"}, "[s1]"},
		{audit.Query{Namespaces: map[string]bool{"prod": true, "team-a": true}, Tag: audit.TagDelete}, "[t1]"},
		{audit.Query{Before: audit.Cursor{Time: at(3), AuditID: "c1"}}, "[s1 p1]"},
		{audit.Query{Before: audit.Cursor{Time: at(3)}}, "[s1 p1]"},
		{audit.Query{Before: audit.Cursor{Time: at(3), AuditID: "c2"}}, "[c1 s1 p1]"},
	}
	for _, c := range cases {
		if got := ids(c.q); got != c.want {
			t.Errorf("%+v: got %s, want %s", c.q, got, c.want)
		}
	}
}

func TestOutOfOrderArrivalStaysExact(t *testing.T) {
	s := audit.NewMemoryStore(1000)
	// Live traffic first, then a backfill of older events, then one far-future
	// event that loosens every bound: answers must stay exact.
	for i := 0; i < 200; i++ {
		s.Add(audit.Event{AuditID: fmt.Sprintf("live-%03d", i), Time: audittest.Base.Add(time.Duration(i) * time.Second), Verb: "create", Username: "alice", ActorKind: "user"})
	}
	for i := 0; i < 200; i++ {
		s.Add(audit.Event{AuditID: fmt.Sprintf("back-%03d", i), Time: audittest.Base.Add(-time.Duration(i) * time.Second), Verb: "create", Username: "alice", ActorKind: "user"})
	}
	got := s.Query(audit.Query{Limit: 3})
	if len(got) != 3 || got[0].AuditID != "live-199" || got[2].AuditID != "live-197" {
		t.Fatalf("newest = %v", idsOf(got))
	}
	got = s.Query(audit.Query{Before: audit.CursorOf(audit.Event{AuditID: "live-000", Time: audittest.Base}), Limit: 2})
	// back-000 shares live-000's time and sorts below it by AuditID.
	if len(got) != 2 || got[0].AuditID != "back-000" || got[1].AuditID != "back-001" {
		t.Fatalf("after live-000 = %v", idsOf(got))
	}
	s.Add(audit.Event{AuditID: "future", Time: audittest.Base.Add(24 * time.Hour), Verb: "create", Username: "alice", ActorKind: "user"})
	got = s.Query(audit.Query{Limit: 2, Before: audit.Cursor{Time: audittest.Base.Add(24 * time.Hour)}})
	if len(got) != 2 || got[0].AuditID != "live-199" {
		t.Fatalf("below future = %v", idsOf(got))
	}
}

func TestUpsertMovesIndexMembership(t *testing.T) {
	s := audit.NewMemoryStore(10)
	e := audit.Event{AuditID: "x", Time: audittest.Base, Stage: "ResponseStarted", Verb: "get", Username: "alice", ActorKind: "user", Resource: "pods", StatusCode: 200}
	s.Add(e)
	if n := len(s.Query(audit.Query{})); n != 0 {
		t.Fatalf("an untagged read is not in the default view, got %d", n)
	}
	e.Stage, e.StatusCode = "ResponseComplete", 403
	e.Tags = audit.Classify(e)
	s.Add(e)
	if got := s.Query(audit.Query{Tag: audit.TagDenied}); len(got) != 1 || got[0].Stage != "ResponseComplete" {
		t.Fatalf("tag index after upsert = %+v", got)
	}
	if got := s.Query(audit.Query{}); len(got) != 1 {
		t.Fatalf("default view after upsert = %+v", got)
	}
	// Evicting the record must leave no index behind.
	for i := 0; i < 10; i++ {
		s.Add(audit.Event{AuditID: fmt.Sprint(i), Time: audittest.Base.Add(time.Minute), Verb: "create", Username: "bob", ActorKind: "user"})
	}
	if got := s.Query(audit.Query{Tag: audit.TagDenied}); len(got) != 0 {
		t.Fatalf("evicted record still indexed: %+v", got)
	}
}

func TestCoverageAndAdapter(t *testing.T) {
	m := audit.NewMemoryStore(5)
	st := m.AsStore()
	ctx := context.Background()
	if c, err := st.Coverage(ctx); err != nil || c.Events != 0 || !c.Oldest.IsZero() || c.Backend != "memory" || c.MaxEvents != 5 {
		t.Fatalf("empty coverage = %+v, %v", c, err)
	}
	err := st.Add(ctx, []audit.Event{
		{AuditID: "b", Time: audittest.Base.Add(time.Hour), Verb: "create", Username: "alice", ActorKind: "user"},
		{AuditID: "a", Time: audittest.Base, Verb: "create", Username: "alice", ActorKind: "user"},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, _ := st.Coverage(ctx)
	if c.Events != 2 || !c.Oldest.Equal(audittest.Base) || !c.Newest.Equal(audittest.Base.Add(time.Hour)) {
		t.Errorf("coverage = %+v", c)
	}
	sum, _ := st.Summarize(ctx, audit.Query{})
	if sum.TotalEvents != 2 || len(sum.Users) != 1 || sum.Users[0].Writes != 2 {
		t.Errorf("summary = %+v", sum)
	}
	if back, ok := audit.MemoryOf(st); !ok || back != m {
		t.Error("MemoryOf should return the wrapped store")
	}
}

func TestCursorToken(t *testing.T) {
	c := audit.Cursor{Time: audittest.Base.Add(123456 * time.Microsecond), AuditID: "a:b/c"}
	got, err := audit.DecodeCursor(c.Encode())
	if err != nil || !got.Time.Equal(c.Time) || got.AuditID != c.AuditID {
		t.Fatalf("round trip = %+v, %v", got, err)
	}
	if z, err := audit.DecodeCursor(""); err != nil || !z.IsZero() {
		t.Fatalf("empty token = %+v, %v", z, err)
	}
	for _, bad := range []string{"%%%", "djI6MTox", "bm9wZQ"} {
		if _, err := audit.DecodeCursor(bad); err == nil {
			t.Errorf("token %q accepted", bad)
		}
	}
}

// benchStore fills a store with n events shaped like a busy cluster, one
// every 200ms (about 28 hours for 500k).
func benchStore(b *testing.B, n int) *audit.MemoryStore {
	b.Helper()
	s := audit.NewMemoryStore(n)
	events := audittest.Busy(rand.New(rand.NewSource(1)), n, audittest.Base, 200*time.Millisecond)
	for i := 0; i < len(events); i += 1000 {
		s.Add(events[i:min(i+1000, len(events))]...)
	}
	return s
}

func BenchmarkMemoryQuery500k(b *testing.B) {
	const n = 500_000
	s := benchStore(b, n)
	end := audittest.Base.Add(n * 200 * time.Millisecond)
	deep := s.Query(audit.Query{Limit: 5000})
	for _, c := range audittest.BenchQueries(end, audit.CursorOf(deep[len(deep)-1])) {
		b.Run(c.Name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if c.Summary {
					s.Summarize(c.Q)
				} else {
					s.Query(c.Q)
				}
			}
		})
	}
}

func BenchmarkMemoryAdd(b *testing.B) {
	rng := rand.New(rand.NewSource(1))
	events := audittest.Events(rng, 10000, span)
	s := audit.NewMemoryStore(50_000)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e := events[i%len(events)]
		e.AuditID = fmt.Sprint(i)
		s.Add(e)
	}
}
