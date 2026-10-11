package pgstore

// The Summarize cache must keep callers with different audit scopes apart.
// The API passes Namespaces == nil for a caller who may read every namespace
// (unrestricted, or a cluster-wide grant) and an empty, non-nil map for a
// caller who may read none. fmt's %+v printed both as "map[]", so the two
// once shared one cache key.

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/audit/audittest"
)

func TestSummaryCacheKeySeparatesNilAndEmptyNamespaces(t *testing.T) {
	ttl := 30 * time.Second
	since := time.Now().Add(-24 * time.Hour)
	everything := audit.Query{Since: since}.Canonical()                             // auditScope with sc.All
	nothing := audit.Query{Since: since, Namespaces: map[string]bool{}}.Canonical() // no grants
	clusterOnly := audit.Query{Since: since, Namespaces: map[string]bool{}, ClusterScoped: true}.Canonical()
	keys := map[string]string{}
	for name, q := range map[string]audit.Query{"everything": everything, "nothing": nothing, "clusterOnly": clusterOnly} {
		k := summaryCacheKey(q, ttl)
		if other, dup := keys[k]; dup {
			t.Errorf("%s and %s share the cache key %s", name, other, k)
		}
		keys[k] = name
	}
	// Map order and false entries do not split keys.
	a := audit.Query{Namespaces: map[string]bool{"a": true, "b": true, "c": false}}
	b := audit.Query{Namespaces: map[string]bool{"b": true, "a": true}}
	if summaryCacheKey(a, ttl) != summaryCacheKey(b, ttl) {
		t.Error("equal scopes give different keys")
	}
}

// Without Postgres: seed the cache entry an unrestricted caller's Summarize
// leaves behind, then ask as a caller with no audit grants. Serving the
// seeded entry is the leak; going to the database (nil pool: panic,
// recovered) means the keys differ.
func TestSummaryCacheDoesNotServeAnotherScope(t *testing.T) {
	ttl := 30 * time.Second
	s := &Store{o: Options{CacheTTL: ttl}, sumCache: map[string]sumEntry{}}
	since := time.Now().Add(-24 * time.Hour)
	everything := audit.Query{Since: since}
	nothing := audit.Query{Since: since, Namespaces: map[string]bool{}}
	s.sumCache[summaryCacheKey(everything.Canonical(), ttl)] = sumEntry{at: time.Now(), sum: audit.Summary{TotalEvents: 42,
		Users: []audit.UserSummary{{Username: "admin@corp", ActorKind: "user", Total: 42}}, ByTag: map[string]int{"exec": 7}}}

	got, served := func() (sum audit.Summary, ok bool) {
		defer func() {
			if recover() != nil {
				ok = false // went to the (absent) database
			}
		}()
		sum, _ = s.Summarize(context.Background(), nothing)
		return sum, true
	}()
	if served && got.TotalEvents != 0 {
		t.Errorf("a caller with no audit grants got the unrestricted caller's cached summary: %+v", got)
	}
}

// Every field of audit.Query changes the key, so a field added later cannot
// be forgotten silently.
func TestSummaryCacheKeyCoversEveryQueryField(t *testing.T) {
	base := audit.Query{Since: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), Namespaces: map[string]bool{"a": true}}
	change := map[string]func(*audit.Query){
		"Since":         func(q *audit.Query) { q.Since = q.Since.Add(-time.Hour) },
		"User":          func(q *audit.Query) { q.User = "u" },
		"Namespace":     func(q *audit.Query) { q.Namespace = "a" },
		"Resource":      func(q *audit.Query) { q.Resource = "pods" },
		"Name":          func(q *audit.Query) { q.Name = "x" },
		"Verb":          func(q *audit.Query) { q.Verb = "get" },
		"Tag":           func(q *audit.Query) { q.Tag = "exec" },
		"Actors":        func(q *audit.Query) { q.Actors = map[string]bool{} },
		"IncludeReads":  func(q *audit.Query) { q.IncludeReads = true },
		"Limit":         func(q *audit.Query) { q.Limit = 5 },
		"Namespaces":    func(q *audit.Query) { q.Namespaces = nil },
		"ClusterScoped": func(q *audit.Query) { q.ClusterScoped = true },
		"Before":        func(q *audit.Query) { q.Before = audit.Cursor{Time: q.Since.Add(time.Hour), AuditID: "x"} },
	}
	typ := reflect.TypeOf(audit.Query{})
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		f, ok := change[name]
		if !ok {
			t.Errorf("audit.Query.%s is not covered: add it to summaryKey and to this test", name)
			continue
		}
		q := base
		q.Namespaces = map[string]bool{"a": true}
		f(&q)
		if summaryCacheKey(base, time.Second) == summaryCacheKey(q, time.Second) {
			t.Errorf("changing %s does not change the cache key", name)
		}
	}
}

// With Postgres (KUBESENTRY_TEST_PG_DSN): the same, end to end.
func TestPGSummaryCacheSeparatesScopes(t *testing.T) {
	ctx := context.Background()
	s := openTest(t, Options{CacheTTL: time.Hour})
	e := ev("a", "ResponseComplete", 200, audittest.Base)
	e.Namespace = "secret-team"
	if err := s.Add(ctx, []audit.Event{e}); err != nil {
		t.Fatal(err)
	}
	flush(t, s)
	since := audittest.Base.Add(-time.Hour)
	all, err := s.Summarize(ctx, audit.Query{Since: since})
	if err != nil || all.TotalEvents != 1 {
		t.Fatalf("unrestricted summary = %+v, %v", all, err)
	}
	none, err := s.Summarize(ctx, audit.Query{Since: since, Namespaces: map[string]bool{}})
	if err != nil {
		t.Fatal(err)
	}
	if none.TotalEvents != 0 || len(none.Users) != 0 {
		t.Errorf("caller with no audit grants sees %+v", none)
	}
}
