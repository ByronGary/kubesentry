package pgstore

// Review probes: the Summarize cache must keep callers with different audit
// scopes apart. The API passes Namespaces == nil for a caller who may read
// every namespace (unrestricted, or a cluster-wide grant) and an empty,
// non-nil map for a caller who may read none. fmt's %+v prints both as
// "map[]", so the two share one cache key.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/audit/audittest"
)

// Without Postgres: seed the cache entry an unrestricted caller's Summarize
// leaves behind (key derived exactly as Summarize derives it), then ask as a
// caller with no audit grants. Serving the seeded entry is the leak; going to
// the database (nil pool: panic, recovered) means the keys differ.
func TestProbeSummaryCacheKeyNilVsEmptyNamespaces(t *testing.T) {
	ttl := 30 * time.Second
	s := &Store{o: Options{CacheTTL: ttl}, sumCache: map[string]sumEntry{}}
	since := time.Now().Add(-24 * time.Hour)

	everything := audit.Query{Since: since}                             // auditScope with sc.All
	nothing := audit.Query{Since: since, Namespaces: map[string]bool{}} // auditScope with no grants
	keyOf := func(q audit.Query) string {                               // as in Summarize
		kq := q.Canonical()
		kq.Limit = 0
		kq.Since = kq.Since.Truncate(ttl)
		return fmt.Sprintf("%+v", kq)
	}
	if keyOf(everything) == keyOf(nothing) {
		t.Errorf("cache key for an unrestricted caller equals the key for a caller with no grants:\n%s", keyOf(nothing))
	}
	s.sumCache[keyOf(everything)] = sumEntry{at: time.Now(), sum: audit.Summary{TotalEvents: 42,
		Users: []audit.UserSummary{{Username: "admin@corp", ActorKind: "user", Total: 42}}, ByTag: map[string]int{"exec": 7}}}

	got, leaked := func() (sum audit.Summary, ok bool) {
		defer func() {
			if recover() != nil {
				ok = false // went to the (absent) database: not served from the other caller's entry
			}
		}()
		sum, _ = s.Summarize(context.Background(), nothing)
		return sum, true
	}()
	if leaked && got.TotalEvents != 0 {
		t.Errorf("a caller with no audit grants got the unrestricted caller's cached summary: %+v", got)
	}
}

// With Postgres (KUBESENTRY_TEST_PG_DSN): the same, end to end.
func TestPGProbeSummaryCacheSeparatesScopes(t *testing.T) {
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
