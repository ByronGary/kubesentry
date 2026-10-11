package cloudwatch

// End to end against Postgres: cwfake → Reader → pgstore Leader, with a
// leadership handover and a leader whose session dies mid-run. Needs
// KUBESENTRY_TEST_PG_DSN (eval "$(hack/pg-test.sh)"). Only this test file
// links pgstore into the cloudwatch package.

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/cloudwatch/cwfake"
	"github.com/ByronGary/kubesentry/internal/pgstore"
)

func TestReaderIntoPostgresAcrossLeaders(t *testing.T) {
	dsn := os.Getenv("KUBESENTRY_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("KUBESENTRY_TEST_PG_DSN not set; run eval \"$(hack/pg-test.sh)\"")
	}
	ctx := context.Background()
	app := fmt.Sprintf("cwtest-%d", rand.Intn(1_000_000))
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	qv := u.Query()
	qv.Set("application_name", app)
	u.RawQuery = qv.Encode()
	schema := "kst_cw_" + fmt.Sprint(rand.Intn(1_000_000))
	store, err := pgstore.Open(ctx, u.String(), pgstore.Options{Schema: schema, CacheTTL: -1, Logger: quiet(),
		Now: func() time.Time { return t0 }})
	if err != nil {
		t.Fatal(err)
	}
	// Admin statements go through the store's own pool (this package does
	// not import pgx); pooled sessions hold no advisory locks.
	admin := store.Pool()
	t.Cleanup(func() {
		admin.Exec(ctx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
		store.Close(ctx)
	})

	clk := &clock{t: t0.Add(45 * time.Minute)}
	srv, f := cwfake.NewServer(cwfake.Options{Seed: 7, Start: t0, Rate: 6, Events: 12000, Streams: 3,
		DuplicateFraction: 0.05, LateFraction: 0.05, PageSize: 1000, Now: clk.Now})
	defer srv.Close()
	api := client(t, srv.URL, 0)
	reader := func(c Committer) *Reader {
		return &Reader{API: api, Store: c, LogGroup: "/aws/eks/fake/cluster", Start: 50 * time.Minute,
			MaxWindow: 5 * time.Minute, CommitEvery: 800, Now: clk.Now, Logger: quiet()}
	}
	lead := func() *pgstore.Leader {
		l, ok, err := store.TryLead(ctx, "cloudwatch")
		if err != nil || !ok {
			t.Fatalf("TryLead = %v, %v", ok, err)
		}
		return l
	}

	// Leader 1 reads a few windows and hands over cleanly.
	l1 := lead()
	r1 := reader(l1)
	for i := 0; i < 3; i++ {
		if _, err := r1.Step(ctx); err != nil {
			t.Fatal(err)
		}
	}
	l1.Release(ctx)

	// Leader 2 reads on until its session is killed.
	l2 := lead()
	r2 := reader(l2)
	if _, err := r2.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `SELECT pg_terminate_backend(a.pid) FROM pg_stat_activity a
JOIN pg_locks l ON l.pid = a.pid WHERE a.application_name = $1 AND l.locktype = 'advisory'`, app); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if _, err := r2.Step(ctx); !errors.Is(err, audit.ErrLeadershipLost) {
		t.Fatalf("step after the session died = %v, want ErrLeadershipLost", err)
	}
	if r2.Status().ErrorKind != "leadership-lost" {
		t.Errorf("status = %+v", r2.Status())
	}

	// Leader 3 resumes from the committed checkpoint.
	l3 := lead()
	defer l3.Release(ctx)
	r3 := reader(l3)
	for i := 0; ; i++ {
		done, err := r3.Step(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if done {
			break
		}
		if i > 100 {
			t.Fatal("never caught up")
		}
	}
	expectExactly(t, f, stored(t, store), 0, 12000)
	var n int64
	if err := store.Pool().QueryRow(ctx, "SELECT count(*) FROM audit_events").Scan(&n); err != nil || n != 12000 {
		t.Fatalf("rows = %d, %v; want 12000", n, err)
	}
}
