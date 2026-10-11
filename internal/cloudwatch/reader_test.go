package cloudwatch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"

	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/cloudwatch/cwfake"
)

var t0 = time.Date(2026, 10, 10, 8, 0, 0, 0, time.UTC)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// client is the real SDK client, built by New from static credentials in the
// environment, pointed at the fake. attempts 1 turns off the SDK's retries so
// the Reader's own throttling handling is what is tested.
func client(t *testing.T, url string, attempts int) *cloudwatchlogs.Client {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDCWFAKE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "cwfake-secret")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "credentials"))
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	c, err := New(context.Background(), "us-east-1", url, func(o *cloudwatchlogs.Options) {
		if attempts > 0 {
			o.RetryMaxAttempts = attempts
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// catchUp steps the reader until it reports being caught up.
func catchUp(t *testing.T, r *Reader) {
	t.Helper()
	for i := 0; i < 1000; i++ {
		done, err := r.Step(context.Background())
		if err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
		if done {
			return
		}
	}
	t.Fatal("reader never caught up")
}

// stored returns the auditIDs held, failing on duplicates.
func stored(t *testing.T, st audit.Store) map[string]bool {
	t.Helper()
	events, err := st.Query(context.Background(), audit.Query{IncludeReads: true, Actors: map[string]bool{"user": true, "serviceaccount": true, "system": true}})
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, e := range events {
		if ids[e.AuditID] {
			t.Fatalf("auditID %s stored twice", e.AuditID)
		}
		ids[e.AuditID] = true
	}
	return ids
}

// expectExactly checks the store holds exactly the fake's events [lo, hi).
func expectExactly(t *testing.T, f *cwfake.Fake, ids map[string]bool, lo, hi int64) {
	t.Helper()
	missing := 0
	for i := lo; i < hi; i++ {
		if !ids[f.AuditID(i)] {
			if missing < 5 {
				t.Errorf("event %d (%s at %s) missing", i, f.AuditID(i), f.Time(i).Format(time.RFC3339Nano))
			}
			missing++
		}
	}
	if missing > 0 || int64(len(ids)) != hi-lo {
		t.Fatalf("store holds %d events, want %d; %d missing", len(ids), hi-lo, missing)
	}
}

func TestReaderPagesWindowsAndDedupes(t *testing.T) {
	clk := &clock{t: t0.Add(30 * time.Minute)}
	srv, f := cwfake.NewServer(cwfake.Options{Seed: 1, Start: t0, Rate: 10, Events: 6000, Streams: 3,
		DuplicateFraction: 0.1, LateFraction: 0.05, PageSize: 250, Now: clk.Now})
	defer srv.Close()
	mem := audit.NewMemoryStore(1 << 20).AsStore()
	r := &Reader{API: client(t, srv.URL, 0), Store: &StoreCommitter{Store: mem}, LogGroup: "/aws/eks/fake/cluster",
		Start: 40 * time.Minute, MaxWindow: 4 * time.Minute, Now: clk.Now, Logger: quiet()}
	catchUp(t, r)

	expectExactly(t, f, stored(t, mem), 0, 6000)
	st := r.Status()
	if st.ParseErrors != 0 {
		t.Errorf("%d parse errors: the authenticator stream leaked through the prefix", st.ParseErrors)
	}
	if want := clk.Now().Add(-30 * time.Second); !st.WindowEnd.Equal(want) || st.Lag != 30*time.Second || st.LastError != "" {
		t.Errorf("status = %+v, want window end %s", st, want)
	}
	// 6000 events plus duplicates over 250-event pages: dozens of pages, and
	// the 10 windows of 4 minutes each.
	if f.Requests() < 40 {
		t.Errorf("only %d requests: paging did not happen", f.Requests())
	}
	// The overlap re-read returns the same log events again; the reader skips
	// those it committed, so only the fake's duplicates are re-committed.
	if st.EventsIngested < 6000 || st.EventsIngested > 6000+700 {
		t.Errorf("events committed = %d, want 6000 plus the duplicated deliveries", st.EventsIngested)
	}

	// Polling again with no new data commits nothing new.
	before := st.EventsIngested
	clk.Advance(time.Minute)
	catchUp(t, r)
	if after := r.Status().EventsIngested; after != before {
		t.Errorf("an idle poll committed %d events", after-before)
	}
}

// crashing fails every Commit after the first n, like a process that dies.
type crashing struct {
	Committer
	n int
}

func (c *crashing) Commit(ctx context.Context, events []audit.Event, source string, pos []byte) error {
	if c.n <= 0 {
		return errors.New("crash")
	}
	c.n--
	return c.Committer.Commit(ctx, events, source, pos)
}

func TestReaderResumesAfterCrashWithoutGapsOrDuplicates(t *testing.T) {
	clk := &clock{t: t0.Add(40 * time.Minute)}
	srv, f := cwfake.NewServer(cwfake.Options{Seed: 2, Start: t0, Rate: 10, Events: 8000, Streams: 2,
		DuplicateFraction: 0.05, LateFraction: 0.05, PageSize: 400, Now: clk.Now})
	defer srv.Close()
	mem := audit.NewMemoryStore(1 << 20).AsStore()
	durable := &StoreCommitter{Store: mem} // stands in for Postgres: survives the crash
	api := client(t, srv.URL, 0)
	newReader := func(c Committer) *Reader {
		return &Reader{API: api, Store: c, LogGroup: "/aws/eks/fake/cluster", Start: 45 * time.Minute,
			MaxWindow: 5 * time.Minute, CommitEvery: 300, Now: clk.Now, Logger: quiet()}
	}

	// The first process commits a few times, part of the way into a window
	// (CommitEvery splits windows), then dies.
	a := newReader(&crashing{Committer: durable, n: 7})
	var err error
	for i := 0; i < 100 && err == nil; i++ {
		_, err = a.Step(context.Background())
	}
	if err == nil || a.Status().ErrorKind != "store" {
		t.Fatalf("the crash was not reported: %v, %+v", err, a.Status())
	}
	partial := len(stored(t, mem))
	if partial == 0 || partial >= 8000 {
		t.Fatalf("after the crash the store holds %d events; want a partial load", partial)
	}

	// A new process resumes from the durable checkpoint.
	b := newReader(durable)
	catchUp(t, b)
	expectExactly(t, f, stored(t, mem), 0, 8000)
}

func TestReaderThrottlingBackoff(t *testing.T) {
	clk := &clock{t: t0.Add(20 * time.Minute)}
	srv, f := cwfake.NewServer(cwfake.Options{Seed: 3, Start: t0, Rate: 5, Events: 3000, PageSize: 200, ThrottleEvery: 3, Now: clk.Now})
	defer srv.Close()
	mem := audit.NewMemoryStore(1 << 20).AsStore()
	r := &Reader{API: client(t, srv.URL, 1), Store: &StoreCommitter{Store: mem}, LogGroup: "/aws/eks/fake/cluster",
		Start: 25 * time.Minute, ThrottleBackoff: 2 * time.Millisecond, Now: clk.Now, Logger: quiet()}
	catchUp(t, r)
	expectExactly(t, f, stored(t, mem), 0, 3000)
	st := r.Status()
	if f.Throttled() == 0 || st.Throttled != f.Throttled() {
		t.Errorf("fake throttled %d calls, reader saw %d", f.Throttled(), st.Throttled)
	}
	if st.LastError != "" {
		t.Errorf("a recovered throttle left an error: %q", st.LastError)
	}
}

func TestReaderSDKRetriesThrottling(t *testing.T) {
	clk := &clock{t: t0.Add(20 * time.Minute)}
	srv, f := cwfake.NewServer(cwfake.Options{Seed: 4, Start: t0, Rate: 1, Events: 600, PageSize: 100, ThrottleEvery: 4, Now: clk.Now})
	defer srv.Close()
	mem := audit.NewMemoryStore(1 << 20).AsStore()
	r := &Reader{API: client(t, srv.URL, 0), Store: &StoreCommitter{Store: mem}, LogGroup: "/aws/eks/fake/cluster",
		Start: 25 * time.Minute, MaxWindow: time.Hour, Now: clk.Now, Logger: quiet()}
	catchUp(t, r)
	expectExactly(t, f, stored(t, mem), 0, 600)
	if f.Throttled() == 0 {
		t.Error("no throttling was injected")
	}
}

func TestReaderReportsMissingLogGroup(t *testing.T) {
	srv, _ := cwfake.NewServer(cwfake.Options{Events: 10})
	defer srv.Close()
	r := &Reader{API: client(t, srv.URL, 0), Store: &StoreCommitter{Store: audit.NewMemoryStore(10).AsStore()},
		LogGroup: "/aws/eks/wrong/cluster", Logger: quiet()}
	_, err := r.Step(context.Background())
	if !errors.Is(err, ErrLogGroupNotFound) {
		t.Fatalf("err = %v, want ErrLogGroupNotFound", err)
	}
	if st := r.Status(); st.ErrorKind != "log-group-not-found" || st.LastError == "" {
		t.Errorf("status = %+v", st)
	}
	if pos, _ := r.Store.Checkpoint(context.Background(), r.Source); pos != nil {
		t.Errorf("checkpoint advanced without a read: %s", pos)
	}
}

func TestReaderLiveTailCatchesLateEvents(t *testing.T) {
	clk := &clock{t: t0}
	srv, f := cwfake.NewServer(cwfake.Options{Seed: 5, Start: t0.Add(-2 * time.Minute), Rate: 4, LateFraction: 0.2,
		LateBy: 3 * time.Minute, DuplicateFraction: 0.05, PageSize: 1000, Now: clk.Now})
	defer srv.Close()
	mem := audit.NewMemoryStore(1 << 20).AsStore()
	r := &Reader{API: client(t, srv.URL, 0), Store: &StoreCommitter{Store: mem}, LogGroup: "/aws/eks/fake/cluster",
		Start: 5 * time.Minute, Now: clk.Now, Logger: quiet()}
	for i := 0; i < 60; i++ { // 15 minutes of 15s polls
		if _, err := r.Step(context.Background()); err != nil {
			t.Fatal(err)
		}
		if lag := r.Status().Lag; lag > 30*time.Second {
			t.Fatalf("lag %s after poll %d", lag, i)
		}
		clk.Advance(15 * time.Second)
	}
	end := r.Status().WindowEnd
	// Everything older than the late delivery delay is in, late events
	// included (the overlap re-read found them); nothing past the window is.
	_, settled := f.Range(t0.Add(-2*time.Minute), end.Add(-3*time.Minute-5*time.Second))
	ids := stored(t, mem)
	for i := int64(0); i < settled; i++ {
		if !ids[f.AuditID(i)] {
			t.Fatalf("event %d at %s (late=%v) missing", i, f.Time(i), f.Late(i))
		}
	}
	_, all := f.Range(t0.Add(-2*time.Minute), end)
	if int64(len(ids)) > all {
		t.Fatalf("store holds %d events, more than the %d up to the window end", len(ids), all)
	}
	lateCaught := 0
	for i := int64(0); i < settled; i++ {
		if f.Late(i) {
			lateCaught++
		}
	}
	if lateCaught == 0 {
		t.Fatal("the test generated no late events")
	}

	// Control: without the overlap the same tail loses late events, so the
	// check above is meaningful.
	clk2 := &clock{t: t0}
	srv2, f2 := cwfake.NewServer(cwfake.Options{Seed: 5, Start: t0.Add(-2 * time.Minute), Rate: 4, LateFraction: 0.2,
		LateBy: 3 * time.Minute, PageSize: 1000, Now: clk2.Now})
	defer srv2.Close()
	mem2 := audit.NewMemoryStore(1 << 20).AsStore()
	r2 := &Reader{API: client(t, srv2.URL, 0), Store: &StoreCommitter{Store: mem2}, LogGroup: "/aws/eks/fake/cluster",
		Start: 5 * time.Minute, Overlap: -1, Now: clk2.Now, Logger: quiet()}
	for i := 0; i < 40; i++ {
		if _, err := r2.Step(context.Background()); err != nil {
			t.Fatal(err)
		}
		clk2.Advance(15 * time.Second)
	}
	_, settled2 := f2.Range(t0.Add(-2*time.Minute), r2.Status().WindowEnd.Add(-4*time.Minute))
	ids2 := stored(t, mem2)
	lost := 0
	for i := int64(0); i < settled2; i++ {
		if !ids2[f2.AuditID(i)] {
			lost++
		}
	}
	if lost == 0 {
		t.Error("without overlap no late event was lost; the late-delivery check proves nothing")
	}
}

func TestRunStopsOnLostLeadership(t *testing.T) {
	clk := &clock{t: t0.Add(10 * time.Minute)}
	srv, _ := cwfake.NewServer(cwfake.Options{Start: t0, Rate: 1, Events: 100, Now: clk.Now})
	defer srv.Close()
	lost := &failing{err: fmt.Errorf("pgstore: cloudwatch: lock not held: %w", audit.ErrLeadershipLost)}
	r := &Reader{API: client(t, srv.URL, 0), Store: lost, LogGroup: "/aws/eks/fake/cluster", Now: clk.Now, Logger: quiet()}
	done := make(chan error, 1)
	go func() { done <- r.Run(context.Background()) }()
	select {
	case err := <-done:
		if !errors.Is(err, audit.ErrLeadershipLost) {
			t.Fatalf("Run = %v, want ErrLeadershipLost", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run kept going without leadership")
	}

	ok := &StoreCommitter{Store: audit.NewMemoryStore(1000).AsStore()}
	r2 := &Reader{API: r.API, Store: ok, LogGroup: "/aws/eks/fake/cluster", Start: 15 * time.Minute,
		Poll: 5 * time.Millisecond, Now: clk.Now, Logger: quiet()}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { done <- r2.Run(ctx) }()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if r2.Status().EventsIngested >= 100 {
			break
		}
	}
	time.Sleep(20 * time.Millisecond) // a few idle polls
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run after cancel = %v", err)
	}
	if n := len(stored(t, ok.Store)); n != 100 {
		t.Errorf("Run stored %d events, want 100", n)
	}
}

type failing struct{ err error }

func (f *failing) Commit(context.Context, []audit.Event, string, []byte) error { return f.err }
func (f *failing) Checkpoint(context.Context, string) ([]byte, error)          { return nil, nil }
