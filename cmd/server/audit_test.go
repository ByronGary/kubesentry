package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/cloudwatch"
	"github.com/ByronGary/kubesentry/internal/cloudwatch/cwfake"
)

// fakeLeader is a held lock whose commits the test can stall: from the
// second commit on, Commit blocks until release is closed, honouring its
// context only when honourCtx is set (a commit stuck on a dead connection
// does not).
type fakeLeader struct {
	honourCtx bool
	lost      chan struct{}
	release   chan struct{}
	blocked   chan struct{} // closed when a commit starts to block

	mu        sync.Mutex
	commits   int
	position  []byte
	released  bool
	blockOnce sync.Once
}

func newFakeLeader(honourCtx bool) *fakeLeader {
	return &fakeLeader{honourCtx: honourCtx, lost: make(chan struct{}), release: make(chan struct{}), blocked: make(chan struct{})}
}

func (l *fakeLeader) Commit(ctx context.Context, events []audit.Event, source string, position []byte) error {
	l.mu.Lock()
	l.commits++
	n := l.commits
	l.mu.Unlock()
	if n >= 2 {
		l.blockOnce.Do(func() { close(l.blocked) })
		if l.honourCtx {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-l.release:
			}
		} else {
			<-l.release
		}
	}
	l.mu.Lock()
	l.position = append([]byte(nil), position...)
	l.mu.Unlock()
	return nil
}

func (l *fakeLeader) Checkpoint(context.Context, string) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.position, nil
}

func (l *fakeLeader) Lost() <-chan struct{} { return l.lost }

func (l *fakeLeader) Release(context.Context) error {
	l.mu.Lock()
	l.released = true
	l.mu.Unlock()
	return nil
}

// cwTestRunner is a cwRunner reading a live cwfake log group that started 40
// minutes ago, so the reader needs several windows to catch up.
func cwTestRunner(t *testing.T) *cwRunner {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDCWFAKE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "cwfake-secret")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "credentials"))
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	srv, _ := cwfake.NewServer(cwfake.Options{Seed: 7, Start: time.Now().Add(-40 * time.Minute), Rate: 2})
	t.Cleanup(srv.Close)
	client, err := cloudwatch.New(context.Background(), "us-east-1", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &cwRunner{api: client, logGroup: "/aws/eks/fake/cluster", prefix: "kube-apiserver-audit", start: 40 * time.Minute,
		ingest: func(b []byte) ([]audit.Event, error) { return audit.Parse(bytes.NewReader(b)) }}
}

func waitFor(t *testing.T, what string, within time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not within %s", what, within)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A leader that loses its lock while its reader is stuck in a commit must
// stop reporting at once: no status, no lag, no readiness error from a
// replica that no longer reads. It used to keep them until Run returned.
func TestCloudWatchStatusClearsWhenTheLockIsLost(t *testing.T) {
	for _, tc := range []struct {
		name      string
		honourCtx bool
	}{{"commit stuck", false}, {"commit honours cancel", true}} {
		t.Run(tc.name, func(t *testing.T) {
			c := cwTestRunner(t)
			l := newFakeLeader(tc.honourCtx)
			done := make(chan struct{})
			go func() {
				c.lead(context.Background(), l)
				close(done)
			}()
			select {
			case <-l.blocked: // the first window is stored; the second commit hangs
			case <-time.After(20 * time.Second):
				t.Fatal("the reader never reached its second commit")
			}
			st, ok := c.status()
			if !ok || st.WindowEnd.IsZero() || c.lagSeconds() <= 0 {
				t.Fatalf("leading: status %+v, %v, lag %v; want a window and a lag", st, ok, c.lagSeconds())
			}

			close(l.lost)
			waitFor(t, "status cleared after the lock was lost", 100*time.Millisecond, func() bool {
				_, ok := c.status()
				return !ok
			})
			if lag := c.lagSeconds(); lag != 0 {
				t.Errorf("lag after losing the lock = %v, want 0", lag)
			}
			if tc.honourCtx {
				// Run returns as soon as its context is cancelled.
				select {
				case <-done:
				case <-time.After(2 * time.Second):
					t.Fatal("lead did not return promptly after the lock was lost")
				}
			} else {
				select {
				case <-done:
					t.Fatal("lead returned while Run was still committing")
				case <-time.After(50 * time.Millisecond):
				}
				close(l.release)
				select {
				case <-done:
				case <-time.After(2 * time.Second):
					t.Fatal("lead did not return once the commit came back")
				}
			}
			l.mu.Lock()
			released := l.released
			l.mu.Unlock()
			if !released {
				t.Error("the lock was not released")
			}
			if _, ok := c.status(); ok {
				t.Error("status reappeared after lead returned")
			}
		})
	}
}
