package audit

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func appendTo(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
}

func expectLine(t *testing.T, ch <-chan string, want string) {
	t.Helper()
	select {
	case got := <-ch:
		if got != want {
			t.Fatalf("got line %q, want %q", got, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for %q", want)
	}
}

func startTail(t *testing.T, path string, fromStart bool) (<-chan string, context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	lines := make(chan string, 16)
	done := make(chan error, 1)
	go func() {
		done <- TailFile(ctx, path, fromStart, 10*time.Millisecond, func(b []byte) { lines <- string(b) })
	}()
	return lines, cancel, done
}

func TestTailFileFollowsAppendsPartialsRotationAndTruncation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	appendTo(t, path, "old1\nold2\n")

	lines, cancel, done := startTail(t, path, false)
	time.Sleep(200 * time.Millisecond) // let the tailer open and seek to the end

	appendTo(t, path, "new1\n")
	expectLine(t, lines, "new1") // existing lines were skipped

	appendTo(t, path, "par")
	time.Sleep(50 * time.Millisecond)
	appendTo(t, path, "tial\n")
	expectLine(t, lines, "partial") // a half-written line is held until complete

	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	appendTo(t, path, "rot1\n")
	expectLine(t, lines, "rot1") // rotation: new file read from its start

	if err := os.WriteFile(path, []byte("t1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	expectLine(t, lines, "t1") // truncation: reread from the start

	cancel()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Errorf("TailFile returned %v, want context.Canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("TailFile did not stop on cancel")
	}
}

func TestTailFileFromStartWaitsForFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "later.log")
	lines, cancel, _ := startTail(t, path, true)
	defer cancel()

	time.Sleep(50 * time.Millisecond) // file does not exist yet
	appendTo(t, path, "a\n\nb\n")
	expectLine(t, lines, "a")
	expectLine(t, lines, "b") // blank lines are skipped
}
