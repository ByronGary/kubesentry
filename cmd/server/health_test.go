package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/pgstore"
)

type fakePinger struct {
	mu      sync.Mutex
	err     error
	lastErr string
}

func (f *fakePinger) Ping(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.err
}

func (f *fakePinger) Stats() pgstore.Stats {
	f.mu.Lock()
	defer f.mu.Unlock()
	return pgstore.Stats{LastError: f.lastErr}
}

func (f *fakePinger) set(err error, lastErr string) {
	f.mu.Lock()
	f.err, f.lastErr = err, lastErr
	f.mu.Unlock()
}

// The Overview's audit store health reads the last background ping and the
// write path's last error, never the database itself.
func TestWatchPostgres(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pg := &fakePinger{}
	health := watchPostgres(ctx, pg, 5*time.Millisecond)
	if err := health(); err != nil {
		t.Fatalf("healthy store: %v", err)
	}
	pg.set(nil, "copy audit events: connection reset")
	if err := health(); err == nil || err.Error() != "copy audit events: connection reset" {
		t.Errorf("failing writes: %v", err)
	}
	pg.set(errors.New("connection refused"), "")
	deadline := time.Now().Add(5 * time.Second)
	for health() == nil && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if err := health(); err == nil || err.Error() != "connection refused" {
		t.Errorf("failing pings: %v", err)
	}
	pg.set(nil, "")
	for health() != nil && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if err := health(); err != nil {
		t.Errorf("recovered: %v", err)
	}
}
