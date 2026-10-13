package main

import (
	"errors"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/metrics"
	"github.com/ByronGary/kubesentry/internal/snapshot"
)

func TestDependencyUpAndSnapshotHealth(t *testing.T) {
	var err error
	dependencyUp("test-dependency", func() error { return err })
	g := metrics.DependencyUp.With("test-dependency")
	if g.Value() != 1 {
		t.Errorf("healthy = %v", g.Value())
	}
	err = errors.New("down")
	if g.Value() != 0 {
		t.Errorf("down = %v", g.Value())
	}

	var v *snapshot.View
	h := snapshotHealth(func() *snapshot.View { return v })
	if h() == nil {
		t.Error("no view counts as up")
	}
	v = &snapshot.View{}
	if h() != nil {
		t.Errorf("a fresh view: %v", h())
	}
	v = &snapshot.View{Stale: true, Err: "list pods: forbidden"}
	if e := h(); e == nil || e.Error() != "list pods: forbidden" {
		t.Errorf("stale view: %v", e)
	}

	at := time.Unix(1_760_000_000, 500_000_000)
	registerLastChange(func() time.Time { return at })
	if got := metrics.SnapshotLastChange.Value(); got != 1_760_000_000.5 {
		t.Errorf("last change = %v", got)
	}
	at = time.Time{}
	if got := metrics.SnapshotLastChange.Value(); got != 0 {
		t.Errorf("no change yet = %v", got)
	}
}
