package main

import (
	"time"

	"github.com/ByronGary/kubesentry/internal/metrics"
	"github.com/ByronGary/kubesentry/internal/snapshot"
)

// dependencyUp exports kubesentry_dependency_up{dependency=name}: 1 while
// check reports nil, 0 otherwise. check runs at every scrape, so it must be
// cheap: it reads state the health probes keep (the logic behind /readyz),
// never a dependency itself.
func dependencyUp(name string, check func() error) {
	metrics.DependencyUp.With(name).SetFunc(func() float64 {
		if check() != nil {
			return 0
		}
		return 1
	})
}

// errStale reports a view that is missing or serving after failed rebuilds.
type errStale string

func (e errStale) Error() string { return string(e) }

// snapshotHealth is the snapshot dependency: down before the first view
// and while the last good view is served after failed rebuilds.
func snapshotHealth(current func() *snapshot.View) func() error {
	return func() error {
		v := current()
		switch {
		case v == nil:
			return errStale("no view yet")
		case v.Stale:
			return errStale(v.Err)
		}
		return nil
	}
}

// registerLastChange exports when the cluster last changed, as the
// snapshot manager heard it (kubesentry_snapshot_last_change_timestamp_seconds).
func registerLastChange(last func() time.Time) {
	metrics.SnapshotLastChange.SetFunc(func() float64 {
		t := last()
		if t.IsZero() {
			return 0
		}
		return float64(t.UnixNano()) / 1e9
	})
}
