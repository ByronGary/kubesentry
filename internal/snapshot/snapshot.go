// Package snapshot precomputes everything the inventory pages show, so a
// request only filters a ready-made view by the caller's scope instead of
// listing the cluster and running the detectors itself. A Manager rebuilds the
// view when the cluster changes (debounced) and swaps it in atomically; the
// last good view keeps serving if a rebuild fails.
//
// Stdlib, model and detectors only.
package snapshot

import (
	"context"
	"time"

	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/model"
)

// Source reads a consistent inventory. internal/kube's informer cache
// implements it; FromLists adapts the older per-request list interfaces.
type Source interface {
	Inventory(ctx context.Context) (model.Inventory, error)
}

// Notifier is optionally implemented by a Source that knows when the cluster
// changed. Signals are coalesced: one pending signal stands for many changes.
type Notifier interface {
	Changes() <-chan struct{}
}

// ViewProvider hands out the current view.
type ViewProvider interface {
	View(ctx context.Context) (*View, error)
}

// View is one consistent, precomputed picture of the cluster. It is immutable
// once built; per-namespace maps are keyed by namespace, and "" holds
// cluster-scoped entries where that applies (security findings).
type View struct {
	Version       uint64
	Built         time.Time
	BuildDuration time.Duration
	// Stale is set when the latest rebuild failed and this is the last good view.
	Stale bool
	Err   string // the rebuild error when Stale

	Inv    model.Inventory
	Policy detectors.Policy

	Workloads map[string][]detectors.WorkloadSummary
	Claims    map[string][]detectors.ClaimSummary
	Unused    map[string][]detectors.UnusedPVC
	Certs     map[string][]detectors.CertSummary
	Requests  map[string][]detectors.RequestSummary
	Findings  map[string][]detectors.SecurityFinding
	Posture   []detectors.NamespacePosture
	Issuers   []detectors.IssuerSummary
	Nodes     []detectors.NodeSummary
	Volumes   []detectors.VolumeSummary
	Classes   []detectors.ClassSummary

	// NamespacesWithPods is sorted; the Map picker offers these.
	NamespacesWithPods []string
	// LivePods counts live pods per namespace (for choosing a default namespace).
	LivePods map[string]int
}
