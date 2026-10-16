package demo

import (
	"context"
	"net/http"
	"time"

	"github.com/ByronGary/kubesentry/internal/api"
	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/procmon"
	"github.com/ByronGary/kubesentry/internal/snapshot"
)

// NewServer returns an API server wired to synthetic data. ui may be nil. It
// serves the same handlers as the real server: a snapshot.Manager builds the
// views from the demo cluster, and every caller is unrestricted. The views
// and process data are refreshed in the background until ctx ends.
func NewServer(ctx context.Context, ui http.Handler) (*api.Server, error) {
	now := time.Now()
	cluster := NewCluster(now)
	ing := &audit.Ingester{Store: audit.NewMemoryStore(10000)}
	if err := SeedAudit(ing, now); err != nil {
		return nil, err
	}
	procs := procmon.NewStore()
	for _, r := range Processes(cluster, now) {
		procs.Update(r)
	}
	go KeepFresh(ctx, procs, cluster, 10*time.Second)

	policy := detectors.DefaultPolicy()
	// The Overview's history: a believable day before now, then every view.
	hist := snapshot.NewHistory(snapshot.DefaultHistoryStep, snapshot.DefaultHistoryBuckets)
	inv, err := cluster.Inventory(ctx)
	if err != nil {
		return nil, err
	}
	PrefillHistory(hist, snapshot.Build(inv, policy, now), now)
	views := &snapshot.Manager{Source: cluster, Policy: policy, MinInterval: 30 * time.Second, MaxDelay: time.Minute,
		OnBuild: func(v *snapshot.View, _ time.Duration, err error) {
			if err == nil {
				hist.Record(v)
			}
		}}
	go func() { _ = views.Run(ctx) }()

	metrics := NewMetrics(cluster, now)
	inc, incStore, err := NewIncidents(ctx, cluster, metrics, ing.Active(), policy, now)
	if err != nil {
		return nil, err
	}
	// The incidents' clock: whole seconds, so the alert episodes they hold match.
	al, err := NewAlerts(ctx, now.Truncate(time.Second))
	if err != nil {
		return nil, err
	}

	return &api.Server{
		History:       hist,
		Cluster:       cluster,
		Views:         views,
		Policy:        policy,
		ResponseCache: &api.ResponseCache{MaxBytes: 16 << 20},
		Processes:     procs,
		Metrics:       metrics,
		Audit:         ing,
		Incidents:     inc,
		IncidentStore: incStore,
		Alerts:        demoAlerts{al},
		UI:            ui,
		Demo:          true,
		PVCOptions:    detectors.PVCOptions{MinAge: 24 * time.Hour},
		LeakOptions:   policy.Leak,
	}, nil
}
