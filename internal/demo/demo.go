package demo

import (
	"context"
	"net/http"
	"time"

	"github.com/ByronGary/kubesentry/internal/api"
	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/procmon"
)

// NewServer returns an API server wired to synthetic data. ui may be nil. The
// process data is refreshed in the background until ctx ends.
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
	return &api.Server{
		Cluster:   cluster,
		Processes: procs,
		Metrics:   NewMetrics(cluster, now),
		Audit:     ing,
		Inventory: cluster,
		Certs:     cluster,
		UI:        ui,
		Demo:      true,
		PVCOptions: detectors.PVCOptions{
			MinAge:                  24 * time.Hour,
			PricePerGiBMonth:        map[string]float64{"gp3": 0.08, "io2": 0.125},
			DefaultPricePerGiBMonth: 0.10,
		},
		LeakOptions: detectors.DefaultLeakOptions(),
	}, nil
}
