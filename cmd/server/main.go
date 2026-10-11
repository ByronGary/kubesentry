// Command server runs the kubesentry HTTP API.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ByronGary/kubesentry/internal/api"
	"github.com/ByronGary/kubesentry/internal/auth"
	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/kube"
	"github.com/ByronGary/kubesentry/internal/metrics"
	"github.com/ByronGary/kubesentry/internal/model"
	"github.com/ByronGary/kubesentry/internal/procmon"
	"github.com/ByronGary/kubesentry/internal/prom"
	"github.com/ByronGary/kubesentry/internal/snapshot"
	"github.com/ByronGary/kubesentry/internal/web"
)

// version is stamped at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	cfg, err := parseFlags(os.Args[1:], os.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "kubesentry:", err)
		os.Exit(2)
	}
	if cfg.showVersion {
		fmt.Println("kubesentry", version)
		return
	}
	if err := run(cfg); err != nil {
		slog.Error("kubesentry stopped", "err", err)
		os.Exit(1)
	}
}

// run wires everything up and serves until SIGTERM or SIGINT, then drains.
func run(cfg *config) error {
	if soft := setMemoryLimit(); soft > 0 {
		slog.Info("memory limit from cgroup", "goMemLimitBytes", soft)
	}
	policy, err := cfg.policy()
	if err != nil {
		return err
	}
	authn, err := cfg.authenticator()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	clients, err := kube.ConnectWith(cfg.kubeconfig, kube.ClientOptions{
		QPS: float32(cfg.kubeQPS), Burst: cfg.kubeBurst, UserAgent: "kubesentry/" + version,
		Observe: func(verb, resource, code string) { metrics.KubeRequests.With(verb, resource, code).Inc() },
	})
	if err != nil {
		return fmt.Errorf("kubernetes client: %w", err)
	}

	srv := &api.Server{
		Policy:      policy,
		PVCOptions:  detectors.PVCOptions{MinAge: cfg.pvcMinAge},
		LeakOptions: policy.Leak,
		APIToken:    cfg.apiToken,
		UI:          web.Handler(),
		SignOutURL:  cfg.signOutURL,
		ClusterInfo: model.ClusterInfo{Name: cfg.clusterName},
		RateLimit:   cfg.rateLimit, RateBurst: cfg.rateBurst, MaxInflight: cfg.maxInflight,
		AccessLog:     slog.Default(),
		Authenticator: authn,
	}

	// Views: the informer cache feeding a debounced snapshot manager, or a
	// per-request LIST for debugging.
	var current func() *snapshot.View
	var ready atomic.Bool
	if cfg.cache {
		cache := kube.NewCache(clients, kube.CacheOptions{AWSAuth: cfg.awsAuth, NodeLabelKeysAdd: cfg.nodeLabelKeysAdd.items, ClusterName: cfg.clusterName})
		if err := cache.Start(ctx); err != nil {
			return fmt.Errorf("start informer cache: %w", err)
		}
		mgr := &snapshot.Manager{Source: cache, Policy: policy, MinInterval: cfg.snapshotMinInterval, MaxDelay: cfg.snapshotMaxDelay, OnBuild: onBuild}
		go func() {
			start := time.Now()
			if err := cache.WaitSynced(ctx); err != nil {
				return
			}
			slog.Info("informer cache synced", "took", time.Since(start).Round(time.Millisecond), "unavailable", cache.Unavailable())
			_ = mgr.Run(ctx)
		}()
		srv.Cluster, srv.Inventory, srv.Certs = cache, cache, cache
		srv.Views = mgr
		srv.Unavailable = cache.Unavailable
		srv.ResponseCache = &api.ResponseCache{MaxBytes: 64 << 20}
		current = mgr.Current
		srv.Ready = func() bool {
			if !ready.Load() && cache.Ready() && mgr.Current() != nil {
				ready.Store(true)
			}
			return ready.Load()
		}
		registerCacheMetrics(cache)
	} else {
		src := kube.NewSourceWithOptions(clients.CS, clients.Dyn, kube.SourceOptions{
			AWSAuth: cfg.awsAuth, NodeLabelKeysAdd: cfg.nodeLabelKeysAdd.items, ClusterName: cfg.clusterName})
		views := &recordingViews{inner: snapshot.OnDemand{Source: src, Policy: policy}}
		srv.Cluster, srv.Inventory, srv.Certs = src, src, src
		srv.Views = views
		current = views.latest
		slog.Warn("-cache=false: every request lists the cluster; use only for debugging")
	}
	registerSnapshotMetrics(current)

	if cfg.authMode == "proxy" {
		reviewer, err := kube.NewReviewer(clients, float32(cfg.authzQPS), 2*int(cfg.authzQPS))
		if err != nil {
			return fmt.Errorf("subjectaccessreview client: %w", err)
		}
		srv.Authorizer = &auth.SARAuthorizer{
			Reviewer:      reviewer,
			Candidates:    viewCandidates{current},
			TTL:           cfg.authzCacheTTL,
			DenyTTL:       cfg.authzDenyTTL,
			ShareByGroups: cfg.authzShareByGroups,
			Metrics:       metrics.AuthzObserver,
		}
	}

	sel, _ := prom.ParseMatchers(cfg.promSelector) // validated with the flags
	metricsSource := &promSource{}
	err = promSetup{
		url: cfg.promURL, service: cfg.promService, region: cfg.awsRegion, sigv4: cfg.promSigV4, ksmLimits: cfg.promKSMLimits,
		autodiscover: cfg.promAutodiscover, selector: sel,
		scan: prom.LeakScanOptions{Interval: cfg.leakScanInterval, Window: cfg.leakScanWindow, Leak: policy.Leak},
		pods: func(context.Context) ([]model.Pod, error) {
			if v := current(); v != nil {
				return v.Inv.Pods, nil // shared and read-only, which the scanner respects
			}
			return nil, errors.New("no cluster view yet")
		},
		discover: func(ctx context.Context) ([]string, error) {
			return kube.DiscoverPrometheus(ctx, clients.CS, cfg.promService)
		},
	}.start(ctx, metricsSource)
	if err != nil {
		return err
	}
	srv.Metrics = metricsSource
	srv.PrometheusInfo = metricsSource.Info

	closers, err := setupAudit(ctx, cfg, policy, srv)
	if err != nil {
		return err
	}
	defer closers.close()

	if cfg.agentToken != "" {
		store := procmon.NewStoreWithOptions(procmon.StoreOptions{Interval: cfg.agentInterval})
		srv.Processes = store
		srv.AgentToken = cfg.agentToken
		metrics.AgentNodesReporting.SetFunc(func() float64 { return float64(store.Reporting()) })
		go func() {
			// Forget silent nodes even when no agent reports at all.
			t := time.NewTicker(cfg.agentInterval)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					store.Sweep()
				}
			}
		}()
	}

	srv.Checks = append(srv.Checks, api.HealthCheck{Name: "snapshot", Check: func(context.Context) error {
		if v := current(); v != nil && v.Stale {
			return fmt.Errorf("serving the last good view: %s", v.Err)
		}
		return nil
	}})

	return serve(ctx, stop, cfg, srv)
}

// serve runs the listeners. On a signal it fails readiness, waits the drain
// delay so load balancers stop sending traffic, then shuts the listeners
// down, letting requests in flight finish.
func serve(ctx context.Context, stop context.CancelFunc, cfg *config, srv *api.Server) error {
	var draining atomic.Bool
	if r := srv.Ready; r != nil {
		srv.Ready = func() bool { return !draining.Load() && r() }
	} else {
		srv.Ready = func() bool { return !draining.Load() }
	}

	type listener struct {
		name, addr string
		parts      api.Parts
		tls        bool
		readTO     time.Duration
	}
	web := listener{name: "web", addr: cfg.addr, parts: api.Parts{Web: true}, tls: cfg.tlsCert != "", readTO: 30 * time.Second}
	ls := []*listener{&web}
	if cfg.ingestAddr == "" {
		web.parts.Ingest = true
		web.readTO = 2 * time.Minute
	} else {
		ls = append(ls, &listener{name: "ingest", addr: cfg.ingestAddr, parts: api.Parts{Ingest: true}, tls: cfg.tlsCert != "", readTO: 2 * time.Minute})
	}
	if cfg.opsAddr == "" {
		web.parts.Probes = true
	} else {
		ls = append(ls, &listener{name: "ops", addr: cfg.opsAddr, parts: api.Parts{Probes: true, Metrics: true, Pprof: cfg.pprof}, readTO: 30 * time.Second})
	}

	servers := make([]*http.Server, len(ls))
	errc := make(chan error, len(ls))
	for i, l := range ls {
		hs := &http.Server{
			Addr: l.addr, Handler: srv.Serve(l.parts),
			ReadHeaderTimeout: 10 * time.Second, ReadTimeout: l.readTO, IdleTimeout: 2 * time.Minute,
			MaxHeaderBytes: 256 << 10,
		}
		servers[i] = hs
		ln, err := net.Listen("tcp", l.addr)
		if err != nil {
			return fmt.Errorf("%s listener: %w", l.name, err)
		}
		slog.Info("kubesentry listening", "listener", l.name, "addr", ln.Addr().String(), "tls", l.tls, "version", version)
		go func() {
			var err error
			if l.tls {
				err = hs.ServeTLS(ln, cfg.tlsCert, cfg.tlsKey)
			} else {
				err = hs.Serve(ln)
			}
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("%s listener: %w", l.name, err)
			}
		}()
	}

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	stop() // a second signal kills at once
	draining.Store(true)
	slog.Info("shutting down", "drain", cfg.shutdownDrain, "timeout", cfg.shutdownTimeout)
	time.Sleep(cfg.shutdownDrain)
	sctx, cancel := context.WithTimeout(context.Background(), cfg.shutdownTimeout)
	defer cancel()
	for _, hs := range servers {
		if err := hs.Shutdown(sctx); err != nil {
			slog.Warn("shutdown", "addr", hs.Addr, "err", err)
		}
	}
	return nil
}

// viewCandidates proposes namespaces from the RBAC index of whatever view is
// current, so the authorizer follows RBAC changes as views are rebuilt.
type viewCandidates struct{ current func() *snapshot.View }

func (c viewCandidates) Namespaces(user string, groups []string, cp auth.Capability) []string {
	if v := c.current(); v != nil {
		return v.RBAC().Namespaces(user, groups, cp)
	}
	return nil
}

// Ready is false until the first view exists: scopes computed before then
// have no candidates, so the authorizer does not cache them.
func (c viewCandidates) Ready() bool { return c.current() != nil }

// HasUserBindings reports whether a binding names the user. Before the first
// view nobody knows, so it says yes: with -authz-share-by-groups the user's
// answers are then cached per user rather than shared.
func (c viewCandidates) HasUserBindings(user string) bool {
	if v := c.current(); v != nil {
		return v.RBAC().HasUserBindings(user)
	}
	return true
}

var (
	_ auth.CandidatesReadiness = viewCandidates{}
	_ auth.UserBindings        = viewCandidates{}
)

// recordingViews remembers the last view an OnDemand provider built, for the
// authorizer's candidates and metrics in -cache=false mode.
type recordingViews struct {
	inner snapshot.ViewProvider
	last  atomic.Pointer[snapshot.View]
}

func (r *recordingViews) View(ctx context.Context) (*snapshot.View, error) {
	v, err := r.inner.View(ctx)
	if err == nil {
		r.last.Store(v)
	}
	return v, err
}

func (r *recordingViews) latest() *snapshot.View { return r.last.Load() }

// onBuild feeds the snapshot metrics after every build attempt.
func onBuild(v *snapshot.View, took time.Duration, err error) {
	if err != nil {
		slog.Warn("snapshot rebuild failed; serving the last good view", "err", err)
		return
	}
	metrics.SnapshotBuild.Observe(took.Seconds())
	metrics.SnapshotVersion.Set(float64(v.Version))
}

func registerSnapshotMetrics(current func() *snapshot.View) {
	metrics.SnapshotAge.SetFunc(func() float64 {
		if v := current(); v != nil {
			return time.Since(v.Built).Seconds()
		}
		return 0
	})
}

// registerCacheMetrics exposes how many objects each informer holds. Counts
// are read at most every 5s, however many gauges a scrape reads.
func registerCacheMetrics(c *kube.Cache) {
	var (
		at     atomic.Int64
		counts atomic.Pointer[map[string]int]
	)
	get := func() map[string]int {
		if p := counts.Load(); p != nil && time.Since(time.Unix(0, at.Load())) < 5*time.Second {
			return *p
		}
		m := c.ObjectCounts()
		counts.Store(&m)
		at.Store(time.Now().UnixNano())
		return m
	}
	for res := range c.ObjectCounts() {
		metrics.InformerObjects.With(res).SetFunc(func() float64 { return float64(get()[res]) })
	}
}

// isLoopback reports whether addr ("host:port") listens on loopback only.
func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// closers runs cleanups in reverse order.
type closers []func()

func (c closers) close() {
	for i := len(c) - 1; i >= 0; i-- {
		c[i]()
	}
}

// hostname names this replica in Postgres checkpoints: the pod name when the
// chart sets POD_NAME.
func hostname() string {
	if p := os.Getenv("POD_NAME"); p != "" {
		return p
	}
	h, _ := os.Hostname()
	return strings.TrimSpace(h)
}
