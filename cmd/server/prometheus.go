package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ByronGary/kubesentry/internal/api"
	"github.com/ByronGary/kubesentry/internal/awsauth"
	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/metrics"
	"github.com/ByronGary/kubesentry/internal/model"
	"github.com/ByronGary/kubesentry/internal/prom"
)

// errNoPrometheus is returned while no Prometheus has been found.
var errNoPrometheus = errors.New("no Prometheus configured or discovered yet")

// promSource is the server's metrics source: the Prometheus named by
// -prometheus-url, or one discovery finds later, with the background leak
// scanner over it. It satisfies api.MetricsSource; until a Prometheus is
// known it reports MetricsAvailable false and the API treats it as absent.
type promSource struct {
	cur atomic.Pointer[promState]
}

type promState struct {
	client  *prom.Client
	probe   *http.Client // signs for AMP; nil uses Probe's default
	scanner *prom.LeakScanner
	info    api.PrometheusInfo // info.URL never carries user info
	rawURL  string             // as configured, user info included: only for probing
	health  *promHealth
}

func (p *promSource) MetricsAvailable() bool { return p.cur.Load() != nil }

// Health reports why Prometheus cannot be queried now, nil when it can or
// when there is none to query (that is configuration, not an outage). /info
// lists it under unavailable and the ops /readyz under degraded.
func (p *promSource) Health() error {
	if st := p.cur.Load(); st != nil && st.health != nil {
		return st.health.Err()
	}
	return nil
}

// promDownAfter consecutive failed requests mark Prometheus down; the next
// success marks it up.
const promDownAfter = 2

// promHeartbeat is how often the health probe checks Prometheus, so an
// outage (and the recovery) shows even while nobody opens a page that
// queries it, and while the query cache answers those who do.
const promHeartbeat = 15 * time.Second

// promHealth remembers how the last requests to Prometheus went: every
// request (pages, the leak scanner, the probes) passes healthTransport.
type promHealth struct {
	mu      sync.Mutex
	fails   int
	lastErr string
}

func (h *promHealth) observe(reason string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if reason == "" {
		h.fails, h.lastErr = 0, ""
		return
	}
	h.fails++
	h.lastErr = reason
}

// Err is non-nil while Prometheus is down.
func (h *promHealth) Err() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.fails < promDownAfter {
		return nil
	}
	return fmt.Errorf("%d queries failed in a row; last: %s", h.fails, h.lastErr)
}

// healthTransport records whether each request reached a Prometheus that
// answered. Failures are a transport error, a 5xx, 401, 403 or 429; a 4xx
// for a bad query still counts as an answer. A request its caller cancelled
// says nothing either way. The reason never includes the URL: queries carry
// namespace names, and /info shows the reason to every user.
type healthTransport struct {
	base http.RoundTripper
	h    *promHealth
}

func (t healthTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(r)
	switch {
	case err != nil:
		if r.Context().Err() == nil {
			var ue *url.Error
			if errors.As(err, &ue) {
				err = ue.Err
			}
			t.h.observe("unreachable: " + err.Error())
		}
	case resp.StatusCode >= 500, resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden,
		resp.StatusCode == http.StatusTooManyRequests:
		t.h.observe("HTTP " + resp.Status)
	default:
		t.h.observe("")
	}
	return resp, err
}

// heartbeat probes Prometheus (buildinfo and a count(up) query, uncached)
// every interval until ctx ends; the outcome reaches st.health through the
// probe client's transport.
func (st *promState) heartbeat(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		_, _ = prom.Probe(ctx, st.rawURL, st.probe)
	}
}

func (p *promSource) state() (*promState, error) {
	if st := p.cur.Load(); st != nil {
		return st, nil
	}
	return nil, errNoPrometheus
}

func (p *promSource) ContainerMemory(ctx context.Context, lookback, step time.Duration) ([]model.ContainerSeries, error) {
	st, err := p.state()
	if err != nil {
		return nil, err
	}
	return st.client.ContainerMemory(ctx, lookback, step)
}

func (p *promSource) ContainerMemoryLimits(ctx context.Context) (map[model.ContainerKey]float64, error) {
	st, err := p.state()
	if err != nil {
		return nil, err
	}
	return st.client.ContainerMemoryLimits(ctx)
}

func (p *promSource) ContainerMemoryIn(ctx context.Context, namespaces []string, lookback, step time.Duration) ([]model.ContainerSeries, error) {
	st, err := p.state()
	if err != nil {
		return nil, err
	}
	return st.client.ContainerMemoryIn(ctx, namespaces, lookback, step)
}

func (p *promSource) ContainerMemoryLimitsIn(ctx context.Context, namespaces []string) (map[model.ContainerKey]float64, error) {
	st, err := p.state()
	if err != nil {
		return nil, err
	}
	return st.client.ContainerMemoryLimitsIn(ctx, namespaces)
}

func (p *promSource) PodMemory(ctx context.Context, ns, pod string, lookback, step time.Duration) ([]model.ContainerSeries, map[model.ContainerKey]float64, error) {
	st, err := p.state()
	if err != nil {
		return nil, nil, err
	}
	return st.client.PodMemory(ctx, ns, pod, lookback, step)
}

// LeakReport is the leak scanner's latest report and window.
func (p *promSource) LeakReport() (detectors.LeakReport, time.Duration, bool) {
	st := p.cur.Load()
	if st == nil || st.scanner == nil {
		return detectors.LeakReport{}, 0, false
	}
	return st.scanner.Latest(), st.scanner.Window(), true
}

// Info is /info's prometheus field.
func (p *promSource) Info() *api.PrometheusInfo {
	if st := p.cur.Load(); st != nil {
		info := st.info
		return &info
	}
	return &api.PrometheusInfo{Source: "none"}
}

// promSetup is what building the Prometheus client needs.
type promSetup struct {
	url, service, region string
	sigv4, ksmLimits     bool
	autodiscover         bool
	selector             prom.Matchers
	scan                 prom.LeakScanOptions
	pods                 prom.PodLister
	// discover returns candidate base URLs, best first (kube.DiscoverPrometheus).
	discover func(ctx context.Context) ([]string, error)
	retry    time.Duration // between discovery attempts; default 1m
	// heartbeat is how often the health probe runs; default promHeartbeat.
	heartbeat time.Duration
}

// start sets the source up: at once for -prometheus-url, otherwise by
// discovery in the background, retried until a Prometheus answers.
func (s promSetup) start(ctx context.Context, p *promSource) error {
	if s.url != "" {
		st, err := s.connect(ctx, s.url, "flag")
		if err != nil {
			return err
		}
		p.cur.Store(st)
		go s.describe(ctx, p, st)
		return nil
	}
	if !s.autodiscover || s.discover == nil {
		slog.Warn("no Prometheus: set -prometheus-url or -prometheus-autodiscover; OOM leak detection is off (OOMKilled events still work)")
		return nil
	}
	go s.discoverLoop(ctx, p)
	return nil
}

// connect builds the client (SigV4-signed for Amazon Managed Prometheus)
// and the leak scanner, which starts at once.
func (s promSetup) connect(ctx context.Context, url, source string) (*promState, error) {
	var tr http.RoundTripper
	if s.sigv4 || awsauth.IsAMP(url) {
		t, err := awsauth.New(ctx, url, awsauth.Options{Region: s.region})
		if err != nil {
			return nil, fmt.Errorf("prometheus SigV4: %w", err)
		}
		tr, source = t, "amp"
	}
	health := &promHealth{}
	queryTr := tr
	if queryTr == nil {
		queryTr = http.DefaultTransport
	}
	c, err := prom.NewClient(url, prom.Options{
		BearerToken: os.Getenv("PROMETHEUS_TOKEN"),
		Transport:   healthTransport{base: queryTr, h: health},
		Selector:    s.selector,
		KSMLimits:   s.ksmLimits,
		Cache:       prom.NewCache(prom.CacheOptions{}),
		Observer: prom.ObserverFuncs{
			Cache: func(result string) { metrics.PromCache.With(result).Inc() },
			Query: func(kind string, d time.Duration) { metrics.PromQuery.With(kind).Observe(d.Seconds()) },
		},
	})
	if err != nil {
		return nil, err
	}
	probe := probeClient(tr)
	probe.Transport = healthTransport{base: probe.Transport, h: health}
	st := &promState{client: c, info: api.PrometheusInfo{Source: source, URL: c.BaseURL()}, rawURL: url, probe: probe, health: health}
	heartbeat := s.heartbeat
	if heartbeat <= 0 {
		heartbeat = promHeartbeat
	}
	go st.heartbeat(ctx, heartbeat)
	if c.HasURLCredentials() {
		slog.Warn("-prometheus-url carries credentials (user:password@); they are sent as basic auth but kept out of logs and /info. "+
			"Prefer PROMETHEUS_TOKEN (chart: prometheus.bearerTokenSecret), which stays out of the process arguments", "url", c.BaseURL())
	}
	st.scanner = prom.NewLeakScanner(c, s.pods, s.scan)
	go st.scanner.Run(ctx)
	slog.Info("prometheus", "url", c.BaseURL(), "source", source, "selector", s.selector.String(), "ksmLimits", s.ksmLimits,
		"leakScanWindow", st.scanner.Window())
	return st, nil
}

// describe probes a configured Prometheus for its flavour, version and
// retention, for /info. A failed probe only logs: queries may still work.
func (s promSetup) describe(ctx context.Context, p *promSource, st *promState) {
	bi, err := prom.Probe(ctx, st.rawURL, st.probe)
	if err != nil {
		// net/http masks the password in the URLs of its errors.
		slog.Warn("prometheus probe failed; queries may still work", "url", st.info.URL, "err", err)
		return
	}
	next := *st
	next.info.Flavor, next.info.Version, next.info.RetentionHours = bi.Flavor, bi.Version, bi.RetentionHours
	p.cur.CompareAndSwap(st, &next)
}

// discoverLoop looks for an in-cluster Prometheus until one answers.
func (s promSetup) discoverLoop(ctx context.Context, p *promSource) {
	wait := s.retry
	if wait <= 0 {
		wait = time.Minute
	}
	for {
		if st, err := s.discoverOnce(ctx); err == nil {
			p.cur.Store(st)
			return
		} else if ctx.Err() == nil {
			slog.Warn("no Prometheus found; leak detection waits for one", "retryIn", wait, "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// discoverOnce lists the candidates and picks the first that answers.
func (s promSetup) discoverOnce(ctx context.Context) (*promState, error) {
	urls, err := s.discover(ctx)
	if err != nil && len(urls) == 0 {
		return nil, fmt.Errorf("discover: %w", err)
	}
	bi, rejected, err := prom.Choose(ctx, urls, probeClient(nil))
	for _, r := range rejected {
		slog.Info("prometheus candidate rejected", "url", r.URL, "reason", r.Reason)
	}
	if err != nil {
		return nil, err
	}
	st, err := s.connect(ctx, bi.URL, "discovered")
	if err != nil {
		return nil, err
	}
	st.info.Flavor, st.info.Version, st.info.RetentionHours = bi.Flavor, bi.Version, bi.RetentionHours
	return st, nil
}

// probeClient is the HTTP client for buildinfo probes and discovery. It
// authenticates the way queries do: SigV4 when tr signs (Amazon Managed
// Prometheus), otherwise PROMETHEUS_TOKEN as a bearer token when set, so a
// Prometheus behind auth is not rejected during discovery.
func probeClient(tr http.RoundTripper) *http.Client {
	if tr == nil {
		tr = http.DefaultTransport
		if tok := os.Getenv("PROMETHEUS_TOKEN"); tok != "" {
			tr = bearerTransport{token: tok, base: tr}
		}
	}
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

type bearerTransport struct {
	token string
	base  http.RoundTripper
}

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(r)
}

// parseBytesPerHour reads a growth rate such as "1MiB", "512KiB/h" or
// "1048576" (bytes per hour).
func parseBytesPerHour(s string) (float64, error) {
	t := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), "/h"))
	mult := 1.0
	for _, u := range []struct {
		suffix string
		mult   float64
	}{{"KiB", 1 << 10}, {"MiB", 1 << 20}, {"GiB", 1 << 30}, {"Ki", 1 << 10}, {"Mi", 1 << 20}, {"Gi", 1 << 30},
		{"KB", 1e3}, {"MB", 1e6}, {"GB", 1e9}, {"B", 1}} {
		if strings.HasSuffix(t, u.suffix) {
			t, mult = strings.TrimSpace(strings.TrimSuffix(t, u.suffix)), u.mult
			break
		}
	}
	v, err := strconv.ParseFloat(t, 64)
	if err != nil || v < 0 {
		return 0, fmt.Errorf("invalid growth rate %q: use e.g. 1MiB or 1048576 (bytes per hour)", s)
	}
	return v * mult, nil
}

// bytesPerHourValue is a flag.Value for parseBytesPerHour.
type bytesPerHourValue float64

func (b *bytesPerHourValue) String() string {
	if b == nil {
		return ""
	}
	return strconv.FormatFloat(float64(*b), 'f', -1, 64)
}

func (b *bytesPerHourValue) Set(s string) error {
	v, err := parseBytesPerHour(s)
	*b = bytesPerHourValue(v)
	return err
}
