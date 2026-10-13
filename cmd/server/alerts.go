package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ByronGary/kubesentry/internal/alerts"
	"github.com/ByronGary/kubesentry/internal/api"
	"github.com/ByronGary/kubesentry/internal/awsauth"
	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/metrics"
	"github.com/ByronGary/kubesentry/internal/pgstore"
	"github.com/ByronGary/kubesentry/internal/snapshot"
)

// Secrets for the Alertmanager sink come from the environment (the chart
// mounts them from a Secret), never from flags.
const (
	alertmanagerTokenEnv    = "ALERTMANAGER_TOKEN"
	alertmanagerPasswordEnv = "ALERTMANAGER_PASSWORD"
)

// alertsConfig is the alerting flags.
type alertsConfig struct {
	enabled       bool
	urls          string
	caFile        string
	sigv4         bool
	basicUser     string
	interval      time.Duration
	resend        time.Duration
	resolveGrace  time.Duration
	maxNew        int
	defaultOwner  string
	leakCritHours float64
	runbookURL    string
	externalURL   string
}

type durFlag func(p *time.Duration, name string, def time.Duration, usage string)

func (a *alertsConfig) register(fs *flag.FlagSet, dur durFlag) {
	fs.BoolVar(&a.enabled, "alerts", false, "evaluate findings and send them to Alertmanager (with Postgres, on the replica holding the alerts lock)")
	fs.StringVar(&a.urls, "alertmanager-url", "", "Alertmanager base URLs, comma-separated; every alert goes to each (an HA pair, or an AMP workspace's .../alertmanager). Bearer token from "+alertmanagerTokenEnv)
	fs.StringVar(&a.caFile, "alertmanager-ca-file", "", "PEM CA bundle to verify Alertmanager's TLS certificate (added to the system roots)")
	fs.BoolVar(&a.sigv4, "alertmanager-sigv4", false, "sign requests with AWS SigV4 for the Amazon Managed Prometheus alert manager (automatic for aps-workspaces.*.amazonaws.com)")
	fs.StringVar(&a.basicUser, "alertmanager-basic-auth-user", "", "basic auth user for Alertmanager; the password comes from "+alertmanagerPasswordEnv)
	dur(&a.interval, "alerts-interval", 30*time.Second, "alerts are evaluated after view rebuilds, at most this often, and at least this often in a quiet cluster")
	dur(&a.resend, "alerts-resend", time.Minute, "open alerts are posted again this often, with endsAt 4x this ahead")
	dur(&a.resolveGrace, "alerts-resolve-grace", 5*time.Minute, "a finding gone this long resolves (and Alertmanager gets endsAt=now)")
	fs.IntVar(&a.maxNew, "alerts-max-new", 50, "more new alerts than this in one evaluation go out as one digest per owner (kubesentry_digest=\"true\")")
	fs.StringVar(&a.defaultOwner, "alerts-default-owner", "platform", "owner of findings whose namespace has no owner annotation, and of cluster-scoped findings")
	fs.Float64Var(&a.leakCritHours, "alerts-leak-crit-hours", 0, "a memory leak alert is critical when the limit is closer than this many hours (0: -leak-crit-hours)")
	fs.StringVar(&a.runbookURL, "alerts-runbook-url", alerts.DefaultRunbookURL, "each alert's runbook_url is this plus #<alert name in lower case>")
	fs.StringVar(&a.externalURL, "external-url", "", "kubesentry's URL as users reach it (e.g. https://kubesentry.example.com); alerts link to their finding there (kubesentry_url)")
}

// endpoints parses -alertmanager-url.
func (a *alertsConfig) endpoints() ([]string, error) {
	var out []string
	for _, u := range strings.Split(a.urls, ",") {
		if u = strings.TrimSpace(u); u == "" {
			continue
		}
		if _, err := alerts.Endpoint(u); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, nil
}

// useSigV4 reports whether requests are signed: -alertmanager-sigv4, or
// every URL is an AMP workspace.
func (a *alertsConfig) useSigV4(urls []string) bool {
	if a.sigv4 {
		return true
	}
	for _, u := range urls {
		if !awsauth.IsAMP(u) {
			return false
		}
	}
	return len(urls) > 0
}

func (a *alertsConfig) validate(c *config) error {
	urls, err := a.endpoints()
	if err != nil {
		return fmt.Errorf("-alertmanager-url: %w", err)
	}
	if !a.enabled {
		if len(urls) > 0 {
			return errors.New("-alertmanager-url needs -alerts")
		}
		return nil
	}
	amp := 0
	for _, u := range urls {
		if awsauth.IsAMP(u) {
			amp++
		}
	}
	if amp > 0 && amp < len(urls) && !a.sigv4 {
		return errors.New("-alertmanager-url mixes Amazon Managed Prometheus workspaces with other Alertmanagers: SigV4 would sign only some; use one kind, or -alertmanager-sigv4 to sign all")
	}
	switch {
	case !c.cache:
		return errors.New("-alerts evaluates the informer cache's views: it needs -cache=true")
	case a.interval <= 0:
		return errors.New("-alerts-interval must be positive")
	case a.resend < a.interval:
		return fmt.Errorf("-alerts-resend (%s) must be at least -alerts-interval (%s): resends happen at evaluations", a.resend, a.interval)
	case a.resolveGrace < 0:
		return errors.New("-alerts-resolve-grace must not be negative")
	case a.maxNew < 1:
		return errors.New("-alerts-max-new must be at least 1")
	case strings.TrimSpace(a.defaultOwner) == "":
		return errors.New("-alerts-default-owner must not be empty")
	case a.leakCritHours < 0:
		return errors.New("-alerts-leak-crit-hours must not be negative")
	}
	if a.externalURL != "" {
		u, err := url.Parse(a.externalURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("-external-url %q: want http(s)://host[:port][/path]", a.externalURL)
		}
	}
	if u, err := url.Parse(a.runbookURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("-alerts-runbook-url %q: want an http(s) URL", a.runbookURL)
	}
	return nil
}

// alertsSetup is what setupAlerts wires together.
type alertsSetup struct {
	cfg     *config
	current func() *snapshot.View
	leaks   func() (detectors.LeakReport, time.Duration, bool)
	pg      *pgstore.Store // nil: the memory store, this replica alone
	kick    <-chan struct{}
}

// start builds the sink and the runner and starts them; the runner serves
// /alerts, /info's alerts and the Overview's widget.
func (s alertsSetup) start(ctx context.Context, srv *api.Server) (*alerts.Runner, error) {
	a := s.cfg.alerts
	sink, err := s.sink(ctx)
	if err != nil {
		return nil, err
	}
	r := &alerts.Runner{
		Sink: sink, Kick: s.kick, Interval: a.interval,
		Options: alerts.Options{
			Resend: a.resend, ResolveGrace: a.resolveGrace, MaxNew: a.maxNew, DefaultOwner: strings.TrimSpace(a.defaultOwner),
			LeakCritHours: a.leakCritHours, ExternalURL: a.externalURL, RunbookURL: a.runbookURL, Cluster: s.cfg.clusterName,
		},
		Input: func() (alerts.Input, bool) {
			v := s.current()
			if v == nil {
				return alerts.Input{}, false
			}
			in := alerts.Input{View: v, Now: time.Now()}
			if rep, _, ok := s.leaks(); ok && !rep.GeneratedAt.IsZero() {
				in.Leaks = &rep
			}
			return in, true
		},
		OnEvaluate: observeEvaluation,
		OnLeader:   observeLeader,
		Logger:     slog.Default(),
	}
	if s.pg != nil {
		r.Store = s.pg.Alerts()
		r.Elect = func(ctx context.Context) (alerts.Lease, bool, error) {
			l, ok, err := s.pg.TryLead(ctx, "alerts")
			if err != nil || !ok {
				return nil, false, err
			}
			return pgLease{l}, true, nil
		}
	} else {
		r.Store = alerts.NewMemoryStore()
	}
	observeLeader(false)
	go r.Run(ctx)
	srv.Alerts = r
	store := "memory (this replica alone; state is lost on restart)"
	if s.pg != nil {
		store = "postgres (the replica holding the alerts lock evaluates)"
	}
	slog.Info("alerting on", "sink", sink.Status().Name, "store", store, "interval", a.interval, "resend", a.resend,
		"resolveGrace", a.resolveGrace, "maxNew", a.maxNew, "defaultOwner", a.defaultOwner, "externalURL", a.externalURL)
	return r, nil
}

// sink builds the Alertmanager sink, or a sink that notifies nobody when
// no URL is set (findings are still tracked and listed).
func (s alertsSetup) sink(ctx context.Context) (alerts.Sink, error) {
	a := s.cfg.alerts
	urls, err := a.endpoints()
	if err != nil {
		return nil, err
	}
	if len(urls) == 0 {
		slog.Warn("-alerts without -alertmanager-url: findings are tracked and listed, but nobody is notified")
		return alerts.NopSink{}, nil
	}
	base := http.DefaultTransport.(*http.Transport).Clone()
	if a.caFile != "" {
		pem, err := os.ReadFile(a.caFile)
		if err != nil {
			return nil, fmt.Errorf("-alertmanager-ca-file: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("-alertmanager-ca-file %s: no PEM certificate in it", a.caFile)
		}
		base.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	var tr http.RoundTripper = base
	token, password := os.Getenv(alertmanagerTokenEnv), os.Getenv(alertmanagerPasswordEnv)
	if token != "" && a.basicUser != "" {
		return nil, fmt.Errorf("set either %s or -alertmanager-basic-auth-user, not both", alertmanagerTokenEnv)
	}
	if a.basicUser != "" && password == "" {
		return nil, fmt.Errorf("-alertmanager-basic-auth-user needs %s", alertmanagerPasswordEnv)
	}
	signed := a.useSigV4(urls)
	if signed {
		if token != "" || a.basicUser != "" {
			return nil, errors.New("SigV4 signs Alertmanager requests itself: drop the token or basic auth")
		}
		t, err := awsauth.New(ctx, urls[0], awsauth.Options{Region: s.cfg.awsRegion, Service: awsauth.ServiceAPS, Base: base})
		if err != nil {
			return nil, fmt.Errorf("alertmanager SigV4: %w", err)
		}
		tr = t
	}
	am, err := alerts.NewAlertmanager(alerts.AlertmanagerOptions{
		URLs: urls, Client: &http.Client{Transport: tr, Timeout: 10 * time.Second},
		BearerToken: token, BasicUser: a.basicUser, BasicPassword: password,
		UserAgent: "kubesentry/" + version,
		OnResult:  func(result string, n int) { metrics.AlertsSent.With(result).Add(float64(n)) },
	})
	if err != nil {
		return nil, err
	}
	go am.Run(ctx)
	metrics.AlertsQueueDepth.SetFunc(func() float64 { return float64(am.Status().Queued) })
	dependencyUp("alertmanager", func() error {
		if st := am.Status(); st.LastError != "" {
			return errors.New(st.LastError)
		}
		return nil
	})
	slog.Info("alertmanager sink", "urls", len(urls), "sigv4", signed, "caFile", a.caFile != "", "bearerToken", token != "", "basicAuth", a.basicUser != "")
	return am, nil
}

// pgLease is a Postgres advisory lock as an alerts.Lease: its store
// writes only while the lock is held.
type pgLease struct{ *pgstore.Leader }

func (l pgLease) Store() alerts.Store { return l.Alerts() }

var _ alerts.Lease = pgLease{}

// observeEvaluation feeds kubesentry_alerts_evaluation_seconds and
// kubesentry_findings{check,severity}.
func observeEvaluation(res alerts.Result, took time.Duration, err error) {
	metrics.AlertsEvaluation.Observe(took.Seconds())
	if err != nil {
		return
	}
	for _, check := range alerts.Checks() {
		for _, sev := range []string{alerts.SeverityWarning, alerts.SeverityCritical} {
			metrics.Findings.With(check, sev).Set(float64(res.OpenBy[[2]string{check, sev}]))
		}
	}
}

// observeLeader feeds kubesentry_alerts_leader; a replica that does not
// evaluate reports no findings, so sums across replicas stay right.
func observeLeader(on bool) {
	if on {
		metrics.AlertsLeader.Set(1)
		return
	}
	metrics.AlertsLeader.Set(0)
	for _, check := range alerts.Checks() {
		for _, sev := range []string{alerts.SeverityWarning, alerts.SeverityCritical} {
			metrics.Findings.With(check, sev).Set(0)
		}
	}
}
