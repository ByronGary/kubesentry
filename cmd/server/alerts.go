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
	"sort"
	"strings"
	"time"
	_ "time/tzdata" // -alerts-digest-tz works wherever the binary runs (Windows has no zone database)

	"github.com/ByronGary/kubesentry/internal/alerts"
	"github.com/ByronGary/kubesentry/internal/api"
	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/awsauth"
	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/incidents"
	"github.com/ByronGary/kubesentry/internal/metrics"
	"github.com/ByronGary/kubesentry/internal/pgstore"
	"github.com/ByronGary/kubesentry/internal/procmon"
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
	ownerMaxNew   int
	ownerWindow   time.Duration
	maxSilence    time.Duration
	defaultOwner  string
	leakCritHours float64
	runbookURL    string
	externalURL   string

	// The catalog: checks turned off, the audit checks, the agent check.
	disableChecks     string
	auditChecks       string
	auditProdOnly     string
	auditHold         time.Duration
	auditDeniedBurst  int
	auditDeniedWindow time.Duration
	agents            string
	agentDaemonSet    string
	agentFanout       bool
	// Standing-state digests.
	digestAt       string
	digestTZ       string
	digestKinds    string
	certDigestDays int
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
	fs.IntVar(&a.ownerMaxNew, "alerts-owner-max-new", 20, "one owner gets at most this many new alerts on their own per -alerts-owner-window; more join that owner's digest")
	dur(&a.ownerWindow, "alerts-owner-window", 15*time.Minute, "the sliding window of -alerts-owner-max-new")
	dur(&a.maxSilence, "alerts-max-silence", alerts.DefaultMaxSilence, "the longest silence a user may set on a finding (at most 30d)")
	fs.StringVar(&a.defaultOwner, "alerts-default-owner", "platform", "owner of findings whose namespace has no owner annotation, and of cluster-scoped findings")
	fs.Float64Var(&a.leakCritHours, "alerts-leak-crit-hours", 0, "a memory leak alert is critical when the limit is closer than this many hours (0: -leak-crit-hours)")
	fs.StringVar(&a.runbookURL, "alerts-runbook-url", alerts.DefaultRunbookURL, "each alert's runbook_url is this plus #<alert name in lower case>")
	fs.StringVar(&a.externalURL, "external-url", "", "kubesentry's URL as users reach it (e.g. https://kubesentry.example.com); alerts link to their finding there (kubesentry_url), and with -incidents to their incident (incident_url); browsers may send write requests from its origin")

	fs.StringVar(&a.disableChecks, "alerts-disable-checks", "", "checks that never alert, comma-separated (e.g. nodeport,ingress-no-tls); their open findings resolve")
	fs.StringVar(&a.auditChecks, "alerts-audit", "all", "audit checks to run when an audit store exists, comma-separated: "+strings.Join(alerts.AuditChecks(), ",")+"; all, or none")
	fs.StringVar(&a.auditProdOnly, "alerts-audit-production-only", strings.Join(alerts.DefaultAuditProductionOnly, ","), "audit checks that count only events in production namespaces (-production-label), comma-separated; empty for none")
	dur(&a.auditHold, "alerts-audit-hold", time.Hour, "an audit finding stays open until this long passes without another matching event")
	fs.IntVar(&a.auditDeniedBurst, "alerts-audit-denied-burst", 20, "audit-denied-burst: this many denied requests by one actor within -alerts-audit-denied-window")
	dur(&a.auditDeniedWindow, "alerts-audit-denied-window", 10*time.Minute, "the window of -alerts-audit-denied-burst")
	fs.StringVar(&a.agents, "alerts-agents", "auto", "the agent-missing check: on, off, or auto (on when every agent report reaches this replica: the memory store's single replica, or -agent-fanout)")
	fs.StringVar(&a.agentDaemonSet, "agent-daemonset", "", "the node agent DaemonSet as namespace/name; nodes running its pod must report (agent-missing). The chart sets it")
	fs.BoolVar(&a.agentFanout, "agent-fanout", false, "every agent report reaches every replica: agents post to each replica, or there is only one (the chart sets it with agent.fanout or replicas: 1)")
	fs.StringVar(&a.digestAt, "alerts-digest-at", "", "when the standing-state digests go out: \"Mon 09:00\" weekly, \"09:00\" daily; empty turns them off")
	fs.StringVar(&a.digestTZ, "alerts-digest-tz", "UTC", "the time zone of -alerts-digest-at (an IANA name such as Europe/Berlin)")
	fs.StringVar(&a.digestKinds, "alerts-digest-kinds", strings.Join(alerts.DigestKinds(), ","), "standing digests to send, comma-separated: "+strings.Join(alerts.DigestKinds(), ","))
	fs.IntVar(&a.certDigestDays, "alerts-cert-digest-days", alerts.DefaultCertDigestDays, "with the certificates digest, an expiring certificate with more days left is only listed there; it alerts on its own once fewer are left")
}

// checkSet reads a comma-separated list of names from allowed into a set.
func checkSet(flagName, raw string, allowed []string) (map[string]bool, error) {
	ok := map[string]bool{}
	for _, c := range allowed {
		ok[c] = true
	}
	out := map[string]bool{}
	for _, c := range splitList(raw) {
		if !ok[c] {
			return nil, fmt.Errorf("-%s: unknown %q; use %s", flagName, c, strings.Join(allowed, ", "))
		}
		out[c] = true
	}
	return out, nil
}

// auditEnabled is -alerts-audit as a set.
func (a *alertsConfig) auditEnabled() (map[string]bool, error) {
	switch strings.TrimSpace(a.auditChecks) {
	case "all":
		return checkSet("alerts-audit", strings.Join(alerts.AuditChecks(), ","), alerts.AuditChecks())
	case "none", "":
		return map[string]bool{}, nil
	}
	return checkSet("alerts-audit", a.auditChecks, alerts.AuditChecks())
}

// agentsOn resolves -alerts-agents: auto runs the agent-missing check only
// where every agent report reaches this replica, so a replica that hears
// from some agents does not call the others missing.
func (a *alertsConfig) agentsOn(c *config) bool {
	switch a.agents {
	case "on":
		return true
	case "auto":
		return a.agentDaemonSet != "" && c.agentToken != "" && (c.auditStore != "postgres" || a.agentFanout)
	}
	return false
}

// digestSchedule parses -alerts-digest-at in -alerts-digest-tz.
func (a *alertsConfig) digestSchedule() (alerts.DigestSchedule, error) {
	s, err := alerts.ParseDigestSchedule(a.digestAt, a.digestTZ)
	if err != nil {
		return s, fmt.Errorf("-alerts-digest-at: %w", err)
	}
	return s, nil
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
	if _, err := externalOrigin(a.externalURL); err != nil {
		return err
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
	case a.ownerMaxNew < 1:
		return errors.New("-alerts-owner-max-new must be at least 1")
	case a.ownerWindow <= 0:
		return errors.New("-alerts-owner-window must be positive")
	case a.maxSilence < alerts.MinSilence || a.maxSilence > alerts.MaxSilenceCap:
		return fmt.Errorf("-alerts-max-silence must be from %s to 30d", alerts.MinSilence)
	case strings.TrimSpace(a.defaultOwner) == "":
		return errors.New("-alerts-default-owner must not be empty")
	case a.leakCritHours < 0:
		return errors.New("-alerts-leak-crit-hours must not be negative")
	}
	if u, err := url.Parse(a.runbookURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("-alerts-runbook-url %q: want an http(s) URL", a.runbookURL)
	}
	return a.validateCatalog(c)
}

// validateCatalog checks the flags of the checks and the standing digests.
func (a *alertsConfig) validateCatalog(c *config) error {
	if _, err := checkSet("alerts-disable-checks", a.disableChecks, alerts.Checks()); err != nil {
		return err
	}
	if _, err := a.auditEnabled(); err != nil {
		return err
	}
	if _, err := checkSet("alerts-audit-production-only", a.auditProdOnly, alerts.AuditChecks()); err != nil {
		return err
	}
	switch {
	case a.auditHold < 10*time.Minute || a.auditHold > 24*time.Hour:
		return errors.New("-alerts-audit-hold must be from 10m to 24h")
	case a.auditDeniedBurst < 2:
		return errors.New("-alerts-audit-denied-burst must be at least 2")
	case a.auditDeniedWindow < time.Minute || a.auditDeniedWindow > a.auditHold:
		return errors.New("-alerts-audit-denied-window must be from 1m to -alerts-audit-hold")
	case a.certDigestDays < 1 || a.certDigestDays > 365:
		return errors.New("-alerts-cert-digest-days must be from 1 to 365")
	}
	if _, err := a.digestSchedule(); err != nil {
		return err
	}
	if _, err := checkSet("alerts-digest-kinds", a.digestKinds, alerts.DigestKinds()); err != nil {
		return err
	}
	if a.agentDaemonSet != "" {
		ns, name, ok := alerts.SplitDaemonSet(a.agentDaemonSet)
		if !ok || !validDNSLabel(ns) || !validDNSSubdomain(name) {
			return fmt.Errorf("-agent-daemonset %q: want namespace/name", a.agentDaemonSet)
		}
	}
	switch a.agents {
	case "auto", "off":
	case "on":
		if a.agentDaemonSet == "" {
			return errors.New("-alerts-agents=on needs -agent-daemonset (namespace/name of the node agent DaemonSet)")
		}
		if c.agentToken == "" {
			return errors.New("-alerts-agents=on needs -agent-token: without it no agent reports")
		}
	default:
		return fmt.Errorf("-alerts-agents %q: use auto, on or off", a.agents)
	}
	return nil
}

// validDNSLabel reports whether s is a DNS-1123 label (a namespace name).
func validDNSLabel(s string) bool {
	if len(s) == 0 || len(s) > 63 {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '-' && i > 0 && i < len(s)-1:
		default:
			return false
		}
	}
	return true
}

// validDNSSubdomain reports whether s is a DNS-1123 subdomain (an object
// name).
func validDNSSubdomain(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, part := range strings.Split(s, ".") {
		if !validDNSLabel(part) {
			return false
		}
	}
	return true
}

// externalOrigin checks -external-url and returns its origin
// (scheme://host[:port]), which browsers may send write requests from; ""
// when it is not set.
func externalOrigin(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("-external-url %q: want http(s)://host[:port][/path]", raw)
	}
	return u.Scheme + "://" + u.Host, nil
}

// alertsSetup is what setupAlerts wires together.
type alertsSetup struct {
	cfg     *config
	current func() *snapshot.View
	leaks   func() (detectors.LeakReport, time.Duration, bool)
	pg      *pgstore.Store // nil: the memory store, this replica alone
	kick    <-chan struct{}
	// audit is the audit store the audit checks read (nil: none, so they are
	// off), and auditHealth whether it can be read now (nil: always).
	audit       audit.Store
	auditHealth func() error
	// procs is the node agents' store (nil without -agent-token).
	procs *procmon.Store
}

// catalog resolves which checks run and how: the disabled checks (with the
// audit checks -alerts-audit leaves out or no audit store backs, and
// agent-missing when it is off), the audit options, the agent DaemonSet
// and the digests.
func (s alertsSetup) catalog() (alerts.Options, error) {
	a := s.cfg.alerts
	var o alerts.Options
	disabled, err := checkSet("alerts-disable-checks", a.disableChecks, alerts.Checks())
	if err != nil {
		return o, err
	}
	enabled, err := a.auditEnabled()
	if err != nil {
		return o, err
	}
	for _, c := range alerts.AuditChecks() {
		if !enabled[c] || s.audit == nil {
			disabled[c] = true
		}
	}
	if a.agentsOn(s.cfg) && s.procs != nil {
		o.AgentDaemonSet = a.agentDaemonSet
	} else {
		disabled[alerts.CheckAgentMissing] = true
	}
	o.Disabled = disabled
	prodOnly, err := checkSet("alerts-audit-production-only", a.auditProdOnly, alerts.AuditChecks())
	if err != nil {
		return o, err
	}
	red, err := incidents.NewRedactor(s.cfg.incidents.redactPatterns)
	if err != nil {
		return o, err
	}
	o.Audit = alerts.AuditOptions{ProductionOnly: prodOnly, Hold: a.auditHold, DeniedBurst: a.auditDeniedBurst,
		DeniedWindow: a.auditDeniedWindow, Redact: red.String}
	sched, err := a.digestSchedule()
	if err != nil {
		return o, err
	}
	o.Digests = alerts.DigestOptions{Schedule: sched, Kinds: splitList(a.digestKinds), CertDays: a.certDigestDays, PVCMinAge: s.cfg.pvcMinAge}
	if o.Digests.Kinds == nil {
		o.Digests.Kinds = []string{}
	}
	return o, nil
}

// input is what each evaluation judges: the current view, the leak scan,
// the audit store while it can be read, and the agents' reports.
func (s alertsSetup) input(agents bool) (alerts.Input, bool) {
	v := s.current()
	if v == nil {
		return alerts.Input{}, false
	}
	in := alerts.Input{View: v, Now: time.Now()}
	if rep, _, ok := s.leaks(); ok && !rep.GeneratedAt.IsZero() {
		in.Leaks = &rep
	}
	if s.audit != nil && (s.auditHealth == nil || s.auditHealth() == nil) {
		in.Audit = s.audit
	}
	if agents && s.procs != nil {
		as := s.procs.Agents()
		last := make(map[string]time.Time, len(as))
		for _, x := range as {
			last[x.Node] = x.LastReport
		}
		in.Agents = &alerts.AgentReports{Interval: s.procs.Options().Interval, Last: last}
	}
	return in, true
}

// start builds the sink and the runner and starts them; the runner serves
// /alerts, /info's alerts and the Overview's widget.
func (s alertsSetup) start(ctx context.Context, srv *api.Server) (*alerts.Runner, error) {
	a := s.cfg.alerts
	o, err := s.catalog()
	if err != nil {
		return nil, err
	}
	sink, err := s.sink(ctx)
	if err != nil {
		return nil, err
	}
	o.Resend, o.ResolveGrace, o.MaxNew, o.DefaultOwner = a.resend, a.resolveGrace, a.maxNew, strings.TrimSpace(a.defaultOwner)
	o.OwnerMaxNew, o.OwnerWindow, o.MaxSilence = a.ownerMaxNew, a.ownerWindow, a.maxSilence
	o.LeakCritHours, o.ExternalURL, o.RunbookURL, o.Cluster = a.leakCritHours, a.externalURL, a.runbookURL, s.cfg.clusterName
	agents := o.AgentDaemonSet != ""
	r := &alerts.Runner{
		Sink: sink, Kick: s.kick, Interval: a.interval, Options: o,
		Input:      func() (alerts.Input, bool) { return s.input(agents) },
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
	for _, reason := range []string{alerts.DigestMaxNew, alerts.DigestOwnerBudget} {
		metrics.AlertsDigested.With(reason).Add(0)
	}
	for _, kind := range o.Digests.Kinds {
		metrics.AlertsStandingDigests.With(kind).Add(0)
	}
	go r.Run(ctx)
	srv.Alerts = r
	store := "memory (this replica alone; state is lost on restart)"
	if s.pg != nil {
		store = "postgres (the replica holding the alerts lock evaluates)"
	}
	var off []string
	for c := range o.Disabled {
		off = append(off, c)
	}
	sort.Strings(off)
	slog.Info("alerting on", "sink", sink.Status().Name, "store", store, "interval", a.interval, "resend", a.resend,
		"resolveGrace", a.resolveGrace, "maxNew", a.maxNew, "ownerMaxNew", a.ownerMaxNew, "ownerWindow", a.ownerWindow,
		"maxSilence", a.maxSilence, "defaultOwner", a.defaultOwner, "externalURL", a.externalURL,
		"checksOff", off, "agentDaemonSet", o.AgentDaemonSet, "digests", o.Digests.Schedule.String(), "digestKinds", o.Digests.Kinds)
	if a.agents == "auto" && !agents && a.agentDaemonSet != "" && s.procs != nil {
		slog.Info("alerts: agent-missing is off: with several replicas and no agent fan-out, a replica hears from only some agents (set -agent-fanout or -alerts-agents=on)")
	}
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

// observeEvaluation feeds kubesentry_alerts_evaluation_seconds,
// kubesentry_findings{check,severity} and
// kubesentry_alerts_digested_total{reason}.
func observeEvaluation(res alerts.Result, took time.Duration, err error) {
	metrics.AlertsEvaluation.Observe(took.Seconds())
	if err != nil {
		return
	}
	for reason, n := range res.Digested {
		metrics.AlertsDigested.With(reason).Add(float64(n))
	}
	for kind, n := range res.StandingDigests {
		metrics.AlertsStandingDigests.With(kind).Add(float64(n))
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
