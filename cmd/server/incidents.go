package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ByronGary/kubesentry/internal/alerts"
	"github.com/ByronGary/kubesentry/internal/api"
	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/aws/cloudtrail"
	"github.com/ByronGary/kubesentry/internal/aws/cwmetrics"
	"github.com/ByronGary/kubesentry/internal/cloudwatch"
	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/incidents"
	"github.com/ByronGary/kubesentry/internal/kube"
	"github.com/ByronGary/kubesentry/internal/metrics"
	"github.com/ByronGary/kubesentry/internal/model"
	"github.com/ByronGary/kubesentry/internal/pgstore"
	"github.com/ByronGary/kubesentry/internal/prom"
	"github.com/ByronGary/kubesentry/internal/snapshot"
)

// incidentsConfig is the incidents flags (-incidents, -incident-*,
// -cloudtrail*).
type incidentsConfig struct {
	enabled                                  bool
	interval, maxRange                       time.Duration
	retention, eventsRetention               time.Duration
	quiet, lookbehind, logLead, logLag       time.Duration
	namespaces                               *listValue
	includeSystem                            bool
	appLabel                                 string
	appLabels                                *listValue
	requestRatio, requestCritRatio           float64
	requestMinRPS                            float64
	errorRatio, errorCritRatio               float64
	memoryPct, memoryCritPct, memoryJumpRate float64
	memoryJumpMin                            sizeValue
	spikeRecent, spikeBaseline               time.Duration
	eventMinCount                            int
	requestSources                           *listValue
	requestProfilesFile                      string
	alb                                      bool
	eventNormalReasons                       *listValue
	logs, logsGroup, logsStreamPrefix        string
	logsMaxLines                             int
	logsMaxBytes                             sizeValue
	redactPatterns                           multiValue

	cloudtrail         string
	cloudtrailLogGroup string
	cloudtrailRegion   string
	cloudtrailQPS      float64
	cloudtrailStart    time.Duration
}

func (c *incidentsConfig) register(fs *flag.FlagSet, dur durFlag) {
	d := incidents.Options{}.WithDefaults()
	th := d.Thresholds
	c.namespaces, c.appLabels = newList(), newList()
	c.requestSources = newList("nginx", "app")
	c.eventNormalReasons = newList(kube.DefaultNormalReasons...)
	c.memoryJumpMin, c.logsMaxBytes = sizeValue(th.MemoryJumpMin), sizeValue(d.LogsMaxBytes)

	fs.BoolVar(&c.enabled, "incidents", false, "group critical and warning signals per workload into incidents (needs -cache; with more than one replica, -audit-store=postgres)")
	dur(&c.interval, "incident-interval", d.Interval, "how often the request and memory metrics are scanned")
	dur(&c.maxRange, "incident-max-range", d.MaxRange, "an incident longer than this closes (capped) and continues in a new one; at most 24h")
	dur(&c.retention, "incident-retention", d.Retention, "how long resolved incidents are kept")
	dur(&c.eventsRetention, "incident-events-retention", d.EventsRetention, "how long Kubernetes events are kept for incidents")
	dur(&c.quiet, "incident-quiet", d.Quiet, "an incident resolves once no trigger has been active this long")
	dur(&c.lookbehind, "incident-lookbehind", d.Lookbehind, "context (deploys, changes) this long before an incident starts attaches to it")
	dur(&c.logLead, "incident-log-lead", d.LogLead, "logs and events are read from this long before an incident starts")
	dur(&c.logLag, "incident-log-lag", d.LogLag, "logs and events are read until this long after an incident ends (logs are written after the fact)")
	fs.Var(c.namespaces, "incident-namespaces", "only these namespaces have incidents, comma-separated (default: all but the system namespaces)")
	fs.BoolVar(&c.includeSystem, "incident-include-system", false, "system namespaces have incidents too")
	fs.StringVar(&c.appLabel, "incident-app-label", "", "a custom label key that ties workloads into one app (tags incidents and relates them)")
	fs.Var(c.appLabels, "incident-app-labels", "replace the label keys incidents are tagged with, comma-separated (default: app.kubernetes.io/{name,instance,part-of,component}, app, k8s-app)")
	fs.Float64Var(&c.requestRatio, "incident-request-ratio", th.RequestRatio, "a request rate this many times its baseline is a warning spike")
	fs.Float64Var(&c.requestCritRatio, "incident-request-crit-ratio", th.RequestCritRatio, "a request rate this many times its baseline is a critical spike")
	fs.Float64Var(&c.requestMinRPS, "incident-request-min-rps", th.RequestMinRPS, "subjects below this many requests per second never spike")
	fs.Float64Var(&c.errorRatio, "incident-error-ratio", th.ErrorRatio, "a share of 5xx responses at or above this is a warning")
	fs.Float64Var(&c.errorCritRatio, "incident-error-crit-ratio", th.ErrorCritRatio, "a share of 5xx responses at or above this is critical")
	fs.Float64Var(&c.memoryPct, "incident-memory-limit-pct", th.MemoryPct, "memory at this percent of the container's limit is a warning spike")
	fs.Float64Var(&c.memoryCritPct, "incident-memory-crit-pct", th.MemoryCritPct, "memory at this percent of the container's limit is a critical spike")
	fs.Float64Var(&c.memoryJumpRate, "incident-memory-jump-ratio", th.MemoryJumpRatio, "without a limit, memory this many times the previous scan is a spike")
	fs.Var(&c.memoryJumpMin, "incident-memory-jump-min", "without a limit, a memory jump must also be at least this much (e.g. 128MiB)")
	dur(&c.spikeRecent, "incident-spike-recent", th.SpikeRecent, "the recent window a request rate is averaged over")
	dur(&c.spikeBaseline, "incident-spike-baseline", th.SpikeBaseline, "the baseline window a request rate is compared with (before the recent one)")
	fs.IntVar(&c.eventMinCount, "incident-event-min-count", th.EventMinCount, "BackOff, Unhealthy and the like open an incident at this many in 5 minutes")
	fs.Var(c.requestSources, "incident-request-sources", "built-in Prometheus request profiles to read, comma-separated ("+strings.Join(prom.BuiltinRequestProfileNames(), ", ")+"); empty for none")
	fs.StringVar(&c.requestProfilesFile, "incident-request-profiles-file", "", "JSON file of request profiles {name, metric, namespaceLabel, serviceLabel|podLabel, statusLabel, errorRegex}, read besides the built-ins named")
	fs.BoolVar(&c.alb, "incident-alb", false, "read ALB request counts and 5xx from CloudWatch for the target groups of TargetGroupBindings")
	fs.Var(c.eventNormalReasons, "incident-event-normal-reasons", "Normal Kubernetes event reasons kept besides every Warning, comma-separated; empty for Warnings only")
	fs.StringVar(&c.logs, "incident-logs", "auto", "where incident logs come from: auto (CloudWatch first when -incident-logs-group is set, then pods/log), kubernetes, cloudwatch or off")
	fs.StringVar(&c.logsGroup, "incident-logs-group", "", "CloudWatch Logs group of container logs (default with -incident-logs=cloudwatch: /aws/containerinsights/<cluster-name>/application)")
	fs.StringVar(&c.logsStreamPrefix, "incident-logs-stream-prefix", "", "log stream name prefix template with {namespace} and {pod}, when streams are named by pod (default: a filter pattern on the kubernetes fields)")
	fs.IntVar(&c.logsMaxLines, "incident-logs-max-lines", d.LogsMaxLines, "lines one log read returns at most")
	fs.Var(&c.logsMaxBytes, "incident-logs-max-bytes", "bytes of text one log read returns at most (e.g. 1MiB)")
	fs.Var(&c.redactPatterns, "incident-redact-patterns", "a regular expression whose matches are redacted from logs, events, CloudTrail records and bundles, besides the built-in secrets; repeat for more")
	fs.StringVar(&c.cloudtrail, "cloudtrail", "off", "attach AWS changes to incidents: off, lookup (CloudTrail event history) or logs (a trail delivered to -cloudtrail-log-group)")
	fs.StringVar(&c.cloudtrailLogGroup, "cloudtrail-log-group", "", "with -cloudtrail=logs: the CloudWatch Logs group the trail delivers to")
	fs.StringVar(&c.cloudtrailRegion, "cloudtrail-region", "", "region whose CloudTrail is read (default -aws-region)")
	fs.Float64Var(&c.cloudtrailQPS, "cloudtrail-qps", cloudtrail.DefaultQPS, "LookupEvents calls per second (the account allows about 2, shared)")
	dur(&c.cloudtrailStart, "cloudtrail-start", d.CloudTrailStart, "how far back the first CloudTrail read goes")
}

// validLabelKeyOrPrefix accepts a label key, or "prefix*".
func validLabelKeyOrPrefix(k string) bool {
	if p, ok := strings.CutSuffix(k, "*"); ok {
		return p != "" && !strings.Contains(p, "*")
	}
	return detectors.ValidLabelKey(k)
}

func (c *incidentsConfig) validate(cfg *config) error {
	if !c.enabled {
		if c.cloudtrail != "off" {
			return errors.New("-cloudtrail attaches AWS changes to incidents: it needs -incidents")
		}
		return nil
	}
	switch {
	case !cfg.cache:
		return errors.New("-incidents follows the informer cache's views: it needs -cache=true")
	case c.maxRange <= 0 || c.maxRange > incidents.MaxRange:
		return fmt.Errorf("-incident-max-range must be between 0 and %s", incidents.MaxRange)
	case c.interval < 10*time.Second:
		return errors.New("-incident-interval must be at least 10s")
	case c.retention < incidents.DefaultBoardWindow:
		return errors.New("-incident-retention must be at least 24h: the board shows a day")
	case c.eventsRetention < time.Hour:
		return errors.New("-incident-events-retention must be at least 1h")
	case c.quiet <= 0 || c.lookbehind < 0 || c.logLead < 0 || c.logLag < 0:
		return errors.New("-incident-quiet must be positive; -incident-lookbehind, -incident-log-lead and -incident-log-lag not negative")
	case c.spikeRecent <= 0 || c.spikeBaseline <= c.spikeRecent:
		return errors.New("-incident-spike-baseline must be longer than -incident-spike-recent, which must be positive")
	case c.requestRatio <= 1 || c.requestMinRPS < 0 || c.errorRatio <= 0 || c.errorCritRatio > 1 || c.memoryPct <= 0 || c.memoryCritPct > 100 ||
		c.memoryJumpRate <= 1 || c.memoryJumpMin < 0:
		return errors.New("incident thresholds: request ratios above 1, error ratios in (0, 1], memory percents in (0, 100], the memory jump ratio above 1")
	case c.eventMinCount < 1:
		return errors.New("-incident-event-min-count must be at least 1")
	case c.logsMaxLines < 1 || c.logsMaxLines > 10000:
		return errors.New("-incident-logs-max-lines must be between 1 and 10000")
	case c.logsMaxBytes < 1<<10 || c.logsMaxBytes > 16<<20:
		return errors.New("-incident-logs-max-bytes must be between 1KiB and 16MiB")
	case c.cloudtrailQPS <= 0 || c.cloudtrailQPS > 10:
		return errors.New("-cloudtrail-qps must be above 0 and at most 10")
	case c.cloudtrailStart <= 0 || c.cloudtrailStart > cloudtrail.MaxLookback:
		return fmt.Errorf("-cloudtrail-start must be between 0 and %s", cloudtrail.MaxLookback)
	}
	if c.appLabel != "" && !detectors.ValidLabelKey(c.appLabel) {
		return fmt.Errorf("-incident-app-label %q: want a label key such as app.kubernetes.io/name", c.appLabel)
	}
	for _, k := range c.appLabels.items {
		if !validLabelKeyOrPrefix(k) {
			return fmt.Errorf("-incident-app-labels: %q is not a label key (or prefix*)", k)
		}
	}
	for _, ns := range c.namespaces.items {
		if !dnsLabel.MatchString(ns) || len(ns) > 63 {
			return fmt.Errorf("-incident-namespaces: %q is not a namespace name", ns)
		}
	}
	switch c.logs {
	case "auto", "kubernetes", "off":
	case "cloudwatch":
		if c.logsGroup == "" && cfg.clusterName == "" {
			return errors.New("-incident-logs=cloudwatch needs -incident-logs-group or -cluster-name")
		}
	default:
		return fmt.Errorf("-incident-logs %q: use auto, kubernetes, cloudwatch or off", c.logs)
	}
	if c.logsStreamPrefix != "" && !strings.Contains(c.logsStreamPrefix, "{pod}") && !strings.Contains(c.logsStreamPrefix, "{namespace}") {
		return errors.New("-incident-logs-stream-prefix must name {namespace} or {pod}")
	}
	switch c.cloudtrail {
	case "off", cloudtrail.ModeLookup:
		if c.cloudtrailLogGroup != "" {
			return errors.New("-cloudtrail-log-group is read with -cloudtrail=logs")
		}
	case cloudtrail.ModeLogs:
		if c.cloudtrailLogGroup == "" {
			return errors.New("-cloudtrail=logs needs -cloudtrail-log-group")
		}
	default:
		return fmt.Errorf("-cloudtrail %q: use off, lookup or logs", c.cloudtrail)
	}
	if _, err := incidents.NewRedactor(c.redactPatterns); err != nil {
		return fmt.Errorf("-incident-redact-patterns: %w", err)
	}
	return c.options(cfg).Validate()
}

// appLabelKeys are the workload labels the informers keep besides their
// defaults: the custom app label and -incident-app-labels.
func (c *incidentsConfig) appLabelKeys() []string {
	if !c.enabled {
		return nil
	}
	var out []string
	if c.appLabel != "" {
		out = append(out, c.appLabel)
	}
	return append(out, c.appLabels.items...)
}

// normalReasons is -incident-event-normal-reasons: nil keeps the default,
// an empty flag keeps Warnings only.
func (c *incidentsConfig) normalReasons() []string {
	if c.eventNormalReasons.set && len(c.eventNormalReasons.items) == 0 {
		return []string{}
	}
	return c.eventNormalReasons.items
}

// options maps the flags onto the engine's options.
func (c *incidentsConfig) options(cfg *config) incidents.Options {
	o := incidents.Options{
		Quiet: c.quiet, Lookbehind: c.lookbehind, LogLead: c.logLead, LogLag: c.logLag, MaxRange: c.maxRange,
		Namespaces: c.namespaces.items, IncludeSystem: c.includeSystem, AppLabel: c.appLabel,
		DefaultOwner: strings.TrimSpace(cfg.alerts.defaultOwner), Cluster: cfg.clusterName,
		Interval: c.interval, Retention: c.retention, EventsRetention: c.eventsRetention, CloudTrailStart: c.cloudtrailStart,
		EventNormalReasons: c.normalReasons(), LogsMaxLines: c.logsMaxLines, LogsMaxBytes: int64(c.logsMaxBytes),
		RedactPatterns: c.redactPatterns,
		Thresholds: incidents.Thresholds{
			RequestRatio: c.requestRatio, RequestCritRatio: c.requestCritRatio, RequestMinRPS: c.requestMinRPS,
			ErrorRatio: c.errorRatio, ErrorCritRatio: c.errorCritRatio,
			MemoryPct: c.memoryPct, MemoryCritPct: c.memoryCritPct, MemoryJumpRatio: c.memoryJumpRate, MemoryJumpMin: float64(c.memoryJumpMin),
			SpikeRecent: c.spikeRecent, SpikeBaseline: c.spikeBaseline, EventMinCount: c.eventMinCount,
		},
	}
	if c.appLabels.set {
		for _, k := range c.appLabels.items {
			if !strings.HasSuffix(k, "*") {
				o.TagKeys = append(o.TagKeys, k) // the engine tags by exact keys
			}
		}
	}
	return o
}

// incidentsSetup is what the incidents runner is built from.
type incidentsSetup struct {
	cfg     *config
	current func() *snapshot.View
	kick    <-chan struct{}
	clients *kube.Clients
	cache   *kube.Cache
	prom    *promSource
	pg      *pgstore.Store // nil: the memory stores, this replica alone
	audit   audit.Store    // nil without audit
	alerts  *alerts.Runner // nil when alerting is off
	cw      *cwLogs
}

// start builds the runner and its sources and starts it; it serves the
// incidents routes, /info's incidents and the Overview's.
func (s incidentsSetup) start(ctx context.Context, srv *api.Server) (*incidents.Runner, error) {
	c := s.cfg.incidents
	rc := incidents.Config{View: s.current, Kick: s.kick, Options: c.options(s.cfg), Logger: slog.Default(), Hooks: incidentHooks()}
	var listStore incidents.Store
	if s.pg != nil {
		listStore = s.pg.Incidents()
		rc.Store, rc.Events, rc.Elect = listStore, s.pg.KubeEvents(), s.pg.IncidentElector()
	} else {
		listStore = incidents.NewMemoryStore()
		rc.Store, rc.Events = listStore, incidents.NewMemoryEventStore()
	}

	var reqs []prom.RequestProfile
	if len(c.requestSources.items) > 0 || c.requestProfilesFile != "" {
		var file []prom.RequestProfile
		if c.requestProfilesFile != "" {
			var err error
			if file, err = prom.LoadRequestProfiles(c.requestProfilesFile); err != nil {
				return nil, fmt.Errorf("-incident-request-profiles-file: %w", err)
			}
		}
		var err error
		if reqs, err = prom.SelectRequestProfiles(c.requestSources.items, file); err != nil {
			return nil, fmt.Errorf("-incident-request-sources: %w", err)
		}
	}
	var alb *cwmetrics.Source
	if c.alb {
		var err error
		alb, err = cwmetrics.New(ctx, cwmetrics.Options{Region: s.cfg.awsRegion, Targets: func() []cwmetrics.Target {
			if v := s.current(); v != nil {
				return cwmetrics.TargetsFrom(v.Inv.TargetGroupBindings)
			}
			return nil
		}})
		if err != nil {
			return nil, fmt.Errorf("-incident-alb: %w", err)
		}
	}
	hasProm := s.cfg.promURL != "" || s.cfg.promAutodiscover
	if hasProm {
		for _, p := range reqs {
			rc.Rates = append(rc.Rates, &promRates{p: s.prom, profile: p})
		}
		rc.Memory = promMemory{s.prom}
	}
	if alb != nil {
		rc.Rates = append(rc.Rates, alb)
	}
	if hasProm || alb != nil {
		ss := &seriesSource{prom: s.prom, profiles: reqs, alb: alb}
		if !hasProm {
			ss.prom = nil
		}
		rc.Series = ss
	}

	// The watcher is also the events probe. A forbidden watch returns at
	// once; the runner retries it, waiting up to 5 minutes between tries.
	rc.EventSource = kube.NewEventWatcher(s.clients, kube.EventWatcherOptions{NormalReasons: c.normalReasons()})

	if c.logs == "cloudwatch" || (c.logs == "auto" && c.logsGroup != "") {
		logsAPI, err := s.cw.client(ctx, "")
		if err != nil {
			return nil, fmt.Errorf("incident logs: %w", err)
		}
		group := c.logsGroup
		if group == "" {
			group = cloudwatch.DefaultApplicationLogGroup(s.cfg.clusterName)
		}
		rc.Logs = append(rc.Logs, &cloudwatch.LogLookup{API: logsAPI, LogGroup: group, StreamPrefix: c.logsStreamPrefix,
			MaxLines: c.logsMaxLines, MaxBytes: int64(c.logsMaxBytes), Pacer: s.cw.pacer})
	}
	if c.logs == "kubernetes" || c.logs == "auto" {
		var pods kube.PodGetter
		if s.cache != nil {
			pods = s.cache
		}
		rc.Logs = append(rc.Logs, kube.NewPodLogs(s.clients, pods, kube.PodLogsOptions{MaxLines: c.logsMaxLines, MaxBytes: int64(c.logsMaxBytes)}))
	}

	countCT := func(result string, n int) { metrics.CloudTrailEvents.With(result).Add(float64(n)) }
	region := c.cloudtrailRegion
	if region == "" {
		region = s.cfg.awsRegion
	}
	switch c.cloudtrail {
	case cloudtrail.ModeLookup:
		src, err := cloudtrail.NewLookup(ctx, cloudtrail.LookupOptions{Region: region, QPS: c.cloudtrailQPS, Start: c.cloudtrailStart, OnResult: countCT})
		if err != nil {
			return nil, fmt.Errorf("-cloudtrail=lookup: %w", err)
		}
		rc.CloudTrail = src
	case cloudtrail.ModeLogs:
		logsAPI, err := s.cw.client(ctx, c.cloudtrailRegion)
		if err != nil {
			return nil, fmt.Errorf("-cloudtrail=logs: %w", err)
		}
		src, err := cloudtrail.NewLogs(&cloudwatch.RawReader{API: logsAPI, LogGroup: c.cloudtrailLogGroup, Pacer: s.cw.pacer},
			cloudtrail.LogsOptions{Start: c.cloudtrailStart, OnResult: countCT})
		if err != nil {
			return nil, fmt.Errorf("-cloudtrail=logs: %w", err)
		}
		rc.CloudTrail = src
	}
	if s.alerts != nil {
		ar := s.alerts
		rc.Alerts = func() []alerts.Finding {
			if b := ar.Board(); b != nil {
				return b.Findings
			}
			return nil
		}
	}
	if s.audit != nil {
		rc.Audit = s.audit
	}

	r, err := incidents.NewRunner(rc)
	if err != nil {
		return nil, err
	}
	if s.alerts != nil {
		// The alerts runner started first; its alerts link to their
		// incidents (incident_url) from the next evaluation on.
		s.alerts.SetIncidentLookup(incidentLookup(r))
	}
	incidentMetrics(r)
	observeIncidentsLeader(false)
	if rc.CloudTrail != nil {
		dependencyUp("cloudtrail", func() error {
			if st := r.Sources()["cloudtrail"]; strings.HasPrefix(st, "error") {
				return errors.New(st)
			}
			return nil
		})
	}
	go r.Run(ctx)
	srv.Incidents, srv.IncidentStore = r, listStore
	store := "memory (this replica alone; incidents are lost on restart)"
	if s.pg != nil {
		store = "postgres (the replica holding the incidents lock runs the engine)"
	}
	var logs []string
	for _, l := range rc.Logs {
		logs = append(logs, l.Name())
	}
	var rates []string
	for _, rs := range rc.Rates {
		rates = append(rates, rs.Name())
	}
	slog.Info("incidents on", "store", store, "requestSources", rates, "logs", logs, "cloudtrail", c.cloudtrail,
		"maxRange", c.maxRange, "quiet", c.quiet, "logLead", c.logLead, "logLag", c.logLag)
	return r, nil
}

// incidentHooks feed the incidents metrics.
func incidentHooks() incidents.Hooks {
	return incidents.Hooks{
		OnLeader: observeIncidentsLeader,
		OnCommit: func(open map[incidents.Severity]int, _ time.Duration, err error) {
			if err != nil {
				return
			}
			for _, sev := range []incidents.Severity{incidents.Warning, incidents.Critical} {
				metrics.Incidents.With(string(sev)).Set(float64(open[sev]))
			}
		},
		OnSignals: func(typ string, n int) { metrics.IncidentSignals.With(typ).Add(float64(n)) },
		OnEvents:  func(result string, n int) { metrics.KubeEvents.With(result).Add(float64(n)) },
		// The source counts what it read ("fetched", "duplicate", ...); the
		// engine adds what matched a related resource and failed polls.
		OnCloudTrail: func(result string, n int) {
			if result != "read" {
				metrics.CloudTrailEvents.With(result).Add(float64(n))
			}
		},
		OnLogFetch: func(source, result string) { metrics.IncidentLogFetches.With(source, result).Inc() },
	}
}

// incidentLookup finds the incident a finding's current episode joined, on
// this replica's incidents board (every replica keeps one).
func incidentLookup(r *incidents.Runner) func(*alerts.Finding) string {
	return func(f *alerts.Finding) string {
		id, _ := r.IncidentOfSignal(incidents.EpisodeID(f))
		return id
	}
}

// incidentMetrics exports kubesentry_incident_source_up for each source the
// runner reports (the set is fixed when it is made), and
// kubesentry_incidents_leader.
func incidentMetrics(r *incidents.Runner) {
	for k := range r.Sources() {
		metrics.IncidentSourceUp.With(k).SetOptionalFunc(func() (float64, bool) { return sourceUp(r.Source(k)) })
	}
	metrics.IncidentsLeader.SetFunc(func() float64 {
		if r.Leader() {
			return 1
		}
		return 0
	})
}

// sourceUp is a source state as kubesentry_incident_source_up: 1 while ok,
// 0 while failing, no sample while absent.
func sourceUp(state string) (float64, bool) {
	switch state {
	case "ok":
		return 1, true
	case "absent", "":
		return 0, false
	}
	return 0, true
}

// observeIncidentsLeader zeroes kubesentry_incidents on a replica that does
// not run the engine, so sums across replicas stay right.
func observeIncidentsLeader(on bool) {
	if on {
		return
	}
	for _, sev := range []incidents.Severity{incidents.Warning, incidents.Critical} {
		metrics.Incidents.With(string(sev)).Set(0)
	}
}

// fanout signals each subscriber after every view build; a pending signal
// stands for many builds. The alerts and the incidents each subscribe.
type fanout struct {
	mu   sync.Mutex
	subs []chan struct{}
}

func (f *fanout) subscribe() <-chan struct{} {
	ch := make(chan struct{}, 1)
	f.mu.Lock()
	f.subs = append(f.subs, ch)
	f.mu.Unlock()
	return ch
}

func (f *fanout) notify() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, ch := range f.subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// promRates reads one request profile from whichever Prometheus is current
// (it may be discovered after startup).
type promRates struct {
	p       *promSource
	profile prom.RequestProfile

	mu     sync.Mutex
	client *prom.Client
	src    *prom.RequestSource
}

var _ incidents.RateSource = (*promRates)(nil)

func (r *promRates) Name() string { return r.profile.Name }

func (r *promRates) source() (*prom.RequestSource, error) {
	st, err := r.p.state()
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.client != st.client {
		src, err := st.client.RequestSource(r.profile)
		if err != nil {
			return nil, err
		}
		r.client, r.src = st.client, src
	}
	return r.src, nil
}

func (r *promRates) Rates(ctx context.Context, at time.Time, window, offset time.Duration, namespaces []string) ([]model.RateSample, error) {
	src, err := r.source()
	if err != nil {
		return nil, err
	}
	return src.Rates(ctx, at, window, offset, namespaces)
}

func (r *promRates) Probe(ctx context.Context) string {
	src, err := r.source()
	if errors.Is(err, errNoPrometheus) {
		return prom.ProbeAbsent
	}
	if err != nil {
		return "error: " + err.Error()
	}
	return src.Probe(ctx)
}

// promMemory reads container memory from whichever Prometheus is current.
type promMemory struct{ p *promSource }

func (m promMemory) MemoryUsage(ctx context.Context, at time.Time, namespaces []string) ([]model.MemorySample, error) {
	st, err := m.p.state()
	if err != nil {
		return nil, err
	}
	return st.client.MemoryUsage(ctx, at, namespaces)
}

// seriesSource draws an incident's charts from the current Prometheus (memory
// and the request profiles) and the ALB metrics. Node incidents have no
// namespace, and no charts.
type seriesSource struct {
	prom     *promSource // nil: no Prometheus
	profiles []prom.RequestProfile
	alb      *cwmetrics.Source
}

func (s *seriesSource) SubjectSeries(ctx context.Context, q incidents.SeriesQuery) ([]incidents.Series, error) {
	if q.Namespace == "" {
		return nil, nil
	}
	var out []incidents.Series
	var errs []error
	if s.prom != nil {
		if st, err := s.prom.state(); err != nil {
			errs = append(errs, err)
		} else {
			reqs, err := st.client.RequestSources(s.profiles)
			if err != nil {
				return nil, err
			}
			got, err := prom.NewSeriesSource(st.client, reqs...).SubjectSeries(ctx, q)
			out = append(out, got...)
			if err != nil {
				errs = append(errs, err)
			}
		}
	}
	if s.alb != nil {
		got, err := s.alb.SubjectSeries(ctx, q)
		out = append(out, got...)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return out, errors.Join(errs...)
}

// dnsLabel matches a namespace name (DNS-1123 label).
var dnsLabel = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

// cwLogs hands out CloudWatch Logs clients, one per region, and the pacer
// every CloudWatch Logs reader shares (the audit reader, container logs, a
// CloudTrail trail), so throttling slows them together.
type cwLogs struct {
	region, endpoint string
	pacer            *cloudwatch.Pacer

	mu      sync.Mutex
	clients map[string]cloudwatch.FilterAPI
}

func newCWLogs(region, endpoint string) *cwLogs {
	return &cwLogs{region: region, endpoint: endpoint, pacer: cloudwatch.NewPacer(0), clients: map[string]cloudwatch.FilterAPI{}}
}

// client returns the client for region ("" for -aws-region).
func (c *cwLogs) client(ctx context.Context, region string) (cloudwatch.FilterAPI, error) {
	if region == "" {
		region = c.region
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if api, ok := c.clients[region]; ok {
		return api, nil
	}
	api, err := cloudwatch.New(ctx, region, c.endpoint)
	if err != nil {
		return nil, err
	}
	c.clients[region] = api
	return api, nil
}

// sizeValue is a flag.Value for byte sizes: "128MiB", "1GiB", "1048576".
type sizeValue int64

func (v *sizeValue) String() string {
	if v == nil {
		return ""
	}
	n := int64(*v)
	for _, u := range []struct {
		suffix string
		size   int64
	}{{"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}} {
		if n >= u.size && n%u.size == 0 {
			return strconv.FormatInt(n/u.size, 10) + u.suffix
		}
	}
	return strconv.FormatInt(n, 10)
}

func (v *sizeValue) Set(s string) error {
	if strings.HasSuffix(strings.TrimSpace(s), "/h") {
		return fmt.Errorf("invalid size %q: use e.g. 128MiB", s)
	}
	f, err := parseBytesPerHour(s)
	if err != nil {
		return fmt.Errorf("invalid size %q: use e.g. 128MiB or 1048576", s)
	}
	*v = sizeValue(f)
	return nil
}

// multiValue is a repeatable string flag.
type multiValue []string

func (m *multiValue) String() string {
	if m == nil {
		return ""
	}
	return strings.Join(*m, " ")
}

func (m *multiValue) Set(s string) error {
	*m = append(*m, s)
	return nil
}
