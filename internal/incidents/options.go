package incidents

import (
	"fmt"
	"time"
)

// Subject kinds besides the workload kinds (Deployment, StatefulSet, ...,
// "Pod" for bare and static pods). A Node subject has incidents of its own
// (kernel OOM kills, evictions reported on the node). Namespace and Cluster
// subjects only carry context: a namespace-level change (a ConfigMap, Secret
// or RoleBinding edit) attaches to every incident in that namespace, a
// cluster-level one (an EKS add-on or node group update) to every incident.
const (
	KindNode      = "Node"
	KindNamespace = "Namespace"
	KindCluster   = "Cluster"
)

// Reserved tag keys. The others are the label keys of TagKeys (and the
// custom key).
const (
	// TagApp is the display app: the first of the custom key,
	// app.kubernetes.io/name, app, or the workload's name. Query.App matches it.
	TagApp = "kubesentry.io/app"
	// TagService and TagIngress list the subject's Services and the Ingresses
	// routing to them, comma-separated and sorted.
	TagService = "service"
	TagIngress = "ingress"
)

// DefaultTagKeys are the labels incidents correlate on.
var DefaultTagKeys = []string{
	"app.kubernetes.io/name", "app.kubernetes.io/instance", "app.kubernetes.io/part-of", "app.kubernetes.io/component",
	"app", "k8s-app",
}

// Options configures the engine, the producers and the runner. Zero values
// take the defaults shown.
type Options struct {
	// Quiet: an incident resolves once no trigger is active and the last one
	// ended this long ago. DefaultQuiet.
	Quiet time.Duration
	// Lookbehind: context signals up to this long before an incident's start
	// attach to it. DefaultLookbehind.
	Lookbehind time.Duration
	// LogLead and LogLag pad the window logs and events are read in, and
	// LogLag also how long after its end a resolved incident still takes
	// context signals. DefaultLogLead, DefaultLogLag.
	LogLead, LogLag time.Duration
	// MaxRange caps an incident: it closes (capped) and continues in a new
	// one. MaxRange is also the most allowed; Validate refuses more.
	MaxRange time.Duration
	// LateWindow is how long after its padded window ends a resolved incident
	// is kept in memory to take late context (CloudTrail delivers events up
	// to about 15 minutes late). Default 1h.
	LateWindow time.Duration
	// BoardWindow: resolved incidents stay on the board this long after they
	// end. DefaultBoardWindow.
	BoardWindow time.Duration
	// StaleAfter ends a condition (a spike, a crash loop, an alert episode)
	// whose producer has not reported it for this long, at the last report:
	// a producer that stopped cannot keep an incident open. Default 30m.
	StaleAfter time.Duration
	// MaxSignals per incident (MaxSignals); MaxPending context signals wait
	// for an incident to open (10,000).
	MaxSignals int
	MaxPending int

	// Namespaces limits incidents to these namespaces (nil: all);
	// IncludeSystem admits the policy's system namespaces too. Node and
	// cluster subjects are always admitted.
	Namespaces    []string
	IncludeSystem bool
	// AppLabel is the custom tag key (-incident-app-label); TagKeys replaces
	// DefaultTagKeys when set (-incident-app-labels).
	AppLabel string
	TagKeys  []string
	// DefaultOwner owns incidents whose namespace names no owner (and node
	// and cluster ones). Empty leaves Owner empty.
	DefaultOwner string
	// Cluster names the cluster in bundles and matches EKS CloudTrail
	// events; the view's ClusterInfo.Name is used when empty.
	Cluster string

	Thresholds Thresholds

	// Interval is how often the metrics scan runs (1m); AlertsEvery the alert
	// episodes (15s); AuditEvery the audit poll (1m); CloudTrailEvery the
	// CloudTrail poll (2m); LogsEvery the error-log counts (2m).
	Interval, AlertsEvery, AuditEvery, CloudTrailEvery, LogsEvery time.Duration
	// CommitEvery batches commits (5s; a state change commits at once);
	// Refresh is how often a replica that does not lead re-reads the board
	// (15s); Retry how often it tries for the lease (30s); ProbeEvery how
	// often sources are probed (10m).
	CommitEvery, Refresh, Retry, ProbeEvery time.Duration
	// Retention keeps resolved incidents (DefaultRetention); EventsRetention
	// keeps Kubernetes events (DefaultEventsKeep).
	Retention, EventsRetention time.Duration
	// CloudTrailStart is how far back the first CloudTrail poll reads (1h).
	CloudTrailStart time.Duration
	// EventNormalReasons are Normal event reasons kept as context
	// (SuccessfulRescale); other Normal events are dropped.
	EventNormalReasons []string
	// LogsMaxLines and LogsMaxBytes cap one log read (2,000 lines, 1 MiB).
	LogsMaxLines int
	LogsMaxBytes int64
	// RedactPatterns are extra regular expressions whose matches are
	// redacted from logs, event messages, CloudTrail records and bundles.
	RedactPatterns []string
	// LogErrorsMax is how many open incidents the error-log counter looks
	// at per run (10).
	LogErrorsMax int

	// Now is the clock; default time.Now.
	Now func() time.Time
}

// Thresholds are the signal rules. Zero values take the defaults shown.
type Thresholds struct {
	RequestRatio     float64 // 2: a warning request spike against the baseline
	RequestCritRatio float64 // 4
	RequestMinRPS    float64 // 1: quieter subjects never spike
	ErrorRatio       float64 // 0.05: a warning 5xx share
	ErrorCritRatio   float64 // 0.2
	MemoryPct        float64 // 85: a warning share of the memory limit, in percent
	MemoryCritPct    float64 // 95
	MemoryJumpRatio  float64 // 1.5: without a limit, a jump against the previous scan
	MemoryJumpMin    float64 // 128 MiB, in bytes
	// SpikeRecent and SpikeBaseline are the windows compared (5m, 1h; the
	// baseline is offset by SpikeRecent).
	SpikeRecent, SpikeBaseline time.Duration
	// SpikeEnd: a spike ends after EndScans scans below EndFraction times its
	// threshold (0.8, 2).
	EndFraction float64
	EndScans    int
	// EventMinCount: BackOff, Unhealthy and the like trigger at this many in
	// EventWindow (3 in 5m).
	EventMinCount int
	EventWindow   time.Duration
	// RestartWarn and RestartCrit: restarts of one pod within Quiet; zero uses
	// the view's policy (-restart-warn, -restart-crit).
	RestartWarn, RestartCrit int32
	// LogBurstRatio and LogBurstMin: an error-log burst is at least this many
	// times the rate before the incident, and at least LogBurstMin lines per
	// minute (3, 5).
	LogBurstRatio float64
	LogBurstMin   float64
}

func (o *Options) defaults() {
	setDur := func(d *time.Duration, def time.Duration) {
		if *d <= 0 {
			*d = def
		}
	}
	setDur(&o.Quiet, DefaultQuiet)
	setDur(&o.Lookbehind, DefaultLookbehind)
	setDur(&o.LogLead, DefaultLogLead)
	setDur(&o.LogLag, DefaultLogLag)
	setDur(&o.MaxRange, MaxRange)
	setDur(&o.LateWindow, time.Hour)
	setDur(&o.BoardWindow, DefaultBoardWindow)
	setDur(&o.StaleAfter, 30*time.Minute)
	setDur(&o.Interval, time.Minute)
	setDur(&o.AlertsEvery, 15*time.Second)
	setDur(&o.AuditEvery, time.Minute)
	setDur(&o.CloudTrailEvery, 2*time.Minute)
	setDur(&o.LogsEvery, 2*time.Minute)
	setDur(&o.CommitEvery, 5*time.Second)
	setDur(&o.Refresh, 15*time.Second)
	setDur(&o.Retry, 30*time.Second)
	setDur(&o.ProbeEvery, 10*time.Minute)
	setDur(&o.Retention, DefaultRetention)
	setDur(&o.EventsRetention, DefaultEventsKeep)
	setDur(&o.CloudTrailStart, time.Hour)
	if o.MaxSignals <= 0 {
		o.MaxSignals = MaxSignals
	}
	if o.MaxPending <= 0 {
		o.MaxPending = 10_000
	}
	if o.EventNormalReasons == nil {
		o.EventNormalReasons = []string{"SuccessfulRescale"}
	}
	if o.LogsMaxLines <= 0 {
		o.LogsMaxLines = 2000
	}
	if o.LogsMaxBytes <= 0 {
		o.LogsMaxBytes = 1 << 20
	}
	if o.LogErrorsMax <= 0 {
		o.LogErrorsMax = 10
	}
	if len(o.TagKeys) == 0 {
		o.TagKeys = DefaultTagKeys
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	t := &o.Thresholds
	setF := func(f *float64, def float64) {
		if *f <= 0 {
			*f = def
		}
	}
	setF(&t.RequestRatio, 2)
	setF(&t.RequestCritRatio, 4)
	setF(&t.RequestMinRPS, 1)
	setF(&t.ErrorRatio, 0.05)
	setF(&t.ErrorCritRatio, 0.2)
	setF(&t.MemoryPct, 85)
	setF(&t.MemoryCritPct, 95)
	setF(&t.MemoryJumpRatio, 1.5)
	setF(&t.MemoryJumpMin, 128<<20)
	setF(&t.EndFraction, 0.8)
	setF(&t.LogBurstRatio, 3)
	setF(&t.LogBurstMin, 5)
	setDur(&t.SpikeRecent, 5*time.Minute)
	setDur(&t.SpikeBaseline, time.Hour)
	setDur(&t.EventWindow, 5*time.Minute)
	if t.EndScans <= 0 {
		t.EndScans = 2
	}
	if t.EventMinCount <= 0 {
		t.EventMinCount = 3
	}
}

// WithDefaults returns o with every zero value replaced by its default.
func (o Options) WithDefaults() Options {
	o.defaults()
	return o
}

// Validate refuses options the incidents cannot honour.
func (o Options) Validate() error {
	if o.MaxRange > MaxRange {
		return fmt.Errorf("incidents: max range %s is more than %s", o.MaxRange, MaxRange)
	}
	t := o.WithDefaults().Thresholds
	if t.RequestCritRatio < t.RequestRatio {
		return fmt.Errorf("incidents: request critical ratio %g is below the warning ratio %g", t.RequestCritRatio, t.RequestRatio)
	}
	if t.ErrorCritRatio < t.ErrorRatio {
		return fmt.Errorf("incidents: error critical ratio %g is below the warning ratio %g", t.ErrorCritRatio, t.ErrorRatio)
	}
	if t.MemoryCritPct < t.MemoryPct {
		return fmt.Errorf("incidents: memory critical percent %g is below the warning percent %g", t.MemoryCritPct, t.MemoryPct)
	}
	if t.EndFraction >= 1 {
		return fmt.Errorf("incidents: spike end fraction %g must be below 1", t.EndFraction)
	}
	if _, err := NewRedactor(o.RedactPatterns); err != nil {
		return err
	}
	return nil
}
