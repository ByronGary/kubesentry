// Package incidents groups the critical and warning signals of one workload
// (request and memory spikes, restarts, OOM kills, Kubernetes events, alert
// episodes) into incidents, and attaches what changed around them (deploys,
// audit edits, CloudTrail changes, error-log bursts). An incident covers at
// most 24 hours; its log and event window is padded so logs written after the
// fact still land in it.
//
// Stdlib only. The engine runs on the replica holding the "incidents" lease;
// stores persist incidents, their signals and raw Kubernetes events.
package incidents

import (
	"context"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
)

// Severity uses the alerts' words; "caution" in the UI is Warning.
type Severity string

const (
	Warning  Severity = "warning"
	Critical Severity = "critical"
)

// Worse reports whether a is more severe than b.
func Worse(a, b Severity) bool { return a == Critical && b != Critical }

// Role says whether a signal can open an incident and set its severity
// (Trigger), or only attaches to one (Context).
type Role string

const (
	Trigger Role = "trigger"
	Context Role = "context"
)

// Signal types.
const (
	TypeRequestSpike     = "request-spike"
	TypeErrorRate        = "error-rate"
	TypeMemorySpike      = "memory-spike"
	TypeOOMKill          = "oom-kill"
	TypeRestart          = "restart"
	TypeCrashLoop        = "crashloop"
	TypeEviction         = "eviction"
	TypeKubeEvent        = "k8s-event"
	TypeAlert            = "alert"
	TypeDeploy           = "deploy"
	TypeScale            = "scale"
	TypeAuditChange      = "audit-change"
	TypeCloudTrailChange = "cloudtrail-change"
	TypeLogErrors        = "log-errors"
)

// Signal sources.
const (
	SourceView       = "view"       // diff of consecutive snapshot views
	SourceMetrics    = "metrics"    // Prometheus or CloudWatch metrics scan
	SourceEvents     = "events"     // Kubernetes Events
	SourceAlerts     = "alerts"     // alert finding episodes
	SourceAudit      = "audit"      // Kubernetes audit store
	SourceCloudTrail = "cloudtrail" // AWS CloudTrail
	SourceLogs       = "logs"       // container logs
)

// Subject is the workload root a signal or incident is about (Assoc.RootOf:
// a Job rolls up to its CronJob, a pod to its Deployment).
type Subject struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
}

// Signal is one observation.
type Signal struct {
	// ID is stable per source, so re-observing the same thing is idempotent.
	ID       string    `json:"id"`
	Type     string    `json:"type"`
	Source   string    `json:"source"`
	Role     Role      `json:"role"`
	Severity Severity  `json:"severity,omitempty"` // triggers only
	Start    time.Time `json:"start"`
	// End is nil while the condition lasts (or for point events).
	End     *time.Time `json:"end,omitempty"`
	Subject Subject    `json:"subject"`
	// Object is the concrete thing observed: a Pod, Service, Node, or an AWS
	// resource ("AWS::EC2::SecurityGroup/sg-…").
	Object    model.ObjectRef `json:"object"`
	Title     string          `json:"title"`
	Value     *float64        `json:"value,omitempty"`
	Baseline  *float64        `json:"baseline,omitempty"`
	Threshold *float64        `json:"threshold,omitempty"`
	Count     int             `json:"count,omitempty"`
	// Tags are the app/service tags of the subject when the signal was made.
	Tags map[string]string `json:"tags,omitempty"`
	// Attrs explain the signal (query, ratio, image diff, event reason):
	// at most MaxAttrs keys of at most MaxAttrLen bytes.
	Attrs map[string]string `json:"attrs,omitempty"`
}

// Limits on signal attributes and incident lists.
const (
	MaxAttrs           = 16
	MaxAttrLen         = 512
	MaxSignals         = 500 // per incident
	MaxListed          = 50  // services, pods, nodes per incident
	MaxRange           = 24 * time.Hour
	CoalesceWithin     = time.Minute
	DefaultQuiet       = 15 * time.Minute
	DefaultLookbehind  = 30 * time.Minute
	DefaultLogLead     = 5 * time.Minute
	DefaultLogLag      = 10 * time.Minute
	DefaultRetention   = 7 * 24 * time.Hour
	DefaultEventsKeep  = 48 * time.Hour
	DefaultBoardWindow = 24 * time.Hour
)

// State of an incident.
type State string

const (
	Open     State = "open"
	Resolved State = "resolved"
)

// Incident groups the signals of one subject.
type Incident struct {
	// ID sorts by start time and is derived from subject and start, so a new
	// lease holder rebuilds the same ID.
	ID           string     `json:"id"`
	Subject      Subject    `json:"subject"`
	Title        string     `json:"title"`
	Severity     Severity   `json:"severity"`     // worst active trigger
	PeakSeverity Severity   `json:"peakSeverity"` // never decreases
	State        State      `json:"state"`
	Start        time.Time  `json:"start"`
	LastSignal   time.Time  `json:"lastSignal"`
	End          *time.Time `json:"end,omitempty"`
	// Capped is set when the incident closed at MaxRange; Previous links a
	// continuation to the incident it continues.
	Capped     bool              `json:"capped,omitempty"`
	Previous   string            `json:"previous,omitempty"`
	Owner      string            `json:"owner,omitempty"`
	Production bool              `json:"production,omitempty"`
	Tags       map[string]string `json:"tags,omitempty"`
	Services   []string          `json:"services,omitempty"`
	Pods       []string          `json:"pods,omitempty"`
	Nodes      []string          `json:"nodes,omitempty"`
	Types      []string          `json:"types"`  // signal types present
	Counts     map[string]int    `json:"counts"` // signals per type
}

// Window is the padded range whose logs and events belong to the incident:
// [Start-lead, End+lag] (End is now while open), never longer than MaxRange.
func (in Incident) Window(lead, lag time.Duration, now time.Time) (from, to time.Time) {
	end := now
	if in.End != nil {
		end = *in.End
	}
	from, to = in.Start.Add(-lead), end.Add(lag)
	if to.After(now) {
		to = now
	}
	if to.Sub(from) > MaxRange {
		from = to.Add(-MaxRange)
	}
	return from, to
}

// Query selects incidents. Namespaces nil means all; an empty non-nil map
// means none (the caller sees nothing namespaced). ClusterScoped admits
// incidents without a namespace (node and cluster subjects).
type Query struct {
	From, To time.Time
	// Severity matches PeakSeverity (an incident that was ever critical stays
	// in a critical filter).
	Severity      Severity
	Types         []string
	State         State
	Namespaces    map[string]bool
	ClusterScoped bool
	Owner         string
	// App matches the reserved tag TagApp ("kubesentry.io/app"), the display
	// app chosen from the custom key, app.kubernetes.io/name, app, or the
	// workload name. Service matches the comma-separated "service" tag.
	App     string
	Service string
	Tags    map[string]string
	Limit   int
	// Before is the keyset cursor (start, id), newest first.
	Before *Cursor
}

// Cursor positions a newest-first incident listing.
type Cursor struct {
	Start time.Time
	ID    string
}

// Commit is one atomic write by the lease holder.
type Commit struct {
	Incidents []Incident
	// Signals to add or replace, keyed by incident ID.
	Signals map[string][]Signal
	// Checkpoints of the pollers (audit, CloudTrail), by source name.
	Checkpoints map[string][]byte
}

// Store persists incidents and their signals. The memory and Postgres
// implementations must behave the same (parity tests).
type Store interface {
	// LoadOpen returns open incidents with their signals, for a new lease holder.
	LoadOpen(ctx context.Context) ([]Incident, map[string][]Signal, error)
	Commit(ctx context.Context, c Commit) error
	Checkpoint(ctx context.Context, source string) ([]byte, error)
	List(ctx context.Context, q Query) ([]Incident, error)
	Get(ctx context.Context, id string) (Incident, []Signal, bool, error)
	Prune(ctx context.Context, before time.Time) (int, error)
}

// EventQuery selects stored Kubernetes events.
type EventQuery struct {
	Namespace string
	// Subject filters by resolved workload root (optional).
	Subject  *Subject
	Object   *model.ObjectRef
	From, To time.Time
	Limit    int
}

// EventStore keeps raw Kubernetes events for the incident window.
type EventStore interface {
	AddEvents(ctx context.Context, evs []StoredEvent) error
	Events(ctx context.Context, q EventQuery) ([]StoredEvent, error)
	PruneEvents(ctx context.Context, before time.Time) (int, error)
}

// StoredEvent is a Kubernetes event with the workload root it resolved to.
type StoredEvent struct {
	model.KubeEvent
	Subject *Subject `json:"subject,omitempty"`
}

// Board is what replicas serve without touching the store: the incidents of
// the last BoardWindow, refreshed by followers from the store.
type Board interface {
	// Snapshot returns the incidents (newest first) and a version that
	// changes whenever they do.
	Snapshot() ([]Incident, uint64)
	Signals(id string) ([]Signal, bool)
}
