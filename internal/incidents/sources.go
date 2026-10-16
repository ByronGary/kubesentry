package incidents

import (
	"context"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
)

// The engine reads its inputs through these interfaces. Implementations live
// where their dependencies are allowed: Prometheus in internal/prom, CloudWatch
// in internal/cloudwatch and internal/aws/**, Kubernetes in internal/kube.
// cmd/server wires them; tests use fakes.

// RateSource reports request rates. Implementations: Prometheus request
// profiles (nginx, app) and the ALB CloudWatch metrics.
type RateSource interface {
	// Name is the source name used in RateSample.Source and /info ("nginx", "app", "alb").
	Name() string
	// Rates returns the average rate over [at-offset-window, at-offset],
	// for subjects in the given namespaces (nil: all non-excluded).
	Rates(ctx context.Context, at time.Time, window, offset time.Duration, namespaces []string) ([]model.RateSample, error)
	// Probe reports whether the source has data ("ok", "absent", "error: …").
	Probe(ctx context.Context) string
}

// MemorySource reports container working sets (Prometheus).
type MemorySource interface {
	MemoryUsage(ctx context.Context, at time.Time, namespaces []string) ([]model.MemorySample, error)
}

// SeriesQuery asks for the detail charts of one incident.
type SeriesQuery struct {
	Namespace string
	Pods      []string // memory and pod-level request series
	Services  []string // service-level request series
	From, To  time.Time
	Step      time.Duration
	MaxSeries int // per metric; the rest fold into "others"
}

// Series is one line on the incident's shared time axis.
type Series struct {
	Metric string       `json:"metric"` // "memory", "requests", "errors"
	Label  string       `json:"label"`
	Unit   string       `json:"unit"` // "bytes", "rps", "ratio"
	Source string       `json:"source,omitempty"`
	Points [][2]float64 `json:"points"` // [unixMs, value]
}

// SeriesSource draws the detail charts (Prometheus, plus ALB when configured).
type SeriesSource interface {
	SubjectSeries(ctx context.Context, q SeriesQuery) ([]Series, error)
}

// EventSource streams Kubernetes events while the context lives. It is run
// only by the lease holder; sink receives batches. Run returns at once when
// it cannot watch (the runner retries it, waiting longer after each quick
// failure). A source that is also a Prober is probed on every replica.
type EventSource interface {
	Run(ctx context.Context, sink func([]model.KubeEvent)) error
}

// Prober is a source that can tell whether it works: "ok", "absent" or
// "error: …" (any other answer is read as an error). Event and log sources
// may implement it; request and CloudTrail sources must.
type Prober interface {
	Probe(ctx context.Context) string
}

// LogQuery reads container logs in a window.
type LogQuery struct {
	Namespace  string
	Pods       []string
	Containers []string // empty: all containers
	From, To   time.Time
	Level      string // "", "error", "warn", "info", "debug"
	Text       string // substring filter
	Limit      int    // lines
	MaxBytes   int64
	// Previous also reads the previous container instance (Kubernetes only),
	// for containers that restarted inside the window.
	Previous bool
}

// LogLine is one container log line.
type LogLine struct {
	Time      time.Time `json:"time"`
	Pod       string    `json:"pod"`
	Container string    `json:"container"`
	Level     string    `json:"level"`
	Text      string    `json:"text"`
	Source    string    `json:"source"` // "kubernetes" or "cloudwatch"
}

// LogResult is what a log source returns.
type LogResult struct {
	Lines     []LogLine
	Truncated bool
	Warnings  []string
}

// LogSource reads logs (Kubernetes pods/log, CloudWatch Logs). A source
// that is also a Prober is probed on every replica as logs:<name>.
type LogSource interface {
	Name() string // "kubernetes" or "cloudwatch"
	Logs(ctx context.Context, q LogQuery) (LogResult, error)
}

// CloudTrailEvent is a write event from CloudTrail.
type CloudTrailEvent struct {
	ID        string    `json:"id"`
	Time      time.Time `json:"time"`
	Name      string    `json:"name"`   // e.g. "AuthorizeSecurityGroupIngress"
	Source    string    `json:"source"` // e.g. "ec2.amazonaws.com"
	Region    string    `json:"region,omitempty"`
	Actor     string    `json:"actor"` // principal ARN or user name
	ReadOnly  bool      `json:"readOnly"`
	ErrorCode string    `json:"errorCode,omitempty"`
	// Resources are the identifiers the event touches (ARNs, instance IDs,
	// security group IDs, target group ARNs, role ARNs), from resources[] and
	// the string values of requestParameters.
	Resources []string `json:"resources"`
	// Raw is the redacted event JSON, capped, for the bundle.
	Raw string `json:"raw,omitempty"`
}

// CloudTrailSource returns write events after a checkpoint. It paces itself
// (LookupEvents is limited per account and region) and returns a new
// checkpoint to persist with the commit.
type CloudTrailSource interface {
	Name() string // "lookup" or "logs"
	Changes(ctx context.Context, since time.Time, checkpoint []byte) ([]CloudTrailEvent, []byte, error)
	Probe(ctx context.Context) string
}
