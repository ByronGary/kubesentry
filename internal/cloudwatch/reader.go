// Package cloudwatch reads EKS control-plane audit logs from CloudWatch Logs
// into an audit store. EKS writes one audit.k8s.io/v1 Event per log event to
// the kube-apiserver-audit-* streams of /aws/eks/<cluster>/cluster.
//
// The Reader polls FilterLogEvents in time windows and commits each window's
// events together with its checkpoint, so a restart (or a new leader replica)
// resumes where the last durable write ended: no gaps, and re-read events
// collapse in the store's (auditID, time) upsert, so no duplicates. Each
// window re-reads Overlap before its start to catch late-delivered events.
//
// For incidents, LogLookup reads container logs on demand (lookup.go) and
// RawReader reads raw messages, such as a CloudTrail trail's (raw.go). All
// readers wait out throttling through a Pacer, which they can share.
//
// The AWS SDK is used only here, in internal/awsauth and in internal/aws;
// the fake in cwfake is stdlib-only.
package cloudwatch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"

	"github.com/ByronGary/kubesentry/internal/audit"
)

// FilterAPI is the part of the CloudWatch Logs client the Reader uses.
type FilterAPI interface {
	FilterLogEvents(ctx context.Context, in *cloudwatchlogs.FilterLogEventsInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.FilterLogEventsOutput, error)
}

// Committer durably stores a batch of events together with the reader's
// checkpoint. pgstore's Leader implements it (one transaction on the
// advisory-lock connection); StoreCommitter does for a single replica.
// Commit errors wrapping audit.ErrLeadershipLost stop the Reader.
type Committer interface {
	Commit(ctx context.Context, events []audit.Event, source string, position []byte) error
	Checkpoint(ctx context.Context, source string) ([]byte, error)
}

// New builds a CloudWatch Logs client from the default credential chain
// (IRSA web identity, EKS Pod Identity, environment, shared config, instance
// role). endpoint, when set, overrides the service endpoint (cwfake, a VPC
// endpoint). The SDK retries throttling itself; the Reader paces on top.
func New(ctx context.Context, region, endpoint string, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.Client, error) {
	var opts []func(*config.LoadOptions) error
	if region != "" {
		opts = append(opts, config.WithRegion(region))
	}
	opts = append(opts, config.WithRetryMaxAttempts(5))
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("cloudwatch: load AWS config: %w", err)
	}
	if cfg.Region == "" {
		return nil, errors.New("cloudwatch: no AWS region: set -aws-region or AWS_REGION")
	}
	return cloudwatchlogs.NewFromConfig(cfg, func(o *cloudwatchlogs.Options) {
		if endpoint != "" {
			o.BaseEndpoint = aws.String(endpoint)
		}
		for _, fn := range optFns {
			fn(o)
		}
	}), nil
}

// Errors the Reader reports in Status and returns from Step.
var (
	// ErrLogGroupNotFound: the log group does not exist, usually because EKS
	// control-plane audit logging is off or the cluster name is wrong.
	ErrLogGroupNotFound = errors.New("cloudwatch: log group not found")
	// ErrAccessDenied: the role lacks logs:FilterLogEvents on the group.
	ErrAccessDenied = errors.New("cloudwatch: access denied")
)

// Reader polls one log group. Set API, Store and LogGroup; the rest default.
type Reader struct {
	API          FilterAPI
	Store        Committer
	LogGroup     string
	StreamPrefix string        // "kube-apiserver-audit"
	Source       string        // checkpoint key; "cloudwatch:<LogGroup>:<StreamPrefix>"
	Start        time.Duration // 24h: how far back to start without a checkpoint
	Overlap      time.Duration // 5m re-read before each window, for late delivery
	Lag          time.Duration // 30s: windows end this far behind now
	Poll         time.Duration // 15s between polls once caught up
	MaxWindow    time.Duration // 15m per window while catching up
	PageLimit    int32         // events per call; 0 is the service maximum (10,000)
	// CommitEvery bounds memory on busy windows: events are committed (without
	// advancing the checkpoint) once this many are buffered. Default 20,000.
	CommitEvery int
	// Ingest turns one log message into events; default audit.Parse. Pass
	// a function that also applies the ingester's policy (Ingester.Prepare).
	Ingest func([]byte) ([]audit.Event, error)
	// ThrottleBackoff is the first wait after a throttled call (default 1s);
	// it doubles while throttling persists (to 30s) and the reader then paces
	// its calls, relaxing as calls succeed.
	ThrottleBackoff time.Duration
	// Pacer, when set, is shared with other readers of the same account
	// (ThrottleBackoff is then the Pacer's); nil makes one from
	// ThrottleBackoff.
	Pacer  *Pacer
	Now    func() time.Time
	Logger *slog.Logger

	mu     sync.Mutex
	status Status
	seen   map[string]int64 // eventId → timestamp (ms) of events committed in the overlap region
}

// Status is the reader's health, for /info, /readyz and metrics.
type Status struct {
	LogGroup       string        `json:"logGroup"`
	WindowEnd      time.Time     `json:"windowEnd"` // everything before this is stored
	Lag            time.Duration `json:"lag"`       // now − WindowEnd at the last commit
	LastPoll       time.Time     `json:"lastPoll"`  // last successful window
	LastError      string        `json:"lastError,omitempty"`
	ErrorKind      string        `json:"errorKind,omitempty"` // "log-group-not-found", "access-denied", "throttled", "store", "leadership-lost", "aws"
	EventsIngested int64         `json:"eventsIngested"`      // events committed (including re-reads of the overlap)
	ParseErrors    int64         `json:"parseErrors"`         // log messages that were not audit events
	Throttled      int64         `json:"throttled"`           // throttled calls
	Calls          int64         `json:"calls"`               // FilterLogEvents calls
}

// position is the checkpoint stored with each commit.
type position struct {
	WindowEnd time.Time `json:"windowEnd"`
}

func (r *Reader) defaults() {
	if r.StreamPrefix == "" {
		r.StreamPrefix = "kube-apiserver-audit"
	}
	if r.Source == "" {
		r.Source = "cloudwatch:" + r.LogGroup + ":" + r.StreamPrefix
	}
	if r.Start <= 0 {
		r.Start = 24 * time.Hour
	}
	if r.Overlap == 0 { // negative turns the overlap off; see overlap()
		r.Overlap = 5 * time.Minute
	}
	if r.Lag <= 0 {
		r.Lag = 30 * time.Second
	}
	if r.Poll <= 0 {
		r.Poll = 15 * time.Second
	}
	if r.MaxWindow <= 0 {
		r.MaxWindow = 15 * time.Minute
	}
	if r.CommitEvery <= 0 {
		r.CommitEvery = 20_000
	}
	if r.Ingest == nil {
		r.Ingest = func(b []byte) ([]audit.Event, error) { return audit.Parse(bytes.NewReader(b)) }
	}
	if r.ThrottleBackoff <= 0 {
		r.ThrottleBackoff = time.Second
	}
	if r.Now == nil {
		r.Now = time.Now
	}
	if r.Logger == nil {
		r.Logger = slog.Default()
	}
	r.mu.Lock()
	if r.seen == nil {
		r.seen = map[string]int64{}
	}
	r.status.LogGroup = r.LogGroup
	r.mu.Unlock()
}

// Status returns a snapshot of the reader's progress.
func (r *Reader) Status() Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.status
	if !s.WindowEnd.IsZero() && r.Now != nil {
		s.Lag = r.Now().Sub(s.WindowEnd)
	}
	return s
}

// Run polls until ctx ends or the Committer reports lost leadership. Other
// errors are reported in Status and retried with backoff.
func (r *Reader) Run(ctx context.Context) error {
	r.defaults()
	fails := 0
	for {
		caughtUp, err := r.Step(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		wait := time.Duration(0)
		switch {
		case err == nil:
			fails = 0
			if caughtUp {
				wait = r.Poll
			}
		case errors.Is(err, audit.ErrLeadershipLost):
			return err
		default:
			fails++
			wait = min(r.Poll*time.Duration(1<<min(fails-1, 4)), 5*time.Minute)
			r.Logger.Warn("cloudwatch audit poll failed", "logGroup", r.LogGroup, "retryIn", wait, "err", err)
		}
		if wait > 0 && !sleep(ctx, wait) {
			return ctx.Err()
		}
	}
}

// Step reads and commits one window: from the checkpoint (or now−Start) to
// min(now−Lag, from+MaxWindow). caughtUp is true when the window reached
// now−Lag (or there was nothing to read yet).
func (r *Reader) Step(ctx context.Context) (caughtUp bool, err error) {
	r.defaults()
	defer func() { r.noteErr(err) }()
	now := r.Now().UTC()
	from, err := r.checkpoint(ctx, now)
	if err != nil {
		return false, err
	}
	horizon := now.Add(-r.Lag).Truncate(time.Millisecond)
	to := horizon
	if limit := from.Add(r.MaxWindow); limit.Before(to) {
		to = limit
	}
	if !to.After(from) {
		return true, nil
	}
	in := &cloudwatchlogs.FilterLogEventsInput{
		LogGroupName:        aws.String(r.LogGroup),
		LogStreamNamePrefix: aws.String(r.StreamPrefix),
		StartTime:           aws.Int64(from.Add(-r.overlap()).UnixMilli()),
		EndTime:             aws.Int64(to.UnixMilli()),
	}
	if r.PageLimit > 0 {
		in.Limit = aws.Int32(r.PageLimit)
	}
	var (
		buf     []audit.Event
		pending = map[string]int64{} // eventIds in buf
		total   int64
		parse   int64
	)
	commit := func(pos time.Time) error {
		b, _ := json.Marshal(position{WindowEnd: pos})
		if err := r.Store.Commit(ctx, buf, r.Source, b); err != nil {
			if errors.Is(err, audit.ErrLeadershipLost) {
				return err
			}
			return fmt.Errorf("%w: %w", errStore, err)
		}
		total += int64(len(buf))
		r.mu.Lock()
		for id, ts := range pending {
			r.seen[id] = ts
		}
		r.mu.Unlock()
		buf, pending = buf[:0], map[string]int64{}
		return nil
	}
	for {
		out, err := r.filter(ctx, in)
		if err != nil {
			return false, err
		}
		for _, le := range out.Events {
			if le.Message == nil {
				continue
			}
			id := aws.ToString(le.EventId)
			if id != "" {
				r.mu.Lock()
				_, dup := r.seen[id]
				r.mu.Unlock()
				if _, inBuf := pending[id]; dup || inBuf {
					continue // already stored by this reader in an earlier window's overlap
				}
			}
			events, err := r.Ingest([]byte(*le.Message))
			if err != nil {
				parse++
				continue
			}
			buf = append(buf, events...)
			if id != "" {
				pending[id] = aws.ToInt64(le.Timestamp)
			}
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		in.NextToken = out.NextToken
		if len(buf) >= r.CommitEvery {
			// Events only: the checkpoint stays at from until the window is whole.
			if err := commit(from); err != nil {
				return false, err
			}
		}
	}
	if err := commit(to); err != nil {
		return false, err
	}

	// Forget event IDs that no later window's overlap can return.
	cut := to.Add(-r.overlap()).UnixMilli()
	r.mu.Lock()
	for id, ts := range r.seen {
		if ts < cut {
			delete(r.seen, id)
		}
	}
	r.status.WindowEnd = to
	r.status.Lag = now.Sub(to)
	r.status.LastPoll = now
	r.status.EventsIngested += total
	r.status.ParseErrors += parse
	r.mu.Unlock()
	if parse > 0 {
		r.Logger.Warn("cloudwatch messages that are not audit events were skipped", "count", parse, "logGroup", r.LogGroup, "streamPrefix", r.StreamPrefix)
	}
	return !to.Before(horizon), nil
}

var errStore = errors.New("store")

// overlap is the re-read before each window; a negative Overlap disables it.
func (r *Reader) overlap() time.Duration { return max(r.Overlap, 0) }

// checkpoint returns where the next window starts.
func (r *Reader) checkpoint(ctx context.Context, now time.Time) (time.Time, error) {
	b, err := r.Store.Checkpoint(ctx, r.Source)
	if err != nil {
		if errors.Is(err, audit.ErrLeadershipLost) {
			return time.Time{}, err
		}
		return time.Time{}, fmt.Errorf("%w: read checkpoint: %w", errStore, err)
	}
	if len(b) > 0 {
		var p position
		if err := json.Unmarshal(b, &p); err == nil && !p.WindowEnd.IsZero() {
			return p.WindowEnd.UTC(), nil
		}
		r.Logger.Warn("ignoring unreadable cloudwatch checkpoint", "source", r.Source, "position", string(b))
	}
	return now.Add(-r.Start).Truncate(time.Millisecond), nil
}

// filter calls FilterLogEvents, waiting out throttling with the pacer.
func (r *Reader) filter(ctx context.Context, in *cloudwatchlogs.FilterLogEventsInput) (*cloudwatchlogs.FilterLogEventsOutput, error) {
	var out *cloudwatchlogs.FilterLogEventsOutput
	err := r.pacer().Do(ctx, func() error {
		r.mu.Lock()
		r.status.Calls++
		r.mu.Unlock()
		var err error
		out, err = r.API.FilterLogEvents(ctx, in)
		return err
	}, isThrottled, func(err error) {
		r.mu.Lock()
		r.status.Throttled++
		r.status.LastError, r.status.ErrorKind = err.Error(), "throttled"
		r.mu.Unlock()
	})
	if err == nil {
		return out, nil
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	switch code := errorCode(err); {
	case code == "ResourceNotFoundException":
		return nil, fmt.Errorf("%w: %s (is the EKS control plane audit log enabled? check -cloudwatch-log-group): %v", ErrLogGroupNotFound, r.LogGroup, err)
	case isAccessDenied(code):
		return nil, fmt.Errorf("%w: logs:FilterLogEvents on %s: %v", ErrAccessDenied, r.LogGroup, err)
	}
	return nil, err
}

// pacer returns the Reader's Pacer, creating one from ThrottleBackoff when
// none was given.
func (r *Reader) pacer() *Pacer {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.Pacer == nil {
		r.Pacer = NewPacer(r.ThrottleBackoff)
	}
	return r.Pacer
}

func (r *Reader) noteErr(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err == nil {
		r.status.LastError, r.status.ErrorKind = "", ""
		return
	}
	r.status.LastError = err.Error()
	switch {
	case errors.Is(err, audit.ErrLeadershipLost):
		r.status.ErrorKind = "leadership-lost"
	case errors.Is(err, ErrLogGroupNotFound):
		r.status.ErrorKind = "log-group-not-found"
	case errors.Is(err, ErrAccessDenied):
		r.status.ErrorKind = "access-denied"
	case errors.Is(err, errStore):
		r.status.ErrorKind = "store"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		r.status.LastError, r.status.ErrorKind = "", ""
	default:
		r.status.ErrorKind = "aws"
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// StoreCommitter commits into an audit.Store and keeps checkpoints in
// memory: for a single replica with the memory store, where history does not
// outlive the process anyway. If the store has a Flush method (pgstore), it is
// called so the checkpoint never runs ahead of durable events.
type StoreCommitter struct {
	Store audit.Store

	mu        sync.Mutex
	positions map[string][]byte
}

func (c *StoreCommitter) Commit(ctx context.Context, events []audit.Event, source string, pos []byte) error {
	if len(events) > 0 {
		if err := c.Store.Add(ctx, events); err != nil {
			return err
		}
		if f, ok := c.Store.(interface{ Flush(context.Context) error }); ok {
			if err := f.Flush(ctx); err != nil {
				return err
			}
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.positions == nil {
		c.positions = map[string][]byte{}
	}
	c.positions[source] = append([]byte(nil), pos...)
	return nil
}

func (c *StoreCommitter) Checkpoint(_ context.Context, source string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.positions[source], nil
}
