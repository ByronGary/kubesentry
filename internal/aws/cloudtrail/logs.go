package cloudtrail

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ByronGary/kubesentry/internal/cloudwatch"
	"github.com/ByronGary/kubesentry/internal/incidents"
)

// LogsFilterPattern selects a trail's write events in CloudWatch Logs.
const LogsFilterPattern = "{ $.readOnly IS FALSE }"

// LogsOptions configures NewLogs.
type LogsOptions struct {
	Overlap time.Duration // default DefaultOverlap
	Start   time.Duration // first poll's look-back; default DefaultStart
	Now     func() time.Time
	// OnResult, if set, counts events and polls by result (Result*).
	OnResult func(result string, n int)
}

// LogsSource reads a trail delivered to CloudWatch Logs. It implements
// incidents.CloudTrailSource.
type LogsSource struct {
	r        *cloudwatch.RawReader
	overlap  time.Duration
	start    time.Duration
	now      func() time.Time
	onResult func(string, int)
}

var _ incidents.CloudTrailSource = (*LogsSource)(nil)

// NewLogs reads through r (API and LogGroup set, -cloudtrail-log-group); an
// empty r.FilterPattern becomes LogsFilterPattern.
func NewLogs(r *cloudwatch.RawReader, o LogsOptions) (*LogsSource, error) {
	if r == nil || r.API == nil || r.LogGroup == "" {
		return nil, errors.New("cloudtrail logs: a reader with an API and a log group is required")
	}
	if r.FilterPattern == "" {
		r.FilterPattern = LogsFilterPattern
	}
	s := &LogsSource{r: r, overlap: o.Overlap, start: o.Start, now: o.Now, onResult: o.OnResult}
	if s.overlap <= 0 {
		s.overlap = DefaultOverlap
	}
	if s.start <= 0 {
		s.start = DefaultStart
	}
	if s.now == nil {
		s.now = time.Now
	}
	return s, nil
}

// Name is ModeLogs.
func (s *LogsSource) Name() string { return ModeLogs }

func (s *LogsSource) result(r string, n int) {
	if s.onResult != nil && n > 0 {
		s.onResult(r, n)
	}
}

// Changes returns the write events since the checkpoint, oldest first, and
// the checkpoint to store. Events come oldest first, so a poll that stops at
// the reader's cap resumes where it stopped; a poll that stops without
// having read any event (a sparse scan) skips to now and reports
// ResultTruncated.
func (s *LogsSource) Changes(ctx context.Context, since time.Time, cpb []byte) ([]incidents.CloudTrailEvent, []byte, error) {
	cp := decodeCheckpoint(cpb)
	now := s.now().UTC().Truncate(time.Millisecond)
	start := from(now, since, cp, s.overlap, s.start)
	if !now.After(start) {
		return nil, cpb, nil
	}
	raws, more, err := s.r.Read(ctx, start, now)
	if err != nil {
		return nil, cpb, fmt.Errorf("cloudtrail logs: %w", err)
	}
	var out []incidents.CloudTrailEvent
	got := map[string]int64{}
	dups, unparsed := 0, 0
	for _, raw := range raws {
		ev, err := ParseRecord([]byte(raw.Message))
		if err != nil {
			unparsed++
			continue
		}
		if ev.ID == "" {
			ev.ID = "cwl:" + raw.ID
		}
		if ev.Time.IsZero() {
			ev.Time = raw.Time
		}
		if _, dup := got[ev.ID]; dup {
			continue
		}
		// Remembered by the later of the event's time and the log
		// event's, which is what the next poll's window is cut on.
		got[ev.ID] = max(ev.Time.Unix(), raw.Time.Unix())
		if _, dup := cp.Seen[ev.ID]; dup {
			dups++
			continue
		}
		if ev.ReadOnly {
			continue
		}
		out = append(out, ev)
	}
	next := checkpoint{Last: now}
	if more {
		s.result(ResultTruncated, 1)
		if len(raws) > 0 {
			next.Last, next.Partial = raws[len(raws)-1].Time, true
		}
	}
	next.Seen = remember(cp.Seen, got, next.Last.Add(-s.overlap))
	sortEvents(out)
	s.result(ResultFetched, len(out))
	s.result(ResultDuplicate, dups)
	s.result(ResultUnparsed, unparsed)
	return out, next.encode(), nil
}

// Probe reports whether the trail's log group can be read: "ok", "absent"
// (no such group) or "error: …".
func (s *LogsSource) Probe(ctx context.Context) string { return s.r.Probe(ctx) }
