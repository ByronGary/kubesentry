package cloudwatch

import (
	"context"
	"errors"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
)

// RawEvent is one log event as stored.
type RawEvent struct {
	ID      string // eventId
	Time    time.Time
	Stream  string
	Message string
}

// Defaults of a RawReader.
const (
	DefaultRawMaxCalls  = 20
	DefaultRawMaxEvents = 5000
)

// RawReader reads raw messages from one log group for sources that parse
// them themselves, such as a CloudTrail trail delivered to CloudWatch Logs
// (FilterPattern `{ $.readOnly IS FALSE }`). Set API and LogGroup.
type RawReader struct {
	API           FilterAPI
	LogGroup      string
	StreamPrefix  string // optional logStreamNamePrefix
	FilterPattern string
	MaxCalls      int   // calls per Read; default 20
	MaxEvents     int   // events per Read; default 5000
	PageLimit     int32 // events per call; 0 is the service maximum (10,000)
	// Pacer waits out throttling; share one per account. nil makes one with
	// a 1s backoff per Read.
	Pacer *Pacer
}

// Read returns the events in [from, to], oldest first. more is true when it
// stopped at MaxCalls or MaxEvents with events left: the caller resumes from
// the last event's time (and drops the IDs it has seen).
func (r *RawReader) Read(ctx context.Context, from, to time.Time) (events []RawEvent, more bool, err error) {
	if !to.After(from) {
		return nil, false, errors.New("cloudwatch: empty time range")
	}
	maxCalls := positive(r.MaxCalls, DefaultRawMaxCalls)
	maxEvents := positive(r.MaxEvents, DefaultRawMaxEvents)
	pacer := r.Pacer
	if pacer == nil {
		pacer = NewPacer(time.Second)
	}
	in := &cloudwatchlogs.FilterLogEventsInput{
		LogGroupName: aws.String(r.LogGroup),
		StartTime:    aws.Int64(from.UnixMilli()),
		EndTime:      aws.Int64(to.UnixMilli()),
	}
	if r.FilterPattern != "" {
		in.FilterPattern = aws.String(r.FilterPattern)
	}
	if r.StreamPrefix != "" {
		in.LogStreamNamePrefix = aws.String(r.StreamPrefix)
	}
	if r.PageLimit > 0 {
		in.Limit = aws.Int32(r.PageLimit)
	}
	for calls := 0; ; {
		if calls >= maxCalls {
			return events, true, nil
		}
		calls++
		out, err := pacedFilter(ctx, r.API, pacer, in, r.LogGroup)
		if err != nil {
			return events, false, err
		}
		for _, ev := range out.Events {
			if ev.Message == nil {
				continue
			}
			if len(events) >= maxEvents {
				return events, true, nil
			}
			events = append(events, RawEvent{
				ID:      aws.ToString(ev.EventId),
				Time:    time.UnixMilli(aws.ToInt64(ev.Timestamp)).UTC(),
				Stream:  aws.ToString(ev.LogStreamName),
				Message: *ev.Message,
			})
		}
		if out.NextToken == nil || *out.NextToken == "" {
			return events, false, nil
		}
		in.NextToken = out.NextToken
	}
}

// Probe reports whether the log group can be read: ProbeOK, ProbeAbsent
// (no such group) or "error: …".
func (r *RawReader) Probe(ctx context.Context) string {
	now := time.Now()
	in := &cloudwatchlogs.FilterLogEventsInput{
		LogGroupName: aws.String(r.LogGroup),
		StartTime:    aws.Int64(now.Add(-time.Hour).UnixMilli()),
		EndTime:      aws.Int64(now.UnixMilli()),
		Limit:        aws.Int32(1),
	}
	pacer := r.Pacer
	if pacer == nil {
		pacer = NewPacer(time.Second)
	}
	_, err := pacedFilter(ctx, r.API, pacer, in, r.LogGroup)
	return probeResult(err)
}
