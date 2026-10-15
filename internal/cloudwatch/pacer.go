package cloudwatch

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/aws/smithy-go"
)

// Pacer waits out throttling for callers of one API. After a throttled call
// it sleeps Backoff, doubling while throttling persists (to 30s), and spaces
// later calls by an adaptive pace that also doubles on each throttle and
// halves with each success. CloudWatch Logs limits FilterLogEvents per
// account and region, so the readers of one account (the audit Reader, the
// incident LogLookup, the CloudTrail RawReader) can share one Pacer.
type Pacer struct {
	backoff time.Duration
	// sleep waits d or until ctx ends, reporting whether it waited; tests
	// replace it.
	sleep func(ctx context.Context, d time.Duration) bool

	mu   sync.Mutex
	pace time.Duration
}

// maxBackoff caps both the wait after a throttle and the pace.
const maxBackoff = 30 * time.Second

// NewPacer returns a pacer whose first wait after a throttled call is backoff
// (default 1s).
func NewPacer(backoff time.Duration) *Pacer {
	if backoff <= 0 {
		backoff = time.Second
	}
	return &Pacer{backoff: backoff, sleep: sleep}
}

// Pace is the current spacing between calls.
func (p *Pacer) Pace() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pace
}

// Do runs call, first waiting the current pace, until it succeeds, fails
// other than by throttling, or ctx ends. throttled classifies call's errors;
// onThrottle, if set, is told of each throttled attempt before the wait.
func (p *Pacer) Do(ctx context.Context, call func() error, throttled func(error) bool, onThrottle func(error)) error {
	backoff := p.backoff
	for {
		p.mu.Lock()
		pace := p.pace
		p.mu.Unlock()
		if pace > 0 && !p.sleep(ctx, pace) {
			return ctx.Err()
		}
		err := call()
		if err == nil {
			p.mu.Lock()
			p.pace /= 2
			if p.pace < p.backoff/8 {
				p.pace = 0
			}
			p.mu.Unlock()
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !throttled(err) {
			return err
		}
		p.mu.Lock()
		p.pace = min(max(p.pace*2, p.backoff), maxBackoff)
		p.mu.Unlock()
		if onThrottle != nil {
			onThrottle(err)
		}
		if !p.sleep(ctx, backoff) {
			return ctx.Err()
		}
		backoff = min(backoff*2, maxBackoff)
	}
}

// errorCode is the AWS error code of err, or "".
func errorCode(err error) string {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode()
	}
	return ""
}

// isThrottled reports whether err is CloudWatch Logs throttling.
func isThrottled(err error) bool { return isThrottle(errorCode(err), err) }

func isThrottle(code string, err error) bool {
	switch code {
	case "ThrottlingException", "Throttling", "RequestLimitExceeded", "TooManyRequestsException", "LimitExceededException", "ServiceUnavailableException":
		return true
	}
	// The SDK's own retry budget running dry is throttling by another name.
	return strings.Contains(err.Error(), "retry quota exceeded")
}

// isAccessDenied reports whether code means the caller may not read.
func isAccessDenied(code string) bool {
	return code == "AccessDeniedException" || code == "UnrecognizedClientException" || code == "ExpiredTokenException"
}
