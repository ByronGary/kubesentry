// Package awsjson sends AWS JSON protocol requests (awsJson1_0, awsJson1_1)
// over a plain HTTP client whose transport signs them (awsauth.Transport):
// POST / with an X-Amz-Target header naming the operation and a JSON body.
// It is how kubesentry calls CloudWatch GetMetricData and CloudTrail
// LookupEvents without their SDK modules. A Limiter spaces calls (APIs such
// as LookupEvents allow a couple per second per account), and throttled or
// failed-on-the-server calls are retried with a doubling backoff.
package awsjson

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Content types of the two protocol versions.
const (
	JSON10 = "application/x-amz-json-1.0"
	JSON11 = "application/x-amz-json-1.1"
)

// DefaultMaxResponse caps one response body.
const DefaultMaxResponse = 16 << 20

// Client calls one service.
type Client struct {
	// Endpoint is the service URL, e.g. https://monitoring.us-east-1.amazonaws.com.
	Endpoint string
	// Target prefixes the operation in X-Amz-Target: "<Target>.<Op>".
	Target string
	// ContentType is JSON10 or JSON11.
	ContentType string
	// HTTP sends the requests; its transport signs them.
	HTTP *http.Client
	// Limiter spaces calls, retries included; nil does not.
	Limiter *Limiter
	// Retries after a throttled or 5xx answer; default 4, negative none.
	Retries int
	// Backoff is the first wait before a retry (default 1s); it doubles to
	// 30s.
	Backoff time.Duration
	// MaxResponse caps a response body; default DefaultMaxResponse.
	MaxResponse int64
	// Sleep waits d or until ctx ends, reporting whether it waited; tests
	// replace it (default a timer).
	Sleep func(ctx context.Context, d time.Duration) bool
	// OnThrottle, if set, is told of each throttled answer.
	OnThrottle func()
}

// Error is an error answer from the service.
type Error struct {
	Op      string
	Status  int
	Code    string // e.g. "ThrottlingException", without any namespace
	Message string
}

func (e *Error) Error() string {
	msg := e.Message
	if msg == "" {
		msg = http.StatusText(e.Status)
	}
	return fmt.Sprintf("%s: HTTP %d %s: %s", e.Op, e.Status, e.Code, msg)
}

// Code returns the service error code of err, or "".
func Code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// IsThrottle reports whether err is the service asking to slow down.
func IsThrottle(err error) bool {
	var e *Error
	if !errors.As(err, &e) {
		return false
	}
	switch e.Code {
	case "ThrottlingException", "Throttling", "ThrottledException", "TooManyRequestsException", "RequestLimitExceeded", "RequestThrottled", "RequestThrottledException", "SlowDown":
		return true
	}
	return e.Status == http.StatusTooManyRequests
}

// IsAccessDenied reports whether err means the caller's identity may not
// make the call.
func IsAccessDenied(err error) bool {
	switch Code(err) {
	case "AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "UnrecognizedClientException",
		"InvalidClientTokenId", "ExpiredToken", "ExpiredTokenException", "SignatureDoesNotMatch", "IncompleteSignature",
		"MissingAuthenticationToken", "OperationNotPermittedException":
		return true
	}
	return false
}

func retryable(err error) bool {
	var e *Error
	if !errors.As(err, &e) {
		return false
	}
	return IsThrottle(err) || e.Status >= 500 || e.Code == "ServiceUnavailable" || e.Code == "InternalFailure"
}

// Do calls op with in marshalled as the body and decodes the answer into
// out (nil discards it).
func (c *Client) Do(ctx context.Context, op string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return fmt.Errorf("%s: encode request: %w", op, err)
	}
	retries := c.Retries
	if retries == 0 {
		retries = 4
	}
	backoff := c.Backoff
	if backoff <= 0 {
		backoff = time.Second
	}
	for attempt := 0; ; attempt++ {
		if c.Limiter != nil {
			if err := c.Limiter.Wait(ctx); err != nil {
				return err
			}
		}
		err := c.once(ctx, op, body, out)
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if IsThrottle(err) && c.OnThrottle != nil {
			c.OnThrottle()
		}
		if attempt >= retries || !retryable(err) {
			return err
		}
		if !c.sleep(ctx, backoff) {
			return ctx.Err()
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

func (c *Client) sleep(ctx context.Context, d time.Duration) bool {
	if c.Sleep != nil {
		return c.Sleep(ctx, d)
	}
	return SleepCtx(ctx, d)
}

func (c *Client) once(ctx context.Context, op string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.Endpoint, "/")+"/", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	req.Header.Set("Content-Type", c.ContentType)
	req.Header.Set("X-Amz-Target", c.Target+"."+op)
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	defer resp.Body.Close()
	limit := c.MaxResponse
	if limit <= 0 {
		limit = DefaultMaxResponse
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return fmt.Errorf("%s: read answer: %w", op, err)
	}
	if int64(len(b)) > limit {
		return fmt.Errorf("%s: answer larger than %d bytes", op, limit)
	}
	if resp.StatusCode != http.StatusOK {
		return parseError(op, resp, b)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("%s: decode answer: %w", op, err)
	}
	return nil
}

// parseError reads an AWS JSON error: the code from x-amzn-query-error (the
// awsQuery-compatible code CloudWatch sends), X-Amzn-ErrorType, or the
// body's __type, without namespace ("…#Code") or suffix ("Code:…").
func parseError(op string, resp *http.Response, body []byte) error {
	var e struct {
		Type     string `json:"__type"`
		Code     string `json:"code"`
		Message  string `json:"message"`
		MessageU string `json:"Message"`
	}
	_ = json.Unmarshal(body, &e)
	code := ""
	for _, c := range []string{resp.Header.Get("X-Amzn-Query-Error"), resp.Header.Get("X-Amzn-Errortype"), e.Type, e.Code} {
		if c = cleanCode(c); c != "" {
			code = c
			break
		}
	}
	msg := e.Message
	if msg == "" {
		msg = e.MessageU
	}
	return &Error{Op: op, Status: resp.StatusCode, Code: code, Message: msg}
}

func cleanCode(c string) string {
	if i := strings.LastIndexByte(c, '#'); i >= 0 {
		c = c[i+1:]
	}
	if i := strings.IndexAny(c, ":;"); i >= 0 {
		c = c[:i]
	}
	return strings.TrimSpace(c)
}

// Endpoint is the regional endpoint of a service: https://<service>.<region>.amazonaws.com
// (.amazonaws.com.cn in the China regions).
func Endpoint(service, region string) string {
	suffix := "amazonaws.com"
	if strings.HasPrefix(region, "cn-") {
		suffix = "amazonaws.com.cn"
	}
	return "https://" + service + "." + region + "." + suffix
}

// Limiter spaces calls at most qps per second, across goroutines.
type Limiter struct {
	interval time.Duration
	// Now and Sleep are the clock; tests replace them.
	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) bool

	mu   sync.Mutex
	next time.Time
}

// NewLimiter allows qps calls per second; qps <= 0 does not limit.
func NewLimiter(qps float64) *Limiter {
	l := &Limiter{Now: time.Now, Sleep: SleepCtx}
	if qps > 0 {
		l.interval = time.Duration(float64(time.Second) / qps)
	}
	return l
}

// Interval is the spacing between calls.
func (l *Limiter) Interval() time.Duration { return l.interval }

// Wait blocks until the next call may go, or ctx ends.
func (l *Limiter) Wait(ctx context.Context) error {
	if l == nil || l.interval <= 0 {
		return ctx.Err()
	}
	l.mu.Lock()
	now := l.Now()
	at := l.next
	if at.Before(now) {
		at = now
	}
	l.next = at.Add(l.interval)
	l.mu.Unlock()
	if d := at.Sub(now); d > 0 && !l.Sleep(ctx, d) {
		return ctx.Err()
	}
	return ctx.Err()
}

// SleepCtx waits d or until ctx ends, reporting whether it waited.
func SleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// Seconds is an AWS JSON timestamp: epoch seconds, possibly fractional.
type Seconds float64

// Time converts it.
func (s Seconds) Time() time.Time {
	sec := int64(s)
	return time.Unix(sec, int64((float64(s)-float64(sec))*1e9)).UTC().Round(time.Millisecond)
}

// At converts a time to whole epoch seconds.
func At(t time.Time) Seconds { return Seconds(t.Unix()) }
