package alerts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// AlertsPath is Alertmanager's v2 endpoint for posting alerts.
const AlertsPath = "/api/v2/alerts"

// Delivery results, for kubesentry_alerts_sent_total{result}.
const (
	ResultSent    = "sent"    // Alertmanager took the alert
	ResultFailed  = "failed"  // every attempt failed, or Alertmanager refused it
	ResultDropped = "dropped" // the queue was full, or leadership was lost
)

// AlertmanagerOptions configures an Alertmanager sink. Zero values take the
// defaults shown.
type AlertmanagerOptions struct {
	// URLs are the Alertmanager base URLs (an AMP workspace's ends in
	// /alertmanager); AlertsPath is appended unless already there. Every
	// alert goes to each of them: an HA pair gossips, and duplicates are
	// harmless because Alertmanager knows an alert by its label set.
	URLs []string
	// Client sends the requests; its transport carries a custom CA and,
	// for Amazon Managed Prometheus, SigV4 signing. Default: a client with
	// a 10s timeout.
	Client *http.Client
	// BearerToken or BasicUser/BasicPassword authenticate each request
	// (a SigV4 transport replaces either).
	BearerToken              string
	BasicUser, BasicPassword string
	UserAgent                string
	// QueueSize bounds the alerts waiting per URL (default 10,000); what does
	// not fit is dropped and counted.
	QueueSize int
	// BatchSize alerts at most go in one POST (default 500).
	BatchSize int
	// MaxAttempts per POST (default 4), retried after Backoff, doubling up
	// to 30s (default 1s). A 4xx other than 429 is not retried.
	MaxAttempts int
	Backoff     time.Duration
	// OnResult counts alerts by delivery result (per URL).
	OnResult func(result string, n int)
	Logger   *slog.Logger
	Now      func() time.Time
}

// Alertmanager posts alerts to Alertmanager's v2 API from a bounded queue
// per URL, each drained by its own goroutine, so a slow or failing
// Alertmanager never blocks the evaluator or the other URLs.
type Alertmanager struct {
	o       AlertmanagerOptions
	targets []*amTarget
}

type amTarget struct {
	n, of    int // 1-based position among the URLs, for messages
	endpoint string
	host     string

	mu       sync.Mutex
	queue    []Alert
	gen      uint64 // bumped by Drop: a retry in progress gives up
	wake     chan struct{}
	lastSent time.Time
	lastErr  string
	inflight int
}

var _ Sink = (*Alertmanager)(nil)

// NewAlertmanager returns a sink for the URLs. Call Run to start delivery.
func NewAlertmanager(o AlertmanagerOptions) (*Alertmanager, error) {
	if len(o.URLs) == 0 {
		return nil, errors.New("alertmanager: no URL")
	}
	if o.Client == nil {
		o.Client = &http.Client{Timeout: 10 * time.Second}
	}
	if o.QueueSize <= 0 {
		o.QueueSize = 10_000
	}
	if o.BatchSize <= 0 {
		o.BatchSize = 500
	}
	if o.MaxAttempts <= 0 {
		o.MaxAttempts = 4
	}
	if o.Backoff <= 0 {
		o.Backoff = time.Second
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	a := &Alertmanager{o: o}
	for i, raw := range o.URLs {
		ep, err := Endpoint(raw)
		if err != nil {
			return nil, err
		}
		u, _ := url.Parse(ep)
		a.targets = append(a.targets, &amTarget{n: i + 1, of: len(o.URLs), endpoint: ep, host: u.Host, wake: make(chan struct{}, 1)})
	}
	return a, nil
}

// Endpoint is the alerts endpoint of an Alertmanager base URL: http(s)
// only, without user info (credentials go in their own options), with
// AlertsPath appended unless the URL already ends in it.
func Endpoint(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("alertmanager URL %q: want http(s)://host[:port][/path]", raw)
	}
	if u.User != nil {
		return "", fmt.Errorf("alertmanager URL %q: put credentials in ALERTMANAGER_TOKEN or the basic auth options, not the URL", u.Redacted())
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("alertmanager URL %q: no query or fragment", raw)
	}
	p := strings.TrimRight(u.Path, "/")
	if !strings.HasSuffix(p, AlertsPath) {
		p += AlertsPath
	}
	u.Path = p
	return u.String(), nil
}

// Run delivers until ctx ends.
func (a *Alertmanager) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, t := range a.targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a.drain(ctx, t)
		}()
	}
	wg.Wait()
}

// Send queues alerts for every URL; it never blocks. A URL whose queue
// cannot take them all drops them (counted as dropped).
func (a *Alertmanager) Send(alerts []Alert) {
	if len(alerts) == 0 {
		return
	}
	for _, t := range a.targets {
		t.mu.Lock()
		if len(t.queue)+len(alerts) > a.o.QueueSize {
			t.mu.Unlock()
			a.result(ResultDropped, len(alerts))
			a.o.Logger.Warn("alertmanager queue full; alerts dropped (they are posted again at the next resend)",
				"alertmanager", t.n, "dropped", len(alerts), "queue", a.o.QueueSize)
			continue
		}
		t.queue = append(t.queue, alerts...)
		t.mu.Unlock()
		select {
		case t.wake <- struct{}{}:
		default:
		}
	}
}

// Drop forgets every queued alert and stops retries in progress: this
// replica lost the leadership.
func (a *Alertmanager) Drop() {
	for _, t := range a.targets {
		t.mu.Lock()
		n := len(t.queue)
		t.queue = nil
		t.gen++
		t.mu.Unlock()
		if n > 0 {
			a.result(ResultDropped, n)
		}
	}
}

// Status reports the latest successful delivery, the errors of the URLs
// whose latest delivery failed, and the alerts queued.
func (a *Alertmanager) Status() SinkStatus {
	st := SinkStatus{Name: "alertmanager"}
	var errs []string
	for _, t := range a.targets {
		t.mu.Lock()
		if t.lastSent.After(st.LastSent) {
			st.LastSent = t.lastSent
		}
		if t.lastErr != "" {
			errs = append(errs, t.lastErr)
		}
		st.Queued += len(t.queue) + t.inflight
		t.mu.Unlock()
	}
	st.LastError = strings.Join(errs, "; ")
	return st
}

func (a *Alertmanager) result(r string, n int) {
	if a.o.OnResult != nil && n > 0 {
		a.o.OnResult(r, n)
	}
}

// drain posts t's queue, a batch at a time, until ctx ends.
func (a *Alertmanager) drain(ctx context.Context, t *amTarget) {
	for {
		t.mu.Lock()
		n := min(len(t.queue), a.o.BatchSize)
		batch := t.queue[:n:n]
		t.queue = t.queue[n:]
		if len(t.queue) == 0 {
			t.queue = nil
		}
		t.inflight = n
		gen := t.gen
		t.mu.Unlock()
		if n == 0 {
			select {
			case <-ctx.Done():
				return
			case <-t.wake:
				continue
			}
		}
		err := a.post(ctx, t, gen, batch)
		t.mu.Lock()
		t.inflight = 0
		dropped := t.gen != gen
		if err == nil {
			t.lastSent, t.lastErr = a.o.Now(), ""
		} else if !dropped && ctx.Err() == nil {
			t.lastErr = fmt.Sprintf("alertmanager %d of %d: %s", t.n, t.of, err)
		}
		t.mu.Unlock()
		switch {
		case err == nil:
			a.result(ResultSent, n)
		case dropped || ctx.Err() != nil:
			a.result(ResultDropped, n)
		default:
			a.result(ResultFailed, n)
			a.o.Logger.Warn("alerts not delivered to Alertmanager", "alertmanager", t.n, "host", t.host, "alerts", n, "err", err)
		}
		if ctx.Err() != nil {
			return
		}
	}
}

// permanent marks an error retrying cannot fix.
type permanent struct{ error }

// post sends one batch, retrying with backoff; it gives up early when ctx
// ends or Drop is called (gen moves on).
func (a *Alertmanager) post(ctx context.Context, t *amTarget, gen uint64, batch []Alert) error {
	body, err := json.Marshal(batch)
	if err != nil {
		return err
	}
	wait := a.o.Backoff
	for attempt := 1; ; attempt++ {
		err = a.once(ctx, t, body)
		var perm permanent
		if err == nil || errors.As(err, &perm) || attempt >= a.o.MaxAttempts {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		t.mu.Lock()
		stale := t.gen != gen
		t.mu.Unlock()
		if stale {
			return errors.New("dropped: leadership lost")
		}
		wait = min(2*wait, 30*time.Second)
	}
}

// once is one POST. Errors name the status or the network failure, never
// the body: Alertmanager echoes label values, and /info shows the error to
// every user.
func (a *Alertmanager) once(ctx context.Context, t *amTarget, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.endpoint, bytes.NewReader(body))
	if err != nil {
		return permanent{err}
	}
	req.Header.Set("Content-Type", "application/json")
	if a.o.UserAgent != "" {
		req.Header.Set("User-Agent", a.o.UserAgent)
	}
	switch {
	case a.o.BearerToken != "":
		req.Header.Set("Authorization", "Bearer "+a.o.BearerToken)
	case a.o.BasicUser != "":
		req.SetBasicAuth(a.o.BasicUser, a.o.BasicPassword)
	}
	resp, err := a.o.Client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // the URL is known; keep the cause
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("unreachable: %w", err)
	}
	defer resp.Body.Close()
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 == 2 {
		return nil
	}
	err = fmt.Errorf("HTTP %s", resp.Status)
	if resp.StatusCode/100 == 4 && resp.StatusCode != http.StatusTooManyRequests {
		a.o.Logger.Warn("alertmanager refused alerts", "alertmanager", t.n, "status", resp.Status, "response", strings.TrimSpace(string(snippet)))
		return permanent{err}
	}
	return err
}
