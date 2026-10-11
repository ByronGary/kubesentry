package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ByronGary/kubesentry/internal/procmon"
)

// reporter posts reports to the server, or with fanout to every replica
// behind a headless Service. Each replica has its own backoff, so one slow or
// failing replica never holds up the others.
type reporter struct {
	client     *http.Client
	server     *url.URL // -server, the base URL
	endpoint   string   // -server + /agent/report
	fanoutHost string   // -server-fanout: a bare host name; "" posts to -server only
	token      string
	gzip       bool
	interval   time.Duration
	maxBackoff time.Duration
	resolve    func(ctx context.Context, host string) ([]string, error)
	now        func() time.Time
	rand       func() float64

	targets map[string]*target // by endpoint URL; only touched by report
}

// target is one endpoint's delivery state.
type target struct {
	url       string
	failures  int       // consecutive
	notBefore time.Time // backing off until then
	plain     bool      // the server refused gzip: send uncompressed
}

// outcome is what happened to one endpoint in one round.
type outcome struct {
	url      string
	status   int   // HTTP status; 0 without a response
	err      error // nil on success
	skipped  bool  // still backing off, nothing sent
	failures int   // consecutive failures after this round
}

func newReporter(client *http.Client, server *url.URL, fanoutHost, token string, gz bool, interval, maxBackoff time.Duration) *reporter {
	return &reporter{
		client: client, server: server, endpoint: server.JoinPath("agent", "report").String(),
		fanoutHost: fanoutHost, token: token, gzip: gz, interval: interval, maxBackoff: maxBackoff,
		resolve: lookupIPs, now: time.Now, rand: randFloat,
		targets: map[string]*target{},
	}
}

func lookupIPs(ctx context.Context, host string) ([]string, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.IP.String())
	}
	return out, nil
}

// endpoints resolves the fanout host (A and AAAA) into one URL per replica,
// reusing the scheme, port and path of -server. Without fanout, or when the
// lookup fails or finds nothing, the report goes to -server alone.
func (r *reporter) endpoints(ctx context.Context) []string {
	if r.fanoutHost == "" {
		return []string{r.endpoint}
	}
	lctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ips, err := r.resolve(lctx, r.fanoutHost)
	if err != nil || len(ips) == 0 {
		slog.Warn("fanout lookup found no replicas; reporting to -server", "host", r.fanoutHost, "err", err)
		return []string{r.endpoint}
	}
	port := r.server.Port()
	if port == "" {
		port = map[string]string{"https": "443", "http": "80"}[r.server.Scheme]
	}
	seen := map[string]bool{}
	var out []string
	for _, ip := range ips {
		u := *r.server
		u.Host = net.JoinHostPort(ip, port)
		e := u.JoinPath("agent", "report").String()
		if !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	sort.Strings(out)
	return out
}

// report sends one report to every endpoint in parallel and returns what
// happened to each, in endpoint order.
func (r *reporter) report(ctx context.Context, rep procmon.Report) []outcome {
	raw, err := json.Marshal(rep)
	if err != nil {
		return []outcome{{url: r.endpoint, err: err}}
	}
	var zipped []byte
	if r.gzip {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write(raw)
		_ = zw.Close()
		zipped = buf.Bytes()
	}

	eps := r.endpoints(ctx)
	live := make(map[string]*target, len(eps))
	for _, e := range eps {
		t := r.targets[e]
		if t == nil {
			t = &target{url: e}
		}
		live[e] = t
	}
	r.targets = live // replicas that went away are forgotten

	out := make([]outcome, len(eps))
	now := r.now()
	var wg sync.WaitGroup
	for i, e := range eps {
		t := live[e]
		if now.Before(t.notBefore) {
			out[i] = outcome{url: e, skipped: true, failures: t.failures}
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			out[i] = r.deliver(ctx, t, raw, zipped)
		}()
	}
	wg.Wait()
	return out
}

// deliver posts to one target and updates its backoff.
func (r *reporter) deliver(ctx context.Context, t *target, raw, zipped []byte) outcome {
	compressed := zipped != nil && !t.plain
	body := raw
	if compressed {
		body = zipped
	}
	status, retryAfter, err := r.post(ctx, t.url, body, compressed)
	// A server from before gzip support answers 400 or 415: resend plain and
	// remember, so mixed versions work during a rollout.
	if compressed && (status == http.StatusUnsupportedMediaType || status == http.StatusBadRequest) {
		if s2, ra2, err2 := r.post(ctx, t.url, raw, false); err2 == nil {
			slog.Info("server does not accept gzip; sending uncompressed", "url", t.url)
			t.plain = true
			status, retryAfter, err = s2, ra2, nil
		}
	}
	if err == nil {
		t.failures, t.notBefore = 0, time.Time{}
		return outcome{url: t.url, status: status}
	}
	t.failures++
	if transient(status) {
		delay := backoff(t.failures, r.interval, r.maxBackoff, r.rand())
		if retryAfter > 0 {
			ra := min(retryAfter, r.maxBackoff)
			delay = ra + time.Duration(r.rand()*float64(ra)/5) // spread agents told the same
		}
		t.notBefore = r.now().Add(delay)
	}
	return outcome{url: t.url, status: status, err: err, failures: t.failures}
}

// transient statuses back off: no response, overload and server errors.
// Other refusals (401, 403, 413) are configuration problems that waiting does
// not fix.
func transient(status int) bool {
	return status == 0 || status == http.StatusTooManyRequests || status >= 500
}

func (r *reporter) post(ctx context.Context, endpoint string, body []byte, compressed bool) (int, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, 0, err
	}
	// Replicas are dialled by IP but addressed by the -server name, which is
	// also what TLS verifies (tls.Config.ServerName).
	req.Host = r.server.Host
	req.Header.Set("Authorization", "Bearer "+r.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "kubesentry-agent/"+version)
	if compressed {
		req.Header.Set("Content-Encoding", "gzip")
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return resp.StatusCode, 0, nil
	}
	ra, _ := parseRetryAfter(resp.Header.Get("Retry-After"), r.now())
	return resp.StatusCode, ra, fmt.Errorf("server answered %s", resp.Status)
}

// parseRetryAfter reads delay-seconds or an HTTP date.
func parseRetryAfter(v string, now time.Time) (time.Duration, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	if s, err := strconv.Atoi(v); err == nil {
		return time.Duration(max(s, 0)) * time.Second, s >= 0
	}
	if t, err := http.ParseTime(v); err == nil {
		return max(t.Sub(now), 0), true
	}
	return 0, false
}

// backoff is capped exponential backoff with jitter: interval × 2^(n-1),
// at most limit, and a random point in its upper half.
func backoff(failures int, interval, limit time.Duration, rnd float64) time.Duration {
	d := interval
	for i := 1; i < failures && d < limit; i++ {
		d *= 2
	}
	d = min(d, limit)
	return d/2 + time.Duration(rnd*float64(d/2))
}

// jittered spreads an interval by ±frac so agents drift apart.
func jittered(d time.Duration, frac, rnd float64) time.Duration {
	return time.Duration(float64(d) * (1 + frac*(2*rnd-1)))
}

// startDelay is a random wait in [0, d) before the first report, so agents
// restarted together (a DaemonSet rollout, a server upgrade) do not report
// in lockstep.
func startDelay(d time.Duration, rnd float64) time.Duration {
	return time.Duration(rnd * float64(d))
}

// newHTTPClient trusts -ca-file (else the system roots) and always verifies
// the server certificate against the -server host name, also when dialling
// a replica by IP, and sends that name as SNI.
func newHTTPClient(server *url.URL, caFile string, timeout time.Duration) (*http.Client, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.MaxIdleConnsPerHost = 2
	if server.Scheme == "https" {
		cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: server.Hostname()}
		if caFile != "" {
			pem, err := os.ReadFile(caFile)
			if err != nil {
				return nil, fmt.Errorf("read -ca-file: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, errors.New("-ca-file holds no PEM certificates")
			}
			cfg.RootCAs = pool
		}
		tr.TLSClientConfig = cfg
	}
	return &http.Client{Timeout: timeout, Transport: tr}, nil
}

// validFanoutHost accepts a bare DNS name (or IP): no scheme, path or port.
func validFanoutHost(h string) error {
	switch {
	case h == "":
		return nil
	case strings.Contains(h, "/"):
		return fmt.Errorf("-server-fanout takes a bare host name such as kubesentry-ingest-headless.kubesentry.svc, not a URL: %q", h)
	case strings.Contains(h, ":") && net.ParseIP(h) == nil:
		return fmt.Errorf("-server-fanout takes no port (the port of -server is used): %q", h)
	}
	return nil
}
