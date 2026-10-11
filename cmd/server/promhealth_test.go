package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/prom"
)

// A Prometheus that stops answering is reported (for /info's unavailable
// and the ops /readyz's degraded) after two failed requests in a row, and
// cleared by the next success; the heartbeat notices even when no page
// queries it. The reason names neither the query nor its path.
func TestPrometheusHealth(t *testing.T) {
	var down atomic.Bool
	inner := fakeProm(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if down.Load() {
			http.Error(w, "upstream down", http.StatusServiceUnavailable)
			return
		}
		r.URL.Host, r.URL.Scheme, r.RequestURI = strings.TrimPrefix(inner.URL, "http://"), "http", ""
		resp, err := http.DefaultTransport.RoundTrip(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &promSource{}
	if p.Health() != nil {
		t.Fatal("no Prometheus is not an outage")
	}
	setup := promSetup{url: srv.URL, scan: prom.LeakScanOptions{Interval: time.Hour, StartJitter: -1}, heartbeat: 10 * time.Millisecond}
	if err := setup.start(ctx, p); err != nil {
		t.Fatal(err)
	}
	waitHealth := func(what string, want func(error) bool) error {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			err := p.Health()
			if want(err) {
				return err
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: health = %v", what, err)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	time.Sleep(50 * time.Millisecond) // a few heartbeats
	if err := p.Health(); err != nil {
		t.Fatalf("healthy Prometheus reported down: %v", err)
	}

	down.Store(true)
	err := waitHealth("after the outage began", func(err error) bool { return err != nil })
	if !strings.Contains(err.Error(), "HTTP 503") || strings.Contains(err.Error(), "vector") || strings.Contains(err.Error(), "/api/v1") {
		t.Errorf("reason = %q; want the status, without the query", err)
	}
	down.Store(false)
	waitHealth("after it recovered", func(err error) bool { return err == nil })

	srv.Close()
	err = waitHealth("after the server went away", func(err error) bool { return err != nil })
	if !strings.Contains(err.Error(), "unreachable") || strings.Contains(err.Error(), "/api/v1") {
		t.Errorf("reason = %q; want unreachable, without the URL path", err)
	}
}

type failingTransport struct{ err error }

func (f failingTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, f.err }

// A timeout is a failure; a request its caller cancelled is not.
func TestPromHealthTimeoutsAndCancels(t *testing.T) {
	h := &promHealth{}
	send := func(ctx context.Context) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://prometheus:9090/api/v1/query", nil)
		_, _ = healthTransport{base: failingTransport{ctx.Err()}, h: h}.RoundTrip(req)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	send(cancelled)
	send(cancelled)
	if err := h.Err(); err != nil {
		t.Errorf("requests the caller cancelled marked Prometheus down: %v", err)
	}
	expired, cancel2 := context.WithTimeout(context.Background(), -time.Second)
	defer cancel2()
	send(expired)
	send(expired)
	if err := h.Err(); err == nil || !strings.Contains(err.Error(), "no answer in time") {
		t.Errorf("two timeouts: %v", err)
	}
}

func TestPromHealthNeedsTwoFailures(t *testing.T) {
	h := &promHealth{}
	h.observe("unreachable: connection refused")
	if h.Err() != nil {
		t.Error("one failure marked Prometheus down")
	}
	h.observe("")
	h.observe("HTTP 502 Bad Gateway")
	if h.Err() != nil {
		t.Error("a success did not reset the count")
	}
	h.observe("HTTP 502 Bad Gateway")
	if err := h.Err(); err == nil || !strings.Contains(err.Error(), "502") {
		t.Errorf("two failures in a row: %v", err)
	}
	h.observe("")
	if h.Err() != nil {
		t.Error("a success did not mark it up")
	}
}
