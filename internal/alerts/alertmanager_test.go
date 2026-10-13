package alerts

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeAM is an Alertmanager that records what it is sent and answers with
// the next status in its script (200 once the script runs out).
type fakeAM struct {
	*httptest.Server
	mu       sync.Mutex
	script   []int
	requests []*http.Request
	bodies   [][]byte
	hang     chan struct{} // when set, requests wait for it
}

func newFakeAM(t *testing.T, script ...int) *fakeAM {
	f := &fakeAM{script: script}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f.hang != nil {
			select {
			case <-f.hang:
			case <-r.Context().Done():
				return
			}
		}
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.requests = append(f.requests, r)
		f.bodies = append(f.bodies, body)
		code := http.StatusOK
		if len(f.script) > 0 {
			code, f.script = f.script[0], f.script[1:]
		}
		f.mu.Unlock()
		w.WriteHeader(code)
		if code != http.StatusOK {
			_, _ = io.WriteString(w, `{"message":"bad label payments"}`)
		}
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeAM) received() ([]*http.Request, [][]byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*http.Request(nil), f.requests...), append([][]byte(nil), f.bodies...)
}

type counts struct {
	mu sync.Mutex
	m  map[string]int
}

func (c *counts) add(r string, n int) { c.mu.Lock(); c.m[r] += n; c.mu.Unlock() }
func (c *counts) get(r string) int    { c.mu.Lock(); defer c.mu.Unlock(); return c.m[r] }

func startSink(t *testing.T, o AlertmanagerOptions) (*Alertmanager, *counts) {
	t.Helper()
	c := &counts{m: map[string]int{}}
	o.OnResult = c.add
	if o.Backoff == 0 {
		o.Backoff = 5 * time.Millisecond
	}
	a, err := NewAlertmanager(o)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { a.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return a, c
}

// The wire format: POST /api/v2/alerts, JSON, the payload the golden test
// pins, with the bearer token.
func TestAlertmanagerPostsPayload(t *testing.T) {
	am := newFakeAM(t)
	a, c := startSink(t, AlertmanagerOptions{URLs: []string{am.URL + "/"}, BearerToken: "s3cret", UserAgent: "kubesentry/test"})
	h := newHarness(t, Options{ExternalURL: "https://kubesentry.example.com/", Cluster: "prod-eks"})
	h.at(0)
	_, alerts := h.at(10 * time.Minute)
	a.Send(alerts)
	eventually(t, "delivery", func() bool { return c.get(ResultSent) == len(alerts) })
	reqs, bodies := am.received()
	if len(reqs) != 1 {
		t.Fatalf("%d requests", len(reqs))
	}
	r := reqs[0]
	if r.Method != http.MethodPost || r.URL.Path != "/api/v2/alerts" || r.Header.Get("Content-Type") != "application/json" ||
		r.Header.Get("Authorization") != "Bearer s3cret" || r.Header.Get("User-Agent") != "kubesentry/test" {
		t.Errorf("request %s %s %v", r.Method, r.URL.Path, r.Header)
	}
	var got []Alert
	if err := json.Unmarshal(bodies[0], &got); err != nil {
		t.Fatal(err)
	}
	var posted []map[string]any
	_ = json.Unmarshal(bodies[0], &posted)
	golden(t, "alertmanager-post", posted)
	if st := a.Status(); st.Name != "alertmanager" || st.LastSent.IsZero() || st.LastError != "" || st.Queued != 0 {
		t.Errorf("status %+v", st)
	}
}

// 5xx and 429 are retried with backoff; a 4xx is not; basic auth is sent.
func TestAlertmanagerRetries(t *testing.T) {
	am := newFakeAM(t, 503, 429, 200, 400)
	a, c := startSink(t, AlertmanagerOptions{URLs: []string{am.URL}, BasicUser: "ks", BasicPassword: "pw"})
	one := []Alert{{Labels: map[string]string{"alertname": "X"}, StartsAt: t0, EndsAt: t0.Add(time.Minute)}}
	a.Send(one)
	eventually(t, "sent after two retries", func() bool { return c.get(ResultSent) == 1 })
	if reqs, _ := am.received(); len(reqs) != 3 {
		t.Fatalf("%d attempts, want 3", len(reqs))
	} else if u, p, ok := reqs[0].BasicAuth(); !ok || u != "ks" || p != "pw" {
		t.Errorf("basic auth %q %q %v", u, p, ok)
	}
	a.Send(one)
	eventually(t, "refused", func() bool { return c.get(ResultFailed) == 1 })
	time.Sleep(30 * time.Millisecond)
	if reqs, _ := am.received(); len(reqs) != 4 {
		t.Errorf("a 400 was retried: %d requests", len(reqs))
	}
	if st := a.Status(); st.LastError != "alertmanager 1 of 1: HTTP 400 Bad Request" {
		t.Errorf("last error %q (it must not quote the response body)", st.LastError)
	}
}

// HA: every URL gets every alert; one that is down does not hold up the
// other, and the status names it.
func TestAlertmanagerFansOut(t *testing.T) {
	up := newFakeAM(t)
	down := newFakeAM(t)
	down.Close()
	a, c := startSink(t, AlertmanagerOptions{URLs: []string{down.URL, up.URL}, MaxAttempts: 2})
	a.Send([]Alert{{Labels: map[string]string{"alertname": "X"}, StartsAt: t0, EndsAt: t0}})
	eventually(t, "one sent, one failed", func() bool { return c.get(ResultSent) == 1 && c.get(ResultFailed) == 1 })
	if reqs, _ := up.received(); len(reqs) != 1 {
		t.Errorf("up got %d requests", len(reqs))
	}
	st := a.Status()
	if !strings.HasPrefix(st.LastError, "alertmanager 1 of 2: unreachable: ") || st.LastSent.IsZero() {
		t.Errorf("status %+v", st)
	}
}

// A full queue drops (and counts) instead of blocking; Drop empties the
// queue and stops a retry in progress.
func TestAlertmanagerQueueBoundsAndDrop(t *testing.T) {
	am := newFakeAM(t)
	am.hang = make(chan struct{})
	a, c := startSink(t, AlertmanagerOptions{URLs: []string{am.URL}, QueueSize: 3, BatchSize: 2})
	mk := func(n int) []Alert {
		out := make([]Alert, n)
		for i := range out {
			out[i] = Alert{Labels: map[string]string{"alertname": "X", "i": string(rune('a' + i))}, StartsAt: t0, EndsAt: t0}
		}
		return out
	}
	done := make(chan struct{})
	go func() {
		a.Send(mk(2)) // taken by the worker, which hangs in the POST
		time.Sleep(20 * time.Millisecond)
		a.Send(mk(2)) // queued
		a.Send(mk(2)) // 2+2 > 3: dropped
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Send blocked")
	}
	if c.get(ResultDropped) != 2 || a.Status().Queued != 4 {
		t.Fatalf("dropped %d, queued %d", c.get(ResultDropped), a.Status().Queued)
	}
	a.Drop()
	if c.get(ResultDropped) != 4 {
		t.Errorf("after Drop: dropped %d, want 4", c.get(ResultDropped))
	}
	close(am.hang)
	eventually(t, "the batch in flight finished", func() bool { return a.Status().Queued == 0 })
	time.Sleep(20 * time.Millisecond)
	if reqs, _ := am.received(); len(reqs) != 1 {
		t.Errorf("%d requests after Drop, want only the one in flight", len(reqs))
	}
}

func TestEndpoint(t *testing.T) {
	for in, want := range map[string]string{
		"http://am:9093":                 "http://am:9093/api/v2/alerts",
		"http://am:9093/":                "http://am:9093/api/v2/alerts",
		"https://am.example.com/prefix/": "https://am.example.com/prefix/api/v2/alerts",
		"http://am:9093/api/v2/alerts":   "http://am:9093/api/v2/alerts",
		"https://aps-workspaces.us-east-1.amazonaws.com/workspaces/ws-1/alertmanager": "https://aps-workspaces.us-east-1.amazonaws.com/workspaces/ws-1/alertmanager/api/v2/alerts",
	} {
		if got, err := Endpoint(in); err != nil || got != want {
			t.Errorf("Endpoint(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"am:9093", "ftp://am", "http://user:pw@am:9093", "http://am:9093/?x=1", ""} {
		if _, err := Endpoint(bad); err == nil {
			t.Errorf("Endpoint(%q) accepted", bad)
		} else if strings.Contains(err.Error(), "pw") {
			t.Errorf("error shows the password: %v", err)
		}
	}
}

// Send must be cheap for the evaluator however slow Alertmanager is.
func TestAlertmanagerSendNeverBlocks(t *testing.T) {
	am := newFakeAM(t)
	am.hang = make(chan struct{})
	defer close(am.hang)
	a, _ := startSink(t, AlertmanagerOptions{URLs: []string{am.URL}, QueueSize: 100})
	var n atomic.Int32
	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			a.Send([]Alert{{Labels: map[string]string{"alertname": "X"}}})
			n.Add(1)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("Send blocked after %d calls", n.Load())
	}
}
