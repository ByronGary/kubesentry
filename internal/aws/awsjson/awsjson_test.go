package awsjson

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Sleep(ctx context.Context, d time.Duration) bool {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
	return ctx.Err() == nil
}

func TestLimiterSpacesCalls(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1792058400, 0)}
	l := NewLimiter(2)
	l.Now, l.Sleep = clk.Now, clk.Sleep
	var at []time.Time
	for i := 0; i < 4; i++ {
		if err := l.Wait(context.Background()); err != nil {
			t.Fatal(err)
		}
		at = append(at, clk.Now())
	}
	for i := 1; i < len(at); i++ {
		if d := at[i].Sub(at[i-1]); d != 500*time.Millisecond {
			t.Errorf("call %d after %v, want 500ms", i, d)
		}
	}
	// Idle time is not banked: after a pause the next call goes at once.
	clk.Sleep(context.Background(), 10*time.Second)
	before := clk.Now()
	l.Wait(context.Background())
	if clk.Now() != before {
		t.Errorf("waited %v after a pause", clk.Now().Sub(before))
	}
	if err := NewLimiter(0).Wait(context.Background()); err != nil {
		t.Error(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := l.Wait(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled wait = %v", err)
	}
}

func TestDoRetriesAndParsesErrors(t *testing.T) {
	var n int
	answers := []struct {
		status int
		hdr    string
		body   string
	}{
		{500, "", `{"__type":"InternalFailure"}`},
		{400, "", `{"__type":"com.amazonaws.cloudtrail.v20131101#ThrottlingException","message":"Rate exceeded"}`},
		{200, "", `{"ok":true}`},
		{400, "", `{"__type":"InvalidTimeRangeException","Message":"bad range"}`},
		{400, "AccessDeniedException:http://internal.amazon.com/coral/", `{"message":"no"}`},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Amz-Target") != "Svc_2013.Op" || r.Header.Get("Content-Type") != JSON11 {
			t.Errorf("headers %v", r.Header)
		}
		a := answers[n]
		n++
		if a.hdr != "" {
			w.Header().Set("X-Amzn-ErrorType", a.hdr)
		}
		w.WriteHeader(a.status)
		w.Write([]byte(a.body))
	}))
	defer srv.Close()
	var sleeps []time.Duration
	throttles := 0
	c := &Client{Endpoint: srv.URL, Target: "Svc_2013", ContentType: JSON11, HTTP: srv.Client(),
		Sleep:      func(ctx context.Context, d time.Duration) bool { sleeps = append(sleeps, d); return true },
		OnThrottle: func() { throttles++ }}
	var out struct{ OK bool }
	if err := c.Do(context.Background(), "Op", map[string]int{"a": 1}, &out); err != nil || !out.OK {
		t.Fatalf("after retries: %+v %v", out, err)
	}
	if n != 3 || throttles != 1 || len(sleeps) != 2 || sleeps[0] != time.Second || sleeps[1] != 2*time.Second {
		t.Errorf("%d calls, %d throttles, sleeps %v", n, throttles, sleeps)
	}
	err := c.Do(context.Background(), "Op", nil, nil)
	if Code(err) != "InvalidTimeRangeException" || IsThrottle(err) || n != 4 {
		t.Errorf("client error retried or misread: %v (%d calls)", err, n)
	}
	var e *Error
	if !errors.As(err, &e) || e.Message != "bad range" || e.Status != 400 {
		t.Errorf("error = %#v", err)
	}
	err = c.Do(context.Background(), "Op", nil, nil)
	if Code(err) != "AccessDeniedException" || !IsAccessDenied(err) {
		t.Errorf("access denied from the header: %v", err)
	}
}

func TestCleanCodeAndEndpoints(t *testing.T) {
	for in, want := range map[string]string{
		"Throttling;Sender": "Throttling",
		"com.amazonaws.cloudwatch#LimitExceededException": "LimitExceededException",
		"AccessDeniedException:http://internal":           "AccessDeniedException",
		"":                                                "",
	} {
		if got := cleanCode(in); got != want {
			t.Errorf("cleanCode(%q) = %q", in, got)
		}
	}
	if got := Endpoint("cloudtrail", "eu-west-1"); got != "https://cloudtrail.eu-west-1.amazonaws.com" {
		t.Error(got)
	}
	if got := Endpoint("monitoring", "cn-north-1"); got != "https://monitoring.cn-north-1.amazonaws.com.cn" {
		t.Error(got)
	}
	ts := Seconds(1792058403.25).Time()
	if want := time.Date(2026, 10, 15, 10, 0, 3, 250e6, time.UTC); !ts.Equal(want) {
		t.Errorf("Seconds = %v, want %v", ts, want)
	}
}
