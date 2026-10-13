package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/auth"
	"github.com/ByronGary/kubesentry/internal/metrics"
)

// mwIdentityHeader is a test authenticator: X-Test-User names the caller.
type mwTestAuthn struct{}

func (mwTestAuthn) Authenticate(r *http.Request) (auth.Identity, bool) {
	u := r.Header.Get("X-Test-User")
	if u == "" {
		return auth.Identity{}, false
	}
	return auth.Identity{User: u, Groups: []string{auth.GroupAuthenticated}, Source: "proxy", Unrestricted: u == "admin"}, true
}

func mwServe(h http.Handler, method, path string, hdr ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Add(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func mwJSON(body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, body)
	})
}

func TestMWRequestID(t *testing.T) {
	var seen string
	h := WithRequestID()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen = RequestID(r.Context()) }))
	w := mwServe(h, "GET", "/")
	id := w.Header().Get("X-Request-Id")
	if id == "" || id != seen {
		t.Fatalf("header %q, context %q", id, seen)
	}
	if w2 := mwServe(h, "GET", "/"); w2.Header().Get("X-Request-Id") == id {
		t.Fatal("ids repeat")
	}
	if w := mwServe(h, "GET", "/", "X-Request-Id", "proxy-abc.123"); w.Header().Get("X-Request-Id") != "proxy-abc.123" || seen != "proxy-abc.123" {
		t.Fatalf("proxy id not kept: %q", w.Header().Get("X-Request-Id"))
	}
	if w := mwServe(h, "GET", "/", "X-Request-Id", "bad id\"{}"); w.Header().Get("X-Request-Id") == "bad id\"{}" {
		t.Fatal("malformed id echoed")
	}
	if RequestID(context.Background()) != "" {
		t.Fatal("id without middleware")
	}
}

func TestMWAccessLog(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	mux := http.NewServeMux()
	mux.Handle("GET /api/v1/pods/{namespace}", WithMetrics("pods")(mwJSON(`{"ok":true}`)))
	mux.Handle("GET /plain", mwJSON(`{}`))
	h := Compose(WithRequestID(), WithAccessLog(logger), WithAuthentication(mwTestAuthn{}))(mux)

	w := mwServe(h, "GET", "/api/v1/pods/team-a", "X-Test-User", "alice@example.com")
	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("%v: %s", err, buf.String())
	}
	want := map[string]any{
		"msg": "http request", "id": w.Header().Get("X-Request-Id"), "user": "alice@example.com", "source": "proxy",
		"method": "GET", "route": "pods", "path": "/api/v1/pods/team-a", "status": float64(200), "bytes": float64(len(`{"ok":true}`)),
	}
	for k, v := range want {
		if rec[k] != v {
			t.Errorf("%s = %v, want %v", k, rec[k], v)
		}
	}
	if _, ok := rec["duration"]; !ok {
		t.Error("no duration")
	}

	// Without WithMetrics the mux pattern is used when the request reaches the
	// mux unchanged; an unauthenticated /api/ call is logged with its 401.
	buf.Reset()
	Compose(WithAccessLog(logger))(mux).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/plain", nil))
	if !strings.Contains(buf.String(), `"route":"GET /plain"`) {
		t.Errorf("pattern fallback: %s", buf.String())
	}
	buf.Reset()
	mwServe(h, "GET", "/api/v1/pods/x")
	if !strings.Contains(buf.String(), `"status":401`) || !strings.Contains(buf.String(), `"user":""`) {
		t.Errorf("401 line: %s", buf.String())
	}
}

func TestMWSecurityHeaders(t *testing.T) {
	w := mwServe(WithSecurityHeaders()(mwJSON("{}")), "GET", "/")
	for k, v := range map[string]string{
		"Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'",
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "no-referrer",
		"X-Frame-Options":         "DENY",
	} {
		if got := w.Header().Get(k); got != v {
			t.Errorf("%s = %q", k, got)
		}
	}
}

func gunzip(t *testing.T, b []byte) string {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestMWGzip(t *testing.T) {
	big := `{"items":"` + strings.Repeat("abcdefgh", 1000) + `"}`
	h := WithGzip()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/big":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Length", strconv.Itoa(len(big)))
			w.Write([]byte(big[:10])) // in pieces
			w.Write([]byte(big[10:]))
		case "/small":
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"a":1}`)
		case "/png":
			w.Header().Set("Content-Type", "image/png")
			w.Write(bytes.Repeat([]byte{1}, 4096))
		case "/sniff":
			io.WriteString(w, "<!doctype html><html>"+strings.Repeat("x", 2000))
		case "/notmodified":
			w.WriteHeader(http.StatusNotModified)
		case "/empty":
		}
	}))

	w := mwServe(h, "GET", "/big", "Accept-Encoding", "br;q=1, gzip;q=0.8")
	if w.Header().Get("Content-Encoding") != "gzip" || w.Header().Get("Content-Length") != "" {
		t.Fatalf("headers %v", w.Header())
	}
	if got := gunzip(t, w.Body.Bytes()); got != big {
		t.Fatal("body differs after gunzip")
	}
	if w.Body.Len() >= len(big)/4 {
		t.Fatalf("compressed %d of %d", w.Body.Len(), len(big))
	}
	if !strings.Contains(w.Header().Get("Vary"), "Accept-Encoding") {
		t.Fatal("no Vary")
	}

	for _, tc := range []struct {
		path, accept, method string
	}{
		{"/big", "", "GET"},
		{"/big", "gzip;q=0", "GET"},
		{"/big", "identity", "GET"},
		{"/big", "gzip", "HEAD"},
		{"/small", "gzip", "GET"},
		{"/png", "gzip", "GET"},
	} {
		w := mwServe(h, tc.method, tc.path, "Accept-Encoding", tc.accept)
		if w.Header().Get("Content-Encoding") != "" {
			t.Errorf("%s %s accept %q: compressed", tc.method, tc.path, tc.accept)
		}
		if tc.method == "GET" && tc.path == "/big" && w.Body.String() != big {
			t.Errorf("%s accept %q: body mangled", tc.path, tc.accept)
		}
	}
	if w := mwServe(h, "GET", "/sniff", "Accept-Encoding", "gzip"); w.Header().Get("Content-Encoding") != "gzip" || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
		t.Errorf("sniffed html: %v", w.Header())
	}
	if w := mwServe(h, "GET", "/notmodified", "Accept-Encoding", "gzip"); w.Code != 304 || w.Body.Len() != 0 || w.Header().Get("Content-Encoding") != "" {
		t.Errorf("304: %d %v", w.Code, w.Header())
	}
	if w := mwServe(h, "GET", "/empty", "Accept-Encoding", "gzip"); w.Code != 200 || w.Body.Len() != 0 {
		t.Errorf("empty: %d %q", w.Code, w.Body.String())
	}
}

func TestMWETag(t *testing.T) {
	var calls atomic.Int64
	h := WithETag()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		switch r.URL.Path {
		case "/own":
			w.Header().Set("ETag", `"v1"`)
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"own":true}`)
		case "/missing":
			writeError(w, http.StatusNotFound, "not found")
		default:
			if r.Method == "POST" {
				w.WriteHeader(http.StatusCreated)
			}
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"a":1}`)
		}
	}))
	w := mwServe(h, "GET", "/x")
	et := w.Header().Get("ETag")
	if w.Code != 200 || et == "" || w.Body.String() != `{"a":1}` || w.Header().Get("Cache-Control") != "private, no-cache" {
		t.Fatalf("%d %q %q %v", w.Code, et, w.Body.String(), w.Header())
	}
	w = mwServe(h, "GET", "/x", "If-None-Match", et)
	if w.Code != http.StatusNotModified || w.Body.Len() != 0 || w.Header().Get("ETag") != et {
		t.Fatalf("revalidation: %d %q", w.Code, w.Body.String())
	}
	if w := mwServe(h, "GET", "/x", "If-None-Match", `"other", W/`+et); w.Code != 304 {
		t.Fatalf("weak/list match: %d", w.Code)
	}
	if w := mwServe(h, "GET", "/x", "If-None-Match", `"other"`); w.Code != 200 || w.Body.String() != `{"a":1}` {
		t.Fatalf("mismatch: %d", w.Code)
	}
	if w := mwServe(h, "GET", "/own", "If-None-Match", `"v1"`); w.Code != 304 {
		t.Fatalf("handler ETag: %d", w.Code)
	}
	if w := mwServe(h, "GET", "/own"); w.Header().Get("ETag") != `"v1"` || w.Body.String() != `{"own":true}` {
		t.Fatalf("handler ETag replaced: %v", w.Header())
	}
	if w := mwServe(h, "GET", "/missing"); w.Code != 404 || w.Header().Get("ETag") != "" || !strings.Contains(w.Body.String(), "not found") {
		t.Fatalf("404: %d %v", w.Code, w.Header())
	}
	if w := mwServe(h, "POST", "/x"); w.Code != 201 || w.Header().Get("ETag") != "" {
		t.Fatalf("POST: %d %v", w.Code, w.Header())
	}
}

func TestMWRateLimit(t *testing.T) {
	rejected := metrics.HTTPRejected.With("rate_limit").Value()
	h := Compose(WithAuthentication(mwTestAuthn{}), WithRateLimit(0.001, 2))(mwJSON("{}"))
	for i := range 2 {
		if w := mwServe(h, "GET", "/api/v1/x", "X-Test-User", "alice"); w.Code != 200 {
			t.Fatalf("request %d: %d", i, w.Code)
		}
	}
	w := mwServe(h, "GET", "/api/v1/x", "X-Test-User", "alice")
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("third request: %d", w.Code)
	}
	if ra, _ := strconv.Atoi(w.Header().Get("Retry-After")); ra < 1 {
		t.Fatalf("Retry-After %q", w.Header().Get("Retry-After"))
	}
	if !strings.Contains(w.Body.String(), `"error":"rate limited"`) {
		t.Fatalf("body %q", w.Body.String())
	}
	if w := mwServe(h, "GET", "/api/v1/x", "X-Test-User", "bob"); w.Code != 200 {
		t.Fatalf("other identity limited: %d", w.Code)
	}
	// Unauthenticated (open) paths are limited per remote address.
	for range 2 {
		mwServe(h, "GET", "/healthz")
	}
	if w := mwServe(h, "GET", "/healthz"); w.Code != http.StatusTooManyRequests {
		t.Fatalf("ip bucket: %d", w.Code)
	}
	if n := metrics.HTTPRejected.With("rate_limit").Value() - rejected; n != 2 {
		t.Errorf("kubesentry_http_rejected_total{reason=rate_limit} grew by %v, want 2", n)
	}
	if mwServe(WithRateLimit(0, 0)(mwJSON("{}")), "GET", "/").Code != 200 {
		t.Fatal("disabled limiter limited")
	}
}

func TestMWRateLimiterRefillsAndSweeps(t *testing.T) {
	now := time.Unix(0, 0)
	l := &rateLimiter{rate: 2, burst: 2, buckets: map[string]*tokenBucket{}, now: func() time.Time { return now }}
	l.allow("a")
	l.allow("a")
	if ok, wait := l.allow("a"); ok || wait != 500*time.Millisecond {
		t.Fatalf("ok %v wait %v", ok, wait)
	}
	now = now.Add(500 * time.Millisecond)
	if ok, _ := l.allow("a"); !ok {
		t.Fatal("not refilled")
	}
	now = now.Add(2 * time.Minute)
	l.allow("b")
	if _, ok := l.buckets["a"]; ok || len(l.buckets) != 1 {
		t.Fatalf("idle bucket kept: %v", l.buckets)
	}
}

func TestMWMaxInflight(t *testing.T) {
	release := make(chan struct{})
	var started sync.WaitGroup
	started.Add(2)
	h := WithMaxInflight(2)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started.Done()
		<-release
	}))
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); mwServe(h, "GET", "/") }()
	}
	started.Wait()
	rejected := metrics.HTTPRejected.With("max_inflight").Value()
	w := mwServe(h, "GET", "/")
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") != "1" || !strings.Contains(w.Body.String(), "server busy") {
		t.Fatalf("%d %v %q", w.Code, w.Header(), w.Body.String())
	}
	if n := metrics.HTTPRejected.With("max_inflight").Value() - rejected; n != 1 {
		t.Errorf("kubesentry_http_rejected_total{reason=max_inflight} grew by %v, want 1", n)
	}
	close(release)
	wg.Wait()
	started.Add(1)
	if w := mwServe(h, "GET", "/"); w.Code != 200 {
		t.Fatalf("after release: %d", w.Code)
	}
}

func TestMWTimeout(t *testing.T) {
	slow := WithTimeout(20 * time.Millisecond)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
		w.Write([]byte("too late"))
	}))
	w := mwServe(slow, "GET", "/")
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), `"error":"timeout"`) {
		t.Fatalf("%d %q", w.Code, w.Body.String())
	}

	fast := WithTimeout(time.Second)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.Context().Deadline(); !ok {
			t.Error("no deadline")
		}
		w.Header().Set("X-A", "1")
		w.WriteHeader(http.StatusTeapot)
		io.WriteString(w, "short and stout")
	}))
	w = mwServe(fast, "GET", "/")
	if w.Code != http.StatusTeapot || w.Header().Get("X-A") != "1" || w.Body.String() != "short and stout" {
		t.Fatalf("%d %v %q", w.Code, w.Header(), w.Body.String())
	}

	panicky := WithTimeout(time.Second)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") }))
	func() {
		defer func() {
			if p := recover(); p != "boom" {
				t.Fatalf("recovered %v", p)
			}
		}()
		mwServe(panicky, "GET", "/")
	}()
}

func TestMWAuthentication(t *testing.T) {
	var got auth.Identity
	var has bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, has = auth.FromContext(r.Context())
		w.WriteHeader(204)
	})
	h := WithAuthentication(mwTestAuthn{}, "/api/v1/public")(next)

	rejected := metrics.HTTPRejected.With("unauthenticated").Value()
	w := mwServe(h, "GET", "/api/v1/pods")
	if n := metrics.HTTPRejected.With("unauthenticated").Value() - rejected; n != 1 {
		t.Errorf("kubesentry_http_rejected_total{reason=unauthenticated} grew by %v, want 1", n)
	}
	if w.Code != 401 || w.Header().Get("WWW-Authenticate") != "Bearer" || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
	var body map[string]string
	if json.Unmarshal(w.Body.Bytes(), &body); body["error"] != "unauthorized" {
		t.Fatalf("body %q", w.Body.String())
	}
	for _, p := range []string{"/api", "/api/"} {
		if mwServe(h, "GET", p).Code != 401 {
			t.Errorf("%s open", p)
		}
	}
	for _, p := range []string{"/healthz", "/readyz", "/", "/assets/index.js", "/api/v1/public", "/apidocs"} {
		has = true
		if w := mwServe(h, "GET", p); w.Code != 204 || has {
			t.Errorf("%s: %d identity=%v", p, w.Code, has)
		}
	}
	if w := mwServe(h, "GET", "/api/v1/pods", "X-Test-User", "alice"); w.Code != 204 || !has || got.User != "alice" {
		t.Fatalf("%d %v %+v", w.Code, has, got)
	}
	// Authenticated callers carry their identity on open paths too.
	if mwServe(h, "GET", "/healthz", "X-Test-User", "alice"); !has {
		t.Fatal("identity dropped on open path")
	}
	if w := mwServe(WithAuthentication(nil)(next), "GET", "/api/v1/pods"); w.Code != 401 {
		t.Fatalf("nil authenticator: %d", w.Code)
	}
}

func TestMWMetrics(t *testing.T) {
	route := "mw-test-route"
	var inflight float64
	h := WithMetrics(route)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inflight = metrics.Inflight.Value()
		w.WriteHeader(http.StatusTeapot)
	}))
	before := metrics.HTTPRequests.With(route, "418").Value()
	beforeN := metrics.HTTPDuration.With(route).Count()
	mwServe(h, "GET", "/")
	mwServe(h, "GET", "/")
	if d := metrics.HTTPRequests.With(route, "418").Value() - before; d != 2 {
		t.Fatalf("requests +%v", d)
	}
	if d := metrics.HTTPDuration.With(route).Count() - beforeN; d != 2 {
		t.Fatalf("durations +%d", d)
	}
	if inflight < 1 || metrics.Inflight.Value() != 0 {
		t.Fatalf("inflight during %v after %v", inflight, metrics.Inflight.Value())
	}
}

// mwScopeKeyFunc keys by path and an X-Scope header, standing in for a scope key.
func mwScopeKeyFunc(r *http.Request) (string, bool) {
	s := r.Header.Get("X-Scope")
	return r.URL.Path + "|" + s, s != "nocache"
}

func TestResponseCache(t *testing.T) {
	var calls atomic.Int64
	big := strings.Repeat("y", 3000)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		switch r.URL.Path {
		case "/err":
			writeError(w, 502, "upstream")
			return
		case "/cookie":
			w.Header().Set("Set-Cookie", "a=b")
		case "/nostore":
			w.Header().Set("Cache-Control", "no-store")
		case "/big":
			w.Header().Set("Content-Type", "text/plain")
			io.WriteString(w, big)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"path":%q,"scope":%q}`, r.URL.Path, r.Header.Get("X-Scope"))
	})
	c := &ResponseCache{MaxBytes: 64 << 10, MaxEntryBytes: 2048, KeyFunc: mwScopeKeyFunc}
	h := c.Middleware(handler)

	w1 := mwServe(h, "GET", "/a", "X-Scope", "s1")
	w2 := mwServe(h, "GET", "/a", "X-Scope", "s1")
	if calls.Load() != 1 || w1.Body.String() != w2.Body.String() || w2.Header().Get("X-Kubesentry-Cache") != "hit" || w1.Header().Get("X-Kubesentry-Cache") != "miss" {
		t.Fatalf("calls %d, %q vs %q, %v", calls.Load(), w1.Body.String(), w2.Body.String(), w2.Header())
	}
	if w1.Header().Get("ETag") == "" || w1.Header().Get("ETag") != w2.Header().Get("ETag") || w2.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("headers %v / %v", w1.Header(), w2.Header())
	}
	// Another scope never sees the first scope's response.
	if w := mwServe(h, "GET", "/a", "X-Scope", "s2"); !strings.Contains(w.Body.String(), `"scope":"s2"`) || calls.Load() != 2 {
		t.Fatalf("scope leak: %q", w.Body.String())
	}
	// HEAD is answered from a cached GET, without a body.
	if w := mwServe(h, "HEAD", "/a", "X-Scope", "s1"); w.Body.Len() != 0 || w.Header().Get("X-Kubesentry-Cache") != "hit" || calls.Load() != 2 {
		t.Fatalf("HEAD: %q %v", w.Body.String(), w.Header())
	}
	// The accepted encoding is part of the key.
	mwServe(h, "GET", "/a", "X-Scope", "s1", "Accept-Encoding", "gzip")
	if calls.Load() != 3 {
		t.Fatalf("gzip variant shared the identity entry: %d calls", calls.Load())
	}
	// Not cached: errors, cookies, no-store, KeyFunc refusals, other methods, oversized bodies.
	for _, tc := range []struct{ method, path, scope string }{
		{"GET", "/err", "s1"}, {"GET", "/cookie", "s1"}, {"GET", "/nostore", "s1"},
		{"GET", "/a", "nocache"}, {"POST", "/a", "s1"}, {"GET", "/big", "s1"},
	} {
		n := calls.Load()
		w1, w2 := mwServe(h, tc.method, tc.path, "X-Scope", tc.scope), mwServe(h, tc.method, tc.path, "X-Scope", tc.scope)
		if calls.Load()-n != 2 {
			t.Errorf("%s %s scope %s: cached", tc.method, tc.path, tc.scope)
		}
		if w1.Body.String() != w2.Body.String() || w1.Body.Len() == 0 {
			t.Errorf("%s %s: bodies %q / %q", tc.method, tc.path, w1.Body.String(), w2.Body.String())
		}
	}
	if w := mwServe(h, "GET", "/big", "X-Scope", "s1"); w.Body.String() != big || w.Code != 200 {
		t.Fatalf("oversized pass-through: %d %d bytes", w.Code, w.Body.Len())
	}
	if w := mwServe(h, "GET", "/err", "X-Scope", "s1"); w.Code != 502 {
		t.Fatalf("status %d", w.Code)
	}
}

func TestResponseCacheEvictsAndExpires(t *testing.T) {
	now := time.Unix(1000, 0)
	var calls atomic.Int64
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		io.WriteString(w, strings.Repeat("z", 1000))
	})
	c := &ResponseCache{MaxBytes: 5000, MaxEntryBytes: 2000, KeyFunc: mwScopeKeyFunc, TTL: time.Minute, Now: func() time.Time { return now }}
	ch := c.Middleware(h)
	for i := range 10 {
		mwServe(ch, "GET", fmt.Sprintf("/p%d", i), "X-Scope", "s")
	}
	if n := c.Len(); n < 1 || n > 4 {
		t.Fatalf("%d entries for a 5000-byte budget", n)
	}
	n := calls.Load()
	mwServe(ch, "GET", "/p9", "X-Scope", "s") // most recent: still there
	if calls.Load() != n {
		t.Fatal("most recent entry evicted")
	}
	mwServe(ch, "GET", "/p0", "X-Scope", "s") // oldest: evicted
	if calls.Load() != n+1 {
		t.Fatal("oldest entry kept")
	}
	now = now.Add(2 * time.Minute)
	mwServe(ch, "GET", "/p9", "X-Scope", "s")
	if calls.Load() != n+2 {
		t.Fatal("expired entry served")
	}
}

func TestResponseCacheCoalescesMisses(t *testing.T) {
	var calls atomic.Int64
	release := make(chan struct{})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		<-release
		io.WriteString(w, `{"v":1}`)
	})
	c := &ResponseCache{KeyFunc: mwScopeKeyFunc}
	ch := c.Middleware(h)
	var wg sync.WaitGroup
	bodies := make([]string, 50)
	for i := range bodies {
		wg.Add(1)
		go func() {
			defer wg.Done()
			bodies[i] = mwServe(ch, "GET", "/slow", "X-Scope", "s").Body.String()
		}()
	}
	for calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("%d handler calls for 50 concurrent misses", calls.Load())
	}
	for i, b := range bodies {
		if b != `{"v":1}` {
			t.Fatalf("request %d got %q", i, b)
		}
	}
}

// TestMWChain runs the recommended order end to end: a JSON route behind
// authentication, metrics, ETag, the response cache and gzip.
func TestMWChain(t *testing.T) {
	var calls atomic.Int64
	big := `{"items":"` + strings.Repeat("0123456789", 500) + `"}`
	mux := http.NewServeMux()
	cache := &ResponseCache{KeyFunc: CacheKeyFunc(nil, func() uint64 { return 7 })}
	route := Compose(WithMetrics("chain"), WithTimeout(time.Second), WithETag(), cache.Middleware, WithGzip())
	mux.Handle("GET /api/v1/things", route(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, big)
	})))
	h := Compose(WithRequestID(), WithAccessLog(slog.New(slog.NewTextHandler(io.Discard, nil))), WithSecurityHeaders(),
		WithAuthentication(mwTestAuthn{}), WithRateLimit(100, 100), WithMaxInflight(10))(mux)

	if w := mwServe(h, "GET", "/api/v1/things"); w.Code != 401 {
		t.Fatalf("anonymous: %d", w.Code)
	}
	w := mwServe(h, "GET", "/api/v1/things", "X-Test-User", "admin", "Accept-Encoding", "gzip")
	if w.Code != 200 || w.Header().Get("Content-Encoding") != "gzip" || gunzip(t, w.Body.Bytes()) != big {
		t.Fatalf("first: %d %v", w.Code, w.Header())
	}
	et := w.Header().Get("ETag")
	if et == "" || w.Header().Get("X-Request-Id") == "" || w.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("headers %v", w.Header())
	}
	w = mwServe(h, "GET", "/api/v1/things", "X-Test-User", "admin", "Accept-Encoding", "gzip", "If-None-Match", et)
	if w.Code != 304 || w.Body.Len() != 0 || calls.Load() != 1 {
		t.Fatalf("revalidation: %d, %d calls", w.Code, calls.Load())
	}
	w = mwServe(h, "GET", "/api/v1/things", "X-Test-User", "admin")
	if w.Code != 200 || w.Body.String() != big || w.Header().Get("ETag") == et || calls.Load() != 2 {
		t.Fatalf("identity encoding: %d %q, %d calls", w.Code, w.Header().Get("ETag"), calls.Load())
	}
	// A restricted caller with no authorizer configured is not cached (fail closed).
	mwServe(h, "GET", "/api/v1/things", "X-Test-User", "alice")
	mwServe(h, "GET", "/api/v1/things", "X-Test-User", "alice")
	if calls.Load() != 4 {
		t.Fatalf("restricted caller cached without a scope: %d calls", calls.Load())
	}
}
