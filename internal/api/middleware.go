package api

// HTTP middleware: request ids, access log, security headers, compression,
// ETags, a response cache, rate and concurrency limits, timeouts, metrics
// and authentication. Each constructor returns a func(http.Handler)
// http.Handler; Compose chains them.
//
// A sensible order, outermost first:
//
//	WithRequestID, WithAccessLog, WithSecurityHeaders, WithAuthentication,
//	WithRateLimit, WithMaxInflight
//
// around the mux, and per route:
//
//	WithMetrics(route), WithTimeout(d), WithETag, ResponseCache.Middleware, WithGzip
//
// The response cache sits outside gzip so it stores compressed bodies (its
// key includes the accepted encoding) and inside the ETag check so a cached
// response's ETag is reused instead of re-hashing the body.

import (
	"bytes"
	"compress/gzip"
	"container/list"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"math"
	"mime"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ByronGary/kubesentry/internal/auth"
	"github.com/ByronGary/kubesentry/internal/metrics"
)

// Compose returns one middleware that applies mws in order, the first
// outermost.
func Compose(mws ...func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		for i := len(mws) - 1; i >= 0; i-- {
			if mws[i] != nil {
				h = mws[i](h)
			}
		}
		return h
	}
}

// requestInfo is shared by the middleware of one request so the access log,
// which runs outermost, learns what inner layers found out (identity, route)
// even though they see a copy of the request.
type requestInfo struct {
	mu          sync.Mutex
	id          string
	route       string
	identity    auth.Identity
	hasIdentity bool
}

type requestInfoKey struct{}

func requestInfoFrom(ctx context.Context) *requestInfo {
	ri, _ := ctx.Value(requestInfoKey{}).(*requestInfo)
	return ri
}

// withRequestInfo returns r carrying a requestInfo, adding one if needed.
func withRequestInfo(r *http.Request) (*http.Request, *requestInfo) {
	if ri := requestInfoFrom(r.Context()); ri != nil {
		return r, ri
	}
	ri := &requestInfo{}
	return r.WithContext(context.WithValue(r.Context(), requestInfoKey{}, ri)), ri
}

func (ri *requestInfo) setRoute(route string) {
	ri.mu.Lock()
	ri.route = route
	ri.mu.Unlock()
}

func (ri *requestInfo) setIdentity(id auth.Identity) {
	ri.mu.Lock()
	ri.identity, ri.hasIdentity = id, true
	ri.mu.Unlock()
}

// RequestID returns the id WithRequestID gave the request, or "".
func RequestID(ctx context.Context) string {
	if ri := requestInfoFrom(ctx); ri != nil {
		ri.mu.Lock()
		defer ri.mu.Unlock()
		return ri.id
	}
	return ""
}

var (
	requestIDPrefix = func() string {
		b := make([]byte, 6)
		_, _ = rand.Read(b)
		return hex.EncodeToString(b)
	}()
	requestIDSeq atomic.Uint64
)

func newRequestID() string {
	return requestIDPrefix + "-" + strconv.FormatUint(requestIDSeq.Add(1), 36)
}

// validRequestID accepts a caller-supplied id only if it is short and plain,
// so it cannot inject anything into logs or headers.
func validRequestID(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == ':') {
			return false
		}
	}
	return true
}

// WithRequestID gives every request an id, taken from a well-formed
// X-Request-Id header (set by a proxy) or generated, and echoes it in the
// response's X-Request-Id header. RequestID reads it back.
func WithRequestID() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.Header.Get("X-Request-Id")
			if !validRequestID(id) {
				id = newRequestID()
			}
			r, ri := withRequestInfo(r)
			ri.mu.Lock()
			ri.id = id
			ri.mu.Unlock()
			w.Header().Set("X-Request-Id", id)
			next.ServeHTTP(w, r)
		})
	}
}

// statusWriter records the status and size of a response.
type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (s *statusWriter) WriteHeader(code int) {
	if s.status == 0 && code >= 200 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(p []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	n, err := s.ResponseWriter.Write(p)
	s.bytes += int64(n)
	return n, err
}

func (s *statusWriter) Flush() {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func (s *statusWriter) code() int {
	if s.status == 0 {
		return http.StatusOK // nothing written: net/http sends 200
	}
	return s.status
}

// WithAccessLog logs one structured line per request: request id, the
// caller's user and how they authenticated, method, route pattern, path,
// status, response bytes and duration. A nil logger uses slog.Default().
func WithAccessLog(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			r, ri := withRequestInfo(r)
			sw := &statusWriter{ResponseWriter: w}
			next.ServeHTTP(sw, r)
			l := logger
			if l == nil {
				l = slog.Default()
			}
			ri.mu.Lock()
			id, route, ident, hasIdent := ri.id, ri.route, ri.identity, ri.hasIdentity
			ri.mu.Unlock()
			if route == "" {
				route = r.Pattern // set by the mux when no layer in between copied r
			}
			var user, source string
			if hasIdent {
				user, source = ident.User, ident.Source
			}
			l.LogAttrs(r.Context(), slog.LevelInfo, "http request",
				slog.String("id", id),
				slog.String("user", user),
				slog.String("source", source),
				slog.String("method", r.Method),
				slog.String("route", route),
				slog.String("path", r.URL.Path),
				slog.Int("status", sw.code()),
				slog.Int64("bytes", sw.bytes),
				slog.Duration("duration", time.Since(start)),
			)
		})
	}
}

// ContentSecurityPolicy is the policy WithSecurityHeaders sets. The UI loads
// only its own script and stylesheet; inline styles set from script (React
// style props) are not affected by style-src.
const ContentSecurityPolicy = "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"

// WithSecurityHeaders sets the CSP and the usual hardening headers on every
// response. Handlers may override them.
func WithSecurityHeaders() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("Content-Security-Policy", ContentSecurityPolicy)
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("Referrer-Policy", "no-referrer")
			h.Set("X-Frame-Options", "DENY")
			next.ServeHTTP(w, r)
		})
	}
}

// WithAuthentication authenticates every request. On success the Identity
// is stored in the request context (auth.FromContext). Without one, /api/
// routes answer 401 {"error":"unauthorized"}; other paths (the UI's static
// files, /healthz, /readyz and any listed in open) pass through without an
// identity. Routes that accept pushed data keep their own token guards.
func WithAuthentication(authn auth.Authenticator, open ...string) func(http.Handler) http.Handler {
	openPaths := map[string]bool{"/healthz": true, "/readyz": true}
	for _, p := range open {
		openPaths[p] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if authn != nil {
				if id, ok := authn.Authenticate(r); ok {
					if ri := requestInfoFrom(r.Context()); ri != nil {
						ri.setIdentity(id)
					}
					next.ServeHTTP(w, r.WithContext(auth.WithIdentity(r.Context(), id)))
					return
				}
			}
			p := r.URL.Path
			if (p == "/api" || strings.HasPrefix(p, "/api/")) && !openPaths[p] {
				metrics.HTTPRejected.With("unauthenticated").Inc()
				w.Header().Set("WWW-Authenticate", "Bearer")
				writeError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// rateKey identifies the caller for rate limiting: the authenticated user,
// else the remote address.
func rateKey(r *http.Request) string {
	if id, ok := auth.FromContext(r.Context()); ok {
		return "id:" + id.Source + "|" + id.User
	}
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		return "ip:" + ap.Addr().Unmap().String()
	}
	return "ip:" + r.RemoteAddr
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

type rateLimiter struct {
	mu        sync.Mutex
	rate      float64 // tokens per second
	burst     float64
	buckets   map[string]*tokenBucket
	lastSweep time.Time
	now       func() time.Time
}

// allow takes a token for key, or says how long until one is available.
func (l *rateLimiter) allow(key string) (bool, time.Duration) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.lastSweep) > time.Minute {
		l.sweep(now)
	}
	b, ok := l.buckets[key]
	if !ok {
		b = &tokenBucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	if el := now.Sub(b.last).Seconds(); el > 0 {
		b.tokens = math.Min(l.burst, b.tokens+el*l.rate)
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	return false, time.Duration((1 - b.tokens) / l.rate * float64(time.Second))
}

// sweep drops buckets that have refilled completely: they are
// indistinguishable from new ones.
func (l *rateLimiter) sweep(now time.Time) {
	l.lastSweep = now
	full := time.Duration(l.burst / l.rate * float64(time.Second))
	for k, b := range l.buckets {
		if now.Sub(b.last) >= full {
			delete(l.buckets, k)
		}
	}
}

// WithRateLimit limits each caller (the authenticated user, else the remote
// address) to perIdentityRPS requests per second with bursts of burst, and
// answers 429 with Retry-After beyond that. Put it inside WithAuthentication.
// A non-positive rate disables it.
func WithRateLimit(perIdentityRPS float64, burst int) func(http.Handler) http.Handler {
	if perIdentityRPS <= 0 {
		return func(next http.Handler) http.Handler { return next }
	}
	l := &rateLimiter{rate: perIdentityRPS, burst: math.Max(1, float64(burst)), buckets: map[string]*tokenBucket{}, now: time.Now}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ok, wait := l.allow(rateKey(r))
			if !ok {
				metrics.HTTPRejected.With("rate_limit").Inc()
				w.Header().Set("Retry-After", strconv.Itoa(max(1, int(math.Ceil(wait.Seconds())))))
				writeError(w, http.StatusTooManyRequests, "rate limited")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// WithMaxInflight serves at most n requests at once and answers 503 with
// Retry-After to the rest instead of queueing them. n <= 0 disables it.
func WithMaxInflight(n int) func(http.Handler) http.Handler {
	if n <= 0 {
		return func(next http.Handler) http.Handler { return next }
	}
	sem := make(chan struct{}, n)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
				next.ServeHTTP(w, r)
			default:
				metrics.HTTPRejected.With("max_inflight").Inc()
				w.Header().Set("Retry-After", "1")
				writeError(w, http.StatusServiceUnavailable, "server busy")
			}
		})
	}
}

// identityInflight counts each identity's requests in flight.
type identityInflight struct {
	mu   sync.Mutex
	max  int
	busy map[string]int
}

// WithIdentityInflight lets each caller (the authenticated user, else the
// remote address) have at most n requests in flight through the handlers it
// wraps, together, and answers 429 with Retry-After to the rest instead of
// queueing them. Use one instance around the expensive routes, so a single
// user cannot hold many slow queries at once. n <= 0 disables it.
func WithIdentityInflight(n int) func(http.Handler) http.Handler {
	if n <= 0 {
		return func(next http.Handler) http.Handler { return next }
	}
	l := &identityInflight{max: n, busy: map[string]int{}}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := rateKey(r)
			l.mu.Lock()
			if l.busy[key] >= l.max {
				l.mu.Unlock()
				w.Header().Set("Retry-After", "1")
				writeError(w, http.StatusTooManyRequests, "too many expensive requests in flight; retry when one finishes")
				return
			}
			l.busy[key]++
			l.mu.Unlock()
			defer func() {
				l.mu.Lock()
				if l.busy[key]--; l.busy[key] <= 0 {
					delete(l.busy, key) // the map holds only callers with requests in flight
				}
				l.mu.Unlock()
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// timeoutWriter buffers a handler's response so WithTimeout can replace it
// with a 503 if the deadline passes first.
type timeoutWriter struct {
	mu          sync.Mutex
	h           http.Header
	buf         bytes.Buffer
	code        int
	wroteHeader bool
	timedOut    bool
}

func (t *timeoutWriter) Header() http.Header { return t.h }

func (t *timeoutWriter) WriteHeader(code int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.timedOut || t.wroteHeader || code < 200 {
		return
	}
	t.code, t.wroteHeader = code, true
}

func (t *timeoutWriter) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.timedOut {
		return 0, http.ErrHandlerTimeout
	}
	if !t.wroteHeader {
		t.code, t.wroteHeader = http.StatusOK, true
	}
	return t.buf.Write(p)
}

// WithTimeout bounds a route: the handler's context ends after d, and if the
// handler has not finished by then the client gets 503 {"error":"timeout"}.
// The response is buffered (no streaming through it). d <= 0 disables it.
func WithTimeout(d time.Duration) func(http.Handler) http.Handler {
	if d <= 0 {
		return func(next http.Handler) http.Handler { return next }
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), d)
			defer cancel()
			r = r.WithContext(ctx)
			tw := &timeoutWriter{h: make(http.Header)}
			done := make(chan struct{})
			panicked := make(chan any, 1)
			go func() {
				defer func() {
					if p := recover(); p != nil {
						panicked <- p
						return
					}
					close(done)
				}()
				next.ServeHTTP(tw, r)
			}()
			select {
			case p := <-panicked:
				panic(p)
			case <-done:
				tw.mu.Lock()
				defer tw.mu.Unlock()
				dst := w.Header()
				for k, vv := range tw.h {
					dst[k] = vv
				}
				if !tw.wroteHeader {
					tw.code = http.StatusOK
				}
				w.WriteHeader(tw.code)
				_, _ = w.Write(tw.buf.Bytes())
			case <-ctx.Done():
				tw.mu.Lock()
				tw.timedOut = true
				tw.mu.Unlock()
				if errors.Is(ctx.Err(), context.DeadlineExceeded) {
					writeError(w, http.StatusServiceUnavailable, "timeout")
				}
			}
		})
	}
}

// WithMetrics records kubesentry_http_requests_total{route,code},
// kubesentry_http_request_duration_seconds{route} and
// kubesentry_http_inflight. Wrap each route with its own fixed route name
// (never a raw path). An empty route uses the mux pattern when known.
func WithMetrics(route string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			metrics.Inflight.Inc()
			defer metrics.Inflight.Dec()
			if ri := requestInfoFrom(r.Context()); ri != nil && route != "" {
				ri.setRoute(route)
			}
			sw := &statusWriter{ResponseWriter: w}
			next.ServeHTTP(sw, r)
			name := route
			if name == "" {
				if name = r.Pattern; name == "" {
					name = "other"
				}
			}
			metrics.HTTPRequests.With(name, strconv.Itoa(sw.code())).Inc()
			metrics.HTTPDuration.With(name).Observe(time.Since(start).Seconds())
		})
	}
}

// acceptsGzip reports whether the request's Accept-Encoding allows gzip.
func acceptsGzip(r *http.Request) bool {
	for _, v := range r.Header.Values("Accept-Encoding") {
		for _, part := range strings.Split(v, ",") {
			coding, params, _ := strings.Cut(strings.TrimSpace(part), ";")
			coding = strings.ToLower(strings.TrimSpace(coding))
			if coding != "gzip" && coding != "*" {
				continue
			}
			q := 1.0
			for _, p := range strings.Split(params, ";") {
				if k, val, ok := strings.Cut(strings.TrimSpace(p), "="); ok && strings.EqualFold(strings.TrimSpace(k), "q") {
					if f, err := strconv.ParseFloat(strings.TrimSpace(val), 64); err == nil {
						q = f
					}
				}
			}
			if q > 0 {
				return true
			}
		}
	}
	return false
}

// compressible reports whether a Content-Type is worth gzipping.
func compressible(contentType string) bool {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	switch {
	case strings.HasPrefix(mt, "text/"),
		mt == "application/json", mt == "application/javascript", mt == "application/xml",
		mt == "application/x-ndjson", mt == "image/svg+xml",
		strings.HasSuffix(mt, "+json"), strings.HasSuffix(mt, "+xml"):
		return true
	}
	return false
}

const (
	gzipMinBytes = 1024 // smaller bodies are sent as they are
	gzipLevel    = 5
)

var gzipPool = sync.Pool{New: func() any {
	zw, _ := gzip.NewWriterLevel(io.Discard, gzipLevel)
	return zw
}}

// gzipWriter compresses a response once it knows the content type and that
// the body is large enough to be worth it.
type gzipWriter struct {
	http.ResponseWriter
	head    bool
	status  int
	decided bool
	zw      *gzip.Writer // set when compressing
	buf     []byte       // held back until gzipMinBytes or the end
}

func (g *gzipWriter) WriteHeader(code int) {
	if code < 200 {
		g.ResponseWriter.WriteHeader(code)
		return
	}
	if g.status == 0 {
		g.status = code
	}
}

// eligible decides from status and headers alone whether compressing is allowed.
func (g *gzipWriter) eligible() bool {
	h := g.ResponseWriter.Header()
	st := g.status
	if st == 0 {
		st = http.StatusOK
	}
	return !g.head && st != http.StatusNoContent && st != http.StatusNotModified && st != http.StatusPartialContent &&
		h.Get("Content-Encoding") == "" && h.Get("Content-Range") == "" && compressible(h.Get("Content-Type"))
}

// start commits the headers, compressing or not.
func (g *gzipWriter) start(compress bool) {
	g.decided = true
	if g.status == 0 {
		g.status = http.StatusOK
	}
	if compress {
		h := g.ResponseWriter.Header()
		h.Set("Content-Encoding", "gzip")
		h.Del("Content-Length")
		h.Del("Accept-Ranges")
		g.zw = gzipPool.Get().(*gzip.Writer)
		g.zw.Reset(g.ResponseWriter)
	}
	g.ResponseWriter.WriteHeader(g.status)
}

func (g *gzipWriter) Write(p []byte) (int, error) {
	if !g.decided {
		h := g.ResponseWriter.Header()
		if h.Get("Content-Type") == "" && len(g.buf) == 0 {
			h.Set("Content-Type", http.DetectContentType(p))
		}
		if !g.eligible() {
			g.start(false)
		} else {
			g.buf = append(g.buf, p...)
			if len(g.buf) < gzipMinBytes {
				return len(p), nil
			}
			g.start(true)
			if _, err := g.zw.Write(g.buf); err != nil {
				return 0, err
			}
			g.buf = nil
			return len(p), nil
		}
	}
	if g.zw != nil {
		return g.zw.Write(p)
	}
	return g.ResponseWriter.Write(p)
}

func (g *gzipWriter) Flush() {
	if !g.decided {
		g.start(g.eligible() && len(g.buf) > 0)
		if len(g.buf) > 0 {
			if g.zw != nil {
				_, _ = g.zw.Write(g.buf)
			} else {
				_, _ = g.ResponseWriter.Write(g.buf)
			}
			g.buf = nil
		}
	}
	if g.zw != nil {
		_ = g.zw.Flush()
	}
	if f, ok := g.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (g *gzipWriter) Unwrap() http.ResponseWriter { return g.ResponseWriter }

// finish sends whatever is held back and closes the gzip stream.
func (g *gzipWriter) finish() {
	if !g.decided {
		if g.status == 0 && len(g.buf) == 0 {
			return // the handler wrote nothing; net/http sends its default 200
		}
		g.start(false)
		if len(g.buf) > 0 {
			_, _ = g.ResponseWriter.Write(g.buf)
		}
		return
	}
	if g.zw != nil {
		_ = g.zw.Close()
		g.zw.Reset(io.Discard)
		gzipPool.Put(g.zw)
		g.zw = nil
	}
}

// WithGzip compresses responses with a compressible content type (text,
// JSON, JavaScript, SVG, XML) of at least 1 KiB when the client accepts
// gzip, and adds Vary: Accept-Encoding.
func WithGzip() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("Vary", "Accept-Encoding")
			if !acceptsGzip(r) {
				next.ServeHTTP(w, r)
				return
			}
			g := &gzipWriter{ResponseWriter: w, head: r.Method == http.MethodHead}
			defer g.finish()
			next.ServeHTTP(g, r)
		})
	}
}

// bodyETag is a strong validator derived from the body. It is the same on
// every replica for the same bytes.
func bodyETag(body []byte) string {
	sum := sha256.Sum256(body)
	return `"` + base64.RawURLEncoding.EncodeToString(sum[:18]) + `"`
}

// etagMatches implements If-None-Match's weak comparison.
func etagMatches(ifNoneMatch, etag string) bool {
	if ifNoneMatch == "" || etag == "" {
		return false
	}
	want := strings.TrimPrefix(etag, "W/")
	for _, cand := range strings.Split(ifNoneMatch, ",") {
		cand = strings.TrimSpace(cand)
		if cand == "*" || strings.TrimPrefix(cand, "W/") == want {
			return true
		}
	}
	return false
}

// etagWriter holds a 200 response back to compute its ETag. If the handler
// sets an ETag itself (the response cache does), the body is not hashed.
type etagWriter struct {
	http.ResponseWriter
	r           *http.Request
	status      int
	wroteHeader bool
	passthrough bool // headers sent; writes go straight out
	discard     bool // 304 sent; writes are dropped
	buf         bytes.Buffer
}

func (e *etagWriter) WriteHeader(code int) {
	if code < 200 {
		e.ResponseWriter.WriteHeader(code)
		return
	}
	if e.wroteHeader {
		return
	}
	e.status, e.wroteHeader = code, true
	if code != http.StatusOK {
		e.commit()
		return
	}
	if et := e.ResponseWriter.Header().Get("ETag"); et != "" {
		e.setCacheControl()
		if etagMatches(e.r.Header.Get("If-None-Match"), et) {
			e.notModified()
		} else {
			e.commit()
		}
	}
}

func (e *etagWriter) setCacheControl() {
	h := e.ResponseWriter.Header()
	if h.Get("Cache-Control") == "" {
		// Per-user responses: browsers revalidate, shared caches do not store.
		h.Set("Cache-Control", "private, no-cache")
	}
}

func (e *etagWriter) notModified() {
	e.discard = true
	h := e.ResponseWriter.Header()
	h.Del("Content-Length")
	h.Del("Content-Type")
	h.Del("Content-Encoding")
	e.ResponseWriter.WriteHeader(http.StatusNotModified)
}

func (e *etagWriter) commit() {
	e.passthrough = true
	e.ResponseWriter.WriteHeader(e.status)
	if e.buf.Len() > 0 {
		_, _ = e.ResponseWriter.Write(e.buf.Bytes())
		e.buf.Reset()
	}
}

func (e *etagWriter) Write(p []byte) (int, error) {
	if !e.wroteHeader {
		e.WriteHeader(http.StatusOK)
	}
	switch {
	case e.discard:
		return len(p), nil
	case e.passthrough:
		return e.ResponseWriter.Write(p)
	}
	return e.buf.Write(p)
}

func (e *etagWriter) Flush() {
	if !e.wroteHeader {
		e.WriteHeader(http.StatusOK)
	}
	if !e.passthrough && !e.discard {
		e.commit() // streaming: no ETag
	}
	if f, ok := e.ResponseWriter.(http.Flusher); ok && !e.discard {
		f.Flush()
	}
}

func (e *etagWriter) Unwrap() http.ResponseWriter { return e.ResponseWriter }

func (e *etagWriter) finish() {
	if !e.wroteHeader || e.passthrough || e.discard {
		return
	}
	body := e.buf.Bytes()
	h := e.ResponseWriter.Header()
	et := bodyETag(body)
	h.Set("ETag", et)
	e.setCacheControl()
	if etagMatches(e.r.Header.Get("If-None-Match"), et) {
		e.notModified()
		return
	}
	e.ResponseWriter.WriteHeader(e.status)
	_, _ = e.ResponseWriter.Write(body)
}

// WithETag adds a strong ETag (a hash of the body) to 200 responses to GET
// and HEAD, and answers 304 Not Modified when If-None-Match matches it. It
// also marks those responses Cache-Control: private, no-cache unless the
// handler set Cache-Control.
func WithETag() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				next.ServeHTTP(w, r)
				return
			}
			e := &etagWriter{ResponseWriter: w, r: r}
			next.ServeHTTP(e, r)
			e.finish()
		})
	}
}

// ResponseCache keeps GET responses in memory, LRU, up to MaxBytes. KeyFunc
// decides what may be cached and under which key; the key MUST include
// everything the response depends on: the path and query, the caller's
// authorization scope and the data version (CacheKeyFunc builds exactly
// that). The accepted encoding is added to the key here. Only 200 responses
// without Set-Cookie or Cache-Control: no-store are kept. Concurrent misses
// for one key run the handler once; the others wait and replay its result.
type ResponseCache struct {
	MaxBytes      int64 // total; default 64 MiB
	MaxEntryBytes int64 // one response; default MaxBytes/16
	// TTL bounds an entry's life; 0 keeps it until evicted (keys that carry
	// the view version go stale by themselves).
	TTL     time.Duration
	KeyFunc func(r *http.Request) (key string, ok bool)
	Now     func() time.Time

	mu      sync.Mutex
	ll      list.List
	m       map[string]*list.Element
	size    int64
	flights map[string]chan struct{}
}

type cachedResponse struct {
	key    string
	header http.Header
	body   []byte
	size   int64
	exp    time.Time
}

func (c *ResponseCache) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *ResponseCache) limits() (total, entry int64) {
	total = c.MaxBytes
	if total <= 0 {
		total = 64 << 20
	}
	entry = c.MaxEntryBytes
	if entry <= 0 {
		entry = total / 16
	}
	return total, min(entry, total)
}

// Len returns the number of cached responses.
func (c *ResponseCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}

func (c *ResponseCache) get(key string) *cachedResponse {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.m[key]
	if !ok {
		return nil
	}
	cr := el.Value.(*cachedResponse)
	if !cr.exp.IsZero() && !c.now().Before(cr.exp) {
		c.remove(el)
		return nil
	}
	c.ll.MoveToFront(el)
	return cr
}

func (c *ResponseCache) remove(el *list.Element) {
	cr := el.Value.(*cachedResponse)
	c.ll.Remove(el)
	delete(c.m, cr.key)
	c.size -= cr.size
}

func (c *ResponseCache) put(cr *cachedResponse) {
	total, _ := c.limits()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]*list.Element{}
	}
	if el, ok := c.m[cr.key]; ok {
		c.remove(el)
	}
	c.m[cr.key] = c.ll.PushFront(cr)
	c.size += cr.size
	for c.size > total && c.ll.Len() > 0 {
		c.remove(c.ll.Back())
	}
}

// join registers interest in computing key. It returns a channel to wait on
// when another request is already computing it, or nil when the caller
// leads (and must call leave).
func (c *ResponseCache) join(key string) <-chan struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ch, ok := c.flights[key]; ok {
		return ch
	}
	if c.flights == nil {
		c.flights = map[string]chan struct{}{}
	}
	c.flights[key] = make(chan struct{})
	return nil
}

func (c *ResponseCache) leave(key string) {
	c.mu.Lock()
	ch := c.flights[key]
	delete(c.flights, key)
	c.mu.Unlock()
	if ch != nil {
		close(ch)
	}
}

func replay(w http.ResponseWriter, r *http.Request, cr *cachedResponse, state string) {
	dst := w.Header()
	for k, vv := range cr.header {
		dst[k] = vv
	}
	dst.Set("X-Kubesentry-Cache", state)
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(cr.body)
	}
}

// cacheRecorder captures a response, falling back to passing it through
// when it grows beyond the entry limit or is flushed.
type cacheRecorder struct {
	w           http.ResponseWriter
	h           http.Header
	status      int
	wroteHeader bool
	buf         bytes.Buffer
	limit       int64
	passthrough bool
	onPass      func() // called when the recorder gives up capturing
}

func (rec *cacheRecorder) Header() http.Header {
	if rec.passthrough {
		return rec.w.Header()
	}
	return rec.h
}

func (rec *cacheRecorder) WriteHeader(code int) {
	if code < 200 {
		rec.w.WriteHeader(code)
		return
	}
	if rec.wroteHeader {
		return
	}
	rec.status, rec.wroteHeader = code, true
}

func (rec *cacheRecorder) Write(p []byte) (int, error) {
	if !rec.wroteHeader {
		rec.WriteHeader(http.StatusOK)
	}
	if rec.passthrough {
		return rec.w.Write(p)
	}
	if int64(rec.buf.Len()+len(p)) > rec.limit {
		rec.toPassthrough()
		return rec.w.Write(p)
	}
	return rec.buf.Write(p)
}

func (rec *cacheRecorder) Flush() {
	if !rec.wroteHeader {
		rec.WriteHeader(http.StatusOK)
	}
	if !rec.passthrough {
		rec.toPassthrough()
	}
	if f, ok := rec.w.(http.Flusher); ok {
		f.Flush()
	}
}

func (rec *cacheRecorder) Unwrap() http.ResponseWriter { return rec.w }

func (rec *cacheRecorder) toPassthrough() {
	rec.passthrough = true
	if rec.onPass != nil {
		rec.onPass()
	}
	dst := rec.w.Header()
	for k, vv := range rec.h {
		dst[k] = vv
	}
	rec.w.WriteHeader(rec.status)
	if rec.buf.Len() > 0 {
		_, _ = rec.w.Write(rec.buf.Bytes())
		rec.buf.Reset()
	}
}

func storable(status int, h http.Header) bool {
	if status != http.StatusOK || h.Get("Set-Cookie") != "" {
		return false
	}
	for _, v := range h.Values("Cache-Control") {
		if strings.Contains(strings.ToLower(v), "no-store") {
			return false
		}
	}
	return true
}

// Middleware returns the caching handler around next.
func (c *ResponseCache) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if (r.Method != http.MethodGet && r.Method != http.MethodHead) || c.KeyFunc == nil {
			next.ServeHTTP(w, r)
			return
		}
		base, ok := c.KeyFunc(r)
		if !ok {
			metrics.HTTPCache.With("skip").Inc()
			next.ServeHTTP(w, r)
			return
		}
		key := base + "\x00identity"
		if acceptsGzip(r) {
			key = base + "\x00gzip"
		}
		if cr := c.get(key); cr != nil {
			metrics.HTTPCache.With("hit").Inc()
			replay(w, r, cr, "hit")
			return
		}
		if r.Method == http.MethodHead {
			metrics.HTTPCache.With("skip").Inc()
			next.ServeHTTP(w, r)
			return
		}
		if wait := c.join(key); wait != nil {
			select {
			case <-wait:
			case <-r.Context().Done():
				return
			}
			if cr := c.get(key); cr != nil {
				metrics.HTTPCache.With("coalesced").Inc()
				replay(w, r, cr, "hit")
				return
			}
			metrics.HTTPCache.With("miss").Inc()
			c.serve(w, r, next, key, false)
			return
		}
		metrics.HTTPCache.With("miss").Inc()
		c.serve(w, r, next, key, true)
	})
}

// serve runs the handler, stores a cacheable result and writes it out. A
// leader releases the requests waiting on it as soon as the entry is stored
// (or cannot be), before writing to its own, possibly slow, client.
func (c *ResponseCache) serve(w http.ResponseWriter, r *http.Request, next http.Handler, key string, leader bool) {
	release := func() {
		if leader {
			leader = false
			c.leave(key)
		}
	}
	defer release()
	_, entryLimit := c.limits()
	rec := &cacheRecorder{w: w, h: make(http.Header), limit: entryLimit, onPass: release}
	next.ServeHTTP(rec, r)
	if rec.passthrough {
		return
	}
	if !rec.wroteHeader {
		rec.status = http.StatusOK
	}
	body := rec.buf.Bytes()
	// A response built while an authorization lookup failed shows the
	// caller less than they may see (lookups fail closed): serve it, but
	// never keep it for others.
	if storable(rec.status, rec.h) && !authzFailed(r.Context()) {
		if rec.h.Get("ETag") == "" {
			rec.h.Set("ETag", bodyETag(body))
		}
		cr := &cachedResponse{key: key, header: rec.h.Clone(), body: bytes.Clone(body)}
		cr.size = int64(len(cr.body) + len(key) + 256)
		for k, vv := range cr.header {
			cr.size += int64(len(k))
			for _, v := range vv {
				cr.size += int64(len(v))
			}
		}
		if c.TTL > 0 {
			cr.exp = c.now().Add(c.TTL)
		}
		c.put(cr)
		rec.h.Set("X-Kubesentry-Cache", "miss")
	}
	release()
	dst := w.Header()
	for k, vv := range rec.h {
		dst[k] = vv
	}
	w.WriteHeader(rec.status)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}
