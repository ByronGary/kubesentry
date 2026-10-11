// Package ks is a small client for the kubesentry HTTP API, with the response
// shapes the harness reads mirrored from internal/api and web/src/types.ts
// (the harness is a separate module and does not import product code).
package ks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Identity authenticates a request. Today kubesentry has one shared bearer
// token; in Phase 2 users sign in through oauth2-proxy, so identities become
// trusted headers or JWTs per virtual user. Load generators take an Identity
// per user so that change needs no rewrite.
type Identity interface {
	// Name labels results ("token", "alice@corp.example", ...).
	Name() string
	// Apply sets credentials on an outgoing request.
	Apply(r *http.Request)
}

// Bearer is the shared API token.
type Bearer struct {
	Label string
	Token string
}

func (b Bearer) Name() string {
	if b.Label != "" {
		return b.Label
	}
	return "token"
}

func (b Bearer) Apply(r *http.Request) {
	if b.Token != "" {
		r.Header.Set("Authorization", "Bearer "+b.Token)
	}
}

// ProxyHeaders is the trusted-header identity oauth2-proxy forwards
// (X-Forwarded-User / X-Forwarded-Groups by default). Phase 2.
type ProxyHeaders struct {
	User   string
	Groups []string
	// UserHeader and GroupsHeader override the header names.
	UserHeader, GroupsHeader string
}

func (p ProxyHeaders) Name() string { return p.User }

func (p ProxyHeaders) Apply(r *http.Request) {
	uh, gh := p.UserHeader, p.GroupsHeader
	if uh == "" {
		uh = "X-Forwarded-User"
	}
	if gh == "" {
		gh = "X-Forwarded-Groups"
	}
	r.Header.Set(uh, p.User)
	if len(p.Groups) > 0 {
		r.Header.Set(gh, strings.Join(p.Groups, ","))
	}
}

// JWT sends a signed ID token as a bearer token (for the oauth2-proxy
// --skip-jwt-bearer-tokens path). Minting is left to the caller. Phase 2.
type JWT struct {
	Subject string
	Token   string
}

func (j JWT) Name() string          { return j.Subject }
func (j JWT) Apply(r *http.Request) { r.Header.Set("Authorization", "Bearer "+j.Token) }

// Client calls kubesentry.
type Client struct {
	Base string
	HTTP *http.Client
}

// NewHTTP returns an http.Client tuned for many concurrent virtual users.
func NewHTTP(timeout time.Duration, maxConns int) *http.Client {
	tr := &http.Transport{
		Proxy:               nil,
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:        maxConns,
		MaxIdleConnsPerHost: maxConns,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
	}
	return &http.Client{Transport: tr, Timeout: timeout}
}

// Response is a raw response with timing.
type Response struct {
	Header  http.Header
	Status  int
	Bytes   int64
	Elapsed time.Duration
	Body    []byte // only when keepBody
	Err     error
}

// Do performs one request and reads the whole body (counting bytes); it keeps
// the body only when keepBody is set.
func (c *Client) Do(ctx context.Context, id Identity, method, path string, body []byte, contentType string, keepBody bool) Response {
	h := map[string]string{}
	if contentType != "" {
		h["Content-Type"] = contentType
	}
	return c.DoH(ctx, id, method, path, body, h, keepBody)
}

// DoH is Do with extra headers; path may also be an absolute URL.
func (c *Client) DoH(ctx context.Context, id Identity, method, path string, body []byte, headers map[string]string, keepBody bool) Response {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	u := c.Base + path
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		u = path
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return Response{Err: err}
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Accept", "application/json")
	if id != nil {
		id.Apply(req)
	}
	start := time.Now()
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return Response{Err: err, Elapsed: time.Since(start)}
	}
	defer resp.Body.Close()
	r := Response{Status: resp.StatusCode, Header: resp.Header}
	if keepBody {
		var buf bytes.Buffer
		r.Bytes, err = io.Copy(&buf, resp.Body)
		r.Body = buf.Bytes()
	} else {
		r.Bytes, err = io.Copy(io.Discard, resp.Body)
	}
	r.Elapsed = time.Since(start)
	r.Err = err
	return r
}

// GetJSON fetches path and decodes it into v. A 429 (the per-identity rate
// limit) is retried after its Retry-After, up to ten times: the verifiers
// measure correctness, not throughput.
func (c *Client) GetJSON(ctx context.Context, id Identity, path string, v any) (Response, error) {
	r := c.Do(ctx, id, http.MethodGet, path, nil, "", true)
	for attempt := 0; attempt < 10 && r.Err == nil && r.Status == http.StatusTooManyRequests; attempt++ {
		wait := time.Second
		if s := r.Header.Get("Retry-After"); s != "" {
			var n int
			if _, err := fmt.Sscan(s, &n); err == nil && n > 0 {
				wait = time.Duration(n) * time.Second
			}
		}
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return r, ctx.Err()
		}
		r = c.Do(ctx, id, http.MethodGet, path, nil, "", true)
	}
	if r.Err != nil {
		return r, r.Err
	}
	if r.Status != http.StatusOK {
		msg := string(r.Body)
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return r, fmt.Errorf("GET %s: HTTP %d: %s", path, r.Status, msg)
	}
	if err := json.Unmarshal(r.Body, v); err != nil {
		return r, fmt.Errorf("GET %s: decode: %w", path, err)
	}
	r.Body = nil
	return r, nil
}

// Response shapes (subset), mirrored from internal/api and internal/detectors.

type Info struct {
	Demo      bool `json:"demo"`
	Metrics   bool `json:"metrics"`
	Audit     bool `json:"audit"`
	Processes bool `json:"processes"`
	Inventory bool `json:"inventory"`
	Certs     bool `json:"certs"`
}

type GraphNode struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
	Status    string `json:"status"`
	Detail    string `json:"detail"`
	OwnerKind string `json:"ownerKind,omitempty"` // the real kind behind a Controller node
}

type GraphEdge struct {
	From        string `json:"from"`
	To          string `json:"to"`
	How         string `json:"how,omitempty"`
	Ready       int    `json:"ready,omitempty"`
	NotReady    int    `json:"notReady,omitempty"`
	Terminating int    `json:"terminating,omitempty"`
}

type MapResponse struct {
	Namespace      string   `json:"namespace"`
	Namespaces     []string `json:"namespaces"`
	NamespaceStats []struct {
		Name   string `json:"name"`
		Pods   int    `json:"pods"`
		System bool   `json:"system"`
	} `json:"namespaceStats,omitempty"`
	Graph struct {
		Nodes []GraphNode `json:"nodes"`
		Edges []GraphEdge `json:"edges"`
	} `json:"graph"`
}

type WorkloadSummary struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Status    string `json:"status"`
	Pods      int    `json:"pods"`
}

type WorkloadsResponse struct {
	Count    int               `json:"count"`
	Items    []WorkloadSummary `json:"items"`
	Continue string            `json:"continue,omitempty"`
}

type NodePod struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Phase     string `json:"phase"`
	Status    string `json:"status"`
	Workload  string `json:"workload,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

type NodeSummary struct {
	Name                 string    `json:"name"`
	Status               string    `json:"status"`
	Pods                 []NodePod `json:"pods"`
	PodCount             *int      `json:"podCount,omitempty"`
	CPURequestedMilli    int64     `json:"cpuRequestedMilli"`
	MemoryRequestedBytes int64     `json:"memoryRequestedBytes"`
}

type NodesResponse struct {
	Count int           `json:"count"`
	Items []NodeSummary `json:"items"`
}

type SecurityFinding struct {
	ID          string `json:"id"`
	Category    string `json:"category"`
	Check       string `json:"check"`
	Severity    string `json:"severity"`
	Subject     string `json:"subject"`
	SubjectKind string `json:"subjectKind"`
	Namespace   string `json:"namespace,omitempty"`
	System      bool   `json:"system"`
}

type SecurityResponse struct {
	Counts     map[string]int    `json:"counts"`
	Findings   []SecurityFinding `json:"findings"`
	Namespaces []struct {
		Name string `json:"name"`
	} `json:"namespaces"`
	Warnings []string `json:"warnings,omitempty"`
	Continue string   `json:"continue,omitempty"`
}

type ProcessesResponse struct {
	Available  bool       `json:"available"`
	Node       string     `json:"node,omitempty"`
	ObservedAt *time.Time `json:"observedAt,omitempty"`
	Stale      bool       `json:"stale"`
	Processes  []struct {
		PID  int    `json:"pid"`
		Name string `json:"name"`
	} `json:"processes"`
}

type OOMResponse struct {
	Window           string   `json:"window"`
	MetricsAvailable bool     `json:"metricsAvailable"`
	Events           []any    `json:"events"`
	Leaks            []Leak   `json:"leaks"`
	Warnings         []string `json:"warnings,omitempty"`
}

type Leak struct {
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Container string `json:"container"`
}

type PodsResponse struct {
	Count int `json:"count"`
	Items []struct {
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
		Phase     string `json:"phase"`
		Workload  string `json:"workload,omitempty"`
		Node      string `json:"node,omitempty"`
		Ready     *bool  `json:"ready,omitempty"`
		Reason    string `json:"reason,omitempty"`
	} `json:"items"`
	Continue string `json:"continue,omitempty"`
}

// Info is the full /api/v1/info, as far as the harness reads it.
type InfoFull struct {
	Info
	Identity *struct {
		User   string   `json:"user"`
		Groups []string `json:"groups"`
		Source string   `json:"source"`
	} `json:"identity,omitempty"`
	Capabilities map[string]bool `json:"capabilities,omitempty"`
	Snapshot     *struct {
		Version    int64   `json:"version"`
		AgeSeconds float64 `json:"ageSeconds"`
		Stale      bool    `json:"stale"`
	} `json:"snapshot,omitempty"`
	AuditStore *struct {
		Backend string `json:"backend"`
		Events  int64  `json:"events"`
	} `json:"auditStore,omitempty"`
	Prometheus *struct {
		Source string `json:"source"`
		URL    string `json:"url"`
	} `json:"prometheus,omitempty"`
	Namespaces  *int              `json:"namespaces,omitempty"`
	Unavailable map[string]string `json:"unavailable,omitempty"`
}

// Paged is any response with a continue token.
type Paged interface{ Next() string }

func (r *PodsResponse) Next() string      { return r.Continue }
func (r *WorkloadsResponse) Next() string { return r.Continue }
func (r *SecurityResponse) Next() string  { return r.Continue }

// GetAll follows continue tokens with limit, calling each for every page.
// It returns the number of pages and the total response time and bytes.
func GetAll[T any, PT interface {
	*T
	Paged
}](ctx context.Context, c *Client, id Identity, path string, limit int, each func(PT)) (pages int, elapsed time.Duration, bytes int64, err error) {
	cont := ""
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	for {
		p := fmt.Sprintf("%s%slimit=%d", path, sep, limit)
		if cont != "" {
			p += "&continue=" + url.QueryEscape(cont)
		}
		var v T
		r, e := c.GetJSON(ctx, id, p, PT(&v))
		elapsed += r.Elapsed
		bytes += r.Bytes
		if e != nil {
			return pages, elapsed, bytes, e
		}
		pages++
		each(PT(&v))
		cont = PT(&v).Next()
		if cont == "" || pages > 10000 {
			return pages, elapsed, bytes, nil
		}
	}
}
