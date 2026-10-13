package kube

// Running outside the cluster: bearer tokens from a token source (the EKS
// token kubesentry mints itself), the fallback for an EKS exec plugin that is
// not installed, and Services reached through the API server's proxy.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/rest"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// TokenSource returns a bearer token for the API server and when it expires.
// A zero expiry means the token is not cached: the source is asked again for
// the next request.
type TokenSource func(ctx context.Context) (token string, expiry time.Time, err error)

// tokenRefreshBefore is how long before its expiry a cached token is
// replaced, so a request never leaves with a token about to lapse.
const tokenRefreshBefore = time.Minute

// EKSExec is what an EKS exec credential plugin in a kubeconfig asks for.
type EKSExec struct {
	Command string // as written in the kubeconfig
	Cluster string // --cluster-name (aws) or -i/--cluster-id (aws-iam-authenticator)
	Region  string // --region, else AWS_REGION / AWS_DEFAULT_REGION in the plugin's env
	Profile string // --profile, else AWS_PROFILE in the plugin's env
	RoleARN string // --role-arn (aws) or -r/--role (aws-iam-authenticator)
}

// applyCredentials replaces the kubeconfig's credentials with o.TokenSource,
// or with o.ExecFallback's source when the config's EKS exec plugin cannot
// run here.
func applyCredentials(cfg *rest.Config, o ClientOptions) error {
	src := o.TokenSource
	if src == nil && o.ExecFallback != nil && cfg.ExecProvider != nil {
		if e, ok := parseEKSExec(cfg.ExecProvider); ok {
			if _, err := exec.LookPath(e.Command); err != nil {
				s, err := o.ExecFallback(e)
				if err != nil {
					return fmt.Errorf("the kubeconfig's credential plugin %q is not installed, and kubesentry's own EKS token failed: %w", e.Command, err)
				}
				src = s
			}
		}
	}
	if src == nil {
		return nil
	}
	cfg.ExecProvider, cfg.AuthProvider = nil, nil
	cfg.BearerToken, cfg.BearerTokenFile = "", ""
	cfg.Username, cfg.Password = "", ""
	cfg.CertFile, cfg.CertData, cfg.KeyFile, cfg.KeyData = "", nil, "", nil
	cache := &tokenCache{source: src, now: time.Now}
	cfg.Wrap(func(rt http.RoundTripper) http.RoundTripper { return &tokenTransport{cache: cache, next: rt} })
	return nil
}

// tokenCache keeps the last token until shortly before it expires. Every
// client built from one config shares it.
type tokenCache struct {
	source TokenSource
	now    func() time.Time

	mu     sync.Mutex
	token  string
	expiry time.Time
}

func (c *tokenCache) get(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if c.token != "" && now.Before(c.expiry.Add(-tokenRefreshBefore)) {
		return c.token, nil
	}
	tok, expiry, err := c.source(ctx)
	if err != nil {
		// A token that has not lapsed yet still works; keep using it while
		// the source recovers (e.g. a credential refresh that failed once).
		if c.token != "" && now.Before(c.expiry) {
			return c.token, nil
		}
		return "", err
	}
	if tok == "" {
		return "", errors.New("token source returned an empty token")
	}
	c.token, c.expiry = tok, expiry
	if expiry.IsZero() {
		c.token = ""
	}
	return tok, nil
}

// invalidate drops tok after the API server refused it, so the next request
// gets a new one.
func (c *tokenCache) invalidate(tok string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token == tok {
		c.token = ""
	}
}

// tokenTransport sets the Authorization header from the cache unless the
// request already carries one, as client-go's exec plugin transport does.
type tokenTransport struct {
	cache *tokenCache
	next  http.RoundTripper
}

func (t *tokenTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Header.Get("Authorization") != "" {
		return t.next.RoundTrip(r)
	}
	tok, err := t.cache.get(r.Context())
	if err != nil {
		return nil, fmt.Errorf("kubernetes bearer token: %w", err)
	}
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+tok)
	resp, err := t.next.RoundTrip(r)
	if err == nil && resp.StatusCode == http.StatusUnauthorized {
		t.cache.invalidate(tok)
	}
	return resp, err
}

// parseEKSExec recognises the exec plugins that `aws eks update-kubeconfig`
// and eksctl write:
//
//	aws [--region R] eks get-token --cluster-name NAME [--region R] [--role-arn ARN] [--profile P]
//	aws-iam-authenticator token -i NAME [--region R] [-r ARN]
func parseEKSExec(e *clientcmdapi.ExecConfig) (EKSExec, bool) {
	out := EKSExec{Command: e.Command}
	base := strings.TrimSuffix(strings.ToLower(filepath.Base(strings.ReplaceAll(e.Command, `\`, "/"))), ".exe")
	args := e.Args
	value := func(i int, names ...string) (string, int, bool) {
		for _, n := range names {
			if args[i] == n && i+1 < len(args) {
				return args[i+1], i + 1, true
			}
			if v, ok := strings.CutPrefix(args[i], n+"="); ok {
				return v, i, true
			}
		}
		return "", i, false
	}
	var words []string
	for i := 0; i < len(args); i++ {
		var v string
		var ok bool
		switch {
		case base == "aws":
			if v, i, ok = value(i, "--cluster-name"); ok {
				out.Cluster = v
			} else if v, i, ok = value(i, "--region"); ok {
				out.Region = v
			} else if v, i, ok = value(i, "--role-arn"); ok {
				out.RoleARN = v
			} else if v, i, ok = value(i, "--profile"); ok {
				out.Profile = v
			} else if !strings.HasPrefix(args[i], "-") {
				words = append(words, args[i])
			}
		case base == "aws-iam-authenticator":
			if v, i, ok = value(i, "-i", "--cluster-id"); ok {
				out.Cluster = v
			} else if v, i, ok = value(i, "--region"); ok {
				out.Region = v
			} else if v, i, ok = value(i, "-r", "--role"); ok {
				out.RoleARN = v
			} else if !strings.HasPrefix(args[i], "-") {
				words = append(words, args[i])
			}
		default:
			return EKSExec{}, false
		}
	}
	// The subcommand, wherever option values (--output json) put it.
	want := " eks get-token "
	if base == "aws-iam-authenticator" {
		want = " token "
	}
	if !strings.Contains(" "+strings.Join(words, " ")+" ", want) || out.Cluster == "" {
		return EKSExec{}, false
	}
	for _, env := range e.Env {
		switch env.Name {
		case "AWS_PROFILE":
			if out.Profile == "" {
				out.Profile = env.Value
			}
		case "AWS_REGION", "AWS_DEFAULT_REGION":
			if out.Region == "" {
				out.Region = env.Value
			}
		}
	}
	return out, true
}

// ProxyTransport is an HTTP transport that sends requests to the API server
// with the clients' credentials and TLS settings, for the API server's
// Service proxy. It is built once.
func (c *Clients) ProxyTransport() (http.RoundTripper, error) {
	c.proxyOnce.Do(func() {
		if c.Config == nil {
			c.proxyErr = errors.New("no Kubernetes client configuration")
			return
		}
		c.proxyRT, c.proxyErr = rest.TransportFor(c.Config)
	})
	return c.proxyRT, c.proxyErr
}

// ServiceProxy returns the API server proxy URL of a Service port,
// https://<apiserver>/api/v1/namespaces/<ns>/services/<name>:<port>/proxy,
// and the transport to send requests there with. port is a number or a port
// name. Requests through it need get (and, for POST, create) on
// services/proxy for that Service.
func (c *Clients) ServiceProxy(ns, name, port string) (string, http.RoundTripper, error) {
	u, err := c.ServiceProxyURL(ns, name, port)
	if err != nil {
		return "", nil, err
	}
	rt, err := c.ProxyTransport()
	if err != nil {
		return "", nil, err
	}
	return u, rt, nil
}

// ServiceProxyURL is ServiceProxy's URL alone.
func (c *Clients) ServiceProxyURL(ns, name, port string) (string, error) {
	for _, part := range []string{ns, name} {
		if errs := validation.IsDNS1123Label(part); len(errs) > 0 {
			return "", fmt.Errorf("service %s/%s: %q: %s", ns, name, part, strings.Join(errs, "; "))
		}
	}
	if n, err := strconv.ParseUint(port, 10, 16); err != nil || n == 0 {
		if errs := validation.IsValidPortName(port); len(errs) > 0 {
			return "", fmt.Errorf("service %s/%s: port %q: %s", ns, name, port, strings.Join(errs, "; "))
		}
	}
	if c.Config == nil {
		return "", errors.New("no Kubernetes client configuration")
	}
	// The host may carry a path prefix (an API server behind a proxy).
	base, _, err := rest.DefaultServerUrlFor(c.Config)
	if err != nil {
		return "", err
	}
	path := strings.TrimRight(base.Path, "/") + "/api/v1/namespaces/" + ns + "/services/" + name + ":" + port + "/proxy"
	return (&url.URL{Scheme: base.Scheme, Host: base.Host, Path: path}).String(), nil
}
