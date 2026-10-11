package api

// The Host allowlist. A listener that trusts every local caller
// (-auth-mode=none, or token mode without a token on loopback) is reachable
// from any web page the user opens: DNS rebinding points a name the page
// controls at 127.0.0.1, and the browser then sends the page's requests,
// with the page's Host, to kubesentry. Refusing Host names that do not name
// this server stops that, as kubectl proxy's --accept-hosts does.

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/ByronGary/kubesentry/internal/auth"
)

// LoopbackHosts is the allowlist a server that trusts every local caller
// uses by default: the loopback names, on any port.
var LoopbackHosts = []string{"localhost", "127.0.0.1", "[::1]"}

// ParseAllowedHosts reads -allowed-hosts: comma-separated host[:port]
// patterns. A host without a port matches any port; "*.example.com" matches
// any subdomain of example.com (not example.com itself); IPv6 addresses are
// bracketed ("[::1]", "[::1]:8080"); "*" alone allows every Host. Empty
// yields nil (no allowlist).
func ParseAllowedHosts(s string) ([]string, error) {
	var out []string
	for _, f := range strings.Split(s, ",") {
		f = strings.ToLower(strings.TrimSpace(f))
		if f == "" {
			continue
		}
		if f != "*" {
			host, port := splitHostPattern(f)
			if host == "" || strings.ContainsAny(host, "/?#@ ") || (port != "" && strings.Trim(port, "0123456789") != "") ||
				strings.Contains(strings.TrimPrefix(host, "*."), "*") {
				return nil, fmt.Errorf("invalid allowed host %q: use host, host:port, *.domain or [ipv6]:port", f)
			}
		}
		out = append(out, f)
	}
	return out, nil
}

// splitHostPattern splits "host[:port]" or "[v6][:port]" into its parts,
// lowercased, without brackets or a trailing dot.
func splitHostPattern(s string) (host, port string) {
	s = strings.ToLower(strings.TrimSpace(s))
	if h, p, err := net.SplitHostPort(s); err == nil {
		host, port = h, p
	} else {
		host = strings.TrimSuffix(strings.TrimPrefix(s, "["), "]")
	}
	return strings.TrimSuffix(host, "."), port
}

// hostAllowed reports whether a request's Host matches one of the patterns.
func hostAllowed(patterns []string, requestHost string) bool {
	host, port := splitHostPattern(requestHost)
	if host == "" {
		return false
	}
	for _, p := range patterns {
		if p == "*" {
			return true
		}
		ph, pp := splitHostPattern(p)
		if pp != "" && pp != port {
			continue
		}
		if ph == host {
			return true
		}
		if rest, ok := strings.CutPrefix(ph, "*."); ok && strings.HasSuffix(host, "."+rest) {
			return true
		}
	}
	return false
}

// WithAllowedHosts answers 403 to requests whose Host header matches none of
// patterns. Nil or empty patterns allow every Host.
func WithAllowedHosts(patterns []string) func(http.Handler) http.Handler {
	if len(patterns) == 0 {
		return func(next http.Handler) http.Handler { return next }
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !hostAllowed(patterns, r.Host) {
				writeError(w, http.StatusForbidden, "host not allowed")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// allowedHosts is AllowedHosts, or LoopbackHosts when the server lets every
// local caller in (auth.NoneAuthenticator) and none were given.
func (s *Server) allowedHosts() []string {
	if s.AllowedHosts != nil {
		return s.AllowedHosts
	}
	switch s.Authenticator.(type) {
	case auth.NoneAuthenticator, *auth.NoneAuthenticator:
		return LoopbackHosts
	}
	return nil
}
