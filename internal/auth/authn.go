package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"strings"
)

// GroupAuthenticated is added to every identity, as the API server does.
const GroupAuthenticated = "system:authenticated"

// TokenUser is the user name of the break-glass API token identity.
const TokenUser = "kubesentry:api-token"

// AnonymousUser is the user name of the -auth-mode=none identity.
const AnonymousUser = "kubesentry:anonymous"

// HeaderAuthenticator reads the identity an SSO proxy (oauth2-proxy) passes in
// request headers. Headers are trusted only when the request comes straight
// from a trusted proxy address; from anywhere else they are ignored, so a
// client cannot claim an identity by setting them itself.
type HeaderAuthenticator struct {
	UserHeader   string // e.g. X-Forwarded-Email
	GroupsHeader string // e.g. X-Forwarded-Groups; comma-separated and/or repeated
	// UsernamePrefix and GroupsPrefix are prepended like the API server's
	// --oidc-username-prefix and --oidc-groups-prefix, so the identity matches
	// the subjects RBAC bindings name. A UsernamePrefix of "-" means none.
	UsernamePrefix string
	GroupsPrefix   string
	// GroupMap adds Kubernetes groups for identity-provider groups. Keys are
	// matched against the raw header values (before GroupsPrefix); the mapped
	// groups are added as written. The original (prefixed) groups are kept.
	GroupMap map[string][]string
	// TrustedProxies are the addresses allowed to send identity headers.
	// Empty trusts nobody.
	TrustedProxies []netip.Prefix
}

// Authenticate implements Authenticator.
func (h HeaderAuthenticator) Authenticate(r *http.Request) (Identity, bool) {
	if h.UserHeader == "" || !h.trusted(r.RemoteAddr) {
		return Identity{}, false
	}
	user := strings.TrimSpace(r.Header.Get(h.UserHeader))
	if user == "" {
		return Identity{}, false
	}
	if p := h.UsernamePrefix; p != "" && p != "-" {
		user = p + user
	}
	// Identity providers do not get to claim Kubernetes system identities:
	// those would make the SubjectAccessReviews answer for a control-plane
	// component or system:masters. Admin-written GroupMap entries may.
	if strings.HasPrefix(user, "system:") {
		return Identity{}, false
	}

	seen := map[string]bool{GroupAuthenticated: true}
	groups := []string{}
	add := func(g string) {
		if g != "" && !seen[g] {
			seen[g] = true
			groups = append(groups, g)
		}
	}
	if h.GroupsHeader != "" {
		for _, v := range r.Header.Values(h.GroupsHeader) {
			for _, raw := range strings.Split(v, ",") {
				raw = strings.TrimSpace(raw)
				if raw == "" {
					continue
				}
				if g := h.GroupsPrefix + raw; !strings.HasPrefix(g, "system:") {
					add(g)
				}
				for _, mapped := range h.GroupMap[raw] {
					add(strings.TrimSpace(mapped))
				}
			}
		}
	}
	groups = append(groups, GroupAuthenticated)
	return Identity{User: user, Groups: groups, Source: "proxy"}, true
}

func (h HeaderAuthenticator) trusted(remoteAddr string) bool {
	addr, ok := remoteIP(remoteAddr)
	if !ok {
		return false
	}
	for _, p := range h.TrustedProxies {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// remoteIP parses http.Request.RemoteAddr ("ip:port", or a bare ip).
func remoteIP(remoteAddr string) (netip.Addr, bool) {
	if ap, err := netip.ParseAddrPort(remoteAddr); err == nil {
		return ap.Addr().Unmap(), true
	}
	if a, err := netip.ParseAddr(strings.Trim(remoteAddr, "[]")); err == nil {
		return a.Unmap(), true
	}
	return netip.Addr{}, false
}

// TokenAuthenticator accepts the shared API token as a bearer token. The
// token is the break-glass identity: it is unrestricted. An empty Token
// accepts nothing.
type TokenAuthenticator struct {
	Token string
}

// Authenticate implements Authenticator.
func (t TokenAuthenticator) Authenticate(r *http.Request) (Identity, bool) {
	if t.Token == "" {
		return Identity{}, false
	}
	scheme, got, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return Identity{}, false
	}
	// Comparing digests keeps the comparison constant-time in the length too.
	a := sha256.Sum256([]byte(strings.TrimSpace(got)))
	b := sha256.Sum256([]byte(t.Token))
	if subtle.ConstantTimeCompare(a[:], b[:]) != 1 {
		return Identity{}, false
	}
	return Identity{User: TokenUser, Groups: []string{GroupAuthenticated}, Source: "token", Unrestricted: true}, true
}

// NoneAuthenticator lets every local caller in, unrestricted
// (-auth-mode=none). It refuses requests from non-loopback addresses, so a
// listener bound to a routable address by mistake does not expose everything.
type NoneAuthenticator struct{}

// Authenticate implements Authenticator.
func (NoneAuthenticator) Authenticate(r *http.Request) (Identity, bool) {
	addr, ok := remoteIP(r.RemoteAddr)
	if !ok || !addr.IsLoopback() {
		return Identity{}, false
	}
	return Identity{User: AnonymousUser, Groups: []string{GroupAuthenticated}, Source: "none", Unrestricted: true}, true
}

type chain []Authenticator

// Chain tries each authenticator in order; the first that accepts wins.
func Chain(authns ...Authenticator) Authenticator {
	out := make(chain, 0, len(authns))
	for _, a := range authns {
		if a != nil {
			out = append(out, a)
		}
	}
	return out
}

func (c chain) Authenticate(r *http.Request) (Identity, bool) {
	for _, a := range c {
		if id, ok := a.Authenticate(r); ok {
			return id, true
		}
	}
	return Identity{}, false
}

// LoadGroupMap reads a JSON object mapping identity-provider groups to
// Kubernetes groups: {"idp-group": ["k8s-group", ...]}.
func LoadGroupMap(path string) (map[string][]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("group map: %w", err)
	}
	var raw map[string][]string
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("group map %s: %w", path, err)
	}
	out := make(map[string][]string, len(raw))
	for k, vs := range raw {
		k = strings.TrimSpace(k)
		if k == "" {
			return nil, fmt.Errorf("group map %s: empty group name", path)
		}
		for _, v := range vs {
			if v = strings.TrimSpace(v); v == "" {
				return nil, fmt.Errorf("group map %s: empty Kubernetes group for %q", path, k)
			}
			out[k] = append(out[k], v)
		}
	}
	return out, nil
}

// ParseCIDRs parses a comma-separated list of CIDRs. A bare address stands for
// itself (/32 or /128).
func ParseCIDRs(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if !strings.Contains(f, "/") {
			a, err := netip.ParseAddr(f)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", f, err)
			}
			a = a.Unmap()
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(f)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", f, err)
		}
		if p.Addr().Is4In6() && p.Bits() >= 96 {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}
