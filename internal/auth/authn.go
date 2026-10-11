package auth

import (
	"context"
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

// DefaultReservedPrefixes are the user and group name prefixes of platform
// identities (Kubernetes' own and EKS's), as -system-principal-prefixes
// defaults them.
var DefaultReservedPrefixes = []string{"system:", "eks:"}

// HeaderAuthenticator reads the identity an SSO proxy (oauth2-proxy) passes in
// request headers. Headers are trusted only when the request comes straight
// from the proxy: over a connection the proxy alone can open (a Unix socket
// shared with the sidecar, TrustProxyConn), or else from a trusted proxy
// address. From anywhere else they are ignored, so a client cannot claim an
// identity by setting them itself.
type HeaderAuthenticator struct {
	UserHeader string // e.g. X-Forwarded-Email; must appear exactly once
	// GroupsHeader carries the groups, e.g. X-Forwarded-Groups. Values are
	// comma-separated (oauth2-proxy joins a user's groups with commas), and
	// repeated headers add up, so group names containing commas are not
	// supported.
	GroupsHeader string
	// UsernamePrefix and GroupsPrefix are prepended like the API server's
	// --oidc-username-prefix and --oidc-groups-prefix, so the identity matches
	// the subjects RBAC bindings name. A UsernamePrefix of "-" means none.
	UsernamePrefix string
	GroupsPrefix   string
	// GroupMap adds Kubernetes groups for identity-provider groups. Keys are
	// matched against the raw header values (before GroupsPrefix); the mapped
	// groups are added as written. The original (prefixed) groups are kept.
	GroupMap map[string][]string
	// ReservedPrefixes are platform principal prefixes (the policy's system
	// principal prefixes, -system-principal-prefixes). A user name starting
	// with one is refused and such identity-provider groups are dropped, so
	// no IdP claim can become system:masters or an eks: identity. "system:"
	// is always reserved; nil means DefaultReservedPrefixes. GroupMap output
	// is kept as the admin wrote it.
	ReservedPrefixes []string
	// TrustProxyConn trusts the headers on connections marked by
	// WithProxyConn (accepted on a Unix socket only the SSO proxy can
	// reach), and nowhere else: TrustedProxies is then ignored, so a TCP
	// connection from loopback, as kubectl port-forward makes, is not the
	// proxy.
	TrustProxyConn bool
	// TrustedProxies are the addresses allowed to send identity headers over
	// TCP. Empty trusts nobody.
	TrustedProxies []netip.Prefix
}

// Authenticate implements Authenticator.
func (h HeaderAuthenticator) Authenticate(r *http.Request) (Identity, bool) {
	if h.UserHeader == "" || !h.trusted(r) {
		return Identity{}, false
	}
	// A repeated user header is ambiguous: a proxy sets it once, so a second
	// value means something else added one. Refuse rather than pick.
	vals := r.Header.Values(h.UserHeader)
	if len(vals) != 1 {
		return Identity{}, false
	}
	user := strings.TrimSpace(vals[0])
	if user == "" {
		return Identity{}, false
	}
	if p := h.UsernamePrefix; p != "" && p != "-" {
		user = p + user
	}
	// Identity providers do not get to claim platform identities: those
	// would make the SubjectAccessReviews answer for a control-plane
	// component, system:masters or an EKS internal role. Admin-written
	// GroupMap entries may.
	if h.reserved(user) {
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
				if g := h.GroupsPrefix + raw; !h.reserved(g) {
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

// reserved reports whether name starts with a platform principal prefix.
func (h HeaderAuthenticator) reserved(name string) bool {
	if strings.HasPrefix(name, "system:") {
		return true
	}
	prefixes := h.ReservedPrefixes
	if prefixes == nil {
		prefixes = DefaultReservedPrefixes
	}
	for _, p := range prefixes {
		if p != "" && strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

func (h HeaderAuthenticator) trusted(r *http.Request) bool {
	if h.TrustProxyConn {
		return FromProxyConn(r.Context())
	}
	addr, ok := remoteIP(r.RemoteAddr)
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

type proxyConnKey struct{}

// WithProxyConn marks ctx as belonging to a connection accepted on a
// listener only the SSO proxy can reach: a Unix socket in a volume shared
// with the oauth2-proxy sidecar. Set it from http.Server.ConnContext.
func WithProxyConn(ctx context.Context) context.Context {
	return context.WithValue(ctx, proxyConnKey{}, true)
}

// FromProxyConn reports whether WithProxyConn marked ctx.
func FromProxyConn(ctx context.Context) bool {
	v, _ := ctx.Value(proxyConnKey{}).(bool)
	return v
}

// AnyAddress reports whether p admits every address (0.0.0.0/0 or ::/0).
func AnyAddress(p netip.Prefix) bool { return p.IsValid() && p.Bits() == 0 }

// HasLoopback reports whether p contains a loopback address.
func HasLoopback(p netip.Prefix) bool {
	return p.Addr().IsLoopback() || p.Contains(netip.AddrFrom4([4]byte{127, 0, 0, 1})) || p.Contains(netip.IPv6Loopback())
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
