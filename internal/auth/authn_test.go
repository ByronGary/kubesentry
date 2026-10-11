package auth

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func proxyAuthn(t *testing.T) HeaderAuthenticator {
	t.Helper()
	trusted, err := ParseCIDRs("127.0.0.1/32, ::1, 10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	return HeaderAuthenticator{UserHeader: "X-Forwarded-Email", GroupsHeader: "X-Forwarded-Groups", TrustedProxies: trusted}
}

func TestHeaderAuthenticatorTrustsOnlyProxies(t *testing.T) {
	h := proxyAuthn(t)
	for _, tc := range []struct {
		remote string
		ok     bool
	}{
		{"127.0.0.1:5555", true},
		{"[::1]:5555", true},
		{"[::ffff:127.0.0.1]:5555", true}, // IPv4-mapped loopback
		{"10.1.2.3:443", true},
		{"192.168.1.10:5555", false}, // spoofed headers from a client: ignored
		{"[2001:db8::1]:5555", false},
		{"garbage", false},
		{"", false},
	} {
		r := httptest.NewRequest("GET", "/api/v1/info", nil)
		r.RemoteAddr = tc.remote
		r.Header.Set("X-Forwarded-Email", "alice@example.com")
		r.Header.Set("X-Forwarded-Groups", "system:masters,team-a")
		id, ok := h.Authenticate(r)
		if ok != tc.ok {
			t.Errorf("%s: ok=%v, want %v (%+v)", tc.remote, ok, tc.ok, id)
		}
		if !ok && id.User != "" {
			t.Errorf("%s: rejected identity leaks %+v", tc.remote, id)
		}
	}
}

func TestHeaderAuthenticatorGroups(t *testing.T) {
	h := proxyAuthn(t)
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:1"
	r.Header.Set("X-Forwarded-Email", "  alice@example.com ")
	r.Header.Add("X-Forwarded-Groups", " team-a , team-b,,team-a")
	r.Header.Add("X-Forwarded-Groups", "team-c")
	r.Header.Add("X-Forwarded-Groups", "team-b, system:masters, system:authenticated")
	id, ok := h.Authenticate(r)
	if !ok {
		t.Fatal("rejected")
	}
	want := Identity{User: "alice@example.com", Groups: []string{"team-a", "team-b", "team-c", "system:authenticated"}, Source: "proxy"}
	if !reflect.DeepEqual(id, want) {
		t.Fatalf("got %+v\nwant %+v", id, want)
	}
}

func TestHeaderAuthenticatorPrefixesAndGroupMap(t *testing.T) {
	h := proxyAuthn(t)
	h.UsernamePrefix = "oidc:"
	h.GroupsPrefix = "oidc:"
	h.GroupMap = map[string][]string{"Platform Admins": {"cluster-viewers", "system:masters"}, "team-a": {"team-a-k8s"}}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.7:1"
	r.Header.Set("X-Forwarded-Email", "bob@example.com")
	r.Header.Set("X-Forwarded-Groups", "Platform Admins,team-a,system:masters")
	id, ok := h.Authenticate(r)
	if !ok {
		t.Fatal("rejected")
	}
	want := []string{"oidc:Platform Admins", "cluster-viewers", "system:masters", "oidc:team-a", "team-a-k8s", "oidc:system:masters", "system:authenticated"}
	if id.User != "oidc:bob@example.com" || !reflect.DeepEqual(id.Groups, want) {
		t.Fatalf("got %+v\nwant groups %v", id, want)
	}

	h.UsernamePrefix = "-" // like the API server: "-" disables prefixing
	if id, _ := h.Authenticate(r); id.User != "bob@example.com" {
		t.Fatalf("user %q", id.User)
	}
}

func TestHeaderAuthenticatorRejects(t *testing.T) {
	h := proxyAuthn(t)
	for name, user := range map[string]string{"empty": "", "blank": "   ", "system user": "system:kube-controller-manager"} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "127.0.0.1:1"
		if user != "" {
			r.Header.Set("X-Forwarded-Email", user)
		}
		if id, ok := h.Authenticate(r); ok {
			t.Errorf("%s: accepted %+v", name, id)
		}
	}
	// No trusted proxies configured: nobody may send headers.
	h.TrustedProxies = nil
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:1"
	r.Header.Set("X-Forwarded-Email", "alice@example.com")
	if _, ok := h.Authenticate(r); ok {
		t.Error("accepted without trusted proxies")
	}
}

// A proxy sets the user header once; two values mean something else added
// one, and picking either would trust it.
func TestHeaderAuthenticatorRefusesRepeatedUserHeader(t *testing.T) {
	h := proxyAuthn(t)
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:1"
	r.Header.Add("X-Forwarded-Email", "alice@example.com")
	r.Header.Add("X-Forwarded-Email", "platform-admin@example.com")
	if id, ok := h.Authenticate(r); ok {
		t.Errorf("repeated user header accepted as %+v", id)
	}
}

// Platform principal prefixes (system:, eks:, and any the policy adds) are
// not the identity provider's to claim; the admin's group map may.
func TestHeaderAuthenticatorReservedPrefixes(t *testing.T) {
	h := proxyAuthn(t)
	h.GroupMap = map[string][]string{"ops": {"eks:cluster-admins"}}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:1"
	r.Header.Set("X-Forwarded-Email", "alice@example.com")
	r.Header.Set("X-Forwarded-Groups", "eks:node-manager,system:masters,okta:admins,ops")
	id, ok := h.Authenticate(r)
	if !ok {
		t.Fatal("rejected")
	}
	want := []string{"okta:admins", "ops", "eks:cluster-admins", "system:authenticated"}
	if !reflect.DeepEqual(id.Groups, want) {
		t.Errorf("groups = %v, want %v", id.Groups, want)
	}
	h.ReservedPrefixes = []string{"eks:", "okta:"}
	id, _ = h.Authenticate(r)
	if want := []string{"ops", "eks:cluster-admins", "system:authenticated"}; !reflect.DeepEqual(id.Groups, want) {
		t.Errorf("with okta: reserved, groups = %v, want %v", id.Groups, want)
	}
	for _, user := range []string{"eks:node-manager", "system:admin", "okta:robot"} {
		r.Header.Set("X-Forwarded-Email", user)
		if id, ok := h.Authenticate(r); ok {
			t.Errorf("user %q accepted as %+v", user, id)
		}
	}
}

// With TrustProxyConn only connections the proxy alone can open (a Unix
// socket shared with the sidecar) carry identity: kubectl port-forward and
// a DNS-rebinding page behind it arrive over TCP from loopback.
func TestHeaderAuthenticatorProxyConnOnly(t *testing.T) {
	h := HeaderAuthenticator{UserHeader: "X-Forwarded-Email", GroupsHeader: "X-Forwarded-Groups", TrustProxyConn: true,
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}} // ignored with TrustProxyConn
	req := func(proxyConn bool) *http.Request {
		r := httptest.NewRequest("GET", "http://rebind.attacker.example:8080/api/v1/pods", nil)
		r.RemoteAddr = "127.0.0.1:40000"
		r.Header.Set("X-Forwarded-Email", "platform-admin@corp.example")
		if proxyConn {
			r = r.WithContext(WithProxyConn(r.Context()))
			r.RemoteAddr = "@"
		}
		return r
	}
	if id, ok := h.Authenticate(req(false)); ok {
		t.Errorf("loopback TCP accepted as %+v", id)
	}
	if id, ok := h.Authenticate(req(true)); !ok || id.User != "platform-admin@corp.example" {
		t.Errorf("socket connection = %+v, %v", id, ok)
	}
}

func TestProxyCIDRHelpers(t *testing.T) {
	for cidr, want := range map[string][2]bool{ // AnyAddress, HasLoopback
		"0.0.0.0/0": {true, true}, "::/0": {true, true}, "127.0.0.1/32": {false, true}, "127.0.0.2/32": {false, true},
		"::1/128": {false, true}, "10.0.0.0/8": {false, false}, "fd00::/8": {false, false},
	} {
		p := netip.MustParsePrefix(cidr)
		if got := [2]bool{AnyAddress(p), HasLoopback(p)}; got != want {
			t.Errorf("%s: any, loopback = %v, want %v", cidr, got, want)
		}
	}
}

func TestTokenAuthenticator(t *testing.T) {
	a := TokenAuthenticator{Token: "s3cret"}
	for _, tc := range []struct {
		header string
		ok     bool
	}{
		{"Bearer s3cret", true},
		{"bearer s3cret", true},
		{"Bearer s3cre", false},
		{"Bearer s3cret2", false},
		{"Basic s3cret", false},
		{"s3cret", false},
		{"", false},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		if tc.header != "" {
			r.Header.Set("Authorization", tc.header)
		}
		id, ok := a.Authenticate(r)
		if ok != tc.ok {
			t.Errorf("%q: ok=%v", tc.header, ok)
		}
		if ok && (id.User != TokenUser || id.Source != "token" || !id.Unrestricted) {
			t.Errorf("identity %+v", id)
		}
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer ")
	if _, ok := (TokenAuthenticator{}).Authenticate(r); ok {
		t.Error("empty token accepted an empty bearer")
	}
}

func TestNoneAuthenticatorLoopbackOnly(t *testing.T) {
	for remote, want := range map[string]bool{
		"127.0.0.1:80": true, "127.3.4.5:80": true, "[::1]:80": true,
		"10.0.0.1:80": false, "[2001:db8::1]:80": false, "": false,
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		id, ok := NoneAuthenticator{}.Authenticate(r)
		if ok != want {
			t.Errorf("%q: ok=%v want %v", remote, ok, want)
		}
		if ok && (id.Source != "none" || !id.Unrestricted) {
			t.Errorf("identity %+v", id)
		}
	}
}

func TestChainFirstMatchWins(t *testing.T) {
	h := proxyAuthn(t)
	c := Chain(h, nil, TokenAuthenticator{Token: "tok"})
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:1"
	r.Header.Set("X-Forwarded-Email", "alice@example.com")
	r.Header.Set("Authorization", "Bearer tok")
	if id, ok := c.Authenticate(r); !ok || id.Source != "proxy" {
		t.Fatalf("got %+v %v", id, ok)
	}
	// A client off the proxy path with spoofed headers falls through to the token.
	r.RemoteAddr = "192.0.2.1:1"
	if id, ok := c.Authenticate(r); !ok || id.Source != "token" {
		t.Fatalf("got %+v %v", id, ok)
	}
	r.Header.Del("Authorization")
	if id, ok := c.Authenticate(r); ok {
		t.Fatalf("accepted %+v", id)
	}
}

func TestLoadGroupMap(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "m.json")
	os.WriteFile(p, []byte(`{"Admins": ["cluster-admins", " viewers "], "devs": []}`), 0o600)
	m, err := LoadGroupMap(p)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(m, map[string][]string{"Admins": {"cluster-admins", "viewers"}}) {
		t.Fatalf("%v", m)
	}
	os.WriteFile(p, []byte(`{"a": [""]}`), 0o600)
	if _, err := LoadGroupMap(p); err == nil {
		t.Error("empty group accepted")
	}
	os.WriteFile(p, []byte(`["a"]`), 0o600)
	if _, err := LoadGroupMap(p); err == nil {
		t.Error("array accepted")
	}
	if _, err := LoadGroupMap(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing file accepted")
	}
}

func TestParseCIDRs(t *testing.T) {
	got, err := ParseCIDRs(" 127.0.0.1/32,::1/128 , 10.1.2.3/8,192.0.2.7,,::ffff:10.0.0.0/104")
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("::1/128"), netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("192.0.2.7/32"), netip.MustParsePrefix("10.0.0.0/8"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for _, bad := range []string{"10.0.0.0/33", "nope", "1.2.3/8"} {
		if _, err := ParseCIDRs(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if got, err := ParseCIDRs(""); err != nil || len(got) != 0 {
		t.Errorf("empty: %v %v", got, err)
	}
}
