package main

import (
	"context"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ByronGary/kubesentry/internal/api"
	"github.com/ByronGary/kubesentry/internal/auth"
)

// shortTempDir returns a temporary directory with a path short enough for a
// Unix socket (t.TempDir names can exceed the 108-byte limit).
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ks")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func TestListenUnixSocket(t *testing.T) {
	dir := shortTempDir(t)
	path := filepath.Join(dir, "web.sock")
	ln, unix, err := listen("unix://" + path)
	if err != nil || !unix {
		t.Fatalf("listen = %v, %v", unix, err)
	}
	defer ln.Close()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&fs.ModeSocket == 0 || fi.Mode().Perm() != socketMode {
		t.Errorf("socket mode = %v, want a socket with %v", fi.Mode(), socketMode)
	}

	// Requests over it carry the proxy-connection mark, as serve sets it.
	hs := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if auth.FromProxyConn(r.Context()) {
				io.WriteString(w, "proxy")
			}
		}),
		ConnContext: func(ctx context.Context, _ net.Conn) context.Context { return auth.WithProxyConn(ctx) },
	}
	go hs.Serve(ln)
	defer hs.Close()
	c := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}}
	resp, err := c.Get("http://kubesentry/api/v1/info")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "proxy" {
		t.Errorf("request over the socket was not marked as the proxy's: %q", body)
	}
}

func TestListenReplacesOnlyStaleSockets(t *testing.T) {
	dir := shortTempDir(t)

	// A socket left behind by a previous run (nothing listens) is replaced.
	stale := filepath.Join(dir, "stale.sock")
	old, err := net.Listen("unix", stale)
	if err != nil {
		t.Fatal(err)
	}
	old.(*net.UnixListener).SetUnlinkOnClose(false)
	old.Close()
	if _, err := os.Stat(stale); err != nil {
		t.Fatalf("the stale socket should still exist: %v", err)
	}
	ln, _, err := listen("unix://" + stale)
	if err != nil {
		t.Fatalf("stale socket not replaced: %v", err)
	}

	// A live one is not: another server is using it.
	if _, _, err := listen("unix://" + stale); err == nil || !strings.Contains(err.Error(), "in use") {
		t.Errorf("listening on a live socket = %v, want in use", err)
	}
	ln.Close()

	// Nor is anything that is not a socket.
	file := filepath.Join(dir, "data")
	if err := os.WriteFile(file, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := listen("unix://" + file); err == nil {
		t.Error("a regular file was replaced by the socket")
	}
	if b, _ := os.ReadFile(file); string(b) != "keep me" {
		t.Errorf("file changed: %q", b)
	}

	for _, bad := range []string{"unix://relative.sock", "unix://", "unix:///" + strings.Repeat("x", 120)} {
		if _, _, err := listen(bad); err == nil {
			t.Errorf("%s should be refused", bad)
		}
	}
}

func TestProxyListenerFlags(t *testing.T) {
	t.Setenv("KUBESENTRY_API_TOKEN", "")
	// A Unix socket web listener trusts the socket only.
	c, err := parseFlags([]string{"-auth-mode=proxy", "-addr=unix:///var/run/kubesentry/web.sock", "-ingest-addr=:8081"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	a, err := c.authenticator()
	if err != nil {
		t.Fatal(err)
	}
	h, ok := a.(auth.HeaderAuthenticator)
	if !ok || !h.TrustProxyConn || len(h.TrustedProxies) != 0 {
		t.Errorf("socket authenticator = %+v", a)
	}
	if strings.Join(h.ReservedPrefixes, ",") != "system:,eks:" {
		t.Errorf("reserved prefixes = %v", h.ReservedPrefixes)
	}

	// Refused: a socket without an ingest listener, a relative socket path,
	// and a CIDR admitting everyone without -auth-allow-any-proxy.
	for _, args := range [][]string{
		{"-auth-mode=proxy", "-addr=unix:///run/web.sock"},
		{"-auth-mode=proxy", "-addr=unix://web.sock", "-ingest-addr=:8081"},
		{"-auth-mode=proxy", "-addr=:8080", "-auth-trusted-proxy-cidrs=10.0.0.0/8,0.0.0.0/0"},
		{"-auth-mode=proxy", "-addr=:8080", "-auth-trusted-proxy-cidrs=::/0"},
		{"-auth-mode=none", "-addr=unix:///run/web.sock", "-ingest-addr=:8081"},
		{"-allowed-hosts=a/b"},
		{"-max-inflight-per-identity=-1"},
	} {
		if _, err := parseFlags(args, io.Discard); err == nil {
			t.Errorf("%v should be refused", args)
		}
	}
	c, err = parseFlags([]string{"-auth-mode=proxy", "-addr=:8080", "-auth-trusted-proxy-cidrs=0.0.0.0/0", "-auth-allow-any-proxy"}, io.Discard)
	if err != nil {
		t.Fatalf("-auth-allow-any-proxy: %v", err)
	}
	if a, err := c.authenticator(); err != nil || len(a.(auth.HeaderAuthenticator).TrustedProxies) != 1 {
		t.Errorf("any-proxy authenticator = %+v, %v", a, err)
	}
}

func TestWebAllowedHosts(t *testing.T) {
	t.Setenv("KUBESENTRY_API_TOKEN", "")
	for _, tc := range []struct {
		args []string
		want string
	}{
		{nil, strings.Join(api.LoopbackHosts, ",")}, // token mode without a token on loopback acts as none
		{[]string{"-auth-mode=none"}, strings.Join(api.LoopbackHosts, ",")},
		{[]string{"-auth-mode=none", "-allowed-hosts=dev.local:8080"}, "dev.local:8080"},
		{[]string{"-api-token=s3cret", "-addr=:8080"}, ""},
		{[]string{"-auth-mode=proxy", "-addr=:8080"}, ""},
		{[]string{"-auth-mode=proxy", "-addr=:8080", "-allowed-hosts=kubesentry.corp.example"}, "kubesentry.corp.example"},
	} {
		c, err := parseFlags(tc.args, io.Discard)
		if err != nil {
			t.Fatalf("%v: %v", tc.args, err)
		}
		if got := strings.Join(c.webAllowedHosts(), ","); got != tc.want {
			t.Errorf("%v: allowed hosts %q, want %q", tc.args, got, tc.want)
		}
	}
}
