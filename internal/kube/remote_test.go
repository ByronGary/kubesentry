package kube

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// apiServer is a TLS test server standing in for the API server. It records
// the Authorization header and path of every request, and refuses tokens in
// reject with 401.
type apiServer struct {
	*httptest.Server
	mu     sync.Mutex
	auth   []string
	paths  []string
	reject map[string]bool
}

func newAPIServer(t *testing.T) *apiServer {
	t.Helper()
	a := &apiServer{reject: map[string]bool{}}
	a.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		h := r.Header.Get("Authorization")
		a.auth = append(a.auth, h)
		a.paths = append(a.paths, r.Method+" "+r.URL.Path)
		rejected := a.reject[strings.TrimPrefix(h, "Bearer ")]
		a.mu.Unlock()
		if rejected {
			http.Error(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"Unauthorized","code":401}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/version":
			_, _ = io.WriteString(w, `{"major":"1","minor":"33","gitVersion":"v1.33.0"}`)
		case strings.Contains(r.URL.Path, "/proxy/"):
			_, _ = io.WriteString(w, `{"status":"success","data":{"resultType":"vector","result":[]}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(a.Close)
	return a
}

func (a *apiServer) caPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.Certificate().Raw})
}

func (a *apiServer) seen() (auth, paths []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.auth...), append([]string(nil), a.paths...)
}

// writeKubeconfig writes a kubeconfig with contexts "a" (current) and "b",
// both for server; users holds each context's user stanza.
func writeKubeconfig(t *testing.T, server string, ca []byte, userA, userB string) string {
	t.Helper()
	cfg := fmt.Sprintf(`apiVersion: v1
kind: Config
current-context: a
clusters:
- name: ca
  cluster:
    server: %[1]s
    certificate-authority-data: %[2]s
- name: cb
  cluster:
    server: %[1]s/b-prefix
    certificate-authority-data: %[2]s
contexts:
- name: a
  context: {cluster: ca, user: ua}
- name: b
  context: {cluster: cb, user: ub}
users:
- name: ua
  user:
%[3]s
- name: ub
  user:
%[4]s
`, server, base64.StdEncoding.EncodeToString(ca), userA, userB)
	p := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestConnectWithContext(t *testing.T) {
	ca := newAPIServer(t).caPEM()
	path := writeKubeconfig(t, "https://a.example:6443", ca, "    token: token-a", "    token: token-b")
	c, err := ConnectWith(path, ClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if c.Config.Host != "https://a.example:6443" || c.Config.BearerToken != "token-a" || c.InCluster {
		t.Errorf("current context: host %s token %s inCluster %v", c.Config.Host, c.Config.BearerToken, c.InCluster)
	}
	c, err = ConnectWith(path, ClientOptions{Context: "b"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Config.Host != "https://a.example:6443/b-prefix" || c.Config.BearerToken != "token-b" {
		t.Errorf("context b: host %s token %s", c.Config.Host, c.Config.BearerToken)
	}
	// The context also applies to KUBECONFIG, without an explicit path.
	t.Setenv("KUBECONFIG", path)
	c, err = ConnectWith("", ClientOptions{Context: "b"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Config.BearerToken != "token-b" {
		t.Errorf("KUBECONFIG context b: token %s", c.Config.BearerToken)
	}
	if _, err := ConnectWith(path, ClientOptions{Context: "nope"}); err == nil || !strings.Contains(err.Error(), "nope") {
		t.Errorf("missing context: %v", err)
	}
}

func TestServerNeedsTokenSource(t *testing.T) {
	if _, err := ConnectWith("", ClientOptions{Server: "https://x.example"}); err == nil {
		t.Fatal("a server without a token source was accepted")
	}
}

// TestTokenSourceReplacesCredentials: a token source wins over every
// credential in the kubeconfig, including an exec plugin.
func TestTokenSourceReplacesCredentials(t *testing.T) {
	api := newAPIServer(t)
	path := writeKubeconfig(t, api.URL, api.caPEM(), `    token: static-token
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: aws
      args: [eks, get-token, --cluster-name, prod]
      interactiveMode: Never`, "    token: unused")
	var calls int
	src := func(context.Context) (string, time.Time, error) {
		calls++
		return fmt.Sprintf("minted-%d", calls), time.Now().Add(14 * time.Minute), nil
	}
	c, err := ConnectWith(path, ClientOptions{TokenSource: src})
	if err != nil {
		t.Fatal(err)
	}
	if c.Config.ExecProvider != nil || c.Config.BearerToken != "" {
		t.Errorf("kubeconfig credentials kept: exec %v token %q", c.Config.ExecProvider, c.Config.BearerToken)
	}
	for i := 0; i < 3; i++ {
		if _, err := c.Disc.ServerVersion(); err != nil {
			t.Fatal(err)
		}
	}
	auth, _ := api.seen()
	if want := []string{"Bearer minted-1", "Bearer minted-1", "Bearer minted-1"}; !reflect.DeepEqual(auth, want) {
		t.Errorf("Authorization = %v, want %v (one token, cached)", auth, want)
	}
}

// TestServerAndTokenWithoutKubeconfig is -eks-cluster without a kubeconfig:
// the endpoint and CA from DescribeCluster and the minted token.
func TestServerAndTokenWithoutKubeconfig(t *testing.T) {
	api := newAPIServer(t)
	api.reject["first"] = true
	tokens := []string{"first", "second"}
	src := func(context.Context) (string, time.Time, error) {
		tok := tokens[0]
		if len(tokens) > 1 {
			tokens = tokens[1:]
		}
		return tok, time.Now().Add(14 * time.Minute), nil
	}
	var observed []string
	var mu sync.Mutex
	c, err := ConnectWith("", ClientOptions{Server: api.URL, CAData: api.caPEM(), TokenSource: src,
		Observe: func(verb, resource, code string) {
			mu.Lock()
			observed = append(observed, verb+" "+resource+" "+code)
			mu.Unlock()
		}})
	if err != nil {
		t.Fatal(err)
	}
	if c.InCluster {
		t.Error("InCluster with an explicit server")
	}
	// The first token is refused: it is dropped, and the retry gets a new one.
	if _, err := c.Disc.ServerVersion(); err == nil {
		t.Fatal("a refused token succeeded")
	}
	if _, err := c.Disc.ServerVersion(); err != nil {
		t.Fatal(err)
	}
	auth, _ := api.seen()
	if auth[0] != "Bearer first" || auth[len(auth)-1] != "Bearer second" {
		t.Errorf("Authorization = %v", auth)
	}

	// The Service proxy uses the same credentials and observer.
	u, rt, err := c.ServiceProxy("monitoring", "prometheus", "9090")
	if err != nil {
		t.Fatal(err)
	}
	if want := api.URL + "/api/v1/namespaces/monitoring/services/prometheus:9090/proxy"; u != want {
		t.Errorf("proxy URL %s, want %s", u, want)
	}
	resp, err := (&http.Client{Transport: rt}).Post(u+"/api/v1/query", "application/x-www-form-urlencoded", strings.NewReader("query=up"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("proxy status %d", resp.StatusCode)
	}
	auth, paths := api.seen()
	if paths[len(paths)-1] != "POST /api/v1/namespaces/monitoring/services/prometheus:9090/proxy/api/v1/query" || auth[len(auth)-1] != "Bearer second" {
		t.Errorf("proxied request %s with %s", paths[len(paths)-1], auth[len(auth)-1])
	}
	mu.Lock()
	last := observed[len(observed)-1]
	mu.Unlock()
	if last != "create services/proxy 200" {
		t.Errorf("observed %s", last)
	}
	rt2, _ := c.ProxyTransport()
	if rt2 != rt {
		t.Error("the proxy transport is rebuilt per call")
	}
}

func TestServiceProxyURL(t *testing.T) {
	c := &Clients{Config: &rest.Config{Host: "https://rancher.example/k8s/clusters/c-1", TLSClientConfig: rest.TLSClientConfig{CAData: []byte("x")}}}
	u, err := c.ServiceProxyURL("monitoring", "kps-prometheus", "http-web")
	if err != nil {
		t.Fatal(err)
	}
	if want := "https://rancher.example/k8s/clusters/c-1/api/v1/namespaces/monitoring/services/kps-prometheus:http-web/proxy"; u != want {
		t.Errorf("got %s, want %s", u, want)
	}
	for _, bad := range [][3]string{{"Mon", "p", "9090"}, {"m", "p/x", "9090"}, {"m", "p", "0"}, {"m", "p", "has space"}, {"m", "p", ""}} {
		if _, err := c.ServiceProxyURL(bad[0], bad[1], bad[2]); err == nil {
			t.Errorf("ServiceProxyURL%v accepted", bad)
		}
	}
	if _, _, err := (&Clients{}).ServiceProxy("m", "p", "9090"); err == nil {
		t.Error("no config accepted")
	}
}

func TestTokenCache(t *testing.T) {
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	var calls int
	var fail error
	expiry := 14 * time.Minute
	c := &tokenCache{now: func() time.Time { return now }, source: func(context.Context) (string, time.Time, error) {
		if fail != nil {
			return "", time.Time{}, fail
		}
		calls++
		e := time.Time{}
		if expiry > 0 {
			e = now.Add(expiry)
		}
		return fmt.Sprintf("t%d", calls), e, nil
	}}
	get := func() string {
		t.Helper()
		tok, err := c.get(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	if get() != "t1" {
		t.Fatal("first token")
	}
	now = now.Add(12 * time.Minute)
	if get() != "t1" {
		t.Error("refreshed too early")
	}
	now = now.Add(time.Minute + time.Second) // within a minute of expiry
	if get() != "t2" {
		t.Error("not refreshed a minute before expiry")
	}
	// The source fails: the current token works until it lapses.
	fail = errors.New("sso session expired")
	now = now.Add(13*time.Minute + 30*time.Second)
	if get() != "t2" {
		t.Error("a still-valid token was dropped when the source failed")
	}
	now = now.Add(time.Minute)
	if _, err := c.get(context.Background()); err == nil {
		t.Error("an expired token was served")
	}
	fail = nil
	if get() != "t3" {
		t.Error("no recovery")
	}
	c.invalidate("t3")
	if get() != "t4" {
		t.Error("an invalidated token was served")
	}
	c.invalidate("t3") // stale: keeps t4
	if get() != "t4" {
		t.Error("invalidating an old token dropped the new one")
	}
	expiry = 0 // no expiry: not cached
	c.invalidate("t4")
	if get() != "t5" || get() != "t6" {
		t.Error("a token without expiry was cached")
	}
}

func TestTokenTransportKeepsExplicitAuthorization(t *testing.T) {
	var got string
	tt := &tokenTransport{
		cache: &tokenCache{now: time.Now, source: func(context.Context) (string, time.Time, error) { return "minted", time.Now().Add(time.Hour), nil }},
		next: rtFunc(func(r *http.Request) (*http.Response, error) {
			got = r.Header.Get("Authorization")
			return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
		}),
	}
	req := httptest.NewRequest("GET", "https://api.example/version", nil)
	req.Header.Set("Authorization", "Bearer explicit")
	_, _ = tt.RoundTrip(req)
	if got != "Bearer explicit" {
		t.Errorf("explicit header replaced: %s", got)
	}
	req = httptest.NewRequest("GET", "https://api.example/version", nil)
	_, _ = tt.RoundTrip(req)
	if got != "Bearer minted" || req.Header.Get("Authorization") != "" {
		t.Errorf("sent %q; caller's request modified: %q", got, req.Header.Get("Authorization"))
	}
}

func TestParseEKSExec(t *testing.T) {
	env := func(kv ...string) []clientcmdapi.ExecEnvVar {
		var out []clientcmdapi.ExecEnvVar
		for i := 0; i < len(kv); i += 2 {
			out = append(out, clientcmdapi.ExecEnvVar{Name: kv[i], Value: kv[i+1]})
		}
		return out
	}
	cases := []struct {
		name string
		e    clientcmdapi.ExecConfig
		want EKSExec
		ok   bool
	}{
		{"update-kubeconfig", clientcmdapi.ExecConfig{Command: "aws", Args: []string{"--region", "eu-west-1", "eks", "get-token", "--cluster-name", "prod", "--output", "json"}},
			EKSExec{Command: "aws", Cluster: "prod", Region: "eu-west-1"}, true},
		{"profile in env, = forms", clientcmdapi.ExecConfig{Command: "/usr/local/bin/aws", Args: []string{"eks", "get-token", "--cluster-name=prod", "--role-arn=arn:aws:iam::1:role/r"}, Env: env("AWS_PROFILE", "work", "AWS_REGION", "us-east-2")},
			EKSExec{Command: "/usr/local/bin/aws", Cluster: "prod", Region: "us-east-2", Profile: "work", RoleARN: "arn:aws:iam::1:role/r"}, true},
		{"flag profile wins over env", clientcmdapi.ExecConfig{Command: "aws", Args: []string{"--profile", "flag", "--region", "ap-south-1", "eks", "get-token", "--cluster-name", "c"}, Env: env("AWS_PROFILE", "env", "AWS_DEFAULT_REGION", "us-east-1")},
			EKSExec{Command: "aws", Cluster: "c", Region: "ap-south-1", Profile: "flag"}, true},
		{"windows", clientcmdapi.ExecConfig{Command: `C:\Program Files\Amazon\AWSCLIV2\aws.exe`, Args: []string{"eks", "get-token", "--cluster-name", "prod"}},
			EKSExec{Command: `C:\Program Files\Amazon\AWSCLIV2\aws.exe`, Cluster: "prod"}, true},
		{"aws-iam-authenticator", clientcmdapi.ExecConfig{Command: "aws-iam-authenticator", Args: []string{"token", "-i", "prod", "-r", "arn:aws:iam::1:role/r"}},
			EKSExec{Command: "aws-iam-authenticator", Cluster: "prod", RoleARN: "arn:aws:iam::1:role/r"}, true},
		{"aws-iam-authenticator long", clientcmdapi.ExecConfig{Command: "aws-iam-authenticator", Args: []string{"token", "--cluster-id=prod", "--region", "us-west-2"}},
			EKSExec{Command: "aws-iam-authenticator", Cluster: "prod", Region: "us-west-2"}, true},
		{"no cluster", clientcmdapi.ExecConfig{Command: "aws", Args: []string{"eks", "get-token"}}, EKSExec{}, false},
		{"another aws command", clientcmdapi.ExecConfig{Command: "aws", Args: []string{"sso", "login", "--cluster-name", "x"}}, EKSExec{}, false},
		{"kubelogin", clientcmdapi.ExecConfig{Command: "kubelogin", Args: []string{"get-token", "--server-id", "x"}}, EKSExec{}, false},
		{"gke", clientcmdapi.ExecConfig{Command: "gke-gcloud-auth-plugin"}, EKSExec{}, false},
	}
	for _, tc := range cases {
		got, ok := parseEKSExec(&tc.e)
		if ok != tc.ok || got != tc.want {
			t.Errorf("%s: got %+v %v, want %+v %v", tc.name, got, ok, tc.want, tc.ok)
		}
	}
}

// TestExecFallback: the kubeconfig's EKS exec plugin is not installed (a
// container without the AWS CLI), so kubesentry's own token is used.
func TestExecFallback(t *testing.T) {
	api := newAPIServer(t)
	execUser := `    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: aws
      args: [--region, eu-west-1, eks, get-token, --cluster-name, prod, --output, json]
      env:
      - {name: AWS_PROFILE, value: work}
      interactiveMode: Never`
	path := writeKubeconfig(t, api.URL, api.caPEM(), execUser, "    token: unused")
	bin := t.TempDir()
	t.Setenv("PATH", bin)

	var asked []EKSExec
	fallback := func(e EKSExec) (TokenSource, error) {
		asked = append(asked, e)
		return func(context.Context) (string, time.Time, error) {
			return "native", time.Now().Add(14 * time.Minute), nil
		}, nil
	}
	c, err := ConnectWith(path, ClientOptions{ExecFallback: fallback})
	if err != nil {
		t.Fatal(err)
	}
	if want := []EKSExec{{Command: "aws", Cluster: "prod", Region: "eu-west-1", Profile: "work"}}; !reflect.DeepEqual(asked, want) {
		t.Fatalf("fallback asked %+v, want %+v", asked, want)
	}
	if _, err := c.Disc.ServerVersion(); err != nil {
		t.Fatal(err)
	}
	if auth, _ := api.seen(); auth[len(auth)-1] != "Bearer native" {
		t.Errorf("Authorization %v", auth)
	}

	// A failing fallback is an error that names the plugin.
	_, err = ConnectWith(path, ClientOptions{ExecFallback: func(EKSExec) (TokenSource, error) { return nil, errors.New("no region") }})
	if err == nil || !strings.Contains(err.Error(), `"aws" is not installed`) || !strings.Contains(err.Error(), "no region") {
		t.Errorf("failing fallback: %v", err)
	}

	// With the plugin installed, it runs as usual and the fallback is not asked.
	if runtime.GOOS == "windows" {
		return
	}
	if err := os.WriteFile(filepath.Join(bin, "aws"), []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	asked = nil
	c, err = ConnectWith(path, ClientOptions{ExecFallback: fallback})
	if err != nil {
		t.Fatal(err)
	}
	if len(asked) != 0 || c.Config.ExecProvider == nil {
		t.Errorf("installed plugin replaced: asked %v, exec %v", asked, c.Config.ExecProvider)
	}
}

// TestDiscoverPrometheusServicesKeepsThePin: without permission to list
// Services (common for a remote user), the pinned Service still comes back.
func TestDiscoverPrometheusServicesKeepsThePin(t *testing.T) {
	cs := fake.NewClientset()
	cs.PrependReactor("list", "services", func(k8stesting.Action) (bool, k8sruntime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "services"}, "", errors.New("no"))
	})
	got, err := DiscoverPrometheusServices(context.Background(), cs, "monitoring/prometheus:9090")
	if err == nil {
		t.Error("the list error was swallowed")
	}
	if want := []PrometheusService{{Namespace: "monitoring", Name: "prometheus", Port: 9090}}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if got[0].URL() != "http://prometheus.monitoring.svc:9090" {
		t.Errorf("URL %s", got[0].URL())
	}
}
