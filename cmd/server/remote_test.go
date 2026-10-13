package main

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/kube"
	"github.com/ByronGary/kubesentry/internal/model"
	"github.com/ByronGary/kubesentry/internal/prom"
)

func TestRemoteFlags(t *testing.T) {
	cfg, err := parseFlags([]string{"-kube-context", "work-prod", "-eks-cluster", "prod-eks", "-prometheus-via-apiserver=false"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.remote.kubeContext != "work-prod" || cfg.remote.eksCluster != "prod-eks" || cfg.clusterName != "prod-eks" {
		t.Errorf("context %q, eks %q, cluster name %q", cfg.remote.kubeContext, cfg.remote.eksCluster, cfg.clusterName)
	}
	if cfg.remote.viaAPIServer(false) || cfg.remote.viaAPIServer(true) {
		t.Error("-prometheus-via-apiserver=false still proxies")
	}

	cfg, err = parseFlags([]string{"-eks-cluster", "prod-eks", "-cluster-name", "Production"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.clusterName != "Production" {
		t.Errorf("-cluster-name overridden: %q", cfg.clusterName)
	}
	if !cfg.remote.viaAPIServer(false) || cfg.remote.viaAPIServer(true) {
		t.Error("auto: proxy outside the cluster only")
	}

	for _, arg := range []string{"-prometheus-via-apiserver", "-prometheus-via-apiserver=true", "-prometheus-via-apiserver=1"} {
		cfg, err := parseFlags([]string{arg}, io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		if !cfg.remote.viaAPIServer(true) {
			t.Errorf("%s: not forced on", arg)
		}
	}
	cfg, _ = parseFlags([]string{"-prometheus-via-apiserver=auto"}, io.Discard)
	if !cfg.remote.promViaAPIServer.auto() || cfg.remote.promViaAPIServer.String() != "auto" {
		t.Errorf("=auto gives %q", cfg.remote.promViaAPIServer.String())
	}
	if _, err := parseFlags([]string{"-prometheus-via-apiserver=maybe"}, io.Discard); err == nil {
		t.Error("-prometheus-via-apiserver=maybe accepted")
	}
	// -cloudwatch takes its log group from the EKS cluster name.
	if _, err := parseFlags([]string{"-cloudwatch", "-eks-cluster", "prod-eks"}, io.Discard); err != nil {
		t.Errorf("-cloudwatch with -eks-cluster: %v", err)
	}
}

// remoteAPI stands in for the API server of a remote cluster: Services are
// forbidden to list, and the Service proxy forwards to a fake Prometheus.
type remoteAPI struct {
	*httptest.Server
	mu    sync.Mutex
	auths []string
	paths []string
}

const proxyPrefix = "/api/v1/namespaces/monitoring/services/prometheus:9090/proxy"

func newRemoteAPI(t *testing.T) *remoteAPI {
	t.Helper()
	a := &remoteAPI{}
	a.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		a.auths = append(a.auths, r.Header.Get("Authorization"))
		a.paths = append(a.paths, r.URL.Path)
		a.mu.Unlock()
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		path, proxied := strings.CutPrefix(r.URL.Path, proxyPrefix)
		switch {
		case r.URL.Path == "/version":
			_, _ = io.WriteString(w, `{"major":"1","minor":"33","gitVersion":"v1.33.0"}`)
		case r.URL.Path == "/api/v1/services":
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"kind":"Status","apiVersion":"v1","status":"Failure","reason":"Forbidden","code":403}`)
		case proxied && path == "/api/v1/status/buildinfo":
			_, _ = io.WriteString(w, `{"status":"success","data":{"version":"3.5.0","revision":"abc","goVersion":"go1.24"}}`)
		case proxied && path == "/api/v1/status/runtimeinfo":
			_, _ = io.WriteString(w, `{"status":"success","data":{"storageRetention":"15d"}}`)
		case proxied && (path == "/api/v1/query" || path == "/api/v1/query_range"):
			_, _ = io.WriteString(w, `{"status":"success","data":{"resultType":"vector","result":[]}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(a.Close)
	return a
}

func (a *remoteAPI) caPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.Certificate().Raw})
}

func (a *remoteAPI) seen() (auths, paths []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.auths...), append([]string(nil), a.paths...)
}

func TestPrometheusThroughTheAPIServer(t *testing.T) {
	api := newRemoteAPI(t)
	t.Setenv("PROMETHEUS_TOKEN", "prom-secret") // must not reach the API server
	clients, err := kube.ConnectWith("", kube.ClientOptions{Server: api.URL, CAData: api.caPEM(),
		TokenSource: func(context.Context) (string, time.Time, error) { return "kube-token", time.Now().Add(time.Hour), nil }})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := parseFlags([]string{"-prometheus-service", "monitoring/prometheus:9090"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	discover, via, err := cfg.promDiscovery(clients)
	if err != nil || via == nil {
		t.Fatalf("outside the cluster discovery should go through the API server: via %v, err %v", via, err)
	}
	urls, err := discover(context.Background())
	if want := api.URL + proxyPrefix; len(urls) != 1 || urls[0] != want {
		t.Fatalf("candidates %v (err %v), want [%s]", urls, err, want)
	}
	if err == nil {
		t.Error("the forbidden Service list was not reported")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	setup := promSetup{
		autodiscover: true, discover: discover, via: via,
		scan: prom.LeakScanOptions{Interval: time.Hour, StartJitter: -1},
		pods: func(context.Context) ([]model.Pod, error) { return nil, nil },
	}
	st, err := setup.discoverOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.info.URL != api.URL+proxyPrefix || st.info.Source != "discovered" || st.info.Version != "3.5.0" {
		t.Errorf("info %+v", st.info)
	}
	if _, err := st.client.ContainerMemoryLimits(ctx); err != nil {
		t.Errorf("query through the proxy: %v", err)
	}
	if _, err := prom.Probe(ctx, st.rawURL, st.probe); err != nil {
		t.Errorf("health probe through the proxy: %v", err)
	}
	auths, paths := api.seen()
	proxied := 0
	for i, p := range paths {
		if auths[i] != "Bearer kube-token" {
			t.Errorf("%s sent %q, want the Kubernetes token", p, auths[i])
		}
		if strings.HasPrefix(p, proxyPrefix+"/") {
			proxied++
		}
	}
	if proxied < 3 {
		t.Errorf("%d proxied requests: %v", proxied, paths)
	}

	// Forced off, discovery returns in-cluster Service URLs and no transport.
	cfg.remote.promViaAPIServer = "false"
	discover, via, err = cfg.promDiscovery(clients)
	if err != nil || via != nil {
		t.Fatalf("via %v, err %v", via, err)
	}
	if urls, _ := discover(context.Background()); len(urls) != 1 || urls[0] != "http://prometheus.monitoring.svc:9090" {
		t.Errorf("direct candidates %v", urls)
	}
}

// eksKubeconfig writes a kubeconfig for server whose user signs in with the
// AWS CLI's exec plugin.
func eksKubeconfig(t *testing.T, server string, ca []byte) string {
	t.Helper()
	kc := fmt.Sprintf(`apiVersion: v1
kind: Config
current-context: prod
clusters:
- name: prod
  cluster: {server: %q, certificate-authority-data: %s}
contexts:
- name: prod
  context: {cluster: prod, user: prod}
- name: other
  context: {cluster: prod, user: other}
users:
- name: prod
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: aws
      args: [--region, eu-west-1, eks, get-token, --cluster-name, from-kubeconfig, --output, json]
      interactiveMode: Never
- name: other
  user: {token: static}
`, server, base64.StdEncoding.EncodeToString(ca))
	p := filepath.Join(t.TempDir(), "kubeconfig")
	if err := os.WriteFile(p, []byte(kc), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// tokenRequest decodes an EKS bearer token into its presigned URL.
func tokenRequest(t *testing.T, auth string) *url.URL {
	t.Helper()
	enc, ok := strings.CutPrefix(auth, "Bearer k8s-aws-v1.")
	if !ok {
		t.Fatalf("Authorization %q is not an EKS token", auth)
	}
	raw, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// staticAWS points the AWS SDK at fixed keys and no shared files.
func staticAWS(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(t.TempDir(), "none"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "none"))
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
}

// TestEKSTokenEndToEnd: -eks-cluster with -kube-context signs every request
// with kubesentry's own token for that cluster, whatever the context's user.
func TestEKSTokenEndToEnd(t *testing.T) {
	staticAWS(t)
	api := newRemoteAPI(t)
	path := eksKubeconfig(t, api.URL, api.caPEM())
	cfg, err := parseFlags([]string{"-kubeconfig", path, "-kube-context", "other", "-eks-cluster", "prod-eks", "-aws-region", "us-west-2"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	clients, err := connectKube(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clients.Disc.ServerVersion(); err != nil {
		t.Fatal(err)
	}
	auths, _ := api.seen()
	u := tokenRequest(t, auths[len(auths)-1])
	q := u.Query()
	if u.Host != "sts.us-west-2.amazonaws.com" || q.Get("Action") != "GetCallerIdentity" ||
		!strings.HasPrefix(q.Get("X-Amz-Credential"), "AKIDEXAMPLE/") || q.Get("X-Amz-SignedHeaders") != "host;x-k8s-aws-id" {
		t.Errorf("token URL %s", u)
	}
}

// TestExecPluginFallback: the kubeconfig's `aws eks get-token` is not
// installed (the container image), so kubesentry mints the same token for the
// cluster and region the plugin names.
func TestExecPluginFallback(t *testing.T) {
	staticAWS(t)
	t.Setenv("PATH", t.TempDir())
	api := newRemoteAPI(t)
	cfg, err := parseFlags([]string{"-kubeconfig", eksKubeconfig(t, api.URL, api.caPEM())}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	clients, err := connectKube(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clients.Disc.ServerVersion(); err != nil {
		t.Fatal(err)
	}
	auths, _ := api.seen()
	if u := tokenRequest(t, auths[len(auths)-1]); u.Host != "sts.eu-west-1.amazonaws.com" {
		t.Errorf("token for %s, want the plugin's --region eu-west-1", u.Host)
	}
}
