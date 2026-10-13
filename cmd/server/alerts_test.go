package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/alerts"
	"github.com/ByronGary/kubesentry/internal/api"
	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/metrics"
	"github.com/ByronGary/kubesentry/internal/model"
	"github.com/ByronGary/kubesentry/internal/snapshot"
)

func TestAlertsFlags(t *testing.T) {
	c, err := parseFlags(nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	a := c.alerts
	if a.enabled || a.urls != "" || a.interval != 30*time.Second || a.resend != time.Minute || a.resolveGrace != 5*time.Minute ||
		a.maxNew != 50 || a.defaultOwner != "platform" || a.leakCritHours != 0 || a.externalURL != "" || a.runbookURL != alerts.DefaultRunbookURL {
		t.Errorf("defaults = %+v", a)
	}
	bad := [][]string{
		{"-alertmanager-url=http://am:9093"}, // without -alerts
		{"-alerts", "-alertmanager-url=am:9093"},
		{"-alerts", "-alertmanager-url=http://user:pw@am:9093"},
		{"-alerts", "-alertmanager-url=http://am:9093,https://aps-workspaces.us-east-1.amazonaws.com/workspaces/ws-1/alertmanager"},
		{"-alerts", "-cache=false"},
		{"-alerts", "-alerts-interval=0s"},
		{"-alerts", "-alerts-resend=10s"},
		{"-alerts", "-alerts-resolve-grace=-1m"},
		{"-alerts", "-alerts-max-new=0"},
		{"-alerts", "-alerts-default-owner= "},
		{"-alerts", "-alerts-leak-crit-hours=-1"},
		{"-alerts", "-external-url=kubesentry.example.com"},
		{"-alerts", "-external-url=https://ks.example.com/#/x"},
		{"-alerts", "-alerts-runbook-url=docs/alerts.md"},
	}
	for _, args := range bad {
		if _, err := parseFlags(args, io.Discard); err == nil {
			t.Errorf("%v should be refused", args)
		} else if strings.Contains(err.Error(), "pw") {
			t.Errorf("%v: the error shows the password: %v", args, err)
		}
	}
	good := [][]string{
		{"-alerts"},
		{"-alerts", "-alertmanager-url=http://am-0:9093, http://am-1:9093", "-external-url=https://ks.example.com/"},
		{"-alerts", "-alertmanager-url=https://aps-workspaces.eu-west-1.amazonaws.com/workspaces/ws-1/alertmanager"},
		{"-alerts", "-alertmanager-url=http://am:9093,https://aps-workspaces.us-east-1.amazonaws.com/workspaces/ws-1/alertmanager", "-alertmanager-sigv4"},
		{"-alerts", "-alerts-interval=1m", "-alerts-resend=1m", "-alerts-resolve-grace=0s", "-alerts-max-new=1", "-alerts-leak-crit-hours=12"},
	}
	for _, args := range good {
		if _, err := parseFlags(args, io.Discard); err != nil {
			t.Errorf("%v: %v", args, err)
		}
	}
}

// fakeAlertmanager records the requests it gets.
type fakeAlertmanager struct {
	mu   sync.Mutex
	reqs []*http.Request
	body [][]byte
}

func (f *fakeAlertmanager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.reqs = append(f.reqs, r)
	f.body = append(f.body, b)
	f.mu.Unlock()
}

func (f *fakeAlertmanager) wait(t *testing.T) (*http.Request, []byte) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		if len(f.reqs) > 0 {
			r, b := f.reqs[0], f.body[0]
			f.mu.Unlock()
			return r, b
		}
		f.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("Alertmanager got nothing")
	return nil, nil
}

func sinkFor(t *testing.T, args ...string) (alerts.Sink, error) {
	t.Helper()
	cfg, err := parseFlags(append([]string{"-alerts"}, args...), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return alertsSetup{cfg: cfg}.sink(ctx)
}

var oneAlert = []alerts.Alert{{Labels: map[string]string{"alertname": "KubesentryTest"}, StartsAt: time.Now(), EndsAt: time.Now().Add(time.Minute)}}

func TestAlertmanagerAuth(t *testing.T) {
	t.Run("bearer", func(t *testing.T) {
		am := &fakeAlertmanager{}
		srv := httptest.NewServer(am)
		defer srv.Close()
		t.Setenv(alertmanagerTokenEnv, "am-token")
		s, err := sinkFor(t, "-alertmanager-url="+srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		s.Send(oneAlert)
		r, _ := am.wait(t)
		if r.Header.Get("Authorization") != "Bearer am-token" || r.URL.Path != "/api/v2/alerts" || !strings.HasPrefix(r.UserAgent(), "kubesentry/") {
			t.Errorf("request %s %v", r.URL.Path, r.Header)
		}
	})
	t.Run("basic", func(t *testing.T) {
		am := &fakeAlertmanager{}
		srv := httptest.NewServer(am)
		defer srv.Close()
		t.Setenv(alertmanagerPasswordEnv, "pw")
		s, err := sinkFor(t, "-alertmanager-url="+srv.URL, "-alertmanager-basic-auth-user=kubesentry")
		if err != nil {
			t.Fatal(err)
		}
		s.Send(oneAlert)
		r, _ := am.wait(t)
		if u, p, ok := r.BasicAuth(); !ok || u != "kubesentry" || p != "pw" {
			t.Errorf("basic auth %q %q %v", u, p, ok)
		}
	})
	t.Run("custom CA", func(t *testing.T) {
		am := &fakeAlertmanager{}
		srv := httptest.NewTLSServer(am)
		defer srv.Close()
		ca := filepath.Join(t.TempDir(), "ca.pem")
		if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
			t.Fatal(err)
		}
		s, err := sinkFor(t, "-alertmanager-url="+srv.URL, "-alertmanager-ca-file="+ca)
		if err != nil {
			t.Fatal(err)
		}
		s.Send(oneAlert)
		am.wait(t)

		// Without the CA the certificate is not trusted.
		untrusted, err := sinkFor(t, "-alertmanager-url="+srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		untrusted.Send(oneAlert)
		deadline := time.Now().Add(10 * time.Second)
		for untrusted.Status().LastError == "" && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if e := untrusted.Status().LastError; !strings.Contains(e, "certificate") {
			t.Errorf("untrusted certificate: %q", e)
		}
	})
	t.Run("sigv4", func(t *testing.T) {
		staticAWS(t)
		am := &fakeAlertmanager{}
		srv := httptest.NewServer(am)
		defer srv.Close()
		s, err := sinkFor(t, "-alertmanager-url="+srv.URL+"/workspaces/ws-1/alertmanager", "-alertmanager-sigv4", "-aws-region=eu-west-1")
		if err != nil {
			t.Fatal(err)
		}
		s.Send(oneAlert)
		r, body := am.wait(t)
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/") || !strings.Contains(auth, "/eu-west-1/aps/aws4_request") ||
			!strings.Contains(auth, "SignedHeaders=") || !strings.Contains(auth, "Signature=") || r.Header.Get("X-Amz-Date") == "" {
			t.Errorf("SigV4 headers: Authorization %q, X-Amz-Date %q", auth, r.Header.Get("X-Amz-Date"))
		}
		if r.URL.Path != "/workspaces/ws-1/alertmanager/api/v2/alerts" || len(body) == 0 {
			t.Errorf("path %s, body %d bytes", r.URL.Path, len(body))
		}
	})
	t.Run("conflicts", func(t *testing.T) {
		t.Setenv(alertmanagerTokenEnv, "x")
		if _, err := sinkFor(t, "-alertmanager-url=http://am:9093", "-alertmanager-basic-auth-user=u"); err == nil {
			t.Error("token and basic auth together")
		}
		if _, err := sinkFor(t, "-alertmanager-url=http://am:9093", "-alertmanager-sigv4"); err == nil {
			t.Error("token and SigV4 together")
		}
		t.Setenv(alertmanagerTokenEnv, "")
		t.Setenv(alertmanagerPasswordEnv, "")
		if _, err := sinkFor(t, "-alertmanager-url=http://am:9093", "-alertmanager-basic-auth-user=u"); err == nil {
			t.Error("basic auth without a password")
		}
		if _, err := sinkFor(t, "-alertmanager-url=http://am:9093", "-alertmanager-ca-file=/nonexistent"); err == nil {
			t.Error("a missing CA file")
		}
		if s, err := sinkFor(t); err != nil || s.Status().Name != "none" {
			t.Errorf("no URL: %v, %v", s, err)
		}
	})
}

// End to end with the memory store: the runner evaluates the current view,
// posts to Alertmanager with the cluster label and the external link, and
// serves /alerts and /info; the metrics follow.
func TestAlertsEndToEnd(t *testing.T) {
	am := &fakeAlertmanager{}
	amSrv := httptest.NewServer(am)
	defer amSrv.Close()
	cfg, err := parseFlags([]string{"-alerts", "-alertmanager-url=" + amSrv.URL, "-alerts-interval=10ms", "-alerts-resend=1s",
		"-external-url=https://ks.example.com", "-cluster-name=prod-eks"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	inv := model.Inventory{
		Namespaces: []model.Namespace{{Name: "payments", Annotations: map[string]string{"kubesentry.io/owner": "payments"}}},
		Certs: model.CertManager{Installed: true, Issuers: []model.Issuer{{Kind: "ClusterIssuer", Name: "le", Ready: "True"}},
			Certificates: []model.Certificate{{Namespace: "payments", Name: "api-tls", IssuerKind: "ClusterIssuer", IssuerName: "le", Ready: "True",
				NotBefore: now.Add(-89 * 24 * time.Hour), NotAfter: now.Add(24 * time.Hour)}}},
	}
	v := snapshot.Build(inv, detectors.DefaultPolicy(), now)
	srv := &api.Server{Views: snapshot.Static(v)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err = alertsSetup{cfg: cfg, current: func() *snapshot.View { return v },
		leaks: func() (detectors.LeakReport, time.Duration, bool) { return detectors.LeakReport{}, 0, false }}.start(ctx, srv)
	if err != nil {
		t.Fatal(err)
	}
	_, body := am.wait(t)
	var posted []alerts.Alert
	if err := json.Unmarshal(body, &posted); err != nil || len(posted) != 1 {
		t.Fatalf("posted %s (%v)", body, err)
	}
	a := posted[0]
	if a.Labels["alertname"] != alerts.AlertCertificateExpiring || a.Labels["owner"] != "payments" || a.Labels["cluster"] != "prod-eks" ||
		a.Labels["severity"] != "critical" || a.Annotations["kubesentry_url"] != "https://ks.example.com/#/certificates?q=payments%2Fapi-tls" {
		t.Errorf("alert %+v", a)
	}
	h := srv.Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/alerts", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"key":"cert-expiring/Certificate/payments/api-tls"`) {
		t.Errorf("/alerts = %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/info", nil))
	if !strings.Contains(rec.Body.String(), `"alerts":{"enabled":true,"sink":"alertmanager","leader":true`) {
		t.Errorf("/info = %s", rec.Body.String())
	}
	if metrics.AlertsLeader.Value() != 1 || metrics.Findings.With(alerts.CheckCertExpiring, "critical").Value() != 1 ||
		metrics.DependencyUp.With("alertmanager").Value() != 1 {
		t.Errorf("metrics: leader %v, findings %v, alertmanager up %v", metrics.AlertsLeader.Value(),
			metrics.Findings.With(alerts.CheckCertExpiring, "critical").Value(), metrics.DependencyUp.With("alertmanager").Value())
	}
}
