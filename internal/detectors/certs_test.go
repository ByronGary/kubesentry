package detectors

import (
	"strings"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
)

func TestSummarizeCerts(t *testing.T) {
	day := 24 * time.Hour
	cm := model.CertManager{
		Installed: true,
		Issuers: []model.Issuer{
			{Kind: "ClusterIssuer", Name: "le", Type: "acme", Ready: "True"},
			{Kind: "ClusterIssuer", Name: "vault", Type: "vault", Ready: "False", Message: "Failed to initialize Vault client: permission denied"},
			{Kind: "Issuer", Namespace: "app", Name: "self", Type: "selfSigned", Ready: "True"},
		},
	}
	cert := func(name, kind, issuer, ready string, notAfter time.Duration) model.Certificate {
		c := model.Certificate{Namespace: "app", Name: name, IssuerKind: kind, IssuerName: issuer, Ready: ready}
		if notAfter != 0 {
			c.NotAfter = podNow.Add(notAfter)
		}
		return c
	}
	failed := cert("failed", "ClusterIssuer", "le", "False", 0)
	failed.Reason, failed.Message = "DoesNotExist", "Issuing certificate as Secret does not exist"

	cases := []struct {
		c      model.Certificate
		status string
		detail string
	}{
		{cert("good", "ClusterIssuer", "le", "True", 60*day+time.Hour), StatusOK, "Valid for 60 more days."},
		{cert("default-kind", "", "self", "True", 90*day), StatusOK, "Valid for 90 more days."},
		{cert("no-issuer", "ClusterIssuer", "gone", "True", 90*day), StatusCrit, "ClusterIssuer gone not found."},
		{cert("wrong-ns", "Issuer", "le", "True", 90*day), StatusCrit, "Issuer le not found."},
		{cert("vault", "ClusterIssuer", "vault", "True", 90*day), StatusCrit, "ClusterIssuer vault is not ready: Failed to initialize Vault client: permission denied."},
		{failed, StatusCrit, "Issuing certificate as Secret does not exist."},
		{cert("expired", "ClusterIssuer", "le", "True", -3*day), StatusCrit, "Expired 3d ago."},
		{cert("soon", "ClusterIssuer", "le", "True", 5*day), StatusCrit, "Expires in 5 days."},
		{cert("hours", "ClusterIssuer", "le", "True", 30*time.Hour), StatusCrit, "Expires in 30 hours."},
		{cert("month", "ClusterIssuer", "le", "True", 20*day+time.Hour), StatusWarn, "Expires in 20 days."},
		{cert("new", "ClusterIssuer", "le", "", 0), StatusWarn, "Not issued yet."},
		{cert("unknown", "ClusterIssuer", "le", "Unknown", 0), StatusWarn, "Not issued yet."},
		// External issuers (e.g. AWS Private CA) cannot be looked up, so they are not judged.
		{cert("external", "AWSPCAClusterIssuer", "pca", "True", 90*day), StatusOK, "Valid for 90 more days."},
	}
	for _, c := range cases {
		in := cm
		in.Certificates = []model.Certificate{c.c}
		certs, _, _ := SummarizeCerts(in, podNow)
		got := certs[0]
		if got.Status != c.status || got.Detail != c.detail {
			t.Errorf("%s: got %s %q, want %s %q", c.c.Name, got.Status, got.Detail, c.status, c.detail)
		}
		if (got.ExpiresInHours != nil) != !c.c.NotAfter.IsZero() || (got.NotAfter != nil) != !c.c.NotAfter.IsZero() {
			t.Errorf("%s: expiry fields %v %v", c.c.Name, got.ExpiresInHours, got.NotAfter)
		}
		if got.DNSNames == nil {
			t.Errorf("%s: dnsNames must encode as []", c.c.Name)
		}
	}

	in := cm
	in.Certificates = []model.Certificate{cert("e", "ClusterIssuer", "le", "True", -2*time.Hour)}
	certs, _, _ := SummarizeCerts(in, podNow)
	if h := *certs[0].ExpiresInHours; h != -2 {
		t.Errorf("expiresInHours = %v, want -2", h)
	}
}

func TestSummarizeCertsIssuersAndRequests(t *testing.T) {
	cm := model.CertManager{
		Installed: true,
		Issuers: []model.Issuer{
			{Kind: "Issuer", Namespace: "app", Name: "self", Ready: "True"},
			{Kind: "ClusterIssuer", Name: "le", Ready: "True"},
			{Kind: "ClusterIssuer", Name: "vault", Ready: "False", Message: "permission denied"},
			{Kind: "ClusterIssuer", Name: "new", Ready: ""},
		},
		Certificates: []model.Certificate{
			{Namespace: "app", Name: "a", IssuerKind: "ClusterIssuer", IssuerName: "le"},
			{Namespace: "web", Name: "b", IssuerKind: "ClusterIssuer", IssuerName: "le"},
			{Namespace: "app", Name: "c", IssuerName: "self"},
			{Namespace: "web", Name: "d", IssuerName: "self"}, // a different namespace's Issuer
		},
		Requests: []model.CertificateRequest{
			{Namespace: "app", Name: "done", Ready: "True", Created: podNow.Add(-time.Hour)},
			{Namespace: "app", Name: "failed", Ready: "False", Reason: "Failed", Approved: true, Created: podNow.Add(-3 * time.Hour)},
			{Namespace: "app", Name: "denied", Ready: "False", Reason: "Denied", Denied: true, Created: podNow.Add(-time.Hour)},
			{Namespace: "app", Name: "stuck", Ready: "False", Reason: "Pending", Created: podNow.Add(-time.Hour)},
			{Namespace: "app", Name: "fresh", Ready: "False", Reason: "Pending", Created: podNow.Add(-time.Minute)},
		},
	}
	_, issuers, reqs := SummarizeCerts(cm, podNow)

	var rows []string
	for _, is := range issuers {
		rows = append(rows, is.Name+"="+is.Status)
	}
	if got := strings.Join(rows, " "); got != "new=crit vault=crit le=ok self=ok" {
		t.Errorf("issuers = %s", got)
	}
	uses := map[string]int{}
	for _, is := range issuers {
		uses[is.Name] = is.Certificates
	}
	if uses["le"] != 2 || uses["self"] != 1 || uses["vault"] != 0 {
		t.Errorf("certificate counts = %v", uses)
	}
	if issuers[1].Detail != "Not ready: permission denied." {
		t.Errorf("vault detail = %q", issuers[1].Detail)
	}

	rows = nil
	for _, r := range reqs {
		rows = append(rows, r.Name+"="+r.Status)
	}
	if got := strings.Join(rows, " "); got != "denied=crit failed=crit stuck=warn" {
		t.Errorf("requests = %s", got)
	}
}

func TestSummarizeCertsNotInstalled(t *testing.T) {
	certs, issuers, reqs := SummarizeCerts(model.CertManager{}, podNow)
	if certs == nil || issuers == nil || reqs == nil {
		t.Fatal("want empty non-nil slices so JSON encodes as []")
	}
}
