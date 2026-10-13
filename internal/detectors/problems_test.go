package detectors

import (
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
)

func TestCertProblem(t *testing.T) {
	issuers := IssuerSet([]IssuerSummary{{Kind: "ClusterIssuer", Name: "le"}, {Kind: "Issuer", Namespace: "a", Name: "self"}})
	h := func(v float64) *float64 { return &v }
	for _, c := range []struct {
		cert CertSummary
		want string
	}{
		{CertSummary{Status: StatusOK, IssuerKind: "ClusterIssuer", IssuerName: "gone"}, ""},
		{CertSummary{Status: StatusCrit, IssuerKind: "ClusterIssuer", IssuerName: "gone"}, CertProblemIssuerMissing},
		{CertSummary{Status: StatusCrit, Namespace: "b", IssuerKind: "Issuer", IssuerName: "self"}, CertProblemIssuerMissing},
		{CertSummary{Status: StatusWarn, IssuerKind: "VaultIssuer", IssuerName: "x", Ready: "True", ExpiresInHours: h(5)}, CertProblemExpiring},
		{CertSummary{Status: StatusCrit, IssuerKind: "ClusterIssuer", IssuerName: "le", Ready: "False", ExpiresInHours: h(-1)}, CertProblemExpiring},
		{CertSummary{Status: StatusCrit, IssuerKind: "ClusterIssuer", IssuerName: "le", Ready: "False", ExpiresInHours: h(100)}, CertProblemNotReady},
		{CertSummary{Status: StatusWarn, Namespace: "a", IssuerKind: "Issuer", IssuerName: "self"}, CertProblemNotReady},
	} {
		if got := CertProblem(&c.cert, issuers); got != c.want {
			t.Errorf("CertProblem(%+v) = %q, want %q", c.cert, got, c.want)
		}
	}
}

func TestReasonCountsAndLeakTitle(t *testing.T) {
	if got := ReasonCounts(map[string]int{"ImagePullBackOff": 1, "CrashLoopBackOff": 3, "ErrImagePull": 1, "Zero": 0}); got != "CrashLoopBackOff ×3, ErrImagePull ×1, ImagePullBackOff ×1" {
		t.Errorf("ReasonCounts = %q", got)
	}
	ttl := 2.6
	f := LeakFinding{ContainerKey: model.ContainerKey{Container: "api"}, SlopeBytesPerHour: 120 << 20, TimeToLimitHours: &ttl}
	if got := LeakTitle(f); got != "Memory leak in api: 120 MiB/h, reaches its limit in ~3h" {
		t.Errorf("LeakTitle = %q", got)
	}
	f.TimeToLimitHours = nil
	if got := LeakTitle(f); got != "Memory leak in api: 120 MiB/h, no memory limit" {
		t.Errorf("LeakTitle without limit = %q", got)
	}
}

func TestPodNamed(t *testing.T) {
	inv := model.Inventory{Pods: []model.Pod{{Namespace: "a", Name: "p", Created: time.Now()}}}
	a := Associate(inv, DefaultPolicy())
	if p, ok := a.PodNamed("a", "p"); !ok || p.Name != "p" {
		t.Errorf("PodNamed(a, p) = %v, %v", p, ok)
	}
	if _, ok := a.PodNamed("b", "p"); ok {
		t.Error("PodNamed found a pod in the wrong namespace")
	}
}
