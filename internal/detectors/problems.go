package detectors

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/ByronGary/kubesentry/internal/model"
)

// The helpers here name problems the same way wherever they are raised:
// the Overview's "Needs attention" list (internal/api) and the alerts
// (internal/alerts) share them.

// Certificate problems.
const (
	CertProblemIssuerMissing = "cert-issuer-missing" // the Issuer or ClusterIssuer it names does not exist
	CertProblemExpiring      = "cert-expiring"       // expired, or issued and expiring (renewal is the alert's concern)
	CertProblemNotReady      = "cert-not-ready"      // not ready for another reason (issuer not ready, failed issuance, not issued yet)
)

// IssuerSet indexes issuers by "Kind/namespace/name" for IssuerMissing and
// CertProblem.
func IssuerSet(iss []IssuerSummary) map[string]bool {
	out := make(map[string]bool, len(iss))
	for _, is := range iss {
		out[is.Kind+"/"+is.Namespace+"/"+is.Name] = true
	}
	return out
}

// IssuerMissing reports whether c names a cert-manager issuer that does not
// exist (its detail says so too). External issuer kinds are not judged.
func IssuerMissing(c *CertSummary, issuers map[string]bool) bool {
	switch c.IssuerKind {
	case "Issuer":
		return !issuers["Issuer/"+c.Namespace+"/"+c.IssuerName]
	case "ClusterIssuer":
		return !issuers["ClusterIssuer//"+c.IssuerName]
	}
	return false
}

// CertProblem names what is wrong with a certificate whose status is warn
// or crit, "" for one that is fine: its issuer is missing, else it is
// expiring (expired, or issued and ready but close to expiry or overdue for
// renewal), else it is not ready.
func CertProblem(c *CertSummary, issuers map[string]bool) string {
	if c.Status != StatusCrit && c.Status != StatusWarn {
		return ""
	}
	switch h := c.ExpiresInHours; {
	case IssuerMissing(c, issuers):
		return CertProblemIssuerMissing
	case h != nil && (*h <= 0 || c.Ready == "True"):
		return CertProblemExpiring
	}
	return CertProblemNotReady
}

// IsStuckReason reports whether a container waiting reason does not clear
// by itself (CrashLoopBackOff, ImagePullBackOff, CreateContainerConfigError
// and the like).
func IsStuckReason(reason string) bool { return stuckReasons[reason] }

// ReasonCounts formats reason counts most first, then by name:
// "CrashLoopBackOff ×3, ImagePullBackOff ×1". Zero counts are left out.
func ReasonCounts(counts map[string]int) string {
	type rn struct {
		r string
		n int
	}
	rs := make([]rn, 0, len(counts))
	for r, n := range counts {
		if n > 0 {
			rs = append(rs, rn{r, n})
		}
	}
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].n != rs[j].n {
			return rs[i].n > rs[j].n
		}
		return rs[i].r < rs[j].r
	})
	parts := make([]string, len(rs))
	for i, x := range rs {
		parts[i] = fmt.Sprintf("%s ×%d", x.r, x.n)
	}
	return strings.Join(parts, ", ")
}

// PodNamed returns the inventory's pod with this namespace and name.
func (a *Assoc) PodNamed(ns, name string) (*model.Pod, bool) {
	i, ok := a.podAt[nsName{ns, name}]
	if !ok {
		return nil, false
	}
	return &a.inv.Pods[i], true
}

// LeakTitle is a leak finding in one line: "Memory leak in api: 120 MiB/h,
// reaches its limit in ~3h", or "..., no memory limit".
func LeakTitle(f LeakFinding) string {
	rate := FormatRate(f.SlopeBytesPerHour)
	if f.TimeToLimitHours != nil {
		return fmt.Sprintf("Memory leak in %s: %s, reaches its limit in %s", f.Container, rate, ApproxHours(*f.TimeToLimitHours))
	}
	return fmt.Sprintf("Memory leak in %s: %s, no memory limit", f.Container, rate)
}

// FormatRate formats a growth in bytes per hour: "120 MiB/h".
func FormatRate(b float64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GiB/h", b/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.0f MiB/h", b/(1<<20))
	}
	return fmt.Sprintf("%.0f KiB/h", b/(1<<10))
}

// ApproxHours formats a number of hours roughly: "~40m", "~3h", "~5d".
func ApproxHours(h float64) string {
	switch {
	case h < 1:
		return fmt.Sprintf("~%dm", max(1, int(h*60)))
	case h < 48:
		return fmt.Sprintf("~%dh", int(math.Round(h)))
	}
	return fmt.Sprintf("~%dd", int(math.Round(h/24)))
}
