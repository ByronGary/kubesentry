package detectors

import (
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
)

// Certificates expiring sooner than these are flagged, even when cert-manager
// still reports them Ready.
const (
	certCritBefore = 7 * 24 * time.Hour
	certWarnBefore = 30 * 24 * time.Hour
)

// SummarizeCerts judges cert-manager Certificates, their issuers and any
// CertificateRequests that are stuck. Each list is sorted most troubled first.
func SummarizeCerts(cm model.CertManager, now time.Time) ([]CertSummary, []IssuerSummary, []RequestSummary) {
	issuers := map[string]model.Issuer{}
	for _, is := range cm.Issuers {
		issuers[roleKey(is.Kind, is.Namespace, is.Name)] = is
	}
	uses := map[string]int{}

	certs := make([]CertSummary, 0, len(cm.Certificates))
	for _, c := range cm.Certificates {
		kind := c.IssuerKind
		if kind == "" {
			kind = "Issuer"
		}
		s := CertSummary{
			Namespace: c.Namespace, Name: c.Name, SecretName: c.SecretName, DNSNames: append([]string{}, c.DNSNames...),
			IssuerKind: kind, IssuerName: c.IssuerName, Ready: c.Ready, Reason: c.Reason, Message: c.Message,
			NotAfter: timePtr(c.NotAfter), RenewalTime: timePtr(c.RenewalTime),
		}
		if !c.NotAfter.IsZero() {
			h := c.NotAfter.Sub(now).Hours()
			s.ExpiresInHours = &h
		}

		// Only cert-manager's own kinds can be looked up; external issuers are not judged.
		var issuer model.Issuer
		known, found := false, false
		switch kind {
		case "Issuer":
			known = true
			issuer, found = issuers[roleKey("Issuer", c.Namespace, c.IssuerName)]
		case "ClusterIssuer":
			known = true
			issuer, found = issuers[roleKey("ClusterIssuer", "", c.IssuerName)]
		}
		if found {
			uses[roleKey(issuer.Kind, issuer.Namespace, issuer.Name)]++
		}

		left := c.NotAfter.Sub(now)
		switch {
		case known && !found:
			s.Status, s.Detail = StatusCrit, fmt.Sprintf("%s %s not found.", kind, c.IssuerName)
		case found && issuer.Ready != "True":
			s.Status, s.Detail = StatusCrit, fmt.Sprintf("%s %s is not ready: %s", kind, c.IssuerName, sentence(issuer.Message, "no reason given"))
		case c.Ready == "False":
			s.Status, s.Detail = StatusCrit, sentence(c.Message, "Not ready: "+c.Reason)
		case !c.NotAfter.IsZero() && left <= 0:
			s.Status, s.Detail = StatusCrit, "Expired "+ago(-left)+"."
		case !c.NotAfter.IsZero() && left < certCritBefore:
			s.Status, s.Detail = StatusCrit, "Expires in "+daysOrHours(left)+"."
		case !c.NotAfter.IsZero() && left < certWarnBefore:
			s.Status, s.Detail = StatusWarn, "Expires in "+daysOrHours(left)+"."
		case c.NotAfter.IsZero() && c.Ready != "True":
			s.Status, s.Detail = StatusWarn, "Not issued yet."
		case c.NotAfter.IsZero():
			s.Status, s.Detail = StatusOK, "Ready."
		default:
			s.Status, s.Detail = StatusOK, fmt.Sprintf("Valid for %d more days.", days(left))
		}
		certs = append(certs, s)
	}
	sort.Slice(certs, func(i, j int) bool {
		a, b := certs[i], certs[j]
		switch {
		case statusRank(a.Status) != statusRank(b.Status):
			return statusRank(a.Status) < statusRank(b.Status)
		case a.Namespace != b.Namespace:
			return a.Namespace < b.Namespace
		}
		return a.Name < b.Name
	})

	iss := make([]IssuerSummary, 0, len(cm.Issuers))
	for _, is := range cm.Issuers {
		s := IssuerSummary{
			Kind: is.Kind, Namespace: is.Namespace, Name: is.Name, Type: is.Type, Server: is.Server,
			Ready: is.Ready, Reason: is.Reason, Message: is.Message,
			Certificates: uses[roleKey(is.Kind, is.Namespace, is.Name)],
		}
		if is.Ready == "True" {
			s.Status, s.Detail = StatusOK, "Ready."
		} else {
			s.Status, s.Detail = StatusCrit, "Not ready: "+sentence(is.Message, "no reason given")
		}
		iss = append(iss, s)
	}
	sort.Slice(iss, func(i, j int) bool {
		a, b := iss[i], iss[j]
		switch {
		case statusRank(a.Status) != statusRank(b.Status):
			return statusRank(a.Status) < statusRank(b.Status)
		case a.Kind != b.Kind:
			return a.Kind < b.Kind
		case a.Namespace != b.Namespace:
			return a.Namespace < b.Namespace
		}
		return a.Name < b.Name
	})

	reqs := []RequestSummary{}
	for _, r := range cm.Requests {
		if r.Ready == "True" {
			continue
		}
		var status string
		switch {
		case r.Denied || (r.Ready == "False" && r.Reason == "Failed"):
			status = StatusCrit
		case now.Sub(r.Created) > pendingGrace:
			status = StatusWarn
		default:
			continue // just created; give it a moment
		}
		reqs = append(reqs, RequestSummary{
			Namespace: r.Namespace, Name: r.Name, Certificate: r.Certificate, IssuerKind: r.IssuerKind, IssuerName: r.IssuerName,
			Ready: r.Ready, Reason: r.Reason, Message: r.Message, Approved: r.Approved, Denied: r.Denied,
			Created: r.Created, Status: status,
		})
	}
	sort.Slice(reqs, func(i, j int) bool {
		a, b := reqs[i], reqs[j]
		switch {
		case statusRank(a.Status) != statusRank(b.Status):
			return statusRank(a.Status) < statusRank(b.Status)
		case !a.Created.Equal(b.Created):
			return a.Created.After(b.Created)
		case a.Namespace != b.Namespace:
			return a.Namespace < b.Namespace
		}
		return a.Name < b.Name
	})
	return certs, iss, reqs
}

// daysOrHours formats a time span as "12 days", or "30 hours" under two days.
// Days are rounded, as the UI does, so the detail and the expiry column agree.
func daysOrHours(d time.Duration) string {
	if d < 48*time.Hour {
		return hours(d.Hours())
	}
	n := days(d)
	return fmt.Sprintf("%d %s", n, plural(n, "day", "days"))
}

func days(d time.Duration) int { return int(math.Round(d.Hours() / 24)) }
