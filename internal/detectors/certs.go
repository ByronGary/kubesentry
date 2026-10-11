package detectors

import (
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
)

// certDefaultDuration is cert-manager's default certificate lifetime, used
// when neither spec.duration nor the issued certificate's dates are known.
const certDefaultDuration = 90 * 24 * time.Hour

// SummarizeCerts judges cert-manager objects with the default policy.
func SummarizeCerts(cm model.CertManager, now time.Time) ([]CertSummary, []IssuerSummary, []RequestSummary) {
	return SummarizeCertsWith(cm, compatPolicy(), now)
}

// certLifetime is the span expiry is judged against: the issued
// certificate's own validity when both dates are known (a CA may cap what was
// asked for), else spec.duration, else cert-manager's 90-day default.
func certLifetime(c model.Certificate) time.Duration {
	if !c.NotBefore.IsZero() && c.NotAfter.After(c.NotBefore) {
		return c.NotAfter.Sub(c.NotBefore)
	}
	if c.Duration > 0 {
		return c.Duration
	}
	return certDefaultDuration
}

// certThresholds returns the time-left cut-offs for crit and warn:
// min(cap, fraction × lifetime) each.
func certThresholds(life time.Duration, t Thresholds) (crit, warn time.Duration) {
	crit = time.Duration(float64(life) * t.CertCritFraction)
	if t.CertCritCap > 0 && (crit <= 0 || t.CertCritCap < crit) {
		crit = t.CertCritCap
	}
	warn = time.Duration(float64(life) * t.CertWarnFraction)
	if t.CertWarnCap > 0 && (warn <= 0 || t.CertWarnCap < warn) {
		warn = t.CertWarnCap
	}
	return crit, warn
}

// SummarizeCertsWith judges cert-manager Certificates, their issuers and any
// CertificateRequests that are stuck. Expiry is judged against each
// certificate's lifetime (see Thresholds), so short-lived certificates are not
// always critical. Each list is sorted most troubled first.
func SummarizeCertsWith(cm model.CertManager, p Policy, now time.Time) ([]CertSummary, []IssuerSummary, []RequestSummary) {
	t := p.Thresholds
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
		critBelow, warnBelow := certThresholds(certLifetime(c), t)
		overdue := !c.RenewalTime.IsZero() && now.Sub(c.RenewalTime) > t.CertRenewalGrace
		switch {
		case known && !found:
			s.Status, s.Detail = StatusCrit, fmt.Sprintf("%s %s not found.", kind, c.IssuerName)
		case found && issuer.Ready != "True":
			s.Status, s.Detail = StatusCrit, fmt.Sprintf("%s %s is not ready: %s", kind, c.IssuerName, sentence(issuer.Message, "no reason given"))
		case c.Ready == "False":
			s.Status, s.Detail = StatusCrit, sentence(c.Message, "Not ready: "+c.Reason)
		case !c.NotAfter.IsZero() && left <= 0:
			s.Status, s.Detail = StatusCrit, "Expired "+ago(-left)+"."
		case !c.NotAfter.IsZero() && left < critBelow:
			s.Status, s.Detail = StatusCrit, "Expires in "+daysOrHours(left)+"."
		case !c.NotAfter.IsZero() && overdue:
			s.Status, s.Detail = StatusWarn, "Renewal is overdue by "+daysOrHours(now.Sub(c.RenewalTime))+"; expires in "+daysOrHours(left)+"."
		case !c.NotAfter.IsZero() && left < warnBelow:
			s.Status, s.Detail = StatusWarn, "Expires in "+daysOrHours(left)+"."
		case c.NotAfter.IsZero() && c.Ready != "True":
			s.Status, s.Detail = StatusWarn, "Not issued yet."
		case c.NotAfter.IsZero():
			s.Status, s.Detail = StatusOK, "Ready."
		case left < 48*time.Hour:
			s.Status, s.Detail = StatusOK, "Valid for "+hours(left.Hours())+" more."
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
		case now.Sub(r.Created) > t.PendingGrace:
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
