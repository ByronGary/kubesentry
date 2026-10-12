package snapshot

import (
	"time"

	"github.com/ByronGary/kubesentry/internal/detectors"
)

// The Overview's tiles and its history share these counters, so a tile and
// its sparkline always agree.
const (
	UnhealthyWorkloads = iota // workloads with status crit or warn
	FailingPods               // detectors.PodState failing
	SecurityCrit              // non-system security findings, by severity
	SecurityWarn
	CertsExpiringSoon // certificates expiring within ExpiringSoon (or expired)
	NumSeries
)

// SeriesNames are the counters' JSON names, by index.
var SeriesNames = [NumSeries]string{"unhealthyWorkloads", "failingPods", "securityCrit", "securityWarn", "certsExpiringSoon"}

// ExpiringSoon is how close to expiry a certificate counts on the Overview.
const ExpiringSoon = 14 * 24 * time.Hour

// Counts holds one value per series.
type Counts [NumSeries]int32

// IsZero reports whether every counter is zero.
func (c Counts) IsZero() bool { return c == Counts{} }

// CountKey says what a Counts covers, so a caller sums exactly what they may
// see: one namespace's counters (RBAC false), that namespace's RBAC findings
// (RBAC true; the security series only, which need ViewRBAC there), or with
// Namespace "" the cluster-scoped findings (ViewClusterRBAC).
type CountKey struct {
	Namespace string
	RBAC      bool
}

// Counts returns the view's counters by CountKey, computed once per view.
// Keys whose counters are all zero are left out. The map is shared: do not
// modify it.
func (v *View) Counts() map[CountKey]Counts {
	return v.Memo("snapshot/counts", func() any {
		out := map[CountKey]Counts{}
		add := func(k CountKey, s int) {
			c := out[k]
			c[s]++
			out[k] = c
		}
		for ns, ws := range v.Workloads {
			for i := range ws {
				if s := ws[i].Status; s == detectors.StatusCrit || s == detectors.StatusWarn {
					add(CountKey{Namespace: ns}, UnhealthyWorkloads)
				}
			}
		}
		th := v.Policy.Thresholds
		for i := range v.Inv.Pods {
			p := &v.Inv.Pods[i]
			if st, _ := detectors.PodState(p, th, v.Built); st == detectors.PodFailing {
				add(CountKey{Namespace: p.Namespace}, FailingPods)
			}
		}
		for ns, fs := range v.Findings {
			for i := range fs {
				f := &fs[i]
				if f.System {
					continue
				}
				k := CountKey{Namespace: ns, RBAC: ns != "" && f.Category == "rbac"}
				switch f.Severity {
				case detectors.StatusCrit:
					add(k, SecurityCrit)
				case detectors.StatusWarn:
					add(k, SecurityWarn)
				}
			}
		}
		for ns, cs := range v.Certs {
			for i := range cs {
				if CertExpiringSoon(&cs[i]) {
					add(CountKey{Namespace: ns}, CertsExpiringSoon)
				}
			}
		}
		return out
	}).(map[CountKey]Counts)
}

// CertExpiringSoon reports whether a certificate expires within
// ExpiringSoon of the view's build, or has expired.
func CertExpiringSoon(c *detectors.CertSummary) bool {
	return c.ExpiresInHours != nil && *c.ExpiresInHours < ExpiringSoon.Hours()
}
