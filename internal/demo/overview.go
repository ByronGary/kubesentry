package demo

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/model"
	"github.com/ByronGary/kubesentry/internal/snapshot"
)

// leakWindow is the demo leak scan's window, the real scanner's default.
const leakWindow = 24 * time.Hour

// leakScan is the demo's background leak scan: the synthetic series are
// analysed as the real scanner analyses Prometheus', at most once a minute.
type leakScan struct {
	mu  sync.Mutex
	at  time.Time
	rep detectors.LeakReport
}

// LeakReport serves the leak scan to /oom (for its default window) and to
// the Overview's attention list, as the real server's scanner does.
func (m *Metrics) LeakReport() (detectors.LeakReport, time.Duration, bool) {
	m.scan.mu.Lock()
	defer m.scan.mu.Unlock()
	now := time.Now()
	if now.Sub(m.scan.at) >= time.Minute {
		m.scan.rep, m.scan.at = m.leakScan(now), now
	}
	return m.scan.rep, leakWindow, true
}

func (m *Metrics) leakScan(now time.Time) detectors.LeakReport {
	series, _ := m.ContainerMemory(context.Background(), leakWindow, leakWindow/240)
	limits := m.limits(func(model.ContainerKey) bool { return true })
	ooms := map[model.ContainerKey]detectors.OOMEvent{}
	for _, e := range detectors.FindOOMKills(m.pods, now.Add(-leakWindow)) {
		ooms[e.ContainerKey] = e
	}
	rep := detectors.LeakReport{GeneratedAt: now, LastAttempt: now, Window: leakWindow.String(), Candidates: len(series), Findings: []detectors.LeakFinding{}}
	for _, s := range series {
		f, ok := detectors.AnalyzeLeak(s, limits[s.Key], detectors.DefaultLeakOptions())
		if !ok {
			continue
		}
		if e, hit := ooms[s.Key]; hit {
			t := e.LastOOMAt
			f.OOMKilled, f.LastOOMAt = true, &t
		}
		rep.Findings = append(rep.Findings, f)
	}
	sort.Slice(rep.Findings, func(i, j int) bool {
		a, b := rep.Findings[i].TimeToLimitHours, rep.Findings[j].TimeToLimitHours
		switch {
		case a != nil && b != nil && *a != *b:
			return *a < *b
		case (a == nil) != (b == nil):
			return a != nil
		}
		return rep.Findings[i].SlopeBytesPerHour > rep.Findings[j].SlopeBytesPerHour
	})
	return rep
}

// PrefillHistory gives the Overview a believable day of history ending at
// now, built from the demo's current counters: the crash loop in prod began
// about 40 minutes ago, the backup failed two hours ago, a deploy wobbled
// in staging this morning, and a privileged pod appeared in data six hours
// ago (so "new since 24h" has something to say).
func PrefillHistory(h *snapshot.History, v *snapshot.View, now time.Time) {
	cur := v.Counts()
	step := h.Step()
	n := h.Buckets()
	for i := n - 1; i >= 1; i-- {
		at := now.Add(-time.Duration(i) * step)
		ago := time.Duration(i) * step
		counts := make(map[snapshot.CountKey]snapshot.Counts, len(cur))
		for k, c := range cur {
			c := c
			if k.Namespace == "prod" && !k.RBAC {
				if ago > 40*time.Minute {
					c[snapshot.FailingPods] = 0
					c[snapshot.UnhealthyWorkloads] = max(0, c[snapshot.UnhealthyWorkloads]-1)
				}
				if ago > 2*time.Hour {
					c[snapshot.UnhealthyWorkloads] = max(0, c[snapshot.UnhealthyWorkloads]-1)
				}
				// Certificates crossed into their last 14 days over the day.
				if ago > 12*time.Hour {
					c[snapshot.CertsExpiringSoon] = max(0, c[snapshot.CertsExpiringSoon]-1)
				}
			}
			if k.Namespace == "data" && !k.RBAC && ago > 6*time.Hour {
				c[snapshot.SecurityCrit] = max(0, c[snapshot.SecurityCrit]-1)
				c[snapshot.SecurityWarn] = max(0, c[snapshot.SecurityWarn]-2)
			}
			counts[k] = c
		}
		// A rollout in staging this morning: two workloads unhealthy for 40 minutes.
		if ago > 9*time.Hour && ago <= 9*time.Hour+40*time.Minute {
			c := counts[snapshot.CountKey{Namespace: "staging"}]
			c[snapshot.UnhealthyWorkloads] += 2
			c[snapshot.FailingPods]++
			counts[snapshot.CountKey{Namespace: "staging"}] = c
		}
		h.RecordCounts(at, counts)
	}
	h.Record(v)
}
