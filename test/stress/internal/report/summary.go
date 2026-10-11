package report

import (
	"fmt"

	"github.com/ByronGary/kubesentry/test/stress/internal/firehose"
	"github.com/ByronGary/kubesentry/test/stress/internal/hist"
	"sort"
	"strings"
)

// Summary renders the cross-level comparison from several report.json files.
func Summary(title string, reps []*Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", title)
	fmt.Fprintf(&b, "Runs: ")
	for i, r := range reps {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%s (%s, limit %s)", r.Run, r.Level, r.MemoryLimit)
	}
	b.WriteString("\n\n## Levels\n\n| Run | Fake nodes | Pods | Namespaces | Services | Deployments | kubesentry mem max MiB | restarts (OOMKilled) | apiserver mem max MiB | etcd mem max MiB | host avail min MiB |\n|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n")
	for _, r := range reps {
		nodes, pods, ns, svcs, deps := 0, 0, 0, 0, 0
		if g := r.Gen; g != nil {
			nodes, pods, ns, deps = g.Settle.FakeNodes, g.Settle.Pods, g.Plan.TeamNamespaces+g.Plan.AddonNamespaces, g.Plan.Deployments
			for _, v := range g.Plan.Services {
				svcs += v
			}
		}
		var kmax, amax, emax, hmin float64
		restarts := 0
		reasons := map[string]bool{}
		for _, s := range r.Steps {
			kmax = max(kmax, s.Usage["kubesentry"].MemMiB.Max)
			amax = max(amax, s.Usage["kube-apiserver"].MemMiB.Max)
			emax = max(emax, s.Usage["etcd"].MemMiB.Max)
			if s.HostAvailMinMiB > 0 && (hmin == 0 || s.HostAvailMinMiB < hmin) {
				hmin = s.HostAvailMinMiB
			}
			restarts += max(0, s.Restarts)
			if s.LastReason != "" {
				reasons[s.LastReason] = true
			}
		}
		fmt.Fprintf(&b, "| %s | %d | %d | %d | %d | %d | %.0f | %d %s | %.0f | %.0f | %.0f |\n", r.Run, nodes, pods, ns, svcs, deps, kmax, restarts, keys(reasons), amax, emax, hmin)
	}

	b.WriteString("\n## Dashboard users: highest stage within the abort criteria\n\nA stage passes when, over the whole stage, the error rate (5xx, 429, timeouts, transport errors, superseded polls) is at most 20% and the slowest route's p99 (all requests; unfinished ones at their elapsed time) is at most 60s.\n\n| Run | Users run | Stages (users: error rate, p99) | Highest passing stage | Ramp aborted |\n|---|---|---|---:|---|\n")
	for _, r := range reps {
		names := make([]string, 0, len(r.Users))
		for n := range r.Users {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			u := r.Users[n]
			best := 0
			var parts []string
			for _, s := range u.Stages {
				er, p99 := StageErrors(s.Routes)
				parts = append(parts, fmt.Sprintf("%d: %.0f%%, %s", s.Users, 100*er, ms(p99)))
				if er <= 0.2 && p99 <= 60000 && s.Users > best {
					best = s.Users
				}
			}
			ab := "no"
			if u.Aborted {
				ab = u.Reason
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %d | %s |\n", r.Run, n, strings.Join(parts, "; "), best, ab)
		}
	}
	b.WriteString("\n## Dashboard users: latency by route and user count\n\np50 / p95 / p99 over all requests (timeouts and client aborts counted at their elapsed time, so values are lower bounds when they occur).\n\n")
	for _, r := range reps {
		names := make([]string, 0, len(r.Users))
		for n := range r.Users {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			u := r.Users[n]
			fmt.Fprintf(&b, "### %s / %s\n\n", r.Run, n)
			if u.Aborted {
				fmt.Fprintf(&b, "Aborted: %s.\n\n", u.Reason)
			}
			fmt.Fprintf(&b, "| Users | req/s | info | pods | diagnostics | processes | oom | workloads | nodes | map | security | audit-events | errors | timeouts | kubesentry API req/s |\n|---:|---:|---|---|---|---|---|---|---|---|---|---|---:|---:|---:|\n")
			for _, s := range u.Stages {
				fmt.Fprintf(&b, "| %d | %.1f |", s.Users, s.RPS)
				for _, rn := range []string{"info", "pods", "diagnostics", "processes", "oom", "workloads", "nodes", "map", "security", "audit-events"} {
					rr := routeOf(s.Routes, rn)
					if rr == nil {
						b.WriteString(" - |")
						continue
					}
					fmt.Fprintf(&b, " %s / %s / %s |", ms(rr.All.P50), ms(rr.All.P95), ms(rr.All.P99))
				}
				var reqs, bad, tos int64
				for _, rr := range s.Routes {
					reqs += rr.Requests - rr.Aborted
					bad += int64(rr.ErrorRate * float64(rr.Requests-rr.Aborted))
					tos += rr.Timeouts
				}
				er := 0.0
				if reqs > 0 {
					er = float64(bad) / float64(reqs)
				}
				api := "-"
				for _, st := range r.Steps {
					if strings.HasPrefix(st.Name, n) && st.KubesentryAPI != nil && !s.Started.Before(st.Start) && !s.Started.After(st.End) {
						// per-stage rate from the per-minute counts
						var cnt, mins int
						for _, m := range st.KubesentryAPI.Minutes {
							if !m.T.Before(s.Started) && m.T.Before(s.Started.Add(secs(s.Seconds))) {
								cnt += m.N
								mins++
							}
						}
						if mins > 0 {
							api = fmt.Sprintf("%.2f", float64(cnt)/float64(mins*60))
						}
					}
				}
				fmt.Fprintf(&b, " %.1f%% | %d | %s |\n", 100*er, tos, api)
			}
			b.WriteString("\n")
		}
	}

	b.WriteString("## Association precision / recall\n\n| Run | ")
	rels := []string{"pod-owner@map", "pod-owner@nodes", "service-pods@map", "pod-node@map", "pod-node@nodes", "pod-pvc@map", "cronjob-job@map", "ingress-service@map", "security-group@security", "workload-pods@workloads"}
	b.WriteString(strings.Join(rels, " | "))
	b.WriteString(" | tricky cases met |\n|---|")
	for range rels {
		b.WriteString("---|")
	}
	b.WriteString("---|\n")
	for _, r := range reps {
		if r.Assoc == nil {
			continue
		}
		fmt.Fprintf(&b, "| %s |", r.Run)
		for _, k := range rels {
			s, ok := r.Assoc.Summary[k]
			if !ok {
				b.WriteString(" - |")
				continue
			}
			fmt.Fprintf(&b, " %.1f%% / %.1f%% |", 100*s.Precision, 100*s.Recall)
		}
		pass := 0
		for _, c := range r.Assoc.Cases {
			if c.OK {
				pass++
			}
		}
		fmt.Fprintf(&b, " %d/%d |\n", pass, len(r.Assoc.Cases))
	}
	b.WriteString("\n(workload-pods: share of workloads whose pod count is exact.)\n\n## Connectivity\n\n| Run | probes passed | by check | Prometheus via kubesentry | agents fresh |\n|---|---|---|---|---|\n")
	for _, r := range reps {
		if c := r.Conn; c != nil {
			fmt.Fprintf(&b, "| %s | %d/%d | %v | metrics=%v oom=%v (%s) | %d/%d |\n", r.Run, c.Passed, c.Passed+c.Failed, c.ByCheck, c.Prometheus.InfoMetrics, c.Prometheus.OOMOK, ms(c.Prometheus.OOMMs), countAgents(c.Agents), len(c.Agents))
		}
	}
	b.WriteString("\n## Audit firehose and queries\n\n| Run | accepted / sent | events/s | webhook p50/p99 | failed batches | events?limit=500 p50/p99 | summary 24h p50/p99 | all reads p50/p99 |\n|---|---|---:|---|---:|---|---|---|\n")
	for _, r := range reps {
		runs := []struct {
			name string
			a    *firehose.Result
		}{{r.Run + " (" + r.MemoryLimit + ")", r.Audit}}
		for n, a := range r.AuditExtra {
			runs = append(runs, struct {
				name string
				a    *firehose.Result
			}{r.Run + " " + n, a})
		}
		for _, run := range runs {
			a := run.a
			if a == nil {
				continue
			}
			wh := "-"
			for _, in := range a.Ingest {
				wh = ms(in.All.P50) + " / " + ms(in.All.P99)
			}
			q := func(name string) string {
				rr := routeOf(a.Queries, name)
				switch {
				case rr == nil:
					return "-"
				case rr.Status["200"] == 0:
					return fmt.Sprintf("failed %v", rr.Errors)
				case rr.Status["200"] < rr.Requests:
					return fmt.Sprintf("%s / %s (%d of %d failed)", ms(rr.Completed.P50), ms(rr.Completed.P99), rr.Requests-rr.Status["200"], rr.Requests)
				}
				return ms(rr.Completed.P50) + " / " + ms(rr.Completed.P99)
			}
			fmt.Fprintf(&b, "| %s | %d / %d | %.0f | %s | %d | %s | %s | %s |\n", run.name, a.AcceptedEvents, a.SentEvents, a.AchievedRate, wh, a.FailedBatches,
				q("events default (Findings)"), q("summary 24h"), q("events all reads"))
		}
	}
	b.WriteString("\n## Agents\n\n| Run | mode | agents | posts/s | MB/s | success | 429 | 5xx | timeouts | p50 / p99 | fresh / checked |\n|---|---|---:|---:|---:|---:|---:|---:|---:|---|---|\n")
	for _, r := range reps {
		names := make([]string, 0, len(r.Agents))
		for n := range r.Agents {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			ag := r.Agents[n]
			lat := "-"
			for _, p := range ag.Posts {
				lat = ms(p.All.P50) + " / " + ms(p.All.P99)
			}
			fmt.Fprintf(&b, "| %s | %s | %d | %.1f | %.1f | %.1f%% | %d | %d | %d | %s | %d / %d |\n", r.Run, ag.Mode, ag.Agents, ag.PostsPerSec, ag.MBytesPerSec, 100*ag.SuccessRate, ag.Status429, ag.Status5xx, ag.Timeouts, lat, ag.Fresh, ag.CheckedPods)
		}
	}
	return b.String()
}

// StageErrors returns a stage's error rate over requests not abandoned by
// navigation, and the p99 over all of its requests.
func StageErrors(routes []hist.RouteReport) (float64, float64) {
	var reqs, bad float64
	p99 := 0.0
	for _, rr := range routes {
		n := float64(rr.Requests - rr.Aborted)
		reqs += n
		bad += rr.ErrorRate * n
		p99 = max(p99, rr.All.P99)
	}
	if reqs == 0 {
		return 0, p99
	}
	return bad / reqs, p99
}

func keys(m map[string]bool) string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return ""
	}
	return "(" + strings.Join(out, ",") + ")"
}
