package main

import (
	"context"
	"flag"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/ByronGary/kubesentry/test/stress/internal/chaos"
	"github.com/ByronGary/kubesentry/test/stress/internal/kc"
	"github.com/ByronGary/kubesentry/test/stress/internal/out"
	"github.com/ByronGary/kubesentry/test/stress/internal/report"
	"github.com/ByronGary/kubesentry/test/stress/internal/users"
)

func prom(cl *kc.Clients) *report.Prom {
	return &report.Prom{CS: cl.CS, Namespace: "monitoring", Service: "kps-kube-prometheus-stack-prometheus", Port: "9090"}
}

// cmdServerMetrics records what kubesentry, Postgres and oauth2-proxy did
// during windows of a run (users stages, steps, chaos scenarios) while
// Prometheus still has the data (6h retention; the Prometheus chaos scenario
// wipes it): server-<name>.json and .md in the run directory.
func cmdServerMetrics(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("server-metrics", flag.ExitOnError)
	var kf kc.Flags
	kf.Register(fs, 20, 40)
	dir := fs.String("dir", "", "run directory")
	usersFile := fs.String("users", "", "users result (e.g. users-1Gi.json): one window per stage")
	steps := fs.String("steps", "", "comma-separated step names from steps.tsv (the last run of each)")
	chaosFile := fs.String("chaos", "", "chaos result: one window per scenario")
	name := fs.String("name", "", "output name (server-<name>.json); default from the input")
	_ = fs.Parse(args)
	if *dir == "" {
		return fmt.Errorf("--dir is required")
	}
	var ws []report.Window
	if *usersFile != "" {
		var u users.Result
		if err := out.ReadJSON(filepath.Join(*dir, *usersFile), &u); err != nil {
			return err
		}
		for _, s := range u.Stages {
			ws = append(ws, report.Window{Name: fmt.Sprintf("%d users", s.Users), From: s.Started, To: s.Started.Add(time.Duration(s.Seconds * float64(time.Second)))})
		}
		if *name == "" {
			*name = strings.TrimSuffix(*usersFile, ".json")
		}
	}
	if *steps != "" {
		all, err := report.ReadSteps(filepath.Join(*dir, "steps.tsv"))
		if err != nil {
			return err
		}
		for _, n := range splitList(*steps) {
			var last *report.Step
			for i := range all {
				if all[i].Name == n {
					last = &all[i]
				}
			}
			if last == nil {
				out.Logf("server-metrics: no step %q in steps.tsv", n)
				continue
			}
			ws = append(ws, report.Window{Name: n, From: last.Start, To: last.End})
		}
		if *name == "" {
			*name = "steps"
		}
	}
	if *chaosFile != "" {
		var c chaos.Result
		if err := out.ReadJSON(filepath.Join(*dir, *chaosFile), &c); err != nil {
			return err
		}
		for _, s := range c.Scenarios {
			if !s.Started.IsZero() {
				ws = append(ws, report.Window{Name: s.Name, From: s.Started, To: s.Ended})
			}
		}
		if *name == "" {
			*name = strings.TrimSuffix(*chaosFile, ".json")
		}
	}
	if len(ws) == 0 {
		return fmt.Errorf("no windows: pass --users, --steps or --chaos")
	}
	cl, err := kf.Connect()
	if err != nil {
		return err
	}
	ms := report.CollectAll(ctx, prom(cl), ws)
	for _, m := range ms {
		out.Logf("server-metrics %s: SAR %.1f/s, authz cache hit %.0f%%, http cache hit %.0f%%, kube %.2f/s, RSS %v, snapshot p99 %.1fs, pg CPU max %.2f, proxy CPU max %v, errors %d",
			m.Name, m.SARPerSec, 100*m.AuthzHitRatio, 100*m.HTTPHitRatio, m.KubePerSec, m.RSSMaxMiB, m.SnapshotAgeP99, m.PostgresCPUMax, m.ProxyCPUMax, len(m.Errors))
	}
	if err := out.WriteJSON(*dir, "server-"+*name+".json", ms); err != nil {
		return err
	}
	return out.WriteText(*dir, "server-"+*name+".md", "# Server-side metrics: "+*name+"\n\n"+report.ServerMarkdown(ms))
}

// cmdSoakReport writes soak.json and soak.md: kubesentry's memory,
// goroutines, snapshot age, Postgres size and partitions, and the users'
// errors over the soak, with upward trends flagged.
func cmdSoakReport(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("soak-report", flag.ExitOnError)
	var kf kc.Flags
	kf.Register(fs, 20, 40)
	dir := fs.String("dir", "", "run directory")
	usersFile := fs.String("users", "users-soak.json", "the soak's users result")
	pgFile := fs.String("pg", "pg-soak.csv", "the Postgres sampler's CSV")
	warmup := fs.Duration("warmup", 15*time.Minute, "ignored for trends")
	restarts := fs.String("restarts", "", "kubesentry restarts during the soak (from hack/stress-run.sh)")
	_ = fs.Parse(args)
	if *dir == "" {
		return fmt.Errorf("--dir is required")
	}
	var u users.Result
	if err := out.ReadJSON(filepath.Join(*dir, *usersFile), &u); err != nil {
		return err
	}
	pg, err := report.ReadPGSamples(filepath.Join(*dir, *pgFile))
	if err != nil {
		out.Logf("soak-report: %v", err)
	}
	cl, err := kf.Connect()
	if err != nil {
		return err
	}
	s := report.BuildSoak(ctx, prom(cl), &u, pg, u.Started, u.Finished, *warmup)
	s.Restarts = *restarts
	for _, f := range s.Flagged {
		out.Logf("soak: flagged %s", f)
	}
	if err := out.WriteJSON(*dir, "soak.json", s); err != nil {
		return err
	}
	return out.WriteText(*dir, "soak.md", s.Markdown())
}
