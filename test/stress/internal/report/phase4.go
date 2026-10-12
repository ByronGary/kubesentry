package report

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ByronGary/kubesentry/test/stress/internal/chaos"
	"github.com/ByronGary/kubesentry/test/stress/internal/out"
	"github.com/ByronGary/kubesentry/test/stress/internal/verify"
)

// Extras are the after run's additional results: server-side metrics per
// window, the soak, chaos runs and the repeated verifications.
type Extras struct {
	Server map[string][]ServerMetrics     `json:"server,omitempty"`
	Soak   *Soak                          `json:"soak,omitempty"`
	Chaos  map[string]*chaos.Result       `json:"chaos,omitempty"`
	Assocs map[string]*verify.AssocResult `json:"assocRuns,omitempty"`
	Authzs map[string]*verify.AuthzResult `json:"authzRuns,omitempty"`
}

func base(f string) string { return strings.TrimSuffix(filepath.Base(f), ".json") }

func loadExtras(dir string, errs *[]string) Extras {
	x := Extras{Server: map[string][]ServerMetrics{}, Chaos: map[string]*chaos.Result{}, Assocs: map[string]*verify.AssocResult{}, Authzs: map[string]*verify.AuthzResult{}}
	read := func(f string, v any) bool {
		if err := out.ReadJSON(f, v); err != nil {
			*errs = append(*errs, filepath.Base(f)+": "+err.Error())
			return false
		}
		return true
	}
	files, _ := filepath.Glob(filepath.Join(dir, "server-*.json"))
	for _, f := range files {
		var ms []ServerMetrics
		if read(f, &ms) {
			x.Server[strings.TrimPrefix(base(f), "server-")] = ms
		}
	}
	var s Soak
	if files, _ := filepath.Glob(filepath.Join(dir, "soak.json")); len(files) == 1 && read(files[0], &s) {
		x.Soak = &s
	}
	files, _ = filepath.Glob(filepath.Join(dir, "chaos*.json"))
	for _, f := range files {
		var c chaos.Result
		if read(f, &c) {
			x.Chaos[base(f)] = &c
		}
	}
	files, _ = filepath.Glob(filepath.Join(dir, "assoc*.json"))
	for _, f := range files {
		var a verify.AssocResult
		if read(f, &a) {
			x.Assocs[base(f)] = &a
		}
	}
	files, _ = filepath.Glob(filepath.Join(dir, "authz*.json"))
	for _, f := range files {
		var a verify.AuthzResult
		if read(f, &a) {
			x.Authzs[base(f)] = &a
		}
	}
	return x
}

func sortedKeys[V any](m map[string]V) []string {
	k := make([]string, 0, len(m))
	for n := range m {
		k = append(k, n)
	}
	sort.Strings(k)
	return k
}

// AssocLine summarises one verify assoc run.
func AssocLine(a *verify.AssocResult) string {
	pass := 0
	for _, c := range a.Cases {
		if c.OK {
			pass++
		}
	}
	worstP, worstR, worst := 1.0, 1.0, ""
	for _, k := range sortedKeys(a.Summary) {
		s := a.Summary[k]
		if s.Precision < worstP || s.Recall < worstR {
			worstP, worstR, worst = min(worstP, s.Precision), min(worstR, s.Recall), k
		}
	}
	return fmt.Sprintf("tricky %d/%d; lowest precision / recall %.1f%% / %.1f%% (%s); workload counts %d/%d exact; %d errors",
		pass, len(a.Cases), 100*worstP, 100*worstR, worst, a.WorkloadPods.Exact, a.WorkloadPods.Workloads, len(a.Errors))
}

func (x Extras) markdown(b *strings.Builder) {
	if len(x.Server) > 0 {
		b.WriteString("## Server-side metrics (Prometheus)\n\nPer window: SubjectAccessReviews per second, cache hit ratios, kubesentry's own API requests, memory and CPU per replica, snapshot age as scraped every 30s, Postgres and the oauth2-proxy sidecars.\n\n")
		for _, n := range sortedKeys(x.Server) {
			fmt.Fprintf(b, "### %s\n\n%s\n", n, ServerMarkdown(x.Server[n]))
		}
	}
	if x.Soak != nil {
		b.WriteString("## Soak\n\nSee soak.md.")
		if len(x.Soak.Flagged) == 0 {
			b.WriteString(" No unexpected upward trend.\n\n")
		} else {
			fmt.Fprintf(b, " Flagged: %s.\n\n", strings.Join(x.Soak.Flagged, "; "))
		}
	}
	if len(x.Chaos) > 0 {
		b.WriteString("## Chaos\n\n| Run | Scenario | Result | Seconds | Summary |\n|---|---|---|---:|---|\n")
		for _, n := range sortedKeys(x.Chaos) {
			for _, s := range x.Chaos[n].Scenarios {
				v := "pass"
				if !s.Pass {
					v = "FAIL: " + strings.Join(s.Problems, "; ")
				}
				fmt.Fprintf(b, "| %s | %s | %s | %.0f | %s |\n", n, s.Name, v, s.Seconds, strings.ReplaceAll(s.Summary, "|", "/"))
			}
		}
		b.WriteString("\n")
	}
	if len(x.Assocs) > 1 || len(x.Authzs) > 1 {
		b.WriteString("## Verification runs\n\n| Run | Started | Result |\n|---|---|---|\n")
		for _, n := range sortedKeys(x.Assocs) {
			a := x.Assocs[n]
			fmt.Fprintf(b, "| %s | %s | %s |\n", n, a.Started.Format("15:04"), AssocLine(a))
		}
		for _, n := range sortedKeys(x.Authzs) {
			a := x.Authzs[n]
			fmt.Fprintf(b, "| %s | %s | %d personas, %d leaks, %d problems |\n", n, a.Started.Format("15:04"), len(a.Personas), a.Leaks, a.Problems)
		}
		b.WriteString("\n")
	}
}
