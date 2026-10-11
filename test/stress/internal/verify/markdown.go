package verify

import (
	"fmt"
	"strings"
)

func pct(f float64) string { return fmt.Sprintf("%.1f%%", 100*f) }

func yes(b bool) string {
	if b {
		return "pass"
	}
	return "FAIL"
}

// Markdown renders assoc.md.
func (r *AssocResult) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Association verification\n\n")
	fmt.Fprintf(&b, "Run %s, %.0fs. Ground truth: %v.\n\n", r.Started.Format("2006-01-02 15:04:05Z"), r.Seconds, r.TruthCounts)
	fmt.Fprintf(&b, "Map checked for %d of %d namespaces with pods.\n\n", len(r.MapNamespaces), r.AllNamespaces)
	fmt.Fprintf(&b, "## Precision and recall\n\nTruth is taken before and after kubesentry is queried: edges in both are required, edges in only one (churn, e.g. CronJob runs) are volatile and accepted either way.\n\n| Relation | Source | Truth | Volatile | Reported | Matched | Precision | Recall |\n|---|---|---:|---:|---:|---:|---:|---:|\n")
	for _, s := range r.Relations {
		fmt.Fprintf(&b, "| %s | %s | %d | %d | %d | %d | %s | %s |\n", s.Relation, s.Source, s.Truth, s.Volatile, s.Observed, s.Matched, pct(s.Precision), pct(s.Recall))
	}
	w := r.WorkloadPods
	fmt.Fprintf(&b, "| workload pod counts | workloads | %d workloads | %d | %d listed | %d exact | %s | |\n\n", w.Workloads, w.Volatile, w.Workloads-w.Missing, w.Exact, pct(w.Accuracy))
	fmt.Fprintf(&b, "Workload pod counts by kind (exact/total):")
	for k, v := range w.ByKind {
		fmt.Fprintf(&b, " %s %d/%d;", k, v[0], v[1])
	}
	fmt.Fprintf(&b, " live pods truth %d, reported %d.\n\n", w.TruthPods, w.Observed)

	fmt.Fprintf(&b, "## Tricky cases\n\n| Case | Relation | From | Want | Truth | | kubesentry | |\n|---|---|---|---|---|---|---|---|\n")
	for _, c := range r.Cases {
		fmt.Fprintf(&b, "| %s | %s | %s %s | %s | %s | %s | %s | %s |\n", c.Case, c.Relation, c.From, c.To, c.Want, c.Truth, yes(c.TruthOK), c.Kubesentry, yes(c.OK))
	}
	fmt.Fprintf(&b, "\nTruth columns check that the cluster really has the intended shape; kubesentry columns are the verdict.\n\n")

	fmt.Fprintf(&b, "## Mismatches by case and category\n\n| Case | Category | Count | Sources | Example |\n|---|---|---:|---|---|\n")
	for _, g := range r.Mismatches {
		ex := ""
		if len(g.Samples) > 0 {
			ex = strings.ReplaceAll(g.Samples[0], "|", " → ")
		}
		fmt.Fprintf(&b, "| %s | %s | %d | %s | %s |\n", g.Case, g.Category, g.Count, strings.Join(g.Sources, ","), ex)
	}
	if len(r.Errors) > 0 {
		fmt.Fprintf(&b, "\n## Errors\n\n")
		for _, e := range r.Errors {
			fmt.Fprintf(&b, "- %s\n", e)
		}
	}
	fmt.Fprintf(&b, "\n## kubesentry calls made by the verifier\n\n| Path | ms | bytes | status |\n|---|---:|---:|---:|\n")
	for _, c := range r.Calls {
		fmt.Fprintf(&b, "| %s | %.0f | %d | %d |\n", c.Path, c.Ms, c.Bytes, c.Status)
	}
	return b.String()
}
