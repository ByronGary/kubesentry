package verify

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/ByronGary/kubesentry/test/stress/internal/ks"
	"github.com/ByronGary/kubesentry/test/stress/internal/out"
	"github.com/ByronGary/kubesentry/test/stress/internal/plan"
	"github.com/ByronGary/kubesentry/test/stress/internal/tricky"
	"github.com/ByronGary/kubesentry/test/stress/internal/truth"
	"k8s.io/client-go/kubernetes"
)

// AssocOptions control verify assoc.
type AssocOptions struct {
	Client  *ks.Client
	ID      ks.Identity
	OutDir  string
	MapNS   int // namespaces to map besides the stress-* ones; <0 maps all
	Timeout time.Duration
}

// CallTiming is one kubesentry request made by the verifier.
type CallTiming struct {
	Path    string  `json:"path"`
	Ms      float64 `json:"ms"`
	Bytes   int64   `json:"bytes"`
	Status  int     `json:"status"`
	Error   string  `json:"error,omitempty"`
	Started string  `json:"started"`
}

// CaseCheck is one expectation from expected.json, judged on truth and on kubesentry.
type CaseCheck struct {
	Case       string `json:"case"`
	Relation   string `json:"relation"`
	From       string `json:"from"`
	To         string `json:"to"`
	Want       string `json:"want"`
	Truth      string `json:"truth"`
	TruthOK    bool   `json:"truthOK"`
	Kubesentry string `json:"kubesentry"`
	OK         bool   `json:"ok"`
	Note       string `json:"note,omitempty"`
}

// AssocResult is assoc.json.
type AssocResult struct {
	Started       time.Time        `json:"started"`
	Seconds       float64          `json:"seconds"`
	TruthCounts   map[string]int   `json:"truthCounts"`
	MapNamespaces []string         `json:"mapNamespaces"`
	AllNamespaces int              `json:"allNamespaces"`
	Relations     []RelStats       `json:"relations"`
	WorkloadPods  CountStats       `json:"workloadPods"`
	Cases         []CaseCheck      `json:"cases"`
	Mismatches    []Group          `json:"mismatches"`
	Calls         []CallTiming     `json:"calls"`
	Errors        []string         `json:"errors,omitempty"`
	Summary       map[string]Score `json:"summary"`
}

// Score is precision and recall summed over sources for one relation.
type Score struct {
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	Truth     int     `json:"truth"`
	Observed  int     `json:"observed"`
}

// Assoc runs the association verifier.
func Assoc(ctx context.Context, cs kubernetes.Interface, o AssocOptions) (*AssocResult, error) {
	res := &AssocResult{Started: time.Now().UTC(), Summary: map[string]Score{}}
	start := time.Now()
	call := func(path string, v any) error {
		cctx, cancel := context.WithTimeout(ctx, o.Timeout)
		defer cancel()
		t := time.Now()
		r, err := o.Client.GetJSON(cctx, o.ID, path, v)
		ct := CallTiming{Path: path, Ms: out.Ms(time.Since(t)), Bytes: r.Bytes, Status: r.Status, Started: t.UTC().Format(time.RFC3339)}
		if err != nil {
			ct.Error = err.Error()
			res.Errors = append(res.Errors, err.Error())
		}
		res.Calls = append(res.Calls, ct)
		out.Logf("verify: GET %s -> %d, %d bytes, %s", path, r.Status, r.Bytes, time.Since(t).Round(time.Millisecond))
		return err
	}

	// Truth is taken before and after kubesentry is queried; only what both
	// snapshots agree on is required, and anything in either is accepted.
	if err := tricky.EnsureTerminating(ctx, cs); err != nil {
		out.Logf("verify: could not re-arm the terminating-endpoint case: %v", err)
	}
	out.Logf("verify: computing ground truth from the API server (before)")
	t0, err := truth.Compute(ctx, cs)
	if err != nil {
		return nil, err
	}
	obs := newObserved()
	var first ks.MapResponse
	if err := call("/api/v1/map", &first); err != nil {
		return nil, fmt.Errorf("map: %w", err)
	}
	res.AllNamespaces = len(first.Namespaces)
	scope := pickNamespaces(first.Namespaces, o.MapNS)
	res.MapNamespaces = scope
	for _, ns := range scope {
		var m ks.MapResponse
		if err := call("/api/v1/map?namespace="+url.QueryEscape(ns), &m); err != nil {
			continue
		}
		obs.AddMap(&m)
	}
	// List routes page (limit/continue) on the new build; the baseline
	// ignores the parameters and answers everything at once.
	paged := func(path string, run func() (int, time.Duration, int64, error)) {
		t := time.Now()
		pages, _, bytes, err := run()
		ct := CallTiming{Path: fmt.Sprintf("%s (%d pages)", path, pages), Ms: out.Ms(time.Since(t)), Bytes: bytes, Status: 200, Started: t.UTC().Format(time.RFC3339)}
		if err != nil {
			ct.Error, ct.Status = err.Error(), 0
			res.Errors = append(res.Errors, err.Error())
		}
		res.Calls = append(res.Calls, ct)
		out.Logf("verify: GET %s: %d pages, %d bytes, %s", path, pages, bytes, time.Since(t).Round(time.Millisecond))
	}
	paged("/api/v1/workloads", func() (int, time.Duration, int64, error) {
		cctx, cancel := context.WithTimeout(ctx, o.Timeout)
		defer cancel()
		return ks.GetAll(cctx, o.Client, o.ID, "/api/v1/workloads", 1000, func(w *ks.WorkloadsResponse) { obs.AddWorkloads(w) })
	})
	var nodes ks.NodesResponse
	if call("/api/v1/nodes", &nodes) == nil {
		obs.AddNodes(&nodes)
	}
	paged("/api/v1/security", func() (int, time.Duration, int64, error) {
		cctx, cancel := context.WithTimeout(ctx, o.Timeout)
		defer cancel()
		return ks.GetAll(cctx, o.Client, o.ID, "/api/v1/security", 1000, func(s *ks.SecurityResponse) { obs.AddSecurity(s) })
	})

	out.Logf("verify: computing ground truth from the API server (after)")
	t, err := truth.Compute(ctx, cs)
	if err != nil {
		return nil, err
	}
	res.TruthCounts = t.Counts
	res.TruthCounts["namespacesWithPods"] = len(t.Namespaces)

	generated := map[string]bool{}
	for i := 0; i < 2000; i++ {
		generated[plan.NamespaceName(i)] = true
	}
	for _, n := range plan.AddonNamespaces {
		generated[n] = true
	}
	inMap := map[string]bool{}
	for _, ns := range scope {
		inMap[ns] = true
	}
	mapScope := func(e string) bool { return inMap[EdgeNamespace(e)] }

	var mism []Mismatch
	score := func(rel, source string, scopeFn func(string) bool) {
		req, all := Stable(t0.Relations[rel], t.Relations[rel])
		s, missing, extra := Compare(rel, source, req, all, obs.Rel(source, rel), scopeFn)
		res.Relations = append(res.Relations, s)
		mism = append(mism, Categorize(t, generated, rel, source, missing, extra)...)
	}
	for _, rel := range []string{truth.PodOwner, truth.ServicePods, truth.PodNode, truth.PodPVC, truth.CronJobJob, truth.IngressService} {
		score(rel, "map", mapScope)
	}
	// The node view lists only pods that have a node.
	scheduled := func(e string) bool {
		_, to := Split(e)
		p := podOf(t, to)
		return p == nil || p.Node != ""
	}
	score(truth.PodOwner, "nodes", scheduled)
	score(truth.PodNode, "nodes", nil)
	score(truth.SecurityGroup, "security", nil)
	res.WorkloadPods = CompareCounts(t0.WorkloadPods, t.WorkloadPods, obs.WorkloadPods, nil)
	for _, w := range res.WorkloadPods.AllWrong {
		mism = append(mism, Mismatch{Case: caseOfWorkload(t, generated, w.Workload), Category: "workload-pods: count differs (" + kindOf(w.Workload) + ")", Source: "workloads",
			Detail: fmt.Sprintf("%s: %d live pods, reported %d", w.Workload, w.Truth, w.Observed)})
	}
	res.Mismatches = GroupMismatches(mism)
	for _, s := range res.Relations {
		res.Summary[s.Relation+"@"+s.Source] = Score{Precision: s.Precision, Recall: s.Recall, Truth: s.Truth, Observed: s.Observed}
	}
	res.Summary["workload-pods@workloads"] = Score{Precision: res.WorkloadPods.Accuracy, Recall: res.WorkloadPods.Accuracy, Truth: res.WorkloadPods.Workloads, Observed: res.WorkloadPods.Exact}
	res.Cases = checkCases(t, obs)
	res.Seconds = time.Since(start).Seconds()
	return res, nil
}

// pickNamespaces returns every stress-* namespace plus up to n others chosen
// deterministically (n < 0: all).
func pickNamespaces(all []string, n int) []string {
	var stress, other []string
	for _, ns := range all {
		if strings.HasPrefix(ns, "stress-") {
			stress = append(stress, ns)
		} else {
			other = append(other, ns)
		}
	}
	if n >= 0 && len(other) > n {
		r := rand.New(rand.NewPCG(7, 7))
		r.Shuffle(len(other), func(i, j int) { other[i], other[j] = other[j], other[i] })
		other = other[:n]
	}
	out := append(stress, other...)
	sort.Strings(out)
	return out
}

// checkCases judges every expectation of every tricky case.
func checkCases(t *truth.Truth, obs *Observed) []CaseCheck {
	var out []CaseCheck
	for _, c := range tricky.Cases {
		for _, e := range c.Expect {
			cc := CaseCheck{Case: c.ID, Relation: e.Relation, From: e.From, To: e.To, Note: e.Note}
			podsWith := func(prefix string) []*truth.Pod {
				var ps []*truth.Pod
				for _, p := range t.Pods {
					if p.Namespace == c.Namespace && prefix != "" && strings.HasPrefix(p.Name, prefix) {
						ps = append(ps, p)
					}
				}
				return ps
			}
			edgesFrom := func(rel map[string]bool, from string) int {
				n := 0
				for k := range rel {
					f, _ := Split(k)
					if Glob(from, f) {
						n++
					}
				}
				return n
			}
			edgesInto := func(rel map[string]bool, pods []*truth.Pod) int {
				ids := map[string]bool{}
				for _, p := range pods {
					ids[p.ID()] = true
				}
				n := 0
				for k := range rel {
					_, to := Split(k)
					if ids[to] {
						n++
					}
				}
				return n
			}
			edgesOut := func(rel map[string]bool, pods []*truth.Pod, to string) int {
				ids := map[string]bool{}
				for _, p := range pods {
					ids[p.ID()] = true
				}
				n := 0
				for k := range rel {
					f, tt := Split(k)
					if ids[f] && (to == "" || tt == to || strings.HasPrefix(tt, to)) {
						n++
					}
				}
				return n
			}
			switch e.Relation {
			case truth.PodOwner:
				if e.From == "" {
					ps := podsWith(e.To)
					cc.Want = "no owner"
					tv, ov := edgesInto(t.Relations[truth.PodOwner], ps), edgesInto(obs.Rel("map", truth.PodOwner), ps)
					cc.Truth, cc.TruthOK = fmt.Sprintf("%d pods, %d owner edges", len(ps), tv), tv == 0 && len(ps) == e.Count
					cc.Kubesentry, cc.OK = fmt.Sprintf("%d owner edges", ov), ov == 0
				} else {
					cc.Want = fmt.Sprintf("%d pods", e.Count)
					tv, ov := edgesFrom(t.Relations[truth.PodOwner], e.From), edgesFrom(obs.Rel("map", truth.PodOwner), e.From)
					cc.Truth, cc.TruthOK = fmt.Sprint(tv), tv == e.Count
					cc.Kubesentry, cc.OK = fmt.Sprint(ov), ov == e.Count
				}
			case truth.ServicePods:
				cc.Want = fmt.Sprintf("%d pods", e.Count)
				tv, ov := edgesFrom(t.Relations[truth.ServicePods], e.From), edgesFrom(obs.Rel("map", truth.ServicePods), e.From)
				want := e.Count
				if want < 0 { // whatever the EndpointSlice lists
					want = tv
					cc.Want = fmt.Sprintf("as the EndpointSlice: %d pods", tv)
				}
				cc.Truth, cc.TruthOK = fmt.Sprint(tv), tv == want
				cc.Kubesentry, cc.OK = fmt.Sprint(ov), ov == want
				if eps := t.Endpoints[e.From]; len(eps) > 0 {
					var ready, notReady, term int
					for _, ep := range eps {
						switch {
						case ep.Terminating:
							term++
						case ep.Ready:
							ready++
						default:
							notReady++
						}
					}
					cc.Truth += fmt.Sprintf(" (%d ready, %d not ready, %d terminating)", ready, notReady, term)
				}
			case "workload-pods":
				cc.Want = fmt.Sprintf("%d live pods", e.Count)
				tv := t.WorkloadPods[e.From]
				ov, ok := obs.WorkloadPods[e.From]
				cc.Truth, cc.TruthOK = fmt.Sprint(tv), tv == e.Count
				cc.Kubesentry, cc.OK = fmt.Sprint(ov), ok && ov == e.Count
				if !ok {
					cc.Kubesentry = "not listed"
				}
			case truth.PodNode:
				ps := podsWith(strings.TrimPrefix(e.From, "Pod/"+c.Namespace+"/"))
				tv, ov := edgesOut(t.Relations[truth.PodNode], ps, e.To), edgesOut(obs.Rel("map", truth.PodNode), ps, e.To)
				if e.To == "" {
					cc.Want = "no node"
					cc.Truth, cc.TruthOK = fmt.Sprintf("%d node edges", tv), tv == 0 && len(ps) > 0
					cc.Kubesentry, cc.OK = fmt.Sprintf("%d node edges", ov), ov == 0
				} else {
					cc.Want = "on " + e.To
					cc.Truth, cc.TruthOK = fmt.Sprint(tv), tv > 0
					cc.Kubesentry, cc.OK = fmt.Sprint(ov), ov > 0
				}
			case truth.PodPVC:
				ps := podsWith(strings.TrimPrefix(e.From, "Pod/"+c.Namespace+"/"))
				tv, ov := edgesOut(t.Relations[truth.PodPVC], ps, e.To), edgesOut(obs.Rel("map", truth.PodPVC), ps, e.To)
				cc.Want = "mounts " + e.To
				cc.Truth, cc.TruthOK = fmt.Sprint(tv), tv > 0
				cc.Kubesentry, cc.OK = fmt.Sprint(ov), ov > 0
			case truth.CronJobJob:
				tv, ov := edgesFrom(t.Relations[truth.CronJobJob], e.From), edgesFrom(obs.Rel("map", truth.CronJobJob), e.From)
				cc.Want = "at least 1 Job"
				cc.Truth, cc.TruthOK = fmt.Sprint(tv), tv > 0
				cc.Kubesentry, cc.OK = fmt.Sprint(ov), ov > 0
			case truth.IngressService:
				tv, ov := edgesFrom(t.Relations[truth.IngressService], e.From), edgesFrom(obs.Rel("map", truth.IngressService), e.From)
				if e.To == "" {
					cc.Want = "no backend edge"
					cc.Truth, cc.TruthOK = fmt.Sprint(tv), tv == 0
					cc.Kubesentry, cc.OK = fmt.Sprint(ov), ov == 0
				} else {
					cc.Want = "→ " + e.To
					cc.Truth, cc.TruthOK = fmt.Sprint(tv), t.Relations[truth.IngressService][truth.Key(e.From, e.To)]
					cc.Kubesentry, cc.OK = fmt.Sprint(ov), obs.Rel("map", truth.IngressService)[truth.Key(e.From, e.To)]
				}
			case "status":
				ps := podsWith(strings.TrimPrefix(e.From, "Pod/"+c.Namespace+"/"))
				cc.Want = e.To + " (not ok)"
				var tr, ks []string
				anyOK := false
				for _, p := range ps {
					tr = append(tr, p.Reason)
					st := obs.PodStatus[p.ID()]
					ks = append(ks, st)
					if st == "ok" || st == "" {
						anyOK = true
					}
				}
				cc.Truth = strings.Join(tr, ",")
				cc.TruthOK = len(ps) > 0 && strings.Contains(cc.Truth, e.To)
				cc.Kubesentry = strings.Join(ks, ",")
				cc.OK = len(ps) > 0 && !anyOK
			}
			out = append(out, cc)
		}
	}
	return out
}
