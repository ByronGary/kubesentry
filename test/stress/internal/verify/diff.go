// Package verify compares what kubesentry reports with ground truth computed
// from the API server, and checks connectivity.
package verify

import (
	"path"
	"sort"
	"strings"

	"github.com/ByronGary/kubesentry/test/stress/internal/ks"
	"github.com/ByronGary/kubesentry/test/stress/internal/truth"
)

// RelStats is precision and recall of one relation from one kubesentry source.
type RelStats struct {
	Relation  string   `json:"relation"`
	Source    string   `json:"source"` // map, nodes, workloads, security
	Truth     int      `json:"truth"`  // stable truth edges (in both snapshots)
	Volatile  int      `json:"volatile"`
	Observed  int      `json:"observed"`
	Matched   int      `json:"matched"`
	Precision float64  `json:"precision"`
	Recall    float64  `json:"recall"`
	Missing   []string `json:"missingSample,omitempty"` // in truth, not reported
	Extra     []string `json:"extraSample,omitempty"`   // reported, not in truth
}

const sampleCap = 15

// Compare scores observed edges against truth taken twice, before and after
// kubesentry was queried, so objects that churned in between (CronJob runs,
// restarts) neither count against nor for it. req holds the edges in both
// snapshots (recall is measured against them), all the edges in either
// (an observed edge in all is correct). Sets hold "from|to" keys; only edges
// for which inScope returns true count.
func Compare(rel, source string, req, all, o map[string]bool, inScope func(string) bool) (RelStats, []string, []string) {
	s := RelStats{Relation: rel, Source: source}
	var missing, extra []string
	for e := range all {
		if inScope != nil && !inScope(e) {
			continue
		}
		if !req[e] {
			s.Volatile++
			continue
		}
		s.Truth++
		if o[e] {
			s.Matched++
		} else {
			missing = append(missing, e)
		}
	}
	correct := 0
	for e := range o {
		if inScope != nil && !inScope(e) {
			continue
		}
		s.Observed++
		if all[e] {
			correct++
		} else {
			extra = append(extra, e)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	s.Precision, s.Recall = ratio(correct, s.Observed), ratio(s.Matched, s.Truth)
	s.Missing, s.Extra = capped(missing), capped(extra)
	return s, missing, extra
}

// Stable returns the intersection and union of two snapshots of a relation.
func Stable(a, b map[string]bool) (req, all map[string]bool) {
	req, all = map[string]bool{}, map[string]bool{}
	for k := range a {
		all[k] = true
		if b[k] {
			req[k] = true
		}
	}
	for k := range b {
		all[k] = true
	}
	return req, all
}

func ratio(a, b int) float64 {
	if b == 0 {
		return 1
	}
	return float64(a) / float64(b)
}

func capped(s []string) []string {
	if len(s) > sampleCap {
		return append([]string(nil), s[:sampleCap]...)
	}
	return s
}

// Split splits an edge key.
func Split(e string) (from, to string) {
	i := strings.IndexByte(e, '|')
	if i < 0 {
		return e, ""
	}
	return e[:i], e[i+1:]
}

// NamespaceOf returns the namespace of an ID "Kind/ns/name" ("" for Node/x).
func NamespaceOf(id string) string {
	parts := strings.SplitN(id, "/", 3)
	if len(parts) == 3 {
		return parts[1]
	}
	return ""
}

// EdgeNamespace is the namespace of either end of an edge.
func EdgeNamespace(e string) string {
	from, to := Split(e)
	if ns := NamespaceOf(from); ns != "" {
		return ns
	}
	return NamespaceOf(to)
}

// Observed is what kubesentry reported, as relations.
type Observed struct {
	Relations    map[string]map[string]bool // by source then relation: key "source/relation"
	WorkloadPods map[string]int
	PodStatus    map[string]string // pod ID → map status (ok, warn, crit, unknown)
}

func newObserved() *Observed {
	return &Observed{Relations: map[string]map[string]bool{}, WorkloadPods: map[string]int{}, PodStatus: map[string]string{}}
}

func (o *Observed) add(source, rel, from, to string) {
	k := source + "/" + rel
	if o.Relations[k] == nil {
		o.Relations[k] = map[string]bool{}
	}
	o.Relations[k][truth.Key(from, to)] = true
}

// Rel returns one relation from one source (never nil).
func (o *Observed) Rel(source, rel string) map[string]bool {
	if m := o.Relations[source+"/"+rel]; m != nil {
		return m
	}
	return map[string]bool{}
}

var notWorkload = map[string]bool{"Ingress": true, "Service": true, "Pod": true, "PVC": true, "Node": true}

func kindOf(id string) string {
	if i := strings.IndexByte(id, '/'); i > 0 {
		return id[:i]
	}
	return id
}

// AddMap folds one namespace's map graph into the observed relations.
// Workload→Pod edges are pod ownership (a ReplicaSet the map shows under a
// Deployment collapses to the Deployment); Service→Workload edges expand to
// the workload's pods on the same map.
func (o *Observed) AddMap(m *ks.MapResponse) {
	// A Controller node stands for an owner of another kind (a Rollout, a
	// custom resource); compare it under that kind.
	real := map[string]string{}
	for _, n := range m.Graph.Nodes {
		if n.Kind == "Controller" && n.OwnerKind != "" {
			real[n.ID] = n.OwnerKind + "/" + n.Namespace + "/" + n.Name
		}
	}
	if len(real) > 0 {
		edges := make([]ks.GraphEdge, len(m.Graph.Edges))
		for i, e := range m.Graph.Edges {
			if r, ok := real[e.From]; ok {
				e.From = r
			}
			if r, ok := real[e.To]; ok {
				e.To = r
			}
			edges[i] = e
		}
		m.Graph.Edges = edges
	}
	owner := map[string]string{} // ReplicaSet → Deployment
	for _, e := range m.Graph.Edges {
		if kindOf(e.From) == "Deployment" && kindOf(e.To) == "ReplicaSet" {
			owner[e.To] = e.From
		}
	}
	podsOf := map[string][]string{}
	for _, n := range m.Graph.Nodes {
		if n.Kind == "Pod" {
			o.PodStatus[n.ID] = n.Status
		}
	}
	for _, e := range m.Graph.Edges {
		fk, tk := kindOf(e.From), kindOf(e.To)
		switch {
		case tk == "Pod" && !notWorkload[fk]:
			from := e.From
			if d, ok := owner[from]; ok {
				from = d
			}
			o.add("map", truth.PodOwner, from, e.To)
			podsOf[e.From] = append(podsOf[e.From], e.To)
			if from != e.From {
				podsOf[from] = append(podsOf[from], e.To)
			}
		case fk == "Pod" && tk == "Node":
			o.add("map", truth.PodNode, e.From, e.To)
		case fk == "Pod" && tk == "PVC":
			o.add("map", truth.PodPVC, e.From, e.To)
		case fk == "CronJob" && tk == "Job":
			o.add("map", truth.CronJobJob, e.From, e.To)
		case fk == "Ingress" && tk == "Service":
			o.add("map", truth.IngressService, e.From, e.To)
		}
	}
	for _, e := range m.Graph.Edges {
		if kindOf(e.From) != "Service" {
			continue
		}
		if kindOf(e.To) == "Pod" {
			o.add("map", truth.ServicePods, e.From, e.To)
			continue
		}
		for _, p := range podsOf[e.To] {
			o.add("map", truth.ServicePods, e.From, p)
		}
	}
}

// AddNodes folds the node view: pod → node, and pod → workload.
func (o *Observed) AddNodes(n *ks.NodesResponse) {
	for _, node := range n.Items {
		for _, p := range node.Pods {
			pid := "Pod/" + p.Namespace + "/" + p.Name
			o.add("nodes", truth.PodNode, pid, "Node/"+node.Name)
			if p.Workload != "" {
				kind, name, _ := strings.Cut(p.Workload, "/")
				o.add("nodes", truth.PodOwner, kind+"/"+p.Namespace+"/"+name, pid)
			}
		}
	}
}

// AddWorkloads records pod counts per workload.
func (o *Observed) AddWorkloads(w *ks.WorkloadsResponse) {
	for _, it := range w.Items {
		o.WorkloadPods[it.Kind+"/"+it.Namespace+"/"+it.Name] = it.Pods
	}
}

// SecurityCheck is the pod check used to verify grouping: it fires for any
// container without allowPrivilegeEscalation=false, so its subjects are
// exactly the owners kubesentry groups pods under.
const SecurityCheck = "privilege-escalation"

// AddSecurity records the subjects of pod findings for SecurityCheck.
func (o *Observed) AddSecurity(s *ks.SecurityResponse) {
	for _, f := range s.Findings {
		if f.Category == "pod" && f.Check == SecurityCheck {
			o.add("security", truth.SecurityGroup, f.SubjectKind+"/"+f.Subject, "")
		}
	}
}

// CountStats scores per-workload pod counts.
type CountStats struct {
	Workloads int               `json:"workloads"`
	Exact     int               `json:"exact"`
	Accuracy  float64           `json:"accuracy"`
	TruthPods int               `json:"truthPods"`
	Observed  int               `json:"observedPods"`
	Missing   int               `json:"missingWorkloads"` // listed by truth, absent from kubesentry
	Volatile  int               `json:"volatile"`         // count changed between the truth snapshots
	ByKind    map[string][2]int `json:"byKind"`           // kind → [exact, total]
	Wrong     []CountMismatch   `json:"wrongSample,omitempty"`
	AllWrong  []CountMismatch   `json:"-"`
}

// CountMismatch is one workload whose pod count differs.
type CountMismatch struct {
	Workload string `json:"workload"`
	Truth    int    `json:"truth"`
	Observed int    `json:"observed"`
}

// listedKinds are the workload kinds kubesentry's Workloads page lists today;
// other owners (ReplicaSets, custom resources) are compared through pod-owner.
var listedKinds = map[string]bool{"Deployment": true, "StatefulSet": true, "DaemonSet": true, "Job": true, "CronJob": true}

// CompareCounts compares workload pod counts for the listed kinds. A
// workload whose count differs between the two truth snapshots (t0, t) is
// volatile and skipped.
func CompareCounts(t0, t map[string]int, o map[string]int, inScope func(string) bool) CountStats {
	s := CountStats{ByKind: map[string][2]int{}}
	keys := make([]string, 0, len(t))
	for k := range t {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		kind := kindOf(k)
		if !listedKinds[kind] || (inScope != nil && !inScope(k)) {
			continue
		}
		if before, ok := t0[k]; !ok || before != t[k] {
			s.Volatile++
			continue
		}
		s.Workloads++
		s.TruthPods += t[k]
		bk := s.ByKind[kind]
		bk[1]++
		got, ok := o[k]
		if !ok {
			s.Missing++
		}
		s.Observed += got
		if ok && got == t[k] {
			s.Exact++
			bk[0]++
		} else {
			s.AllWrong = append(s.AllWrong, CountMismatch{Workload: k, Truth: t[k], Observed: got})
		}
		s.ByKind[kind] = bk
	}
	s.Accuracy = ratio(s.Exact, s.Workloads)
	s.Wrong = s.AllWrong
	if len(s.Wrong) > sampleCap {
		s.Wrong = s.Wrong[:sampleCap]
	}
	return s
}

// Glob matches an ID against a pattern with * (path.Match semantics).
func Glob(pattern, id string) bool {
	if !strings.Contains(pattern, "*") {
		return pattern == id
	}
	ok, _ := path.Match(pattern, id)
	return ok
}
