package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/ByronGary/kubesentry/internal/auth"
	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/snapshot"
)

// namespaceParam reads the optional ?namespace= filter. ok is false after it
// has answered 400 for an invalid name.
func namespaceParam(w http.ResponseWriter, r *http.Request) (ns string, ok bool) {
	ns = r.URL.Query().Get("namespace")
	if ns != "" && !validName(ns) {
		writeError(w, http.StatusBadRequest, "invalid namespace")
		return "", false
	}
	return ns, true
}

// statusRank orders statuses worst first, as the detectors do.
func statusRank(s string) int {
	switch s {
	case detectors.StatusCrit:
		return 0
	case detectors.StatusWarn:
		return 1
	case detectors.StatusUnknown:
		return 2
	}
	return 3
}

// workloadRows is every workload, most troubled first.
func workloadRows(v *snapshot.View) []keyed[detectors.WorkloadSummary] {
	return memoRows(v, "workloads", func() []keyed[detectors.WorkloadSummary] {
		var rows []keyed[detectors.WorkloadSummary]
		for ns, ws := range v.Workloads {
			for _, w := range ws {
				rows = append(rows, keyed[detectors.WorkloadSummary]{
					key: keyJoin(keyRank(statusRank(w.Status)), w.Namespace, w.Name, w.Kind), ns: ns, v: w,
				})
			}
		}
		return rows
	})
}

// workloads lists Deployments, StatefulSets, DaemonSets, Jobs and CronJobs in
// the caller's namespaces, most troubled first, a page at a time.
func (s *Server) workloads(w http.ResponseWriter, r *http.Request) {
	ns, ok := namespaceParam(w, r)
	if !ok {
		return
	}
	pg, ok := pageParams(w, r, "workloads")
	if !ok {
		return
	}
	v, ok := s.view(w, r)
	if !ok {
		return
	}
	items, last := pageRows(workloadRows(v), pg.after, pg.limit, inScope[detectors.WorkloadSummary](s.scope(r, auth.ViewNamespace), ns))
	writeJSON(w, http.StatusOK, workloadsResponse{Count: len(items), Items: items, Continue: encodeToken("workloads", last)})
}

// nodeScope is what the caller may see of nodes.
type nodeScope struct {
	nodes bool       // cluster-wide ViewNodes: full node details
	pods  auth.Scope // ViewNamespace: which pods are listed under nodes
}

func (s *Server) nodeScope(r *http.Request) nodeScope {
	return nodeScope{nodes: s.can(r, auth.ViewNodes), pods: s.scope(r, auth.ViewNamespace)}
}

// visibleNode returns n as the caller may see it, and false when they may
// not see it at all. Pods are limited to the caller's namespaces (and
// PodCount to the live ones among them). Without ViewNodes a node shows
// only when it runs one of the caller's pods, and then by name only, with
// status unknown. n is shared with the view and never modified.
func (ns nodeScope) visibleNode(n detectors.NodeSummary) (detectors.NodeSummary, bool) {
	if ns.pods.All && ns.nodes {
		return n, true
	}
	pods := make([]detectors.NodePod, 0, len(n.Pods))
	live := 0
	for _, p := range n.Pods {
		if ns.pods.Has(p.Namespace) {
			pods = append(pods, p)
			if p.Phase != "Succeeded" && p.Phase != "Failed" {
				live++
			}
		}
	}
	if !ns.nodes {
		if len(pods) == 0 {
			return detectors.NodeSummary{}, false
		}
		return detectors.NodeSummary{
			Name: n.Name, Status: detectors.StatusUnknown, Roles: []string{}, Pressure: []string{}, Taints: []string{},
			Pods: pods, PodCount: live,
		}, true
	}
	out := n
	out.Pods, out.PodCount = pods, live
	return out, true
}

// nodeOut is a node in a ?summary=true listing: the same, without its pods.
type nodeOut struct {
	detectors.NodeSummary
	Pods []detectors.NodePod `json:"pods,omitempty"`
}

// nodes lists cluster nodes with their requested resources and the caller's
// pods on them; ?summary=true leaves the pods out (podCount stays).
func (s *Server) nodes(w http.ResponseWriter, r *http.Request) {
	summary := r.URL.Query().Get("summary") == "true"
	v, ok := s.view(w, r)
	if !ok {
		return
	}
	sc := s.nodeScope(r)
	if summary {
		items := make([]nodeOut, 0, len(v.Nodes))
		for _, n := range v.Nodes {
			if n, ok := sc.visibleNode(n); ok {
				items = append(items, nodeOut{NodeSummary: n})
			}
		}
		writeJSON(w, http.StatusOK, nodesSummaryResponse{Count: len(items), Items: items})
		return
	}
	items := make([]detectors.NodeSummary, 0, len(v.Nodes))
	for _, n := range v.Nodes {
		if n, ok := sc.visibleNode(n); ok {
			items = append(items, n)
		}
	}
	writeJSON(w, http.StatusOK, nodesResponse{Count: len(items), Items: items})
}

// node returns one node with the caller's pods on it.
func (s *Server) node(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !validName(name) {
		writeError(w, http.StatusBadRequest, "invalid node name")
		return
	}
	v, ok := s.view(w, r)
	if !ok {
		return
	}
	byName := v.Memo("api/nodeIndex", func() any {
		m := make(map[string]int, len(v.Nodes))
		for i, n := range v.Nodes {
			m[n.Name] = i
		}
		return m
	}).(map[string]int)
	i, found := byName[name]
	if found {
		if n, ok := s.nodeScope(r).visibleNode(v.Nodes[i]); ok {
			writeJSON(w, http.StatusOK, n)
			return
		}
	}
	writeError(w, http.StatusNotFound, "node not found")
}

// claimRows is every claim, most troubled first.
func claimRows(v *snapshot.View) []keyed[detectors.ClaimSummary] {
	return memoRows(v, "claims", func() []keyed[detectors.ClaimSummary] {
		var rows []keyed[detectors.ClaimSummary]
		for ns, cs := range v.Claims {
			for _, c := range cs {
				rows = append(rows, keyed[detectors.ClaimSummary]{key: keyJoin(keyRank(statusRank(c.Status)), c.Namespace, c.Name), ns: ns, v: c})
			}
		}
		return rows
	})
}

// unusedRows is every unused claim, most expensive first.
func unusedRows(v *snapshot.View) []keyed[detectors.UnusedPVC] {
	return memoRows(v, "unused", func() []keyed[detectors.UnusedPVC] {
		var rows []keyed[detectors.UnusedPVC]
		for ns, us := range v.Unused {
			for _, u := range us {
				cents := int64(u.EstMonthlyCostUSD * 100)
				rows = append(rows, keyed[detectors.UnusedPVC]{key: keyJoin(keyDesc(cents), u.Namespace, u.Name), ns: ns, v: u})
			}
		}
		return rows
	})
}

// visibleUnused returns the unused claims in the caller's namespaces that are
// at least minAge old, most expensive first, and their summed cost.
func visibleUnused(v *snapshot.View, sc auth.Scope, minAge time.Duration) ([]detectors.UnusedPVC, float64) {
	min := minAge.Hours()
	items := []detectors.UnusedPVC{}
	total := 0.0
	for _, row := range unusedRows(v) {
		if sc.Has(row.ns) && row.v.AgeHours >= min {
			items = append(items, row.v)
			total += row.v.EstMonthlyCostUSD
		}
	}
	return items, total
}

// storage judges claims (paged), volumes and classes, and repeats the
// unused-claim list so the page needs one request. Volumes and classes are
// cluster-scoped: without ViewPVs or ViewStorageClass the caller sees only
// those their own claims use, by name, with status unknown.
func (s *Server) storage(w http.ResponseWriter, r *http.Request) {
	pg, ok := pageParams(w, r, "storage")
	if !ok {
		return
	}
	v, ok := s.view(w, r)
	if !ok {
		return
	}
	sc := s.scope(r, auth.ViewNamespace)
	resp := storageResponse{}
	var last string
	resp.Claims, last = pageRows(claimRows(v), pg.after, pg.limit, inScope[detectors.ClaimSummary](sc, ""))
	resp.Continue = encodeToken("storage", last)
	resp.Unused, resp.UnusedMonthlyCostUSD = visibleUnused(v, sc, s.PVCOptions.MinAge)
	resp.Volumes = s.visibleVolumes(r, v, sc)
	resp.Classes = s.visibleClasses(r, v, sc)
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) visibleVolumes(r *http.Request, v *snapshot.View, sc auth.Scope) []detectors.VolumeSummary {
	if s.can(r, auth.ViewPVs) {
		return v.Volumes
	}
	out := []detectors.VolumeSummary{}
	for _, pv := range v.Volumes {
		ns, _, ok := strings.Cut(pv.Claim, "/")
		if ok && sc.Has(ns) {
			out = append(out, detectors.VolumeSummary{Name: pv.Name, Claim: pv.Claim, StorageClass: pv.StorageClass, Status: detectors.StatusUnknown})
		}
	}
	return out
}

// visibleClasses returns the storage classes; unless the caller sees every
// namespace, the claim counts cover only their claims, and without
// ViewStorageClass only classes their claims use are listed, by name.
func (s *Server) visibleClasses(r *http.Request, v *snapshot.View, sc auth.Scope) []detectors.ClassSummary {
	full := s.can(r, auth.ViewStorageClass)
	if full && sc.All {
		return v.Classes
	}
	type use struct {
		claims int
		bytes  int64
	}
	uses := map[string]use{}
	for _, row := range claimRows(v) {
		if sc.Has(row.ns) {
			u := uses[row.v.StorageClass]
			u.claims++
			u.bytes += row.v.CapacityBytes
			uses[row.v.StorageClass] = u
		}
	}
	out := []detectors.ClassSummary{}
	for _, c := range v.Classes {
		u, used := uses[c.Name]
		switch {
		case full:
			c.Claims, c.CapacityBytes = u.claims, u.bytes
			out = append(out, c)
		case used:
			out = append(out, detectors.ClassSummary{Name: c.Name, Claims: u.claims, CapacityBytes: u.bytes})
		}
	}
	return out
}

// findingRows is every security finding in the detectors' order: most severe
// first, people's findings before plumbing.
func findingRows(v *snapshot.View) []keyed[detectors.SecurityFinding] {
	return memoRows(v, "findings", func() []keyed[detectors.SecurityFinding] {
		var rows []keyed[detectors.SecurityFinding]
		for ns, fs := range v.Findings {
			for _, f := range fs {
				system := "0"
				if f.System {
					system = "1"
				}
				rows = append(rows, keyed[detectors.SecurityFinding]{
					key: keyJoin(keyRank(severityRank(f.Severity)), system, f.Category, f.Subject, f.ID), ns: ns, v: f,
				})
			}
		}
		return rows
	})
}

func severityRank(s string) int {
	switch s {
	case "crit":
		return 0
	case "warn":
		return 1
	}
	return 2
}

// summaryFindings is how many findings ?view=summary returns.
const summaryFindings = 200

// securitySources names what each unreadable source means for the security
// checks; keys are as the informer cache and the list adapters record them.
var securitySources = map[string]string{
	snapshot.SourcePods: "pods", snapshot.SourceWorkloads: "workloads", "deployments": "workloads", "statefulsets": "workloads",
	"daemonsets": "workloads", "jobs": "workloads", "cronjobs": "workloads",
	snapshot.SourceNamespaces: "namespaces", snapshot.SourceRBAC: "roles and bindings", "roles": "roles and bindings",
	"rolebindings": "roles and bindings", "clusterroles": "roles and bindings", "clusterrolebindings": "roles and bindings",
	snapshot.SourceServices: "services", snapshot.SourceIngresses: "ingresses",
}

// security lists risks in the caller's namespaces: pod specs, namespaced
// RBAC, Pod Security labels and exposure, plus cluster-wide RBAC findings
// with ViewClusterRBAC. ?view=summary returns the counts and the most severe
// findings; otherwise findings are paged. A source that could not be read
// skips its checks and adds a warning instead of failing the page.
func (s *Server) security(w http.ResponseWriter, r *http.Request) {
	summary := r.URL.Query().Get("view") == "summary"
	pg, ok := pageParams(w, r, "security")
	if !ok {
		return
	}
	v, ok := s.view(w, r)
	if !ok {
		return
	}
	sc := s.scope(r, auth.ViewNamespace)
	clusterRBAC := s.can(r, auth.ViewClusterRBAC)
	visible := func(row *keyed[detectors.SecurityFinding]) bool {
		if row.ns == "" {
			return clusterRBAC
		}
		return sc.Has(row.ns)
	}

	rows := findingRows(v)
	resp := securityResponse{Counts: map[string]int{"crit": 0, "warn": 0, "info": 0}, Namespaces: []detectors.NamespacePosture{}}
	for i := range rows {
		if !rows[i].v.System && visible(&rows[i]) {
			resp.Counts[rows[i].v.Severity]++
		}
	}
	if summary {
		resp.Findings, _ = pageRows(rows, "", summaryFindings, func(row *keyed[detectors.SecurityFinding]) bool {
			return !row.v.System && visible(row)
		})
	} else {
		var last string
		resp.Findings, last = pageRows(rows, pg.after, pg.limit, visible)
		resp.Continue = encodeToken("security", last)
	}
	for _, p := range v.Posture {
		if sc.Has(p.Name) {
			resp.Namespaces = append(resp.Namespaces, p)
		}
	}
	seen := map[string]bool{}
	for _, src := range sortedKeys(v.Inv.Unavailable) {
		if what, ok := securitySources[strings.ToLower(src)]; ok && !seen[what] {
			seen[what] = true
			resp.Warnings = append(resp.Warnings, "Could not read "+what+"; those checks were skipped.")
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// certRows and requestRows flatten the view's per-namespace lists back into
// the detectors' order.
func certRows(v *snapshot.View) []keyed[detectors.CertSummary] {
	return memoRows(v, "certs", func() []keyed[detectors.CertSummary] {
		var rows []keyed[detectors.CertSummary]
		for ns, cs := range v.Certs {
			for _, c := range cs {
				rows = append(rows, keyed[detectors.CertSummary]{key: keyJoin(keyRank(statusRank(c.Status)), c.Namespace, c.Name), ns: ns, v: c})
			}
		}
		return rows
	})
}

func requestRows(v *snapshot.View) []keyed[detectors.RequestSummary] {
	return memoRows(v, "requests", func() []keyed[detectors.RequestSummary] {
		var rows []keyed[detectors.RequestSummary]
		for ns, rs := range v.Requests {
			for _, q := range rs {
				rows = append(rows, keyed[detectors.RequestSummary]{
					key: keyJoin(keyRank(statusRank(q.Status)), keyDesc(q.Created.UnixNano()), q.Namespace, q.Name), ns: ns, v: q,
				})
			}
		}
		return rows
	})
}

// certificates reports cert-manager Certificates, issuers and stuck requests
// in the caller's namespaces. ClusterIssuers need ViewClusterIssuer; without
// it the caller sees those their certificates use, by name, status unknown.
func (s *Server) certificates(w http.ResponseWriter, r *http.Request) {
	v, ok := s.view(w, r)
	if !ok {
		return
	}
	if _, failed := v.Inv.Unavailable[snapshot.SourceCertManager]; failed && !v.Inv.Certs.Installed {
		upstreamError(w, "cert-manager", errString(v.Inv.Unavailable[snapshot.SourceCertManager]))
		return
	}
	sc := s.scope(r, auth.ViewNamespace)
	clusterIssuers := s.can(r, auth.ViewClusterIssuer)
	resp := certificatesResponse{
		Installed: v.Inv.Certs.Installed, Certificates: []detectors.CertSummary{},
		Issuers: []detectors.IssuerSummary{}, Requests: []detectors.RequestSummary{},
	}
	uses := map[string]int{} // issuer kind/namespace/name → visible certificates
	for _, row := range certRows(v) {
		if sc.Has(row.ns) {
			resp.Certificates = append(resp.Certificates, row.v)
			ins := ""
			if row.v.IssuerKind == "Issuer" {
				ins = row.v.Namespace
			}
			uses[row.v.IssuerKind+"/"+ins+"/"+row.v.IssuerName]++
		}
	}
	for _, row := range requestRows(v) {
		if sc.Has(row.ns) {
			resp.Requests = append(resp.Requests, row.v)
		}
	}
	for _, is := range v.Issuers {
		n := uses[is.Kind+"/"+is.Namespace+"/"+is.Name]
		switch {
		case is.Namespace != "":
			if !sc.Has(is.Namespace) {
				continue
			}
		case !clusterIssuers:
			if n > 0 {
				resp.Issuers = append(resp.Issuers, detectors.IssuerSummary{Kind: is.Kind, Name: is.Name, Certificates: n, Status: detectors.StatusUnknown})
			}
			continue
		}
		if !sc.All {
			is.Certificates = n
		}
		resp.Issuers = append(resp.Issuers, is)
	}
	writeJSON(w, http.StatusOK, resp)
}

type errString string

func (e errString) Error() string { return string(e) }

// topology maps one namespace the caller may see. Without ?namespace= it
// picks their busiest non-system namespace. Without ViewNodes the nodes on
// the map show with status unknown.
func (s *Server) topology(w http.ResponseWriter, r *http.Request) {
	ns, ok := namespaceParam(w, r)
	if !ok {
		return
	}
	v, ok := s.view(w, r)
	if !ok {
		return
	}
	sc := s.scope(r, auth.ViewNamespace)
	namespaces := make([]string, 0, len(v.NamespacesWithPods))
	for _, n := range v.NamespacesWithPods {
		if sc.Has(n) {
			namespaces = append(namespaces, n)
		}
	}
	switch {
	case ns != "":
		found := false
		for _, n := range namespaces {
			found = found || n == ns
		}
		if !found {
			writeError(w, http.StatusNotFound, "no pods in namespace "+ns)
			return
		}
	case len(namespaces) > 0:
		ns = defaultNamespace(v, namespaces)
	}

	g := v.Topology(ns)
	if !s.can(r, auth.ViewNodes) {
		nodes := make([]detectors.GraphNode, len(g.Nodes))
		for i, n := range g.Nodes {
			if n.Kind == "Node" {
				n.Status, n.Detail = detectors.StatusUnknown, ""
			}
			nodes[i] = n
		}
		g = detectors.Graph{Nodes: nodes, Edges: g.Edges}
	}
	writeJSON(w, http.StatusOK, mapResponse{Namespace: ns, Namespaces: namespaces, Graph: g})
}

// defaultNamespace is the non-system namespace among candidates with the most
// live pods (ties go to the first by name), else the first candidate.
func defaultNamespace(v *snapshot.View, candidates []string) string {
	a := v.Assoc()
	best, bestN := "", -1
	for _, n := range candidates {
		if a.IsSystem(n) {
			continue
		}
		if live := v.LivePods[n]; live > bestN {
			best, bestN = n, live
		}
	}
	if best == "" {
		return candidates[0]
	}
	return best
}
