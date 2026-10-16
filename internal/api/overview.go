package api

// GET /api/v1/overview: the landing dashboard in one request. Everything is
// derived from the snapshot view, filtered by the caller's scope first and
// then by the ?namespace= and ?owner= filters, like every other route. The
// view-derived part is computed once per view for each (scope, filter) and
// shared (View.Memo); what changes with time (age, health, leak findings,
// sensitive activity, history) is added per request, and the response cache
// keeps whole answers for overviewCacheWindow.

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/ByronGary/kubesentry/internal/auth"
	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/snapshot"
)

// overviewCacheWindow is how long a cached overview is served: its age,
// health and activity are no older than this.
const overviewCacheWindow = 10 * time.Second

// overviewCaps is every capability the overview depends on: the response
// cache keys on all of them (cachedRoutes), the view memo on the first four.
var overviewCaps = []auth.Capability{auth.ViewNamespace, auth.ViewNodes, auth.ViewRBAC, auth.ViewClusterRBAC,
	auth.ViewAudit, auth.ViewClusterAudit, auth.ViewAgents}

// Response shapes. Mirrored in web/src/types.ts (OverviewResponse).
type overviewResponse struct {
	Version      uint64            `json:"version"`
	BuiltAt      time.Time         `json:"builtAt"`
	AgeSeconds   float64           `json:"ageSeconds"`
	Scope        overviewScope     `json:"scope"`
	Health       overviewHealth    `json:"health"`
	Nodes        *overviewNodes    `json:"nodes"`
	Pods         overviewPods      `json:"pods"`
	Workloads    overviewWorkloads `json:"workloads"`
	Certificates *overviewCerts    `json:"certificates"`
	Security     overviewSecurity  `json:"security"`
	Attention    []attentionItem   `json:"attention"`
	Activity     *overviewActivity `json:"activity"`
	Waste        overviewWaste     `json:"waste"`
	Owners       []string          `json:"owners"`
	// Namespaces the caller can see before the filter, sorted, for the picker.
	Namespaces []string         `json:"namespaces"`
	Badges     map[string]badge `json:"badges"`
	History    overviewHistory  `json:"history"`
	// Alerts is left out when alerting is off.
	Alerts *overviewAlerts `json:"alerts,omitempty"`
	// Incidents is left out when incidents are off.
	Incidents *overviewIncidents `json:"incidents,omitempty"`
}

type overviewScope struct {
	Namespace  string `json:"namespace,omitempty"`
	Owner      string `json:"owner,omitempty"`
	Namespaces int    `json:"namespaces"`
}

type overviewHealth struct {
	Prometheus           string          `json:"prometheus"` // ok, unavailable or none
	AuditStore           string          `json:"auditStore"` // ok, degraded or none
	CloudWatchLagSeconds *float64        `json:"cloudwatchLagSeconds,omitempty"`
	Agents               *overviewAgents `json:"agents,omitempty"`
}

type overviewAgents struct {
	Reporting int `json:"reporting"`
	Stale     int `json:"stale"`
}

type overviewNodes struct {
	Total    int            `json:"total"`
	Ready    int            `json:"ready"`
	NotReady int            `json:"notReady"`
	Cordoned int            `json:"cordoned"`
	Pools    []overviewPool `json:"pools"`
	Zones    []overviewZone `json:"zones"`
}

type overviewPool struct {
	Name            string   `json:"name"`
	Kind            string   `json:"kind"` // nodegroup, karpenter, fargate or other
	Nodes           int      `json:"nodes"`
	CPURequestedPct *float64 `json:"cpuRequestedPct,omitempty"`
	MemRequestedPct *float64 `json:"memRequestedPct,omitempty"`
}

type overviewZone struct {
	Name  string `json:"name"`
	Nodes int    `json:"nodes"`
}

type overviewPods struct {
	Total    int            `json:"total"`
	Running  int            `json:"running"`
	Pending  int            `json:"pending"`
	Failing  int            `json:"failing"`
	ByReason map[string]int `json:"byReason"` // failing and pending pods by reason
}

type overviewWorkloads struct {
	Total     int `json:"total"`
	Unhealthy int `json:"unhealthy"`
}

type overviewCerts struct {
	Total         int `json:"total"`
	ExpiringSoon  int `json:"expiringSoon"`
	NotReady      int `json:"notReady"`
	IssuerMissing int `json:"issuerMissing"`
}

type overviewSecurity struct {
	Crit        int  `json:"crit"`
	Warn        int  `json:"warn"`
	NewSince24h *int `json:"newSince24h,omitempty"`
}

type overviewWaste struct {
	UnusedPVCs  int     `json:"unusedPVCs"`
	MonthlyUSD  float64 `json:"monthlyUSD"`
	UsageBilled int     `json:"usageBilled"`
}

type badge struct {
	Count    int    `json:"count"`
	Severity string `json:"severity"` // crit or warn
}

type overviewHistory struct {
	StepSeconds int                `json:"stepSeconds"`
	Start       time.Time          `json:"start"`
	Series      map[string][]int64 `json:"series"`
}

// maxPools bounds the pools listed (Karpenter can make many).
const maxPools = 50

// ovIndex is what the Overview reads from one view, per namespace, built
// once per view and shared by every caller.
type ovIndex struct {
	ns         map[string]*ovNS
	owner      map[string]string // namespace → owner annotation
	byOwner    map[string][]string
	production map[string]bool // namespaces carrying the production label
	names      []string        // namespaces in the view, sorted (as /info counts them)
	nameSet    map[string]bool
	groups     map[groupKey]*attnGroup
	cluster    []*attnGroup // crit cluster-scoped findings (ViewClusterRBAC)
	nodeGroups []*attnGroup // nodes not ready (ViewNodes)
}

// ovNS is one namespace's share of the tiles.
type ovNS struct {
	pods, running, pending, failing int
	byReason                        map[string]int
	workloads, workloadsCrit        int
	certs, certsNotReady            int
	certsIssuerMissing              int
	certsBad, certsCrit             int // status warn or crit, and crit
	oom                             int // OOM kills within OOMRecent
	unused                          []detectors.UnusedPVC
	groups, rbacGroups              []*attnGroup
}

func (x *ovIndex) namespace(ns string) *ovNS {
	n := x.ns[ns]
	if n == nil {
		n = &ovNS{byReason: map[string]int{}}
		x.ns[ns] = n
	}
	return n
}

// overviewIndex returns the view's index, built on first use.
func overviewIndex(v *snapshot.View) *ovIndex {
	return v.Memo("api/overview/index", func() any { return buildOverviewIndex(v) }).(*ovIndex)
}

func buildOverviewIndex(v *snapshot.View) *ovIndex {
	idx := &ovIndex{ns: map[string]*ovNS{}, owner: map[string]string{}, byOwner: map[string][]string{}, production: map[string]bool{}}
	p := v.Policy
	for _, n := range v.Inv.Namespaces {
		if o := p.OwnerOf(n); o != "" {
			idx.owner[n.Name] = o
			idx.byOwner[o] = append(idx.byOwner[o], n.Name)
		}
		if p.IsProduction(n) {
			idx.production[n.Name] = true
		}
	}
	// The namespaces listed, and those holding objects (all there is when
	// namespaces cannot be read).
	idx.nameSet = map[string]bool{}
	for _, n := range v.Inv.Namespaces {
		idx.nameSet[n.Name] = true
	}
	for _, n := range v.Assoc().Namespaces() {
		idx.nameSet[n] = true
	}
	delete(idx.nameSet, "")
	for n := range idx.nameSet {
		idx.names = append(idx.names, n)
	}
	sort.Strings(idx.names)
	th := p.Thresholds
	for i := range v.Inv.Pods {
		pod := &v.Inv.Pods[i]
		n := idx.namespace(pod.Namespace)
		n.pods++
		switch st, reason := detectors.PodState(pod, th, v.Built); st {
		case detectors.PodFailing:
			n.failing++
			n.byReason[reason]++
		case detectors.PodPending:
			n.pending++
			n.byReason[reason]++
		case detectors.PodRunning:
			n.running++
		}
	}
	for ns, ws := range v.Workloads {
		n := idx.namespace(ns)
		n.workloads += len(ws)
		for i := range ws {
			if ws[i].Status == detectors.StatusCrit {
				n.workloadsCrit++
			}
		}
	}
	issuers := detectors.IssuerSet(v.Issuers)
	for ns, cs := range v.Certs {
		n := idx.namespace(ns)
		for i := range cs {
			c := &cs[i]
			n.certs++
			if c.Ready != "True" {
				n.certsNotReady++
			}
			if detectors.IssuerMissing(c, issuers) {
				n.certsIssuerMissing++
			}
			switch c.Status {
			case detectors.StatusCrit:
				n.certsBad++
				n.certsCrit++
			case detectors.StatusWarn:
				n.certsBad++
			}
		}
	}
	for ns, us := range v.Unused {
		idx.namespace(ns).unused = us
	}
	recent := v.Built.Add(-th.OOMRecent)
	for _, e := range oomEvents(v) {
		if !e.LastOOMAt.Before(recent) {
			idx.namespace(e.Namespace).oom++
		}
	}
	buildAttention(v, idx)
	return idx
}

// ovSel is what one caller asked for and may see.
type ovSel struct {
	ns, owner   string
	filtered    bool            // ?namespace= or ?owner= given
	set         map[string]bool // the namespaces they select, when filtered
	sc          auth.Scope      // ViewNamespace
	rbac        auth.Scope      // ViewRBAC
	nodes       bool            // ViewNodes
	clusterRBAC bool            // ViewClusterRBAC
}

// has reports whether namespace ns is in the selection.
func (o *ovSel) has(ns string) bool {
	if o.filtered {
		return o.set[ns]
	}
	return ns != "" && o.sc.Has(ns)
}

// all reports whether the selection is every namespace.
func (o *ovSel) all() bool { return !o.filtered && o.sc.All }

// each calls f for every selected namespace the index holds.
func (o *ovSel) each(idx *ovIndex, f func(ns string, n *ovNS)) {
	switch {
	case o.filtered:
		for ns := range o.set {
			if n := idx.ns[ns]; n != nil {
				f(ns, n)
			}
		}
	case o.sc.All:
		for ns, n := range idx.ns {
			f(ns, n)
		}
	default:
		for ns, held := range o.sc.Namespaces {
			if n := idx.ns[ns]; held && n != nil {
				f(ns, n)
			}
		}
	}
}

// visible is every namespace of the view the caller may see, before any
// filter, sorted. With every namespace it is the index's own slice: do not
// modify it.
func (o *ovSel) visible(idx *ovIndex) []string {
	if o.sc.All {
		return idx.names
	}
	out := []string{}
	for ns, held := range o.sc.Namespaces {
		if held && idx.nameSet[ns] {
			out = append(out, ns)
		}
	}
	sort.Strings(out)
	return out
}

// keep reports whether the caller sees the counters under k, with the gates
// of /security: a namespace's RBAC findings need ViewRBAC there, the
// cluster-scoped ones ViewClusterRBAC (and no filter, which narrows to
// namespaces).
func (o *ovSel) keep(k snapshot.CountKey) bool {
	if k.Namespace == "" {
		return !o.filtered && o.clusterRBAC
	}
	return o.has(k.Namespace) && (!k.RBAC || o.rbac.Has(k.Namespace))
}

// keepAll reports whether the caller sees every counter.
func (o *ovSel) keepAll() bool { return o.all() && o.clusterRBAC && o.rbac.All }

// selection resolves the caller's scope and filters.
func (s *Server) overviewSelection(r *http.Request, idx *ovIndex, ns, owner string) *ovSel {
	sel := &ovSel{
		ns: ns, owner: owner, filtered: ns != "" || owner != "",
		sc: s.scope(r, auth.ViewNamespace), rbac: s.scope(r, auth.ViewRBAC),
		nodes: s.can(r, auth.ViewNodes), clusterRBAC: s.can(r, auth.ViewClusterRBAC),
	}
	if !sel.filtered {
		return sel
	}
	var candidates []string
	switch {
	case owner != "":
		for _, n := range idx.byOwner[owner] {
			if ns == "" || n == ns {
				candidates = append(candidates, n)
			}
		}
	default:
		candidates = []string{ns}
	}
	sel.set = map[string]bool{}
	for _, n := range candidates {
		if sel.sc.Has(n) && idx.nameSet[n] {
			sel.set[n] = true
		}
	}
	return sel
}

// ovBase is the view-derived part of one overview, shared by every caller
// with the same scope and filter. Never modify one.
type ovBase struct {
	namespaces   int
	nodes        *overviewNodes
	pods         overviewPods
	workloads    overviewWorkloads
	certificates *overviewCerts
	security     overviewSecurity
	groups       []*attnGroup // sorted worst first
	waste        overviewWaste
	owners       []string
	visible      []string         // the caller's namespaces before the filter
	badges       map[string]badge // without findings and memory, which leaks change
	oom          int
}

// ovMemo holds the bases of one view by scope and filter.
type ovMemo struct {
	mu sync.Mutex
	m  map[string]*ovMemoEntry
}

type ovMemoEntry struct {
	once sync.Once
	base *ovBase
}

// maxOverviewMemo bounds the bases kept per view; past it they are
// computed per request.
const maxOverviewMemo = 1024

func (m *ovMemo) get(key string, build func() *ovBase) *ovBase {
	m.mu.Lock()
	e := m.m[key]
	if e == nil {
		if len(m.m) >= maxOverviewMemo {
			m.mu.Unlock()
			return build()
		}
		e = &ovMemoEntry{}
		m.m[key] = e
	}
	m.mu.Unlock()
	e.once.Do(func() { e.base = build() })
	return e.base
}

// overviewBase returns the base for sel, from the view's memo when the
// caller's scope could be keyed (an authorization lookup that failed is
// never memoised: it shows less than the caller may see).
func (s *Server) overviewBase(r *http.Request, v *snapshot.View, idx *ovIndex, sel *ovSel) *ovBase {
	build := func() *ovBase { return s.buildOverviewBase(v, idx, sel) }
	sk, err := ScopeKey(r.Context(), s.Authorizer, overviewCaps[:4]...)
	if err != nil || authzFailed(r.Context()) {
		return build()
	}
	key := sk + "\x00" + filterKey(sel) + "\x00" + s.PVCOptions.MinAge.String()
	memo := v.Memo("api/overview", func() any { return &ovMemo{m: map[string]*ovMemoEntry{}} }).(*ovMemo)
	return memo.get(key, build)
}

// filterKey names the namespaces a filter selects (not the filter as
// written), so filters that select the same namespaces, or nothing, share
// one base, and request input cannot grow the memo past the namespaces.
func filterKey(sel *ovSel) string {
	if !sel.filtered {
		return "*"
	}
	names := make([]string, 0, len(sel.set))
	for ns := range sel.set {
		names = append(names, ns)
	}
	sort.Strings(names)
	h := sha256.Sum256([]byte(strings.Join(names, "\x00")))
	return hex.EncodeToString(h[:16])
}

func (s *Server) buildOverviewBase(v *snapshot.View, idx *ovIndex, sel *ovSel) *ovBase {
	b := &ovBase{pods: overviewPods{ByReason: map[string]int{}}, owners: []string{}, badges: map[string]badge{}, visible: sel.visible(idx)}
	b.namespaces = len(b.visible)
	if sel.filtered {
		b.namespaces = len(sel.set)
	}

	var sum snapshot.Counts
	all := sel.keepAll()
	for k, c := range v.Counts() {
		if all || sel.keep(k) {
			for i, n := range c {
				sum[i] += n
			}
		}
	}

	minAge := s.PVCOptions.MinAge.Hours()
	var workloadsCrit, certsBad, certsCrit int
	certs := overviewCerts{ExpiringSoon: int(sum[snapshot.CertsExpiringSoon])}
	var gs []*attnGroup
	sel.each(idx, func(ns string, n *ovNS) {
		b.pods.Total += n.pods
		b.pods.Running += n.running
		b.pods.Pending += n.pending
		b.pods.Failing += n.failing
		for r, c := range n.byReason {
			b.pods.ByReason[r] += c
		}
		b.workloads.Total += n.workloads
		workloadsCrit += n.workloadsCrit
		certs.Total += n.certs
		certs.NotReady += n.certsNotReady
		certs.IssuerMissing += n.certsIssuerMissing
		certsBad += n.certsBad
		certsCrit += n.certsCrit
		b.oom += n.oom
		for _, u := range n.unused {
			if u.AgeHours < minAge {
				continue
			}
			b.waste.UnusedPVCs++
			if u.CostKnown {
				b.waste.MonthlyUSD += u.EstMonthlyCostUSD
			}
			if u.PriceSource == detectors.PriceUsageBilled {
				b.waste.UsageBilled++
			}
		}
		gs = append(gs, n.groups...)
		if sel.rbac.Has(ns) {
			gs = append(gs, n.rbacGroups...)
		}
	})
	b.waste.MonthlyUSD = math.Round(b.waste.MonthlyUSD*100) / 100
	b.workloads.Unhealthy = int(sum[snapshot.UnhealthyWorkloads])
	if v.Inv.Certs.Installed {
		b.certificates = &certs
	}
	b.security = overviewSecurity{Crit: int(sum[snapshot.SecurityCrit]), Warn: int(sum[snapshot.SecurityWarn])}

	if !sel.filtered && sel.clusterRBAC {
		gs = append(gs, idx.cluster...)
	}
	if sel.nodes {
		for _, g := range idx.nodeGroups {
			if !sel.filtered || runsSelectedPods(v, g.key.name, sel) {
				gs = append(gs, g)
			}
		}
		b.nodes = overviewNodesOf(v, sel)
	}
	sortGroups(gs)
	b.groups = gs

	seen := map[string]bool{}
	for ns, o := range idx.owner {
		if !seen[o] && (sel.sc.All || sel.sc.Namespaces[ns]) {
			seen[o] = true
			b.owners = append(b.owners, o)
		}
	}
	sort.Strings(b.owners)

	if n := b.workloads.Unhealthy; n > 0 {
		b.badges["workloads"] = badge{Count: n, Severity: worse(workloadsCrit > 0)}
	}
	switch {
	case b.pods.Failing > 0:
		b.badges["pods"] = badge{Count: b.pods.Failing, Severity: detectors.StatusCrit}
	case b.pods.Pending > 0:
		b.badges["pods"] = badge{Count: b.pods.Pending, Severity: detectors.StatusWarn}
	}
	if n := b.security.Crit + b.security.Warn; n > 0 {
		b.badges["security"] = badge{Count: n, Severity: worse(b.security.Crit > 0)}
	}
	if certsBad > 0 && b.certificates != nil {
		b.badges["certificates"] = badge{Count: certsBad, Severity: worse(certsCrit > 0)}
	}
	return b
}

func worse(crit bool) string {
	if crit {
		return detectors.StatusCrit
	}
	return detectors.StatusWarn
}

// runsSelectedPods reports whether a node runs a live pod of the selection.
func runsSelectedPods(v *snapshot.View, node string, sel *ovSel) bool {
	for _, p := range v.Assoc().PodsOnNode(node) {
		if p.Phase != "Succeeded" && p.Phase != "Failed" && sel.has(p.Namespace) {
			return true
		}
	}
	return false
}

// overviewNodesOf sums the nodes by pool and zone. Requested CPU and memory
// cover the selected namespaces' pods unless the selection is every
// namespace (the /nodes rule); Fargate is not metered.
func overviewNodesOf(v *snapshot.View, sel *ovSel) *overviewNodes {
	type agg struct {
		pool                               overviewPool
		cpuReq, cpuAlloc, memReq, memAlloc int64
	}
	out := &overviewNodes{Pools: []overviewPool{}, Zones: []overviewZone{}}
	pools := map[[2]string]*agg{}
	zones := map[string]int{}
	var uses nodeUses
	if !sel.all() {
		uses = nodeUsesOf(v)
	}
	for i := range v.Nodes {
		n := &v.Nodes[i]
		out.Total++
		if n.Ready {
			out.Ready++
		} else {
			out.NotReady++
		}
		if n.Unschedulable {
			out.Cordoned++
		}
		if z := n.Placement.Zone; z != "" {
			zones[z]++
		}
		kind := n.Placement.PoolKind
		if kind == "" {
			kind = "other"
		}
		name := n.Placement.Pool
		if name == "" {
			name = kind
		}
		a := pools[[2]string{kind, name}]
		if a == nil {
			a = &agg{pool: overviewPool{Name: name, Kind: kind}}
			pools[[2]string{kind, name}] = a
		}
		a.pool.Nodes++
		cpu, mem := n.CPURequestedMilli, n.MemoryRequestedBytes
		if uses != nil {
			cpu, mem = 0, 0
			for ns, u := range uses[n.Name] {
				if sel.has(ns) {
					cpu += u.cpuMilli
					mem += u.memBytes
				}
			}
		}
		a.cpuReq += cpu
		a.memReq += mem
		a.cpuAlloc += n.CPUAllocatableMilli
		a.memAlloc += n.MemoryAllocatableBytes
	}
	for _, a := range pools {
		if a.pool.Kind != detectors.PoolFargate {
			a.pool.CPURequestedPct = pct(a.cpuReq, a.cpuAlloc)
			a.pool.MemRequestedPct = pct(a.memReq, a.memAlloc)
		}
		out.Pools = append(out.Pools, a.pool)
	}
	sort.Slice(out.Pools, func(i, j int) bool {
		a, b := out.Pools[i], out.Pools[j]
		switch {
		case a.Nodes != b.Nodes:
			return a.Nodes > b.Nodes
		case a.Kind != b.Kind:
			return a.Kind < b.Kind
		}
		return a.Name < b.Name
	})
	if len(out.Pools) > maxPools {
		out.Pools = out.Pools[:maxPools]
	}
	for z, n := range zones {
		out.Zones = append(out.Zones, overviewZone{Name: z, Nodes: n})
	}
	sort.Slice(out.Zones, func(i, j int) bool { return out.Zones[i].Name < out.Zones[j].Name })
	return out
}

// pct is part of whole in percent, to one decimal; nil without a whole.
func pct(part, whole int64) *float64 {
	if whole <= 0 {
		return nil
	}
	p := math.Round(1000*float64(part)/float64(whole)) / 10
	return &p
}

// ownerParam reads ?owner=: printable, at most 253 bytes. ok is false after
// it has answered 400.
func ownerParam(w http.ResponseWriter, r *http.Request) (string, bool) {
	o := strings.TrimSpace(r.URL.Query().Get("owner"))
	valid := len(o) <= 253 && strings.IndexFunc(o, func(c rune) bool { return !unicode.IsPrint(c) }) < 0
	if !valid {
		writeError(w, http.StatusBadRequest, "invalid owner")
		return "", false
	}
	return o, true
}

// overview answers GET /api/v1/overview?namespace=&owner=.
func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	ns, ok := namespaceParam(w, r)
	if !ok {
		return
	}
	owner, ok := ownerParam(w, r)
	if !ok {
		return
	}
	v, ok := s.view(w, r)
	if !ok {
		return
	}
	idx := overviewIndex(v)
	sel := s.overviewSelection(r, idx, ns, owner)
	base := s.overviewBase(r, v, idx, sel)
	now := s.now()

	resp := overviewResponse{
		Version: v.Version, BuiltAt: v.Built, AgeSeconds: math.Max(0, math.Round(now.Sub(v.Built).Seconds()*10)/10),
		Scope:  overviewScope{Namespace: ns, Owner: owner, Namespaces: base.namespaces},
		Health: s.overviewHealth(r),
		Nodes:  base.nodes, Pods: base.pods, Workloads: base.workloads, Certificates: base.certificates,
		Security: base.security, Waste: base.waste, Owners: base.owners, Namespaces: base.visible,
		Badges: make(map[string]badge, len(base.badges)+2),
	}
	for k, b := range base.badges {
		resp.Badges[k] = b
	}

	leaks := s.selectedLeaks(sel)
	incExtras, incCounts := s.selectedIncidents(v, sel)
	top, total, worst := mergeExtras(idx, base.groups, append(leakExtras(v, leaks), incExtras...))
	resp.Attention = make([]attentionItem, len(top))
	for i, g := range top {
		resp.Attention[i] = g.out(idx.owner[g.key.ns])
	}
	if total > 0 {
		resp.Badges["findings"] = badge{Count: total, Severity: worst}
	}
	critLeak := false
	for _, f := range leaks {
		critLeak = critLeak || (f.TimeToLimitHours != nil && *f.TimeToLimitHours < v.Policy.Thresholds.LeakCritHours)
	}
	if n := len(leaks) + base.oom; n > 0 {
		resp.Badges["memory"] = badge{Count: n, Severity: worse(critLeak || base.oom > 0)}
	}

	var failed bool
	resp.Activity, failed = s.overviewActivity(r, idx, sel, now)
	if failed {
		// Not the caller's real activity: never keep it for others.
		w.Header().Set("Cache-Control", "no-store")
	}
	resp.History, resp.Security.NewSince24h = s.overviewHistory(now, sel, base.security)
	resp.Alerts = s.overviewAlerts(sel)
	if resp.Incidents = incCounts; incCounts != nil {
		if n := incCounts.Open.Critical + incCounts.Open.Warning; n > 0 {
			resp.Badges["incidents"] = badge{Count: n, Severity: worse(incCounts.Open.Critical > 0)}
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// selectedLeaks is the background leak scan's findings in the selection.
func (s *Server) selectedLeaks(sel *ovSel) []detectors.LeakFinding {
	lr, ok := s.metrics().(leakReporter)
	if !ok {
		return nil
	}
	rep, _, ok := lr.LeakReport()
	if !ok || rep.GeneratedAt.IsZero() {
		return nil
	}
	var out []detectors.LeakFinding
	for _, f := range rep.Findings {
		if sel.has(f.Namespace) {
			out = append(out, f)
		}
	}
	return out
}

// overviewHistory sums the history the caller may see, and how many more
// critical and warning findings there are than a day ago, when the history
// reaches back that far.
func (s *Server) overviewHistory(now time.Time, sel *ovSel, sec overviewSecurity) (overviewHistory, *int) {
	step := snapshot.DefaultHistoryStep
	if s.History != nil {
		step = s.History.Step()
	}
	out := overviewHistory{StepSeconds: int(step / time.Second), Start: now.Truncate(step).UTC(), Series: map[string][]int64{}}
	if s.History == nil {
		return out, nil
	}
	keep := sel.keep
	if sel.keepAll() {
		keep = nil
	}
	w := s.History.Window(now, keep)
	if w.Start.IsZero() {
		return out, nil
	}
	out.Start = w.Start
	for i, name := range snapshot.SeriesNames {
		out.Series[name] = w.Series[i]
	}
	if !w.Full {
		return out, nil
	}
	then := w.Series[snapshot.SecurityCrit][0] + w.Series[snapshot.SecurityWarn][0]
	n := max(0, sec.Crit+sec.Warn-int(then))
	return out, &n
}
