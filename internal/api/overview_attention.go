package api

// The Overview's "Needs attention" list: problems from every source, folded
// per workload (a crash-looping Deployment that also runs privileged and
// leaks memory is one line), ranked worst first.

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/model"
	"github.com/ByronGary/kubesentry/internal/snapshot"
	"github.com/ByronGary/kubesentry/internal/uilink"
)

// attentionLimit is how many items the Overview lists.
const attentionLimit = 10

// maxTitle bounds an item's title (detector details can quote long messages).
const maxTitle = 140

// Categories order items of one severity, as the Findings page orders its
// own, after open incidents (which tie a workload's problems together and
// link to all of them): a node down first (it takes many pods with it), then
// workloads, memory leaks, security, certificates.
const (
	catIncident = iota
	catNode
	catWorkload
	catLeak
	catSecurity
	catCert
)

// attentionItem mirrors web/src/types.ts AttentionItem.
type attentionItem struct {
	Severity  string     `json:"severity"` // crit or warn
	Kind      string     `json:"kind"`
	Namespace string     `json:"namespace,omitempty"`
	Name      string     `json:"name"`
	Title     string     `json:"title"`
	Owner     string     `json:"owner,omitempty"`
	Since     *time.Time `json:"since,omitempty"`
	Href      string     `json:"href"`
}

// attnItem is one problem with one object.
type attnItem struct {
	severity string
	category int
	order    float64 // lower first within a category
	kind     string
	title    string
	href     string
	since    time.Time
}

// groupKey names what items fold under: a workload (its root, as the
// security checks group pods), a certificate, an RBAC subject, a node.
type groupKey struct{ ns, kind, name string }

// attnGroup is one line of the list: every item about one object, worst
// first. Groups are built once per view and shared; never modify one.
type attnGroup struct {
	key   groupKey
	name  string
	rbac  bool // a namespaced RBAC finding: needs ViewRBAC in its namespace
	items []attnItem
}

func (g *attnGroup) worst() *attnItem { return &g.items[0] }

// itemLess orders items worst first: severity, category, order, kind.
func itemLess(a, b *attnItem) bool {
	switch {
	case severityRank(a.severity) != severityRank(b.severity):
		return severityRank(a.severity) < severityRank(b.severity)
	case a.category != b.category:
		return a.category < b.category
	case a.order != b.order:
		return a.order < b.order
	}
	return a.kind < b.kind
}

// groupLess ranks groups by their worst item, then by name.
func groupLess(a, b *attnGroup) bool {
	wa, wb := a.worst(), b.worst()
	if itemLess(wa, wb) {
		return true
	}
	if itemLess(wb, wa) {
		return false
	}
	switch {
	case a.key.ns != b.key.ns:
		return a.key.ns < b.key.ns
	case a.key.name != b.key.name:
		return a.key.name < b.key.name
	}
	return a.key.kind < b.key.kind
}

func sortGroups(gs []*attnGroup) {
	sort.Slice(gs, func(i, j int) bool { return groupLess(gs[i], gs[j]) })
}

func sortItems(items []attnItem) {
	sort.SliceStable(items, func(i, j int) bool { return itemLess(&items[i], &items[j]) })
}

// out renders a group as an item of the response.
func (g *attnGroup) out(owner string) attentionItem {
	w := g.worst()
	title := w.title
	if n := len(g.items) - 1; n > 0 {
		title += fmt.Sprintf(" (+%d more)", n)
	}
	it := attentionItem{Severity: w.severity, Kind: w.kind, Namespace: g.key.ns, Name: g.name, Title: title, Owner: owner, Href: w.href}
	since := w.since
	if since.IsZero() {
		for _, x := range g.items[1:] {
			if !x.since.IsZero() && (since.IsZero() || x.since.Before(since)) {
				since = x.since
			}
		}
	}
	if !since.IsZero() {
		it.Since = &since
	}
	return it
}

// clip shortens s to maxTitle bytes on a rune boundary.
func clip(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= maxTitle {
		return s
	}
	cut := maxTitle - len("…")
	for cut > 0 && !utf8RuneStart(s[cut]) {
		cut--
	}
	return strings.TrimSpace(s[:cut]) + "…"
}

func utf8RuneStart(b byte) bool { return b&0xC0 != 0x80 }

// The pages that explain an item (their hash routes are shared with the
// alerts' kubesentry_url).
var (
	workloadHref = uilink.Workload
	podHref      = uilink.Pod
	securityHref = uilink.Security
	certHref     = uilink.Certificate
	nodeHref     = uilink.Node
)

// buildAttention collects every item the view can raise and folds them into
// groups. Leak findings and open incidents come later, per request (the
// scanner and the incidents engine run on their own schedules).
func buildAttention(v *snapshot.View, idx *ovIndex) {
	a := v.Assoc()
	groups := map[groupKey]*attnGroup{}
	add := func(k groupKey, name string, rbac bool, it attnItem) {
		g := groups[k]
		if g == nil {
			g = &attnGroup{key: k, name: name, rbac: rbac}
			groups[k] = g
		}
		it.title = clip(it.title)
		g.items = append(g.items, it)
	}

	workloads := make(map[groupKey]*model.Workload, len(v.Inv.Workloads))
	for i := range v.Inv.Workloads {
		w := &v.Inv.Workloads[i]
		workloads[groupKey{w.Namespace, w.Kind, w.Name}] = w
	}
	for ns, ws := range v.Workloads {
		for i := range ws {
			w := &ws[i]
			if w.Status != detectors.StatusCrit && w.Status != detectors.StatusWarn {
				continue
			}
			root := groupKey{ns, w.Kind, w.Name}
			if w.Kind == "Job" {
				if cj, _, ok := a.JobParent(ns, w.Name); ok {
					root = groupKey{ns, "CronJob", cj.Name}
				}
			}
			affected := w.NotReady
			for _, n := range w.Waiting {
				affected += n
			}
			add(root, root.name, false, attnItem{
				severity: w.Status, category: catWorkload, order: -float64(affected),
				kind: workloadKind(w), title: workloadTitle(w), href: workloadHref(ns, root.name),
				since: workloadSince(a, w, workloads[groupKey{ns, w.Kind, w.Name}]),
			})
		}
	}

	for ns, fs := range v.Findings {
		for i := range fs {
			f := &fs[i]
			if f.System || f.Severity != detectors.StatusCrit {
				continue
			}
			name := f.Subject
			if ns != "" {
				name = strings.TrimPrefix(f.Subject, ns+"/")
			}
			add(groupKey{ns, f.SubjectKind, name}, name, ns != "" && f.Category == "rbac", attnItem{
				severity: f.Severity, category: catSecurity, kind: f.Check, title: f.Title,
				href: securityHref(f.Check, f.Subject),
			})
		}
	}

	issuers := detectors.IssuerSet(v.Issuers)
	for ns, cs := range v.Certs {
		for i := range cs {
			c := &cs[i]
			kind := detectors.CertProblem(c, issuers)
			if kind == "" {
				continue
			}
			order := -1e9
			if kind == detectors.CertProblemExpiring {
				order = *c.ExpiresInHours
			}
			add(groupKey{ns, "Certificate", c.Name}, c.Name, false, attnItem{
				severity: c.Status, category: catCert, order: order, kind: kind, title: c.Detail, href: certHref(ns, c.Name),
			})
		}
	}

	nodes := make(map[string]*model.Node, len(v.Inv.Nodes))
	for i := range v.Inv.Nodes {
		nodes[v.Inv.Nodes[i].Name] = &v.Inv.Nodes[i]
	}
	for i := range v.Nodes {
		n := &v.Nodes[i]
		if n.Ready {
			continue
		}
		var since time.Time
		if mn := nodes[n.Name]; mn != nil {
			for _, c := range mn.Conditions {
				if c.Type == "Ready" {
					since = c.LastTransition
				}
			}
		}
		order := 0.0
		if !since.IsZero() {
			order = float64(since.Unix())
		}
		add(groupKey{"", "Node", n.Name}, n.Name, false, attnItem{
			severity: detectors.StatusCrit, category: catNode, order: order, kind: "node-not-ready", title: n.Detail,
			href: nodeHref(n.Name), since: since,
		})
	}

	idx.groups = groups
	for k, g := range groups {
		sortItems(g.items)
		switch {
		case k.kind == "Node" && k.ns == "":
			idx.nodeGroups = append(idx.nodeGroups, g)
		case k.ns == "":
			idx.cluster = append(idx.cluster, g)
		default:
			n := idx.namespace(k.ns)
			if g.rbac {
				n.rbacGroups = append(n.rbacGroups, g)
			} else {
				n.groups = append(n.groups, g)
			}
		}
	}
}

// workloadKind names the check behind an unhealthy workload, from its
// worst waiting reason, else from what its status says.
func workloadKind(w *detectors.WorkloadSummary) string {
	switch {
	case w.Waiting["CrashLoopBackOff"] > 0:
		return "crashloop"
	case w.Waiting["ImagePullBackOff"]+w.Waiting["ErrImagePull"]+w.Waiting["ErrImageNeverPull"]+w.Waiting["InvalidImageName"] > 0:
		return "image-pull"
	case w.Waiting["CreateContainerConfigError"]+w.Waiting["CreateContainerError"]+w.Waiting["RunContainerError"] > 0:
		return "config-error"
	case w.Kind == "Job" && w.Status == detectors.StatusCrit:
		return "job-failed"
	case w.Kind == "CronJob":
		return "cronjob"
	case strings.HasPrefix(w.Detail, "Rollout stuck"):
		return "rollout-stuck"
	case w.OOMKilled:
		return "oom-killed"
	case strings.HasPrefix(w.Detail, "Rollout"):
		return "rollout"
	}
	return "not-ready"
}

// workloadTitle is "CrashLoopBackOff ×3" for pods stuck waiting (most pods
// first, as the Workloads page lists them), else the workload's detail.
func workloadTitle(w *detectors.WorkloadSummary) string {
	stuck := map[string]int{}
	for r, n := range w.Waiting {
		if detectors.IsStuckReason(r) {
			stuck[r] = n
		}
	}
	if t := detectors.ReasonCounts(stuck); t != "" {
		return t
	}
	return w.Detail
}

// workloadSince is when the trouble started, if known: the earliest
// readiness flip of its live pods that are not ready, else the transition
// of the condition that says it failed or stalled.
func workloadSince(a *detectors.Assoc, w *detectors.WorkloadSummary, mw *model.Workload) time.Time {
	var since time.Time
	for _, p := range a.PodsOf(detectors.Ref{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name}) {
		if p.Phase == "Succeeded" || p.Phase == "Failed" || !p.DeletedAt.IsZero() || p.Ready || p.ReadyChanged.IsZero() {
			continue
		}
		if since.IsZero() || p.ReadyChanged.Before(since) {
			since = p.ReadyChanged
		}
	}
	if !since.IsZero() || mw == nil {
		return since
	}
	for _, c := range mw.Conditions {
		bad := (c.Type == "Failed" && c.Status == "True") || (c.Type == "Progressing" && c.Status == "False") || (c.Type == "Available" && c.Status == "False")
		if bad && !c.LastTransition.IsZero() && (since.IsZero() || c.LastTransition.Before(since)) {
			since = c.LastTransition
		}
	}
	return since
}

// leakItem turns a leak scanner finding into an item: crit when the
// container reaches its limit sooner than LeakCritHours.
func leakItem(f detectors.LeakFinding, critHours float64) attnItem {
	it := attnItem{severity: detectors.StatusWarn, category: catLeak, kind: "leak", href: podHref(f.Namespace, f.Pod), order: math.MaxFloat64,
		title: detectors.LeakTitle(f)}
	if f.TimeToLimitHours != nil {
		h := *f.TimeToLimitHours
		it.order = h
		if h < critHours {
			it.severity = detectors.StatusCrit
		}
	}
	return it
}

// leakExtras turns the leak findings into items of their workloads' groups.
func leakExtras(v *snapshot.View, leaks []detectors.LeakFinding) []attnExtra {
	a := v.Assoc()
	critHours := v.Policy.Thresholds.LeakCritHours
	out := make([]attnExtra, 0, len(leaks))
	for _, f := range leaks {
		k, name := groupKey{f.Namespace, "Pod", f.Pod}, f.Pod
		if p, ok := a.PodNamed(f.Namespace, f.Pod); ok {
			kind, root := a.RootOf(p)
			k, name = groupKey{f.Namespace, kind, root}, root
		}
		out = append(out, attnExtra{key: k, name: name, item: leakItem(f, critHours)})
	}
	return out
}

// mergeExtras folds per-request items (leak findings, open incidents) into
// the selection's groups and returns the top attentionLimit, plus how many
// groups there are in all and the worst severity among them. groups is
// sorted and shared; the extras must be in the selection already.
func mergeExtras(idx *ovIndex, groups []*attnGroup, extras []attnExtra) (top []*attnGroup, total int, worst string) {
	total = len(groups)
	if len(groups) > 0 {
		worst = groups[0].worst().severity
	}
	if len(extras) == 0 {
		return groups[:min(len(groups), attentionLimit)], total, worst
	}
	merged := map[groupKey]*attnGroup{}
	var order []groupKey
	for _, x := range extras {
		g := merged[x.key]
		if g == nil {
			g = &attnGroup{key: x.key, name: x.name}
			if old := idx.groups[x.key]; old != nil && !old.rbac && inGroups(groups, old) {
				g.items = append(g.items, old.items...)
			} else {
				total++
			}
			merged[x.key] = g
			order = append(order, x.key)
		}
		g.items = append(g.items, x.item)
		if worst == "" || severityRank(x.item.severity) < severityRank(worst) {
			worst = x.item.severity
		}
	}
	top = make([]*attnGroup, 0, attentionLimit+len(merged))
	for _, g := range groups {
		if merged[g.key] != nil {
			continue
		}
		top = append(top, g)
		if len(top) == attentionLimit {
			break
		}
	}
	for _, k := range order {
		g := merged[k]
		sortItems(g.items)
		top = append(top, g)
	}
	sortGroups(top)
	return top[:min(len(top), attentionLimit)], total, worst
}

// inGroups reports whether g is one of the selection's groups. Groups are
// shared per view, so this compares pointers.
func inGroups(groups []*attnGroup, g *attnGroup) bool {
	for _, x := range groups {
		if x == g {
			return true
		}
	}
	return false
}
