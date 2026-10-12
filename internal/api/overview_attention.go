package api

// The Overview's "Needs attention" list: problems from every source, folded
// per workload (a crash-looping Deployment that also runs privileged and
// leaks memory is one line), ranked worst first.

import (
	"fmt"
	"math"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/model"
	"github.com/ByronGary/kubesentry/internal/snapshot"
)

// attentionLimit is how many items the Overview lists.
const attentionLimit = 10

// maxTitle bounds an item's title (detector details can quote long messages).
const maxTitle = 140

// Categories order items of one severity, as the Findings page orders its
// own: a node down first (it takes many pods with it), then workloads, memory
// leaks, security, certificates.
const (
	catNode = iota
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

// Hash routes of the pages that explain an item, with the query parameters
// those pages read (web/src/pages): Workloads namespace and q, Security
// check and q, Certificates q, Nodes node.
func workloadHref(ns, name string) string {
	return "#/workloads?" + url.Values{"namespace": {ns}, "q": {name}}.Encode()
}

func podHref(ns, pod string) string {
	return "#/pods/" + url.PathEscape(ns) + "/" + url.PathEscape(pod)
}

func securityHref(check, subject string) string {
	return "#/security?" + url.Values{"check": {check}, "q": {subject}}.Encode()
}

func certHref(ns, name string) string {
	return "#/certificates?" + url.Values{"q": {ns + "/" + name}}.Encode()
}

func nodeHref(name string) string {
	return "#/nodes?" + url.Values{"node": {name}}.Encode()
}

// buildAttention collects every item the view can raise and folds them into
// groups. Leak findings come later, per request (the scanner runs on its
// own schedule).
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

	issuers := map[string]bool{}
	for _, is := range v.Issuers {
		issuers[is.Kind+"/"+is.Namespace+"/"+is.Name] = true
	}
	for ns, cs := range v.Certs {
		for i := range cs {
			c := &cs[i]
			if c.Status != detectors.StatusCrit && c.Status != detectors.StatusWarn {
				continue
			}
			kind, order := "cert-not-ready", -1e9
			switch h := c.ExpiresInHours; {
			case issuerMissing(c, issuers):
				kind = "cert-issuer-missing"
			case h != nil && (*h <= 0 || c.Ready == "True"):
				kind, order = "cert-expiring", *h
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

// issuerMissing reports whether c names a cert-manager issuer that does not
// exist (its detail says so too). External issuer kinds are not judged.
func issuerMissing(c *detectors.CertSummary, issuers map[string]bool) bool {
	switch c.IssuerKind {
	case "Issuer":
		return !issuers["Issuer/"+c.Namespace+"/"+c.IssuerName]
	case "ClusterIssuer":
		return !issuers["ClusterIssuer//"+c.IssuerName]
	}
	return false
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
	type rn struct {
		r string
		n int
	}
	var stuck []rn
	for r, n := range w.Waiting {
		if n > 0 && workloadStuck[r] {
			stuck = append(stuck, rn{r, n})
		}
	}
	if len(stuck) == 0 {
		return w.Detail
	}
	sort.Slice(stuck, func(i, j int) bool {
		if stuck[i].n != stuck[j].n {
			return stuck[i].n > stuck[j].n
		}
		return stuck[i].r < stuck[j].r
	})
	parts := make([]string, len(stuck))
	for i, s := range stuck {
		parts[i] = fmt.Sprintf("%s ×%d", s.r, s.n)
	}
	return strings.Join(parts, ", ")
}

// workloadStuck are the waiting reasons that do not clear by themselves.
var workloadStuck = map[string]bool{
	"CrashLoopBackOff": true, "ImagePullBackOff": true, "ErrImagePull": true, "ErrImageNeverPull": true, "InvalidImageName": true,
	"CreateContainerConfigError": true, "CreateContainerError": true, "RunContainerError": true,
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
	it := attnItem{severity: detectors.StatusWarn, category: catLeak, kind: "leak", href: podHref(f.Namespace, f.Pod), order: math.MaxFloat64}
	rate := formatRate(f.SlopeBytesPerHour)
	if f.TimeToLimitHours != nil {
		h := *f.TimeToLimitHours
		it.order = h
		if h < critHours {
			it.severity = detectors.StatusCrit
		}
		it.title = fmt.Sprintf("Memory leak in %s: %s, reaches its limit in %s", f.Container, rate, approxHours(h))
	} else {
		it.title = fmt.Sprintf("Memory leak in %s: %s, no memory limit", f.Container, rate)
	}
	return it
}

func formatRate(b float64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GiB/h", b/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.0f MiB/h", b/(1<<20))
	}
	return fmt.Sprintf("%.0f KiB/h", b/(1<<10))
}

func approxHours(h float64) string {
	switch {
	case h < 1:
		return fmt.Sprintf("~%dm", max(1, int(h*60)))
	case h < 48:
		return fmt.Sprintf("~%dh", int(math.Round(h)))
	}
	return fmt.Sprintf("~%dd", int(math.Round(h/24)))
}

// mergeLeaks folds the leak findings into the selection's groups and
// returns the top attentionLimit, plus how many groups there are in all and
// the worst severity among them. groups is sorted and shared; leaks must be
// in the selection already.
func mergeLeaks(v *snapshot.View, idx *ovIndex, groups []*attnGroup, leaks []detectors.LeakFinding) (top []*attnGroup, total int, worst string) {
	total = len(groups)
	if len(groups) > 0 {
		worst = groups[0].worst().severity
	}
	if len(leaks) == 0 {
		return groups[:min(len(groups), attentionLimit)], total, worst
	}
	a := v.Assoc()
	critHours := v.Policy.Thresholds.LeakCritHours
	merged := map[groupKey]*attnGroup{}
	var order []groupKey
	for _, f := range leaks {
		k, name := groupKey{f.Namespace, "Pod", f.Pod}, f.Pod
		for _, p := range a.PodsIn(f.Namespace) {
			if p.Name == f.Pod {
				kind, root := a.RootOf(p)
				k, name = groupKey{f.Namespace, kind, root}, root
				break
			}
		}
		g := merged[k]
		if g == nil {
			g = &attnGroup{key: k, name: name}
			if old := idx.groups[k]; old != nil && !old.rbac {
				g.items = append(g.items, old.items...)
			} else {
				total++
			}
			merged[k] = g
			order = append(order, k)
		}
		it := leakItem(f, critHours)
		g.items = append(g.items, it)
		if severityRank(it.severity) < severityRank(worst) || worst == "" {
			worst = it.severity
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
