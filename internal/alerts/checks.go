package alerts

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/model"
	"github.com/ByronGary/kubesentry/internal/snapshot"
	"github.com/ByronGary/kubesentry/internal/uilink"
)

// Candidate is one problem a check sees in the current view, before the
// evaluator gives it an owner, labels and a lifecycle.
type Candidate struct {
	Check       string
	Kind        string // the object's kind: Deployment, Certificate, ClusterRoleBinding, ...
	Namespace   string
	Name        string
	Severity    string
	Title       string // the summary annotation
	Description string
	// Node is set when every pod involved runs on one node, so the
	// monitoring profile's node-down inhibition can mute the alert.
	Node  string
	Link  string            // the UI hash route that explains it
	Extra map[string]string // further annotations (pods, reasons, predicted_oom, ...)
	// Quiet: report it only in a standing digest, never on its own (a
	// certificate far from expiry).
	Quiet bool
}

// Key is the candidate's dedupe key.
func (c *Candidate) Key() string { return Key(c.Check, c.Kind, c.Namespace, c.Name) }

// checkInfo is what the evaluator needs to know about a check.
type checkInfo struct {
	alert string
	// object: the alert names its object in an "object" label (Kind/name);
	// otherwise in a "workload" label.
	object bool
	// changeBased checks fire on what appeared since the last evaluation
	// (diffed against a stored baseline), not on what stands.
	changeBased bool
	// pending is how long a candidate must be seen before it fires (as
	// Prometheus's for:), so a problem that clears by itself stays quiet.
	pending time.Duration
	// gate decides who may see its findings besides the namespace (Gate);
	// "" is GateOf's default.
	gate Gate
}

// Pending durations.
const (
	certNotReadyPending = 10 * time.Minute // issuance takes a moment
	workloadPending     = 5 * time.Minute  // a crash or pull failure during a rollout may clear
)

var checkInfos = map[string]checkInfo{
	CheckCertExpiring:        {alert: AlertCertificateExpiring, object: true},
	CheckCertNotReady:        {alert: AlertCertificateNotReady, object: true, pending: certNotReadyPending},
	CheckMemoryLeak:          {alert: AlertMemoryLeak},
	CheckWorkloadUnhealthy:   {alert: AlertWorkloadUnhealthy, pending: workloadPending},
	CheckPodEvicted:          {alert: AlertPodEvicted},
	CheckPodStuckTerminating: {alert: AlertPodStuckTerminating},
	CheckClusterAdmin:        {alert: AlertRBACDrift, object: true, changeBased: true, gate: GateRBAC},
	CheckAnonymousBinding:    {alert: AlertRBACDrift, object: true, changeBased: true, gate: GateRBAC},
	CheckWildcardRBAC:        {alert: AlertRBACDrift, object: true, changeBased: true, gate: GateRBAC},
	CheckAWSAuthMasters:      {alert: AlertRBACDrift, object: true, changeBased: true, gate: GateRBAC},
}

// Checks lists every check, sorted.
func Checks() []string {
	out := make([]string, 0, len(checkInfos))
	for c := range checkInfos {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// Input is what one evaluation judges.
type Input struct {
	View *snapshot.View
	// Leaks is the background leak scan, nil when there is none (no
	// Prometheus, or no scan finished yet): the memory-leak check is then
	// skipped and its findings stay as they are.
	Leaks *detectors.LeakReport
	Now   time.Time
}

// Found is what the checks see in one view.
type Found struct {
	Candidates []Candidate
	// Skipped are the checks whose data could not be read: their findings
	// are kept as they are (neither refreshed nor resolved), and a
	// change-based check's baseline is left alone.
	Skipped map[string]bool
}

// Run runs every check over in. leakCritHours is the time to the memory
// limit below which a leak is critical (0: the view's policy).
func Run(in Input, leakCritHours float64) Found {
	f := Found{Skipped: map[string]bool{}}
	v := in.View
	if leakCritHours <= 0 {
		leakCritHours = v.Policy.Thresholds.LeakCritHours
	}
	certChecks(v, in.Now, &f)
	podChecks(v, in.Now, &f)
	leakCheck(v, in.Leaks, leakCritHours, &f)
	rbacChecks(v, &f)
	sort.Slice(f.Candidates, func(i, j int) bool { return f.Candidates[i].Key() < f.Candidates[j].Key() })
	return f
}

// unavailable reports whether any of the sources could not be read for the
// view (keys as internal/kube records them, case and API group ignored).
func unavailable(v *snapshot.View, sources ...string) bool {
	for k := range v.Inv.Unavailable {
		k = strings.ToLower(k)
		for _, s := range sources {
			if k == s || strings.HasPrefix(k, s+".") {
				return true
			}
		}
	}
	return false
}

// ---- certificates ----

func certChecks(v *snapshot.View, now time.Time, f *Found) {
	if unavailable(v, "certificates", "issuers", "clusterissuers") {
		f.Skipped[CheckCertExpiring], f.Skipped[CheckCertNotReady] = true, true
		return
	}
	th := v.Policy.Thresholds
	issuers := detectors.IssuerSet(v.Issuers)
	for _, cs := range v.Certs {
		for i := range cs {
			c := &cs[i]
			problem := detectors.CertProblem(c, issuers)
			if problem == "" {
				continue
			}
			sev := SeverityWarning
			if c.Status == detectors.StatusCrit {
				sev = SeverityCritical
			}
			issuer := c.IssuerKind + "/" + c.IssuerName
			obj := c.Namespace + "/" + c.Name
			cand := Candidate{
				Kind: "Certificate", Namespace: c.Namespace, Name: c.Name, Severity: sev,
				Link:  uilink.Certificate(c.Namespace, c.Name),
				Extra: map[string]string{"issuer": issuer},
			}
			if c.NotAfter != nil {
				cand.Extra["expires_at"] = c.NotAfter.UTC().Format(time.RFC3339)
			}
			names := ""
			if len(c.DNSNames) > 0 {
				names = " for " + strings.Join(firstN(c.DNSNames, 3), ", ")
				if len(c.DNSNames) > 3 {
					names += fmt.Sprintf(" and %d more", len(c.DNSNames)-3)
				}
			}
			switch problem {
			case detectors.CertProblemExpiring:
				if renewsInTime(c, now, th) {
					continue // cert-manager renews it before it matters
				}
				cand.Check = CheckCertExpiring
				cand.Title = "Certificate " + obj + ": " + c.Detail
				cand.Description = fmt.Sprintf("Certificate %s%s (issuer %s, secret %s): %s cert-manager has not renewed it on schedule; check the issuer and the latest CertificateRequest.",
					obj, names, issuer, c.SecretName, c.Detail)
			default:
				cand.Check = CheckCertNotReady
				reason := "not-ready"
				if problem == detectors.CertProblemIssuerMissing {
					reason = "issuer-missing"
				}
				cand.Extra["reason"] = reason
				cand.Title = "Certificate " + obj + " is not ready: " + c.Detail
				cand.Description = fmt.Sprintf("Certificate %s%s (issuer %s, secret %s) is not ready: %s", obj, names, issuer, c.SecretName, c.Detail)
			}
			f.Candidates = append(f.Candidates, cand)
		}
	}
}

// renewsInTime reports whether cert-manager is due to renew c before it
// expires and has not missed that time by more than CertRenewalGrace: a
// short-lived certificate that renews on schedule is always close to
// expiry, and alerting on it would be constant noise (the monitoring
// profile's CertManagerCertificateExpiring follows the same rule).
func renewsInTime(c *detectors.CertSummary, now time.Time, th detectors.Thresholds) bool {
	if c.Ready != "True" || c.RenewalTime == nil || c.NotAfter == nil || !now.Before(*c.NotAfter) {
		return false
	}
	return c.RenewalTime.Before(*c.NotAfter) && now.Before(c.RenewalTime.Add(th.CertRenewalGrace))
}

func firstN(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ---- pods: unhealthy workloads, evictions, stuck terminations ----

// podGroup is the pods of one workload (its root, as the security checks
// and the Overview group them: a Job under its CronJob) that share a
// problem.
type podGroup struct {
	ns, kind, name string
	pods           int
	reasons        map[string]int
	nodes          map[string]bool
	worst          *model.Pod // the pod whose message the description quotes
	at             time.Time  // newest eviction, oldest deletion
}

func (g *podGroup) add(p *model.Pod, reason string) {
	g.pods++
	if g.reasons == nil {
		g.reasons, g.nodes = map[string]int{}, map[string]bool{}
	}
	if reason != "" {
		g.reasons[reason]++
	}
	if p.NodeName != "" {
		g.nodes[p.NodeName] = true
	}
}

// node is the one node every pod of the group runs on, else "".
func (g *podGroup) node() string {
	if len(g.nodes) != 1 {
		return ""
	}
	for n := range g.nodes {
		return n
	}
	return ""
}

func (g *podGroup) object() string { return g.kind + " " + g.ns + "/" + g.name }

type groupKey struct{ ns, kind, name string }

// podChecks folds the pods' problems per workload: one candidate per
// workload and problem, however many pods it has.
func podChecks(v *snapshot.View, now time.Time, f *Found) {
	if unavailable(v, "pods") {
		f.Skipped[CheckWorkloadUnhealthy], f.Skipped[CheckPodEvicted], f.Skipped[CheckPodStuckTerminating] = true, true, true
		return
	}
	th := v.Policy.Thresholds
	a := v.Assoc()
	status := map[groupKey]string{} // workload status, for severity
	for ns, ws := range v.Workloads {
		for i := range ws {
			status[groupKey{ns, ws[i].Kind, ws[i].Name}] = ws[i].Status
		}
	}
	unhealthy, evicted, stuck := map[groupKey]*podGroup{}, map[groupKey]*podGroup{}, map[groupKey]*podGroup{}
	live := map[groupKey]int{}
	group := func(m map[groupKey]*podGroup, p *model.Pod) *podGroup {
		kind, name := a.RootOf(p)
		k := groupKey{p.Namespace, kind, name}
		g := m[k]
		if g == nil {
			g = &podGroup{ns: p.Namespace, kind: kind, name: name}
			m[k] = g
		}
		return g
	}
	for i := range v.Inv.Pods {
		p := &v.Inv.Pods[i]
		if p.Phase != "Succeeded" && p.Phase != "Failed" && p.DeletedAt.IsZero() {
			kind, name := a.RootOf(p)
			live[groupKey{p.Namespace, kind, name}]++
		}
		switch {
		case !p.DeletedAt.IsZero():
			if now.Sub(p.DeletedAt) > th.TerminatingGrace {
				g := group(stuck, p)
				g.add(p, "")
				if g.at.IsZero() || p.DeletedAt.Before(g.at) {
					g.at, g.worst = p.DeletedAt, p
				}
			}
		case p.Reason == "Evicted":
			at := evictedAt(p)
			if now.Sub(at) <= th.RecentPod {
				g := group(evicted, p)
				g.add(p, "")
				if g.worst == nil || at.After(g.at) {
					g.at, g.worst = at, p
				}
			}
		case p.Reason != "" || p.Phase == "Failed":
			// Failed by the node for another reason, or finished: not a
			// workload that cannot start.
		default:
			st, reason := detectors.PodState(p, th, now)
			if st != detectors.PodFailing && st != detectors.PodPending {
				continue
			}
			g := group(unhealthy, p)
			g.add(p, reason)
			if g.worst == nil || reasonRank(reason) < reasonRank(detectors.PodReason(g.worst)) {
				g.worst = p
			}
		}
	}

	for _, g := range sortedGroups(unhealthy) {
		sev := SeverityWarning
		if g.reasons["CrashLoopBackOff"] > 0 || status[groupKey{g.ns, g.kind, g.name}] == detectors.StatusCrit {
			sev = SeverityCritical
		}
		counts := detectors.ReasonCounts(g.reasons)
		total := max(live[groupKey{g.ns, g.kind, g.name}], g.pods)
		desc := fmt.Sprintf("%d of %d %s of %s cannot run: %s.", g.pods, total, plural(total, "pod", "pods"), g.object(), counts)
		if msg := podMessage(g.worst); msg != "" {
			desc += " " + g.worst.Name + ": " + msg
		}
		f.Candidates = append(f.Candidates, Candidate{
			Check: CheckWorkloadUnhealthy, Kind: g.kind, Namespace: g.ns, Name: g.name, Severity: sev,
			Title: g.object() + ": " + counts, Description: desc, Link: workloadLink(g),
			Extra: map[string]string{"pods": strconv.Itoa(g.pods), "reasons": reasonList(g.reasons)},
		})
	}
	for _, g := range sortedGroups(evicted) {
		desc := fmt.Sprintf("%d %s of %s %s evicted in the last %s, the latest %s on node %s.", g.pods, plural(g.pods, "pod", "pods"), g.object(),
			plural(g.pods, "was", "were"), span(th.RecentPod), g.at.UTC().Format(time.RFC3339), orNone(g.worst.NodeName))
		if g.worst.Message != "" {
			desc += " " + clip(g.worst.Message)
		}
		f.Candidates = append(f.Candidates, Candidate{
			Check: CheckPodEvicted, Kind: g.kind, Namespace: g.ns, Name: g.name, Severity: SeverityWarning, Node: g.node(),
			Title:       fmt.Sprintf("%s: %d %s evicted", g.object(), g.pods, plural(g.pods, "pod", "pods")),
			Description: desc, Link: workloadLink(g),
			Extra: map[string]string{"pods": strconv.Itoa(g.pods), "latest_eviction": g.at.UTC().Format(time.RFC3339)},
		})
	}
	for _, g := range sortedGroups(stuck) {
		desc := fmt.Sprintf("%d %s of %s %s still terminating more than %s after %s deletion time (the oldest, pod %s on node %s, since %s); a finalizer or an unreachable node may be holding %s.",
			g.pods, plural(g.pods, "pod", "pods"), g.object(), plural(g.pods, "is", "are"), roughly(th.TerminatingGrace), plural(g.pods, "its", "their"),
			g.worst.Name, orNone(g.worst.NodeName), g.at.UTC().Format(time.RFC3339), plural(g.pods, "it", "them"))
		f.Candidates = append(f.Candidates, Candidate{
			Check: CheckPodStuckTerminating, Kind: g.kind, Namespace: g.ns, Name: g.name, Severity: SeverityWarning, Node: g.node(),
			Title:       fmt.Sprintf("%s: %d %s stuck terminating", g.object(), g.pods, plural(g.pods, "pod", "pods")),
			Description: desc, Link: workloadLink(g),
			Extra: map[string]string{"pods": strconv.Itoa(g.pods), "oldest_deletion": g.at.UTC().Format(time.RFC3339)},
		})
	}
}

func sortedGroups(m map[groupKey]*podGroup) []*podGroup {
	out := make([]*podGroup, 0, len(m))
	for _, g := range m {
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.ns != b.ns {
			return a.ns < b.ns
		}
		if a.kind != b.kind {
			return a.kind < b.kind
		}
		return a.name < b.name
	})
	return out
}

// workloadLink is the Workloads page for a workload, or the pod page for a
// bare pod.
func workloadLink(g *podGroup) string {
	if g.kind == "Pod" {
		return uilink.Pod(g.ns, g.name)
	}
	return uilink.Workload(g.ns, g.name)
}

// evictedAt is when a pod was evicted, as near as the pod tells: its Ready
// condition's flip, else its containers' last termination, else its
// creation.
func evictedAt(p *model.Pod) time.Time {
	if !p.ReadyChanged.IsZero() {
		return p.ReadyChanged
	}
	var at time.Time
	for _, c := range p.Containers {
		if c.LastTerminatedAt.After(at) {
			at = c.LastTerminatedAt
		}
	}
	if at.IsZero() {
		return p.Created
	}
	return at
}

// reasonRank orders the reasons a workload is unhealthy, worst first.
func reasonRank(r string) int {
	switch {
	case r == "CrashLoopBackOff":
		return 0
	case detectors.IsStuckReason(r):
		return 1
	case r == "Unschedulable":
		return 2
	}
	return 3
}

// podMessage is the message that explains why a pod cannot run: its stuck
// container's, else the scheduler's.
func podMessage(p *model.Pod) string {
	if p == nil {
		return ""
	}
	for _, c := range p.Containers {
		if c.State == "waiting" && detectors.IsStuckReason(c.Reason) && c.Message != "" {
			return clip(c.Name + ": " + c.Message)
		}
	}
	if p.Unschedulable != "" {
		return clip(p.Unschedulable)
	}
	return ""
}

// reasonList is "CrashLoopBackOff=3,ImagePullBackOff=1", sorted by reason.
func reasonList(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + "=" + strconv.Itoa(m[k])
	}
	return strings.Join(parts, ",")
}

// ---- memory leaks ----

func leakCheck(v *snapshot.View, rep *detectors.LeakReport, critHours float64, f *Found) {
	if rep == nil || rep.GeneratedAt.IsZero() {
		f.Skipped[CheckMemoryLeak] = true
		return
	}
	type leakGroup struct {
		podGroup
		worst detectors.LeakFinding
		pods  map[string]bool
	}
	a := v.Assoc()
	groups := map[groupKey]*leakGroup{}
	for _, l := range rep.Findings {
		p, ok := a.PodNamed(l.Namespace, l.Pod)
		if !ok {
			continue // the pod is gone; the scan's window still remembers it
		}
		kind, name := a.RootOf(p)
		k := groupKey{l.Namespace, kind, name}
		g := groups[k]
		if g == nil {
			g = &leakGroup{podGroup: podGroup{ns: l.Namespace, kind: kind, name: name}, worst: l, pods: map[string]bool{}}
			groups[k] = g
		} else if sooner(l, g.worst) {
			g.worst = l
		}
		g.pods[l.Pod] = true
	}
	keys := make([]groupKey, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].ns+"\x00"+keys[i].kind+"\x00"+keys[i].name < keys[j].ns+"\x00"+keys[j].kind+"\x00"+keys[j].name
	})
	for _, k := range keys {
		g := groups[k]
		w := g.worst
		sev := SeverityWarning
		extra := map[string]string{"pods": strconv.Itoa(len(g.pods)), "container": w.Container, "pod": w.Pod,
			"growth_bytes_per_hour": strconv.FormatFloat(w.SlopeBytesPerHour, 'f', 0, 64)}
		desc := fmt.Sprintf("Container %s of pod %s grows %s (R² %.2f, %s confidence)", w.Container, w.Pod, detectors.FormatRate(w.SlopeBytesPerHour), w.R2, w.Confidence)
		if w.TimeToLimitHours != nil {
			h := *w.TimeToLimitHours
			if h < critHours {
				sev = SeverityCritical
			}
			oom := rep.GeneratedAt.Add(time.Duration(h * float64(time.Hour))).UTC()
			extra["predicted_oom"] = oom.Format(time.RFC3339)
			desc += fmt.Sprintf(" and reaches its memory limit in about %s, around %s: expect an OOM kill then.", detectors.ApproxHours(h)[1:], oom.Format("2006-01-02 15:04 MST"))
		} else {
			desc += "; it has no memory limit, so nothing stops it growing."
		}
		if n := len(g.pods); n > 1 {
			desc += fmt.Sprintf(" %d pods of %s show the leak.", n, g.object())
		}
		f.Candidates = append(f.Candidates, Candidate{
			Check: CheckMemoryLeak, Kind: g.kind, Namespace: g.ns, Name: g.name, Severity: sev,
			Title: g.object() + ": " + detectors.LeakTitle(w), Description: desc,
			Link: uilink.Pod(w.Namespace, w.Pod), Extra: extra,
		})
	}
}

// sooner reports whether leak a reaches its limit before b (a leak without
// a limit comes last, the faster growing first).
func sooner(a, b detectors.LeakFinding) bool {
	switch {
	case a.TimeToLimitHours != nil && b.TimeToLimitHours != nil:
		return *a.TimeToLimitHours < *b.TimeToLimitHours
	case a.TimeToLimitHours != nil:
		return true
	case b.TimeToLimitHours != nil:
		return false
	}
	return a.SlopeBytesPerHour > b.SlopeBytesPerHour
}

// ---- RBAC drift ----

// rbacDriftChecks are the security checks whose new findings are RBAC drift.
var rbacDriftChecks = map[string]bool{
	CheckClusterAdmin: true, CheckAnonymousBinding: true, CheckWildcardRBAC: true, CheckAWSAuthMasters: true,
}

// driftWhat says what appeared, per drift check.
var driftWhat = map[string]string{
	CheckClusterAdmin:     "new cluster-admin binding",
	CheckAnonymousBinding: "new anonymous binding",
	CheckWildcardRBAC:     "new wildcard role in use",
	CheckAWSAuthMasters:   "new aws-auth system:masters mapping",
}

// rbacChecks lists every standing RBAC finding the drift checks watch; the
// evaluator alerts only on those missing from the baseline. Findings about
// platform plumbing (system subjects, built-in roles) are left out.
func rbacChecks(v *snapshot.View, f *Found) {
	rbacKnown := !unavailable(v, "roles", "clusterroles", "rolebindings", "clusterrolebindings")
	awsKnown := v.Inv.AWSAuth != nil && !unavailable(v, "aws-auth")
	if !rbacKnown {
		f.Skipped[CheckClusterAdmin], f.Skipped[CheckAnonymousBinding], f.Skipped[CheckWildcardRBAC] = true, true, true
	}
	if !awsKnown {
		f.Skipped[CheckAWSAuthMasters] = true
	}
	for ns, fs := range v.Findings {
		for i := range fs {
			sf := &fs[i]
			if sf.System || sf.Category != "rbac" || !rbacDriftChecks[sf.Check] || f.Skipped[sf.Check] {
				continue
			}
			name := sf.Subject
			if ns != "" {
				name = strings.TrimPrefix(sf.Subject, ns+"/")
			}
			obj := sf.SubjectKind + " " + sf.Subject
			f.Candidates = append(f.Candidates, Candidate{
				Check: sf.Check, Kind: sf.SubjectKind, Namespace: ns, Name: name, Severity: SeverityCritical,
				Title:       "RBAC drift: " + driftWhat[sf.Check] + ": " + obj,
				Description: "kubesentry saw this appear since its last evaluation: " + sf.Detail,
				Link:        uilink.Security(sf.Check, sf.Subject),
			})
		}
	}
}

// ---- formatting ----

const maxText = 400

// clip shortens s to maxText bytes on a rune boundary.
func clip(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= maxText {
		return s
	}
	cut := maxText - len("…")
	for cut > 0 && s[cut]&0xC0 == 0x80 {
		cut--
	}
	return strings.TrimSpace(s[:cut]) + "…"
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// span names a look-back: "day", "6 hours", "30 minutes".
func span(d time.Duration) string {
	switch {
	case d == 24*time.Hour:
		return "day"
	case d >= time.Hour && d%time.Hour == 0:
		return fmt.Sprintf("%d hours", int(d/time.Hour))
	}
	return fmt.Sprintf("%d minutes", int(d/time.Minute))
}

// roughly is a duration in words: "25 minutes", "3 hours", "2 days".
func roughly(d time.Duration) string {
	switch {
	case d < time.Hour:
		n := max(1, int(d/time.Minute))
		return fmt.Sprintf("%d %s", n, plural(n, "minute", "minutes"))
	case d < 48*time.Hour:
		n := int(d / time.Hour)
		return fmt.Sprintf("%d %s", n, plural(n, "hour", "hours"))
	}
	n := int(d / (24 * time.Hour))
	return fmt.Sprintf("%d days", n)
}
