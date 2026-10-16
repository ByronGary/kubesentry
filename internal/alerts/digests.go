package alerts

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/snapshot"
	"github.com/ByronGary/kubesentry/internal/uilink"
)

// Standing digest kinds (-alerts-digest-kinds): what stands rather than
// what changed, sent per owner on a schedule.
const (
	// DigestRBACPosture lists the standing RBAC findings of the Security
	// page (cluster plumbing left out).
	DigestRBACPosture = "rbac-posture"
	// DigestUnusedVolumes lists the claims no pod mounts, with their cost.
	DigestUnusedVolumes = "unused-volumes"
	// DigestCertificates lists the quiet certificates: expiring, not
	// renewing on schedule, with more than CertDays left.
	DigestCertificates = "certificates"
)

// DigestKinds lists every standing digest kind.
func DigestKinds() []string {
	return []string{DigestRBACPosture, DigestUnusedVolumes, DigestCertificates}
}

// DefaultCertDigestDays: an expiring certificate with more days left than
// this is quiet (-alerts-cert-digest-days).
const DefaultCertDigestDays = 14

// standingDigestFor is how long a standing digest alert lasts in
// Alertmanager: it is sent once, never re-posted.
const standingDigestFor = time.Hour

// DigestOptions configures the standing digests. A zero Schedule turns
// them off.
type DigestOptions struct {
	Schedule DigestSchedule
	// Kinds are the digests sent; default DigestKinds.
	Kinds []string
	// CertDays: an expiring certificate with more days left is quiet, listed
	// in the certificates digest and never notified alone. Default
	// DefaultCertDigestDays.
	CertDays int
	// PVCMinAge: the unused-volumes digest lists claims at least this old
	// (-pvc-min-age).
	PVCMinAge time.Duration
}

func (o *DigestOptions) defaults() {
	if o.Kinds == nil {
		o.Kinds = DigestKinds()
	}
	if o.CertDays <= 0 {
		o.CertDays = DefaultCertDigestDays
	}
}

// has reports whether the digest of kind is sent.
func (o *DigestOptions) has(kind string) bool {
	if !o.Schedule.Enabled() {
		return false
	}
	for _, k := range o.Kinds {
		if k == kind {
			return true
		}
	}
	return false
}

// DigestSchedule is when the standing digests go out: weekly on a weekday,
// or daily, at a time of day in a time zone. The zero value is off.
type DigestSchedule struct {
	weekly       bool
	weekday      time.Weekday
	hour, minute int
	loc          *time.Location
}

var weekdays = map[string]time.Weekday{
	"sun": time.Sunday, "mon": time.Monday, "tue": time.Tuesday, "wed": time.Wednesday,
	"thu": time.Thursday, "fri": time.Friday, "sat": time.Saturday,
}

// ParseDigestSchedule reads -alerts-digest-at ("Mon 09:00" weekly, "09:00"
// daily, "" off) in the time zone tz (an IANA name; "" is UTC).
func ParseDigestSchedule(at, tz string) (DigestSchedule, error) {
	at = strings.TrimSpace(at)
	if at == "" {
		return DigestSchedule{}, nil
	}
	var s DigestSchedule
	clock := at
	if day, rest, ok := strings.Cut(at, " "); ok {
		d := strings.ToLower(day)
		wd, ok := weekdays[d]
		if !ok && len(d) > 3 {
			wd, ok = weekdays[d[:3]]
			ok = ok && strings.ToLower(wd.String()) == d
		}
		if !ok {
			return s, fmt.Errorf("%q: want a weekday such as Mon or Monday, then HH:MM", at)
		}
		s.weekly, s.weekday, clock = true, wd, strings.TrimSpace(rest)
	}
	t, err := time.Parse("15:04", clock)
	if err != nil || len(clock) != 5 {
		return DigestSchedule{}, fmt.Errorf("%q: want HH:MM (24-hour), optionally after a weekday: \"Mon 09:00\" or \"09:00\"", at)
	}
	s.hour, s.minute = t.Hour(), t.Minute()
	s.loc = time.UTC
	if tz = strings.TrimSpace(tz); tz != "" {
		loc, err := time.LoadLocation(tz)
		if err != nil {
			return DigestSchedule{}, fmt.Errorf("time zone %q: %w", tz, err)
		}
		s.loc = loc
	}
	return s, nil
}

// Enabled reports whether digests are scheduled.
func (s DigestSchedule) Enabled() bool { return s.loc != nil }

// String is the schedule as -alerts-digest-at and -alerts-digest-tz give it.
func (s DigestSchedule) String() string {
	if !s.Enabled() {
		return "off"
	}
	at := fmt.Sprintf("%02d:%02d %s", s.hour, s.minute, s.loc)
	if s.weekly {
		return s.weekday.String()[:3] + " " + at
	}
	return "daily " + at
}

// slot is the scheduled time on the day of t (in the schedule's zone)
// shifted by days.
func (s DigestSchedule) slot(t time.Time, days int) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day()+days, s.hour, s.minute, 0, 0, s.loc)
}

// Latest is the latest scheduled time at or before now (zero when off).
func (s DigestSchedule) Latest(now time.Time) time.Time {
	if !s.Enabled() {
		return time.Time{}
	}
	t := now.In(s.loc)
	back := 0
	if s.weekly {
		back = (int(t.Weekday()) - int(s.weekday) + 7) % 7
	}
	c := s.slot(t, -back)
	if c.After(now) {
		step := 1
		if s.weekly {
			step = 7
		}
		c = s.slot(t, -back-step)
	}
	return c
}

// Next is the first scheduled time after now (zero when off).
func (s DigestSchedule) Next(now time.Time) time.Time {
	if !s.Enabled() {
		return time.Time{}
	}
	l := s.Latest(now).In(s.loc)
	step := 1
	if s.weekly {
		step = 7
	}
	return s.slot(l, step)
}

// digestItem is one line of a standing digest.
type digestItem struct {
	rank int    // worst first
	key  string // then by this
	line string
	// cost is the monthly USD of an unused volume; unpriced, when its class
	// has no price.
	cost     float64
	unpriced bool
}

// dueDigests returns the standing digest alerts due now, one per owner and
// kind, and the kinds sent (with now as their run). A kind is due when its
// latest scheduled time is after its last run; one never sent waits for the
// first scheduled time after this evaluator started, so a restart or a new
// install does not send at once. A kind whose source could not be read
// waits for the next evaluation.
func (e *Evaluator) dueDigests(in Input, found Found, now time.Time, res *Result) ([]Alert, map[string]time.Time) {
	d := &e.o.Digests
	if !d.Schedule.Enabled() {
		return nil, nil
	}
	latest := d.Schedule.Latest(now)
	var out []Alert
	runs := map[string]time.Time{}
	for _, kind := range d.Kinds {
		last, ok := e.digestRuns[kind]
		if !ok {
			last = e.digestSince
		}
		if !last.Before(latest) {
			continue
		}
		byOwner, ok := e.digestItems(kind, in.View, found)
		if !ok {
			continue
		}
		owners := make([]string, 0, len(byOwner))
		for o := range byOwner {
			owners = append(owners, o)
		}
		sort.Strings(owners)
		for _, o := range owners {
			out = append(out, e.standingAlert(kind, o, byOwner[o], now))
		}
		runs[kind] = now
		res.StandingDigests[kind] += len(owners)
	}
	if len(runs) == 0 {
		return nil, nil
	}
	return out, runs
}

// digestItems gathers a digest's lines per owner; ok is false when its
// source could not be read.
func (e *Evaluator) digestItems(kind string, v *snapshot.View, found Found) (map[string][]digestItem, bool) {
	out := map[string][]digestItem{}
	nss := namespaceInfo(v)
	owners := objectOwners(v)
	silenced := func(key string) bool {
		f := e.state[key]
		return f != nil && f.State == StateSilenced
	}
	switch kind {
	case DigestRBACPosture:
		if unavailable(v, "roles", "clusterroles", "rolebindings", "clusterrolebindings") {
			return nil, false
		}
		for ns, fs := range v.Findings {
			for i := range fs {
				sf := &fs[i]
				if sf.System || sf.Category != "rbac" {
					continue
				}
				name := strings.TrimPrefix(sf.Subject, ns+"/")
				key := Key(sf.Check, sf.SubjectKind, ns, name)
				if silenced(key) {
					continue
				}
				sev := map[string]string{detectors.StatusCrit: SeverityCritical, detectors.StatusWarn: SeverityWarning}[sf.Severity]
				if sev == "" {
					sev = SeverityInfo
				}
				rank := map[string]int{SeverityCritical: 0, SeverityWarning: 1, SeverityInfo: 2}[sev]
				owner := e.ownerOf(sf.SubjectKind, ns, name, nss, owners, v)
				out[owner] = append(out[owner], digestItem{rank: rank, key: key,
					line: fmt.Sprintf("[%s] %s %s: %s. %s", sev, sf.SubjectKind, sf.Subject, sf.Title, sf.Detail)})
			}
		}
	case DigestUnusedVolumes:
		if unavailable(v, "persistentvolumeclaims", "pods") {
			return nil, false
		}
		minAge := e.o.Digests.PVCMinAge.Hours()
		for ns, us := range v.Unused {
			for _, u := range us {
				if u.AgeHours < minAge {
					continue
				}
				owner := e.ownerOf("PersistentVolumeClaim", ns, u.Name, nss, owners, v)
				cost := "cost unknown"
				if u.CostKnown {
					cost = fmt.Sprintf("about $%.2f a month", u.EstMonthlyCostUSD)
				}
				class := u.StorageClass
				if class == "" {
					class = "(none)"
				}
				out[owner] = append(out[owner], digestItem{key: ns + "/" + u.Name, cost: u.EstMonthlyCostUSD, unpriced: !u.CostKnown,
					line: fmt.Sprintf("PersistentVolumeClaim %s/%s: %s, class %s, unused for %s, %s", ns, u.Name,
						gib(u.CapacityBytes), class, roughly(time.Duration(u.AgeHours*float64(time.Hour))), cost)})
			}
		}
		for o := range out {
			// The most expensive first.
			sort.SliceStable(out[o], func(i, j int) bool { return out[o][i].cost > out[o][j].cost })
			for i := range out[o] {
				out[o][i].rank = i
			}
		}
	case DigestCertificates:
		if found.Skipped[CheckCertExpiring] {
			return nil, false
		}
		for _, f := range e.state {
			if f.Check != CheckCertExpiring || !f.Quiet || f.Resolved() || f.State == StateSilenced {
				continue
			}
			// The soonest to expire first (RFC 3339 in UTC sorts by time).
			out[f.Owner] = append(out[f.Owner], digestItem{key: f.Annotations["expires_at"] + "\x00" + f.Key, line: f.Title})
		}
	default:
		return nil, false
	}
	return out, true
}

// gib formats a capacity: "100 GiB", "512 MiB".
func gib(b int64) string {
	switch {
	case b >= 1<<30:
		return strconv.FormatFloat(float64(b)/(1<<30), 'f', -1, 64) + " GiB"
	case b > 0:
		return strconv.FormatInt(b>>20, 10) + " MiB"
	}
	return "size unknown"
}

// standingAlert is one owner's digest of kind: sent once, lasting
// standingDigestFor.
func (e *Evaluator) standingAlert(kind, owner string, items []digestItem, now time.Time) Alert {
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].rank != items[j].rank {
			return items[i].rank < items[j].rank
		}
		return items[i].key < items[j].key
	})
	l := map[string]string{
		"alertname": AlertStandingDigest, "severity": SeverityInfo, "digest": kind, "kubesentry_digest": "true", "owner": owner,
	}
	if e.o.Cluster != "" {
		l["cluster"] = e.o.Cluster
	}
	n := len(items)
	ann := map[string]string{
		"runbook_url": e.o.RunbookURL + "#" + strings.ToLower(AlertStandingDigest),
		"count":       strconv.Itoa(n),
	}
	var b strings.Builder
	for i, it := range items {
		if i == maxDigestLines {
			fmt.Fprintf(&b, "\n… and %d more.", n-maxDigestLines)
			break
		}
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString("- " + clip(it.line))
	}
	ann["findings"] = clean(b.String())
	switch kind {
	case DigestRBACPosture:
		bySev := map[int]int{}
		for _, it := range items {
			bySev[it.rank]++
		}
		ann["summary"] = fmt.Sprintf("RBAC posture for %s: %d standing %s", owner, n, plural(n, "finding", "findings"))
		ann["description"] = fmt.Sprintf("Standing RBAC findings owned by %s, cluster plumbing left out: %d critical, %d warning, %d info. They are standing state, so they come in this digest; a binding that newly appears fires on its own as KubesentryRBACDrift.",
			owner, bySev[0], bySev[1], bySev[2])
	case DigestUnusedVolumes:
		total, unpriced := 0.0, 0
		for _, it := range items {
			total += it.cost
			if it.unpriced {
				unpriced++
			}
		}
		ann["monthly_cost_usd"] = strconv.FormatFloat(total, 'f', 2, 64)
		cost := fmt.Sprintf("about $%.2f a month", total)
		if unpriced == n {
			cost = "cost unknown"
		}
		ann["summary"] = fmt.Sprintf("Unused volumes for %s: %d %s, %s", owner, n, plural(n, "claim", "claims"), cost)
		age := ""
		if a := e.o.Digests.PVCMinAge; a > 0 {
			age = ", at least " + roughly(a) + " old"
		}
		desc := fmt.Sprintf("PersistentVolumeClaims owned by %s that no pod mounts%s, most expensive first: about $%.2f a month together", owner, age, total)
		if unpriced > 0 {
			desc += fmt.Sprintf(", not counting %d whose storage class has no price", unpriced)
		}
		ann["description"] = desc + ". A StatefulSet scaled to zero leaves its claims unmounted on purpose."
	case DigestCertificates:
		days := e.o.Digests.CertDays
		ann["summary"] = fmt.Sprintf("Certificates for %s: %d expiring, more than %d days left", owner, n, days)
		ann["description"] = fmt.Sprintf("Certificates owned by %s that cert-manager has not renewed on schedule, with more than %d days left. Each fires on its own as KubesentryCertificateExpiring once fewer days are left.",
			owner, days)
	}
	a := Alert{Labels: l, Annotations: ann, StartsAt: now, EndsAt: now.Add(standingDigestFor)}
	if u := uilink.Absolute(e.o.ExternalURL, uilink.Owner(owner)); u != "" {
		ann["kubesentry_url"] = u
		a.GeneratorURL = u
	}
	return a
}
