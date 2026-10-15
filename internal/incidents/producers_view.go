package incidents

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
	"github.com/ByronGary/kubesentry/internal/snapshot"
)

// ViewDiff turns consecutive snapshot views into signals: restarts (with the
// last termination's reason and exit code), OOM kills, crash loops,
// evictions, deploys (a new Workload.Revision, with the image diff and a
// rollback flag) and scaling (a new Desired).
//
// The first view of a leadership term only sets the baseline: what changed
// before it was the previous leader's to see. Terminations after the lease
// was taken are the exception, since the previous leader may have missed
// them. Crash loops are states, not changes, so they are reported from the
// first view on (Resume continues the ones already in open incidents).
type ViewDiff struct {
	o       Options
	leaseAt time.Time

	prev     *snapshot.View
	crash    map[string]*Signal     // crash-looping container key → its signal
	restarts map[string][]time.Time // pod key → restart times within Quiet
}

// NewViewDiff returns a differ for a leadership term that began at leaseAt.
func NewViewDiff(o Options, leaseAt time.Time) *ViewDiff {
	o.defaults()
	return &ViewDiff{o: o, leaseAt: leaseAt, crash: map[string]*Signal{}, restarts: map[string][]time.Time{}}
}

// Resume continues the crash loops of open incidents (Engine.Active).
func (d *ViewDiff) Resume(active []Signal) {
	for _, s := range active {
		if s.Type == TypeCrashLoop && s.Source == SourceView {
			c := CloneSignal(s)
			d.crash[crashKey(objectPodKey(s.Object), s.Attrs["container"])] = &c
		}
	}
}

func podKey(p *model.Pod) string {
	if p.UID != "" {
		return p.UID
	}
	return p.Namespace + "/" + p.Name
}

func objectPodKey(o model.ObjectRef) string {
	if o.UID != "" {
		return o.UID
	}
	return o.Namespace + "/" + o.Name
}

func crashKey(pod, container string) string { return pod + "|" + container }

func podRef(p *model.Pod) model.ObjectRef {
	return model.ObjectRef{Kind: "Pod", Namespace: p.Namespace, Name: p.Name, UID: p.UID}
}

// Diff compares v with the previous view and returns the signals.
func (d *ViewDiff) Diff(v *snapshot.View, now time.Time) []Signal {
	if v == nil || v == d.prev {
		return nil
	}
	now = NormalTime(now)
	first := d.prev == nil
	var prevBuilt time.Time
	prevPods := map[string]*model.Pod{}
	prevWorkloads := map[Subject]*model.Workload{}
	if !first {
		prevBuilt = d.prev.Built
		for i := range d.prev.Inv.Pods {
			p := &d.prev.Inv.Pods[i]
			prevPods[podKey(p)] = p
		}
		for i := range d.prev.Inv.Workloads {
			w := &d.prev.Inv.Workloads[i]
			prevWorkloads[Subject{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name}] = w
		}
	}
	th := d.o.Thresholds
	warn, crit := th.RestartWarn, th.RestartCrit
	if warn <= 0 {
		warn = v.Policy.Thresholds.RestartWarn
	}
	if crit <= 0 {
		crit = v.Policy.Thresholds.RestartCrit
	}
	if warn <= 0 {
		warn = 3
	}
	if crit <= 0 {
		crit = 10
	}
	a := v.Assoc()
	var out []Signal
	looping := map[string]bool{}
	livePods := map[string]bool{}
	for i := range v.Inv.Pods {
		p := &v.Inv.Pods[i]
		key := podKey(p)
		livePods[key] = true
		subj := subjectOfPod(a, p)
		pp := prevPods[key]
		for _, c := range p.Containers {
			prevCount := int32(-1)
			if pp != nil {
				for _, pc := range pp.Containers {
					if pc.Name == c.Name && pc.Init == c.Init {
						prevCount = pc.RestartCount
					}
				}
			}
			delta := int32(0)
			switch {
			case first:
				if c.RestartCount > 0 && c.LastTerminatedAt.After(d.leaseAt) {
					delta = 1
				}
			case prevCount >= 0:
				delta = c.RestartCount - prevCount
			default: // a pod or container new since the previous view
				if c.RestartCount > 0 && c.LastTerminatedAt.After(prevBuilt) {
					delta = c.RestartCount
				}
			}
			if delta > 0 {
				out = append(out, d.restartSignals(p, c, subj, int(delta), warn, crit, now)...)
			}
			if c.State == "waiting" && c.Reason == "CrashLoopBackOff" {
				k := crashKey(key, c.Name)
				looping[k] = true
				s := d.crash[k]
				if s == nil {
					s = &Signal{ID: fmt.Sprintf("view:crashloop:%s/%s@%d", key, c.Name, now.Unix()), Type: TypeCrashLoop, Source: SourceView,
						Role: Trigger, Severity: Critical, Start: now, Subject: subj, Object: podRef(p)}
					d.crash[k] = s
				}
				s.Title = fmt.Sprintf("%s/%s is crash-looping", p.Name, c.Name)
				s.Count = int(c.RestartCount)
				s.Attrs = map[string]string{"pod": p.Name, "container": c.Name, "restarts": strconv.Itoa(int(c.RestartCount)),
					"lastReason": c.LastTerminatedReason, "exitCode": strconv.Itoa(int(c.LastExitCode)), "message": c.Message}
				out = append(out, CloneSignal(*s))
			}
		}
		evictedNow := p.Reason == "Evicted"
		if evictedNow && !first && (pp == nil || pp.Reason != "Evicted") {
			out = append(out, Signal{ID: "view:eviction:" + key, Type: TypeEviction, Source: SourceView, Role: Trigger, Severity: Warning,
				Start: evictedAt(p, now), Subject: subj, Object: podRef(p), Title: fmt.Sprintf("%s was evicted", p.Name),
				Attrs: map[string]string{"pod": p.Name, "node": p.NodeName, "message": p.Message}})
		}
	}
	keys := make([]string, 0, len(d.crash))
	for k := range d.crash {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if looping[k] {
			continue
		}
		s := d.crash[k]
		s.End = timePtr(now)
		out = append(out, CloneSignal(*s))
		delete(d.crash, k)
	}
	for k := range d.restarts {
		if !livePods[k] {
			delete(d.restarts, k)
		}
	}
	if !first {
		for i := range v.Inv.Workloads {
			w := &v.Inv.Workloads[i]
			pw := prevWorkloads[Subject{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name}]
			if pw == nil {
				continue
			}
			if w.Revision != "" && pw.Revision != "" && w.Revision != pw.Revision {
				out = append(out, d.deploySignal(v, pw, w, now))
			}
			if w.Desired != pw.Desired && (w.Kind == "Deployment" || w.Kind == "StatefulSet") {
				subj, _ := SubjectOfWorkload(v, w.Kind, w.Namespace, w.Name)
				out = append(out, Signal{ID: fmt.Sprintf("view:scale:%s/%s/%s@%d#%d", w.Kind, w.Namespace, w.Name, now.Unix(), w.Desired),
					Type: TypeScale, Source: SourceView, Role: Context, Start: now, Subject: subj,
					Object: model.ObjectRef{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name, UID: w.UID},
					Title:  fmt.Sprintf("%s %s scaled from %d to %d", w.Kind, w.Name, pw.Desired, w.Desired),
					Attrs:  map[string]string{"from": strconv.Itoa(int(pw.Desired)), "to": strconv.Itoa(int(w.Desired))}})
			}
		}
	}
	d.prev = v
	return out
}

// evictedAt is when the pod was evicted, as well as the view tells: its
// containers' last termination, else now.
func evictedAt(p *model.Pod, now time.Time) time.Time {
	var at time.Time
	for _, c := range p.Containers {
		if c.LastTerminatedAt.After(at) {
			at = c.LastTerminatedAt
		}
	}
	if at.IsZero() || at.After(now) {
		return now
	}
	return at
}

// restartSignals reports delta restarts of one container: an OOM kill
// (critical) when the last termination was one, and restarts whose role
// and severity follow the restarts of the pod within Quiet.
func (d *ViewDiff) restartSignals(p *model.Pod, c model.ContainerStatus, subj Subject, delta int, warn, crit int32, now time.Time) []Signal {
	at := c.LastTerminatedAt
	if at.IsZero() || at.After(now) {
		at = now
	}
	key := podKey(p)
	hist := d.restarts[key]
	for i := 0; i < delta; i++ {
		hist = append(hist, at)
	}
	cut := now.Add(-d.o.Quiet)
	kept := hist[:0]
	for _, t := range hist {
		if !t.Before(cut) {
			kept = append(kept, t)
		}
	}
	d.restarts[key] = kept
	n := int32(len(kept))
	attrs := map[string]string{"pod": p.Name, "container": c.Name, "reason": c.LastTerminatedReason,
		"exitCode": strconv.Itoa(int(c.LastExitCode)), "restarts": strconv.Itoa(int(c.RestartCount)), "node": p.NodeName}
	var out []Signal
	if c.LastTerminatedReason == "OOMKilled" {
		out = append(out, Signal{ID: fmt.Sprintf("view:oom-kill:%s/%s#%d", key, c.Name, c.RestartCount), Type: TypeOOMKill, Source: SourceView,
			Role: Trigger, Severity: Critical, Start: at, Subject: subj, Object: podRef(p), Count: 1,
			Title: fmt.Sprintf("%s/%s was OOM killed", p.Name, c.Name), Attrs: attrs})
		delta--
		if delta == 0 {
			return out
		}
	}
	s := Signal{ID: fmt.Sprintf("view:restart:%s/%s#%d", key, c.Name, c.RestartCount), Type: TypeRestart, Source: SourceView,
		Role: Context, Start: at, Subject: subj, Object: podRef(p), Count: delta, Attrs: attrs}
	switch {
	case n >= crit:
		s.Role, s.Severity = Trigger, Critical
	case n >= warn:
		s.Role, s.Severity = Trigger, Warning
	}
	why := c.LastTerminatedReason
	if why == "" {
		why = "unknown reason"
	}
	s.Title = fmt.Sprintf("%s/%s restarted (%s, exit %d)", p.Name, c.Name, why, c.LastExitCode)
	if delta > 1 {
		s.Title = fmt.Sprintf("%s/%s restarted %d times (last: %s, exit %d)", p.Name, c.Name, delta, why, c.LastExitCode)
	}
	return append(out, s)
}

// deploySignal reports a rollout: the revision change, the images that
// changed, and whether it went back to an older ReplicaSet (a rollback).
func (d *ViewDiff) deploySignal(v *snapshot.View, pw, w *model.Workload, now time.Time) Signal {
	subj, _ := SubjectOfWorkload(v, w.Kind, w.Namespace, w.Name)
	oldImgs, newImgs := pw.Images, w.Images
	start := now
	rollback := false
	if w.Kind == "Deployment" {
		newRS := rsOfRevision(v, w, w.Revision)
		oldRS := rsOfRevision(v, w, pw.Revision)
		if oldRS == nil && d.prev != nil {
			oldRS = rsOfRevision(d.prev, pw, pw.Revision)
		}
		if newRS != nil {
			if len(newRS.Images) > 0 {
				newImgs = newRS.Images
			}
			if c := newRS.Created; !c.IsZero() && !c.After(now) && d.prev != nil && c.After(d.prev.Built.Add(-time.Minute)) {
				start = c // a fresh ReplicaSet: the rollout began when it was made
			}
		}
		if oldRS != nil && len(oldRS.Images) > 0 {
			oldImgs = oldRS.Images
		}
		rollback = newRS != nil && oldRS != nil && !newRS.Created.IsZero() && newRS.Created.Before(oldRS.Created)
	}
	diff := imageDiff(oldImgs, newImgs)
	verb := "rolled out revision " + w.Revision
	if rollback {
		verb = "rolled back to revision " + w.Revision
	}
	title := fmt.Sprintf("%s %s %s", w.Kind, w.Name, verb)
	if diff != "" {
		title += ": " + diff
	}
	attrs := map[string]string{"fromRevision": pw.Revision, "toRevision": w.Revision}
	if diff != "" {
		attrs["images"] = diff
	}
	if rollback {
		attrs["rollback"] = "true"
	}
	return Signal{ID: fmt.Sprintf("view:deploy:%s/%s/%s@%s", w.Kind, w.Namespace, w.Name, w.Revision), Type: TypeDeploy, Source: SourceView,
		Role: Context, Start: start, Subject: subj, Object: model.ObjectRef{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name, UID: w.UID},
		Title: title, Attrs: attrs}
}

func rsOfRevision(v *snapshot.View, w *model.Workload, revision string) *model.ReplicaSet {
	if revision == "" {
		return nil
	}
	for i := range v.Inv.ReplicaSets {
		rs := &v.Inv.ReplicaSets[i]
		if rs.Namespace != w.Namespace || rs.Revision != revision {
			continue
		}
		for _, o := range rs.Owners {
			if o.Controller && o.Kind == "Deployment" && o.Name == w.Name && (o.UID == "" || w.UID == "" || o.UID == w.UID) {
				return rs
			}
		}
	}
	return nil
}

// imageDiff describes how two image lists differ: "repo: v1 → v2" for a
// repository whose tag or digest changed, "+image" and "-image" otherwise.
func imageDiff(old, cur []string) string {
	repo := func(img string) string {
		if i := strings.IndexByte(img, '@'); i >= 0 {
			return img[:i]
		}
		if i := strings.LastIndexByte(img, ':'); i > strings.LastIndexByte(img, '/') {
			return img[:i]
		}
		return img
	}
	tag := func(img string) string { return strings.TrimPrefix(img[len(repo(img)):], ":") }
	oldSet, curSet := map[string]bool{}, map[string]bool{}
	for _, i := range old {
		oldSet[i] = true
	}
	for _, i := range cur {
		curSet[i] = true
	}
	oldByRepo := map[string]string{}
	for _, i := range old {
		if !curSet[i] {
			oldByRepo[repo(i)] = i
		}
	}
	var parts []string
	used := map[string]bool{}
	for _, i := range cur {
		if oldSet[i] {
			continue
		}
		if o, ok := oldByRepo[repo(i)]; ok && !used[o] {
			used[o] = true
			parts = append(parts, fmt.Sprintf("%s: %s → %s", repo(i), tag(o), tag(i)))
			continue
		}
		parts = append(parts, "+"+i)
	}
	for _, i := range old {
		if !curSet[i] && !used[i] {
			parts = append(parts, "-"+i)
		}
	}
	return strings.Join(parts, "; ")
}
