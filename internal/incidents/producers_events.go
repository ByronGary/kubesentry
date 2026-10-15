package incidents

import (
	"fmt"
	"slices"
	"sort"
	"strconv"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
	"github.com/ByronGary/kubesentry/internal/snapshot"
)

// Event reasons that become triggers: the first set once they occur
// EventMinCount times within EventWindow for one object, the second at once.
var (
	eventTriggerReasons = map[string]bool{
		"BackOff": true, "Unhealthy": true, "FailedScheduling": true, "FailedMount": true, "Failed": true,
		"FailedCreatePodSandBox": true, "FailedAttachVolume": true, "FailedKillPod": true,
	}
	eventImmediateReasons = map[string]Severity{"OOMKilling": Critical, "Evicted": Warning}
)

// EventsIngest resolves Kubernetes events to subjects, redacts and stores
// them, and turns them into k8s-event signals: triggers for the reasons
// above, context otherwise. Each new occurrence of an event series (its
// count went up) is one signal, so a series that recurs for days opens a
// new incident each time it flares up rather than stretching an old one.
type EventsIngest struct {
	o   Options
	red *Redactor

	last   map[string]seenCount // UID → count last seen
	recent map[string][]occ     // object + reason → occurrences within EventWindow
	normal map[string]bool
}

type seenCount struct {
	count int32
	at    time.Time
}

type occ struct {
	at time.Time
	n  int
}

// NewEventsIngest returns an ingester redacting with red.
func NewEventsIngest(o Options, red *Redactor) *EventsIngest {
	o.defaults()
	p := &EventsIngest{o: o, red: red, last: map[string]seenCount{}, recent: map[string][]occ{}, normal: map[string]bool{}}
	for _, r := range o.EventNormalReasons {
		p.normal[r] = true
	}
	return p
}

// Handle turns a batch into events to store and signals.
func (p *EventsIngest) Handle(v *snapshot.View, evs []model.KubeEvent, now time.Time) ([]StoredEvent, []Signal) {
	now = NormalTime(now)
	var stored []StoredEvent
	var sigs []Signal
	evs = slices.Clone(evs)
	sort.SliceStable(evs, func(i, j int) bool { return evs[i].LastSeen.Before(evs[j].LastSeen) })
	for _, ev := range evs {
		if ev.UID == "" || (ev.Type != "Warning" && !p.normal[ev.Reason]) {
			continue
		}
		ev.Message = p.red.String(cleanString(ev.Message, 1024))
		if ev.Count < 1 {
			ev.Count = 1
		}
		if ev.LastSeen.IsZero() {
			ev.LastSeen = ev.FirstSeen
		}
		if ev.LastSeen.IsZero() {
			ev.LastSeen = now
		}
		// A series that recurred for days keeps its first time; the store
		// partitions on it, so keep it within MaxRange of the last.
		if ev.FirstSeen.IsZero() || ev.LastSeen.Sub(ev.FirstSeen) > MaxRange {
			ev.FirstSeen = ev.LastSeen.Add(-MaxRange)
		}
		var subj *Subject
		if v != nil {
			if s, ok := EventSubject(v, ev); ok {
				subj = &s
			}
		}
		stored = append(stored, NormalizeEvent(StoredEvent{KubeEvent: ev, Subject: subj}))
		if s, ok := p.signal(ev, subj, now); ok {
			sigs = append(sigs, s)
		}
	}
	p.prune(now)
	return stored, sigs
}

func (p *EventsIngest) signal(ev model.KubeEvent, subj *Subject, now time.Time) (Signal, bool) {
	prev, known := p.last[ev.UID]
	p.last[ev.UID] = seenCount{count: ev.Count, at: now}
	var n int
	start := ev.LastSeen
	switch {
	case known:
		n = int(ev.Count - prev.count)
	default:
		// First seen: count the occurrences that fall in the window, as well
		// as a series' first and last time tell.
		span := ev.LastSeen.Sub(ev.FirstSeen)
		n = int(ev.Count)
		if span > p.o.Thresholds.EventWindow {
			n = max(1, int(float64(ev.Count)*float64(p.o.Thresholds.EventWindow)/float64(span)))
			start = ev.LastSeen.Add(-p.o.Thresholds.EventWindow)
		} else {
			start = ev.FirstSeen
		}
	}
	if n <= 0 || subj == nil {
		return Signal{}, false
	}
	key := ev.Regarding.Kind + "/" + ev.Regarding.Namespace + "/" + ev.Regarding.Name + "|" + ev.Reason
	p.recent[key] = append(p.recent[key], occ{at: ev.LastSeen, n: n})
	total := 0
	cut := now.Add(-p.o.Thresholds.EventWindow)
	for _, o := range p.recent[key] {
		if !o.at.Before(cut) {
			total += o.n
		}
	}
	s := Signal{ID: fmt.Sprintf("events:%s#%d", ev.UID, ev.Count), Type: TypeKubeEvent, Source: SourceEvents, Role: Context,
		Start: start, Subject: *subj, Object: ev.Regarding, Count: n,
		Title: ev.Reason + ": " + cleanString(ev.Message, 200),
		Attrs: map[string]string{"reason": ev.Reason, "type": ev.Type, "count": strconv.Itoa(int(ev.Count)), "component": ev.Source,
			"message": ev.Message, "uid": ev.UID}}
	if !ev.LastSeen.Equal(start) {
		s.End = timePtr(ev.LastSeen)
	}
	if sev, ok := eventImmediateReasons[ev.Reason]; ok {
		s.Role, s.Severity = Trigger, sev
	} else if eventTriggerReasons[ev.Reason] && total >= p.o.Thresholds.EventMinCount {
		s.Role, s.Severity = Trigger, Warning
	}
	return s, true
}

func (p *EventsIngest) prune(now time.Time) {
	cut := now.Add(-p.o.Thresholds.EventWindow)
	for k, os := range p.recent {
		kept := os[:0]
		for _, o := range os {
			if !o.at.Before(cut) {
				kept = append(kept, o)
			}
		}
		if len(kept) == 0 {
			delete(p.recent, k)
		} else {
			p.recent[k] = kept
		}
	}
	// Kubernetes keeps events an hour by default; remember series a while
	// longer so a re-list does not count them again.
	keep := now.Add(-3 * time.Hour)
	for uid, s := range p.last {
		if s.at.Before(keep) {
			delete(p.last, uid)
		}
	}
}

// EventSubject resolves the workload root an event is about: a pod's root,
// a workload's root, the Node itself, a Service's (first) root, the root of
// the pods mounting a claim, or the workload an autoscaler of the same name
// scales.
func EventSubject(v *snapshot.View, ev model.KubeEvent) (Subject, bool) {
	r := ev.Regarding
	ns := r.Namespace
	if ns == "" {
		ns = ev.Namespace
	}
	switch r.Kind {
	case "Pod":
		return SubjectOfPod(v, ns, r.Name)
	case "Node":
		return Subject{Kind: KindNode, Name: r.Name}, r.Name != ""
	case "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet":
		if s, ok := SubjectOfWorkload(v, r.Kind, ns, r.Name); ok || r.Kind != "ReplicaSet" {
			return s, r.Name != ""
		}
	case "Service":
		if ss := SubjectsOfService(v, ns, r.Name); len(ss) > 0 {
			return ss[0], true
		}
	case "PersistentVolumeClaim":
		for _, p := range v.Assoc().PodsIn(ns) {
			if livePod(p) && contains(p.Claims, r.Name) {
				return subjectOfPod(v.Assoc(), p), true
			}
		}
	case "HorizontalPodAutoscaler":
		for _, w := range indexOf(v).byName[[2]string{ns, r.Name}] {
			if w.Kind == "Deployment" || w.Kind == "StatefulSet" {
				return Subject{Kind: w.Kind, Namespace: ns, Name: w.Name}, true
			}
		}
	}
	return Subject{}, false
}
