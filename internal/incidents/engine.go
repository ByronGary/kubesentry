package incidents

import (
	"context"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/ByronGary/kubesentry/internal/snapshot"
)

// Engine turns signals into incidents. One engine runs on the lease holder
// for one leadership term: Load reads the open incidents (and the resolved
// ones still taking late context) from the store, Add and Tick change them
// in memory, and Flush commits the changes, then publishes them to the
// board. A failed commit publishes nothing and keeps the changes for the
// next Flush.
//
// The rules (see docs/contracts.md "Incidents"):
//
//   - Open: a trigger for a subject without an open incident opens one.
//   - Join: triggers join the open incident of their subject; context
//     signals join every incident of their subject whose window
//     [start-Lookbehind, end+LogLag] holds them (the end is now while
//     open), resolved ones included, and wait up to Lookbehind for one to
//     open. Namespace-level context joins every incident in the namespace,
//     cluster-level context every incident.
//   - Quiet close: no trigger active and the last one ended Quiet ago; the
//     incident ends when its last trigger did.
//   - Severity: the worst trigger active (a point trigger counts for Quiet
//     after it happened); the peak never decreases.
//   - Cap: at MaxRange the incident closes, capped, and continues in a new
//     one (Previous) carrying the conditions still active.
//   - Bounds: point signals of the same type and object coalesce by count
//     within CoalesceWithin; an incident keeps MaxSignals, then coalesces
//     harder, then only counts.
//
// It is not safe for concurrent use.
type Engine struct {
	o     Options
	store Store
	board *MemBoard

	view    *snapshot.View
	nsAllow map[string]bool

	tracked   map[string]*tracked  // open incidents, and resolved ones still taking late context
	open      map[Subject]string   // subject → its open incident
	bySubject map[Subject][]string // subject → tracked incidents
	homes     map[string][]string  // signal ID → incidents holding it (or a signal it coalesced into)
	alias     map[string]*alias    // incident ID + "\x00" + signal ID → where it coalesced
	seen      map[string]time.Time // incident ID + "\x00" + condition signal ID → last reported
	pending   []Signal             // context waiting for an incident, oldest first

	dirty   map[string]map[string]bool // incident ID → its changed signal IDs
	cps     map[string][]byte
	changed bool
	loaded  bool
}

type tracked struct {
	in      Incident
	sigs    map[string]*Signal
	dropped map[string]int // occurrences counted but not kept (MaxSignals)
	enrich  bool           // lists and tags need refreshing from the view
}

type alias struct {
	target string // the signal it coalesced into
	count  int    // its count as last added
}

// NewEngine returns an engine committing to store and publishing to board.
func NewEngine(store Store, board *MemBoard, o Options) *Engine {
	o.defaults()
	e := &Engine{o: o, store: store, board: board}
	if o.Namespaces != nil {
		e.nsAllow = map[string]bool{}
		for _, ns := range o.Namespaces {
			e.nsAllow[ns] = true
		}
	}
	e.reset()
	return e
}

func (e *Engine) reset() {
	e.tracked = map[string]*tracked{}
	e.open = map[Subject]string{}
	e.bySubject = map[Subject][]string{}
	e.homes = map[string][]string{}
	e.alias = map[string]*alias{}
	e.seen = map[string]time.Time{}
	e.pending = nil
	e.dirty = map[string]map[string]bool{}
	e.cps = map[string][]byte{}
	e.changed = false
}

// Options returns the engine's options, defaults applied.
func (e *Engine) Options() Options { return e.o }

// Load reads the open incidents with their signals, and the resolved ones
// whose window still takes late context, forgetting what the engine held.
func (e *Engine) Load(ctx context.Context) error {
	now := e.o.Now()
	open, sigs, err := e.store.LoadOpen(ctx)
	if err != nil {
		return fmt.Errorf("incidents: load open: %w", err)
	}
	e.reset()
	SortNewest(open)
	for i := len(open) - 1; i >= 0; i-- { // oldest first: the newest open one per subject wins
		e.track(NormalizeIncident(open[i]), sigs[open[i].ID], now)
	}
	late, err := e.store.List(ctx, Query{From: now.Add(-e.o.LogLag - e.o.LateWindow), State: Resolved, Limit: 5000})
	if err != nil {
		return fmt.Errorf("incidents: load resolved: %w", err)
	}
	for _, in := range late {
		if !e.takesLate(&in, now) {
			continue
		}
		got, ss, ok, err := e.store.Get(ctx, in.ID)
		if err != nil {
			return fmt.Errorf("incidents: load %s: %w", in.ID, err)
		}
		if ok {
			e.track(NormalizeIncident(got), ss, now)
		}
	}
	e.loaded = true
	return nil
}

// Loaded reports whether Load succeeded.
func (e *Engine) Loaded() bool { return e.loaded }

func (e *Engine) takesLate(in *Incident, now time.Time) bool {
	return in.End == nil || !in.End.Add(e.o.LogLag+e.o.LateWindow).Before(now)
}

func (e *Engine) track(in Incident, sigs []Signal, now time.Time) *tracked {
	t := &tracked{in: in, sigs: make(map[string]*Signal, len(sigs)), dropped: map[string]int{}}
	occ := map[string]int{}
	for _, s := range sigs {
		s := NormalizeSignal(s)
		t.sigs[s.ID] = &s
		e.homes[s.ID] = appendOnce(e.homes[s.ID], in.ID)
		if _, active := s.lastAt(); active {
			e.seen[in.ID+"\x00"+s.ID] = now
		}
		occ[s.Type] += max(1, s.Count)
	}
	for typ, n := range in.Counts {
		if d := n - occ[typ]; d > 0 {
			t.dropped[typ] = d
		}
	}
	e.tracked[in.ID] = t
	e.bySubject[in.Subject] = appendOnce(e.bySubject[in.Subject], in.ID)
	if in.State == Open {
		e.open[in.Subject] = in.ID
	}
	return t
}

func appendOnce(l []string, s string) []string {
	if slices.Contains(l, s) {
		return l
	}
	return append(l, s)
}

// SetView gives the engine the current view: it maps namespaces to owners
// and the system set, and subjects to their pods, nodes, Services and tags.
func (e *Engine) SetView(v *snapshot.View) {
	if v == nil || v == e.view {
		return
	}
	e.view = v
	for _, id := range e.open {
		e.tracked[id].enrich = true
	}
}

// SetCheckpoint records a poller's position, committed with the next Flush.
func (e *Engine) SetCheckpoint(source string, pos []byte) {
	e.cps[source] = slices.Clone(pos)
}

// Changed reports whether an incident opened, resolved or changed severity
// since the last Flush: the runner commits such changes at once.
func (e *Engine) Changed() bool { return e.changed }

// Dirty reports whether anything waits to be committed.
func (e *Engine) Dirty() bool { return len(e.dirty) > 0 || len(e.cps) > 0 }

// Open returns copies of the open incidents, newest first.
func (e *Engine) Open() []Incident {
	out := make([]Incident, 0, len(e.open))
	for _, id := range e.open {
		out = append(out, CloneIncident(e.tracked[id].in))
	}
	SortNewest(out)
	return out
}

// Incident returns a tracked incident and its signals (sorted).
func (e *Engine) Incident(id string) (Incident, []Signal, bool) {
	t := e.tracked[id]
	if t == nil {
		return Incident{}, nil, false
	}
	return CloneIncident(t.in), t.signalList(), true
}

func (t *tracked) signalList() []Signal {
	out := make([]Signal, 0, len(t.sigs))
	for _, s := range t.sigs {
		out = append(out, CloneSignal(*s))
	}
	SortSignals(out)
	return out
}

// Active returns the conditions from source still active in open
// incidents, so a producer starting a leadership term resumes them (and
// ends them) instead of starting new ones.
func (e *Engine) Active(source string) []Signal {
	var out []Signal
	seen := map[string]bool{}
	for _, id := range e.open {
		for _, s := range e.tracked[id].sigs {
			if _, active := s.lastAt(); active && s.Source == source && !seen[s.ID] {
				seen[s.ID] = true
				out = append(out, CloneSignal(*s))
			}
		}
	}
	SortSignals(out)
	return out
}

// Add applies signals at the engine's clock.
func (e *Engine) Add(sigs ...Signal) {
	now := NormalTime(e.o.Now())
	for _, s := range sigs {
		s = NormalizeSignal(s)
		if s.ID == "" || s.Type == "" || s.Start.IsZero() || s.Subject.Name == "" || !e.admit(&s) {
			continue
		}
		if s.Subject.Kind == KindNamespace || s.Subject.Kind == KindCluster {
			s.Role, s.Severity = Context, "" // only context is that wide
		}
		if s.Role == Trigger {
			if s.Severity == "" {
				s.Severity = Warning
			}
			e.addTrigger(s, now)
		} else {
			s.Role = Context
			e.addContext(s, now)
		}
	}
}

func (e *Engine) admit(s *Signal) bool {
	ns := s.Subject.Namespace
	if s.Subject.Kind == KindNamespace {
		ns = s.Subject.Name
	}
	if ns == "" {
		return true
	}
	if e.nsAllow != nil && !e.nsAllow[ns] {
		return false
	}
	if !e.o.IncludeSystem && e.view != nil && e.view.Assoc().IsSystem(ns) {
		return false
	}
	return true
}

func (e *Engine) addTrigger(s Signal, now time.Time) {
	if e.mergeHomes(s, now) {
		return
	}
	if id, ok := e.open[s.Subject]; ok {
		e.attach(e.tracked[id], s, now)
		return
	}
	// A late trigger from before a resolved incident of its subject ended
	// belongs to it, and reopens it if it lasted longer.
	for _, id := range e.bySubject[s.Subject] {
		t := e.tracked[id]
		if t.in.State != Resolved || t.in.Capped || t.in.End == nil || !s.Start.Before(*t.in.End) || s.Start.Before(t.in.Start) {
			continue
		}
		e.attach(t, s, now)
		e.maybeReopen(t, s)
		return
	}
	start := s.Start
	if floor := now.Add(-e.o.MaxRange / 2); start.Before(floor) {
		start = floor // a trigger from long ago (a standing alert) opens a recent incident
	}
	t := e.newIncident(s.Subject, start, "", now)
	e.attach(t, s, now)
	e.attachPending(t, now)
}

// mergeHomes updates s where it already is; false when it is nowhere.
func (e *Engine) mergeHomes(s Signal, now time.Time) bool {
	homes := e.homes[s.ID]
	if len(homes) == 0 {
		return false
	}
	merged := false
	for _, id := range slices.Clone(homes) {
		t := e.tracked[id]
		if t == nil {
			continue
		}
		if s.Role == Trigger && t.in.State == Resolved {
			if id, ok := e.open[t.in.Subject]; ok && id != t.in.ID {
				continue // the subject has a newer open incident: the trigger joins that one
			}
		}
		merged = true
		if t.in.Capped && IsCondition(s.Type) {
			continue // a capped incident keeps its conditions as they were at the cap
		}
		e.attach(t, s, now)
		if s.Role == Trigger {
			e.maybeReopen(t, s)
		}
	}
	return merged
}

// maybeReopen reopens a resolved incident a late trigger extends past its
// end, unless its subject has another open incident.
func (e *Engine) maybeReopen(t *tracked, s Signal) {
	if t.in.State != Resolved || t.in.Capped || t.in.End == nil {
		return
	}
	if _, ok := e.open[t.in.Subject]; ok {
		return
	}
	cur := t.sigs[s.ID]
	if cur == nil || cur.Role != Trigger {
		return
	}
	// A point trigger reopens only if it came within Quiet of the end: had it
	// arrived in time, the incident would not have resolved.
	if end, active := cur.lastAt(); !active && (!end.After(*t.in.End) || end.Sub(*t.in.End) >= e.o.Quiet) {
		return
	}
	t.in.State, t.in.End = Open, nil
	e.open[t.in.Subject] = t.in.ID
	t.enrich = true
	e.changed = true
	e.markIncident(t)
}

func (e *Engine) addContext(s Signal, now time.Time) {
	e.mergeHomes(s, now)
	for _, t := range e.candidates(s.Subject) {
		if t.sigs[s.ID] != nil || e.alias[t.in.ID+"\x00"+s.ID] != nil {
			continue
		}
		if e.inWindow(t, s.Start, now) {
			e.attach(t, s, now)
		}
	}
	e.addPending(s, now)
}

// candidates are the tracked incidents a context signal about subject may
// join, in ID order.
func (e *Engine) candidates(subject Subject) []*tracked {
	var out []*tracked
	switch subject.Kind {
	case KindNamespace, KindCluster:
		for _, t := range e.tracked {
			if subject.Kind == KindCluster || t.in.Subject.Namespace == subject.Name {
				out = append(out, t)
			}
		}
	default:
		for _, id := range e.bySubject[subject] {
			out = append(out, e.tracked[id])
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].in.ID < out[j].in.ID })
	return out
}

func (e *Engine) inWindow(t *tracked, at, now time.Time) bool {
	end := now
	if t.in.End != nil {
		end = *t.in.End
	}
	return !at.Before(t.in.Start.Add(-e.o.Lookbehind)) && !at.After(end.Add(e.o.LogLag))
}

func (e *Engine) addPending(s Signal, now time.Time) {
	if s.Start.Before(now.Add(-e.o.Lookbehind)) {
		return
	}
	for i := range e.pending {
		if e.pending[i].ID == s.ID && e.pending[i].Subject == s.Subject {
			e.pending[i] = s
			return
		}
	}
	e.pending = append(e.pending, s)
	if over := len(e.pending) - e.o.MaxPending; over > 0 {
		e.pending = append([]Signal(nil), e.pending[over:]...)
	}
}

// attachPending gives a new incident the context that came before it.
func (e *Engine) attachPending(t *tracked, now time.Time) {
	for _, p := range e.pending {
		match := p.Subject == t.in.Subject ||
			(p.Subject.Kind == KindNamespace && p.Subject.Name == t.in.Subject.Namespace && t.in.Subject.Namespace != "") ||
			p.Subject.Kind == KindCluster
		if match && t.sigs[p.ID] == nil && e.inWindow(t, p.Start, now) {
			e.attach(t, p, now)
		}
	}
}

func (e *Engine) newIncident(subject Subject, start time.Time, previous string, now time.Time) *tracked {
	start = NormalTime(start)
	id := IncidentID(subject, start)
	if t := e.tracked[id]; t != nil { // the same incident again: reopen it
		if t.in.State == Resolved {
			t.in.State, t.in.End, t.in.Capped = Open, nil, false
			e.open[subject] = id
			e.changed = true
			e.markIncident(t)
		}
		return t
	}
	t := e.track(Incident{ID: id, Subject: subject, State: Open, Start: start, LastSignal: start, Previous: previous,
		Types: []string{}, Counts: map[string]int{}}, nil, now)
	t.enrich = true
	e.changed = true
	e.markIncident(t)
	return t
}

// attach adds s to t, or merges it into the signal it is (or coalesced
// into), and recomputes t.
func (e *Engine) attach(t *tracked, s Signal, now time.Time) {
	key := t.in.ID + "\x00" + s.ID
	if a := e.alias[key]; a != nil {
		if tgt := t.sigs[a.target]; tgt != nil {
			n := max(1, s.Count)
			if d := n - a.count; d > 0 {
				tgt.Count += d
				a.count = n
			}
			extendEnd(tgt, &s)
			e.markSignal(t, tgt.ID)
			e.recompute(t, now)
			return
		}
		delete(e.alias, key)
	}
	if cur := t.sigs[s.ID]; cur != nil {
		before := CloneSignal(*cur)
		mergeSignal(cur, &s)
		if IsCondition(cur.Type) {
			e.seen[key] = now
		}
		if !reflect.DeepEqual(before, *cur) {
			e.markSignal(t, cur.ID)
			e.recompute(t, now)
		}
		return
	}
	if !IsCondition(s.Type) {
		if tgt := e.coalesceTarget(t, &s, false); tgt != nil {
			e.coalesce(t, tgt, &s, now)
			return
		}
	}
	if len(t.sigs) >= e.o.MaxSignals {
		if tgt := e.coalesceTarget(t, &s, true); tgt != nil {
			e.coalesce(t, tgt, &s, now)
			return
		}
		t.dropped[s.Type] += max(1, s.Count)
		e.markIncident(t)
		e.recompute(t, now)
		return
	}
	c := CloneSignal(s)
	t.sigs[s.ID] = &c
	e.homes[s.ID] = appendOnce(e.homes[s.ID], t.in.ID)
	if IsCondition(s.Type) {
		e.seen[key] = now
	}
	t.enrich = true
	e.markSignal(t, s.ID)
	e.recompute(t, now)
}

// coalesceTarget finds the signal s coalesces into: a point signal with the
// same type, role, object and reason that started within CoalesceWithin;
// when the incident is full (overflow), any such signal, else any signal of
// the same type and role.
func (e *Engine) coalesceTarget(t *tracked, s *Signal, overflow bool) *Signal {
	key := coalesceKey(s)
	var best, sameType *Signal
	for _, x := range t.sigs {
		if IsCondition(x.Type) || x.Type != s.Type || x.Role != s.Role {
			continue
		}
		if sameType == nil || x.Start.After(sameType.Start) || (x.Start.Equal(sameType.Start) && x.ID > sameType.ID) {
			sameType = x
		}
		if coalesceKey(x) != key {
			continue
		}
		if !overflow {
			d := s.Start.Sub(x.Start)
			if d < 0 {
				d = -d
			}
			if d >= CoalesceWithin {
				continue
			}
		}
		if best == nil || x.Start.After(best.Start) || (x.Start.Equal(best.Start) && x.ID > best.ID) {
			best = x
		}
	}
	if best == nil && overflow && !IsCondition(s.Type) {
		return sameType
	}
	return best
}

func (e *Engine) coalesce(t *tracked, tgt *Signal, s *Signal, now time.Time) {
	n := max(1, s.Count)
	tgt.Count = max(1, tgt.Count) + n
	extendEnd(tgt, s)
	if s.Role == Trigger && sevRank(s.Severity) < sevRank(tgt.Severity) {
		tgt.Severity = s.Severity
	}
	e.alias[t.in.ID+"\x00"+s.ID] = &alias{target: tgt.ID, count: n}
	e.homes[s.ID] = appendOnce(e.homes[s.ID], t.in.ID)
	e.markSignal(t, tgt.ID)
	e.recompute(t, now)
}

// extendEnd moves a point signal's last occurrence to s's when later.
func extendEnd(dst, s *Signal) {
	last, _ := s.lastAt()
	if last.IsZero() {
		last = s.Start
	}
	cur, _ := dst.lastAt()
	if last.After(cur) {
		dst.End = timePtr(last)
	}
}

// mergeSignal folds a new report of the same signal into dst. Its start
// never changes; a condition's end follows the latest report, a point
// signal's last occurrence only moves later; a context signal can become a
// trigger but not back.
func mergeSignal(dst, src *Signal) {
	switch {
	case IsCondition(dst.Type):
		dst.End = cloneTime(src.End)
	case src.End != nil && (dst.End == nil || src.End.After(*dst.End)):
		dst.End = cloneTime(src.End)
	}
	if src.Role == Trigger {
		dst.Role = Trigger
		if src.Severity != "" {
			dst.Severity = src.Severity
		}
	}
	if src.Title != "" {
		dst.Title = src.Title
	}
	if src.Value != nil {
		dst.Value = cloneFloat(src.Value)
	}
	if src.Baseline != nil {
		dst.Baseline = cloneFloat(src.Baseline)
	}
	if src.Threshold != nil {
		dst.Threshold = cloneFloat(src.Threshold)
	}
	if src.Count > dst.Count {
		dst.Count = src.Count
	}
	if src.Tags != nil {
		dst.Tags = maps.Clone(src.Tags)
	}
	if src.Attrs != nil {
		dst.Attrs = maps.Clone(src.Attrs)
	}
}

func (e *Engine) markIncident(t *tracked) {
	if e.dirty[t.in.ID] == nil {
		e.dirty[t.in.ID] = map[string]bool{}
	}
}

func (e *Engine) markSignal(t *tracked, id string) {
	e.markIncident(t)
	e.dirty[t.in.ID][id] = true
}

// recompute derives types, counts, last signal, severity and title.
func (e *Engine) recompute(t *tracked, now time.Time) {
	in := &t.in
	old := CloneIncident(*in)
	counts := map[string]int{}
	var last time.Time
	var worst, peak Severity
	for _, s := range t.sigs {
		counts[s.Type] += max(1, s.Count)
		at := s.Start
		if s.End != nil && s.End.After(at) {
			at = *s.End
		}
		if at.After(last) {
			last = at
		}
		if s.Role != Trigger {
			continue
		}
		if peak == "" || sevRank(s.Severity) < sevRank(peak) {
			peak = s.Severity
		}
		end, active := s.lastAt()
		if active || now.Sub(end) < e.o.Quiet {
			if worst == "" || sevRank(s.Severity) < sevRank(worst) {
				worst = s.Severity
			}
		}
	}
	for typ, n := range t.dropped {
		counts[typ] += n
	}
	types := make([]string, 0, len(counts))
	for typ := range counts {
		types = append(types, typ)
	}
	sort.Strings(types)
	in.Types, in.Counts = types, counts
	if last.After(in.LastSignal) {
		in.LastSignal = last
	}
	if worst != "" && in.State == Open {
		in.Severity = worst
	}
	if in.Severity == "" {
		in.Severity = Warning
	}
	for _, s := range []Severity{in.Severity, peak} {
		if s != "" && (in.PeakSeverity == "" || sevRank(s) < sevRank(in.PeakSeverity)) {
			in.PeakSeverity = s
		}
	}
	in.Title = title(t)
	if !reflect.DeepEqual(old, *in) {
		e.markIncident(t)
		if old.Severity != in.Severity || old.State != in.State {
			e.changed = true
		}
	}
}

// typeOrder ranks trigger types in titles: the most telling first.
var typeOrder = []string{TypeOOMKill, TypeCrashLoop, TypeMemorySpike, TypeRequestSpike, TypeErrorRate, TypeEviction,
	TypeRestart, TypeAlert, TypeKubeEvent}

var typeLabels = map[string]string{
	TypeRequestSpike: "request spike", TypeErrorRate: "error rate", TypeMemorySpike: "memory spike", TypeOOMKill: "OOM kill",
	TypeRestart: "restarts", TypeCrashLoop: "crash loop", TypeEviction: "eviction", TypeKubeEvent: "warning events",
	TypeAlert: "alert", TypeDeploy: "deploy", TypeScale: "scale", TypeAuditChange: "change", TypeCloudTrailChange: "AWS change",
	TypeLogErrors: "error logs",
}

// TypeLabel is a signal type in words ("request spike").
func TypeLabel(typ string) string {
	if l, ok := typeLabels[typ]; ok {
		return l
	}
	return typ
}

func title(t *tracked) string {
	name := t.in.Tags[TagApp]
	if name == "" {
		name = t.in.Subject.Name
	}
	have := map[string]bool{}
	for _, s := range t.sigs {
		if s.Role == Trigger {
			have[s.Type] = true
		}
	}
	var labels []string
	for _, typ := range typeOrder {
		if have[typ] {
			labels = append(labels, TypeLabel(typ))
			delete(have, typ)
		}
	}
	rest := make([]string, 0, len(have))
	for typ := range have {
		rest = append(rest, typ)
	}
	sort.Strings(rest)
	for _, typ := range rest {
		labels = append(labels, TypeLabel(typ))
	}
	if len(labels) == 0 {
		return name
	}
	if len(labels) > 3 {
		return fmt.Sprintf("%s: %s and %d more", name, strings.Join(labels[:3], ", "), len(labels)-3)
	}
	return name + ": " + strings.Join(labels, ", ")
}

// Tick applies the rules that depend on time alone: conditions nobody
// reported for StaleAfter end, quiet incidents resolve, incidents reaching
// MaxRange are capped and continue, and resolved incidents past their late
// window are forgotten (they stay on the board and in the store).
func (e *Engine) Tick() {
	now := NormalTime(e.o.Now())
	ids := make([]string, 0, len(e.open))
	for _, id := range e.open {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		t := e.tracked[id]
		e.expireStale(t, now)
		if t.enrich {
			e.enrich(t)
		}
		e.recompute(t, now)
		for t != nil && t.in.State == Open {
			if e.quietEnd(t, now) {
				break
			}
			if now.Sub(t.in.Start) < e.o.MaxRange {
				break
			}
			t = e.split(t, now)
		}
	}
	for id, t := range e.tracked {
		if t.in.State == Resolved && !e.takesLate(&t.in, now) && e.dirty[id] == nil {
			e.forget(t)
		}
	}
	cut := now.Add(-e.o.Lookbehind)
	keep := e.pending[:0]
	for _, p := range e.pending {
		if !p.Start.Before(cut) {
			keep = append(keep, p)
		}
	}
	clear(e.pending[len(keep):])
	e.pending = keep
}

// expireStale ends the conditions of t nobody reported for StaleAfter.
func (e *Engine) expireStale(t *tracked, now time.Time) {
	for _, s := range t.sigs {
		if _, active := s.lastAt(); !active {
			continue
		}
		key := t.in.ID + "\x00" + s.ID
		last, ok := e.seen[key]
		if !ok {
			e.seen[key] = now
			continue
		}
		if now.Sub(last) >= e.o.StaleAfter {
			end := last
			if end.Before(s.Start) {
				end = s.Start
			}
			s.End = timePtr(end)
			delete(e.seen, key)
			e.markSignal(t, s.ID)
		}
	}
}

// quietEnd resolves t when no trigger is active and the last one ended
// Quiet ago; the incident ends when its last trigger did.
func (e *Engine) quietEnd(t *tracked, now time.Time) bool {
	var last time.Time
	for _, s := range t.sigs {
		if s.Role != Trigger {
			continue
		}
		end, active := s.lastAt()
		if active {
			return false
		}
		if end.After(last) {
			last = end
		}
	}
	if last.Before(t.in.Start) {
		last = t.in.Start
	}
	if now.Sub(last) < e.o.Quiet {
		return false
	}
	if capAt := t.in.Start.Add(e.o.MaxRange); last.After(capAt) {
		last = capAt
	}
	e.resolve(t, last, false)
	return true
}

func (e *Engine) resolve(t *tracked, end time.Time, capped bool) {
	t.in.State, t.in.End, t.in.Capped = Resolved, timePtr(end), capped
	if e.open[t.in.Subject] == t.in.ID {
		delete(e.open, t.in.Subject)
	}
	e.changed = true
	e.markIncident(t)
}

// split caps t at MaxRange and continues it in a new incident that carries
// the conditions still active.
func (e *Engine) split(t *tracked, now time.Time) *tracked {
	capAt := t.in.Start.Add(e.o.MaxRange)
	var carry []Signal
	ids := make([]string, 0, len(t.sigs))
	for id := range t.sigs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		s := t.sigs[id]
		if _, active := s.lastAt(); !active {
			continue
		}
		c := CloneSignal(*s)
		if c.Start.Before(capAt) {
			c.Start = capAt
		}
		carry = append(carry, c)
		s.End = timePtr(capAt)
		delete(e.seen, t.in.ID+"\x00"+s.ID)
		e.markSignal(t, s.ID)
	}
	e.resolve(t, capAt, true)
	e.recompute(t, now)
	n := e.newIncident(t.in.Subject, capAt, t.in.ID, now)
	if n.in.Severity == "" {
		n.in.Severity, n.in.PeakSeverity = t.in.Severity, t.in.Severity
	}
	n.in.Owner, n.in.Production, n.in.Tags = t.in.Owner, t.in.Production, maps.Clone(t.in.Tags)
	n.in.Services, n.in.Pods, n.in.Nodes = slices.Clone(t.in.Services), slices.Clone(t.in.Pods), slices.Clone(t.in.Nodes)
	for _, c := range carry {
		e.attach(n, c, now)
	}
	e.recompute(n, now)
	return n
}

func (e *Engine) forget(t *tracked) {
	id := t.in.ID
	delete(e.tracked, id)
	if e.open[t.in.Subject] == id {
		delete(e.open, t.in.Subject)
	}
	e.bySubject[t.in.Subject] = slices.DeleteFunc(e.bySubject[t.in.Subject], func(x string) bool { return x == id })
	if len(e.bySubject[t.in.Subject]) == 0 {
		delete(e.bySubject, t.in.Subject)
	}
	for sid, homes := range e.homes {
		if slices.Contains(homes, id) {
			homes = slices.DeleteFunc(homes, func(x string) bool { return x == id })
			if len(homes) == 0 {
				delete(e.homes, sid)
			} else {
				e.homes[sid] = homes
			}
		}
	}
	prefix := id + "\x00"
	for k := range e.alias {
		if strings.HasPrefix(k, prefix) {
			delete(e.alias, k)
		}
	}
	for k := range e.seen {
		if strings.HasPrefix(k, prefix) {
			delete(e.seen, k)
		}
	}
}

// Flush commits what changed (with the pollers' checkpoints) and, once the
// commit succeeded, publishes it to the board. On failure nothing is
// published and the changes wait for the next Flush.
func (e *Engine) Flush(ctx context.Context) error {
	if !e.Dirty() {
		e.changed = false
		return nil
	}
	now := NormalTime(e.o.Now())
	ids := make([]string, 0, len(e.dirty))
	for id := range e.dirty {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	c := Commit{Signals: map[string][]Signal{}}
	for _, id := range ids {
		t := e.tracked[id]
		if t == nil {
			continue
		}
		if t.enrich {
			e.enrich(t)
			e.recompute(t, now)
		}
		c.Incidents = append(c.Incidents, NormalizeIncident(CloneIncident(t.in)))
		sids := make([]string, 0, len(e.dirty[id]))
		for sid := range e.dirty[id] {
			sids = append(sids, sid)
		}
		sort.Strings(sids)
		for _, sid := range sids {
			if s := t.sigs[sid]; s != nil {
				c.Signals[id] = append(c.Signals[id], NormalizeSignal(CloneSignal(*s)))
			}
		}
	}
	if len(e.cps) > 0 {
		c.Checkpoints = make(map[string][]byte, len(e.cps))
		for k, v := range e.cps {
			c.Checkpoints[k] = slices.Clone(v)
		}
	}
	if err := e.store.Commit(ctx, c); err != nil {
		return fmt.Errorf("incidents: commit: %w", err)
	}
	if e.board != nil && len(c.Incidents) > 0 {
		e.board.Apply(c.Incidents, c.Signals, now)
	}
	e.dirty = map[string]map[string]bool{}
	e.cps = map[string][]byte{}
	e.changed = false
	return nil
}
