package incidents

import (
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// IncidentID derives an incident's ID from its subject and start: the start
// time first (UTC, to the second), so IDs sort by time, then a hash of the
// subject and the exact start, so a new lease holder that rebuilds the same
// incident gives it the same ID.
func IncidentID(s Subject, start time.Time) string {
	start = NormalTime(start)
	h := sha256.Sum256([]byte(s.Kind + "\x00" + s.Namespace + "\x00" + s.Name + "\x00" + start.Format(time.RFC3339Nano)))
	return start.Format("20060102T150405Z") + "-" + hex.EncodeToString(h[:6])
}

// NormalTime is t as Postgres keeps a timestamptz: UTC, microseconds. Both
// stores, the engine and the board keep times this way.
func NormalTime(t time.Time) time.Time {
	if t.IsZero() {
		return time.Time{}
	}
	return t.UTC().Truncate(time.Microsecond)
}

func normalPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := NormalTime(*t)
	return &v
}

func timePtr(t time.Time) *time.Time { return &t }

func floatPtr(f float64) *float64 { return &f }

// conditionTypes last until they end: End nil means still active. Every
// other type is a point in time (End, when set, is its last occurrence).
var conditionTypes = map[string]bool{
	TypeRequestSpike: true, TypeErrorRate: true, TypeMemorySpike: true, TypeCrashLoop: true,
	TypeAlert: true, TypeLogErrors: true,
}

// IsCondition reports whether signals of this type last (a spike, a crash
// loop, an alert episode) rather than happen at one time.
func IsCondition(typ string) bool { return conditionTypes[typ] }

// lastAt is when s last held: its End, else its Start for a point signal.
// active is true for a condition still going on.
func (s *Signal) lastAt() (t time.Time, active bool) {
	if s.End != nil {
		return *s.End, false
	}
	if IsCondition(s.Type) {
		return time.Time{}, true
	}
	return s.Start, false
}

// coalesceKey groups point signals that coalesce: same type, object and
// reason or container.
func coalesceKey(s *Signal) string {
	return s.Type + "|" + string(s.Role) + "|" + s.Object.Kind + "/" + s.Object.Namespace + "/" + s.Object.Name +
		"|" + s.Attrs["reason"] + "|" + s.Attrs["container"]
}

// sevRank orders severities worst first; empty is least.
func sevRank(s Severity) int {
	switch s {
	case Critical:
		return 0
	case Warning:
		return 1
	}
	return 2
}

// cleanString makes s storable everywhere: valid UTF-8 without NUL bytes
// (Postgres refuses both), at most max bytes (0: no cap), cut on a rune
// boundary.
func cleanString(s string, max int) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	if strings.IndexByte(s, 0) >= 0 {
		s = strings.ReplaceAll(s, "\x00", "")
	}
	if max > 0 && len(s) > max {
		cut := max
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut]
	}
	return s
}

// cleanMap caps a tag or attribute map at MaxAttrs keys (the first in key
// order) of MaxAttrLen bytes; empty maps become nil.
func cleanMap(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make(map[string]string, min(len(keys), MaxAttrs))
	for _, k := range keys {
		if len(out) == MaxAttrs {
			break
		}
		ck := cleanString(k, MaxAttrLen)
		if ck == "" {
			continue
		}
		out[ck] = cleanString(m[k], MaxAttrLen)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// NormalizeSignal gives a signal the shape both stores keep: UTC times in
// microseconds, valid strings, capped tags and attributes, nil empty maps.
func NormalizeSignal(s Signal) Signal {
	s.ID = cleanString(s.ID, 512)
	s.Type = cleanString(s.Type, 64)
	s.Source = cleanString(s.Source, 64)
	s.Title = cleanString(s.Title, MaxAttrLen)
	s.Start = NormalTime(s.Start)
	s.End = normalPtr(s.End)
	if s.End != nil && s.End.Before(s.Start) {
		e := s.Start
		s.End = &e
	}
	if s.Role != Trigger {
		s.Severity = ""
	}
	s.Subject = cleanSubject(s.Subject)
	s.Object.Kind = cleanString(s.Object.Kind, 256)
	s.Object.Namespace = cleanString(s.Object.Namespace, 256)
	s.Object.Name = cleanString(s.Object.Name, 512)
	s.Object.UID = cleanString(s.Object.UID, 256)
	s.Value, s.Baseline, s.Threshold = finite(s.Value), finite(s.Baseline), finite(s.Threshold)
	if s.Count < 0 {
		s.Count = 0
	}
	s.Tags = cleanMap(s.Tags)
	s.Attrs = cleanMap(s.Attrs)
	return s
}

func cleanSubject(s Subject) Subject {
	return Subject{Kind: cleanString(s.Kind, 256), Namespace: cleanString(s.Namespace, 256), Name: cleanString(s.Name, 512)}
}

// finite drops NaN and infinities, which JSON and Postgres cannot keep.
func finite(f *float64) *float64 {
	if f == nil || *f != *f || *f > 1.7e308 || *f < -1.7e308 {
		return nil
	}
	v := *f
	return &v
}

// CloneSignal returns a deep copy.
func CloneSignal(s Signal) Signal {
	s.End = cloneTime(s.End)
	s.Value, s.Baseline, s.Threshold = cloneFloat(s.Value), cloneFloat(s.Baseline), cloneFloat(s.Threshold)
	s.Tags = maps.Clone(s.Tags)
	s.Attrs = maps.Clone(s.Attrs)
	return s
}

// CloneIncident returns a deep copy.
func CloneIncident(in Incident) Incident {
	in.End = cloneTime(in.End)
	in.Tags = maps.Clone(in.Tags)
	in.Services = slices.Clone(in.Services)
	in.Pods = slices.Clone(in.Pods)
	in.Nodes = slices.Clone(in.Nodes)
	in.Types = slices.Clone(in.Types)
	in.Counts = maps.Clone(in.Counts)
	return in
}

func cloneTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := *t
	return &v
}

func cloneFloat(f *float64) *float64 {
	if f == nil {
		return nil
	}
	v := *f
	return &v
}

// NormalizeIncident gives an incident the shape both stores keep: UTC times
// in microseconds, valid strings, nil empty lists and tags, non-nil Types
// and Counts (they are always in the JSON).
func NormalizeIncident(in Incident) Incident {
	in.ID = cleanString(in.ID, 128)
	in.Subject = cleanSubject(in.Subject)
	in.Title = cleanString(in.Title, MaxAttrLen)
	in.Start = NormalTime(in.Start)
	in.LastSignal = NormalTime(in.LastSignal)
	in.End = normalPtr(in.End)
	in.Previous = cleanString(in.Previous, 128)
	in.Owner = cleanString(in.Owner, 256)
	in.Tags = cleanMap(in.Tags)
	in.Services = cleanList(in.Services)
	in.Pods = cleanList(in.Pods)
	in.Nodes = cleanList(in.Nodes)
	in.Types = cleanList(in.Types)
	if in.Types == nil {
		in.Types = []string{}
	}
	counts := make(map[string]int, len(in.Counts))
	for k, v := range in.Counts {
		if k = cleanString(k, 64); k != "" {
			counts[k] = v
		}
	}
	in.Counts = counts
	return in
}

// cleanList sorts and deduplicates, caps at MaxListed and returns nil when
// empty.
func cleanList(l []string) []string {
	if len(l) == 0 {
		return nil
	}
	out := make([]string, 0, len(l))
	for _, s := range l {
		if s = cleanString(s, 512); s != "" {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	out = slices.Compact(out)
	if len(out) > MaxListed {
		out = out[:MaxListed]
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Newer reports whether a lists before b, newest first: the later start,
// then the larger ID (byte order, as Postgres compares with COLLATE "C").
func Newer(a, b *Incident) bool {
	if !a.Start.Equal(b.Start) {
		return a.Start.After(b.Start)
	}
	return a.ID > b.ID
}

// SortNewest sorts incidents newest first.
func SortNewest(ins []Incident) {
	sort.Slice(ins, func(i, j int) bool { return Newer(&ins[i], &ins[j]) })
}

// SortSignals sorts signals by start, then ID.
func SortSignals(sigs []Signal) {
	sort.Slice(sigs, func(i, j int) bool {
		if !sigs[i].Start.Equal(sigs[j].Start) {
			return sigs[i].Start.Before(sigs[j].Start)
		}
		return sigs[i].ID < sigs[j].ID
	})
}

// Matches reports whether in matches q, exactly as both stores evaluate it:
//
//   - From/To select incidents overlapping [From, To] (an open one has no end);
//   - Severity matches the peak severity: an incident that was critical stays
//     a critical incident;
//   - Types matches any of the types; Tags must all match; App matches the
//     display app (TagApp); Service any of Services;
//   - Namespaces nil admits every incident; otherwise a namespaced incident
//     must be in it, and one without a namespace needs ClusterScoped;
//   - Before admits incidents strictly after the cursor, newest first.
func (q Query) Matches(in *Incident) bool {
	if !q.To.IsZero() && in.Start.After(q.To) {
		return false
	}
	if !q.From.IsZero() && in.End != nil && in.End.Before(q.From) {
		return false
	}
	if q.Severity != "" && in.PeakSeverity != q.Severity {
		return false
	}
	if len(q.Types) > 0 {
		hit := false
		for _, t := range q.Types {
			if slices.Contains(in.Types, t) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	if q.State != "" && in.State != q.State {
		return false
	}
	if q.Namespaces != nil {
		if in.Subject.Namespace == "" {
			if !q.ClusterScoped {
				return false
			}
		} else if !q.Namespaces[in.Subject.Namespace] {
			return false
		}
	}
	if q.Owner != "" && in.Owner != q.Owner {
		return false
	}
	if q.App != "" && in.Tags[TagApp] != q.App {
		return false
	}
	if q.Service != "" && !slices.Contains(in.Services, q.Service) {
		return false
	}
	for k, v := range q.Tags {
		if got, ok := in.Tags[k]; !ok || got != v {
			return false
		}
	}
	if q.Before != nil {
		c := q.Before
		if in.Start.After(c.Start) || (in.Start.Equal(c.Start) && in.ID >= c.ID) {
			return false
		}
	}
	return true
}

// CursorOf is the keyset cursor after in.
func CursorOf(in *Incident) *Cursor { return &Cursor{Start: in.Start, ID: in.ID} }

// overlaps reports whether in's [Start, End] (End now while open) overlaps
// [from, to].
func overlaps(in *Incident, from, to, now time.Time) bool {
	end := now
	if in.End != nil {
		end = *in.End
	}
	return !in.Start.After(to) && !end.Before(from)
}
