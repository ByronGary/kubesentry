package settings

import (
	"strconv"
	"time"
)

// Sources of a value.
const (
	SourceHelm = "helm" // the flags, as the Helm chart sets them
	SourceUI   = "ui"   // saved by an admin on the Settings page
)

// Source says where a value comes from, and for one changed in the UI who
// changed it and when.
type Source struct {
	Source string     `json:"source"`
	By     string     `json:"by,omitempty"`
	At     *time.Time `json:"at,omitempty"`
}

// Mark is who last changed a field in the UI, and when.
type Mark struct {
	By string    `json:"by"`
	At time.Time `json:"at"`
}

// Stored is what the store keeps: the values saved, and the fields that
// override the flags with who changed each. Fields not listed follow the
// flags, so a Helm upgrade still changes them.
type Stored struct {
	Values Investigator    `json:"values"`
	Fields map[string]Mark `json:"fields"`
}

// field is one setting: its name (as FieldError and Change name it), its
// value as text, and how to copy it.
type field struct {
	name string
	text func(*Investigator) string
	copy func(dst, src *Investigator)
}

var fields = []field{
	{"enabled", func(i *Investigator) string { return strconv.FormatBool(i.Enabled) }, func(d, s *Investigator) { d.Enabled = s.Enabled }},
	{"provider", func(i *Investigator) string { return i.Provider }, func(d, s *Investigator) { d.Provider = s.Provider }},
	{"model", func(i *Investigator) string { return i.Model }, func(d, s *Investigator) { d.Model = s.Model }},
	{"effort", func(i *Investigator) string { return i.Effort }, func(d, s *Investigator) { d.Effort = s.Effort }},
	{"region", func(i *Investigator) string { return i.Region }, func(d, s *Investigator) { d.Region = s.Region }},
	{"bedrockAPI", func(i *Investigator) string { return i.BedrockAPI }, func(d, s *Investigator) { d.BedrockAPI = s.BedrockAPI }},
	{"endpoint", func(i *Investigator) string { return i.Endpoint }, func(d, s *Investigator) { d.Endpoint = s.Endpoint }},
	{"fallback", func(i *Investigator) string { return i.Fallback }, func(d, s *Investigator) { d.Fallback = s.Fallback }},
	{"limits.perHour", func(i *Investigator) string { return strconv.Itoa(i.Limits.PerHour) },
		func(d, s *Investigator) { d.Limits.PerHour = s.Limits.PerHour }},
	{"limits.perHourTotal", func(i *Investigator) string { return strconv.Itoa(i.Limits.PerHourTotal) },
		func(d, s *Investigator) { d.Limits.PerHourTotal = s.Limits.PerHourTotal }},
	{"limits.concurrency", func(i *Investigator) string { return strconv.Itoa(i.Limits.Concurrency) },
		func(d, s *Investigator) { d.Limits.Concurrency = s.Limits.Concurrency }},
	{"limits.maxTurns", func(i *Investigator) string { return strconv.Itoa(i.Limits.MaxTurns) },
		func(d, s *Investigator) { d.Limits.MaxTurns = s.Limits.MaxTurns }},
	{"limits.maxToolCalls", func(i *Investigator) string { return strconv.Itoa(i.Limits.MaxToolCalls) },
		func(d, s *Investigator) { d.Limits.MaxToolCalls = s.Limits.MaxToolCalls }},
	{"limits.maxTokens", func(i *Investigator) string { return strconv.FormatInt(i.Limits.MaxTokens, 10) },
		func(d, s *Investigator) { d.Limits.MaxTokens = s.Limits.MaxTokens }},
	{"limits.timeout", func(i *Investigator) string { return i.Limits.Timeout.String() },
		func(d, s *Investigator) { d.Limits.Timeout = s.Limits.Timeout }},
}

// Fields names every setting, in the order the page shows them.
func Fields() []string {
	out := make([]string, len(fields))
	for i, f := range fields {
		out[i] = f.name
	}
	return out
}

// Change is one field changed: old → new, as text.
type Change struct {
	Field string `json:"field"`
	Old   string `json:"old"`
	New   string `json:"new"`
}

// Effective is the settings in force: the flags (helm), with the fields
// st overrides taken from st; and where each value comes from. A nil st
// (nothing saved, a reset, or locked mode) is the flags alone.
func Effective(helm Investigator, st *Stored) (Investigator, map[string]Source) {
	out := helm
	src := make(map[string]Source, len(fields))
	for _, f := range fields {
		src[f.name] = Source{Source: SourceHelm}
		if st == nil {
			continue
		}
		if m, ok := st.Fields[f.name]; ok {
			f.copy(&out, &st.Values)
			at := m.At
			src[f.name] = Source{Source: SourceUI, By: m.By, At: &at}
		}
	}
	return out, src
}

// Changes lists the fields whose values differ between a and b.
func Changes(a, b Investigator) []Change {
	var out []Change
	for _, f := range fields {
		if o, n := f.text(&a), f.text(&b); o != n {
			out = append(out, Change{Field: f.name, Old: o, New: n})
		}
	}
	return out
}

// Save is what saving next on top of st does: the new stored settings and
// the changes to the settings in force. A field equal to its flag value
// follows the flags again; a field that differs overrides them, keeping its
// earlier mark when its value did not change.
func Save(helm Investigator, st *Stored, next Investigator, actor string, now time.Time) (*Stored, []Change) {
	cur, _ := Effective(helm, st)
	out := &Stored{Values: next, Fields: map[string]Mark{}}
	for _, f := range fields {
		n := f.text(&next)
		if n == f.text(&helm) {
			continue
		}
		mark := Mark{By: actor, At: now.UTC()}
		if st != nil && n == f.text(&cur) {
			if m, ok := st.Fields[f.name]; ok {
				mark = m
			}
		}
		out.Fields[f.name] = mark
	}
	return out, Changes(cur, next)
}

// Reset is what "reset to Helm values" does: nothing overrides the flags.
func Reset(helm Investigator, st *Stored) (*Stored, []Change) {
	cur, _ := Effective(helm, st)
	return &Stored{Values: helm, Fields: map[string]Mark{}}, Changes(cur, helm)
}
