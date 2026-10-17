package investigate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// schema is the small JSON Schema subset the tools and the report use:
// objects (closed: additionalProperties false), arrays, strings (enum,
// date-time), integers and booleans. It renders the JSON Schema sent to the
// model and validates what comes back, so both always agree.
type schema struct {
	Type        string
	Description string
	Props       []prop
	Required    []string
	Enum        []string
	Items       *schema
	Format      string // "date-time"
	// Limits. Validation enforces them on tool input; rendering includes
	// them only in non-strict schemas, since strict tools and structured
	// outputs do not take numeric or length constraints.
	MaxItems  int
	MaxLength int
	Min, Max  *int64
}

type prop struct {
	Name string
	S    *schema
}

func i64(v int64) *int64 { return &v }

// render returns the JSON Schema as a map (json.Marshal sorts its keys,
// so the bytes are stable and the cached prompt prefix with them).
func (s *schema) render(strict bool) map[string]any {
	m := map[string]any{"type": s.Type}
	if s.Description != "" {
		m["description"] = s.Description
	}
	switch s.Type {
	case "object":
		props := map[string]any{}
		for _, p := range s.Props {
			props[p.Name] = p.S.render(strict)
		}
		m["properties"] = props
		m["additionalProperties"] = false
		req := s.Required
		if req == nil {
			req = []string{}
		}
		m["required"] = req
	case "array":
		m["items"] = s.Items.render(strict)
		if !strict && s.MaxItems > 0 {
			m["maxItems"] = s.MaxItems
		}
	case "string":
		if len(s.Enum) > 0 {
			m["enum"] = s.Enum
		}
		if s.Format != "" {
			m["format"] = s.Format
		}
		if !strict && s.MaxLength > 0 {
			m["maxLength"] = s.MaxLength
		}
	case "integer":
		if !strict && s.Min != nil {
			m["minimum"] = *s.Min
		}
		if !strict && s.Max != nil {
			m["maximum"] = *s.Max
		}
	}
	return m
}

// JSON renders the schema.
func (s *schema) JSON(strict bool) json.RawMessage {
	b, err := json.Marshal(s.render(strict))
	if err != nil {
		panic(err) // static schemas
	}
	return b
}

// decodeJSON decodes one JSON value with numbers kept as json.Number and
// nothing after it.
func decodeJSON(raw []byte) (any, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, errors.New("empty input")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("not valid JSON: %s", cut(err.Error(), 120))
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("not valid JSON: data after the value")
	}
	return v, nil
}

// validationError lists what is wrong with a value, at most 8 problems.
type validationError []string

func (e validationError) Error() string { return strings.Join(e, "; ") }

// check validates raw against s. limits enforces MaxItems, MaxLength, Min
// and Max as errors (tool input); without it they are left to the caller
// (the report caps instead of refusing).
func (s *schema) check(raw []byte, limits bool) error {
	v, err := decodeJSON(raw)
	if err != nil {
		return err
	}
	var errs validationError
	s.validate(v, "", &errs, limits)
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func (s *schema) validate(v any, path string, errs *validationError, limits bool) {
	add := func(format string, a ...any) {
		if len(*errs) < 8 {
			p := path
			if p == "" {
				p = "input"
			}
			*errs = append(*errs, p+": "+fmt.Sprintf(format, a...))
		}
	}
	join := func(k string) string {
		if path == "" {
			return k
		}
		return path + "." + k
	}
	switch s.Type {
	case "object":
		m, ok := v.(map[string]any)
		if !ok {
			add("must be an object")
			return
		}
		known := map[string]*schema{}
		for _, p := range s.Props {
			known[p.Name] = p.S
		}
		var unknown []string
		for k := range m {
			if _, ok := known[k]; !ok {
				unknown = append(unknown, k)
			}
		}
		sort.Strings(unknown)
		for _, k := range unknown {
			add("unknown field %q", cut(clean(k), 40))
		}
		for _, r := range s.Required {
			if _, ok := m[r]; !ok {
				*errs = append(*errs, join(r)+": required")
			}
		}
		for _, p := range s.Props {
			if pv, ok := m[p.Name]; ok {
				p.S.validate(pv, join(p.Name), errs, limits)
			}
		}
	case "array":
		l, ok := v.([]any)
		if !ok {
			add("must be an array")
			return
		}
		if limits && s.MaxItems > 0 && len(l) > s.MaxItems {
			add("at most %d items", s.MaxItems)
		}
		for i, e := range l {
			s.Items.validate(e, fmt.Sprintf("%s[%d]", path, i), errs, limits)
		}
	case "string":
		str, ok := v.(string)
		if !ok {
			add("must be a string")
			return
		}
		if len(s.Enum) > 0 && !contains(s.Enum, str) {
			add("must be one of %s", strings.Join(s.Enum, ", "))
		}
		if limits && s.MaxLength > 0 && utf8.RuneCountInString(str) > s.MaxLength {
			add("at most %d characters", s.MaxLength)
		}
		if s.Format == "date-time" {
			if _, err := time.Parse(time.RFC3339, str); err != nil {
				add("must be an RFC 3339 time such as 2026-10-16T12:00:00Z")
			}
		}
	case "integer":
		n, ok := v.(json.Number)
		if !ok {
			add("must be an integer")
			return
		}
		i, err := n.Int64()
		if err != nil {
			add("must be an integer")
			return
		}
		if limits && s.Min != nil && i < *s.Min {
			add("at least %d", *s.Min)
		}
		if limits && s.Max != nil && i > *s.Max {
			add("at most %d", *s.Max)
		}
	case "boolean":
		if _, ok := v.(bool); !ok {
			add("must be true or false")
		}
	}
}

func contains(l []string, s string) bool {
	for _, e := range l {
		if e == s {
			return true
		}
	}
	return false
}
