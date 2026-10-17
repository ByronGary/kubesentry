package investigate

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ByronGary/kubesentry/internal/incidents"
)

// Egress is the single choke point for text leaving for the model: the
// digest, every tool result and the report's text all pass through it. It
// strips control and format characters (bidi overrides, zero-width
// characters), redacts secrets (the incidents redactor, so
// -incident-redact-patterns apply, plus Egress's own extra patterns), cuts
// to length, and drops source IPs and user agents wherever a record or
// attribute map carries them. It is safe for concurrent use.
type Egress struct {
	red   *incidents.Redactor
	extra []*regexp.Regexp
}

// NewEgress returns an egress filter over the incidents redactor (nil: the
// built-in rules) plus extra regular expressions, whose whole matches are
// redacted.
func NewEgress(red *incidents.Redactor, extra []string) (*Egress, error) {
	e := &Egress{red: red}
	for _, p := range extra {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("investigate: redact pattern %q: %w", p, err)
		}
		e.extra = append(e.extra, re)
	}
	return e, nil
}

// defaultEgress applies the built-in rules only.
var defaultEgress = &Egress{}

// Text returns s cleaned, redacted and cut to max bytes (0: no cap), with
// "…" marking a cut.
func (e *Egress) Text(s string, max int) string {
	if s == "" {
		return s
	}
	s = stripControls(s)
	var red *incidents.Redactor
	if e != nil {
		red = e.red
	}
	s = red.String(s)
	if e != nil {
		for _, re := range e.extra {
			s = re.ReplaceAllString(s, incidents.Redacted)
		}
	}
	return cutText(s, max)
}

// Line is Text for one-line fields: newlines and tabs become spaces.
func (e *Egress) Line(s string, max int) string {
	s = e.Text(s, 0)
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || r == '\r' {
			return ' '
		}
		return r
	}, s)
	return cutText(s, max)
}

// Map returns the first maxKeys entries of m in key order, keys and values
// passed through Line, without the source-IP and user-agent attributes. An
// empty result is nil.
func (e *Egress) Map(m map[string]string, maxKeys, maxLen int) map[string]string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		if !droppedKey(k) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	out := map[string]string{}
	for _, k := range keys {
		if maxKeys > 0 && len(out) >= maxKeys {
			break
		}
		ck := e.Line(k, 64)
		if ck == "" {
			continue
		}
		out[ck] = e.Line(m[k], maxLen)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// droppedKey reports whether an attribute or record field names a source IP
// or user agent, which never leave.
func droppedKey(k string) bool {
	switch strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(k)) {
	case "sourceip", "sourceips", "sourceipaddress", "useragent", "clientip", "remoteaddr", "remoteip":
		return true
	}
	return false
}

var ctDropped = regexp.MustCompile(`(?i)"(?:sourceIPAddress|userAgent)"\s*:\s*(?:"(?:[^"\\]|\\.)*"?|[^,}\]]*)\s*,?`)

// CloudTrailRaw returns a raw CloudTrail record without sourceIPAddress and
// userAgent (anywhere in it, even when the record was cut short), redacted
// and cut to max bytes.
func (e *Egress) CloudTrailRaw(raw string, max int) string {
	if raw == "" {
		return ""
	}
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err == nil {
		dropKeys(v)
		if b, err := json.Marshal(v); err == nil {
			raw = string(b)
		}
	} else {
		raw = ctDropped.ReplaceAllString(raw, "")
	}
	return e.Text(raw, max)
}

func dropKeys(v any) {
	switch t := v.(type) {
	case map[string]any:
		for k, c := range t {
			if droppedKey(k) {
				delete(t, k)
				continue
			}
			dropKeys(c)
		}
	case []any:
		for _, c := range t {
			dropKeys(c)
		}
	}
}

// untrusted wraps data from the cluster for the model: JSON-encoded, so
// json.Marshal's escaping of <, > and & guarantees no literal closing tag
// inside, and tagged with where it came from.
func untrusted(source string, v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		data = []byte(`null`)
	}
	return `<untrusted source="` + source + `">` + string(data) + `</untrusted>`
}

// stripControls makes s valid UTF-8 without control characters (newlines
// and tabs stay) or format characters (bidi overrides, zero-width spaces,
// byte-order marks), which could hide text from a reader.
func stripControls(s string) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	clean := true
	for _, r := range s {
		if isStripped(r) {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	return strings.Map(func(r rune) rune {
		if isStripped(r) {
			return -1
		}
		return r
	}, s)
}

func isStripped(r rune) bool {
	if r == '\n' || r == '\t' {
		return false
	}
	return r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || unicode.Is(unicode.Cf, r)
}

// cutText cuts s to at most max bytes on a rune boundary, ending in "…"
// when anything was cut. max 0 means no cap.
func cutText(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	if max <= 3 {
		return cut(s, max)
	}
	return cut(s, max-3) + "…"
}
