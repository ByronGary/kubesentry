package incidents

import (
	"fmt"
	"regexp"
	"strings"
)

// Redactor removes secrets from text before kubesentry shows or bundles it:
// log lines, event messages, CloudTrail records, the bundle. It is best
// effort: it knows the common shapes (AWS access keys, key=value secrets,
// bearer tokens, JWTs, PEM private keys, credentials in URLs) plus the
// configured patterns. It is safe for concurrent use.
type Redactor struct {
	rules []rule
}

type rule struct {
	re   *regexp.Regexp
	repl string // regexp.Expand template
	// hints: the rule can only match text holding one of these (lower
	// case); none means always try it.
	hints []string
}

// Redacted is what a secret is replaced with.
const Redacted = "[REDACTED]"

var builtinRules = []rule{
	// PEM private keys, whole blocks, then a block cut off before its end.
	{regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----`), Redacted, []string{"private key"}},
	{regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*`), Redacted, []string{"private key"}},
	// key=value and "key": "value" secrets; the key (and an Authorization
	// scheme) stays.
	{regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key|authorization)(["']?\s*[:=]\s*["']?)((?:bearer|basic)\s+)?[^\s"',;&}]+`),
		"${1}${2}${3}" + Redacted, []string{"pass", "secret", "token", "key", "authorization"}},
	// Bearer tokens anywhere else.
	{regexp.MustCompile(`(?i)\b(bearer)\s+[A-Za-z0-9\-._~+/]+=*`), "${1} " + Redacted, []string{"bearer"}},
	// JWTs anywhere.
	{regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*`), Redacted, []string{"eyj"}},
	// AWS access key IDs.
	{regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`), Redacted, []string{"akia", "asia"}},
	// user:password@ in URLs.
	{regexp.MustCompile(`(://)[^/\s:@]+:[^/\s@]+@`), "${1}" + Redacted + "@", []string{"://"}},
}

// NewRedactor returns a redactor with the built-in rules plus extra
// regular expressions, whose whole matches are redacted.
func NewRedactor(extra []string) (*Redactor, error) {
	r := &Redactor{rules: append([]rule(nil), builtinRules...)}
	for _, p := range extra {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("incidents: redact pattern %q: %w", p, err)
		}
		r.rules = append(r.rules, rule{re: re, repl: Redacted})
	}
	return r, nil
}

// String returns s with every secret replaced. A nil Redactor applies the
// built-in rules.
func (r *Redactor) String(s string) string {
	if s == "" {
		return s
	}
	rules := builtinRules
	if r != nil {
		rules = r.rules
	}
	lower := strings.ToLower(s)
	for _, ru := range rules {
		if len(ru.hints) > 0 && !containsAny(lower, ru.hints) {
			continue
		}
		s = ru.re.ReplaceAllString(s, ru.repl)
		lower = strings.ToLower(s)
	}
	return s
}

// Map returns a copy of m with every value redacted (keys too: a secret
// can hide in a key).
func (r *Redactor) Map(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[r.String(k)] = r.String(v)
	}
	return out
}

// Signal returns s with its title and attributes redacted.
func (r *Redactor) Signal(s Signal) Signal {
	s = CloneSignal(s)
	s.Title = r.String(s.Title)
	s.Attrs = r.Map(s.Attrs)
	return s
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
