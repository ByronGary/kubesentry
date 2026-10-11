package prom

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Matcher is one extra label matcher, such as cluster="prod".
type Matcher struct {
	Name  string
	Op    string // "=", "!=", "=~" or "!~"
	Value string // unquoted
}

// Matchers are injected into every selector the package builds, so one
// shared workspace (AMP, Thanos, Mimir) can hold several clusters.
type Matchers []Matcher

var labelName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// ParseMatchers parses -prometheus-selector: comma-separated matchers in
// PromQL syntax, optionally wrapped in braces, for example
// `cluster="prod",env=~"p.*"`. Strings may be double-, single- or
// back-quoted with PromQL (Go) escapes. Regular expressions must compile.
// Reserved names (__name__ and other __ labels) are refused, because a
// selector that changes the metric would break every query. An empty string
// yields no matchers.
func ParseMatchers(s string) (Matchers, error) {
	p := &matcherParser{s: strings.TrimSpace(s)}
	if p.s == "" {
		return nil, nil
	}
	if !utf8.ValidString(p.s) {
		return nil, fmt.Errorf("selector is not valid UTF-8")
	}
	if strings.HasPrefix(p.s, "{") {
		if !strings.HasSuffix(p.s, "}") {
			return nil, fmt.Errorf("selector %q: missing closing brace", s)
		}
		p.s = strings.TrimSpace(p.s[1 : len(p.s)-1])
	}
	var out Matchers
	for {
		p.space()
		if p.done() {
			break
		}
		m, err := p.matcher()
		if err != nil {
			return nil, fmt.Errorf("selector %q: %w", s, err)
		}
		out = append(out, m)
		p.space()
		if p.done() {
			break
		}
		if p.s[p.i] != ',' {
			return nil, fmt.Errorf("selector %q: expected ',' at offset %d", s, p.i)
		}
		p.i++
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("selector %q: no matchers", s)
	}
	return out, nil
}

type matcherParser struct {
	s string
	i int
}

func (p *matcherParser) done() bool { return p.i >= len(p.s) }

func (p *matcherParser) space() {
	for p.i < len(p.s) && strings.IndexByte(" \t\r\n", p.s[p.i]) >= 0 {
		p.i++
	}
}

func (p *matcherParser) matcher() (Matcher, error) {
	start := p.i
	for p.i < len(p.s) && (p.s[p.i] == '_' || isAlnum(p.s[p.i])) {
		p.i++
	}
	name := p.s[start:p.i]
	if !labelName.MatchString(name) {
		return Matcher{}, fmt.Errorf("invalid label name at offset %d", start)
	}
	if strings.HasPrefix(name, "__") {
		return Matcher{}, fmt.Errorf("label %q is reserved", name)
	}
	p.space()
	var op string
	for _, cand := range []string{"=~", "!~", "!=", "="} {
		if strings.HasPrefix(p.s[p.i:], cand) {
			op = cand
			break
		}
	}
	if op == "" {
		return Matcher{}, fmt.Errorf("expected =, !=, =~ or !~ after %q", name)
	}
	p.i += len(op)
	p.space()
	val, err := p.str()
	if err != nil {
		return Matcher{}, fmt.Errorf("value of %q: %w", name, err)
	}
	if op == "=~" || op == "!~" {
		// Prometheus anchors regexes and uses RE2 syntax, as Go does.
		if _, err := regexp.Compile("^(?:" + val + ")$"); err != nil {
			return Matcher{}, fmt.Errorf("value of %q is not a valid regular expression: %v", name, err)
		}
	}
	return Matcher{Name: name, Op: op, Value: val}, nil
}

// str reads one quoted string literal and returns its unescaped value.
func (p *matcherParser) str() (string, error) {
	if p.done() {
		return "", fmt.Errorf("missing quoted string")
	}
	q := p.s[p.i]
	if q != '"' && q != '\'' && q != '`' {
		return "", fmt.Errorf("expected a quoted string at offset %d", p.i)
	}
	p.i++
	if q == '`' {
		end := strings.IndexByte(p.s[p.i:], '`')
		if end < 0 {
			return "", fmt.Errorf("unterminated string")
		}
		v := p.s[p.i : p.i+end]
		p.i += end + 1
		return v, nil
	}
	var b strings.Builder
	rest := p.s[p.i:]
	for {
		if rest == "" {
			return "", fmt.Errorf("unterminated string")
		}
		if rest[0] == q {
			p.i = len(p.s) - len(rest) + 1
			if !utf8.ValidString(b.String()) {
				return "", fmt.Errorf("invalid UTF-8")
			}
			return b.String(), nil
		}
		if rest[0] == '\n' {
			return "", fmt.Errorf("newline in string")
		}
		r, multibyte, tail, err := strconv.UnquoteChar(rest, q)
		if err != nil {
			return "", fmt.Errorf("invalid escape near %q", rest[:min(len(rest), 6)])
		}
		if r < utf8.RuneSelf || !multibyte {
			b.WriteByte(byte(r)) // \xHH and octal escapes are bytes, as in strconv.Unquote
		} else {
			b.WriteRune(r)
		}
		rest = tail
	}
}

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// String renders the matchers in canonical PromQL form, values double-quoted:
// `cluster="prod",env=~"p.*"`.
func (ms Matchers) String() string {
	parts := ms.parts()
	return strings.Join(parts, ",")
}

func (ms Matchers) parts() []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.Name+m.Op+strconv.Quote(m.Value))
	}
	return out
}

// sel builds metric{parts...,extra matchers...}. Every selector the package
// sends goes through here so the extra matchers are never forgotten.
func (c *Client) sel(metric string, parts ...string) string {
	all := append(append([]string{}, parts...), c.selector.parts()...)
	return metric + "{" + strings.Join(all, ",") + "}"
}
