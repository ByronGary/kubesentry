package procmon

import (
	"regexp"
	"strings"
)

const maxCmdline = 512

const secretAlt = `(?:pass(?:word|wd)?|secret|token|api[-_]?key|access[-_]?key|auth|credential|private[-_]?key)`

var (
	// --password=hunter2, token:abc, API_KEY=...
	inlineSecret = regexp.MustCompile(`(?i)^(-{0,2}[\w.-]*` + secretAlt + `[\w.-]*)([=:])(.+)$`)
	// --password hunter2 (the value is the next argument)
	flagSecret = regexp.MustCompile(`(?i)^-{1,2}[\w.-]*` + secretAlt + `[\w.-]*$`)
)

// Redact joins args into one string, masking values that look like secrets,
// and truncates the result. Command lines routinely carry credentials, so
// anything uncertain is hidden rather than shown.
func Redact(args []string) string {
	out := make([]string, 0, len(args))
	maskNext := false
	for _, a := range args {
		switch {
		case maskNext:
			out = append(out, "***")
			maskNext = false
		case inlineSecret.MatchString(a):
			m := inlineSecret.FindStringSubmatch(a)
			out = append(out, m[1]+m[2]+"***")
		case flagSecret.MatchString(a):
			out = append(out, a)
			maskNext = true
		default:
			// URLs with embedded credentials: scheme://user:pass@host
			out = append(out, maskURLUserinfo(a))
		}
	}
	s := strings.Join(out, " ")
	if len(s) > maxCmdline {
		s = s[:maxCmdline] + "…"
	}
	return s
}

var urlCreds = regexp.MustCompile(`(://[^/@\s:]+):[^/@\s]+@`)

func maskURLUserinfo(a string) string { return urlCreds.ReplaceAllString(a, "$1:***@") }
