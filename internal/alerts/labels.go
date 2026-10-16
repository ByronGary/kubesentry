package alerts

import (
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/model"
	"github.com/ByronGary/kubesentry/internal/snapshot"
)

// HintPrefix is the namespace annotation prefix whose keys become
// Alertmanager labels: kubesentry.io/slack-channel becomes the label
// kubesentry_slack_channel.
const HintPrefix = "kubesentry.io/"

// Bounds on the routing hints a namespace passes on, so one namespace
// cannot blow up Alertmanager's label sets.
const (
	maxHints     = 10
	maxHintValue = 256
)

// reservedLabels are labels a hint may not set: kubesentry_digest marks
// kubesentry's own digests, which a routing tree sends to a quiet receiver.
var reservedLabels = map[string]bool{"kubesentry_digest": true}

// nsInfo is what a namespace contributes to its findings' labels.
type nsInfo struct {
	ns         *model.Namespace // nil for a namespace the view does not hold (and "")
	owner      string
	production bool
	hints      [][2]string // label, value; sorted
}

// objectOwners maps the objects that name their own owner (the owner
// annotation internal/kube keeps on workloads, Services, Ingresses,
// Certificates and RBAC objects) to it, once per view.
func objectOwners(v *snapshot.View) map[detectors.ObjectRef]string {
	return v.Memo("alerts/object-owners", func() any { return detectors.ObjectOwners(&v.Inv) }).(map[detectors.ObjectRef]string)
}

// namespaceInfo reads owners, production labels and routing hints from the
// view's namespaces, once per view.
func namespaceInfo(v *snapshot.View) map[string]nsInfo {
	return v.Memo("alerts/namespaces", func() any {
		p := v.Policy
		out := make(map[string]nsInfo, len(v.Inv.Namespaces))
		for i := range v.Inv.Namespaces {
			n := v.Inv.Namespaces[i]
			info := nsInfo{ns: &v.Inv.Namespaces[i], owner: p.OwnerOf(n), production: p.IsProduction(n)}
			keys := make([]string, 0, len(n.Annotations))
			for k := range n.Annotations {
				if strings.HasPrefix(k, HintPrefix) && k != p.OwnerAnnotation {
					keys = append(keys, k)
				}
			}
			sort.Strings(keys)
			for _, k := range keys {
				name := HintLabel(k)
				if name == "" || reservedLabels[name] {
					continue
				}
				val := clean(strings.TrimSpace(n.Annotations[k]))
				if val == "" {
					continue
				}
				if len(info.hints) == maxHints {
					break
				}
				info.hints = append(info.hints, [2]string{name, truncate(val, maxHintValue)})
			}
			out[n.Name] = info
		}
		return out
	}).(map[string]nsInfo)
}

// HintLabel turns a kubesentry.io/<x> annotation key into its label name,
// kubesentry_<x> with every character Prometheus does not allow in a label
// name replaced by "_"; "" for any other key.
func HintLabel(key string) string {
	rest, ok := strings.CutPrefix(key, HintPrefix)
	if !ok || rest == "" {
		return ""
	}
	var b strings.Builder
	b.WriteString("kubesentry_")
	for _, r := range rest {
		if r < utf8.RuneSelf && (r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

// clean makes s safe to store and send: valid UTF-8 without NUL bytes.
func clean(s string) string {
	s = strings.ToValidUTF8(s, "�")
	return strings.ReplaceAll(s, "\x00", "")
}

// truncate shortens s to at most n bytes on a rune boundary.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
