// Package users simulates dashboard users: each virtual user opens pages with
// the UI's real request mix and polling intervals (web/src/pages/*.tsx), waits
// for the page to load, reads it for a think time, and moves on.
package users

import (
	"fmt"
	"math/rand/v2"
	"net/url"
	"strings"
	"time"
)

// Hook is one useApi() call on a page: a request fired on load and then
// every Every. Like the browser, a poll aborts the previous request of the
// same hook if it is still running.
type Hook struct {
	Route string // stats key
	Path  string
	Every time.Duration
	// Paged follows `continue` with limit=Limit, as the new UI's usePaged
	// does; it polls only while everything fits in one page.
	Paged bool
	Limit int
	// Needs names the /info capability the UI checks before calling.
	Needs string
}

// Page is one screen of the UI.
type Page struct {
	Name   string
	Weight float64
	Hooks  func(t *Targets, r *rand.Rand) []Hook
}

// Targets are the pods and namespaces users navigate to.
type Targets struct {
	Pods       []PodRef // for the pod page
	Namespaces []string // for the map
}

// Within returns the targets in the given namespaces (nil: all).
func (t *Targets) Within(ns map[string]bool) *Targets {
	if ns == nil {
		return t
	}
	out := &Targets{}
	for _, p := range t.Pods {
		if ns[p.Namespace] {
			out.Pods = append(out.Pods, p)
		}
	}
	for _, n := range t.Namespaces {
		if ns[n] {
			out.Namespaces = append(out.Namespaces, n)
		}
	}
	return out
}

// PodRef names a pod.
type PodRef struct{ Namespace, Name string }

const (
	s15 = 15 * time.Second
	s30 = 30 * time.Second
	s60 = 60 * time.Second
)

// Pages is the default mix: Findings 30%, pod page 20%, Pods 10%, Map 10%,
// Workloads 10%, Activity 10%, Security 5%, Storage 3%, Certificates 2%.
var Pages = []Page{
	{Name: "findings", Weight: 30, Hooks: func(*Targets, *rand.Rand) []Hook {
		return []Hook{
			{Route: "oom", Path: "/api/v1/oom?window=24h", Every: s60},
			{Route: "pvcs-unused", Path: "/api/v1/pvcs/unused", Every: s60},
			{Route: "audit-events", Path: "/api/v1/audit/events?since=24h&limit=500", Every: s60},
			{Route: "security", Path: "/api/v1/security", Every: s60},
			{Route: "certificates", Path: "/api/v1/certificates", Every: s60},
		}
	}},
	{Name: "pod", Weight: 20, Hooks: func(t *Targets, r *rand.Rand) []Hook {
		if len(t.Pods) == 0 {
			return nil
		}
		p := t.Pods[r.IntN(len(t.Pods))]
		base := fmt.Sprintf("/api/v1/pods/%s/%s", url.PathEscape(p.Namespace), url.PathEscape(p.Name))
		return []Hook{
			{Route: "diagnostics", Path: base + "/diagnostics?window=6h", Every: s30},
			{Route: "processes", Path: base + "/processes", Every: s15},
		}
	}},
	{Name: "pods", Weight: 10, Hooks: func(*Targets, *rand.Rand) []Hook {
		return []Hook{{Route: "pods", Path: "/api/v1/pods", Every: s30}}
	}},
	{Name: "map", Weight: 10, Hooks: func(t *Targets, r *rand.Rand) []Hook {
		// The Map page opens on the apps view; about a third of visits switch to the node view.
		if r.Float64() < 0.3 {
			return []Hook{{Route: "nodes", Path: "/api/v1/nodes", Every: s30}}
		}
		path := "/api/v1/map"
		if len(t.Namespaces) > 0 && r.Float64() < 0.6 {
			path += "?namespace=" + url.QueryEscape(t.Namespaces[r.IntN(len(t.Namespaces))])
		}
		return []Hook{{Route: "map", Path: path, Every: s30}}
	}},
	{Name: "workloads", Weight: 10, Hooks: func(*Targets, *rand.Rand) []Hook {
		return []Hook{{Route: "workloads", Path: "/api/v1/workloads", Every: s30}}
	}},
	{Name: "activity", Weight: 10, Hooks: func(*Targets, *rand.Rand) []Hook {
		return []Hook{
			{Route: "audit-summary", Path: "/api/v1/audit/summary?since=24h", Every: s60},
			{Route: "audit-events", Path: "/api/v1/audit/events?since=24h&limit=200", Every: s60},
		}
	}},
	{Name: "security", Weight: 5, Hooks: func(*Targets, *rand.Rand) []Hook {
		return []Hook{{Route: "security", Path: "/api/v1/security", Every: s60}}
	}},
	{Name: "storage", Weight: 3, Hooks: func(*Targets, *rand.Rand) []Hook {
		return []Hook{{Route: "storage", Path: "/api/v1/storage", Every: s60}}
	}},
	{Name: "certificates", Weight: 2, Hooks: func(*Targets, *rand.Rand) []Hook {
		return []Hook{{Route: "certificates", Path: "/api/v1/certificates", Every: s60}}
	}},
}

// PagesAfter is the same mix with the new UI's requests (web/src/pages after
// the enterprise work): paged lists, ?view=summary, the node summary, and
// capability-gated audit and process calls. App.tsx also polls /info every 30s.
var PagesAfter = []Page{
	{Name: "findings", Weight: 30, Hooks: func(*Targets, *rand.Rand) []Hook {
		return []Hook{
			{Route: "oom", Path: "/api/v1/oom?window=24h", Every: s60},
			{Route: "pvcs-unused", Path: "/api/v1/pvcs/unused", Every: s60},
			{Route: "audit-events", Path: "/api/v1/audit/events?since=24h&limit=500", Every: s60, Needs: "audit"},
			{Route: "security", Path: "/api/v1/security?view=summary", Every: s60},
			{Route: "certificates", Path: "/api/v1/certificates", Every: s60},
		}
	}},
	{Name: "pod", Weight: 20, Hooks: func(t *Targets, r *rand.Rand) []Hook {
		if len(t.Pods) == 0 {
			return nil
		}
		p := t.Pods[r.IntN(len(t.Pods))]
		base := fmt.Sprintf("/api/v1/pods/%s/%s", url.PathEscape(p.Namespace), url.PathEscape(p.Name))
		return []Hook{
			{Route: "diagnostics", Path: base + "/diagnostics?window=6h", Every: s30},
			{Route: "processes", Path: base + "/processes", Every: s15, Needs: "processes"},
		}
	}},
	{Name: "pods", Weight: 10, Hooks: func(*Targets, *rand.Rand) []Hook {
		return []Hook{{Route: "pods", Path: "/api/v1/pods", Every: s30, Paged: true, Limit: 1000}}
	}},
	{Name: "map", Weight: 10, Hooks: func(t *Targets, r *rand.Rand) []Hook {
		if r.Float64() < 0.3 {
			return []Hook{{Route: "nodes", Path: "/api/v1/nodes?summary=true", Every: s30}}
		}
		path := "/api/v1/map"
		if len(t.Namespaces) > 0 && r.Float64() < 0.6 {
			path += "?namespace=" + url.QueryEscape(t.Namespaces[r.IntN(len(t.Namespaces))])
		}
		return []Hook{{Route: "map", Path: path, Every: s30}}
	}},
	{Name: "workloads", Weight: 10, Hooks: func(*Targets, *rand.Rand) []Hook {
		return []Hook{{Route: "workloads", Path: "/api/v1/workloads", Every: s30, Paged: true, Limit: 1000}}
	}},
	{Name: "activity", Weight: 10, Hooks: func(*Targets, *rand.Rand) []Hook {
		return []Hook{
			{Route: "audit-summary", Path: "/api/v1/audit/summary?since=24h", Every: s60, Needs: "audit"},
			{Route: "audit-events", Path: "/api/v1/audit/events?since=24h&limit=200", Every: s60, Needs: "audit"},
		}
	}},
	{Name: "security", Weight: 5, Hooks: func(*Targets, *rand.Rand) []Hook {
		return []Hook{{Route: "security", Path: "/api/v1/security?view=summary", Every: s60}}
	}},
	{Name: "storage", Weight: 3, Hooks: func(*Targets, *rand.Rand) []Hook {
		return []Hook{{Route: "storage", Path: "/api/v1/storage", Every: s60, Paged: true, Limit: 1000}}
	}},
	{Name: "certificates", Weight: 2, Hooks: func(*Targets, *rand.Rand) []Hook {
		return []Hook{{Route: "certificates", Path: "/api/v1/certificates", Every: s60}}
	}},
}

// Pick chooses a page by weight.
func Pick(pages []Page, r *rand.Rand) *Page {
	total := 0.0
	for _, p := range pages {
		total += p.Weight
	}
	x := r.Float64() * total
	for i := range pages {
		x -= pages[i].Weight
		if x < 0 {
			return &pages[i]
		}
	}
	return &pages[len(pages)-1]
}

// Stage is one step of the ramp: hold Users for Hold.
type Stage struct {
	Users int
	Hold  time.Duration
}

// ParseStages parses "10:2m,50:3m,200:5m".
func ParseStages(s string) ([]Stage, error) {
	var out []Stage
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		u, d, ok := strings.Cut(part, ":")
		if !ok {
			return nil, fmt.Errorf("stage %q: want users:duration", part)
		}
		var n int
		if _, err := fmt.Sscanf(u, "%d", &n); err != nil || n <= 0 {
			return nil, fmt.Errorf("stage %q: bad user count", part)
		}
		hold, err := time.ParseDuration(d)
		if err != nil {
			return nil, fmt.Errorf("stage %q: %w", part, err)
		}
		out = append(out, Stage{Users: n, Hold: hold})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no stages")
	}
	return out, nil
}
