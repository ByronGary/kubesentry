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
			{"oom", "/api/v1/oom?window=24h", s60},
			{"pvcs-unused", "/api/v1/pvcs/unused", s60},
			{"audit-events", "/api/v1/audit/events?since=24h&limit=500", s60},
			{"security", "/api/v1/security", s60},
			{"certificates", "/api/v1/certificates", s60},
		}
	}},
	{Name: "pod", Weight: 20, Hooks: func(t *Targets, r *rand.Rand) []Hook {
		if len(t.Pods) == 0 {
			return nil
		}
		p := t.Pods[r.IntN(len(t.Pods))]
		base := fmt.Sprintf("/api/v1/pods/%s/%s", url.PathEscape(p.Namespace), url.PathEscape(p.Name))
		return []Hook{
			{"diagnostics", base + "/diagnostics?window=6h", s30},
			{"processes", base + "/processes", s15},
		}
	}},
	{Name: "pods", Weight: 10, Hooks: func(*Targets, *rand.Rand) []Hook {
		return []Hook{{"pods", "/api/v1/pods", s30}}
	}},
	{Name: "map", Weight: 10, Hooks: func(t *Targets, r *rand.Rand) []Hook {
		// The Map page opens on the apps view; about a third of visits switch to the node view.
		if r.Float64() < 0.3 {
			return []Hook{{"nodes", "/api/v1/nodes", s30}}
		}
		path := "/api/v1/map"
		if len(t.Namespaces) > 0 && r.Float64() < 0.6 {
			path += "?namespace=" + url.QueryEscape(t.Namespaces[r.IntN(len(t.Namespaces))])
		}
		return []Hook{{"map", path, s30}}
	}},
	{Name: "workloads", Weight: 10, Hooks: func(*Targets, *rand.Rand) []Hook {
		return []Hook{{"workloads", "/api/v1/workloads", s30}}
	}},
	{Name: "activity", Weight: 10, Hooks: func(*Targets, *rand.Rand) []Hook {
		return []Hook{
			{"audit-summary", "/api/v1/audit/summary?since=24h", s60},
			{"audit-events", "/api/v1/audit/events?since=24h&limit=200", s60},
		}
	}},
	{Name: "security", Weight: 5, Hooks: func(*Targets, *rand.Rand) []Hook {
		return []Hook{{"security", "/api/v1/security", s60}}
	}},
	{Name: "storage", Weight: 3, Hooks: func(*Targets, *rand.Rand) []Hook {
		return []Hook{{"storage", "/api/v1/storage", s60}}
	}},
	{Name: "certificates", Weight: 2, Hooks: func(*Targets, *rand.Rand) []Hook {
		return []Hook{{"certificates", "/api/v1/certificates", s60}}
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
