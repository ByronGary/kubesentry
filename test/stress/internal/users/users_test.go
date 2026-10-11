package users

import (
	"math"
	"math/rand/v2"
	"testing"
	"time"
)

func TestParseStages(t *testing.T) {
	st, err := ParseStages("10:2m, 50:90s,2000:10m")
	if err != nil {
		t.Fatal(err)
	}
	want := []Stage{{10, 2 * time.Minute}, {50, 90 * time.Second}, {2000, 10 * time.Minute}}
	if len(st) != len(want) {
		t.Fatalf("got %v", st)
	}
	for i := range want {
		if st[i] != want[i] {
			t.Errorf("stage %d: got %v want %v", i, st[i], want[i])
		}
	}
	for _, bad := range []string{"", "10", "x:1m", "10:soon", "0:1m"} {
		if _, err := ParseStages(bad); err == nil {
			t.Errorf("%q: want error", bad)
		}
	}
}

func TestPageMixMatchesWeights(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 1))
	counts := map[string]int{}
	const n = 200000
	for i := 0; i < n; i++ {
		counts[Pick(Pages, r).Name]++
	}
	want := map[string]float64{"findings": .30, "pod": .20, "pods": .10, "map": .10, "workloads": .10, "activity": .10, "security": .05, "storage": .03, "certificates": .02}
	for name, w := range want {
		got := float64(counts[name]) / n
		if math.Abs(got-w) > 0.005 {
			t.Errorf("%s: %.3f, want %.2f", name, got, w)
		}
	}
}

func TestPagesUseTheUIPollIntervals(t *testing.T) {
	r := rand.New(rand.NewPCG(2, 2))
	tg := &Targets{Pods: []PodRef{{"ns", "p"}}, Namespaces: []string{"ns"}}
	every := map[string]time.Duration{}
	for i := 0; i < 50; i++ {
		for _, p := range Pages {
			for _, h := range p.Hooks(tg, r) {
				every[h.Route] = h.Every
			}
		}
	}
	want := map[string]time.Duration{"oom": s60, "pvcs-unused": s60, "audit-events": s60, "security": s60, "certificates": s60,
		"diagnostics": s30, "processes": s15, "pods": s30, "map": s30, "nodes": s30, "workloads": s30, "audit-summary": s60, "storage": s60}
	for route, d := range want {
		if every[route] != d {
			t.Errorf("%s polls every %s, want %s", route, every[route], d)
		}
	}
}

func TestAfterPagesMatchTheNewUI(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 3))
	tg := &Targets{Pods: []PodRef{{"a", "p"}, {"b", "q"}}, Namespaces: []string{"a", "b"}}
	seen := map[string]Hook{}
	for i := 0; i < 200; i++ {
		for _, p := range PagesAfter {
			for _, h := range p.Hooks(tg, r) {
				seen[h.Route] = h
			}
		}
	}
	for route, paged := range map[string]bool{"pods": true, "workloads": true, "storage": true, "security": false, "oom": false} {
		if seen[route].Paged != paged {
			t.Errorf("%s paged=%v", route, seen[route].Paged)
		}
	}
	if seen["processes"].Needs != "processes" || seen["audit-summary"].Needs != "audit" {
		t.Error("capability gates missing")
	}
	if seen["security"].Path != "/api/v1/security?view=summary" || seen["nodes"].Path != "/api/v1/nodes?summary=true" {
		t.Errorf("security %q nodes %q", seen["security"].Path, seen["nodes"].Path)
	}
	in := tg.Within(map[string]bool{"b": true})
	if len(in.Pods) != 1 || in.Pods[0].Namespace != "b" || len(in.Namespaces) != 1 {
		t.Errorf("within %+v", in)
	}
	if tg.Within(nil) != tg {
		t.Error("nil scope must keep everything")
	}
}
