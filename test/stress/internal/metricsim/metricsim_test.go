package metricsim

import (
	"fmt"
	"math"
	"testing"
	"time"
)

func cands(n int) []Series {
	out := make([]Series, n)
	for i := range out {
		out[i] = Series{Namespace: fmt.Sprintf("ns-%d", i%30), Pod: fmt.Sprintf("pod-%d", i), Container: "app"}
	}
	return out
}

func TestPlanIsStableAndSized(t *testing.T) {
	a := Plan(cands(20000), 5000, 0.02, 1)
	b := Plan(cands(20000), 5000, 0.02, 1)
	if len(a) != 5000 {
		t.Fatalf("got %d series", len(a))
	}
	leaks := 0
	for i := range a {
		if a[i].Pod != b[i].Pod || a[i].Leak != b[i].Leak || a[i].BaseMiB != b[i].BaseMiB {
			t.Fatal("plan not deterministic")
		}
		if a[i].Leak {
			leaks++
		}
	}
	if leaks < 60 || leaks > 140 {
		t.Errorf("%d leaking of 5000, want about 100", leaks)
	}
	// Adding pods keeps most chosen series (stable while pods exist).
	c := Plan(cands(22000), 5000, 0.02, 1)
	kept := map[string]bool{}
	for _, s := range c {
		kept[s.Pod] = true
	}
	same := 0
	for _, s := range a {
		if kept[s.Pod] {
			same++
		}
	}
	if same < 4000 {
		t.Errorf("only %d of 5000 series kept after growing the candidate set", same)
	}
}

func TestLeakIsASawtoothKubesentryCanSee(t *testing.T) {
	var leak *Series
	for _, s := range Plan(cands(2000), 2000, 0.05, 3) {
		if s.Leak {
			s := s
			leak = &s
			break
		}
	}
	if leak == nil {
		t.Fatal("no leak")
	}
	start := time.Unix(1_800_000_000, 0)
	prev := leak.Value(start)
	drops, rises := 0, 0
	for m := 1; m < 6*60; m++ {
		v := leak.Value(start.Add(time.Duration(m) * time.Minute))
		switch {
		case v < prev*0.7:
			drops++ // a "restart": more than 30% down
		case v > prev:
			rises++
		}
		prev = v
	}
	if drops < 2 {
		t.Errorf("%d restarts in 6h, want at least 2 (period %.0f min)", drops, leak.PeriodMin)
	}
	if rises < 250 {
		t.Errorf("only %d rising minutes", rises)
	}
	steady := Series{BaseMiB: 100, noise: 0.02, Pod: "p"}
	lo, hi := math.Inf(1), 0.0
	for m := 0; m < 600; m++ {
		v := steady.Value(start.Add(time.Duration(m) * time.Minute))
		lo, hi = math.Min(lo, v), math.Max(hi, v)
	}
	if hi/lo > 1.05 {
		t.Errorf("steady series varies %.2fx", hi/lo)
	}
}
