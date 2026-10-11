package hist

import (
	"math"
	"math/rand/v2"
	"sort"
	"sync"
	"testing"
)

func exact(vals []float64, q float64) float64 {
	s := append([]float64(nil), vals...)
	sort.Float64s(s)
	i := int(math.Ceil(q*float64(len(s)))) - 1
	if i < 0 {
		i = 0
	}
	return s[i]
}

func TestQuantilesWithinOnePercent(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	h := New()
	var vals []float64
	for i := 0; i < 100000; i++ {
		v := math.Exp(r.NormFloat64()*1.5 + 4) // lognormal around 55ms, long tail
		vals = append(vals, v)
		h.Add(v)
	}
	for _, q := range []float64{0.5, 0.9, 0.95, 0.99, 0.999} {
		got, want := h.Quantile(q), exact(vals, q)
		if math.Abs(got-want)/want > 0.011 {
			t.Errorf("q%.3f: got %.3f want %.3f", q, got, want)
		}
	}
	s := h.Summarize()
	if s.Count != 100000 || s.Min != math.Round(exact(vals, 0)*100)/100 {
		t.Errorf("summary %+v", s)
	}
}

func TestSmallAndEdgeValues(t *testing.T) {
	h := New()
	if h.Quantile(0.99) != 0 {
		t.Fatal("empty histogram must report 0")
	}
	for _, v := range []float64{0, 0.001, 1, 2, 3, 4, 5, 6, 7, 8, 9, 100} {
		h.Add(v)
	}
	if h.Quantile(1) != 100 || h.Quantile(0) != 0 {
		t.Errorf("ends: %v %v", h.Quantile(0), h.Quantile(1))
	}
	if p50 := h.Quantile(0.5); math.Abs(p50-4) > 0.05 { // rank ceil(0.5*12)=6: the value 4
		t.Errorf("p50 %v, want 4", p50)
	}
	// p99 of 12 values is the maximum.
	if h.Quantile(0.99) != 100 {
		t.Errorf("p99 %v", h.Quantile(0.99))
	}
}

func TestMergeEqualsCombined(t *testing.T) {
	a, b, all := New(), New(), New()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for v := 1; v <= 1000; v++ {
				x := float64(v * (i + 1))
				if i%2 == 0 {
					a.Add(x)
				} else {
					b.Add(x)
				}
				all.Add(x)
			}
		}(i)
	}
	wg.Wait()
	a.Merge(b)
	for _, q := range []float64{0.5, 0.95, 0.99} {
		if a.Quantile(q) != all.Quantile(q) {
			t.Errorf("q%v: merged %v combined %v", q, a.Quantile(q), all.Quantile(q))
		}
	}
	if a.Count() != 4000 {
		t.Errorf("count %d", a.Count())
	}
}
