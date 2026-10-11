package detectors

import (
	"math"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
)

const mib = 1 << 20

var testKey = model.ContainerKey{Namespace: "app", Pod: "web-0", Container: "web"}

// sawtooth builds `cycles` lifetimes, each rising from startMiB by
// stepMiB per sample for `points` samples, 5 minutes apart, then restarting.
func sawtooth(cycles, points int, startMiB, stepMiB float64) []model.Sample {
	t := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)
	var out []model.Sample
	for c := 0; c < cycles; c++ {
		for i := 0; i < points; i++ {
			out = append(out, model.Sample{T: t, V: (startMiB + stepMiB*float64(i)) * mib})
			t = t.Add(5 * time.Minute)
		}
	}
	return out
}

func TestAnalyzeLeakSawtooth(t *testing.T) {
	// 3 lifetimes, each 12 samples rising 10 MiB per 5 min (= 120 MiB/h).
	s := model.ContainerSeries{Key: testKey, Samples: sawtooth(3, 12, 100, 10)}
	limit := 512.0 * mib

	f, ok := AnalyzeLeak(s, limit, DefaultLeakOptions())
	if !ok {
		t.Fatal("expected leak to be detected")
	}
	if f.Segments != 3 || f.LeakySegments != 3 {
		t.Errorf("segments=%d leaky=%d, want 3/3", f.Segments, f.LeakySegments)
	}
	if f.Confidence != "high" {
		t.Errorf("confidence = %q, want high", f.Confidence)
	}
	if want := 120.0 * mib; math.Abs(f.SlopeBytesPerHour-want)/want > 0.01 {
		t.Errorf("slope = %v B/h, want ~%v", f.SlopeBytesPerHour, want)
	}
	if f.R2 < 0.99 {
		t.Errorf("r2 = %v, want ~1", f.R2)
	}
	// Last sample is 210 MiB; (512-210)/120 = 2.516 h to limit.
	if f.TimeToLimitHours == nil || math.Abs(*f.TimeToLimitHours-2.5167) > 0.01 {
		t.Errorf("timeToLimit = %v, want ~2.52h", f.TimeToLimitHours)
	}
}

func TestAnalyzeLeakSingleLifetimeIsMediumConfidence(t *testing.T) {
	s := model.ContainerSeries{Key: testKey, Samples: sawtooth(1, 20, 100, 5)}
	f, ok := AnalyzeLeak(s, 0, DefaultLeakOptions())
	if !ok {
		t.Fatal("expected detection")
	}
	if f.Confidence != "medium" || f.TimeToLimitHours != nil {
		t.Errorf("confidence=%q ttl=%v, want medium and nil (no limit)", f.Confidence, f.TimeToLimitHours)
	}
}

func TestAnalyzeLeakIgnoresFlatAndNoisy(t *testing.T) {
	t0 := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)

	flat := make([]model.Sample, 30)
	noisy := make([]model.Sample, 30)
	for i := range flat {
		ts := t0.Add(time.Duration(i) * 5 * time.Minute)
		flat[i] = model.Sample{T: ts, V: 300 * mib}
		// Oscillates 200..400 MiB with no trend.
		noisy[i] = model.Sample{T: ts, V: (300 + 100*math.Sin(float64(i))) * mib}
	}
	for name, samples := range map[string][]model.Sample{"flat": flat, "noisy": noisy} {
		if f, ok := AnalyzeLeak(model.ContainerSeries{Key: testKey, Samples: samples}, 0, DefaultLeakOptions()); ok {
			t.Errorf("%s series flagged as leak: %+v", name, f)
		}
	}
}

func TestAnalyzeLeakShortSegmentsNotJudged(t *testing.T) {
	// Restarts every 4 samples: below MinSegmentPoints, so no verdict.
	s := model.ContainerSeries{Key: testKey, Samples: sawtooth(6, 4, 100, 50)}
	if f, ok := AnalyzeLeak(s, 0, DefaultLeakOptions()); ok {
		t.Errorf("short segments should not be judged, got %+v", f)
	}
}

func TestAnalyzeLeakHandlesUnsortedAndNaN(t *testing.T) {
	samples := sawtooth(1, 12, 100, 10)
	samples[3].V = math.NaN()
	samples[0], samples[11] = samples[11], samples[0]
	if _, ok := AnalyzeLeak(model.ContainerSeries{Key: testKey, Samples: samples}, 0, DefaultLeakOptions()); !ok {
		t.Error("expected detection despite NaN and unsorted input")
	}
}
