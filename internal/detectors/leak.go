package detectors

import (
	"math"
	"sort"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
)

// LeakOptions tunes memory leak detection.
type LeakOptions struct {
	// DropRatio: a sample below previous*DropRatio starts a new segment. This
	// is how a restart (often an OOMKill) shows up in the working-set series.
	DropRatio float64
	// MinSegmentPoints is the minimum samples a segment needs to be judged.
	MinSegmentPoints int
	// MinSlopeBytesPerHour is the smallest growth rate considered a leak.
	MinSlopeBytesPerHour float64
	// MinR2 is how linear the growth must be (0..1). Steady growth scores near
	// 1; spiky workloads that merely fluctuate score low.
	MinR2 float64
}

func DefaultLeakOptions() LeakOptions {
	return LeakOptions{
		DropRatio:            0.7,
		MinSegmentPoints:     6,
		MinSlopeBytesPerHour: 1 << 20, // 1 MiB/h
		MinR2:                0.8,
	}
}

// LeakFinding describes a container whose memory climbs steadily between
// restarts.
type LeakFinding struct {
	model.ContainerKey
	Segments          int        `json:"segments"`          // process lifetimes seen in the window
	LeakySegments     int        `json:"leakySegments"`     // lifetimes that grew steadily
	SlopeBytesPerHour float64    `json:"slopeBytesPerHour"` // growth rate of the latest leaky segment
	R2                float64    `json:"r2"`
	CurrentBytes      float64    `json:"currentBytes"`
	LimitBytes        float64    `json:"limitBytes,omitempty"`
	TimeToLimitHours  *float64   `json:"timeToLimitHours,omitempty"`
	Confidence        string     `json:"confidence"` // "high" when 2+ lifetimes show the pattern
	OOMKilled         bool       `json:"oomKilled"`
	LastOOMAt         *time.Time `json:"lastOOMAt,omitempty"`
}

// AnalyzeLeak looks for the sawtooth that marks a leak: memory rising steadily
// within each process lifetime, then dropping on restart. It splits the series
// at drops, fits a least-squares line to each segment, and reports the
// container if any sufficiently long segment is steep and linear enough.
// limitBytes may be 0 when unknown.
func AnalyzeLeak(series model.ContainerSeries, limitBytes float64, opts LeakOptions) (LeakFinding, bool) {
	segments := splitSegments(cleanSamples(series.Samples), opts.DropRatio)

	finding := LeakFinding{ContainerKey: series.Key, Segments: len(segments), LimitBytes: limitBytes}
	for _, seg := range segments {
		if len(seg) < opts.MinSegmentPoints {
			continue
		}
		slope, r2 := linearFit(seg)
		perHour := slope * 3600
		if perHour >= opts.MinSlopeBytesPerHour && r2 >= opts.MinR2 {
			finding.LeakySegments++
			finding.SlopeBytesPerHour = perHour
			finding.R2 = r2
		}
	}
	if finding.LeakySegments == 0 {
		return LeakFinding{}, false
	}

	// Current usage is the newest sample overall, not the end of the leaky
	// segment, so time-to-limit reflects where the container is right now.
	latest := segments[len(segments)-1]
	finding.CurrentBytes = latest[len(latest)-1].V
	finding.Confidence = "medium"
	if finding.LeakySegments >= 2 {
		finding.Confidence = "high"
	}
	if limitBytes > finding.CurrentBytes && finding.SlopeBytesPerHour > 0 {
		h := (limitBytes - finding.CurrentBytes) / finding.SlopeBytesPerHour
		finding.TimeToLimitHours = &h
	}
	return finding, true
}

// cleanSamples drops NaN/Inf and returns a time-sorted copy.
func cleanSamples(in []model.Sample) []model.Sample {
	out := make([]model.Sample, 0, len(in))
	for _, s := range in {
		if math.IsNaN(s.V) || math.IsInf(s.V, 0) {
			continue
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].T.Before(out[j].T) })
	return out
}

func splitSegments(s []model.Sample, dropRatio float64) [][]model.Sample {
	if len(s) == 0 {
		return nil
	}
	var segs [][]model.Sample
	start := 0
	for i := 1; i < len(s); i++ {
		if s[i].V < s[i-1].V*dropRatio {
			segs = append(segs, s[start:i])
			start = i
		}
	}
	return append(segs, s[start:])
}

// linearFit returns the least-squares slope (value per second) and R² of the
// samples. It uses centred sums, which stay accurate for values around 1e9.
func linearFit(s []model.Sample) (slope, r2 float64) {
	if len(s) < 2 {
		return 0, 0
	}
	n := float64(len(s))
	t0 := s[0].T
	var mx, my float64
	for _, p := range s {
		mx += p.T.Sub(t0).Seconds()
		my += p.V
	}
	mx /= n
	my /= n

	var sxx, sxy, syy float64
	for _, p := range s {
		dx := p.T.Sub(t0).Seconds() - mx
		dy := p.V - my
		sxx += dx * dx
		sxy += dx * dy
		syy += dy * dy
	}
	if sxx == 0 {
		return 0, 0
	}
	slope = sxy / sxx
	if syy == 0 {
		return slope, 0
	}
	return slope, sxy * sxy / (sxx * syy)
}
