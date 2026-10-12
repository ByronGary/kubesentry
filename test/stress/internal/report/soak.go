package report

import (
	"bufio"
	"context"
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ByronGary/kubesentry/test/stress/internal/users"
)

// SoakSeries is one tracked signal over the soak, at 1-minute resolution.
type SoakSeries struct {
	Name   string  `json:"name"`
	Unit   string  `json:"unit"`
	Points []Point `json:"points"`
	Trend  Trend   `json:"trend"`
}

// Trend compares the soak's first and last thirds (after the warm-up) and
// fits a line through every point after the warm-up.
type Trend struct {
	N              int     `json:"n"`
	FirstThirdMean float64 `json:"firstThirdMean"`
	LastThirdMean  float64 `json:"lastThirdMean"`
	Change         float64 `json:"change"`          // last third / first third - 1
	SlopePerHour   float64 `json:"slopePerHour"`    // least squares, unit per hour
	RelSlopePerH   float64 `json:"relSlopePerHour"` // slope / mean
	Min            float64 `json:"min"`
	Max            float64 `json:"max"`
	Upward         bool    `json:"upward"` // flagged: grows >10% between thirds and >5%/h on the fit
	Expected       bool    `json:"expected,omitempty"`
	Note           string  `json:"note,omitempty"`
}

// PGSample is one row of the soak's Postgres sampler (hack/stress-run.sh).
type PGSample struct {
	T          time.Time `json:"t"`
	DBBytes    float64   `json:"dbBytes"`
	Partitions float64   `json:"partitions"`
	EstRows    float64   `json:"estRows"`
}

// SoakBucket is ten minutes of the users' traffic.
type SoakBucket struct {
	T        time.Time `json:"t"`
	Users    int       `json:"users"`
	Requests int64     `json:"requests"`
	Errors   int64     `json:"errors"`
	ErrRate  float64   `json:"errorRate"`
	P99Max   float64   `json:"p99MaxMs"` // worst 10s bucket p99
	P50Avg   float64   `json:"p50AvgMs"`
}

// Soak is soak.json.
type Soak struct {
	From     time.Time    `json:"from"`
	To       time.Time    `json:"to"`
	Warmup   string       `json:"warmup"`
	Series   []SoakSeries `json:"series"`
	PG       []PGSample   `json:"postgres"`
	Traffic  []SoakBucket `json:"traffic"`
	Flagged  []string     `json:"flagged"`
	Errors   []string     `json:"errors,omitempty"`
	Restarts string       `json:"restarts,omitempty"`
}

func trendOf(pts []Point, from time.Time) Trend {
	var xs, ys []float64
	for _, p := range pts {
		if p.T.Before(from) {
			continue
		}
		xs = append(xs, p.T.Sub(from).Hours())
		ys = append(ys, p.V)
	}
	t := Trend{N: len(ys)}
	if len(ys) < 6 {
		return t
	}
	t.Min, t.Max = math.Inf(1), math.Inf(-1)
	var sx, sy, sxx, sxy float64
	for i := range ys {
		sx += xs[i]
		sy += ys[i]
		sxx += xs[i] * xs[i]
		sxy += xs[i] * ys[i]
		t.Min, t.Max = math.Min(t.Min, ys[i]), math.Max(t.Max, ys[i])
	}
	n := float64(len(ys))
	mean := sy / n
	if den := n*sxx - sx*sx; den != 0 {
		t.SlopePerHour = (n*sxy - sx*sy) / den
	}
	if mean != 0 {
		t.RelSlopePerH = t.SlopePerHour / math.Abs(mean)
	}
	third := len(ys) / 3
	avg := func(v []float64) float64 {
		s := 0.0
		for _, x := range v {
			s += x
		}
		return s / float64(len(v))
	}
	t.FirstThirdMean, t.LastThirdMean = avg(ys[:third]), avg(ys[len(ys)-third:])
	if t.FirstThirdMean != 0 {
		t.Change = t.LastThirdMean/t.FirstThirdMean - 1
	}
	t.Upward = t.Change > 0.10 && t.RelSlopePerH > 0.05
	return t
}

// ReadPGSamples reads the sampler CSV: iso time, db bytes, partitions, estimated rows.
func ReadPGSamples(path string) ([]PGSample, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []PGSample
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := strings.Split(strings.TrimSpace(sc.Text()), ",")
		if len(p) < 4 {
			continue
		}
		t, err := time.Parse(time.RFC3339, p[0])
		if err != nil {
			continue
		}
		s := PGSample{T: t}
		s.DBBytes, _ = strconv.ParseFloat(p[1], 64)
		s.Partitions, _ = strconv.ParseFloat(p[2], 64)
		s.EstRows, _ = strconv.ParseFloat(p[3], 64)
		out = append(out, s)
	}
	return out, sc.Err()
}

// BuildSoak gathers the soak's series from Prometheus, the Postgres sampler
// and the users' 10-second buckets.
func BuildSoak(ctx context.Context, p *Prom, u *users.Result, pg []PGSample, from, to time.Time, warmup time.Duration) *Soak {
	s := &Soak{From: from, To: to, Warmup: warmup.String(), PG: pg}
	const ks = `job="kubesentry-ops"`
	const server = `namespace="kubesentry",container="server"`
	const proxy = `namespace="kubesentry",container="oauth2-proxy"`
	const pgSel = `namespace="stress-pg",container="postgres"`
	type spec struct {
		name, unit, q, by string
		expected          string // why growth is expected, if it is
	}
	specs := []spec{
		{"kubesentry RSS", "MiB", `container_memory_rss{` + server + `} / 1048576`, "pod", ""},
		{"kubesentry working set", "MiB", `container_memory_working_set_bytes{` + server + `} / 1048576`, "pod", ""},
		{"kubesentry Go heap", "MiB", `go_memstats_heap_alloc_bytes{` + ks + `} / 1048576`, "pod", ""},
		{"kubesentry goroutines", "", `go_goroutines{` + ks + `}`, "pod", ""},
		{"kubesentry CPU", "cores", `rate(container_cpu_usage_seconds_total{` + server + `}[2m])`, "pod", ""},
		{"snapshot age (worst replica)", "s", `max(kubesentry_snapshot_age_seconds{` + ks + `})`, "", ""},
		{"kubesentry 5xx", "/s", `sum(rate(kubesentry_http_requests_total{code=~"5.."}[5m]))`, "", ""},
		{"oauth2-proxy working set", "MiB", `container_memory_working_set_bytes{` + proxy + `} / 1048576`, "pod", ""},
		{"oauth2-proxy CPU", "cores", `rate(container_cpu_usage_seconds_total{` + proxy + `}[2m])`, "pod", ""},
		{"Postgres working set", "MiB", `sum(container_memory_working_set_bytes{` + pgSel + `}) / 1048576`, "", "page cache of a growing table"},
		{"Postgres CPU", "cores", `sum(rate(container_cpu_usage_seconds_total{` + pgSel + `}[2m]))`, "", ""},
		{"CloudWatch lag", "s", `max(kubesentry_cloudwatch_lag_seconds{` + ks + `})`, "", ""},
		{"audit queue depth", "", `max(kubesentry_audit_queue_depth{` + ks + `})`, "", ""},
		{"informer objects", "", `max(sum by (pod) (kubesentry_informer_objects{` + ks + `}))`, "", ""},
	}
	start := from.Add(warmup)
	for _, sp := range specs {
		res, err := p.Range(ctx, sp.q, from, to, time.Minute)
		if err != nil {
			s.Errors = append(s.Errors, err.Error())
			continue
		}
		if sp.by == "" {
			ss := SoakSeries{Name: sp.name, Unit: sp.unit, Points: Sum(res)}
			ss.Trend = trendOf(ss.Points, start)
			if sp.expected != "" {
				ss.Trend.Expected, ss.Trend.Note = true, sp.expected
			}
			s.Series = append(s.Series, ss)
			continue
		}
		sort.Slice(res, func(i, j int) bool { return res[i].Labels[sp.by] < res[j].Labels[sp.by] })
		for _, r := range res {
			ss := SoakSeries{Name: sp.name + " " + r.Labels[sp.by], Unit: sp.unit, Points: r.Points}
			ss.Trend = trendOf(ss.Points, start)
			s.Series = append(s.Series, ss)
		}
	}
	// Postgres size grows with the firehose by design; partitions with days.
	if len(pg) > 0 {
		var db, parts, rows []Point
		for _, x := range pg {
			db = append(db, Point{x.T, x.DBBytes / 1048576})
			parts = append(parts, Point{x.T, x.Partitions})
			rows = append(rows, Point{x.T, x.EstRows})
		}
		for _, ss := range []SoakSeries{
			{Name: "Postgres database size", Unit: "MiB", Points: db},
			{Name: "audit partitions", Points: parts},
			{Name: "audit rows (estimate)", Points: rows},
		} {
			ss.Trend = trendOf(ss.Points, start)
			ss.Trend.Expected, ss.Trend.Note = true, "the soak's firehose adds events"
			if ss.Name == "audit partitions" {
				ss.Trend.Note = "one partition per day"
			}
			s.Series = append(s.Series, ss)
		}
	}
	for _, ss := range s.Series {
		if ss.Trend.Upward && !ss.Trend.Expected {
			s.Flagged = append(s.Flagged, fmt.Sprintf("%s: %+.0f%% from the first to the last third (%.4g → %.4g %s), fit %+.1f%%/h",
				ss.Name, 100*ss.Trend.Change, ss.Trend.FirstThirdMean, ss.Trend.LastThirdMean, ss.Unit, 100*ss.Trend.RelSlopePerH))
		}
	}
	if u != nil {
		byKey := map[int64]*SoakBucket{}
		var keys []int64
		n50 := map[int64]int{}
		for _, b := range u.Series {
			if b.T.Before(from) || b.T.After(to) {
				continue
			}
			k := b.T.Unix() / 600
			sb := byKey[k]
			if sb == nil {
				sb = &SoakBucket{T: time.Unix(k*600, 0).UTC()}
				byKey[k] = sb
				keys = append(keys, k)
			}
			sb.Requests += b.Requests
			sb.Errors += b.Errors
			sb.Users = max(sb.Users, b.Users)
			sb.P99Max = math.Max(sb.P99Max, b.P99)
			sb.P50Avg += b.P50
			n50[k]++
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
		var errPts []Point
		for _, k := range keys {
			sb := byKey[k]
			if n50[k] > 0 {
				sb.P50Avg /= float64(n50[k])
			}
			if sb.Requests > 0 {
				sb.ErrRate = float64(sb.Errors) / float64(sb.Requests)
			}
			s.Traffic = append(s.Traffic, *sb)
			errPts = append(errPts, Point{sb.T, sb.ErrRate})
		}
		tr := trendOf(errPts, start)
		if tr.N >= 6 && tr.LastThirdMean > 0.01 && tr.Change > 0.5 {
			s.Flagged = append(s.Flagged, fmt.Sprintf("users' error rate rose from %.2f%% to %.2f%%", 100*tr.FirstThirdMean, 100*tr.LastThirdMean))
		}
	}
	return s
}

func at(pts []Point, t time.Time) (float64, bool) {
	best, ok := 0.0, false
	var bd time.Duration = math.MaxInt64
	for _, p := range pts {
		d := p.T.Sub(t)
		if d < 0 {
			d = -d
		}
		if d < bd && d <= 5*time.Minute {
			best, bd, ok = p.V, d, true
		}
	}
	return best, ok
}

// Markdown renders soak.md.
func (s *Soak) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Soak: %s to %s\n\n", s.From.Format("15:04"), s.To.Format("15:04 MST"))
	fmt.Fprintf(&b, "Trends are taken after a %s warm-up: the mean of the last third against the first third, and a least-squares slope. A signal is flagged as an upward trend (a possible leak) when it grows more than 10%% between the thirds and more than 5%% of its mean per hour on the fit.\n\n", s.Warmup)
	if len(s.Flagged) == 0 {
		b.WriteString("**No unexpected upward trend.**\n\n")
	} else {
		b.WriteString("**Flagged:**\n\n")
		for _, f := range s.Flagged {
			fmt.Fprintf(&b, "- %s\n", f)
		}
		b.WriteString("\n")
	}
	b.WriteString("| Signal | min | max | first third | last third | change | slope /h | verdict |\n|---|---:|---:|---:|---:|---:|---:|---|\n")
	for _, ss := range s.Series {
		t := ss.Trend
		v := "flat"
		switch {
		case t.N < 6:
			v = "too few points"
		case t.Upward && t.Expected:
			v = "grows (expected: " + t.Note + ")"
		case t.Upward:
			v = "**upward trend**"
		case t.Change < -0.10:
			v = "falls"
		}
		fmt.Fprintf(&b, "| %s (%s) | %.4g | %.4g | %.4g | %.4g | %+.1f%% | %+.4g (%+.1f%%) | %s |\n",
			ss.Name, ss.Unit, t.Min, t.Max, t.FirstThirdMean, t.LastThirdMean, 100*t.Change, t.SlopePerHour, 100*t.RelSlopePerH, v)
	}
	// Ten-minute table of the main signals.
	find := func(prefix string) []SoakSeries {
		var out []SoakSeries
		for _, ss := range s.Series {
			if strings.HasPrefix(ss.Name, prefix) {
				out = append(out, ss)
			}
		}
		return out
	}
	rss, gor, heap := find("kubesentry RSS"), find("kubesentry goroutines"), find("kubesentry Go heap")
	age, proxy := find("snapshot age"), find("oauth2-proxy working set")
	dbs, parts := find("Postgres database size"), find("audit partitions")
	b.WriteString("\n## Every ten minutes\n\n| Time | users | req/s | errors | p99 (worst 10s) | RSS MiB per replica | heap MiB | goroutines | snapshot age | oauth2-proxy MiB | Postgres DB MiB | partitions |\n|---|---:|---:|---:|---:|---|---|---|---:|---|---:|---:|\n")
	list := func(ss []SoakSeries, t time.Time, f string) string {
		var parts []string
		for _, x := range ss {
			if v, ok := at(x.Points, t); ok {
				parts = append(parts, fmt.Sprintf(f, v))
			}
		}
		if len(parts) == 0 {
			return "-"
		}
		return strings.Join(parts, " / ")
	}
	for t := s.From.Truncate(10 * time.Minute).Add(10 * time.Minute); !t.After(s.To); t = t.Add(10 * time.Minute) {
		var tb *SoakBucket
		for i := range s.Traffic {
			if s.Traffic[i].T.Equal(t.Add(-10 * time.Minute)) {
				tb = &s.Traffic[i]
			}
		}
		u, rps, er, p99 := "-", "-", "-", "-"
		if tb != nil {
			u, rps, er, p99 = strconv.Itoa(tb.Users), fmt.Sprintf("%.1f", float64(tb.Requests)/600), fmt.Sprintf("%.2f%%", 100*tb.ErrRate), ms(tb.P99Max)
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n", t.Format("15:04"), u, rps, er, p99,
			list(rss, t, "%.0f"), list(heap, t, "%.0f"), list(gor, t, "%.0f"), list(age, t, "%.1fs"), list(proxy, t, "%.0f"), list(dbs, t, "%.0f"), list(parts, t, "%.0f"))
	}
	if s.Restarts != "" {
		fmt.Fprintf(&b, "\nRestarts: %s\n", s.Restarts)
	}
	if len(s.Errors) > 0 {
		b.WriteString("\nCollection errors:\n\n")
		for _, e := range s.Errors {
			fmt.Fprintf(&b, "- %s\n", e)
		}
	}
	return b.String()
}
