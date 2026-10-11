// Package report collects resource use (Prometheus, the API server audit log,
// the host guard) for a run and writes report.md and report.json, plus the
// cross-level summary.
package report

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"time"

	"k8s.io/client-go/kubernetes"
)

// Prom queries Prometheus through the API server's service proxy, so no
// port-forward is needed from the host.
type Prom struct {
	CS        kubernetes.Interface
	Namespace string
	Service   string
	Port      string
}

type promResp struct {
	Status string `json:"status"`
	Error  string `json:"error"`
	Data   struct {
		Result []struct {
			Metric map[string]string `json:"metric"`
			Values [][2]any          `json:"values"`
			Value  [2]any            `json:"value"`
		} `json:"result"`
	} `json:"data"`
}

// Point is one sample.
type Point struct {
	T time.Time `json:"t"`
	V float64   `json:"v"`
}

// SeriesData is one labelled series.
type SeriesData struct {
	Labels map[string]string `json:"labels"`
	Points []Point           `json:"points"`
}

// Range runs a range query.
func (p *Prom) Range(ctx context.Context, q string, start, end time.Time, step time.Duration) ([]SeriesData, error) {
	params := map[string]string{
		"query": q, "start": strconv.FormatInt(start.Unix(), 10), "end": strconv.FormatInt(end.Unix(), 10),
		"step": strconv.Itoa(int(step.Seconds())),
	}
	b, err := p.CS.CoreV1().Services(p.Namespace).ProxyGet("http", p.Service, p.Port, "/api/v1/query_range", params).DoRaw(ctx)
	if err != nil {
		return nil, fmt.Errorf("prometheus %q: %w", q, err)
	}
	var r promResp
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	if r.Status != "success" {
		return nil, fmt.Errorf("prometheus %q: %s", q, r.Error)
	}
	out := make([]SeriesData, 0, len(r.Data.Result))
	for _, res := range r.Data.Result {
		s := SeriesData{Labels: res.Metric}
		for _, v := range res.Values {
			ts, _ := v[0].(float64)
			f, _ := strconv.ParseFloat(fmt.Sprint(v[1]), 64)
			if math.IsNaN(f) || math.IsInf(f, 0) {
				continue
			}
			s.Points = append(s.Points, Point{T: time.Unix(int64(ts), 0).UTC(), V: f})
		}
		out = append(out, s)
	}
	return out, nil
}

// RawSize runs the range query kubesentry's /oom runs and reports the size of
// Prometheus' answer, which kubesentry caps at 64 MiB.
func (p *Prom) RawSize(ctx context.Context, q string, end time.Time, window, step time.Duration) (bytes, series, points int, err error) {
	params := map[string]string{
		"query": q, "start": strconv.FormatInt(end.Add(-window).Unix(), 10), "end": strconv.FormatInt(end.Unix(), 10),
		"step": strconv.Itoa(int(step.Seconds())),
	}
	b, err := p.CS.CoreV1().Services(p.Namespace).ProxyGet("http", p.Service, p.Port, "/api/v1/query_range", params).DoRaw(ctx)
	if err != nil {
		return len(b), 0, 0, err
	}
	var r promResp
	if err := json.Unmarshal(b, &r); err != nil {
		return len(b), 0, 0, err
	}
	for _, res := range r.Data.Result {
		points += len(res.Values)
	}
	return len(b), len(r.Data.Result), points, nil
}

// Stat is min/avg/max of a series over a window.
type Stat struct {
	Min float64 `json:"min"`
	Avg float64 `json:"avg"`
	Max float64 `json:"max"`
	N   int     `json:"n"`
}

// StatOf summarises points within [from, to].
func StatOf(pts []Point, from, to time.Time) Stat {
	s := Stat{Min: math.Inf(1)}
	sum := 0.0
	for _, p := range pts {
		if p.T.Before(from) || p.T.After(to) {
			continue
		}
		s.N++
		sum += p.V
		s.Min = math.Min(s.Min, p.V)
		s.Max = math.Max(s.Max, p.V)
	}
	if s.N == 0 {
		return Stat{}
	}
	s.Avg = sum / float64(s.N)
	return s
}

// Sum adds series point-wise by timestamp.
func Sum(ss []SeriesData) []Point {
	acc := map[int64]float64{}
	for _, s := range ss {
		for _, p := range s.Points {
			acc[p.T.Unix()] += p.V
		}
	}
	out := make([]Point, 0, len(acc))
	for t, v := range acc {
		out = append(out, Point{T: time.Unix(t, 0).UTC(), V: v})
	}
	sortPoints(out)
	return out
}

func secs(s float64) time.Duration { return time.Duration(s * float64(time.Second)) }
