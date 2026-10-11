package demo

import (
	"context"
	"hash/fnv"
	"math"
	"math/rand"
	"time"

	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/model"
)

const mib = float64(1 << 20)

type kind int

const (
	steady  kind = iota // flat with noise
	leak                // sawtooth: climbs to near the limit, then restarts
	creeper             // slow steady growth with no limit set
)

type profile struct {
	kind     kind
	baseMiB  float64
	limitMiB float64 // 0 = no limit
}

// Metrics is an in-memory MetricsSource whose series are computed from the
// clock, so charts always show "now" and the sawtooth keeps moving.
type Metrics struct {
	start    time.Time
	profiles map[model.ContainerKey]profile
}

// NewMetrics assigns a memory profile to every container in the cluster.
// Unlisted containers get a steady profile derived from their name.
func NewMetrics(c *Cluster, start time.Time) *Metrics {
	special := map[model.ContainerKey]profile{
		{Namespace: "prod", Pod: "checkout-api-7d9f8b6c4-x2k9p", Container: "api"}:       {leak, 150, 512},
		{Namespace: "prod", Pod: "payments-worker-5c6d7f9b8-q8wzn", Container: "worker"}: {leak, 220, 1024},
		{Namespace: "staging", Pod: "search-indexer-0", Container: "indexer"}:            {creeper, 400, 0},
	}
	m := &Metrics{start: start, profiles: map[model.ContainerKey]profile{}}
	for _, p := range c.pods {
		if p.Phase != "Running" {
			continue // nothing is scraped from a pod that is not running
		}
		limits := map[string]float64{}
		for _, s := range p.Specs {
			limits[s.Name] = float64(s.MemoryLimitBytes) / mib
		}
		for _, ct := range p.Containers {
			if detectors.IsInitOnly(ct) {
				continue
			}
			key := model.ContainerKey{Namespace: p.Namespace, Pod: p.Name, Container: ct.Name}
			if sp, ok := special[key]; ok {
				m.profiles[key] = sp
				continue
			}
			// Use the limit from the pod spec, so the chart and the spec agree,
			// and sit at 35-65% of it.
			if limit, ok := limits[ct.Name]; ok && limit > 0 {
				m.profiles[key] = profile{steady, limit * (0.35 + float64(hash(key)%30)/100), limit}
				continue
			}
			base := 80 + float64(hash(key)%320)
			limit, ok := limits[ct.Name]
			if !ok {
				limit = math.Round(base*2/64) * 64
			}
			m.profiles[key] = profile{steady, base, limit}
		}
	}
	return m
}

func hash(k model.ContainerKey) uint32 {
	h := fnv.New32a()
	h.Write([]byte(k.Namespace + "/" + k.Pod + "/" + k.Container))
	return h.Sum32()
}

func (m *Metrics) series(key model.ContainerKey, p profile, lookback, step time.Duration) model.ContainerSeries {
	now := time.Now()
	n := int(lookback/step) + 1
	rng := rand.New(rand.NewSource(int64(hash(key))))
	out := model.ContainerSeries{Key: key, Samples: make([]model.Sample, 0, n)}

	const lifetime = 4 * time.Hour
	// Anchor the sawtooth so the current process started 90 minutes ago when
	// the server started, and keeps cycling every 4 hours after that.
	anchor := m.start.Add(-90 * time.Minute)

	for i := 0; i < n; i++ {
		t := now.Add(-time.Duration(n-1-i) * step)
		var v float64
		switch p.kind {
		case leak:
			age := t.Sub(anchor) % lifetime
			if age < 0 {
				age += lifetime
			}
			frac := float64(age) / float64(lifetime)
			v = p.baseMiB + (p.limitMiB*0.93-p.baseMiB)*frac
			v *= 1 + rng.NormFloat64()*0.008
		case creeper:
			v = p.baseMiB + 6*t.Sub(m.start.Add(-20*time.Hour)).Hours()
			v *= 1 + rng.NormFloat64()*0.006
		default:
			v = p.baseMiB * (1 + rng.NormFloat64()*0.03)
		}
		out.Samples = append(out.Samples, model.Sample{T: t, V: v * mib})
	}
	return out
}

func (m *Metrics) limits(filter func(model.ContainerKey) bool) map[model.ContainerKey]float64 {
	out := map[model.ContainerKey]float64{}
	for k, p := range m.profiles {
		if p.limitMiB > 0 && filter(k) {
			out[k] = p.limitMiB * mib
		}
	}
	return out
}

func (m *Metrics) ContainerMemory(_ context.Context, lookback, step time.Duration) ([]model.ContainerSeries, error) {
	out := make([]model.ContainerSeries, 0, len(m.profiles))
	for k, p := range m.profiles {
		out = append(out, m.series(k, p, lookback, step))
	}
	return out, nil
}

func (m *Metrics) ContainerMemoryLimits(context.Context) (map[model.ContainerKey]float64, error) {
	return m.limits(func(model.ContainerKey) bool { return true }), nil
}

// ContainerMemoryIn is ContainerMemory for the given namespaces only.
func (m *Metrics) ContainerMemoryIn(_ context.Context, namespaces []string, lookback, step time.Duration) ([]model.ContainerSeries, error) {
	in := set(namespaces)
	var out []model.ContainerSeries
	for k, p := range m.profiles {
		if in[k.Namespace] {
			out = append(out, m.series(k, p, lookback, step))
		}
	}
	return out, nil
}

// ContainerMemoryLimitsIn is ContainerMemoryLimits for the given namespaces only.
func (m *Metrics) ContainerMemoryLimitsIn(_ context.Context, namespaces []string) (map[model.ContainerKey]float64, error) {
	in := set(namespaces)
	return m.limits(func(k model.ContainerKey) bool { return in[k.Namespace] }), nil
}

func set(xs []string) map[string]bool {
	out := make(map[string]bool, len(xs))
	for _, x := range xs {
		out[x] = true
	}
	return out
}

func (m *Metrics) PodMemory(_ context.Context, ns, pod string, lookback, step time.Duration) ([]model.ContainerSeries, map[model.ContainerKey]float64, error) {
	var out []model.ContainerSeries
	for k, p := range m.profiles {
		if k.Namespace == ns && k.Pod == pod {
			out = append(out, m.series(k, p, lookback, step))
		}
	}
	return out, m.limits(func(k model.ContainerKey) bool { return k.Namespace == ns && k.Pod == pod }), nil
}
