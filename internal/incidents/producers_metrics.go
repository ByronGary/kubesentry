package incidents

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
	"github.com/ByronGary/kubesentry/internal/snapshot"
)

// MetricsScan finds request spikes, error rates and memory spikes. Each scan
// compares the last SpikeRecent against a SpikeBaseline baseline (offset by
// SpikeRecent) for every RateSource, and each container's working set
// against its memory limit (or, without a limit, against the previous
// scan). A spike's baseline is frozen while it lasts; it ends after EndScans
// scans below EndFraction of its threshold, at the first of them.
//
// Samples map to subjects through the pods (Assoc.PodByName, then the
// controllers' naming schemes for pods already gone) or, for Service-level
// samples, through the Service's endpoints. Pod-level rates are summed per
// subject, and memory is the largest container of a subject's pods with
// the same container name, so a spike is one signal per subject.
type MetricsScan struct {
	o      Options
	rates  []RateSource
	memory MemorySource

	state   map[string]*spike  // signal key → the spike going on
	prevMem map[string]float64 // memory key → bytes at the previous scan
	status  map[string]string  // "requests:<source>", "memory" → "ok" or "error: …"
}

type spike struct {
	sig        Signal
	threshold  float64 // frozen at the start
	below      int
	firstBelow time.Time
}

// NewMetricsScan returns a scanner over the given sources (either may be
// empty or nil).
func NewMetricsScan(o Options, rates []RateSource, memory MemorySource) *MetricsScan {
	o.defaults()
	return &MetricsScan{o: o, rates: rates, memory: memory, state: map[string]*spike{}, prevMem: map[string]float64{}, status: map[string]string{}}
}

// Resume continues the spikes of open incidents (Engine.Active).
func (m *MetricsScan) Resume(active []Signal) {
	for _, s := range active {
		if s.Source != SourceMetrics {
			continue
		}
		key, ok := metricsKey(s.ID, s.Type)
		if !ok {
			continue
		}
		th := 0.0
		if s.Threshold != nil {
			th = *s.Threshold
		}
		m.state[s.Type+"\x00"+key] = &spike{sig: CloneSignal(s), threshold: th}
	}
}

// metricsKey recovers a spike's key from its ID: metrics:<type>:<key>@<unix>.
func metricsKey(id, typ string) (string, bool) {
	rest, ok := strings.CutPrefix(id, SourceMetrics+":"+typ+":")
	if !ok {
		return "", false
	}
	i := strings.LastIndexByte(rest, '@')
	if i < 0 {
		return "", false
	}
	return rest[:i], true
}

// Status reports each source's last scan: "requests:<name>" and "memory".
func (m *MetricsScan) Status() map[string]string {
	out := make(map[string]string, len(m.status))
	for k, v := range m.status {
		out[k] = v
	}
	return out
}

// rateAgg is one subject's requests from one source.
type rateAgg struct {
	subject Subject
	object  model.ObjectRef
	rps     float64
	errRPS  float64
	known   bool // the source reports status codes for it
}

// Scan runs one scan at at.
func (m *MetricsScan) Scan(ctx context.Context, v *snapshot.View, at time.Time) []Signal {
	if v == nil {
		return nil
	}
	at = NormalTime(at)
	th := m.o.Thresholds
	var out []Signal
	seen := map[string]bool{}
	for _, src := range m.rates {
		name := src.Name()
		recent, err := src.Rates(ctx, at, th.SpikeRecent, 0, m.o.Namespaces)
		if err == nil {
			var base []model.RateSample
			base, err = src.Rates(ctx, at, th.SpikeBaseline, th.SpikeRecent, m.o.Namespaces)
			if err == nil {
				m.status["requests:"+name] = "ok"
				r, b := m.aggregate(v, name, recent), m.aggregate(v, name, base)
				keys := map[string]bool{}
				for k := range r {
					keys[k] = true
				}
				for k, s := range m.state {
					if s.sig.Type != TypeMemorySpike && s.sig.Attrs["source"] == name {
						keys[strings.SplitN(k, "\x00", 2)[1]] = true
					}
				}
				for _, k := range sortedKeys(keys) {
					seen[TypeRequestSpike+"\x00"+k], seen[TypeErrorRate+"\x00"+k] = true, true
					cur, ok := r[k]
					if !ok {
						cur = m.aggFromState(k)
					}
					if s := m.requests(k, name, cur, b[k], at); s != nil {
						out = append(out, *s)
					}
					if s := m.errors(k, name, cur, at); s != nil {
						out = append(out, *s)
					}
				}
				continue
			}
		}
		m.status["requests:"+name] = "error: " + err.Error()
	}
	if m.memory != nil {
		samples, err := m.memory.MemoryUsage(ctx, at, m.o.Namespaces)
		if err != nil {
			m.status["memory"] = "error: " + err.Error()
		} else {
			m.status["memory"] = "ok"
			out = append(out, m.memorySpikes(v, samples, at, seen)...)
		}
	}
	// Spikes whose source answered but said nothing about them count as
	// below; a source that failed leaves its spikes as they are (they end
	// as stale if it never recovers).
	for k, s := range m.state {
		if seen[k] || m.status[statusKey(s)] != "ok" {
			continue
		}
		if sig := m.below(k, s, at); sig != nil {
			out = append(out, *sig)
		}
	}
	SortSignals(out)
	return out
}

func statusKey(s *spike) string {
	if s.sig.Type == TypeMemorySpike {
		return "memory"
	}
	return "requests:" + s.sig.Attrs["source"]
}

// aggregate sums samples by subject: pod-level samples per root,
// Service-level ones per Service and root.
func (m *MetricsScan) aggregate(v *snapshot.View, source string, samples []model.RateSample) map[string]*rateAgg {
	out := map[string]*rateAgg{}
	add := func(key string, subj Subject, obj model.ObjectRef, s model.RateSample) {
		a := out[key]
		if a == nil {
			a = &rateAgg{subject: subj, object: obj}
			out[key] = a
		}
		if s.PerSecond > 0 && !math.IsInf(s.PerSecond, 0) {
			a.rps += s.PerSecond
			if s.ErrorRatio >= 0 && s.ErrorRatio <= 1 {
				a.errRPS += s.PerSecond * s.ErrorRatio
				a.known = true
			}
		}
	}
	for _, s := range samples {
		switch {
		case s.Pod != "":
			subj, ok := SubjectOfPod(v, s.Namespace, s.Pod)
			if !ok {
				continue
			}
			obj := model.ObjectRef{Kind: subj.Kind, Namespace: subj.Namespace, Name: subj.Name}
			add(source+"/"+subjKey(subj), subj, obj, s)
		case s.Service != "":
			obj := model.ObjectRef{Kind: "Service", Namespace: s.Namespace, Name: s.Service}
			for _, subj := range SubjectsOfService(v, s.Namespace, s.Service) {
				add(source+"/svc/"+s.Namespace+"/"+s.Service+"/"+subjKey(subj), subj, obj, s)
			}
		}
	}
	return out
}

func subjKey(s Subject) string { return s.Kind + "/" + s.Namespace + "/" + s.Name }

// aggFromState is an empty sample for a spike whose subject sent nothing.
func (m *MetricsScan) aggFromState(k string) *rateAgg {
	for _, typ := range []string{TypeRequestSpike, TypeErrorRate} {
		if s := m.state[typ+"\x00"+k]; s != nil {
			return &rateAgg{subject: s.sig.Subject, object: s.sig.Object}
		}
	}
	return &rateAgg{}
}

func fmtRatio(f float64) string { return strconv.FormatFloat(f, 'f', 2, 64) }

// requests evaluates one subject's request rate against its baseline.
func (m *MetricsScan) requests(key, source string, cur, base *rateAgg, at time.Time) *Signal {
	th := m.o.Thresholds
	sk := TypeRequestSpike + "\x00" + key
	s := m.state[sk]
	baseRPS := 0.0
	if base != nil {
		baseRPS = base.rps
	}
	if s == nil {
		if cur.subject.Name == "" || cur.rps < th.RequestMinRPS || baseRPS <= 0 {
			return nil
		}
		ratio := cur.rps / baseRPS
		if ratio < th.RequestRatio {
			return nil
		}
		threshold := baseRPS * th.RequestRatio
		s = &spike{threshold: threshold, sig: Signal{
			ID: fmt.Sprintf("%s:%s:%s@%d", SourceMetrics, TypeRequestSpike, key, at.Unix()), Type: TypeRequestSpike, Source: SourceMetrics,
			Role: Trigger, Severity: Warning, Start: at, Subject: cur.subject, Object: cur.object,
			Baseline: floatPtr(baseRPS), Threshold: floatPtr(threshold),
			Attrs: map[string]string{"source": source, "window": m.o.Thresholds.SpikeRecent.String(), "baselineWindow": m.o.Thresholds.SpikeBaseline.String()},
		}}
		m.state[sk] = s
	}
	base0 := s.threshold / th.RequestRatio
	if cur.rps < th.EndFraction*s.threshold {
		return m.below(sk, s, at)
	}
	s.below = 0
	ratio := cur.rps / base0
	switch {
	case ratio >= th.RequestCritRatio:
		s.sig.Severity = Critical
	case ratio >= th.RequestRatio:
		s.sig.Severity = Warning
	}
	if s.sig.Value == nil || cur.rps > *s.sig.Value {
		s.sig.Value = floatPtr(cur.rps)
		s.sig.Attrs["ratio"] = fmtRatio(ratio)
	}
	s.sig.Title = fmt.Sprintf("%s requests at %.1f/s, %sx the baseline of %.1f/s", objectName(s.sig.Object), *s.sig.Value, s.sig.Attrs["ratio"], base0)
	c := CloneSignal(s.sig)
	return &c
}

// errors evaluates one subject's 5xx share.
func (m *MetricsScan) errors(key, source string, cur *rateAgg, at time.Time) *Signal {
	th := m.o.Thresholds
	sk := TypeErrorRate + "\x00" + key
	s := m.state[sk]
	ratio := 0.0
	if cur.known && cur.rps > 0 {
		ratio = cur.errRPS / cur.rps
	}
	if s == nil {
		if !cur.known || cur.subject.Name == "" || cur.rps < th.RequestMinRPS || ratio < th.ErrorRatio {
			return nil
		}
		s = &spike{threshold: th.ErrorRatio, sig: Signal{
			ID: fmt.Sprintf("%s:%s:%s@%d", SourceMetrics, TypeErrorRate, key, at.Unix()), Type: TypeErrorRate, Source: SourceMetrics,
			Role: Trigger, Severity: Warning, Start: at, Subject: cur.subject, Object: cur.object, Threshold: floatPtr(th.ErrorRatio),
			Attrs: map[string]string{"source": source},
		}}
		m.state[sk] = s
	}
	if !cur.known || ratio < th.EndFraction*s.threshold {
		return m.below(sk, s, at)
	}
	s.below = 0
	switch {
	case ratio >= th.ErrorCritRatio:
		s.sig.Severity = Critical
	case ratio >= th.ErrorRatio:
		s.sig.Severity = Warning
	}
	if s.sig.Value == nil || ratio > *s.sig.Value {
		s.sig.Value = floatPtr(ratio)
		s.sig.Attrs["rps"] = fmtRatio(cur.rps)
	}
	s.sig.Title = fmt.Sprintf("%s: %.0f%% of requests failed", objectName(s.sig.Object), *s.sig.Value*100)
	c := CloneSignal(s.sig)
	return &c
}

// below counts a scan under the end threshold; the spike ends at the
// first of EndScans such scans in a row.
func (m *MetricsScan) below(sk string, s *spike, at time.Time) *Signal {
	s.below++
	if s.below == 1 {
		s.firstBelow = at
	}
	if s.below < m.o.Thresholds.EndScans {
		c := CloneSignal(s.sig)
		return &c
	}
	s.sig.End = timePtr(s.firstBelow)
	delete(m.state, sk)
	c := CloneSignal(s.sig)
	return &c
}

func objectName(o model.ObjectRef) string {
	if o.Kind == "" {
		return o.Name
	}
	return o.Kind + " " + o.Name
}

// memAgg is the largest working set of one container name across a
// subject's pods.
type memAgg struct {
	subject   Subject
	pod       *model.Pod
	container string
	bytes     float64
	limit     float64
}

// memoryLimit is a container's limit: the one the kubelet applied (it
// follows in-place resizes), else the spec's; 0 without one.
func memoryLimit(p *model.Pod, container string) float64 {
	for _, c := range p.Containers {
		if c.Name == container && c.MemoryLimitBytes > 0 {
			return float64(c.MemoryLimitBytes)
		}
	}
	for _, s := range p.Specs {
		if s.Name == container && s.MemoryLimitBytes > 0 {
			return float64(s.MemoryLimitBytes)
		}
	}
	return 0
}

func (m *MetricsScan) memorySpikes(v *snapshot.View, samples []model.MemorySample, at time.Time, seen map[string]bool) []Signal {
	th := m.o.Thresholds
	a := v.Assoc()
	aggs := map[string]*memAgg{}
	for _, s := range samples {
		p, ok := a.PodByName(s.Namespace, s.Pod)
		if !ok || s.Container == "" || s.Bytes <= 0 || math.IsInf(s.Bytes, 0) || math.IsNaN(s.Bytes) {
			continue
		}
		subj := subjectOfPod(a, p)
		key := subjKey(subj) + "/" + s.Container
		limit := memoryLimit(p, s.Container)
		g := aggs[key]
		// The fullest container wins: by share of its limit, else by bytes.
		if g == nil || share(s.Bytes, limit) > share(g.bytes, g.limit) {
			aggs[key] = &memAgg{subject: subj, pod: p, container: s.Container, bytes: s.Bytes, limit: limit}
		}
	}
	var out []Signal
	keys := make([]string, 0, len(aggs))
	for k := range aggs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		g := aggs[key]
		sk := TypeMemorySpike + "\x00" + key
		seen[sk] = true
		prev, hadPrev := m.prevMem[key]
		m.prevMem[key] = g.bytes
		s := m.state[sk]
		if s == nil {
			var threshold float64
			sev := Warning
			switch {
			case g.limit > 0:
				pct := g.bytes / g.limit * 100
				if pct < th.MemoryPct {
					continue
				}
				threshold = g.limit * th.MemoryPct / 100
			case hadPrev && prev > 0 && g.bytes >= th.MemoryJumpRatio*prev && g.bytes-prev >= th.MemoryJumpMin:
				threshold = prev * th.MemoryJumpRatio
			default:
				continue
			}
			s = &spike{threshold: threshold, sig: Signal{
				ID: fmt.Sprintf("%s:%s:%s@%d", SourceMetrics, TypeMemorySpike, key, at.Unix()), Type: TypeMemorySpike, Source: SourceMetrics,
				Role: Trigger, Severity: sev, Start: at, Subject: g.subject, Object: podRef(g.pod), Threshold: floatPtr(threshold),
				Attrs: map[string]string{"container": g.container, "pod": g.pod.Name},
			}}
			if g.limit > 0 {
				s.sig.Attrs["limit"] = strconv.FormatFloat(g.limit, 'f', 0, 64)
			} else {
				s.sig.Baseline = floatPtr(prev)
			}
			m.state[sk] = s
		}
		if g.bytes < th.EndFraction*s.threshold {
			if sig := m.below(sk, s, at); sig != nil {
				out = append(out, *sig)
			}
			continue
		}
		s.below = 0
		if g.limit > 0 {
			pct := g.bytes / g.limit * 100
			switch {
			case pct >= th.MemoryCritPct:
				s.sig.Severity = Critical
			case pct >= th.MemoryPct:
				s.sig.Severity = Warning
			}
		}
		if s.sig.Value == nil || g.bytes > *s.sig.Value {
			s.sig.Value = floatPtr(g.bytes)
			s.sig.Attrs["pod"] = g.pod.Name
		}
		if g.limit > 0 {
			s.sig.Title = fmt.Sprintf("%s/%s at %.0f%% of its memory limit", s.sig.Attrs["pod"], g.container, *s.sig.Value/g.limit*100)
		} else {
			s.sig.Title = fmt.Sprintf("%s/%s memory jumped to %s (no limit)", s.sig.Attrs["pod"], g.container, mib(*s.sig.Value))
		}
		out = append(out, CloneSignal(s.sig))
	}
	for k := range m.prevMem {
		if aggs[k] == nil {
			delete(m.prevMem, k)
		}
	}
	return out
}

func share(bytes, limit float64) float64 {
	if limit > 0 {
		return bytes / limit * 1e12 // any share of a limit outranks raw bytes
	}
	return bytes
}

func mib(b float64) string { return strconv.FormatFloat(b/(1<<20), 'f', 0, 64) + " MiB" }
