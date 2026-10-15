package incidents

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
)

// LogErrors counts error lines in the logs of open incidents and reports
// bursts as log-errors context: at least LogBurstRatio times the error rate
// before the incident and at least LogBurstMin lines a minute. It reads at
// most LogErrorsMax incidents a run (the worst and newest first), at most
// 10 pods each, and keeps counts only: no line is stored.
type LogErrors struct {
	src LogSource
	o   Options

	before map[string]float64   // incident ID → error lines a minute before it started
	last   map[string]time.Time // incident ID → end of the last count
	burst  map[string]*Signal   // incident ID → the burst going on
}

// beforeSpan is how far before an incident its usual error rate is read.
const beforeSpan = 15 * time.Minute

// NewLogErrors returns a counter reading src.
func NewLogErrors(src LogSource, o Options) *LogErrors {
	o.defaults()
	return &LogErrors{src: src, o: o, before: map[string]float64{}, last: map[string]time.Time{}, burst: map[string]*Signal{}}
}

// Resume continues the bursts of open incidents (Engine.Active).
func (p *LogErrors) Resume(active []Signal) {
	for _, s := range active {
		if s.Type == TypeLogErrors && s.Source == SourceLogs && s.Attrs["incident"] != "" {
			c := CloneSignal(s)
			p.burst[s.Attrs["incident"]] = &c
		}
	}
}

// Scan counts the error lines of the open incidents since the last run.
func (p *LogErrors) Scan(ctx context.Context, open []Incident, now time.Time) ([]Signal, error) {
	now = NormalTime(now)
	th := p.o.Thresholds
	cands := make([]Incident, 0, len(open))
	isOpen := map[string]bool{}
	for _, in := range open {
		if in.State != Open {
			continue
		}
		isOpen[in.ID] = true
		if in.Subject.Namespace != "" && len(in.Pods) > 0 {
			cands = append(cands, in)
		}
	}
	sort.Slice(cands, func(i, j int) bool {
		if r1, r2 := sevRank(cands[i].Severity), sevRank(cands[j].Severity); r1 != r2 {
			return r1 < r2
		}
		return Newer(&cands[i], &cands[j])
	})
	if len(cands) > p.o.LogErrorsMax {
		cands = cands[:p.o.LogErrorsMax]
	}
	var out []Signal
	var firstErr error
	for _, in := range cands {
		pods := in.Pods
		if len(pods) > 10 {
			pods = pods[:10]
		}
		q := LogQuery{Namespace: in.Subject.Namespace, Pods: pods, Level: "error", Limit: p.o.LogsMaxLines, MaxBytes: p.o.LogsMaxBytes}
		base, ok := p.before[in.ID]
		if !ok {
			q.From, q.To = in.Start.Add(-beforeSpan), in.Start
			res, err := p.src.Logs(ctx, q)
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			base = float64(len(res.Lines)) / beforeSpan.Minutes()
			p.before[in.ID] = base
		}
		from := p.last[in.ID]
		if from.IsZero() || from.Before(in.Start) {
			from = in.Start
		}
		if earliest := now.Add(-p.o.LogsEvery); from.Before(earliest) {
			from = earliest
		}
		if !now.After(from) {
			continue
		}
		q.From, q.To = from, now
		res, err := p.src.Logs(ctx, q)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		p.last[in.ID] = now
		n := len(res.Lines)
		rate := float64(n) / now.Sub(from).Minutes()
		threshold := max(th.LogBurstMin, base*th.LogBurstRatio)
		s := p.burst[in.ID]
		switch {
		case rate >= threshold && s == nil:
			s = &Signal{ID: fmt.Sprintf("%s:%s:%s@%d", SourceLogs, TypeLogErrors, in.ID, from.Unix()), Type: TypeLogErrors, Source: SourceLogs,
				Role: Context, Start: from, Subject: in.Subject,
				Object:   model.ObjectRef{Kind: in.Subject.Kind, Namespace: in.Subject.Namespace, Name: in.Subject.Name},
				Baseline: floatPtr(base), Threshold: floatPtr(threshold), Value: floatPtr(rate), Count: n,
				Attrs: map[string]string{"incident": in.ID, "source": p.src.Name()}}
			p.burst[in.ID] = s
		case rate >= threshold:
			s.Count += n
			if s.Value == nil || rate > *s.Value {
				s.Value = floatPtr(rate)
			}
		case s != nil:
			s.End = timePtr(from)
			out = append(out, CloneSignal(*s))
			delete(p.burst, in.ID)
			continue
		default:
			continue
		}
		if res.Truncated {
			s.Attrs["truncated"] = "true"
		}
		s.Title = fmt.Sprintf("%d error log lines, up to %.0f a minute (%.1f before the incident)", s.Count, *s.Value, base)
		out = append(out, CloneSignal(*s))
	}
	for id, s := range p.burst {
		if !isOpen[id] {
			s.End = timePtr(now)
			out = append(out, CloneSignal(*s))
			delete(p.burst, id)
		}
	}
	for id := range p.before {
		if !isOpen[id] {
			delete(p.before, id)
			delete(p.last, id)
		}
	}
	SortSignals(out)
	return out, firstErr
}
