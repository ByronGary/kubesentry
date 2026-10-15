// Package incidentstest generates random store operations for
// incidents.Store and incidents.EventStore implementations. The memory
// stores' tests and the Postgres parity tests (internal/pgstore
// TestPGIncidentsMatchMemory, TestPGEventsMatchMemory) share it.
package incidentstest

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/ByronGary/kubesentry/internal/incidents"
	"github.com/ByronGary/kubesentry/internal/model"
)

// Base is the reference time random data is spread after.
var Base = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

var (
	namespaces = []string{"", "shop", "team-a", "zoë"}
	kinds      = []string{"Deployment", "StatefulSet", "CronJob", "Pod", incidents.KindNode}
	names      = []string{"api", "db", "web-ünï", "worker", "node-1"}
	owners     = []string{"", "payments", "platform", "team \"a\""}
	types      = []string{incidents.TypeRequestSpike, incidents.TypeMemorySpike, incidents.TypeOOMKill, incidents.TypeRestart,
		incidents.TypeKubeEvent, incidents.TypeDeploy, incidents.TypeAuditChange, incidents.TypeCloudTrailChange, incidents.TypeAlert}
	services = []string{"api", "api-canary", "db", "web"}
	tagVals  = []string{"api", "store", "web", "ünï"}
	reasons  = []string{"BackOff", "Unhealthy", "OOMKilling", "FailedMount"}
)

func pick[T any](rng *rand.Rand, l []T) T { return l[rng.Intn(len(l))] }

// at is about step minutes after Base, with sub-microsecond noise sometimes
// (the stores must drop it alike).
func at(rng *rand.Rand, step int) time.Time {
	t := Base.Add(time.Duration(step) * time.Minute).Add(time.Duration(rng.Intn(60_000_000)) * time.Microsecond)
	if rng.Intn(4) == 0 {
		t = t.Add(time.Duration(rng.Intn(1000)))
	}
	return t
}

func subject(rng *rand.Rand) incidents.Subject {
	k := pick(rng, kinds)
	ns := pick(rng, namespaces)
	if k == incidents.KindNode {
		ns = ""
	}
	return incidents.Subject{Kind: k, Namespace: ns, Name: pick(rng, names)}
}

// ID is one of a few incident IDs per subject, so later commits update
// earlier incidents.
func ID(rng *rand.Rand) (string, incidents.Subject, time.Time) {
	s := subject(rng)
	start := Base.Add(time.Duration(rng.Intn(6)) * 4 * time.Hour)
	return incidents.IncidentID(s, start), s, start
}

// Incident returns a random incident around step.
func Incident(rng *rand.Rand, step int) incidents.Incident {
	id, s, start := ID(rng)
	now := at(rng, step)
	in := incidents.Incident{ID: id, Subject: s, Title: fmt.Sprintf("%s: ünï \"spike\" %d", s.Name, rng.Intn(9)),
		Severity: pick(rng, []incidents.Severity{incidents.Warning, incidents.Critical}), State: incidents.Open,
		Start: start.Add(time.Duration(rng.Intn(1000)) * time.Microsecond), LastSignal: now, Owner: pick(rng, owners),
		Production: rng.Intn(3) == 0, Counts: map[string]int{}}
	in.PeakSeverity = in.Severity
	if rng.Intn(2) == 0 {
		in.PeakSeverity = incidents.Critical
	}
	if rng.Intn(2) == 0 {
		in.State = incidents.Resolved
		end := in.Start.Add(time.Duration(rng.Intn(48*60)) * time.Minute).Add(time.Duration(rng.Intn(1000)))
		in.End = &end
		in.Capped = rng.Intn(5) == 0
	}
	if rng.Intn(4) == 0 {
		prev, _, _ := ID(rng)
		in.Previous = prev
	}
	if rng.Intn(4) > 0 {
		in.Tags = map[string]string{incidents.TagApp: pick(rng, tagVals)}
		if rng.Intn(2) == 0 {
			in.Tags["app.kubernetes.io/part-of"] = pick(rng, tagVals)
		}
		if rng.Intn(3) == 0 {
			in.Tags[incidents.TagService] = pick(rng, services)
		}
	}
	for n := rng.Intn(3); n > 0; n-- {
		in.Services = append(in.Services, pick(rng, services))
	}
	for n := rng.Intn(4); n > 0; n-- {
		in.Pods = append(in.Pods, fmt.Sprintf("%s-%d", s.Name, rng.Intn(5)))
	}
	for n := rng.Intn(3); n > 0; n-- {
		in.Nodes = append(in.Nodes, fmt.Sprintf("node-%d", rng.Intn(3)))
	}
	for n := 1 + rng.Intn(3); n > 0; n-- {
		t := pick(rng, types)
		if in.Counts[t] == 0 {
			in.Types = append(in.Types, t)
		}
		in.Counts[t] += 1 + rng.Intn(5)
	}
	return in
}

// Signal returns a random signal of an incident about s, around step.
func Signal(rng *rand.Rand, s incidents.Subject, step int) incidents.Signal {
	t := pick(rng, types)
	sig := incidents.Signal{ID: fmt.Sprintf("%s:%s:%d", t, s.Name, rng.Intn(8)), Type: t, Source: pick(rng, []string{incidents.SourceView,
		incidents.SourceMetrics, incidents.SourceEvents, incidents.SourceCloudTrail}), Role: incidents.Context, Start: at(rng, step),
		Subject: s, Object: model.ObjectRef{Kind: pick(rng, []string{"Pod", "Service", "AWS::EC2::SecurityGroup"}), Namespace: s.Namespace,
			Name: pick(rng, names), UID: pick(rng, []string{"", "uid-1"})},
		Title: fmt.Sprintf("%s on %s: «%d»", t, s.Name, rng.Intn(100)), Count: rng.Intn(4)}
	if rng.Intn(2) == 0 {
		sig.Role, sig.Severity = incidents.Trigger, pick(rng, []incidents.Severity{incidents.Warning, incidents.Critical})
	}
	if rng.Intn(2) == 0 {
		end := sig.Start.Add(time.Duration(rng.Intn(600)) * time.Second)
		sig.End = &end
	}
	if rng.Intn(2) == 0 {
		v := rng.Float64() * 1e9
		sig.Value = &v
	}
	if rng.Intn(3) == 0 {
		b, th := rng.Float64()*100, 0.05+rng.Float64()
		sig.Baseline, sig.Threshold = &b, &th
	}
	if rng.Intn(2) == 0 {
		sig.Attrs = map[string]string{"reason": pick(rng, reasons), "ratio": fmt.Sprintf("%.2f", rng.Float64()*5)}
	}
	if rng.Intn(3) == 0 {
		sig.Tags = map[string]string{incidents.TagApp: pick(rng, tagVals)}
	}
	return sig
}

// Commit returns a random commit at about step steps after Base: a few
// incidents with signals (IDs repeat across commits, so later ones update
// earlier ones), sometimes a checkpoint.
func Commit(rng *rand.Rand, step int) incidents.Commit {
	c := incidents.Commit{Signals: map[string][]incidents.Signal{}}
	seen := map[string]bool{}
	for n := rng.Intn(4); n > 0; n-- {
		in := Incident(rng, step)
		if seen[in.ID] {
			continue
		}
		seen[in.ID] = true
		c.Incidents = append(c.Incidents, in)
		for k := rng.Intn(4); k > 0; k-- {
			c.Signals[in.ID] = append(c.Signals[in.ID], Signal(rng, in.Subject, step))
		}
	}
	if rng.Intn(3) == 0 {
		c.Checkpoints = map[string][]byte{pick(rng, []string{"incidents/audit", "incidents/cloudtrail"}): []byte(fmt.Sprintf(`{"step":%d}`, step))}
	}
	return c
}

// Query returns a random incident query around step.
func Query(rng *rand.Rand, step int) incidents.Query {
	var q incidents.Query
	if rng.Intn(2) == 0 {
		q.From = at(rng, step-rng.Intn(24*60))
	}
	if rng.Intn(3) == 0 {
		q.To = at(rng, step-rng.Intn(12*60))
	}
	switch rng.Intn(6) {
	case 0:
		q.Severity = incidents.Critical
	case 1:
		q.Severity = incidents.Warning
	}
	if rng.Intn(4) == 0 {
		q.Types = []string{pick(rng, types), pick(rng, types)}
	}
	switch rng.Intn(5) {
	case 0:
		q.State = incidents.Open
	case 1:
		q.State = incidents.Resolved
	}
	switch rng.Intn(4) {
	case 0:
		q.Namespaces = map[string]bool{}
	case 1:
		q.Namespaces = map[string]bool{pick(rng, namespaces[1:]): true, pick(rng, namespaces[1:]): true}
	}
	q.ClusterScoped = rng.Intn(2) == 0
	if rng.Intn(6) == 0 {
		q.Owner = pick(rng, owners[1:])
	}
	if rng.Intn(6) == 0 {
		q.App = pick(rng, tagVals)
	}
	if rng.Intn(6) == 0 {
		q.Service = pick(rng, services)
	}
	if rng.Intn(6) == 0 {
		q.Tags = map[string]string{"app.kubernetes.io/part-of": pick(rng, tagVals)}
	}
	if rng.Intn(2) == 0 {
		q.Limit = 1 + rng.Intn(10)
	}
	return q
}

// Event returns a random Kubernetes event around step (UIDs repeat, so
// later reports update earlier ones).
func Event(rng *rand.Rand, step int) incidents.StoredEvent {
	last := at(rng, step)
	first := last.Add(-time.Duration(rng.Intn(3600)) * time.Second)
	ns := pick(rng, namespaces)
	e := incidents.StoredEvent{KubeEvent: model.KubeEvent{UID: fmt.Sprintf("uid-%d", rng.Intn(40)), Namespace: ns,
		Type: pick(rng, []string{"Warning", "Normal"}), Reason: pick(rng, reasons), Message: fmt.Sprintf("back-off «%d» restarting", rng.Intn(9)),
		Count: int32(1 + rng.Intn(20)), FirstSeen: first, LastSeen: last,
		Regarding: model.ObjectRef{Kind: pick(rng, []string{"Pod", "Node"}), Namespace: ns, Name: pick(rng, names), UID: pick(rng, []string{"", "u1"})},
		Source:    pick(rng, []string{"kubelet", "default-scheduler", ""})}}
	if rng.Intn(3) > 0 {
		s := subject(rng)
		e.Subject = &s
	}
	return e
}

// EventQuery returns a random event query around step.
func EventQuery(rng *rand.Rand, step int) incidents.EventQuery {
	var q incidents.EventQuery
	if rng.Intn(2) == 0 {
		q.Namespace = pick(rng, namespaces[1:])
	}
	if rng.Intn(3) == 0 {
		s := subject(rng)
		q.Subject = &s
	}
	if rng.Intn(4) == 0 {
		o := model.ObjectRef{Kind: pick(rng, []string{"Pod", "Node"}), Namespace: pick(rng, namespaces), Name: pick(rng, names)}
		if rng.Intn(2) == 0 {
			o.UID = "u1"
		}
		q.Object = &o
	}
	if rng.Intn(2) == 0 {
		q.From = at(rng, step-rng.Intn(120))
	}
	if rng.Intn(2) == 0 {
		q.To = at(rng, step-rng.Intn(60))
	}
	if rng.Intn(2) == 0 {
		q.Limit = 1 + rng.Intn(20)
	}
	return q
}
