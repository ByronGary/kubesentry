package api

import (
	"context"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/auth"
	"github.com/ByronGary/kubesentry/internal/incidents"
	"github.com/ByronGary/kubesentry/internal/model"
)

// fakeLogs is a log source that writes one line per pod, carrying a secret
// the runner must redact.
type fakeLogs struct{ calls atomic.Int32 }

func (*fakeLogs) Name() string { return "kubernetes" }

func (f *fakeLogs) Logs(_ context.Context, q incidents.LogQuery) (incidents.LogResult, error) {
	f.calls.Add(1)
	var res incidents.LogResult
	for _, p := range q.Pods {
		res.Lines = append(res.Lines, incidents.LogLine{Time: q.From.Add(time.Minute), Pod: p, Container: "web", Level: "error",
			Text: "db login failed password=hunter2", Source: "kubernetes"})
	}
	return res, nil
}

// fakeSeries draws one memory line per pod.
type fakeSeries struct{}

func (fakeSeries) SubjectSeries(_ context.Context, q incidents.SeriesQuery) ([]incidents.Series, error) {
	var out []incidents.Series
	for _, p := range q.Pods {
		out = append(out, incidents.Series{Metric: "memory", Label: p + "/web", Unit: "bytes", Source: "prometheus",
			Points: [][2]float64{{float64(q.From.UnixMilli()), 1 << 20}, {float64(q.To.UnixMilli()), 2 << 20}}})
	}
	return out, nil
}

func f64(v float64) *float64 { return &v }

// tenantIncidents is, in every tenant namespace, an open critical incident
// on Deployment web (an OOM kill, a request spike, an audit change and a
// CloudTrail change, with a pod event and a node event), a warning one
// resolved two hours ago and one resolved three days ago (off the board);
// plus an open incident on node n1. It serves them from s, reading audit
// events from s's audit store.
func withTenantIncidents(t *testing.T, s *Server) (*Server, *fakeLogs) {
	t.Helper()
	ctx := context.Background()
	store, evs := incidents.NewMemoryStore(), incidents.NewMemoryEventStore()
	owners := map[string]string{"team-a": "team-alpha", "team-b": "team-beta", "kube-system": "platform"}
	var c incidents.Commit
	c.Signals = map[string][]incidents.Signal{}
	add := func(in incidents.Incident, sigs ...incidents.Signal) {
		in.ID = incidents.IncidentID(in.Subject, in.Start)
		in.Types, in.Counts = []string{}, map[string]int{}
		for _, sg := range sigs {
			if in.Counts[sg.Type] == 0 {
				in.Types = append(in.Types, sg.Type)
			}
			in.Counts[sg.Type]++
		}
		in.LastSignal = in.Start
		c.Incidents = append(c.Incidents, in)
		c.Signals[in.ID] = sigs
	}
	for _, ns := range tenants {
		subj := incidents.Subject{Kind: "Deployment", Namespace: ns, Name: "web"}
		pod := model.ObjectRef{Kind: "Pod", Namespace: ns, Name: "web-1"}
		tags := map[string]string{"app": "web", incidents.TagApp: "web", incidents.TagService: "web", "app.kubernetes.io/part-of": "shop"}
		start := now.Add(-time.Hour)
		sig := func(id, typ, src string, role incidents.Role, sev incidents.Severity, at time.Time, obj model.ObjectRef, title string) incidents.Signal {
			return incidents.Signal{ID: id + ":" + ns, Type: typ, Source: src, Role: role, Severity: sev, Start: at, Subject: subj, Object: obj, Title: title}
		}
		oom := sig("view:oom-kill", incidents.TypeOOMKill, incidents.SourceView, incidents.Trigger, incidents.Critical, start, pod, "web-1/web was OOM killed")
		spike := sig("metrics:request-spike", incidents.TypeRequestSpike, incidents.SourceMetrics, incidents.Trigger, incidents.Warning, start.Add(time.Minute),
			model.ObjectRef{Kind: "Service", Namespace: ns, Name: "web"}, "web requests at 40/s")
		spike.Value, spike.Baseline, spike.Threshold = f64(40), f64(10), f64(20)
		aud := sig("audit:a1", incidents.TypeAuditChange, incidents.SourceAudit, incidents.Context, "", start.Add(-10*time.Minute),
			model.ObjectRef{Kind: "ConfigMap", Namespace: ns, Name: "web-config"}, "dave patched configmaps "+ns+"/web-config")
		ct := sig("cloudtrail:ct1", incidents.TypeCloudTrailChange, incidents.SourceCloudTrail, incidents.Context, "", start.Add(5*time.Minute),
			model.ObjectRef{Kind: "AWS::EC2::SecurityGroup", Name: "sg-0abc"}, "erin called ec2:AuthorizeSecurityGroupIngress on sg-0abc")
		ct.Attrs = map[string]string{"eventID": "ct1", "eventName": "AuthorizeSecurityGroupIngress", "actor": "erin", "raw": `{"token":"password=hunter2"}`}
		add(incidents.Incident{Subject: subj, Title: "web: OOM kill, request spike", Severity: incidents.Critical, PeakSeverity: incidents.Critical,
			State: incidents.Open, Start: start, Owner: owners[ns], Tags: tags, Services: []string{"web"}, Pods: []string{"web-1"}, Nodes: []string{"n1"}},
			oom, spike, aud, ct)

		end := now.Add(-2 * time.Hour)
		add(incidents.Incident{Subject: subj, Title: "web: error rate", Severity: incidents.Warning, PeakSeverity: incidents.Warning,
			State: incidents.Resolved, Start: end.Add(-30 * time.Minute), End: &end, Owner: owners[ns], Tags: tags, Services: []string{"web"}, Pods: []string{"web-0"}},
			sig("metrics:error-rate", incidents.TypeErrorRate, incidents.SourceMetrics, incidents.Trigger, incidents.Warning, end.Add(-30*time.Minute),
				model.ObjectRef{Kind: "Service", Namespace: ns, Name: "web"}, "web: 8% of requests failed"))

		old := now.Add(-72 * time.Hour)
		add(incidents.Incident{Subject: subj, Title: "web: crash loop", Severity: incidents.Critical, PeakSeverity: incidents.Critical,
			State: incidents.Resolved, Start: old.Add(-time.Hour), End: &old, Owner: owners[ns], Tags: tags, Pods: []string{"web-2"}},
			sig("view:crashloop", incidents.TypeCrashLoop, incidents.SourceView, incidents.Trigger, incidents.Critical, old.Add(-time.Hour), pod, "web-1/web is crash-looping"))

		if err := evs.AddEvents(ctx, []incidents.StoredEvent{
			{KubeEvent: model.KubeEvent{UID: "ev-pod-" + ns, Namespace: ns, Type: "Warning", Reason: "BackOff", Message: "Back-off restarting failed container web token=s3cr3t",
				Count: 5, FirstSeen: start, LastSeen: start.Add(5 * time.Minute), Regarding: pod}, Subject: &subj},
			{KubeEvent: model.KubeEvent{UID: "ev-node-" + ns, Type: "Warning", Reason: "OOMKilling", Message: "Memory cgroup out of memory: Killed process 42 (web)",
				Count: 1, FirstSeen: start, LastSeen: start, Regarding: model.ObjectRef{Kind: "Node", Name: "n1"}}, Subject: &subj},
		}); err != nil {
			t.Fatal(err)
		}
	}
	node := incidents.Subject{Kind: incidents.KindNode, Name: "n1"}
	add(incidents.Incident{Subject: node, Title: "n1: eviction", Severity: incidents.Warning, PeakSeverity: incidents.Warning,
		State: incidents.Open, Start: now.Add(-30 * time.Minute), Owner: "platform", Nodes: []string{"n1"}},
		incidents.Signal{ID: "view:eviction:n1", Type: incidents.TypeEviction, Source: incidents.SourceView, Role: incidents.Trigger,
			Severity: incidents.Warning, Start: now.Add(-30 * time.Minute), Subject: node, Object: model.ObjectRef{Kind: "Node", Name: "n1"}, Title: "pods evicted from n1"})
	if err := store.Commit(ctx, c); err != nil {
		t.Fatal(err)
	}
	logs := &fakeLogs{}
	r, err := incidents.NewRunner(incidents.Config{Store: store, Events: evs, Series: fakeSeries{}, Logs: []incidents.LogSource{logs},
		Audit: s.auditStore(), Options: incidents.Options{Now: func() time.Time { return now }}})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Refresh(ctx, store, true); err != nil {
		t.Fatal(err)
	}
	s.Incidents, s.IncidentStore = r, store
	return s, logs
}

// incidentsServer is tenantServer with its incidents.
func incidentsServer(t *testing.T) (*Server, *fakeLogs) {
	t.Helper()
	return withTenantIncidents(t, tenantServer(t))
}

func webSubject(ns string) incidents.Subject {
	return incidents.Subject{Kind: "Deployment", Namespace: ns, Name: "web"}
}

// incidentID is the ID of the open web incident in ns.
func incidentID(ns string) string { return incidents.IncidentID(webSubject(ns), now.Add(-time.Hour)) }

// resolvedID is the ID of the web incident in ns resolved two hours ago.
func resolvedID(ns string) string {
	return incidents.IncidentID(webSubject(ns), now.Add(-2*time.Hour-30*time.Minute))
}

var nodeIncidentID = incidents.IncidentID(incidents.Subject{Kind: incidents.KindNode, Name: "n1"}, now.Add(-30*time.Minute))

// regrant serves s with the tenant grants plus extra.
func regrant(s *Server, extra ...string) {
	g := tenantGrants()
	for _, k := range extra {
		g[k] = true
	}
	s.Authorizer = &auth.SARAuthorizer{Reviewer: g, Candidates: s.Authorizer.(*auth.SARAuthorizer).Candidates}
}

func ids(r incidentsResponse) []string {
	var out []string
	for _, in := range r.Items {
		out = append(out, in.ID)
	}
	return out
}

func hasType(in incidents.Incident, typ string) bool {
	for _, t := range in.Types {
		if t == typ {
			return true
		}
	}
	return in.Counts[typ] > 0
}

func rfc(t time.Time) string { return url.QueryEscape(t.Format(time.RFC3339)) }
