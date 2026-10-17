package investigate_test

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/incidents"
	"github.com/ByronGary/kubesentry/internal/investigate"
	"github.com/ByronGary/kubesentry/internal/model"
)

// t0 is the incident start; the run happens at t0+40m, after the incident
// (resolved at t0+20m) and its padded window [t0-5m, t0+30m].
var t0 = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

func at(min float64) time.Time { return t0.Add(time.Duration(min * float64(time.Minute))) }

func now() time.Time { return at(40) }

func fptr(f float64) *float64 { return &f }

var (
	apiSubject = incidents.Subject{Kind: "Deployment", Namespace: "shop", Name: "api"}
	allAccess  = investigate.Access{Logs: true, Audit: true, CloudTrail: true, Nodes: true}
)

// fakeSource serves one incident from plain data, the way incidents.Runner
// would (Bundle builds a real bundle), and counts every call.
type fakeSource struct {
	mu       sync.Mutex
	calls    map[string]int
	in       incidents.Incident
	signals  []incidents.Signal
	logs     []incidents.LogLine
	series   []incidents.Series
	events   []incidents.StoredEvent
	audit    []audit.Event
	state    *investigate.WorkloadState
	from, to time.Time
	red      *incidents.Redactor
	logErr   error
	// raw makes the source hostile: nothing it returns is redacted, so
	// only the investigator's egress filter stands between it and the model.
	raw bool
	// lastLogs is the newest log request.
	lastLogs incidents.LogRequest
}

func (f *fakeSource) count(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	f.calls[name]++
}

func (f *fakeSource) Calls(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[name]
}

func (f *fakeSource) Get(_ context.Context, id string) (incidents.Incident, []incidents.Signal, bool, error) {
	f.count("Get")
	if id != f.in.ID {
		return incidents.Incident{}, nil, false, nil
	}
	return f.in, f.signals, true, nil
}

func (f *fakeSource) Bundle(_ context.Context, id string, req incidents.BundleRequest) (*incidents.Bundle, error) {
	f.count("Bundle")
	if id != f.in.ID {
		return nil, incidents.ErrNotFound
	}
	skip := func(s string) bool { _, ok := req.Omitted[s]; return ok }
	if f.raw {
		b := &incidents.Bundle{BundleHeader: incidents.BundleHeader{Schema: incidents.BundleSchema, GeneratedAt: now(), Cluster: req.Cluster,
			Incident: f.in, Window: incidents.BundleWindow{From: f.from, To: f.to}, Omitted: req.Omitted}}
		for i := range f.signals {
			b.Signals = append(b.Signals, incidents.BundleSignalOf(f.signals[i]))
			if f.signals[i].Type == incidents.TypeCloudTrailChange && !skip(incidents.SectionCloudTrail) {
				b.CloudTrail = append(b.CloudTrail, incidents.CloudTrailOf(&f.signals[i]))
			}
		}
		b.Metrics = f.series
		for _, e := range f.events {
			b.Events = append(b.Events, incidents.BundleEventOf(e))
		}
		if !skip(incidents.SectionLogs) {
			b.Logs = f.logs
		}
		if !skip(incidents.SectionAudit) {
			b.Audit = f.audit
		}
		return b, nil
	}
	bi := incidents.BundleInput{Cluster: req.Cluster, Incident: f.in, From: f.from, To: f.to, Signals: f.signals, Metrics: f.series,
		Events: f.events, Omitted: req.Omitted, GeneratedAt: now()}
	if !skip(incidents.SectionLogs) {
		for _, l := range f.logs {
			l.Text = f.red.String(l.Text)
			bi.Logs = append(bi.Logs, l)
		}
	}
	if !skip(incidents.SectionAudit) {
		bi.Audit = f.audit
	}
	return incidents.BuildBundle(bi, f.red), nil
}

func (f *fakeSource) Logs(_ context.Context, id string, req incidents.LogRequest) (incidents.LogResponse, error) {
	f.count("Logs")
	f.mu.Lock()
	f.lastLogs = req
	f.mu.Unlock()
	if f.logErr != nil {
		return incidents.LogResponse{}, f.logErr
	}
	resp := incidents.LogResponse{From: req.From, To: req.To, Source: "kubernetes", Lines: []incidents.LogLine{}}
	for _, l := range f.logs {
		if (len(req.Pods) > 0 && !has(req.Pods, l.Pod)) || (req.Level != "" && l.Level != req.Level) ||
			(req.Text != "" && !strings.Contains(l.Text, req.Text)) || l.Time.Before(req.From) || l.Time.After(req.To) {
			continue
		}
		if !f.raw {
			l.Text = f.red.String(l.Text) // the runner redacts
		}
		resp.Lines = append(resp.Lines, l)
		if req.Limit > 0 && len(resp.Lines) == req.Limit {
			resp.Truncated = true
			break
		}
	}
	return resp, nil
}

func (f *fakeSource) Series(_ context.Context, id string, from, to time.Time) ([]incidents.Series, error) {
	f.count("Series")
	return f.series, nil
}

func (f *fakeSource) Events(_ context.Context, q incidents.EventQuery) ([]incidents.StoredEvent, error) {
	f.count("Events")
	var out []incidents.StoredEvent
	for _, e := range f.events {
		if q.Matches(&e) {
			out = append(out, e)
		}
	}
	return out, nil
}

func (f *fakeSource) AuditEvents(_ context.Context, in *incidents.Incident, limit int) ([]audit.Event, error) {
	f.count("AuditEvents")
	return f.audit, nil
}

func (f *fakeSource) WorkloadState(_ context.Context, in *incidents.Incident) (*investigate.WorkloadState, error) {
	f.count("WorkloadState")
	return f.state, nil
}

func has(l []string, s string) bool {
	for _, e := range l {
		if e == s {
			return true
		}
	}
	return false
}

func kev(uid, ns, kind, name, typ, reason, msg string, first, last time.Time) incidents.StoredEvent {
	return incidents.StoredEvent{KubeEvent: model.KubeEvent{UID: uid, Namespace: ns, Type: typ, Reason: reason, Message: msg, Count: 1,
		FirstSeen: first, LastSeen: last, Regarding: model.ObjectRef{Kind: kind, Namespace: ns, Name: name}, Source: "kubelet"}}
}

// source is a small incident: Deployment shop/api, pods api-1 and api-2 on
// node-1, OOM killed at t0 after a deploy at t0-2m.
func source() *fakeSource {
	end := at(20)
	in := incidents.Incident{ID: "inc-1", Subject: apiSubject, Title: "api: OOM kill", Severity: incidents.Critical,
		PeakSeverity: incidents.Critical, State: incidents.Resolved, Start: t0, LastSignal: at(15), End: &end,
		Pods: []string{"api-1", "api-2"}, Nodes: []string{"node-1"}, Services: []string{"api"},
		Types:  []string{incidents.TypeAuditChange, incidents.TypeCloudTrailChange, incidents.TypeDeploy, incidents.TypeMemorySpike, incidents.TypeOOMKill},
		Counts: map[string]int{incidents.TypeOOMKill: 1, incidents.TypeDeploy: 1, incidents.TypeAuditChange: 1, incidents.TypeCloudTrailChange: 1, incidents.TypeMemorySpike: 1}}
	pod := func(n string) model.ObjectRef { return model.ObjectRef{Kind: "Pod", Namespace: "shop", Name: n} }
	sigs := []incidents.Signal{
		{ID: "oom:api-1", Type: incidents.TypeOOMKill, Source: incidents.SourceView, Role: incidents.Trigger, Severity: incidents.Critical,
			Start: t0, Subject: apiSubject, Object: pod("api-1"), Title: "api-1/app was OOM killed", Attrs: map[string]string{"container": "app"}},
		{ID: "mem:api-1", Type: incidents.TypeMemorySpike, Source: incidents.SourceMetrics, Role: incidents.Trigger, Severity: incidents.Warning,
			Start: at(-1), End: timePtr(at(1)), Subject: apiSubject, Object: pod("api-1"), Title: "api-1/app memory at 98% of its limit",
			Value: fptr(500e6), Threshold: fptr(480e6)},
		{ID: "deploy:api:2", Type: incidents.TypeDeploy, Source: incidents.SourceView, Role: incidents.Context, Start: at(-2),
			Subject: apiSubject, Object: model.ObjectRef{Kind: "Deployment", Namespace: "shop", Name: "api"}, Title: "api rolled out revision 2",
			Attrs: map[string]string{"images": "app:v1 → app:v2"}},
		{ID: "audit:a1", Type: incidents.TypeAuditChange, Source: incidents.SourceAudit, Role: incidents.Context, Start: at(-3),
			Subject: apiSubject, Object: model.ObjectRef{Kind: "Deployment", Namespace: "shop", Name: "api"}, Title: "alice patched deployments shop/api",
			Attrs: map[string]string{"user": "alice", "verb": "patch", "sourceIP": "198.51.100.7", "userAgent": "kubectl/v1.36"}},
		{ID: "cloudtrail:ct1", Type: incidents.TypeCloudTrailChange, Source: incidents.SourceCloudTrail, Role: incidents.Context, Start: at(-4),
			Subject: apiSubject, Object: model.ObjectRef{Kind: "AWS::EC2", Name: "sg-0abc"}, Title: "erin called ec2:AuthorizeSecurityGroupIngress on sg-0abc",
			Attrs: map[string]string{"eventID": "ct1", "eventName": "AuthorizeSecurityGroupIngress", "eventSource": "ec2.amazonaws.com",
				"actor": "arn:aws:iam::111122223333:user/erin", "resources": "sg-0abc", "matched": "security-group:sg-0abc",
				"raw": `{"eventName":"AuthorizeSecurityGroupIngress","sourceIPAddress":"198.51.100.9","userAgent":"aws-cli/2.15"}`}},
	}
	logs := []incidents.LogLine{
		{Time: at(-0.5), Pod: "api-1", Container: "app", Level: "error", Text: "cache grew to 480123 entries", Source: "kubernetes"},
		{Time: at(-0.2), Pod: "api-1", Container: "app", Level: "error", Text: "cache grew to 495001 entries", Source: "kubernetes"},
		{Time: at(1), Pod: "api-2", Container: "app", Level: "info", Text: "GET /healthz 200 3ms", Source: "kubernetes"},
		{Time: at(2), Pod: "api-2", Container: "app", Level: "warn", Text: "slow query took 1200ms", Source: "kubernetes"},
	}
	evs := []incidents.StoredEvent{
		kev("e1", "shop", "Pod", "api-1", "Warning", "BackOff", "Back-off restarting failed container app", at(0.5), at(3)),
		kev("e2", "shop", "Pod", "api-1", "Normal", "Pulled", "Container image app:v2 pulled", at(-2), at(-2)),
		kev("e3", "", "Node", "node-1", "Warning", "SystemOOM", "System OOM encountered, victim process: app", t0, t0),
		kev("e4", "other", "Pod", "x-1", "Warning", "BackOff", "another namespace", at(1), at(1)),
	}
	evs[0].Subject = &apiSubject
	evs[1].Subject = &apiSubject
	evs[0].Count = 7
	series := []incidents.Series{{Metric: "memory", Label: "api-1/app", Unit: "bytes", Source: "prometheus"}}
	for i := 0; i <= 140; i++ { // every 15s over the window
		v := 300e6 + float64(i)*1e6
		if i == 20 {
			v = 512e6 // the peak, just before the OOM kill
		}
		series[0].Points = append(series[0].Points, [2]float64{float64(at(-5).Add(time.Duration(i) * 15 * time.Second).UnixMilli()), v})
	}
	aud := []audit.Event{
		{AuditID: "a1", Time: at(-3), Verb: "patch", Username: "alice", ActorKind: "user", SourceIPs: []string{"198.51.100.7"},
			UserAgent: "kubectl/v1.36", Resource: "deployments", Namespace: "shop", Name: "api", RequestURI: "/apis/apps/v1/namespaces/shop/deployments/api",
			StatusCode: 200},
		{AuditID: "a2", Time: at(5), Verb: "get", Username: "bob", ActorKind: "user", Resource: "pods", Namespace: "shop", Name: "api-1", StatusCode: 200},
	}
	state := &investigate.WorkloadState{At: now(),
		Workload: &model.Workload{Kind: "Deployment", Namespace: "shop", Name: "api", Desired: 2, Ready: 1, Updated: 2, Available: 1, Revision: "2",
			Images: []string{"app:v2"}, Conditions: []model.Condition{{Type: "Available", Status: "False", Reason: "MinimumReplicasUnavailable"}}},
		Pods: []model.Pod{{Name: "api-1", Namespace: "shop", Phase: "Running", NodeName: "node-1", PodIP: "10.1.2.3",
			Containers: []model.ContainerStatus{{Name: "app", State: "running", RestartCount: 3, LastTerminatedReason: "OOMKilled", LastTerminatedAt: t0,
				LastExitCode: 137}}, Specs: []model.ContainerSpec{{Name: "app", MemoryLimitBytes: 512 << 20}}}},
		Nodes: []model.Node{{Name: "node-1", Ready: true, InternalIP: "10.0.0.1", Conditions: []model.Condition{{Type: "MemoryPressure", Status: "True"}}}},
	}
	return &fakeSource{in: in, signals: sigs, logs: logs, series: series, events: evs, audit: aud, state: state, from: at(-5), to: at(30)}
}

func timePtr(t time.Time) *time.Time { return &t }

// bundleOf builds the source's bundle as the service would ask for it.
func bundleOf(t *testing.T, src *fakeSource, a investigate.Access) *incidents.Bundle {
	t.Helper()
	omitted := map[string]string{}
	for k, v := range a.Omitted() {
		if k != investigate.SectionNodes {
			omitted[k] = v
		}
	}
	b, err := src.Bundle(context.Background(), src.in.ID, incidents.BundleRequest{Omitted: omitted, Cluster: "prod"})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
