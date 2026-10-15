package incidents

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/alerts"
	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/model"
)

func TestViewDiff(t *testing.T) {
	inv := fixture()
	leaseAt := t0.Add(-time.Minute)
	d := NewViewDiff(Options{}, leaseAt)

	// The first view is a baseline: an old termination says nothing, one
	// after the lease was taken is reported.
	first := withPod(inv, "api-7d9f-a", func(p *model.Pod) {
		p.Containers[0].RestartCount, p.Containers[0].LastTerminatedAt, p.Containers[0].LastTerminatedReason = 4, t0.Add(-time.Hour), "Error"
	})
	first = withPod(first, "db-0", func(p *model.Pod) {
		p.Containers[0].RestartCount, p.Containers[0].LastTerminatedAt, p.Containers[0].LastTerminatedReason = 1, t0.Add(-30*time.Second), "OOMKilled"
	})
	got := d.Diff(view(first, t0), t0)
	if s := sigSummary(got); !reflect.DeepEqual(s, []string{"oom-kill trigger/critical StatefulSet/db"}) {
		t.Fatalf("first view: %v", s)
	}
	if got[0].ID != "view:oom-kill:uid-db-0/app#1" || !got[0].Start.Equal(t0.Add(-30*time.Second)) {
		t.Errorf("oom signal = %+v", got[0])
	}

	// Restarts: context at first, a trigger once the pod restarted
	// RestartWarn (3) times within Quiet.
	cur := first
	var all []Signal
	for i := 1; i <= 3; i++ {
		now := t0.Add(time.Duration(i) * time.Minute)
		cur = withPod(cur, "api-7d9f-a", func(p *model.Pod) {
			p.Containers[0].RestartCount++
			p.Containers[0].LastTerminatedAt, p.Containers[0].LastExitCode = now.Add(-10*time.Second), 137
		})
		all = append(all, d.Diff(view(cur, now), now)...)
	}
	want := []string{"restart context Deployment/api", "restart context Deployment/api", "restart trigger/warning Deployment/api"}
	if s := sigSummary(all); !reflect.DeepEqual(s, want) {
		t.Fatalf("restarts: %v", s)
	}
	if all[2].Attrs["exitCode"] != "137" || all[2].Attrs["reason"] != "Error" || all[2].ID != "view:restart:uid-api-7d9f-a/app#7" {
		t.Errorf("restart = %+v", all[2])
	}

	// A crash loop starts and ends; an eviction; a deploy with its image
	// diff; a scale.
	t4 := t0.Add(4 * time.Minute)
	cur = withPod(cur, "api-7d9f-b", func(p *model.Pod) { p.Containers[0].State, p.Containers[0].Reason = "waiting", "CrashLoopBackOff" })
	cur = withPod(cur, "front-1-x", func(p *model.Pod) { p.Reason, p.Phase, p.Message = "Evicted", "Failed", "low on memory" })
	got = d.Diff(view(cur, t4), t4)
	if s := sigSummary(got); !reflect.DeepEqual(s, []string{"crashloop trigger/critical Deployment/api", "eviction trigger/warning Deployment/front"}) {
		t.Fatalf("crash loop and eviction: %v", s)
	}
	t5 := t0.Add(5 * time.Minute)
	cur = withPod(cur, "api-7d9f-b", func(p *model.Pod) { p.Containers[0].State, p.Containers[0].Reason = "running", "" })
	cur = withWorkload(cur, "shop", "api", func(w *model.Workload) { w.Revision, w.Images, w.Desired = "2", []string{"app:v2"}, 4 })
	cur.ReplicaSets = append(append([]model.ReplicaSet(nil), cur.ReplicaSets...), model.ReplicaSet{Namespace: "shop", Name: "api-8e0a",
		UID: "uid-api-8e0a", Owners: []model.OwnerRef{{Kind: "Deployment", Name: "api", UID: "uid-api", Controller: true}}, Revision: "2",
		Images: []string{"app:v2"}, Created: t5.Add(-20 * time.Second)})
	got = d.Diff(view(cur, t5), t5)
	if s := sigSummary(got); !reflect.DeepEqual(s, []string{"crashloop trigger/critical Deployment/api end=12:05:00", "deploy context Deployment/api", "scale context Deployment/api"}) {
		t.Fatalf("crash loop end, deploy, scale: %v", s)
	}
	dep := got[1]
	if dep.Attrs["images"] != "app: v1 → v2" || dep.Attrs["rollback"] != "" || !dep.Start.Equal(t5.Add(-20*time.Second)) ||
		dep.ID != "view:deploy:Deployment/shop/api@2" {
		t.Errorf("deploy = %+v", dep)
	}
	if got[2].Attrs["from"] != "2" || got[2].Attrs["to"] != "4" {
		t.Errorf("scale = %+v", got[2])
	}

	// Rolling back to revision 1's ReplicaSet (revision 3 now) is flagged.
	t6 := t0.Add(6 * time.Minute)
	back := withWorkload(cur, "shop", "api", func(w *model.Workload) { w.Revision, w.Images = "3", []string{"app:v1"} })
	back.ReplicaSets = append([]model.ReplicaSet(nil), back.ReplicaSets...)
	back.ReplicaSets[0].Revision = "3"
	got = d.Diff(view(back, t6), t6)
	if len(got) != 1 || got[0].Attrs["rollback"] != "true" || got[0].Attrs["images"] != "app: v2 → v1" {
		t.Fatalf("rollback: %+v", got)
	}
}

func TestViewDiffResumesCrashLoops(t *testing.T) {
	inv := withPod(fixture(), "api-7d9f-b", func(p *model.Pod) { p.Containers[0].State, p.Containers[0].Reason = "waiting", "CrashLoopBackOff" })
	d1 := NewViewDiff(Options{}, t0)
	s1 := d1.Diff(view(inv, t0), t0)
	if len(s1) != 1 || s1[0].Type != TypeCrashLoop {
		t.Fatalf("first leader: %v", sigSummary(s1))
	}
	// A new leader resumes it: the same signal, then its end.
	d2 := NewViewDiff(Options{}, t0.Add(time.Minute))
	d2.Resume(s1)
	s2 := d2.Diff(view(inv, t0.Add(time.Minute)), t0.Add(time.Minute))
	if len(s2) != 1 || s2[0].ID != s1[0].ID {
		t.Fatalf("resumed: %v", s2)
	}
	ok := withPod(inv, "api-7d9f-b", func(p *model.Pod) { p.Containers[0].State, p.Containers[0].Reason = "running", "" })
	s3 := d2.Diff(view(ok, t0.Add(2*time.Minute)), t0.Add(2*time.Minute))
	if len(s3) != 1 || s3[0].ID != s1[0].ID || s3[0].End == nil {
		t.Fatalf("ended: %v", s3)
	}
}

func TestImageDiff(t *testing.T) {
	cases := []struct {
		old, cur []string
		want     string
	}{
		{[]string{"repo/app:v1", "envoy:1.30"}, []string{"repo/app:v2", "envoy:1.30"}, "repo/app: v1 → v2"},
		{[]string{"app:v1"}, []string{"app:v1", "sidecar:2"}, "+sidecar:2"},
		{[]string{"app:v1", "old:1"}, []string{"app:v1"}, "-old:1"},
		{[]string{"reg:5000/app:v1"}, []string{"reg:5000/app:v2"}, "reg:5000/app: v1 → v2"},
		{[]string{"app:v1"}, []string{"app:v1"}, ""},
	}
	for _, c := range cases {
		if got := imageDiff(c.old, c.cur); got != c.want {
			t.Errorf("imageDiff(%v, %v) = %q, want %q", c.old, c.cur, got, c.want)
		}
	}
}

// fakeRates serves fixed samples per window.
type fakeRates struct {
	name           string
	recent, base   []model.RateSample
	err            error
	recentW, baseW time.Duration
}

func (f *fakeRates) Name() string { return f.name }
func (f *fakeRates) Rates(_ context.Context, _ time.Time, window, offset time.Duration, _ []string) ([]model.RateSample, error) {
	if f.err != nil {
		return nil, f.err
	}
	if offset == 0 {
		f.recentW = window
		return f.recent, nil
	}
	f.baseW = window
	return f.base, nil
}
func (f *fakeRates) Probe(context.Context) string { return "ok" }

type fakeMemory struct{ samples []model.MemorySample }

func (f *fakeMemory) MemoryUsage(context.Context, time.Time, []string) ([]model.MemorySample, error) {
	return f.samples, nil
}

func podRate(pod string, rps, errRatio float64) model.RateSample {
	return model.RateSample{Source: "app", Namespace: "shop", Pod: pod, PerSecond: rps, ErrorRatio: errRatio}
}

func TestMetricsRequestSpike(t *testing.T) {
	inv := fixture()
	v := view(inv, t0)
	rates := &fakeRates{name: "app"}
	m := NewMetricsScan(Options{}, []RateSource{rates}, nil)
	scan := func(minute int, recentEach, baseEach float64) []Signal {
		// Two pods of api; one gone pod (rolled away) still in the baseline.
		rates.recent = []model.RateSample{podRate("api-7d9f-a", recentEach, -1), podRate("api-7d9f-b", recentEach, -1)}
		rates.base = []model.RateSample{podRate("api-7d9f-a", baseEach, -1), podRate("api-7d9f-b", baseEach, -1), podRate("api-7d9f-gone", baseEach, -1)}
		return m.Scan(context.Background(), v, t0.Add(time.Duration(minute)*time.Minute))
	}
	if got := scan(0, 5, 5); len(got) != 0 { // 10/s against 15/s
		t.Fatalf("no spike: %v", sigSummary(got))
	}
	if rates.recentW != 5*time.Minute || rates.baseW != time.Hour {
		t.Errorf("windows %s %s", rates.recentW, rates.baseW)
	}
	got := scan(1, 20, 5) // 40/s against 15/s: x2.7
	if s := sigSummary(got); !reflect.DeepEqual(s, []string{"request-spike trigger/warning Deployment/api"}) {
		t.Fatalf("spike: %v", s)
	}
	id := got[0].ID
	if *got[0].Baseline != 15 || *got[0].Threshold != 30 || *got[0].Value != 40 || got[0].Attrs["ratio"] != "2.67" {
		t.Errorf("spike values: %+v", got[0])
	}
	// The baseline climbs with the spike, but the spike's is frozen: x4.
	got = scan(2, 30, 15)
	if len(got) != 1 || got[0].ID != id || got[0].Severity != Critical || *got[0].Baseline != 15 {
		t.Fatalf("escalation: %+v", got)
	}
	// Below 0.8 x 30 = 24 for two scans: it ends at the first.
	got = scan(3, 11, 20)
	if len(got) != 1 || got[0].End != nil {
		t.Fatalf("one scan below: %+v", got)
	}
	got = scan(4, 11, 20)
	if len(got) != 1 || got[0].End == nil || !got[0].End.Equal(t0.Add(3*time.Minute)) || got[0].ID != id {
		t.Fatalf("end: %+v", got)
	}
	if got := scan(5, 11, 20); len(got) != 0 {
		t.Fatalf("after the end: %v", sigSummary(got))
	}
	if st := m.Status(); st["requests:app"] != "ok" {
		t.Errorf("status %v", st)
	}
	// Quiet subjects never spike.
	if got := scan(6, 0.4, 0.05); len(got) != 0 {
		t.Errorf("a quiet subject spiked: %v", sigSummary(got))
	}
}

func TestMetricsErrorRateAndServiceSamples(t *testing.T) {
	v := view(fixture(), t0)
	rates := &fakeRates{name: "nginx"}
	m := NewMetricsScan(Options{}, []RateSource{rates}, nil)
	svc := func(name string, rps, errRatio float64) model.RateSample {
		return model.RateSample{Source: "nginx", Namespace: "shop", Service: name, PerSecond: rps, ErrorRatio: errRatio}
	}
	rates.recent = []model.RateSample{svc("api", 10, 0.25), svc("db", 10, 0.01)}
	rates.base = []model.RateSample{svc("api", 10, 0), svc("db", 10, 0)}
	got := m.Scan(context.Background(), v, t0)
	if s := sigSummary(got); !reflect.DeepEqual(s, []string{"error-rate trigger/critical Deployment/api"}) {
		t.Fatalf("errors: %v", s)
	}
	if got[0].Object.Kind != "Service" || got[0].Object.Name != "api" || *got[0].Value != 0.25 {
		t.Errorf("signal: %+v", got[0])
	}
	// A failing source leaves its spikes alone.
	rates.err = errors.New("prometheus down")
	if got := m.Scan(context.Background(), v, t0.Add(time.Minute)); len(got) != 0 {
		t.Errorf("with the source down: %v", sigSummary(got))
	}
	if st := m.Status()["requests:nginx"]; !strings.HasPrefix(st, "error: ") {
		t.Errorf("status %q", st)
	}
	rates.err = nil
	rates.recent = []model.RateSample{svc("api", 10, 0.02)}
	m.Scan(context.Background(), v, t0.Add(2*time.Minute))
	got = m.Scan(context.Background(), v, t0.Add(3*time.Minute))
	if len(got) != 1 || got[0].End == nil || !got[0].End.Equal(t0.Add(2*time.Minute)) {
		t.Fatalf("end: %+v", got)
	}
}

func TestMetricsMemory(t *testing.T) {
	v := view(fixture(), t0)
	mem := &fakeMemory{}
	m := NewMetricsScan(Options{}, nil, mem)
	sample := func(pod string, bytes float64) model.MemorySample {
		return model.MemorySample{Namespace: "shop", Pod: pod, Container: "app", Bytes: bytes}
	}
	scan := func(minute int, s ...model.MemorySample) []Signal {
		mem.samples = s
		return m.Scan(context.Background(), v, t0.Add(time.Duration(minute)*time.Minute))
	}
	// api has a 512 MiB limit: 80% is fine, 90% warns, 96% is critical.
	if got := scan(0, sample("api-7d9f-a", 410*mi), sample("db-0", 100*mi)); len(got) != 0 {
		t.Fatalf("no spike: %v", sigSummary(got))
	}
	got := scan(1, sample("api-7d9f-a", 461*mi), sample("api-7d9f-b", 300*mi), sample("db-0", 120*mi))
	if s := sigSummary(got); !reflect.DeepEqual(s, []string{"memory-spike trigger/warning Deployment/api"}) {
		t.Fatalf("90%%: %v", s)
	}
	if got[0].Attrs["pod"] != "api-7d9f-a" || got[0].Object.Name != "api-7d9f-a" {
		t.Errorf("signal: %+v", got[0])
	}
	got = scan(2, sample("api-7d9f-a", 300*mi), sample("api-7d9f-b", 492*mi), sample("db-0", 120*mi))
	if len(got) != 1 || got[0].Severity != Critical || got[0].Attrs["pod"] != "api-7d9f-b" {
		t.Fatalf("96%%: %+v", got)
	}
	// db has no limit: a jump of x1.5 and 128 MiB against the previous scan.
	got = scan(3, sample("api-7d9f-b", 492*mi), sample("db-0", 300*mi))
	if s := sigSummary(got); !reflect.DeepEqual(s, []string{"memory-spike trigger/critical Deployment/api", "memory-spike trigger/warning StatefulSet/db"}) {
		t.Fatalf("jump: %v", s)
	}
	if db := got[1]; *db.Baseline != 120*mi || *db.Threshold != 180*mi {
		t.Errorf("jump baseline %v threshold %v", *db.Baseline, *db.Threshold)
	}
	// Both fall back: below 0.8 x the threshold for two scans.
	scan(4, sample("api-7d9f-b", 200*mi), sample("db-0", 130*mi))
	got = scan(5, sample("api-7d9f-b", 200*mi), sample("db-0", 130*mi))
	for _, s := range got {
		if s.End == nil || !s.End.Equal(t0.Add(4*time.Minute)) {
			t.Errorf("not ended at minute 4: %+v", s)
		}
	}
	if len(got) != 2 {
		t.Fatalf("ends: %v", sigSummary(got))
	}
}

func TestMetricsResume(t *testing.T) {
	v := view(fixture(), t0)
	rates := &fakeRates{name: "app"}
	rates.recent = []model.RateSample{podRate("api-7d9f-a", 40, -1)}
	rates.base = []model.RateSample{podRate("api-7d9f-a", 10, -1)}
	m1 := NewMetricsScan(Options{}, []RateSource{rates}, nil)
	s1 := m1.Scan(context.Background(), v, t0)
	if len(s1) != 1 {
		t.Fatalf("spike: %v", sigSummary(s1))
	}
	m2 := NewMetricsScan(Options{}, []RateSource{rates}, nil)
	m2.Resume(s1)
	rates.base = []model.RateSample{podRate("api-7d9f-a", 40, -1)} // the baseline caught up; the spike's stays frozen
	s2 := m2.Scan(context.Background(), v, t0.Add(time.Minute))
	if len(s2) != 1 || s2[0].ID != s1[0].ID || s2[0].End != nil {
		t.Fatalf("resumed: %+v", s2)
	}
}

func kev(uid, kind, ns, name, reason string, count int32, first, last time.Time) model.KubeEvent {
	return model.KubeEvent{UID: uid, Namespace: ns, Type: "Warning", Reason: reason, Message: reason + " happened", Count: count,
		FirstSeen: first, LastSeen: last, Regarding: model.ObjectRef{Kind: kind, Namespace: ns, Name: name}, Source: "kubelet"}
}

func TestEventsIngest(t *testing.T) {
	v := view(fixture(), t0)
	p := NewEventsIngest(Options{}, nil)
	// BackOff once is context; at three within 5 minutes a trigger.
	stored, sigs := p.Handle(v, []model.KubeEvent{kev("e1", "Pod", "shop", "api-7d9f-a", "BackOff", 1, t0, t0)}, t0)
	if len(stored) != 1 || stored[0].Subject == nil || *stored[0].Subject != apiSubject {
		t.Fatalf("stored: %+v", stored)
	}
	if s := sigSummary(sigs); !reflect.DeepEqual(s, []string{"k8s-event context Deployment/api"}) {
		t.Fatalf("one BackOff: %v", s)
	}
	t2 := t0.Add(2 * time.Minute)
	_, sigs = p.Handle(v, []model.KubeEvent{kev("e1", "Pod", "shop", "api-7d9f-a", "BackOff", 3, t0, t2)}, t2)
	if s := sigSummary(sigs); !reflect.DeepEqual(s, []string{"k8s-event trigger/warning Deployment/api"}) {
		t.Fatalf("three BackOffs: %v", s)
	}
	if sigs[0].Count != 2 || sigs[0].ID != "events:e1#3" || !sigs[0].Start.Equal(t2) {
		t.Errorf("signal: %+v", sigs[0])
	}
	// The same report again counts nothing.
	if _, sigs = p.Handle(v, []model.KubeEvent{kev("e1", "Pod", "shop", "api-7d9f-a", "BackOff", 3, t0, t2)}, t2); len(sigs) != 0 {
		t.Errorf("repeat: %v", sigSummary(sigs))
	}
	// OOMKilling on a node triggers at once (critical) for the node.
	_, sigs = p.Handle(v, []model.KubeEvent{kev("e2", "Node", "", "node-1", "OOMKilling", 1, t2, t2)}, t2)
	if s := sigSummary(sigs); !reflect.DeepEqual(s, []string{"k8s-event trigger/critical Node/node-1"}) {
		t.Fatalf("OOMKilling: %v", s)
	}
	// Normal events are dropped unless listed; listed ones are context.
	normal := kev("e3", "HorizontalPodAutoscaler", "shop", "api", "SuccessfulRescale", 1, t2, t2)
	normal.Type = "Normal"
	other := kev("e4", "Pod", "shop", "api-7d9f-a", "Pulled", 1, t2, t2)
	other.Type = "Normal"
	stored, sigs = p.Handle(v, []model.KubeEvent{normal, other}, t2)
	if len(stored) != 1 || stored[0].Reason != "SuccessfulRescale" || len(sigs) != 1 || sigs[0].Role != Context || sigs[0].Subject != apiSubject {
		t.Fatalf("normal events: %+v / %v", stored, sigSummary(sigs))
	}
	// Messages are redacted; a long-running series keeps at most a day; an
	// event about nothing incidents know is stored without a subject.
	old := kev("e5", "Pod", "shop", "gone-pod", "Failed", 900, t0.Add(-72*time.Hour), t2)
	old.Message = "pull failed: password=hunter2"
	stored, sigs = p.Handle(v, []model.KubeEvent{old}, t2)
	if stored[0].Subject != nil || strings.Contains(stored[0].Message, "hunter2") || !stored[0].FirstSeen.Equal(t2.Add(-MaxRange)) {
		t.Errorf("stored: %+v", stored[0])
	}
	if len(sigs) != 0 {
		t.Errorf("signal without subject: %v", sigSummary(sigs))
	}
}

func TestEventSubject(t *testing.T) {
	v := view(fixture(), t0)
	cases := []struct {
		kind, ns, name string
		want           Subject
		ok             bool
	}{
		{"Pod", "shop", "api-7d9f-a", apiSubject, true},
		{"Pod", "shop", "api-7d9f-zzzzz", apiSubject, true}, // gone, by its ReplicaSet's name
		{"Pod", "shop", "db-3", dbSubject, true},            // a StatefulSet ordinal
		{"ReplicaSet", "shop", "api-7d9f", apiSubject, true},
		{"Deployment", "web", "front", frontSubject, true},
		{"Service", "shop", "db", dbSubject, true},
		{"HorizontalPodAutoscaler", "shop", "api", apiSubject, true},
		{"Node", "", "node-2", Subject{Kind: KindNode, Name: "node-2"}, true},
		{"ConfigMap", "shop", "x", Subject{}, false},
	}
	for _, c := range cases {
		got, ok := EventSubject(v, model.KubeEvent{Namespace: c.ns, Regarding: model.ObjectRef{Kind: c.kind, Namespace: c.ns, Name: c.name}})
		if ok != c.ok || got != c.want {
			t.Errorf("%s %s/%s: %+v %v, want %+v %v", c.kind, c.ns, c.name, got, ok, c.want, c.ok)
		}
	}
}

func TestAlertEpisodes(t *testing.T) {
	p := NewAlertEpisodes()
	first := t0.Add(-10 * time.Minute)
	f := alerts.Finding{Key: alerts.Key(alerts.CheckWorkloadUnhealthy, "Deployment", "shop", "api"), Alert: alerts.AlertWorkloadUnhealthy,
		Check: alerts.CheckWorkloadUnhealthy, Kind: "Deployment", Namespace: "shop", Name: "api", Severity: alerts.SeverityCritical,
		Title: "Deployment api: 2 CrashLoopBackOff", State: alerts.StateOpen, FirstSeen: first, LastSeen: t0}
	cert := alerts.Finding{Key: "cert", Check: alerts.CheckCertExpiring, Kind: "Certificate", Namespace: "shop", Name: "tls", Severity: "warning",
		State: alerts.StateOpen, FirstSeen: first, LastSeen: t0}
	got := p.Scan([]alerts.Finding{f, cert}, t0)
	if s := sigSummary(got); !reflect.DeepEqual(s, []string{"alert trigger/critical Deployment/api"}) {
		t.Fatalf("firing: %v", s)
	}
	if got[0].ID != "alert:"+f.Key+"@2026-10-15T11:50:00Z" || !got[0].Start.Equal(first) || got[0].End != nil {
		t.Errorf("episode = %+v", got[0])
	}
	// It resolves: the episode ends.
	res := f
	res.State, res.ResolvedAt = alerts.StateResolved, timePtr(t0.Add(2*time.Minute))
	got = p.Scan([]alerts.Finding{res}, t0.Add(3*time.Minute))
	if len(got) != 1 || got[0].End == nil || !got[0].End.Equal(t0.Add(2*time.Minute)) {
		t.Fatalf("resolved: %+v", got)
	}
	// Firing again is a new episode, and leaving the board ends it at its
	// last sighting.
	again := f
	again.FirstSeen, again.LastSeen, again.State = t0.Add(5*time.Minute), t0.Add(6*time.Minute), alerts.StateOpen
	got = p.Scan([]alerts.Finding{again}, t0.Add(6*time.Minute))
	if len(got) != 1 || got[0].ID == EpisodeID(&f) {
		t.Fatalf("new episode: %+v", got)
	}
	got = p.Scan(nil, t0.Add(9*time.Minute))
	if len(got) != 1 || !got[0].End.Equal(t0.Add(6*time.Minute)) {
		t.Fatalf("gone: %+v", got)
	}
	// A resolved finding never seen firing says nothing.
	if got := NewAlertEpisodes().Scan([]alerts.Finding{res}, t0); len(got) != 0 {
		t.Errorf("unseen resolved: %v", sigSummary(got))
	}
}

func TestAuditPoll(t *testing.T) {
	v := view(fixture(), t0)
	st := audit.NewMemoryStore(1000).AsStore()
	ev := func(id, user, kind, verb, resource, ns, name string, at time.Time) audit.Event {
		return audit.Event{AuditID: id, Time: at, Stage: "ResponseComplete", Verb: verb, Username: user, ActorKind: kind,
			Resource: resource, Namespace: ns, Name: name, StatusCode: 200}
	}
	events := []audit.Event{
		ev("a1", "alice", "user", "patch", "deployments", "shop", "api", t0.Add(-2*time.Minute)),
		ev("a2", "alice", "user", "update", "configmaps", "shop", "api-config", t0.Add(-time.Minute)),
		ev("a3", "alice", "user", "get", "secrets", "shop", "db", t0.Add(-time.Minute)),
		ev("a4", "system:serviceaccount:x:y", "serviceaccount", "patch", "deployments", "shop", "api", t0.Add(-time.Minute)),
		ev("a5", "bob", "user", "create", "pods", "shop", "api-7d9f-a", t0.Add(-30*time.Second)),
		ev("a6", "bob", "user", "patch", "nodes", "", "node-1", t0.Add(-20*time.Second)),
		ev("a7", "bob", "user", "patch", "deployments", "shop", "api", t0.Add(-10*time.Second)),
	}
	events[4].Subresource = "exec"
	events[6].StatusCode = 403
	if err := st.Add(context.Background(), events); err != nil {
		t.Fatal(err)
	}
	p := NewAuditPoll(st, Options{}, nil, t0)
	sigs, cp, err := p.Poll(context.Background(), v, t0)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"audit-change context Deployment/api", "audit-change context Namespace/shop", "audit-change context Deployment/api",
		"audit-change context Node/node-1"}
	if s := sigSummary(sigs); !reflect.DeepEqual(s, want) {
		t.Fatalf("signals: %v", s)
	}
	if sigs[0].Title != "alice patched deployments shop/api" || sigs[2].Title != "bob opened pods/exec shop/api-7d9f-a" {
		t.Errorf("titles: %q, %q", sigs[0].Title, sigs[2].Title)
	}
	if !strings.Contains(string(cp), `"time"`) {
		t.Errorf("checkpoint %s", cp)
	}
	// Polled again: nothing new; a new write arrives.
	if sigs, _, _ = p.Poll(context.Background(), v, t0.Add(time.Minute)); len(sigs) != 0 {
		t.Errorf("repeat: %v", sigSummary(sigs))
	}
	_ = st.Add(context.Background(), []audit.Event{ev("a8", "carol", "user", "delete", "pods", "web", "front-1-x", t0.Add(time.Minute))})
	sigs, _, _ = p.Poll(context.Background(), v, t0.Add(2*time.Minute))
	if s := sigSummary(sigs); !reflect.DeepEqual(s, []string{"audit-change context Deployment/front"}) {
		t.Errorf("new write: %v", s)
	}
	// A new leader resumes from the checkpoint, re-reading the lookbehind.
	p2 := NewAuditPoll(st, Options{}, cp, t0.Add(3*time.Minute))
	sigs, _, _ = p2.Poll(context.Background(), v, t0.Add(3*time.Minute))
	if len(sigs) != 5 {
		t.Errorf("after failover: %v", sigSummary(sigs))
	}
}

// fakeTrail serves events once.
type fakeTrail struct {
	evs   []CloudTrailEvent
	since time.Time
	cp    []byte
}

func (f *fakeTrail) Name() string { return "lookup" }
func (f *fakeTrail) Changes(_ context.Context, since time.Time, cp []byte) ([]CloudTrailEvent, []byte, error) {
	f.since, f.cp = since, cp
	return f.evs, []byte(`{"next":"x"}`), nil
}
func (f *fakeTrail) Probe(context.Context) string { return "ok" }

func TestRelatedIndexMatching(t *testing.T) {
	v := view(fixture(), t0)
	idx := RelatedIndexOf(v, "")
	cases := []struct {
		name      string
		ev        CloudTrailEvent
		subjects  []Subject
		matched   []string
		isCluster bool
	}{
		{"instance by ID", CloudTrailEvent{Source: "ec2.amazonaws.com", Resources: []string{"i-0aaa"}},
			// The engine leaves kube-system out (system namespaces); the index does not judge.
			[]Subject{{Kind: KindNode, Name: "node-1"}, {Kind: "DaemonSet", Namespace: "kube-system", Name: "aws-node"}, apiSubject, dbSubject},
			[]string{"instance:i-0aaa"}, false},
		{"instance by ARN", CloudTrailEvent{Source: "ec2.amazonaws.com", Resources: []string{"arn:aws:ec2:us-east-1:111122223333:instance/i-0bbb"}},
			[]Subject{{Kind: KindNode, Name: "node-2"}, frontSubject, apiSubject}, []string{"instance:i-0bbb"}, false},
		{"target group", CloudTrailEvent{Source: "elasticloadbalancing.amazonaws.com",
			Resources: []string{"arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/k8s-shop-api/0123456789abcdef"}},
			[]Subject{apiSubject}, []string{"target-group:arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/k8s-shop-api/0123456789abcdef",
				"target-group:targetgroup/k8s-shop-api/0123456789abcdef"}, false},
		{"ALB by load balancer ARN", CloudTrailEvent{Source: "elasticloadbalancing.amazonaws.com",
			Resources: []string{"arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/shop-alb/50dc6c495c0c9188"}},
			[]Subject{apiSubject}, []string{"load-balancer:shop-alb"}, false},
		{"IRSA role, short form", CloudTrailEvent{Source: "iam.amazonaws.com", Resources: []string{"role/api-role"}},
			[]Subject{apiSubject}, []string{"irsa-role:role/api-role"}, false},
		{"IRSA role ARN", CloudTrailEvent{Source: "iam.amazonaws.com", Resources: []string{"arn:aws:iam::111122223333:role/api-role"}},
			[]Subject{apiSubject}, []string{"irsa-role:arn:aws:iam::111122223333:role/api-role", "irsa-role:role/api-role"}, false},
		{"a bare role name is not enough", CloudTrailEvent{Source: "iam.amazonaws.com", Resources: []string{"api-role"}}, nil, nil, false},
		{"target group suffix", CloudTrailEvent{Source: "elasticloadbalancing.amazonaws.com",
			Resources: []string{"targetgroup/k8s-shop-api/0123456789abcdef"}},
			[]Subject{apiSubject}, []string{"target-group:targetgroup/k8s-shop-api/0123456789abcdef"}, false},
		{"EKS node group", CloudTrailEvent{Source: "eks.amazonaws.com", Resources: []string{"nodegroup/prod/workers"}},
			nil, []string{"cluster:prod"}, true},
		{"EKS cluster", CloudTrailEvent{Source: "eks.amazonaws.com", Resources: []string{"cluster/prod"}},
			nil, []string{"cluster:prod"}, true},
		{"a node group of another cluster", CloudTrailEvent{Source: "eks.amazonaws.com", Resources: []string{"nodegroup/staging/prod"}},
			nil, nil, false},
		{"security group", CloudTrailEvent{Source: "ec2.amazonaws.com", Resources: []string{"sg-0def"}},
			[]Subject{apiSubject}, []string{"security-group:sg-0def"}, false},
		{"NLB security group", CloudTrailEvent{Source: "ec2.amazonaws.com", Resources: []string{"sg-0db"}},
			[]Subject{dbSubject}, []string{"security-group:sg-0db"}, false},
		{"EKS add-on", CloudTrailEvent{Source: "eks.amazonaws.com", Resources: []string{"arn:aws:eks:us-east-1:111122223333:addon/prod/vpc-cni/abc"}},
			nil, []string{"cluster:prod"}, true},
		{"another cluster", CloudTrailEvent{Source: "eks.amazonaws.com", Resources: []string{"arn:aws:eks:us-east-1:111122223333:cluster/staging"}},
			nil, nil, false},
		{"unrelated", CloudTrailEvent{Source: "s3.amazonaws.com", Resources: []string{"arn:aws:s3:::bucket"}}, nil, nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			subjects, matched, cluster := idx.Match(&c.ev)
			sortSubjects(c.subjects)
			if !reflect.DeepEqual(subjects, c.subjects) || !reflect.DeepEqual(matched, c.matched) || cluster != c.isCluster {
				t.Errorf("got %v %v %v, want %v %v %v", subjects, matched, cluster, c.subjects, c.matched, c.isCluster)
			}
		})
	}
}

func TestCloudTrailPoll(t *testing.T) {
	v := view(fixture(), t0)
	src := &fakeTrail{evs: []CloudTrailEvent{
		{ID: "ct1", Time: t0, Name: "AuthorizeSecurityGroupIngress", Source: "ec2.amazonaws.com", Actor: "arn:aws:iam::1:user/erin",
			Resources: []string{"sg-0abc"}, Raw: `{"requestParameters":{"groupId":"sg-0abc"},"secret":"AKIAABCDEFGHIJKLMNOP"}`},
		{ID: "ct2", Time: t0, Name: "DescribeInstances", Source: "ec2.amazonaws.com", ReadOnly: true, Resources: []string{"i-0aaa"}},
		{ID: "ct3", Time: t0, Name: "TerminateInstances", Source: "ec2.amazonaws.com", ErrorCode: "AccessDenied", Resources: []string{"i-0aaa"}},
		{ID: "ct4", Time: t0, Name: "UpdateAddon", Source: "eks.amazonaws.com", Resources: []string{"addon/prod/vpc-cni", "cluster/prod"}},
		{ID: "ct5", Time: t0, Name: "PutObject", Source: "s3.amazonaws.com", Resources: []string{"bucket"}},
	}}
	p := NewCloudTrailPoll(src, Options{}, nil, []byte(`{"next":"w"}`), t0)
	sigs, cp, read, kept, err := p.Poll(context.Background(), v, t0)
	if err != nil {
		t.Fatal(err)
	}
	if string(src.cp) != `{"next":"w"}` || !src.since.Equal(t0.Add(-time.Hour)) || string(cp) != `{"next":"x"}` || read != 5 || kept != 2 {
		t.Errorf("poll: since %s cp %s → %s, read %d kept %d", src.since, src.cp, cp, read, kept)
	}
	want := []string{"cloudtrail-change context Deployment/api", "cloudtrail-change context Cluster/prod"}
	if s := sigSummary(sigs); !reflect.DeepEqual(s, want) {
		t.Fatalf("signals: %v", s)
	}
	if sigs[0].Title != "erin called ec2:AuthorizeSecurityGroupIngress on sg-0abc" || strings.Contains(sigs[0].Attrs["raw"], "AKIA") ||
		sigs[0].Object.Kind != "AWS::EC2" || sigs[0].Object.Name != "sg-0abc" {
		t.Errorf("signal: %+v", sigs[0])
	}
	// Re-read (lookup's overlap): nothing twice.
	if sigs, _, _, _, _ = p.Poll(context.Background(), v, t0); len(sigs) != 0 {
		t.Errorf("repeat: %v", sigSummary(sigs))
	}
}

// fakeLogs counts lines per window.
type fakeLogs struct {
	perMinute func(from time.Time) int
	queries   []LogQuery
}

func (f *fakeLogs) Name() string { return "kubernetes" }
func (f *fakeLogs) Logs(_ context.Context, q LogQuery) (LogResult, error) {
	f.queries = append(f.queries, q)
	var res LogResult
	for t := q.From; t.Before(q.To); t = t.Add(time.Minute) {
		for i := 0; i < f.perMinute(t); i++ {
			res.Lines = append(res.Lines, LogLine{Time: t, Level: "error", Text: "boom"})
		}
	}
	return res, nil
}

func TestLogErrors(t *testing.T) {
	logs := &fakeLogs{perMinute: func(at time.Time) int {
		if at.Before(t0) {
			return 1 // the usual rate
		}
		if at.Before(t0.Add(4 * time.Minute)) {
			return 20
		}
		return 1
	}}
	p := NewLogErrors(logs, Options{})
	in := Incident{ID: "inc", Subject: apiSubject, State: Open, Severity: Critical, Start: t0, Pods: []string{"api-7d9f-a", "api-7d9f-b"}}
	got, err := p.Scan(context.Background(), []Incident{in}, t0.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if s := sigSummary(got); !reflect.DeepEqual(s, []string{"log-errors context Deployment/api"}) {
		t.Fatalf("burst: %v", s)
	}
	if *got[0].Baseline != 1 || *got[0].Value != 20 || got[0].Count != 40 || !got[0].Start.Equal(t0) {
		t.Errorf("signal: %+v", got[0])
	}
	if q := logs.queries[0]; !q.From.Equal(t0.Add(-15*time.Minute)) || q.Level != "error" || q.Namespace != "shop" || len(q.Pods) != 2 {
		t.Errorf("query before: %+v", q)
	}
	got, _ = p.Scan(context.Background(), []Incident{in}, t0.Add(4*time.Minute))
	if len(got) != 1 || got[0].Count != 80 || got[0].End != nil {
		t.Fatalf("still bursting: %+v", got)
	}
	got, _ = p.Scan(context.Background(), []Incident{in}, t0.Add(6*time.Minute))
	if len(got) != 1 || got[0].End == nil || !got[0].End.Equal(t0.Add(4*time.Minute)) {
		t.Fatalf("ended: %+v", got)
	}
}
