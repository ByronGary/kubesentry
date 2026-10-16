package demo

// The demo's incidents: three stories told through the real incidents
// engine, which turns a scripted timeline of signals into incidents, with
// charts, Kubernetes events and container logs that line up with them.
//
//   - checkout-web (prod), open and critical: a release 20 minutes before
//     its requests spiked to almost five times their baseline while one pod
//     ran at 93% of its memory limit; readiness probes failed, the HPA
//     scaled out, dave patched its ConfigMap, someone opened its load
//     balancer's security group, and error logs kept coming after the
//     request spike ended.
//   - recommendations (prod), open and critical: release 4.0.0 was OOM
//     killed on its first start and has crash-looped since.
//   - catalog-api (prod), resolved: 8% of its requests failed for twelve
//     minutes six hours ago; its error logs ran on past the end, inside
//     the padded window.

import (
	"context"
	"fmt"
	"hash/fnv"
	"math"
	"math/rand"
	"sort"
	"strings"
	"time"

	"github.com/ByronGary/kubesentry/internal/api"
	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/incidents"
	"github.com/ByronGary/kubesentry/internal/model"
	"github.com/ByronGary/kubesentry/internal/snapshot"
)

// The audit event behind checkout-web's "change" (seeded by SeedAudit).
const (
	configPatchAuditID = "demo-cm-patch"
	configPatchAgo     = 52 * time.Minute
)

// The pods the stories are about.
const (
	webPod     = "checkout-web-6b8c9d7f5-4tn2m"
	webPod2    = "checkout-web-6b8c9d7f5-j7v9c"
	recsPod    = "recommendations-6d5f7c8b9-zt4qx"
	catalogPod = "catalog-api-5f7d8c9b6-m2xk4"
	albSG      = "sg-0a7c3e91b2d4f6810"
)

// story is the timeline, relative to t0 (the demo's start).
type story struct {
	t0      time.Time
	created map[string]time.Time // namespace/pod → creation
	main    map[string]string    // namespace/pod → its first container
	uids    map[string]string    // pod in prod → UID
}

func newStory(c *Cluster, t0 time.Time) *story {
	s := &story{t0: t0, created: map[string]time.Time{}, main: map[string]string{}, uids: map[string]string{}}
	for _, p := range c.pods {
		k := p.Namespace + "/" + p.Name
		s.created[k] = p.Created
		for _, ct := range p.Containers {
			if !ct.Init {
				s.main[k] = ct.Name
				break
			}
		}
		if p.Namespace == "prod" {
			s.uids[p.Name] = p.UID
		}
	}
	return s
}

// ago is the time d before t0.
func (s *story) ago(d time.Duration) time.Time { return s.t0.Add(-d) }

func (s *story) pod(name string) model.ObjectRef {
	return model.ObjectRef{Kind: "Pod", Namespace: "prod", Name: name, UID: s.uids[name]}
}

func deployment(name string) incidents.Subject {
	return incidents.Subject{Kind: "Deployment", Namespace: "prod", Name: name}
}

func fp(v float64) *float64 { return &v }

func tp(t time.Time) *time.Time { return &t }

// When the stories happen.
const (
	webDeployAgo  = 60 * time.Minute
	webSpikeAgo   = 40 * time.Minute // the request spike begins, the incident opens
	webSpikeEnd   = 12 * time.Minute
	webMemAgo     = 36 * time.Minute
	recsDeployAgo = 50 * time.Minute
	recsOOMAgo    = 47 * time.Minute
	recsLoopAgo   = 44 * time.Minute
	catErrAgo     = 6 * time.Hour
	catErrEnd     = 6*time.Hour - 12*time.Minute
	catLogsEnd    = 6*time.Hour - 20*time.Minute // error logs go on 8 minutes past the end
)

// incidentIDOf is the ID the engine gives the incident a trigger opens.
func incidentIDOf(subj incidents.Subject, start time.Time) string {
	return incidents.IncidentID(subj, incidents.NormalTime(start))
}

// events are the Kubernetes events of the stories, as the event watcher
// would have stored them.
func (s *story) events() []incidents.StoredEvent {
	web, recs, cat := deployment("checkout-web"), deployment("recommendations"), deployment("catalog-api")
	ev := func(uid, ns, typ, reason, msg string, count int32, first, last time.Time, regarding model.ObjectRef, source string, subj incidents.Subject) incidents.StoredEvent {
		return incidents.StoredEvent{KubeEvent: model.KubeEvent{UID: uidOf("event/" + uid), Namespace: ns, Type: typ, Reason: reason, Message: msg,
			Count: count, FirstSeen: first, LastSeen: last, Regarding: regarding, Source: source}, Subject: &subj}
	}
	return []incidents.StoredEvent{
		ev("web-unhealthy", "prod", "Warning", "Unhealthy",
			`Readiness probe failed: Get "http://10.0.12.80:8080/healthz": context deadline exceeded (Client.Timeout exceeded while awaiting headers)`,
			7, s.ago(37*time.Minute), s.ago(14*time.Minute), s.pod(webPod), "kubelet", web),
		ev("web-rescale", "prod", "Normal", "SuccessfulRescale", "New size: 3; reason: cpu resource utilization (percentage of request) above target",
			1, s.ago(38*time.Minute), s.ago(38*time.Minute), model.ObjectRef{Kind: "HorizontalPodAutoscaler", Namespace: "prod", Name: "checkout-web"},
			"horizontal-pod-autoscaler", web),
		ev("recs-backoff", "prod", "Warning", "BackOff", "Back-off restarting failed container api in pod "+recsPod+"_prod("+s.uids[recsPod]+")",
			41, s.ago(recsLoopAgo), s.ago(time.Minute), s.pod(recsPod), "kubelet", recs),
		// Reported on the node: only callers who may see nodes get it.
		ev("recs-oom", "", "Warning", "OOMKilling",
			"Memory cgroup out of memory: Killed process 2211 (recommendations) total-vm:1832404kB, anon-rss:520112kB, file-rss:0kB, shmem-rss:0kB",
			1, s.ago(recsOOMAgo), s.ago(recsOOMAgo), model.ObjectRef{Kind: "Node", Name: nodeB}, "kernel-monitor", recs),
		ev("catalog-unhealthy", "prod", "Warning", "Unhealthy", "Readiness probe failed: HTTP probe failed with statuscode: 503",
			4, s.ago(catErrAgo-3*time.Minute), s.ago(catErrAgo-10*time.Minute), s.pod(catalogPod), "kubelet", cat),
	}
}

// signals are what the producers would have reported, in their own forms.
func (s *story) signals() []incidents.Signal {
	web, recs, cat := deployment("checkout-web"), deployment("recommendations"), deployment("catalog-api")
	webSvc := model.ObjectRef{Kind: "Service", Namespace: "prod", Name: "checkout-web"}
	webID := incidentIDOf(web, s.ago(webSpikeAgo))
	recsID := incidentIDOf(recs, s.ago(recsOOMAgo))
	catID := incidentIDOf(cat, s.ago(catErrAgo))
	unix := func(d time.Duration) int64 { return incidents.NormalTime(s.ago(d)).Unix() }
	limit := float64(256 << 20)
	recsAttrs := func(reason, exit, restarts string) map[string]string {
		return map[string]string{"pod": recsPod, "container": "api", "reason": reason, "exitCode": exit, "restarts": restarts, "node": nodeB}
	}
	ct := `{"eventVersion":"1.09","eventSource":"ec2.amazonaws.com","eventName":"AuthorizeSecurityGroupIngress","awsRegion":"us-east-1",` +
		`"userIdentity":{"type":"AssumedRole","arn":"arn:aws:sts::111122223333:assumed-role/NetworkAdmin/jordan"},` +
		`"requestParameters":{"groupId":"` + albSG + `","ipPermissions":{"items":[{"ipProtocol":"tcp","fromPort":8443,"toPort":8443,` +
		`"ipRanges":{"items":[{"cidrIp":"0.0.0.0/0","description":"temp debug"}]}}]}}}`
	return []incidents.Signal{
		// checkout-web.
		{ID: "view:deploy:Deployment/prod/checkout-web@14", Type: incidents.TypeDeploy, Source: incidents.SourceView, Role: incidents.Context,
			Start: s.ago(webDeployAgo), Subject: web, Object: model.ObjectRef{Kind: "Deployment", Namespace: "prod", Name: "checkout-web"},
			Title: "Deployment checkout-web rolled out revision 14: web: registry.example.com/shop/checkout-web:2.8.0 → registry.example.com/shop/checkout-web:2.8.1",
			Attrs: map[string]string{"fromRevision": "13", "toRevision": "14",
				"images": "web: registry.example.com/shop/checkout-web:2.8.0 → registry.example.com/shop/checkout-web:2.8.1"}},
		{ID: "audit:" + configPatchAuditID, Type: incidents.TypeAuditChange, Source: incidents.SourceAudit, Role: incidents.Context,
			Start: s.ago(configPatchAgo), Subject: incidents.Subject{Kind: incidents.KindNamespace, Name: "prod"},
			Object: model.ObjectRef{Kind: "ConfigMap", Namespace: "prod", Name: "checkout-web-config"},
			Title:  "dave patched configmaps prod/checkout-web-config",
			Attrs: map[string]string{"user": "dave", "verb": "patch", "resource": "configmaps", "auditID": configPatchAuditID, "statusCode": "200",
				"userAgent": "kubectl/v1.31.0", "sourceIP": "10.0.12.34", "arn": "arn:aws:iam::111122223333:role/Developer"}},
		{ID: fmt.Sprintf("metrics:request-spike:prod/Service/checkout-web@%d", unix(webSpikeAgo)), Type: incidents.TypeRequestSpike,
			Source: incidents.SourceMetrics, Role: incidents.Trigger, Severity: incidents.Critical, Start: s.ago(webSpikeAgo), End: tp(s.ago(webSpikeEnd)),
			Subject: web, Object: webSvc, Value: fp(552), Baseline: fp(118), Threshold: fp(236),
			Title: "Service checkout-web requests at 552.0/s, 4.68x the baseline of 118.0/s",
			Attrs: map[string]string{"source": "nginx", "window": "5m0s", "baselineWindow": "1h0m0s", "ratio": "4.68"}},
		{ID: "events:" + uidOf("event/web-rescale") + "#1", Type: incidents.TypeKubeEvent, Source: incidents.SourceEvents, Role: incidents.Context,
			Start: s.ago(38 * time.Minute), Subject: web, Count: 1,
			Object: model.ObjectRef{Kind: "HorizontalPodAutoscaler", Namespace: "prod", Name: "checkout-web"},
			Title:  "SuccessfulRescale: New size: 3; reason: cpu resource utilization (percentage of request) above target",
			Attrs:  map[string]string{"reason": "SuccessfulRescale", "type": "Normal", "count": "1", "component": "horizontal-pod-autoscaler"}},
		{ID: "events:" + uidOf("event/web-unhealthy") + "#7", Type: incidents.TypeKubeEvent, Source: incidents.SourceEvents, Role: incidents.Trigger,
			Severity: incidents.Warning, Start: s.ago(37 * time.Minute), End: tp(s.ago(14 * time.Minute)), Subject: web, Object: s.pod(webPod), Count: 7,
			Title: `Unhealthy: Readiness probe failed: Get "http://10.0.12.80:8080/healthz": context deadline exceeded`,
			Attrs: map[string]string{"reason": "Unhealthy", "type": "Warning", "count": "7", "component": "kubelet"}},
		{ID: fmt.Sprintf("metrics:memory-spike:prod/Deployment/checkout-web/web@%d", unix(webMemAgo)), Type: incidents.TypeMemorySpike,
			Source: incidents.SourceMetrics, Role: incidents.Trigger, Severity: incidents.Warning, Start: s.ago(webMemAgo), Subject: web,
			Object: s.pod(webPod), Value: fp(0.93 * limit), Threshold: fp(0.85 * limit),
			Title: webPod + "/web at 93% of its memory limit",
			Attrs: map[string]string{"container": "web", "pod": webPod, "limit": "268435456"}},
		{ID: "cloudtrail:5d2e7c1a-9b3f-4e8d-a6c0-1f2b3c4d5e6f", Type: incidents.TypeCloudTrailChange, Source: incidents.SourceCloudTrail,
			Role: incidents.Context, Start: s.ago(33 * time.Minute), Subject: web,
			Object: model.ObjectRef{Kind: "AWS::EC2::SecurityGroup", Name: albSG},
			Title:  "NetworkAdmin/jordan called ec2:AuthorizeSecurityGroupIngress on " + albSG,
			Attrs: map[string]string{"eventID": "5d2e7c1a-9b3f-4e8d-a6c0-1f2b3c4d5e6f", "eventName": "AuthorizeSecurityGroupIngress",
				"eventSource": "ec2.amazonaws.com", "region": "us-east-1", "actor": "arn:aws:sts::111122223333:assumed-role/NetworkAdmin/jordan",
				"resources": albSG, "matched": albSG, "raw": ct}},
		{ID: fmt.Sprintf("logs:log-errors:%s@%d", webID, unix(38*time.Minute)), Type: incidents.TypeLogErrors, Source: incidents.SourceLogs,
			Role: incidents.Context, Start: s.ago(38 * time.Minute), End: tp(s.ago(4 * time.Minute)), Subject: web, Object: s.pod(webPod),
			Value: fp(18), Baseline: fp(0.4), Count: 212, Title: "212 error log lines, up to 18 a minute (0.4 before the incident)",
			Attrs: map[string]string{"incident": webID, "source": "kubernetes"}},

		// recommendations.
		{ID: "view:deploy:Deployment/prod/recommendations@7", Type: incidents.TypeDeploy, Source: incidents.SourceView, Role: incidents.Context,
			Start: s.ago(recsDeployAgo), Subject: recs, Object: model.ObjectRef{Kind: "Deployment", Namespace: "prod", Name: "recommendations"},
			Title: "Deployment recommendations rolled out revision 7: api: registry.example.com/shop/recommendations:3.9.2 → registry.example.com/shop/recommendations:4.0.0",
			Attrs: map[string]string{"fromRevision": "6", "toRevision": "7",
				"images": "api: registry.example.com/shop/recommendations:3.9.2 → registry.example.com/shop/recommendations:4.0.0"}},
		{ID: "view:oom-kill:prod/" + recsPod + "/api#1", Type: incidents.TypeOOMKill, Source: incidents.SourceView, Role: incidents.Trigger,
			Severity: incidents.Critical, Start: s.ago(recsOOMAgo), Subject: recs, Object: s.pod(recsPod), Count: 1,
			Title: recsPod + "/api was OOM killed", Attrs: recsAttrs("OOMKilled", "137", "1")},
		{ID: "view:restart:prod/" + recsPod + "/api#14", Type: incidents.TypeRestart, Source: incidents.SourceView, Role: incidents.Context,
			Start: s.ago(recsLoopAgo), End: tp(s.ago(3 * time.Minute)), Subject: recs, Object: s.pod(recsPod), Count: 13,
			Title: recsPod + "/api restarted 13 times (last: Error, exit 1)", Attrs: recsAttrs("Error", "1", "14")},
		{ID: fmt.Sprintf("view:crashloop:prod/%s/api@%d", recsPod, unix(recsLoopAgo)), Type: incidents.TypeCrashLoop, Source: incidents.SourceView,
			Role: incidents.Trigger, Severity: incidents.Critical, Start: s.ago(recsLoopAgo), Subject: recs, Object: s.pod(recsPod), Count: 14,
			Title: recsPod + "/api is crash-looping",
			Attrs: map[string]string{"pod": recsPod, "container": "api", "restarts": "14", "lastReason": "Error", "exitCode": "1",
				"message": "back-off 5m0s restarting failed container=api pod=" + recsPod + "_prod"}},
		{ID: "events:" + uidOf("event/recs-backoff") + "#41", Type: incidents.TypeKubeEvent, Source: incidents.SourceEvents, Role: incidents.Trigger,
			Severity: incidents.Warning, Start: s.ago(recsLoopAgo), End: tp(s.ago(time.Minute)), Subject: recs, Object: s.pod(recsPod), Count: 41,
			Title: "BackOff: Back-off restarting failed container api in pod " + recsPod + "_prod",
			Attrs: map[string]string{"reason": "BackOff", "type": "Warning", "count": "41", "component": "kubelet"}},
		{ID: fmt.Sprintf("logs:log-errors:%s@%d", recsID, unix(recsOOMAgo)), Type: incidents.TypeLogErrors, Source: incidents.SourceLogs,
			Role: incidents.Context, Start: s.ago(recsOOMAgo), Subject: recs, Object: s.pod(recsPod),
			Value: fp(6), Baseline: fp(0), Count: 58, Title: "58 error log lines, up to 6 a minute (0.0 before the incident)",
			Attrs: map[string]string{"incident": recsID, "source": "kubernetes"}},

		// catalog-api, resolved.
		{ID: "events:" + uidOf("event/catalog-unhealthy") + "#4", Type: incidents.TypeKubeEvent, Source: incidents.SourceEvents, Role: incidents.Context,
			Start: s.ago(catErrAgo - 3*time.Minute), End: tp(s.ago(catErrAgo - 10*time.Minute)), Subject: cat, Object: s.pod(catalogPod), Count: 4,
			Title: "Unhealthy: Readiness probe failed: HTTP probe failed with statuscode: 503",
			Attrs: map[string]string{"reason": "Unhealthy", "type": "Warning", "count": "4", "component": "kubelet"}},
		{ID: fmt.Sprintf("metrics:error-rate:prod/Service/catalog-api@%d", unix(catErrAgo)), Type: incidents.TypeErrorRate,
			Source: incidents.SourceMetrics, Role: incidents.Trigger, Severity: incidents.Warning, Start: s.ago(catErrAgo), End: tp(s.ago(catErrEnd)),
			Subject: cat, Object: model.ObjectRef{Kind: "Service", Namespace: "prod", Name: "catalog-api"}, Value: fp(0.083), Threshold: fp(0.05),
			Title: "Service catalog-api: 8% of requests failed", Attrs: map[string]string{"source": "nginx", "rps": "64.20"}},
		{ID: fmt.Sprintf("logs:log-errors:%s@%d", catID, unix(catErrAgo)), Type: incidents.TypeLogErrors, Source: incidents.SourceLogs,
			Role: incidents.Context, Start: s.ago(catErrAgo), End: tp(s.ago(catLogsEnd)), Subject: cat, Object: s.pod(catalogPod),
			Value: fp(9), Baseline: fp(0.2), Count: 96, Title: "96 error log lines, up to 9 a minute (0.2 before the incident)",
			Attrs: map[string]string{"incident": catID, "source": "kubernetes"}},
	}
}

// runTimeline feeds the signals to an engine minute by minute, on a clock
// that ends at now, as the producers would have: conditions are reported
// again every minute while they last, points once, and both once more when
// they end. Then it commits the incidents to store.
func runTimeline(ctx context.Context, store incidents.Store, v *snapshot.View, sigs []incidents.Signal, now time.Time) error {
	sort.SliceStable(sigs, func(i, j int) bool { return sigs[i].Start.Before(sigs[j].Start) })
	clock := sigs[0].Start.Truncate(time.Minute)
	eng := incidents.NewEngine(store, incidents.NewBoard(0), incidents.Options{Now: func() time.Time { return clock }})
	if err := eng.Load(ctx); err != nil {
		return err
	}
	eng.SetView(v)
	type progress struct{ reported, ended bool }
	state := make([]progress, len(sigs))
	for ; ; clock = clock.Add(time.Minute) {
		if clock.After(now) {
			clock = now
		}
		for i := range sigs {
			s, st := sigs[i], &state[i]
			if s.Start.After(clock) || st.ended {
				continue
			}
			if s.End != nil && !s.End.After(clock) {
				eng.Add(s)
				st.ended = true
				continue
			}
			if st.reported && !incidents.IsCondition(s.Type) {
				continue
			}
			s.End = nil
			eng.Add(s)
			st.reported = true
		}
		eng.Tick()
		if clock.Equal(now) {
			break
		}
	}
	return eng.Flush(ctx)
}

// demoIncidents serves the seeded incidents. The engine does not run
// (nothing new happens in the demo), so this replica is said to lead.
type demoIncidents struct{ *incidents.Runner }

func (demoIncidents) Leader() bool { return true }

// The sources /info reports as configured. The demo never calls them: its
// incidents are seeded.
type (
	idleRates      struct{}
	idleMemory     struct{}
	idleEvents     struct{}
	idleCloudTrail struct{}
)

func (idleRates) Name() string { return "nginx" }
func (idleRates) Rates(context.Context, time.Time, time.Duration, time.Duration, []string) ([]model.RateSample, error) {
	return nil, nil
}
func (idleRates) Probe(context.Context) string { return "ok" }
func (idleMemory) MemoryUsage(context.Context, time.Time, []string) ([]model.MemorySample, error) {
	return nil, nil
}
func (idleEvents) Run(ctx context.Context, _ func([]model.KubeEvent)) error {
	<-ctx.Done()
	return nil
}
func (idleCloudTrail) Name() string { return "lookup" }
func (idleCloudTrail) Changes(context.Context, time.Time, []byte) ([]incidents.CloudTrailEvent, []byte, error) {
	return nil, nil, nil
}
func (idleCloudTrail) Probe(context.Context) string { return "ok" }

// NewIncidents tells the stories through the engine and returns what the
// API serves them from: the runner and its store. Charts come from m, logs
// from a deterministic source, audit events from auditStore.
func NewIncidents(ctx context.Context, c *Cluster, m *Metrics, auditStore audit.Store, policy detectors.Policy, now time.Time) (api.IncidentsSource, incidents.Store, error) {
	inv, err := c.Inventory(ctx)
	if err != nil {
		return nil, nil, err
	}
	now = now.Truncate(time.Second) // whole seconds read better in IDs and times
	st := newStory(c, now)
	store := incidents.NewMemoryStore()
	if err := runTimeline(ctx, store, snapshot.Build(inv, policy, now), st.signals(), now); err != nil {
		return nil, nil, fmt.Errorf("demo incidents: %w", err)
	}
	evs := incidents.NewMemoryEventStore()
	if err := evs.AddEvents(ctx, st.events()); err != nil {
		return nil, nil, err
	}
	r, err := incidents.NewRunner(incidents.Config{
		Store: store, Events: evs, Series: incidentSeries{m: m, st: st}, Logs: []incidents.LogSource{demoLogs{st: st}}, Audit: auditStore,
		Rates: []incidents.RateSource{idleRates{}}, Memory: idleMemory{}, EventSource: idleEvents{}, CloudTrail: idleCloudTrail{},
		Options: incidents.Options{Cluster: "demo-eks"},
	})
	if err != nil {
		return nil, nil, err
	}
	if err := r.Refresh(ctx, store, true); err != nil {
		return nil, nil, err
	}
	return demoIncidents{r}, store, nil
}

// noise is a stable value in [-1, 1) for a key and a minute.
func noise(key string, t time.Time) float64 {
	h := fnv.New64a()
	fmt.Fprintf(h, "%s@%d", key, t.Unix()/60)
	return float64(h.Sum64()%2000)/1000 - 1
}

// ramp rises from 0 to 1 over d after start, and falls back over d before
// end (no end: it stays).
func ramp(t, start time.Time, end *time.Time, d time.Duration) float64 {
	if t.Before(start) || (end != nil && !t.Before(*end)) {
		return 0
	}
	f := math.Min(1, float64(t.Sub(start))/float64(d))
	if end != nil {
		f = math.Min(f, float64(end.Sub(t))/float64(d))
	}
	return f
}

// memory is a container's memory in MiB at t, the story's where it tells
// one; ok is false where nothing would have been scraped.
func (s *story) memory(k model.ContainerKey, p profile, t time.Time, base func() float64) (float64, bool) {
	if c, ok := s.created[k.Namespace+"/"+k.Pod]; ok && t.Before(c) {
		return 0, false
	}
	if k.Namespace != "prod" {
		return base(), true
	}
	switch k.Pod {
	case webPod:
		b := base()
		return b + (0.93*p.limitMiB-b)*ramp(t, s.ago(webMemAgo+3*time.Minute), nil, 3*time.Minute) + noise(k.Pod, t)*2, true
	case webPod2:
		b := base()
		return b + (0.88*p.limitMiB-b)*ramp(t, s.ago(33*time.Minute), tp(s.ago(20*time.Minute)), 3*time.Minute), true
	case recsPod:
		switch since := t.Sub(s.ago(recsDeployAgo)); {
		case t.Before(s.ago(recsOOMAgo)):
			return 120 + (0.985*p.limitMiB-120)*float64(since)/float64(recsDeployAgo-recsOOMAgo), true
		case t.Before(s.ago(recsLoopAgo)):
			return 0, false
		default:
			phase := t.Sub(s.ago(recsLoopAgo)) % (4 * time.Minute)
			if phase > 75*time.Second {
				return 0, false // in back-off: not running
			}
			return 60 + 100*float64(phase)/float64(75*time.Second), true
		}
	}
	return base(), true
}

// requests is a Service's request rate and 5xx share at t.
func (s *story) requests(svc string, t time.Time) (rps, errs float64) {
	day := 1 + 0.15*math.Sin(2*math.Pi*float64(t.Hour()*60+t.Minute())/1440)
	n := noise(svc, t)
	switch svc {
	case "checkout-web":
		spike := ramp(t, s.ago(webSpikeAgo+2*time.Minute), tp(s.ago(webSpikeEnd)), 4*time.Minute)
		rps = 118 * day * (1 + 3.7*spike) * (1 + 0.04*n)
		errs = 0.004 + 0.05*spike*(0.8+0.2*n) + 0.02*ramp(t, s.ago(webMemAgo), nil, 5*time.Minute)*(1+n)/2
	case "recommendations":
		rps, errs = 18*day*(1+0.06*n), 0.002
		if !t.Before(s.ago(recsOOMAgo)) {
			rps, errs = 16*(1+0.1*n), 0.35+0.05*n
		}
	case "catalog-api":
		rps, errs = 64*day*(1+0.05*n), 0.003
		if bad := ramp(t, s.ago(catErrAgo+time.Minute), tp(s.ago(catErrEnd)), 2*time.Minute); bad > 0 {
			errs = 0.003 + 0.08*bad*(1+0.1*n)
		}
	case "checkout-api":
		rps, errs = 90*day*(1+0.05*n), 0.002
	default:
		rps, errs = 20*day*(1+0.05*n), 0.001
	}
	return rps, math.Max(0, errs)
}

// incidentSeries draws an incident's charts from the demo's memory profiles
// and the story's request rates.
type incidentSeries struct {
	m  *Metrics
	st *story
}

func (s incidentSeries) SubjectSeries(_ context.Context, q incidents.SeriesQuery) ([]incidents.Series, error) {
	if q.Namespace == "" || !q.To.After(q.From) {
		return nil, nil
	}
	step := q.Step
	if step <= 0 {
		step = incidents.SeriesStep(q.From, q.To)
	}
	start := q.From.Truncate(step)
	if start.Before(q.From) {
		start = start.Add(step)
	}
	ms := func(t time.Time) float64 { return float64(t.UnixMilli()) }
	var out []incidents.Series
	for _, pod := range q.Pods {
		var keys []model.ContainerKey
		for k := range s.m.profiles {
			if k.Namespace == q.Namespace && k.Pod == pod {
				keys = append(keys, k)
			}
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i].Container < keys[j].Container })
		for _, k := range keys {
			p := s.m.profiles[k]
			rng := rand.New(rand.NewSource(int64(hash(k))))
			pts := [][2]float64{}
			for t := start; !t.After(q.To); t = t.Add(step) {
				if v, ok := s.st.memory(k, p, t, func() float64 { return s.m.valueAt(p, t, rng) }); ok {
					pts = append(pts, [2]float64{ms(t), v * mib})
				}
			}
			if len(pts) > 0 {
				out = append(out, incidents.Series{Metric: "memory", Label: pod + "/" + k.Container, Unit: "bytes", Source: "prometheus", Points: pts})
			}
		}
	}
	for _, svc := range q.Services {
		req, errs := [][2]float64{}, [][2]float64{}
		for t := start; !t.After(q.To); t = t.Add(step) {
			r, e := s.st.requests(svc, t)
			req = append(req, [2]float64{ms(t), math.Round(r*10) / 10})
			errs = append(errs, [2]float64{ms(t), math.Round(e*10000) / 10000})
		}
		out = append(out, incidents.Series{Metric: "requests", Label: svc, Unit: "rps", Source: "nginx", Points: req},
			incidents.Series{Metric: "errors", Label: svc, Unit: "ratio", Source: "nginx", Points: errs})
	}
	return out, nil
}

// demoLogs writes every pod a line every 20 seconds or so, the same for the
// same pod and time, telling the stories in their pods' logs.
type demoLogs struct{ st *story }

func (demoLogs) Name() string { return "kubernetes" }

const logStep = 20 * time.Second

var logRanks = map[string]int{"debug": 0, "info": 1, "": 1, "warn": 2, "error": 3}

func (d demoLogs) Logs(_ context.Context, q incidents.LogQuery) (incidents.LogResult, error) {
	var res incidents.LogResult
	if !q.To.After(q.From) {
		return res, nil
	}
	minRank := logRanks[q.Level]
	text := strings.ToLower(q.Text)
	limit := q.Limit
	if limit <= 0 {
		limit = 2000
	}
	start := q.From.Truncate(logStep)
	if start.Before(q.From) {
		start = start.Add(logStep)
	}
	var size int64
	for t := start; !t.After(q.To); t = t.Add(logStep) {
		for _, pod := range q.Pods {
			l, ok := d.st.line(q.Namespace, pod, t)
			if !ok || (len(q.Containers) > 0 && !contains(q.Containers, l.Container)) || logRanks[l.Level] < minRank ||
				(text != "" && !strings.Contains(strings.ToLower(l.Text), text)) {
				continue
			}
			size += int64(len(l.Text))
			if len(res.Lines) >= limit || (q.MaxBytes > 0 && size > q.MaxBytes) {
				res.Truncated = true
				return res, nil
			}
			res.Lines = append(res.Lines, l)
		}
	}
	return res, nil
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// line is what pod logged at t, if anything.
func (s *story) line(ns, pod string, t time.Time) (incidents.LogLine, bool) {
	if c, ok := s.created[ns+"/"+pod]; ok && t.Before(c) {
		return incidents.LogLine{}, false
	}
	h := fnv.New32a()
	fmt.Fprintf(h, "%s/%s@%d", ns, pod, t.Unix())
	r := h.Sum32() % 100
	mk := func(container, level, text string) (incidents.LogLine, bool) {
		return incidents.LogLine{Time: t.Add(time.Duration(h.Sum32()%19000) * time.Millisecond), Pod: pod, Container: container, Level: level,
			Text: text, Source: "kubernetes"}, true
	}
	in := func(from, to time.Duration) bool { return !t.Before(s.ago(from)) && t.Before(s.ago(to)) }
	switch {
	case pod == webPod || pod == webPod2:
		troubled := (pod == webPod && in(38*time.Minute, 0)) || (pod == webPod2 && in(33*time.Minute, 20*time.Minute))
		switch {
		case troubled && r < 35:
			return mk("web", "error", `upstream timed out (110: Connection timed out) while reading response header from upstream, client: 10.0.45.12, request: "POST /api/checkout HTTP/1.1", upstream: "http://10.100.11.23:8080/api/checkout"`)
		case troubled && r < 45:
			return mk("web", "warn", fmt.Sprintf("GC pause %dms, heap %dMiB of 256MiB", 180+r*7, 220+r%17))
		case troubled && r == 45:
			// A secret a careless log line leaks: the API redacts it.
			return mk("web", "error", "payment call failed, retrying with Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjaGVja291dCJ9.c2lnbmF0dXJlLXJlZGFjdGVk")
		case troubled:
			return mk("web", "info", fmt.Sprintf("POST /api/checkout 200 %dms", 900+int(r)*31))
		case r < 2:
			return mk("web", "warn", "slow upstream response from checkout-api: 640ms")
		case r < 60:
			return mk("web", "info", fmt.Sprintf("GET /api/cart 200 %dms", 8+r%23))
		}
	case pod == recsPod:
		switch {
		case in(recsOOMAgo, recsOOMAgo-20*time.Second):
			return mk("api", "error", "fatal error: runtime: out of memory")
		case t.Before(s.ago(recsOOMAgo)) && r < 50:
			return mk("api", "info", "loading model from s3://shop-models/recs/v4/model.bin (1.9 GiB)")
		case !t.Before(s.ago(recsLoopAgo)):
			switch phase := t.Sub(s.ago(recsLoopAgo)) % (4 * time.Minute); {
			case phase < logStep:
				return mk("api", "info", "starting recommendations 4.0.0 (commit 3f9a2c1)")
			case phase < 2*logStep:
				return mk("api", "warn", "RECS_MODEL_URL is not set; falling back to the v3 feature store at 10.100.14.62:6379")
			case phase < 4*logStep:
				return mk("api", "error", "panic: feature store unreachable: dial tcp 10.100.14.62:6379: connect: connection refused")
			}
		}
	case pod == catalogPod:
		switch {
		case in(catErrAgo, catLogsEnd) && r < 45:
			return mk("api", "error", "upstream inventory-svc returned 503 Service Unavailable (GET /v1/stock?sku=…)")
		case in(catErrAgo, catLogsEnd) && r < 55:
			return mk("api", "warn", "circuit breaker open for inventory-svc; serving cached stock")
		case r < 50:
			return mk("api", "info", fmt.Sprintf("GET /v1/products 200 %dms", 12+r%30))
		}
	default:
		if c := s.main[ns+"/"+pod]; c != "" && r < 25 {
			return mk(c, "info", "GET /healthz 200 1ms")
		}
	}
	return incidents.LogLine{}, false
}
