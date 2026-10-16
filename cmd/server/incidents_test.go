package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/ByronGary/kubesentry/internal/api"
	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/incidents"
	"github.com/ByronGary/kubesentry/internal/kube"
	"github.com/ByronGary/kubesentry/internal/metrics"
	"github.com/ByronGary/kubesentry/internal/model"
	"github.com/ByronGary/kubesentry/internal/prom"
	"github.com/ByronGary/kubesentry/internal/snapshot"
)

func TestIncidentsFlags(t *testing.T) {
	c, err := parseFlags(nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	ic := c.incidents
	if ic.enabled || ic.maxRange != 24*time.Hour || ic.retention != 7*24*time.Hour || ic.eventsRetention != 48*time.Hour ||
		ic.quiet != 15*time.Minute || ic.lookbehind != 30*time.Minute || ic.logLead != 5*time.Minute || ic.logLag != 10*time.Minute ||
		ic.interval != time.Minute || strings.Join(ic.requestSources.items, ",") != "nginx,app" || ic.cloudtrail != "off" || ic.logs != "auto" ||
		ic.memoryJumpMin != 128<<20 || ic.logsMaxBytes != 1<<20 || ic.logsMaxLines != 2000 || ic.cloudtrailQPS != 1 || ic.cloudtrailStart != time.Hour ||
		strings.Join(ic.eventNormalReasons.items, ",") != "SuccessfulRescale" || ic.requestRatio != 2 || ic.memoryPct != 85 || ic.eventMinCount != 3 {
		t.Errorf("defaults = %+v", ic)
	}
	if c.incidents.appLabelKeys() != nil {
		t.Errorf("app label keys without -incidents = %v", c.incidents.appLabelKeys())
	}
	bad := [][]string{
		{"-cloudtrail=lookup"}, // without -incidents
		{"-incidents", "-cache=false"},
		{"-incidents", "-incident-max-range=25h"},
		{"-incidents", "-incident-max-range=0s"},
		{"-incidents", "-incident-interval=1s"},
		{"-incidents", "-incident-retention=12h"},
		{"-incidents", "-incident-events-retention=10m"},
		{"-incidents", "-incident-quiet=0s"},
		{"-incidents", "-incident-spike-baseline=5m"},
		{"-incidents", "-incident-request-ratio=1"},
		{"-incidents", "-incident-request-crit-ratio=1.5"},
		{"-incidents", "-incident-error-crit-ratio=0.01"},
		{"-incidents", "-incident-memory-crit-pct=101"},
		{"-incidents", "-incident-memory-jump-min=12/h"},
		{"-incidents", "-incident-event-min-count=0"},
		{"-incidents", "-incident-logs=s3"},
		{"-incidents", "-incident-logs=cloudwatch"}, // no group, no cluster name
		{"-incidents", "-incident-logs-stream-prefix=fixed"},
		{"-incidents", "-incident-logs-max-lines=0"},
		{"-incidents", "-incident-logs-max-bytes=100"},
		{"-incidents", "-incident-redact-patterns=(unclosed"},
		{"-incidents", "-incident-app-label=not a key"},
		{"-incidents", "-incident-app-labels=app,bad key"},
		{"-incidents", "-incident-namespaces=shop,Bad_NS"},
		{"-incidents", "-cloudtrail=yes"},
		{"-incidents", "-cloudtrail=logs"},
		{"-incidents", "-cloudtrail=lookup", "-cloudtrail-log-group=trail"},
		{"-incidents", "-cloudtrail=lookup", "-cloudtrail-qps=0"},
		{"-incidents", "-cloudtrail=lookup", "-cloudtrail-start=48h"},
	}
	for _, args := range bad {
		if _, err := parseFlags(args, io.Discard); err == nil {
			t.Errorf("%v should be refused", args)
		}
	}
	good := [][]string{
		{"-incidents"},
		{"-incidents", "-incident-logs=cloudwatch", "-cluster-name=prod"},
		{"-incidents", "-incident-logs=off", "-incident-request-sources=", "-incident-event-normal-reasons="},
		{"-incidents", "-cloudtrail=logs", "-cloudtrail-log-group=/aws/cloudtrail/org", "-cloudtrail-region=us-west-2"},
		{"-incidents", "-incident-app-labels=app.kubernetes.io/name,team.example.com/*", "-incident-namespaces=shop,payments"},
	}
	for _, args := range good {
		if _, err := parseFlags(args, io.Discard); err != nil {
			t.Errorf("%v: %v", args, err)
		}
	}

	// Every flag reaches the engine's options.
	c, err = parseFlags([]string{"-incidents", "-cluster-name=prod", "-alerts-default-owner=sre", "-incident-interval=30s", "-incident-max-range=12h",
		"-incident-retention=3d", "-incident-events-retention=24h", "-incident-quiet=10m", "-incident-lookbehind=20m", "-incident-log-lead=2m",
		"-incident-log-lag=15m", "-incident-namespaces=shop", "-incident-include-system", "-incident-app-label=team.example.com/app",
		"-incident-app-labels=app,team.example.com/*", "-incident-request-ratio=3", "-incident-request-crit-ratio=6", "-incident-request-min-rps=2",
		"-incident-error-ratio=0.1", "-incident-error-crit-ratio=0.3", "-incident-memory-limit-pct=80", "-incident-memory-crit-pct=90",
		"-incident-memory-jump-ratio=2", "-incident-memory-jump-min=256MiB", "-incident-spike-recent=10m", "-incident-spike-baseline=2h",
		"-incident-event-min-count=5", "-incident-event-normal-reasons=", "-incident-logs-max-lines=500", "-incident-logs-max-bytes=256KiB",
		"-incident-redact-patterns=acct-[0-9]+", "-incident-redact-patterns=x,y", "-cloudtrail=lookup", "-cloudtrail-start=2h"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	o := c.incidents.options(c)
	th := o.Thresholds
	if o.Interval != 30*time.Second || o.MaxRange != 12*time.Hour || o.Retention != 72*time.Hour || o.EventsRetention != 24*time.Hour ||
		o.Quiet != 10*time.Minute || o.Lookbehind != 20*time.Minute || o.LogLead != 2*time.Minute || o.LogLag != 15*time.Minute ||
		strings.Join(o.Namespaces, ",") != "shop" || !o.IncludeSystem || o.AppLabel != "team.example.com/app" || strings.Join(o.TagKeys, ",") != "app" ||
		o.DefaultOwner != "sre" || o.Cluster != "prod" || o.CloudTrailStart != 2*time.Hour || o.EventNormalReasons == nil || len(o.EventNormalReasons) != 0 ||
		o.LogsMaxLines != 500 || o.LogsMaxBytes != 256<<10 || strings.Join(o.RedactPatterns, "|") != "acct-[0-9]+|x,y" {
		t.Errorf("options = %+v", o)
	}
	if th.RequestRatio != 3 || th.RequestCritRatio != 6 || th.RequestMinRPS != 2 || th.ErrorRatio != 0.1 || th.ErrorCritRatio != 0.3 ||
		th.MemoryPct != 80 || th.MemoryCritPct != 90 || th.MemoryJumpRatio != 2 || th.MemoryJumpMin != 256<<20 || th.SpikeRecent != 10*time.Minute ||
		th.SpikeBaseline != 2*time.Hour || th.EventMinCount != 5 {
		t.Errorf("thresholds = %+v", th)
	}
	if got := strings.Join(c.incidents.appLabelKeys(), ","); got != "team.example.com/app,app,team.example.com/*" {
		t.Errorf("app label keys = %s", got)
	}
	if got := c.incidents.normalReasons(); got == nil || len(got) != 0 {
		t.Errorf("normal reasons = %#v, want empty (Warnings only)", got)
	}
}

func TestFanout(t *testing.T) {
	var f fanout
	a, b := f.subscribe(), f.subscribe()
	f.notify()
	f.notify() // coalesced
	for i, ch := range []<-chan struct{}{a, b} {
		select {
		case <-ch:
		default:
			t.Errorf("subscriber %d missed the build", i)
		}
		select {
		case <-ch:
			t.Errorf("subscriber %d got two signals for one pending build", i)
		default:
		}
	}
}

// memoryProm answers instant queries: a container at 97% of its limit for the
// memory query, nothing for anything else.
func memoryProm(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		q := r.Form.Get("query")
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1/query" && strings.HasPrefix(q, "max by (namespace, pod, container) (container_memory_working_set_bytes"):
			fmt.Fprintf(w, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"namespace":"shop","pod":"api-7d9f-a","container":"api"},"value":[%d,"%d"]}]}}`,
				time.Now().Unix(), 97*(256<<20)/100)
		case r.URL.Path == "/api/v1/query":
			fmt.Fprint(w, `{"status":"success","data":{"resultType":"vector","result":[]}}`)
		case r.URL.Path == "/api/v1/query_range":
			fmt.Fprint(w, `{"status":"success","data":{"resultType":"matrix","result":[]}}`)
		default:
			http.NotFound(w, r)
		}
	}))
}

// The runner wired as run() wires it: a memory spike read from Prometheus
// opens an incident the API lists, and the metrics follow.
func TestIncidentsEndToEnd(t *testing.T) {
	ps := memoryProm(t)
	defer ps.Close()
	cfg, err := parseFlags([]string{"-incidents", "-prometheus-url=" + ps.URL, "-incident-logs=kubernetes", "-cluster-name=prod"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	inv := model.Inventory{
		Namespaces: []model.Namespace{{Name: "shop", Annotations: map[string]string{"kubesentry.io/owner": "team-shop"}}},
		Workloads: []model.Workload{{Kind: "Deployment", Namespace: "shop", Name: "api", UID: "dep", Desired: 1, Ready: 1,
			Selector: &model.LabelSelector{MatchLabels: map[string]string{"app": "api"}}}},
		ReplicaSets: []model.ReplicaSet{{Namespace: "shop", Name: "api-7d9f", UID: "rs",
			Owners: []model.OwnerRef{{Kind: "Deployment", Name: "api", UID: "dep", Controller: true}}}},
		Pods: []model.Pod{{UID: "p1", Namespace: "shop", Name: "api-7d9f-a", Phase: "Running", Labels: map[string]string{"app": "api"},
			Owners: []model.OwnerRef{{Kind: "ReplicaSet", Name: "api-7d9f", UID: "rs", Controller: true}},
			Specs:  []model.ContainerSpec{{Name: "api", MemoryLimitBytes: 256 << 20}}, Containers: []model.ContainerStatus{{Name: "api", State: "running", Ready: true}}}},
	}
	v := snapshot.Build(inv, detectors.DefaultPolicy(), now)
	current := func() *snapshot.View { return v }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &promSource{}
	if err := (promSetup{url: cfg.promURL, scan: prom.LeakScanOptions{Interval: time.Hour, Window: time.Hour},
		pods: func(context.Context) ([]model.Pod, error) { return inv.Pods, nil }}).start(ctx, p); err != nil {
		t.Fatal(err)
	}
	srv := &api.Server{Views: snapshot.Static(v), Metrics: p}
	r, err := incidentsSetup{cfg: cfg, current: current, clients: &kube.Clients{CS: fake.NewSimpleClientset()}, prom: p,
		cw: newCWLogs("", "")}.start(ctx, srv)
	if err != nil {
		t.Fatal(err)
	}
	var list struct {
		Items []incidents.Incident `json:"items"`
	}
	h := srv.Handler()
	deadline := time.Now().Add(10 * time.Second)
	for {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/incidents", nil))
		if rec.Code != 200 {
			t.Fatalf("/incidents = %d %s", rec.Code, rec.Body.String())
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &list)
		if len(list.Items) > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(list.Items) != 1 {
		t.Fatalf("incidents = %+v (sources %v)", list.Items, r.Sources())
	}
	in := list.Items[0]
	if in.Subject != (incidents.Subject{Kind: "Deployment", Namespace: "shop", Name: "api"}) || in.Severity != incidents.Critical ||
		in.Owner != "team-shop" || in.Counts[incidents.TypeMemorySpike] != 1 {
		t.Errorf("incident = %+v", in)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/info", nil))
	for _, want := range []string{`"incidents":{"enabled":true,"leader":true`, `"requests:nginx":`, `"memory":"ok"`, `"logs:kubernetes":"ok"`, `"maxRangeHours":24`} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("/info lacks %s: %s", want, rec.Body.String())
		}
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/incidents/"+in.ID, nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"type":"memory-spike"`) {
		t.Errorf("/incidents/%s = %d %s", in.ID, rec.Code, rec.Body.String())
	}
	if metrics.Incidents.With("critical").Value() != 1 || metrics.IncidentSignals.With(incidents.TypeMemorySpike).Value() < 1 {
		t.Errorf("metrics: incidents %v, memory-spike signals %v", metrics.Incidents.With("critical").Value(),
			metrics.IncidentSignals.With(incidents.TypeMemorySpike).Value())
	}
}
