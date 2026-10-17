package main

import (
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/api"
	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/incidents"
	"github.com/ByronGary/kubesentry/internal/investigate"
	"github.com/ByronGary/kubesentry/internal/metrics"
	"github.com/ByronGary/kubesentry/internal/model"
	"github.com/ByronGary/kubesentry/internal/snapshot"
)

// noAWS leaves the AWS SDK only what a test gives it: no profile, files,
// instance metadata or region from the machine running the tests.
func noAWS(t *testing.T) {
	dir := t.TempDir()
	for k, v := range map[string]string{"AWS_REGION": "", "AWS_DEFAULT_REGION": "", "AWS_PROFILE": "", "AWS_ACCESS_KEY_ID": "",
		"AWS_SECRET_ACCESS_KEY": "", "AWS_SESSION_TOKEN": "", "AWS_CONFIG_FILE": filepath.Join(dir, "c"),
		"AWS_SHARED_CREDENTIALS_FILE": filepath.Join(dir, "k"), "AWS_EC2_METADATA_DISABLED": "true", "AWS_BEARER_TOKEN_BEDROCK": "",
		"ANTHROPIC_API_KEY": "", "AWS_WEB_IDENTITY_TOKEN_FILE": "", "AWS_CONTAINER_CREDENTIALS_FULL_URI": ""} {
		t.Setenv(k, v)
	}
}

func TestInvestigatorFlags(t *testing.T) {
	noAWS(t)
	c, err := parseFlags(nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	ic := c.investigator
	if ic.enabled() || ic.provider != "off" || ic.effort != "high" || ic.bedrockAPI != "mantle" || ic.fallback != "auto" ||
		ic.timeout != 10*time.Minute || ic.maxTurns != 16 || ic.maxToolCalls != 24 || ic.maxTokens != 1_500_000 ||
		ic.maxOutputTokens != 16_000 || ic.digestBytes != 64<<10 || ic.perHour != 10 || ic.perHourTotal != 60 || ic.concurrency != 2 {
		t.Errorf("defaults = %+v", ic)
	}
	if ic.modelID() != "claude-opus-5-5" {
		t.Errorf("default model %q", ic.modelID())
	}
	on := []string{"-incidents", "-investigator=anthropic", "-investigator-egress-ack"}
	bad := [][]string{
		{"-investigator=openai"},
		{"-incidents", "-investigator=anthropic"},               // no egress acknowledgement
		{"-investigator=anthropic", "-investigator-egress-ack"}, // no -incidents
		on, // no ANTHROPIC_API_KEY
		{"-incidents", "-investigator=bedrock", "-investigator-egress-ack"}, // no region
		{"-incidents", "-investigator=bedrock", "-investigator-egress-ack", "-aws-region=us-east-1", "-investigator-bedrock-api=converse"},
	}
	for _, args := range bad {
		if _, err := parseFlags(args, io.Discard); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-test")
	for _, extra := range [][]string{{"-investigator-effort=extreme"}, {"-investigator-timeout=30s"}, {"-investigator-max-turns=0"},
		{"-investigator-max-output-tokens=200000"}, {"-investigator-digest-bytes=100"}, {"-investigator-per-hour=0"},
		{"-investigator-endpoint=ftp://proxy"}, {"-investigator-max-tokens=10"}, {"-investigator-fallback="}} {
		if _, err := parseFlags(append(append([]string{}, on...), extra...), io.Discard); err == nil {
			t.Errorf("%v accepted", extra)
		}
	}
	c, err = parseFlags(append(append([]string{}, on...), "-investigator-effort=max", "-investigator-per-hour=3",
		"-investigator-endpoint=https://llm-proxy.internal", "-investigator-fallback=off"), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if o := c.investigator.options(); o.Effort != "max" || o.Model != "claude-opus-5-5" || c.investigator.perHour != 3 {
		t.Errorf("options %+v", o)
	}

	// Bedrock: the region comes from the flag, -aws-region or AWS_REGION.
	b := []string{"-incidents", "-investigator=bedrock", "-investigator-egress-ack"}
	c, err = parseFlags(append(append([]string{}, b...), "-aws-region=eu-west-1"), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.investigator.modelID() != "anthropic.claude-opus-5-5" || c.investigator.bedrockRegion(c) != "eu-west-1" {
		t.Errorf("bedrock model %q region %q", c.investigator.modelID(), c.investigator.bedrockRegion(c))
	}
	t.Setenv("AWS_REGION", "us-west-2")
	c, err = parseFlags(append(append([]string{}, b...), "-investigator-model=us.anthropic.claude-opus-5-5", "-investigator-bedrock-api=runtime"), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.investigator.modelID() != "us.anthropic.claude-opus-5-5" || c.investigator.bedrockRegion(c) != "us-west-2" {
		t.Errorf("bedrock model %q region %q", c.investigator.modelID(), c.investigator.bedrockRegion(c))
	}
}

// investigatorView has Deployment checkout in shop with two pods on n1 and
// n2, a pod of another workload on n1, and a pod of another namespace.
func investigatorView() *snapshot.View {
	inv := model.Inventory{Unavailable: map[string]string{}}
	inv.Nodes = []model.Node{{Name: "n1", Ready: true}, {Name: "n2", Ready: false}, {Name: "n3", Ready: true}}
	inv.Namespaces = []model.Namespace{{Name: "shop"}, {Name: "other"}}
	dep := model.Workload{Kind: "Deployment", Namespace: "shop", Name: "checkout", UID: "d1", Desired: 2, Ready: 1,
		Selector: &model.LabelSelector{MatchLabels: map[string]string{"app": "checkout"}}}
	inv.Workloads = []model.Workload{dep, {Kind: "Deployment", Namespace: "shop", Name: "cart", UID: "d2",
		Selector: &model.LabelSelector{MatchLabels: map[string]string{"app": "cart"}}}}
	inv.ReplicaSets = []model.ReplicaSet{
		{Namespace: "shop", Name: "checkout-1", UID: "rs1", Owners: []model.OwnerRef{{Kind: "Deployment", Name: "checkout", UID: "d1", Controller: true}}},
		{Namespace: "shop", Name: "cart-1", UID: "rs2", Owners: []model.OwnerRef{{Kind: "Deployment", Name: "cart", UID: "d2", Controller: true}}},
	}
	pod := func(ns, name, rs, app, node string) model.Pod {
		return model.Pod{UID: ns + "/" + name, Namespace: ns, Name: name, NodeName: node, Phase: "Running", Labels: map[string]string{"app": app},
			Owners: []model.OwnerRef{{Kind: "ReplicaSet", Name: rs, UID: map[string]string{"checkout-1": "rs1", "cart-1": "rs2"}[rs], Controller: true}}}
	}
	inv.Pods = []model.Pod{pod("shop", "checkout-b", "checkout-1", "checkout", "n2"), pod("shop", "checkout-a", "checkout-1", "checkout", "n1"),
		pod("shop", "cart-a", "cart-1", "cart", "n1"), pod("other", "checkout-a", "checkout-1", "checkout", "n3")}
	return snapshot.Build(inv, detectors.DefaultPolicy(), time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC))
}

func TestInvestigatorWorkloadState(t *testing.T) {
	v := investigatorView()
	src := investigatorSource{current: func() *snapshot.View { return v }}
	ctx := context.Background()
	st, err := src.WorkloadState(ctx, &incidents.Incident{Subject: incidents.Subject{Kind: "Deployment", Namespace: "shop", Name: "checkout"}})
	if err != nil {
		t.Fatal(err)
	}
	var pods, nodes []string
	for _, p := range st.Pods {
		pods = append(pods, p.Namespace+"/"+p.Name)
	}
	for _, n := range st.Nodes {
		nodes = append(nodes, n.Name)
	}
	if st.Workload == nil || st.Workload.Name != "checkout" || st.Workload.Ready != 1 || !st.At.Equal(v.Built) ||
		strings.Join(pods, ",") != "shop/checkout-a,shop/checkout-b" || strings.Join(nodes, ",") != "n1,n2" {
		t.Errorf("state: workload %+v, pods %v, nodes %v", st.Workload, pods, nodes)
	}
	// A pod the incident names joins; a node incident is the node alone.
	st, _ = src.WorkloadState(ctx, &incidents.Incident{Subject: incidents.Subject{Kind: "Deployment", Namespace: "shop", Name: "checkout"},
		Pods: []string{"cart-a"}})
	if len(st.Pods) != 3 {
		t.Errorf("named pod: %d pods", len(st.Pods))
	}
	st, _ = src.WorkloadState(ctx, &incidents.Incident{Subject: incidents.Subject{Kind: incidents.KindNode, Name: "n1"}})
	if st.Workload != nil || len(st.Pods) != 0 || len(st.Nodes) != 1 || st.Nodes[0].Name != "n1" {
		t.Errorf("node incident: %+v", st)
	}
	src.current = func() *snapshot.View { return nil }
	if _, err := src.WorkloadState(ctx, &incidents.Incident{}); err == nil {
		t.Error("no view: no error")
	}
}

func TestInvestigatorSetup(t *testing.T) {
	noAWS(t)
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-test")
	runner, err := incidents.NewRunner(incidents.Config{Store: incidents.NewMemoryStore(), Events: incidents.NewMemoryEventStore()})
	if err != nil {
		t.Fatal(err)
	}
	v := investigatorView()
	for _, args := range [][]string{
		{"-incidents", "-investigator=anthropic", "-investigator-egress-ack", "-investigator-per-hour=4"},
		{"-incidents", "-investigator=bedrock", "-investigator-egress-ack", "-aws-region=us-east-1", "-investigator-per-hour=4"},
		{"-incidents", "-investigator=bedrock", "-investigator-egress-ack", "-aws-region=us-east-1", "-investigator-per-hour=4",
			"-investigator-bedrock-api=runtime"},
	} {
		t.Run(strings.Join(args[1:], " "), func(t *testing.T) {
			if strings.Contains(args[1], "bedrock") {
				t.Setenv("AWS_ACCESS_KEY_ID", "AKIDTEST")
				t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
			}
			cfg, err := parseFlags(args, io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			srv := &api.Server{}
			svc, err := investigatorSetup{cfg: cfg, runner: runner, current: func() *snapshot.View { return v }}.start(context.Background(), srv)
			if err != nil {
				t.Fatal(err)
			}
			defer svc.Shutdown(context.Background())
			if srv.Investigations == nil || svc.PerHour() != 4 || svc.Options().Model != cfg.investigator.modelID() ||
				svc.Provider() != cfg.investigator.provider {
				t.Errorf("service: provider %q, model %q, per hour %d", svc.Provider(), svc.Options().Model, svc.PerHour())
			}
		})
	}
	// Bedrock without credentials fails at startup, not at the first run.
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	cfg, err := parseFlags([]string{"-incidents", "-investigator=bedrock", "-investigator-egress-ack", "-aws-region=us-east-1",
		"-investigator-bedrock-api=runtime"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (investigatorSetup{cfg: cfg, runner: runner, current: func() *snapshot.View { return v }}).start(context.Background(), &api.Server{}); err == nil {
		t.Error("bedrock without credentials started")
	}
}

func TestInvestigatorHooks(t *testing.T) {
	h := investigatorHooks()
	h.OnResult("anthropic", investigate.ResultCompleted)
	h.OnTokens("anthropic", "claude-opus-5-5", investigate.Usage{Input: 10, Output: 5, CacheRead: 100})
	h.OnToolCall("get_logs", "denied")
	h.OnRunning(2)
	h.OnDuration(90 * time.Second)
	if metrics.Investigations.With("anthropic", "completed").Value() < 1 ||
		metrics.InvestigationTokens.With("anthropic", "claude-opus-5-5", "cache_read").Value() < 100 ||
		metrics.InvestigationToolCalls.With("get_logs", "denied").Value() < 1 || metrics.InvestigationsRunning.Value() != 2 {
		t.Error("hooks do not reach the metrics")
	}
}
