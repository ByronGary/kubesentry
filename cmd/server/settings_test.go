package main

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/ByronGary/kubesentry/internal/api"
	"github.com/ByronGary/kubesentry/internal/incidents"
	"github.com/ByronGary/kubesentry/internal/llm"
	"github.com/ByronGary/kubesentry/internal/model"
	"github.com/ByronGary/kubesentry/internal/settings"
	"github.com/ByronGary/kubesentry/internal/snapshot"
)

// The settings package names providers, APIs and fallbacks as internal/llm
// does.
func TestSettingsConstantsMatchLLM(t *testing.T) {
	for a, b := range map[string]string{settings.ProviderAnthropic: llm.ProviderAnthropic, settings.ProviderBedrock: llm.ProviderBedrock,
		settings.BedrockMantle: llm.BedrockMantle, settings.BedrockRuntime: llm.BedrockRuntime, settings.FallbackAuto: llm.FallbackAuto,
		settings.FallbackOff: llm.FallbackOff, settings.DefaultAnthropicModel: llm.DefaultAnthropicModel, settings.DefaultBedrockModel: llm.DefaultBedrockModel} {
		if a != b {
			t.Errorf("settings %q, llm %q", a, b)
		}
	}
}

func TestInvestigatorSettingsFlags(t *testing.T) {
	noAWS(t)
	c, err := parseFlags(nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	h := c.investigator.helm()
	if h.Enabled || h.Provider != "bedrock" || c.investigator.settingsMode != "ui" || h.Limits.PerHour != 10 || h.Limits.Timeout.String() != "10m" {
		t.Errorf("helm values %+v, mode %q", h, c.investigator.settingsMode)
	}
	c, err = parseFlags([]string{"-investigator-default-provider=anthropic", "-investigator-settings=locked", "-investigator-model=x.y"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if h := c.investigator.helm(); h.Provider != "anthropic" || h.Model != "x.y" || c.investigator.settingsMode != "locked" {
		t.Errorf("helm values %+v", h)
	}
	for _, args := range [][]string{{"-investigator-settings=open"}, {"-investigator-default-provider=openai"}, {"-investigator-model=a b"},
		{"-investigator-region=Mars"}} {
		if _, err := parseFlags(args, io.Discard); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
}

func settingsSetup(t *testing.T, args ...string) (investigatorSetup, *api.Server) {
	t.Helper()
	cfg, err := parseFlags(args, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	v := investigatorView()
	s := investigatorSetup{cfg: cfg, current: func() *snapshot.View { return v }, inCluster: true}
	if cfg.incidents.enabled {
		runner, err := incidents.NewRunner(incidents.Config{Store: incidents.NewMemoryStore(), Events: incidents.NewMemoryEventStore()})
		if err != nil {
			t.Fatal(err)
		}
		s.runner = runner
	}
	return s, &api.Server{}
}

// Off by the flags, on from Settings, off again: live, without a restart.
func TestInvestigatorLiveToggle(t *testing.T) {
	noAWS(t)
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-test")
	ctx := context.Background()
	s, srv := settingsSetup(t, "-incidents", "-investigator-default-provider=anthropic")
	svc, err := s.start(ctx, srv)
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Shutdown(ctx)
	if svc.Enabled() || srv.Investigations == nil || srv.Settings == nil {
		t.Fatalf("enabled %v", svc.Enabled())
	}
	st, err := srv.Settings.State(ctx)
	if err != nil {
		t.Fatal(err)
	}
	on := st.Values
	on.Enabled, on.Effort, on.Limits.PerHour = true, "max", 3
	if _, err := srv.Settings.Save(ctx, settings.SaveRequest{Actor: "alice", Values: on}); !errors.Is(err, settings.ErrEgressAck) {
		t.Errorf("no acknowledgement: %v", err)
	}
	if _, err := srv.Settings.Save(ctx, settings.SaveRequest{Actor: "alice", Values: on, EgressAcknowledged: true}); err != nil {
		t.Fatal(err)
	}
	if !svc.Enabled() || svc.Provider() != "anthropic" || svc.Options().Effort != "max" || svc.PerHour() != 3 {
		t.Errorf("after enabling: %v %s %+v %d", svc.Enabled(), svc.Provider(), svc.Options(), svc.PerHour())
	}
	off := on
	off.Enabled = false
	if _, err := srv.Settings.Save(ctx, settings.SaveRequest{Actor: "bob", Version: 1, Values: off}); err != nil {
		t.Fatal(err)
	}
	if svc.Enabled() {
		t.Error("still on")
	}
	// Bedrock without credentials cannot be built: refused, nothing stored.
	bed := on
	bed.Provider, bed.Region = "bedrock", "us-east-1"
	bed.BedrockAPI = "runtime"
	var ae *settings.ApplyError
	if _, err := srv.Settings.Save(ctx, settings.SaveRequest{Actor: "bob", Version: 2, Values: bed, EgressAcknowledged: true}); !errors.As(err, &ae) {
		t.Errorf("bedrock without credentials: %v", err)
	}
	if svc.Enabled() {
		t.Error("on after a refused save")
	}
}

func TestInvestigatorSettingsLockedAndWithoutIncidents(t *testing.T) {
	noAWS(t)
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-test")
	ctx := context.Background()
	s, srv := settingsSetup(t, "-incidents", "-investigator=anthropic", "-investigator-egress-ack", "-investigator-settings=locked")
	svc, err := s.start(ctx, srv)
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Shutdown(ctx)
	st, _ := srv.Settings.State(ctx)
	if !svc.Enabled() || !st.Locked || srv.Settings.Mode() != "locked" {
		t.Errorf("locked: %v %+v", svc.Enabled(), st)
	}
	if _, err := srv.Settings.Save(ctx, settings.SaveRequest{Actor: "a", Values: st.Values}); !errors.Is(err, settings.ErrLocked) {
		t.Errorf("save while locked: %v", err)
	}
	// Without incidents there is no investigator, but the page says why.
	s, srv = settingsSetup(t)
	svc, err = s.start(ctx, srv)
	if err != nil || svc != nil || srv.Investigations != nil || srv.Settings == nil {
		t.Fatalf("without incidents: %v %v", svc, err)
	}
	st, _ = srv.Settings.State(ctx)
	on := st.Values
	on.Enabled = true
	var ve *settings.ValidationError
	if _, err := srv.Settings.Save(ctx, settings.SaveRequest{Actor: "a", Values: on, EgressAcknowledged: true}); !errors.As(err, &ve) || st.Incidents {
		t.Errorf("enabling without incidents: %v", err)
	}
}

func TestSettingsEnvironmentAndTest(t *testing.T) {
	noAWS(t)
	s, _ := settingsSetup(t, "-cluster-name=prod-eks", "-aws-region=us-east-1")
	env := map[string]string{"AWS_ROLE_ARN": "arn:aws:iam::111122223333:role/kubesentry", "AWS_WEB_IDENTITY_TOKEN_FILE": "/var/run/token",
		"POD_NAMESPACE": "kubesentry", "KUBESENTRY_SERVICE_ACCOUNT": "kubesentry", "AWS_SECRET_ACCESS_KEY": "must-not-leak"}
	var probed llm.ProbeConfig
	ss := &settingsService{setup: s, getenv: func(k string) string { return env[k] }, probe: func(_ context.Context, pc llm.ProbeConfig) llm.ProbeResult {
		probed = pc
		return llm.ProbeResult{Provider: pc.Provider, Region: pc.Region, Model: pc.Model, Endpoint: "https://bedrock-mantle.us-east-1.api.aws/anthropic",
			Error: &llm.ProbeError{Kind: llm.ProbeAccessDenied, Message: "denied", Action: "bedrock-mantle:CreateInference", Status: 403}}
	}}
	// The view knows nothing of EKS: in-cluster elsewhere.
	e, creds := ss.Context(context.Background())
	if e.Kind != settings.EnvKubernetes || e.Cluster != "prod-eks" || e.Namespace != "kubesentry" || creds.Kind != settings.CredIRSA ||
		creds.AccountID != "111122223333" {
		t.Errorf("environment %+v, credentials %+v", e, creds)
	}
	v := investigatorView()
	v.Inv.Cluster = model.ClusterInfo{Platform: "eks", Provider: "aws", Region: "us-east-1"}
	ss.setup.current = func() *snapshot.View { return v }
	if e, _ := ss.Context(context.Background()); e.Kind != settings.EnvEKS || e.Label == "" {
		t.Errorf("EKS: %+v", e)
	}
	ss.setup.inCluster = false
	if e, _ := ss.Context(context.Background()); e.Kind != settings.EnvRemote {
		t.Errorf("remote: %+v", e)
	}
	h := s.cfg.investigator.helm()
	res := ss.Test(context.Background(), h)
	if probed.Provider != "bedrock" || probed.Region != "us-east-1" || probed.Model != llm.DefaultBedrockModel || probed.BedrockAPI != "mantle" {
		t.Errorf("probed %+v", probed)
	}
	if res.OK || res.Error == nil || res.Error.Action != "bedrock-mantle:CreateInference" || res.CredentialSource != settings.CredIRSA || res.At.IsZero() {
		t.Errorf("result %+v", res)
	}
}
