package demo

import (
	"context"
	"time"

	"github.com/ByronGary/kubesentry/internal/api"
	"github.com/ByronGary/kubesentry/internal/investigate"
	"github.com/ByronGary/kubesentry/internal/settings"
)

// The demo's AWS identity, as if kubesentry ran in EKS with IRSA.
const (
	demoAccount = "111122223333"
	demoRoleARN = "arn:aws:iam::" + demoAccount + ":role/kubesentry-investigator"
	demoRegion  = "us-east-1"
)

// demoSettings is the Settings page of the demo: the real settings manager
// over a memory store, applying to the demo's investigator (always the
// scripted model: nothing is sent anywhere), an environment that looks like
// EKS with IRSA, and a canned connection test.
type demoSettings struct {
	m *settings.Manager
	// testDelay is how long the canned test takes.
	testDelay time.Duration
}

var _ api.SettingsService = (*demoSettings)(nil)

// demoHelm is what the demo's "Helm values" are: Bedrock through the
// mantle API in us-east-1, on.
func demoHelm() settings.Investigator {
	return settings.Investigator{Enabled: true, Provider: settings.ProviderBedrock, Effort: investigate.DefaultEffort, Region: demoRegion,
		BedrockAPI: settings.BedrockMantle, Fallback: settings.FallbackAuto,
		Limits: settings.Limits{PerHour: investigate.DefaultPerHour, PerHourTotal: investigate.DefaultPerHourTotal,
			Concurrency: investigate.DefaultConcurrency, MaxTurns: investigate.DefaultMaxTurns, MaxToolCalls: investigate.DefaultMaxToolCalls,
			MaxTokens: investigate.DefaultMaxTokens, Timeout: settings.Duration(investigate.DefaultTimeout)}}
}

// NewSettings returns the demo's Settings page over its investigator, each
// scripted turn taking delay; mode is ui or locked.
func NewSettings(ctx context.Context, svc *investigate.Service, delay time.Duration, mode string) (api.SettingsService, error) {
	m, err := settings.NewManager(settings.ManagerConfig{Store: settings.NewMemoryStore(), Helm: demoHelm(), Mode: mode,
		Env: func() settings.Env { return settings.Env{Incidents: true, DefaultRegion: demoRegion} },
		Apply: func(_ context.Context, v settings.Investigator) (settings.Commit, error) {
			if !v.Enabled {
				return func() { _ = svc.Reconfigure(nil) }, nil
			}
			rt := &investigate.Runtime{LLM: scriptedModel{delay: delay}, PerHour: v.Limits.PerHour, PerHourTotal: v.Limits.PerHourTotal,
				Concurrency: v.Limits.Concurrency, Options: investigate.Options{Model: DemoModel, Effort: v.Effort, MaxTurns: v.Limits.MaxTurns,
					MaxToolCalls: v.Limits.MaxToolCalls, MaxTokens: v.Limits.MaxTokens, Timeout: time.Duration(v.Limits.Timeout)}}
			if err := rt.Options.Validate(); err != nil {
				return nil, err
			}
			return func() { _ = svc.Reconfigure(rt) }, nil
		}})
	if err != nil {
		return nil, err
	}
	if err := m.Load(ctx); err != nil {
		return nil, err
	}
	return &demoSettings{m: m, testDelay: 400 * time.Millisecond}, nil
}

func (d *demoSettings) State(ctx context.Context) (*settings.State, error) { return d.m.State(ctx) }
func (d *demoSettings) Mode() string                                      { return d.m.Mode() }
func (d *demoSettings) Save(ctx context.Context, r settings.SaveRequest) (*settings.State, error) {
	return d.m.Save(ctx, r)
}

// Context is EKS with IRSA: cluster demo-eks in us-east-1.
func (d *demoSettings) Context(context.Context) (settings.Environment, settings.Credentials) {
	return settings.Environment{Kind: settings.EnvEKS, Label: settings.EnvironmentLabel(settings.EnvEKS), Cluster: demoClusterName,
			Region: demoRegion, Platform: "eks", Namespace: "kubesentry", ServiceAccount: "kubesentry"},
		settings.Credentials{Kind: settings.CredIRSA, Label: "IRSA (IAM role for the service account)", RoleARN: demoRoleARN, AccountID: demoAccount}
}

// Test is canned: Bedrock in us-east-1 passes; another region answers as
// an account without model access there would, and the Anthropic API as a
// server without ANTHROPIC_API_KEY. Nothing leaves the process.
func (d *demoSettings) Test(ctx context.Context, v settings.Investigator) settings.TestResult {
	start := time.Now()
	select {
	case <-ctx.Done():
	case <-time.After(d.testDelay):
	}
	region := v.RegionOr(demoRegion)
	r := settings.TestResult{Provider: v.Provider, Model: v.ModelID(), At: time.Now().UTC()}
	switch {
	case v.Provider == settings.ProviderAnthropic:
		r.Endpoint = "https://api.anthropic.com"
		r.Error = &settings.TestError{Kind: "auth", Message: "no Anthropic API key: ANTHROPIC_API_KEY is not set",
			Hint: "Create a Secret with the key and set incidents.investigator.existingSecret, then restart kubesentry."}
	default:
		r.Region, r.CredentialSource = region, settings.CredIRSA
		r.IdentityARN, r.Account = "arn:aws:sts::"+demoAccount+":assumed-role/kubesentry-investigator/kubesentry-demo", demoAccount
		r.Endpoint = "https://bedrock-mantle." + region + ".api.aws/anthropic"
		if v.BedrockAPIOrDefault() == settings.BedrockRuntime {
			r.Endpoint = "https://bedrock-runtime." + region + ".amazonaws.com"
		}
		if v.Endpoint != "" {
			r.Endpoint = v.Endpoint
		}
		if region != demoRegion {
			r.Error = &settings.TestError{Kind: "model_access", Status: 403,
				Message: "HTTP 403 AccessDeniedException: You don't have access to the model with the specified model ID.",
				Hint:    "Enable the model in the Bedrock console's Model access page for " + region + " (and its fallback)."}
		} else {
			r.OK = true
		}
	}
	r.LatencyMs = time.Since(start).Milliseconds()
	return r
}
