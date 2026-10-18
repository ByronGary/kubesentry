package main

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/ByronGary/kubesentry/internal/api"
	"github.com/ByronGary/kubesentry/internal/llm"
	"github.com/ByronGary/kubesentry/internal/settings"
)

// settingsService serves the Settings page: the manager's state and saves,
// the detected environment and credentials, and the connection test.
type settingsService struct {
	m     *settings.Manager
	setup investigatorSetup
	// probe tests a connection (llm.Probe; tests replace it).
	probe func(ctx context.Context, pc llm.ProbeConfig) llm.ProbeResult
	// getenv reads the environment (os.Getenv; tests replace it).
	getenv func(string) string
}

var _ api.SettingsService = (*settingsService)(nil)

func (s *settingsService) State(ctx context.Context) (*settings.State, error) { return s.m.State(ctx) }
func (s *settingsService) Mode() string                                       { return s.m.Mode() }
func (s *settingsService) Save(ctx context.Context, req settings.SaveRequest) (*settings.State, error) {
	return s.m.Save(ctx, req)
}

func (s *settingsService) env(k string) string {
	if s.getenv != nil {
		return s.getenv(k)
	}
	return os.Getenv(k)
}

// Context detects where kubesentry runs and where its AWS credentials come
// from. It reads only the environment and the AWS config file's profile
// names, never secret values.
func (s *settingsService) Context(context.Context) (settings.Environment, settings.Credentials) {
	home, _ := os.UserHomeDir()
	creds := settings.DetectCredentials(settings.CredentialEnv{Getenv: s.env, ReadFile: os.ReadFile, Home: home,
		Exists: func(p string) bool { _, err := os.Stat(p); return err == nil }})
	return s.environment(), creds
}

// environment is in-cluster on EKS (the view knows the platform), in-cluster
// elsewhere, or remote mode.
func (s *settingsService) environment() settings.Environment {
	cfg := s.setup.cfg
	e := settings.Environment{Cluster: cfg.clusterName, Region: defaultRegion(cfg), KubeContext: cfg.remote.kubeContext,
		Namespace: s.env("POD_NAMESPACE"), ServiceAccount: s.env("KUBESENTRY_SERVICE_ACCOUNT"), OIDCIssuer: s.env("KUBESENTRY_OIDC_ISSUER")}
	var platform, provider string
	if s.setup.current != nil {
		if v := s.setup.current(); v != nil {
			ci := v.Inv.Cluster
			platform, provider = ci.Platform, ci.Provider
			if e.Region == "" {
				e.Region = ci.Region
			}
			if e.Cluster == "" {
				e.Cluster = ci.Name
			}
		}
	}
	e.Platform = platform
	switch {
	case !s.setup.inCluster:
		e.Kind = settings.EnvRemote
	case platform == "eks" || provider == "aws":
		e.Kind = settings.EnvEKS
	default:
		e.Kind = settings.EnvKubernetes
	}
	e.Label = settings.EnvironmentLabel(e.Kind)
	return e
}

// Test tests the connection with v: STS GetCallerIdentity for Bedrock, then
// a one-token request to the model.
func (s *settingsService) Test(ctx context.Context, v settings.Investigator) settings.TestResult {
	_, creds := s.Context(ctx)
	lc := s.setup.llmConfig(v)
	probe := s.probe
	if probe == nil {
		probe = llm.Probe
	}
	r := probe(ctx, llm.ProbeConfig{Provider: v.Provider, Config: lc})
	out := settings.TestResult{OK: r.OK, Provider: r.Provider, Region: r.Region, Endpoint: r.Endpoint, Model: r.Model,
		IdentityARN: r.IdentityARN, Account: r.Account, LatencyMs: r.LatencyMs, At: time.Now().UTC()}
	if v.Provider == llm.ProviderBedrock {
		out.CredentialSource = creds.Kind
	} else if strings.TrimSpace(s.env("ANTHROPIC_API_KEY")) != "" {
		out.CredentialSource = "anthropic-api-key"
	}
	if r.Error != nil {
		out.Error = &settings.TestError{Kind: r.Error.Kind, Message: r.Error.Message, Hint: r.Error.Hint, Action: r.Error.Action, Status: r.Error.Status}
	}
	return out
}
