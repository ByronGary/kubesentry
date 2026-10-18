package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/ByronGary/kubesentry/internal/api"
	"github.com/ByronGary/kubesentry/internal/incidents"
	"github.com/ByronGary/kubesentry/internal/investigate"
	"github.com/ByronGary/kubesentry/internal/investigate/viewstate"
	"github.com/ByronGary/kubesentry/internal/llm"
	"github.com/ByronGary/kubesentry/internal/metrics"
	"github.com/ByronGary/kubesentry/internal/pgstore"
	"github.com/ByronGary/kubesentry/internal/settings"
	"github.com/ByronGary/kubesentry/internal/snapshot"
)

// investigatorConfig is the AI investigator's flags (-investigator*;
// docs/contracts.md "AI investigator" and "Settings (M7b)"). They are the
// Helm values the Settings page starts from.
type investigatorConfig struct {
	provider        string // off, anthropic or bedrock
	defaultProvider string // the provider Settings offers while off
	settingsMode    string // ui or locked
	egressAck       bool
	model, effort   string
	region          string
	bedrockAPI      string
	endpoint        string
	fallback        string
	timeout         time.Duration
	maxTurns        int
	maxToolCalls    int
	maxTokens       int64
	maxOutputTokens int
	digestBytes     int
	perHour         int
	perHourTotal    int
	concurrency     int
}

func (c *investigatorConfig) register(fs *flag.FlagSet, dur durFlag) {
	fs.StringVar(&c.provider, "investigator", "off", "AI investigator of incidents: off, anthropic (the Anthropic API; ANTHROPIC_API_KEY from the environment) or bedrock (Amazon Bedrock); needs -incidents and -investigator-egress-ack. With -investigator-settings=ui an admin can turn it on and off on the Settings page")
	fs.StringVar(&c.defaultProvider, "investigator-default-provider", llm.ProviderBedrock, "the provider the Settings page starts from while -investigator=off: bedrock or anthropic")
	fs.StringVar(&c.settingsMode, "investigator-settings", settings.ModeUI, "where the investigator's settings come from: ui (these flags give the initial values; values an admin saves on the Settings page win over them, live on every replica) or locked (these flags only; the page is read-only)")
	fs.BoolVar(&c.egressAck, "investigator-egress-ack", false, "acknowledge that the investigator sends a redacted digest of an incident, and the logs, events, audit and CloudTrail records the starting user may see, to the model provider (with it, turning the investigator on in Settings needs no further acknowledgement)")
	fs.StringVar(&c.model, "investigator-model", "", "model ID (default "+llm.DefaultAnthropicModel+"; with bedrock "+llm.DefaultBedrockModel+", or an inference-profile ID or ARN)")
	fs.StringVar(&c.effort, "investigator-effort", investigate.DefaultEffort, "effort: "+strings.Join(investigate.Efforts, ", "))
	fs.StringVar(&c.region, "investigator-region", "", "Bedrock region (default -aws-region, then AWS_REGION)")
	fs.StringVar(&c.bedrockAPI, "investigator-bedrock-api", llm.BedrockMantle, "Bedrock API: mantle (the Messages API on bedrock-mantle, IAM bedrock-mantle:CreateInference) or runtime (InvokeModel on bedrock-runtime, IAM bedrock:InvokeModelWithResponseStream)")
	fs.StringVar(&c.endpoint, "investigator-endpoint", "", "model API base URL override: a proxy or VPC endpoint (for Bedrock mantle, including /anthropic)")
	fs.StringVar(&c.fallback, "investigator-fallback", llm.FallbackAuto, "retry a turn the model declined on another model: auto (the Anthropic API's server-side default fallback; on Bedrock Claude Opus 5 through the SDK's client-side fallback), off, or a model ID")
	dur(&c.timeout, "investigator-timeout", investigate.DefaultTimeout, "how long one investigation may run")
	fs.IntVar(&c.maxTurns, "investigator-max-turns", investigate.DefaultMaxTurns, "model turns per investigation (then one turn to report, and a final one)")
	fs.IntVar(&c.maxToolCalls, "investigator-max-tool-calls", investigate.DefaultMaxToolCalls, "tool calls per investigation")
	fs.Int64Var(&c.maxTokens, "investigator-max-tokens", investigate.DefaultMaxTokens, "tokens per investigation: input, output, cache reads and cache writes over all turns")
	fs.IntVar(&c.maxOutputTokens, "investigator-max-output-tokens", investigate.DefaultMaxOutputTokens, "output tokens per turn (thinking included)")
	fs.IntVar(&c.digestBytes, "investigator-digest-bytes", investigate.DefaultDigestBytes, "size of the incident digest the investigation starts from (4 KiB to 1 MiB)")
	fs.IntVar(&c.perHour, "investigator-per-hour", investigate.DefaultPerHour, "investigations one user may start per hour (runs answered from the cache are free)")
	fs.IntVar(&c.perHourTotal, "investigator-per-hour-total", investigate.DefaultPerHourTotal, "investigations everyone together may start per hour")
	fs.IntVar(&c.concurrency, "investigator-concurrency", investigate.DefaultConcurrency, "investigations one replica runs at once")
}

func (c *investigatorConfig) enabled() bool { return c.provider != "off" }

// helm is the settings these flags give: the Settings page's Helm values.
func (c *investigatorConfig) helm() settings.Investigator {
	p := c.provider
	if p == "off" {
		p = c.defaultProvider
	}
	return settings.Investigator{Enabled: c.enabled(), Provider: p, Model: c.model, Effort: c.effort, Region: c.region,
		BedrockAPI: c.bedrockAPI, Endpoint: c.endpoint, Fallback: c.fallback,
		Limits: settings.Limits{PerHour: c.perHour, PerHourTotal: c.perHourTotal, Concurrency: c.concurrency, MaxTurns: c.maxTurns,
			MaxToolCalls: c.maxToolCalls, MaxTokens: c.maxTokens, Timeout: settings.Duration(c.timeout)}}
}

// modelID is -investigator-model, or the provider's default.
func (c *investigatorConfig) modelID() string { return c.helm().ModelID() }

// defaultRegion is -aws-region, then the environment's.
func defaultRegion(cfg *config) string {
	for _, r := range []string{cfg.awsRegion, os.Getenv("AWS_REGION"), os.Getenv("AWS_DEFAULT_REGION")} {
		if r = strings.TrimSpace(r); r != "" {
			return r
		}
	}
	return ""
}

// bedrockRegion is -investigator-region, -aws-region or the environment's.
func (c *investigatorConfig) bedrockRegion(cfg *config) string {
	return c.helm().RegionOr(defaultRegion(cfg))
}

// optionsFor are the run options of settings v (the per-turn output cap and
// the digest size stay flags).
func (c *investigatorConfig) optionsFor(v settings.Investigator) investigate.Options {
	return investigate.Options{Model: v.ModelID(), Effort: v.Effort, MaxTurns: v.Limits.MaxTurns, MaxToolCalls: v.Limits.MaxToolCalls,
		MaxTokens: v.Limits.MaxTokens, MaxOutputTokens: c.maxOutputTokens, Timeout: time.Duration(v.Limits.Timeout), DigestBytes: c.digestBytes}
}

func (c *investigatorConfig) options() investigate.Options { return c.optionsFor(c.helm()) }

// settingsEnv is the environment settings validation needs.
func settingsEnv(cfg *config) settings.Env {
	return settings.Env{Incidents: cfg.incidents.enabled, AnthropicKey: strings.TrimSpace(os.Getenv("ANTHROPIC_API_KEY")) != "",
		DefaultRegion: defaultRegion(cfg)}
}

// fieldFlags names the flag of each settings field.
var fieldFlags = map[string]string{
	"enabled": "-investigator", "provider": "-investigator", "model": "-investigator-model", "effort": "-investigator-effort",
	"region": "-investigator-region", "bedrockAPI": "-investigator-bedrock-api", "endpoint": "-investigator-endpoint",
	"fallback": "-investigator-fallback", "limits.perHour": "-investigator-per-hour", "limits.perHourTotal": "-investigator-per-hour-total",
	"limits.concurrency": "-investigator-concurrency", "limits.maxTurns": "-investigator-max-turns",
	"limits.maxToolCalls": "-investigator-max-tool-calls", "limits.maxTokens": "-investigator-max-tokens", "limits.timeout": "-investigator-timeout",
}

func (c *investigatorConfig) validate(cfg *config) error {
	switch c.provider {
	case "off", llm.ProviderAnthropic, llm.ProviderBedrock:
	default:
		return fmt.Errorf("-investigator %q: use off, anthropic or bedrock", c.provider)
	}
	switch c.defaultProvider {
	case llm.ProviderAnthropic, llm.ProviderBedrock:
	default:
		return fmt.Errorf("-investigator-default-provider %q: use bedrock or anthropic", c.defaultProvider)
	}
	switch c.settingsMode {
	case settings.ModeUI, settings.ModeLocked:
	default:
		return fmt.Errorf("-investigator-settings %q: use ui or locked", c.settingsMode)
	}
	if c.enabled() && !c.egressAck {
		return errors.New("-investigator sends a redacted digest of each investigated incident, and the logs, events, audit and " +
			"CloudTrail records the starting user may see, to " + c.provider + ": set -investigator-egress-ack=true to accept that")
	}
	// The values themselves, and with the investigator on what it needs:
	// the same rules the Settings page applies.
	if err := c.helm().Validate(settingsEnv(cfg)); err != nil {
		var ve *settings.ValidationError
		if errors.As(err, &ve) {
			f := ve.Fields[0]
			msg := f.Message
			switch {
			case f.Field == "enabled" && strings.Contains(msg, "incidents"):
				return errors.New("-investigator investigates incidents: it needs -incidents")
			case f.Field == "enabled" && strings.Contains(msg, "ANTHROPIC_API_KEY"):
				return errors.New("-investigator=anthropic needs the ANTHROPIC_API_KEY environment variable (the chart sets it from incidents.investigator.existingSecret)")
			case f.Field == "region" && c.enabled():
				return errors.New("-investigator=bedrock needs a region: -investigator-region, -aws-region or AWS_REGION")
			}
			return fmt.Errorf("%s %s", fieldFlags[f.Field], msg)
		}
		return err
	}
	return c.options().Validate()
}

// investigatorSetup is what the investigator is built from.
type investigatorSetup struct {
	cfg     *config
	runner  *incidents.Runner // nil when -incidents is off
	current func() *snapshot.View
	pg      *pgstore.Store // nil: the memory store, this replica alone
	// inCluster is false in remote mode.
	inCluster bool
}

// start builds the investigator's service (off until its settings turn it
// on), the settings manager that applies its settings live, and serves the
// investigator's and the Settings page's routes; the caller shuts the
// service down before the listeners stop. Settings that come from the flags
// alone and cannot be built (Bedrock credentials that do not resolve) stop
// the server, as before; settings saved in the UI that cannot be built are
// logged and leave the investigator off on this replica.
func (s investigatorSetup) start(ctx context.Context, srv *api.Server) (*investigate.Service, error) {
	var svc *investigate.Service
	if s.runner != nil {
		eg, err := investigate.NewEgress(s.runner.Redactor(), nil)
		if err != nil {
			return nil, err
		}
		var store investigate.Store
		if s.pg != nil {
			store = s.pg.Investigations()
		} else {
			store = investigate.NewMemoryStore(0)
		}
		svc, err = investigate.NewService(investigate.Config{Disabled: true,
			Source: investigatorSource{Runner: s.runner, current: s.current}, Store: store, Egress: eg,
			Options: s.cfg.investigator.options(), PerHour: s.cfg.investigator.perHour, PerHourTotal: s.cfg.investigator.perHourTotal,
			Concurrency: s.cfg.investigator.concurrency, Cluster: s.cfg.clusterName, Hooks: investigatorHooks(), Logger: slog.Default()})
		if err != nil {
			return nil, err
		}
	}
	var st settings.Store = settings.NewMemoryStore()
	if s.pg != nil {
		st = s.pg.Settings()
	}
	m, err := settings.NewManager(settings.ManagerConfig{Store: st, Helm: s.cfg.investigator.helm(), Mode: s.cfg.investigator.settingsMode,
		Env: func() settings.Env { return settingsEnv(s.cfg) }, PlatformAck: s.cfg.investigator.egressAck, Apply: s.applier(svc),
		Logger: slog.Default()})
	if err != nil {
		return nil, err
	}
	if err := m.Load(ctx); err != nil {
		var ae *settings.ApplyError
		if !errors.As(err, &ae) || !m.Overridden() {
			if svc != nil {
				_ = svc.Shutdown(context.Background())
			}
			return nil, err
		}
		slog.Error("the investigator settings saved in the UI could not be applied; the investigator stays off on this replica until they can be", "err", err)
	}
	go m.Run(ctx)
	if svc != nil {
		srv.Investigations = svc
	}
	srv.Settings = &settingsService{m: m, setup: s}
	return svc, nil
}

// applier builds the model client and the runtime of settings v, and swaps
// them into svc on commit (running runs finish on what they had).
func (s investigatorSetup) applier(svc *investigate.Service) settings.Applier {
	return func(ctx context.Context, v settings.Investigator) (settings.Commit, error) {
		if !v.Enabled {
			return func() {
				if svc != nil && svc.Enabled() {
					_ = svc.Reconfigure(nil)
					slog.Info("AI investigator off")
				}
			}, nil
		}
		if svc == nil {
			return nil, errors.New("the investigator investigates incidents: it needs -incidents")
		}
		model, lc, err := s.client(ctx, v)
		if err != nil {
			return nil, err
		}
		rt := &investigate.Runtime{LLM: model, Options: s.cfg.investigator.optionsFor(v), PerHour: v.Limits.PerHour,
			PerHourTotal: v.Limits.PerHourTotal, Concurrency: v.Limits.Concurrency}
		if err := rt.Options.Validate(); err != nil {
			return nil, err
		}
		return func() {
			if err := svc.Reconfigure(rt); err != nil {
				slog.Error("AI investigator not reconfigured", "err", err)
				return
			}
			attrs := []any{"provider", v.Provider, "model", v.ModelID(), "effort", v.Effort, "fallback", model.Fallback(),
				"perHour", v.Limits.PerHour, "concurrency", v.Limits.Concurrency}
			if v.Provider == llm.ProviderBedrock {
				attrs = append(attrs, "region", lc.Region, "bedrockAPI", lc.BedrockAPI)
			}
			if v.Endpoint != "" {
				attrs = append(attrs, "endpoint", v.Endpoint)
			}
			slog.Warn("AI investigator on: investigations send redacted incident data to the model provider", attrs...)
		}, nil
	}
}

// llmConfig is the model client's config for settings v.
func (s investigatorSetup) llmConfig(v settings.Investigator) llm.Config {
	lc := llm.Config{Endpoint: v.Endpoint, Model: v.ModelID(), Fallback: v.Fallback, Timeout: time.Duration(v.Limits.Timeout)}
	switch v.Provider {
	case llm.ProviderAnthropic:
		lc.APIKey = os.Getenv("ANTHROPIC_API_KEY")
		// Tool inputs stream as they are generated on the Anthropic API
		// itself; a proxy in front of it may reject the field.
		lc.EagerInputStreaming = v.Endpoint == ""
	case llm.ProviderBedrock:
		lc.Region, lc.BedrockAPI = v.RegionOr(defaultRegion(s.cfg)), v.BedrockAPIOrDefault()
	}
	return lc
}

// client builds the model client of settings v.
func (s investigatorSetup) client(ctx context.Context, v settings.Investigator) (*llm.Client, llm.Config, error) {
	lc := s.llmConfig(v)
	var model *llm.Client
	var err error
	switch v.Provider {
	case llm.ProviderAnthropic:
		model, err = llm.NewAnthropic(lc)
	case llm.ProviderBedrock:
		model, err = llm.NewBedrock(ctx, lc)
	default:
		err = fmt.Errorf("provider %q: use anthropic or bedrock", v.Provider)
	}
	return model, lc, err
}

// investigatorHooks feed the investigator's metrics.
func investigatorHooks() investigate.Hooks {
	return investigate.Hooks{
		OnResult:   func(provider, result string) { metrics.Investigations.With(provider, result).Inc() },
		OnDuration: func(d time.Duration) { metrics.InvestigationDuration.Observe(d.Seconds()) },
		OnRunning:  func(n int) { metrics.InvestigationsRunning.Set(float64(n)) },
		OnTokens: func(provider, model string, u investigate.Usage) {
			for kind, n := range map[string]int64{"input": u.Input, "output": u.Output, "cache_read": u.CacheRead, "cache_write": u.CacheWrite} {
				if n > 0 {
					metrics.InvestigationTokens.With(provider, model, kind).Add(float64(n))
				}
			}
		},
		OnToolCall: func(tool, result string) { metrics.InvestigationToolCalls.With(tool, result).Inc() },
	}
}

// investigatorSource is what the investigator reads: the incident from the
// incidents runner, and the current state of its subject from the latest
// view.
type investigatorSource struct {
	*incidents.Runner
	current func() *snapshot.View
}

var _ investigate.Source = investigatorSource{}

// WorkloadState returns the subject's workload, its pods (and the pods the
// incident names) and the nodes they run on; for a node incident, the node
// alone (viewstate.Of).
func (s investigatorSource) WorkloadState(_ context.Context, in *incidents.Incident) (*investigate.WorkloadState, error) {
	return viewstate.Of(s.current(), in)
}
