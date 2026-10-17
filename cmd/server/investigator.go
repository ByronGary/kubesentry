package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/ByronGary/kubesentry/internal/api"
	"github.com/ByronGary/kubesentry/internal/incidents"
	"github.com/ByronGary/kubesentry/internal/investigate"
	"github.com/ByronGary/kubesentry/internal/llm"
	"github.com/ByronGary/kubesentry/internal/metrics"
	"github.com/ByronGary/kubesentry/internal/pgstore"
	"github.com/ByronGary/kubesentry/internal/snapshot"
)

// investigatorConfig is the AI investigator's flags (-investigator*;
// docs/contracts.md "AI investigator").
type investigatorConfig struct {
	provider        string // off, anthropic or bedrock
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
	fs.StringVar(&c.provider, "investigator", "off", "AI investigator of incidents: off, anthropic (the Anthropic API; ANTHROPIC_API_KEY from the environment) or bedrock (Amazon Bedrock); needs -incidents and -investigator-egress-ack")
	fs.BoolVar(&c.egressAck, "investigator-egress-ack", false, "acknowledge that the investigator sends a redacted digest of an incident, and the logs, events, audit and CloudTrail records the starting user may see, to the model provider")
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

// modelID is -investigator-model, or the provider's default.
func (c *investigatorConfig) modelID() string {
	switch {
	case c.model != "":
		return c.model
	case c.provider == llm.ProviderBedrock:
		return llm.DefaultBedrockModel
	}
	return llm.DefaultAnthropicModel
}

// bedrockRegion is -investigator-region, -aws-region or the environment's.
func (c *investigatorConfig) bedrockRegion(cfg *config) string {
	for _, r := range []string{c.region, cfg.awsRegion, os.Getenv("AWS_REGION"), os.Getenv("AWS_DEFAULT_REGION")} {
		if r = strings.TrimSpace(r); r != "" {
			return r
		}
	}
	return ""
}

func (c *investigatorConfig) options() investigate.Options {
	return investigate.Options{Model: c.modelID(), Effort: c.effort, MaxTurns: c.maxTurns, MaxToolCalls: c.maxToolCalls,
		MaxTokens: c.maxTokens, MaxOutputTokens: c.maxOutputTokens, Timeout: c.timeout, DigestBytes: c.digestBytes}
}

func (c *investigatorConfig) validate(cfg *config) error {
	switch c.provider {
	case "off":
		return nil
	case llm.ProviderAnthropic, llm.ProviderBedrock:
	default:
		return fmt.Errorf("-investigator %q: use off, anthropic or bedrock", c.provider)
	}
	switch {
	case !c.egressAck:
		return errors.New("-investigator sends a redacted digest of each investigated incident, and the logs, events, audit and " +
			"CloudTrail records the starting user may see, to " + c.provider + ": set -investigator-egress-ack=true to accept that")
	case !cfg.incidents.enabled:
		return errors.New("-investigator investigates incidents: it needs -incidents")
	case c.provider == llm.ProviderAnthropic && strings.TrimSpace(os.Getenv("ANTHROPIC_API_KEY")) == "":
		return errors.New("-investigator=anthropic needs the ANTHROPIC_API_KEY environment variable (the chart sets it from incidents.investigator.existingSecret)")
	case c.provider == llm.ProviderBedrock && c.bedrockRegion(cfg) == "":
		return errors.New("-investigator=bedrock needs a region: -investigator-region, -aws-region or AWS_REGION")
	case c.provider == llm.ProviderBedrock && c.bedrockAPI != llm.BedrockMantle && c.bedrockAPI != llm.BedrockRuntime:
		return fmt.Errorf("-investigator-bedrock-api %q: use mantle or runtime", c.bedrockAPI)
	case c.timeout < time.Minute || c.timeout > time.Hour:
		return errors.New("-investigator-timeout must be between 1m and 1h")
	case c.maxTurns < 1 || c.maxTurns > 100:
		return errors.New("-investigator-max-turns must be between 1 and 100")
	case c.maxToolCalls < 1 || c.maxToolCalls > 200:
		return errors.New("-investigator-max-tool-calls must be between 1 and 200")
	case c.maxTokens < 10_000:
		return errors.New("-investigator-max-tokens must be at least 10000")
	case c.maxOutputTokens < 1024:
		return errors.New("-investigator-max-output-tokens must be at least 1024")
	case c.perHour < 1 || c.perHourTotal < 1 || c.concurrency < 1:
		return errors.New("-investigator-per-hour, -investigator-per-hour-total and -investigator-concurrency must be at least 1")
	case strings.TrimSpace(c.fallback) == "":
		return errors.New("-investigator-fallback: use auto, off or a model ID")
	}
	if c.endpoint != "" {
		if u, err := url.Parse(c.endpoint); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return fmt.Errorf("-investigator-endpoint %q: want an http(s) URL", c.endpoint)
		}
	}
	return c.options().Validate()
}

// investigatorSetup is what the investigator is built from.
type investigatorSetup struct {
	cfg     *config
	runner  *incidents.Runner
	current func() *snapshot.View
	pg      *pgstore.Store // nil: the memory store, this replica alone
}

// start builds the model client and the service and serves the
// investigator's routes; the caller shuts the service down before the
// listeners stop.
func (s investigatorSetup) start(ctx context.Context, srv *api.Server) (*investigate.Service, error) {
	c := s.cfg.investigator
	lc := llm.Config{Endpoint: c.endpoint, Model: c.modelID(), Fallback: c.fallback, Timeout: c.timeout}
	var model *llm.Client
	var err error
	switch c.provider {
	case llm.ProviderAnthropic:
		lc.APIKey = os.Getenv("ANTHROPIC_API_KEY")
		// Tool inputs stream as they are generated on the Anthropic API
		// itself; a proxy in front of it may reject the field.
		lc.EagerInputStreaming = c.endpoint == ""
		model, err = llm.NewAnthropic(lc)
	case llm.ProviderBedrock:
		lc.Region, lc.BedrockAPI = c.bedrockRegion(s.cfg), c.bedrockAPI
		model, err = llm.NewBedrock(ctx, lc)
	}
	if err != nil {
		return nil, err
	}
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
	svc, err := investigate.NewService(investigate.Config{
		LLM: model, Source: investigatorSource{Runner: s.runner, current: s.current}, Store: store, Egress: eg,
		Options: c.options(), PerHour: c.perHour, PerHourTotal: c.perHourTotal, Concurrency: c.concurrency,
		Cluster: s.cfg.clusterName, Hooks: investigatorHooks(), Logger: slog.Default(),
	})
	if err != nil {
		return nil, err
	}
	srv.Investigations = svc
	attrs := []any{"provider", c.provider, "model", c.modelID(), "effort", c.effort, "fallback", model.Fallback(),
		"perHour", c.perHour, "concurrency", c.concurrency}
	if c.provider == llm.ProviderBedrock {
		attrs = append(attrs, "region", lc.Region, "bedrockAPI", c.bedrockAPI)
	}
	if c.endpoint != "" {
		attrs = append(attrs, "endpoint", c.endpoint)
	}
	slog.Warn("AI investigator on: investigations send redacted incident data to the model provider", attrs...)
	return svc, nil
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
// alone (the pods on it may belong to namespaces the starter cannot see).
// The view is shared and read-only: values are copied, never changed.
func (s investigatorSource) WorkloadState(_ context.Context, in *incidents.Incident) (*investigate.WorkloadState, error) {
	v := s.current()
	if v == nil {
		return nil, errors.New("no cluster view yet")
	}
	st := &investigate.WorkloadState{At: v.Built}
	sub := in.Subject
	nodes := map[string]bool{}
	switch {
	case sub.Kind == incidents.KindNode:
		nodes[sub.Name] = true
	case sub.Namespace != "":
		for i := range v.Inv.Workloads {
			if w := &v.Inv.Workloads[i]; w.Namespace == sub.Namespace && w.Kind == sub.Kind && w.Name == sub.Name {
				c := *w
				st.Workload = &c
				break
			}
		}
		named := map[string]bool{}
		for _, p := range in.Pods {
			named[p] = true
		}
		a := v.Assoc()
		for _, p := range a.PodsIn(sub.Namespace) {
			kind, name := a.RootOf(p)
			if (kind == sub.Kind && name == sub.Name) || named[p.Name] {
				st.Pods = append(st.Pods, *p)
				if p.NodeName != "" {
					nodes[p.NodeName] = true
				}
			}
		}
		sort.Slice(st.Pods, func(i, j int) bool { return st.Pods[i].Name < st.Pods[j].Name })
	}
	for _, n := range v.Inv.Nodes {
		if nodes[n.Name] {
			st.Nodes = append(st.Nodes, n)
		}
	}
	return st, nil
}
