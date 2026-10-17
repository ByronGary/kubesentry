package llm

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/bedrock"
	"github.com/anthropics/anthropic-sdk-go/lib/betafallback"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/aws/aws-sdk-go-v2/config"
)

// credentialsTimeout bounds resolving the AWS credentials at startup.
const credentialsTimeout = 30 * time.Second

// NewBedrock returns a client of Claude in Amazon Bedrock. Credentials come
// from the AWS SDK's default chain (environment, profile, IRSA web
// identity, EKS Pod Identity), or a Bedrock API key in
// AWS_BEARER_TOKEN_BEDROCK; they are resolved once here, so a missing
// credential fails at startup. Requests are signed with SigV4 for the
// service bedrock-mantle (BedrockMantle) or bedrock (BedrockRuntime).
//
// The refusal fallback is the SDK's client-side middleware: Bedrock has no
// server-side fallback.
func NewBedrock(ctx context.Context, cfg Config) (*Client, error) {
	region := strings.TrimSpace(cfg.Region)
	if region == "" {
		return nil, errors.New("llm: Bedrock needs a region (-investigator-region or -aws-region)")
	}
	if cfg.Endpoint != "" {
		if err := checkEndpoint(cfg.Endpoint); err != nil {
			return nil, err
		}
	}
	c := &Client{provider: ProviderBedrock, now: time.Now, fallback: FallbackOff}
	// The fallback needs the Anthropic-shaped request: it goes first,
	// before the counter (so each hop counts) and the Bedrock adaptation.
	var mws []option.Middleware
	if fb := bedrockFallback(cfg.Fallback, cfg.Model); fb != "" {
		mws = append(mws, betafallback.BetaRefusalFallbackMiddleware([]anthropic.BetaFallbackParam{{Model: anthropic.Model(fb)}}))
		c.pins = &pins{}
		c.fallback = "client-side, " + fb
	}
	mws = append(mws, counter(ProviderBedrock, cfg.OnRequest))
	common := cfg.common(mws...)

	cctx, cancel := context.WithTimeout(ctx, credentialsTimeout)
	defer cancel()
	switch cfg.BedrockAPI {
	case "", BedrockMantle:
		// The client takes its region, endpoint and credentials itself;
		// its SigV4 signing runs after the middlewares above.
		mc, err := bedrock.NewMantleClient(cctx, bedrock.MantleClientConfig{AWSRegion: region, BaseURL: cfg.Endpoint}, common...)
		if err != nil {
			return nil, fmt.Errorf("llm: Bedrock (mantle): %w", err)
		}
		c.msgs = &mc.Beta.Messages
	case BedrockRuntime:
		awsCfg, err := config.LoadDefaultConfig(cctx, config.WithRegion(region))
		if err != nil {
			return nil, fmt.Errorf("llm: Bedrock (runtime): load the AWS configuration: %w", err)
		}
		if awsCfg.Credentials != nil {
			if _, err := awsCfg.Credentials.Retrieve(cctx); err != nil {
				return nil, fmt.Errorf("llm: Bedrock (runtime): resolve AWS credentials: %w", err)
			}
		}
		// bedrock.WithConfig adds the InvokeModel adaptation (URL, body,
		// signing, EventStream to SSE) closest to the wire; it includes
		// WithoutEnvironmentDefaults, so ANTHROPIC_API_KEY is never sent.
		opts := append(common, bedrock.WithConfig(awsCfg))
		if cfg.Endpoint != "" {
			opts = append(opts, option.WithBaseURL(cfg.Endpoint))
		}
		client := anthropic.NewClient(opts...)
		c.msgs = &client.Beta.Messages
	default:
		return nil, fmt.Errorf("llm: Bedrock API %q: use %s or %s", cfg.BedrockAPI, BedrockMantle, BedrockRuntime)
	}
	return c, nil
}

// bedrockFallback is the fallback model for Bedrock: a model ID given, or
// with FallbackAuto Claude Opus 5 in the same form as the Claude Opus 5.5
// ID asked for (anthropic.claude-opus-5, us.anthropic.claude-opus-5, …).
// An inference-profile ARN, or another model, has no automatic fallback.
func bedrockFallback(fallback, model string) string {
	switch fb := strings.TrimSpace(fallback); fb {
	case FallbackOff:
		return ""
	case "", FallbackAuto:
		if model == "" {
			model = DefaultBedrockModel
		}
		const opus55, opus5 = "claude-opus-5-5", "claude-opus-5"
		if strings.HasPrefix(model, "arn:") || !strings.HasSuffix(model, opus55) {
			return ""
		}
		return strings.TrimSuffix(model, opus55) + opus5
	default:
		return fb
	}
}
