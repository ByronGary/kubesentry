package llm

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"github.com/ByronGary/kubesentry/internal/investigate"
)

// ProbeTimeout bounds a connection test.
const ProbeTimeout = 30 * time.Second

// Kinds of a failed connection test (ProbeError.Kind).
const (
	ProbeNoCredentials    = "no_credentials"
	ProbeAccessDenied     = "access_denied"
	ProbeModelAccess      = "model_access"
	ProbeModelUnavailable = "model_unavailable"
	ProbeNetwork          = "network"
	ProbeAuth             = "auth"
	ProbeThrottled        = "throttled"
	ProbeBadConfig        = "config"
	ProbeOther            = "other"
)

// ProbeConfig is what a connection test uses: the provider and the client
// config (Region, BedrockAPI, Endpoint, Model, APIKey, HTTPClient).
type ProbeConfig struct {
	Provider string
	Config
	// STSEndpoint overrides STS's endpoint (tests; AWS_ENDPOINT_URL_STS
	// works too).
	STSEndpoint string
}

// ProbeResult is the outcome of a connection test. It never holds a
// provider's response body beyond the API's short error message.
type ProbeResult struct {
	OK       bool   `json:"ok"`
	Provider string `json:"provider"`
	Region   string `json:"region,omitempty"`
	// Endpoint is the base URL the model request went to.
	Endpoint string `json:"endpoint"`
	Model    string `json:"model"`
	// IdentityARN is who kubesentry is to AWS (STS GetCallerIdentity).
	IdentityARN string      `json:"identityArn,omitempty"`
	Account     string      `json:"account,omitempty"`
	LatencyMs   int64       `json:"latencyMs"`
	Error       *ProbeError `json:"error,omitempty"`
}

// ProbeError says what failed and what to do.
type ProbeError struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
	// Action is the IAM action that was denied, when the error names it.
	Action string `json:"action,omitempty"`
	// Status is the HTTP status of the model API, when it answered.
	Status int `json:"status,omitempty"`
}

// ModelEndpoint is the base URL the provider's requests go to.
func ModelEndpoint(provider string, cfg Config) string {
	if cfg.Endpoint != "" {
		return cfg.Endpoint
	}
	switch {
	case provider == ProviderAnthropic:
		return "https://api.anthropic.com"
	case cfg.BedrockAPI == BedrockRuntime:
		return "https://bedrock-runtime." + cfg.Region + ".amazonaws.com"
	}
	return "https://bedrock-mantle." + cfg.Region + ".api.aws/anthropic"
}

// Probe tests the connection: for Bedrock it resolves the AWS credentials
// and asks STS who they are, then for either provider it sends a one-token
// request to the model. Nothing is retried.
func Probe(ctx context.Context, pc ProbeConfig) ProbeResult {
	ctx, cancel := context.WithTimeout(ctx, ProbeTimeout)
	defer cancel()
	cfg := pc.Config
	cfg.MaxRetries, cfg.Fallback, cfg.EagerInputStreaming = -1, FallbackOff, false
	if cfg.Timeout <= 0 || cfg.Timeout > ProbeTimeout {
		cfg.Timeout = ProbeTimeout
	}
	if cfg.Model == "" {
		cfg.Model = DefaultAnthropicModel
		if pc.Provider == ProviderBedrock {
			cfg.Model = DefaultBedrockModel
		}
	}
	res := ProbeResult{Provider: pc.Provider, Model: cfg.Model, Endpoint: redactURL(ModelEndpoint(pc.Provider, cfg))}
	start := time.Now()
	defer func() { res.LatencyMs = time.Since(start).Milliseconds() }()
	fail := func(e *ProbeError) ProbeResult {
		res.Error = e
		res.LatencyMs = time.Since(start).Milliseconds()
		return res
	}
	var client *Client
	switch pc.Provider {
	case ProviderAnthropic:
		if strings.TrimSpace(cfg.APIKey) == "" {
			return fail(&ProbeError{Kind: ProbeAuth, Message: "no Anthropic API key: ANTHROPIC_API_KEY is not set",
				Hint: "Create a Secret with the key and set incidents.investigator.existingSecret, then restart kubesentry."})
		}
		c, err := NewAnthropic(cfg)
		if err != nil {
			return fail(&ProbeError{Kind: ProbeBadConfig, Message: cut(err.Error(), 300)})
		}
		client = c
	case ProviderBedrock:
		res.Region = strings.TrimSpace(cfg.Region)
		if res.Region == "" {
			return fail(&ProbeError{Kind: ProbeBadConfig, Message: "no region for Bedrock", Hint: "Set the region, or -aws-region (eks.region)."})
		}
		arn, account, perr := callerIdentity(ctx, res.Region, pc.STSEndpoint, cfg)
		if perr != nil {
			return fail(perr)
		}
		res.IdentityARN, res.Account = arn, account
		c, err := NewBedrock(ctx, cfg)
		if err != nil {
			return fail(&ProbeError{Kind: ProbeNoCredentials, Message: cut(err.Error(), 300), Hint: credentialsHint})
		}
		client = c
	default:
		return fail(&ProbeError{Kind: ProbeBadConfig, Message: fmt.Sprintf("provider %q: use anthropic or bedrock", pc.Provider)})
	}
	_, err := client.Send(ctx, &investigate.Request{Model: cfg.Model, MaxTokens: 1,
		Messages: []investigate.Message{{Role: "user", Content: []investigate.Block{{Type: investigate.BlockText, Text: "Reply with OK."}}}}})
	if err != nil {
		return fail(modelError(pc.Provider, cfg, err))
	}
	res.OK = true
	return res
}

const credentialsHint = "In EKS: annotate kubesentry's service account for IRSA, or create an EKS Pod Identity association, then restart kubesentry. " +
	"From a laptop: aws sso login --profile <profile> and AWS_PROFILE. Elsewhere: AWS_ACCESS_KEY_ID from a Kubernetes Secret."

// callerIdentity asks STS who the credentials are.
func callerIdentity(ctx context.Context, region, endpoint string, cfg Config) (string, string, *ProbeError) {
	awsCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region), config.WithHTTPClient(cfg.httpClient()),
		config.WithRetryMaxAttempts(1))
	if err != nil {
		return "", "", &ProbeError{Kind: ProbeNoCredentials, Message: "the AWS configuration could not be loaded: " + cut(err.Error(), 200), Hint: credentialsHint}
	}
	if awsCfg.Credentials == nil {
		return "", "", &ProbeError{Kind: ProbeNoCredentials, Message: "no AWS credentials found", Hint: credentialsHint}
	}
	if _, err := awsCfg.Credentials.Retrieve(ctx); err != nil {
		e := &ProbeError{Kind: ProbeNoCredentials, Message: "no AWS credentials found: " + cut(credentialsReason(err), 200), Hint: credentialsHint}
		if isNetwork(err) {
			e.Hint = "The credential endpoint (STS for IRSA, EKS Auth for Pod Identity) is unreachable: in a private cluster add the com.amazonaws." +
				region + ".sts or .eks-auth VPC endpoint. " + credentialsHint
		}
		if strings.Contains(strings.ToLower(err.Error()), "expired") || strings.Contains(strings.ToLower(err.Error()), "sso") {
			e.Hint = "The SSO session expired or was never started: run aws sso login --profile <profile>."
		}
		return "", "", e
	}
	client := sts.NewFromConfig(awsCfg, func(o *sts.Options) {
		if endpoint != "" {
			o.BaseEndpoint = aws.String(endpoint)
		}
	})
	out, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		if isNetwork(err) {
			return "", "", &ProbeError{Kind: ProbeNetwork, Message: "STS is unreachable: " + cut(networkReason(err), 200),
				Hint: "Allow HTTPS to STS, or add the com.amazonaws." + region + ".sts interface VPC endpoint with private DNS."}
		}
		var ae smithy.APIError
		if errors.As(err, &ae) {
			kind := ProbeOther
			switch code := ae.ErrorCode(); {
			case strings.Contains(code, "Expired"), code == "InvalidClientTokenId", code == "SignatureDoesNotMatch":
				kind = ProbeNoCredentials
			case strings.Contains(code, "AccessDenied"):
				kind = ProbeAccessDenied
			}
			return "", "", &ProbeError{Kind: kind, Message: "STS GetCallerIdentity: " + ae.ErrorCode() + ": " + cut(ae.ErrorMessage(), 200), Hint: credentialsHint}
		}
		return "", "", &ProbeError{Kind: ProbeOther, Message: "STS GetCallerIdentity failed"}
	}
	return aws.ToString(out.Arn), aws.ToString(out.Account), nil
}

// credentialsReason shortens the SDK's chain error to its last cause.
func credentialsReason(err error) string {
	msg := err.Error()
	if i := strings.LastIndex(msg, "caused by: "); i >= 0 {
		msg = msg[i+len("caused by: "):]
	}
	return msg
}

var deniedAction = regexp.MustCompile(`perform:? ([a-z0-9-]+:[A-Za-z0-9*]+)`)

// modelError maps an error of the model request.
func modelError(provider string, cfg Config, err error) *ProbeError {
	if isNetwork(err) {
		e := &ProbeError{Kind: ProbeNetwork, Message: "the model API is unreachable: " + cut(networkReason(err), 200)}
		if provider == ProviderBedrock {
			svc := "bedrock-mantle"
			if cfg.BedrockAPI == BedrockRuntime {
				svc = "bedrock-runtime"
			}
			e.Hint = "Check the interface VPC endpoint com.amazonaws." + cfg.Region + "." + svc + ": private DNS on, its security group allowing TCP 443 from the nodes, " +
				"and the NetworkPolicy's egress. Without private DNS, set the endpoint to the VPC endpoint's DNS name."
		} else {
			e.Hint = "The pods need egress on 443 to api.anthropic.com (or HTTPS_PROXY)."
		}
		return e
	}
	var ae *investigate.APIError
	if !errors.As(err, &ae) {
		if errors.Is(err, context.DeadlineExceeded) {
			return &ProbeError{Kind: ProbeNetwork, Message: "the model API did not answer within " + ProbeTimeout.String(),
				Hint: "A VPC endpoint security group or a NetworkPolicy may drop the traffic."}
		}
		return &ProbeError{Kind: ProbeOther, Message: cut(err.Error(), 300)}
	}
	msg := cut(ae.Message, 300)
	e := &ProbeError{Status: ae.Status, Message: strings.TrimSpace(fmt.Sprintf("HTTP %d %s: %s", ae.Status, ae.Type, msg))}
	lower := strings.ToLower(msg + " " + ae.Type)
	switch {
	case ae.Status == 401 || ae.Type == "authentication_error":
		e.Kind = ProbeAuth
		if provider == ProviderAnthropic {
			e.Hint = "The Anthropic API key is missing or invalid: check the Secret behind incidents.investigator.existingSecret, then restart kubesentry."
		} else {
			e.Kind, e.Hint = ProbeNoCredentials, credentialsHint
		}
	case ae.Status == 403 && (strings.Contains(lower, "access to the model") || strings.Contains(lower, "model access") ||
		strings.Contains(lower, "not enabled") || strings.Contains(lower, "use case")):
		e.Kind = ProbeModelAccess
		e.Hint = "Enable the model in the Bedrock console's Model access page for " + cfg.Region + " (and its fallback)."
	case ae.Status == 403:
		e.Kind = ProbeAccessDenied
		if m := deniedAction.FindStringSubmatch(msg); m != nil {
			e.Action = m[1]
		} else if provider == ProviderBedrock {
			e.Action = "bedrock-mantle:CreateInference"
			if cfg.BedrockAPI == BedrockRuntime {
				e.Action = "bedrock:InvokeModelWithResponseStream"
			}
		}
		if provider == ProviderBedrock {
			e.Hint = "Allow " + e.Action + " for kubesentry's role (the role policy, and the VPC endpoint policy if it has one)."
		} else {
			e.Hint = "The API key's workspace may not use this model."
		}
	case ae.Status == 404 || strings.Contains(lower, "resourcenotfound") || strings.Contains(lower, "model identifier is invalid") ||
		strings.Contains(lower, "not supported") || (ae.Status == 400 && strings.Contains(lower, "model")):
		e.Kind = ProbeModelUnavailable
		e.Hint = "The model is not available in " + or(cfg.Region, "this region") + " under this ID: check the ID, or with the runtime API use an inference profile (us.…, global.…)."
	case ae.Status == 429 || ae.Status == 529 || strings.Contains(lower, "throttl"):
		e.Kind = ProbeThrottled
		e.Hint = "The provider throttled or is overloaded; the connection works. Try again later."
	default:
		e.Kind = ProbeOther
	}
	return e
}

func or(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// isNetwork reports a connection that never got an HTTP answer: DNS, a
// refused or timed-out dial, TLS.
func isNetwork(err error) bool {
	var dns *net.DNSError
	var op *net.OpError
	var ue *url.Error
	return errors.As(err, &dns) || errors.As(err, &op) || (errors.As(err, &ue) && !errors.Is(err, context.Canceled))
}

func networkReason(err error) string {
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return "DNS: " + dns.Name + " " + dns.Err + " (with a VPC endpoint, turn its private DNS on)"
	}
	var op *net.OpError
	if errors.As(err, &op) {
		return op.Op + ": " + op.Err.Error()
	}
	return err.Error()
}
