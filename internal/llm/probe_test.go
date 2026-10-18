package llm

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeSTS answers GetCallerIdentity (the query protocol, XML).
func fakeSTS(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("Action") != "GetCallerIdentity" {
			t.Errorf("STS action %q", r.Form.Get("Action"))
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AKIDTESTKEY/") {
			t.Errorf("STS request not signed: %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

const stsOK = `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult>
<Arn>arn:aws:sts::111122223333:assumed-role/kubesentry/botocore-session-1</Arn><UserId>AROAEXAMPLE:s</UserId><Account>111122223333</Account>
</GetCallerIdentityResult><ResponseMetadata><RequestId>r-1</RequestId></ResponseMetadata></GetCallerIdentityResponse>`

func probeBedrock(t *testing.T, api string, model http.HandlerFunc) ProbeResult {
	t.Helper()
	sts := fakeSTS(t, 200, stsOK)
	f := newFake(t, model)
	ep := f.srv.URL
	if api != BedrockRuntime {
		ep += "/anthropic"
	}
	return Probe(context.Background(), ProbeConfig{Provider: ProviderBedrock, STSEndpoint: sts.URL,
		Config: Config{Region: "us-east-1", BedrockAPI: api, Endpoint: ep, OnRequest: func(string, string) {}}})
}

func TestProbeBedrockOK(t *testing.T) {
	awsTestEnv(t)
	res := probeBedrock(t, BedrockMantle, streamOK(turnEvents("anthropic.claude-opus-5-5", "max_tokens")))
	if !res.OK || res.Error != nil || res.IdentityARN != "arn:aws:sts::111122223333:assumed-role/kubesentry/botocore-session-1" ||
		res.Account != "111122223333" || res.Model != DefaultBedrockModel || res.Region != "us-east-1" || !strings.HasSuffix(res.Endpoint, "/anthropic") {
		t.Errorf("probe %+v %+v", res, res.Error)
	}
}

func TestProbeErrors(t *testing.T) {
	awsTestEnv(t)
	denied := `{"message":"User: arn:aws:sts::111122223333:assumed-role/kubesentry/s is not authorized to perform: bedrock:InvokeModelWithResponseStream on resource: arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-opus-5-5 because no identity-based policy allows the bedrock:InvokeModelWithResponseStream action"}`
	for _, tc := range []struct {
		name   string
		api    string
		model  http.HandlerFunc
		kind   string
		action string
	}{
		{"access denied", BedrockRuntime, errorReply(403, denied, "X-Amzn-ErrorType", "AccessDeniedException:http://x/"), ProbeAccessDenied, "bedrock:InvokeModelWithResponseStream"},
		{"access denied without an action", BedrockMantle, errorReply(403, `{"message":"Forbidden"}`, "X-Amzn-ErrorType", "AccessDeniedException"),
			ProbeAccessDenied, "bedrock-mantle:CreateInference"},
		{"model not enabled", BedrockRuntime, errorReply(403, `{"message":"You don't have access to the model with the specified model ID."}`,
			"X-Amzn-ErrorType", "AccessDeniedException"), ProbeModelAccess, ""},
		{"model not in region", BedrockRuntime, errorReply(400, `{"message":"The provided model identifier is invalid."}`,
			"X-Amzn-ErrorType", "ValidationException"), ProbeModelUnavailable, ""},
		{"model not found", BedrockMantle, errorReply(404, `{"type":"error","error":{"type":"not_found_error","message":"model: anthropic.claude-opus-5-5"}}`),
			ProbeModelUnavailable, ""},
		{"throttled", BedrockMantle, errorReply(429, `{"type":"error","error":{"type":"rate_limit_error","message":"slow down"}}`), ProbeThrottled, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := probeBedrock(t, tc.api, tc.model)
			if res.OK || res.Error == nil || res.Error.Kind != tc.kind || res.Error.Action != tc.action || res.Error.Hint == "" && tc.kind != ProbeOther {
				t.Fatalf("got %+v", res.Error)
			}
			if res.IdentityARN == "" {
				t.Error("no identity")
			}
			if strings.Contains(res.Error.Message, "{") {
				t.Errorf("a response body leaked: %q", res.Error.Message)
			}
		})
	}
}

func TestProbeNoCredentials(t *testing.T) {
	awsTestEnv(t)
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	res := Probe(context.Background(), ProbeConfig{Provider: ProviderBedrock, STSEndpoint: "http://127.0.0.1:1",
		Config: Config{Region: "us-east-1", Endpoint: "http://127.0.0.1:1/anthropic"}})
	if res.OK || res.Error == nil || res.Error.Kind != ProbeNoCredentials || !strings.Contains(res.Error.Hint, "IRSA") {
		t.Errorf("got %+v", res.Error)
	}
	if strings.Contains(res.Error.Message+res.Error.Hint, "sk-ant-must-not-leak") {
		t.Error("the Anthropic key leaked")
	}
	if res := Probe(context.Background(), ProbeConfig{Provider: ProviderBedrock}); res.Error == nil || res.Error.Kind != ProbeBadConfig {
		t.Errorf("no region: %+v", res.Error)
	}
}

// dnsFail is a transport whose every lookup fails, like a VPC without the
// endpoint's private DNS.
func dnsFail() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(addr)
		return nil, &net.OpError{Op: "dial", Net: network, Err: &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}}
	}
	return &http.Client{Transport: tr}
}

func TestProbeNetwork(t *testing.T) {
	awsTestEnv(t)
	// The model endpoint does not resolve: DNS, with the VPC endpoint hint.
	// STS (the fake) answers; every other host fails DNS, so no request
	// leaves the machine.
	sts := fakeSTS(t, 200, stsOK)
	res := Probe(context.Background(), ProbeConfig{Provider: ProviderBedrock, STSEndpoint: sts.URL,
		Config: Config{Region: "us-east-1", HTTPClient: dnsFailExcept(sts.URL), OnRequest: func(string, string) {}}})
	if res.OK || res.Error == nil || res.Error.Kind != ProbeNetwork || !strings.Contains(res.Error.Message, "DNS") ||
		!strings.Contains(res.Error.Hint, "com.amazonaws.us-east-1.bedrock-mantle") || res.IdentityARN == "" {
		t.Errorf("DNS: %+v", res.Error)
	}
	// STS itself unreachable.
	res = Probe(context.Background(), ProbeConfig{Provider: ProviderBedrock, STSEndpoint: "https://sts.us-east-1.amazonaws.com",
		Config: Config{Region: "us-east-1", HTTPClient: dnsFail()}})
	if res.Error == nil || res.Error.Kind != ProbeNetwork || !strings.Contains(res.Error.Hint, ".sts") {
		t.Errorf("STS unreachable: %+v", res.Error)
	}
	// A refused connection to the Anthropic API.
	res = Probe(context.Background(), ProbeConfig{Provider: ProviderAnthropic, Config: Config{APIKey: "sk-ant-test", Endpoint: "http://127.0.0.1:1",
		OnRequest: func(string, string) {}}})
	if res.Error == nil || res.Error.Kind != ProbeNetwork || !strings.Contains(res.Error.Hint, "api.anthropic.com") {
		t.Errorf("refused: %+v", res.Error)
	}
}

// dnsFailExcept fails DNS for every host but the one of allowed.
func dnsFailExcept(allowed string) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	host := strings.TrimPrefix(allowed, "http://")
	var d net.Dialer
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr == host {
			return d.DialContext(ctx, network, addr)
		}
		h, _, _ := net.SplitHostPort(addr)
		return nil, &net.OpError{Op: "dial", Net: network, Err: &net.DNSError{Err: "no such host", Name: h, IsNotFound: true}}
	}
	return &http.Client{Transport: tr}
}

func TestProbeAnthropic(t *testing.T) {
	f := newFake(t, errorReply(401, `{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}`))
	res := Probe(context.Background(), ProbeConfig{Provider: ProviderAnthropic, Config: Config{APIKey: "sk-ant-bad", Endpoint: f.srv.URL,
		OnRequest: func(string, string) {}}})
	if res.OK || res.Error == nil || res.Error.Kind != ProbeAuth || res.Error.Status != 401 || !strings.Contains(res.Error.Hint, "existingSecret") ||
		res.Model != DefaultAnthropicModel || res.IdentityARN != "" {
		t.Errorf("401: %+v %+v", res, res.Error)
	}
	if res := Probe(context.Background(), ProbeConfig{Provider: ProviderAnthropic}); res.Error == nil || res.Error.Kind != ProbeAuth {
		t.Errorf("no key: %+v", res.Error)
	}
	ok := newFake(t, streamOK(turnEvents("claude-opus-5-5", "max_tokens")))
	res = Probe(context.Background(), ProbeConfig{Provider: ProviderAnthropic, Config: Config{APIKey: "sk-ant-ok", Endpoint: ok.srv.URL,
		OnRequest: func(string, string) {}}})
	if !res.OK || res.Endpoint != ok.srv.URL {
		t.Errorf("ok: %+v %+v", res, res.Error)
	}
	body := ok.requests()[0].json(t)
	if body["max_tokens"] != float64(1) || body["tools"] != nil || body["fallbacks"] != nil {
		t.Errorf("probe request %v", body)
	}
	if res := Probe(context.Background(), ProbeConfig{Provider: "openai"}); res.Error == nil || res.Error.Kind != ProbeBadConfig {
		t.Errorf("unknown provider: %+v", res.Error)
	}
	if ModelEndpoint(ProviderBedrock, Config{Region: "eu-west-1", BedrockAPI: BedrockRuntime}) != "https://bedrock-runtime.eu-west-1.amazonaws.com" {
		t.Error("runtime endpoint")
	}
}
