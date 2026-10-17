package llm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream"

	"github.com/ByronGary/kubesentry/internal/investigate"
)

// awsTestEnv gives the AWS SDK static test credentials and nothing else:
// no profile, no config files, no instance metadata, no Bedrock API key.
// ANTHROPIC_API_KEY is set to show it never reaches Bedrock.
func awsTestEnv(t *testing.T) {
	dir := t.TempDir()
	for k, v := range map[string]string{
		"AWS_ACCESS_KEY_ID": "AKIDTESTKEY", "AWS_SECRET_ACCESS_KEY": "test-secret", "AWS_SESSION_TOKEN": "",
		"AWS_PROFILE": "", "AWS_DEFAULT_PROFILE": "", "AWS_REGION": "", "AWS_DEFAULT_REGION": "",
		"AWS_CONFIG_FILE": filepath.Join(dir, "config"), "AWS_SHARED_CREDENTIALS_FILE": filepath.Join(dir, "credentials"),
		"AWS_EC2_METADATA_DISABLED": "true", "AWS_BEARER_TOKEN_BEDROCK": "", "ANTHROPIC_AWS_API_KEY": "",
		"ANTHROPIC_BEDROCK_MANTLE_BASE_URL": "", "ANTHROPIC_API_KEY": "sk-ant-must-not-leak", "AWS_WEB_IDENTITY_TOKEN_FILE": "",
		"AWS_CONTAINER_CREDENTIALS_FULL_URI": "", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "",
	} {
		t.Setenv(k, v)
	}
}

func bedrockClient(t *testing.T, cfg Config) (*Client, *codes) {
	t.Helper()
	cs := &codes{}
	cfg.OnRequest = cs.inc
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	c, err := NewBedrock(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c, cs
}

func bedrockRequest(model string) *investigate.Request {
	r := firstRequest()
	r.Model = model
	return r
}

func checkSigV4(t *testing.T, h http.Header, service string) {
	t.Helper()
	auth := h.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=AKIDTESTKEY/") || !strings.Contains(auth, "/us-east-1/"+service+"/aws4_request") ||
		!strings.Contains(auth, "SignedHeaders=") || !strings.Contains(auth, "Signature=") {
		t.Errorf("Authorization = %q, want SigV4 for %s", auth, service)
	}
	if h.Get("X-Amz-Date") == "" {
		t.Error("no X-Amz-Date")
	}
	if h.Get("X-Api-Key") != "" {
		t.Error("an x-api-key header reached Bedrock")
	}
}

func TestBedrockMantle(t *testing.T) {
	awsTestEnv(t)
	f := newFake(t, streamOK(turnEvents("anthropic.claude-opus-5-5", "tool_use"), "x-amzn-requestid", "amzn-req-1"))
	c, cs := bedrockClient(t, Config{Endpoint: f.srv.URL + "/anthropic", Model: DefaultBedrockModel})
	if c.Provider() != ProviderBedrock || c.Fallback() != "client-side, anthropic.claude-opus-5" {
		t.Errorf("provider %q, fallback %q", c.Provider(), c.Fallback())
	}
	resp, err := c.Send(context.Background(), bedrockRequest(DefaultBedrockModel))
	if err != nil {
		t.Fatal(err)
	}
	r := f.requests()[0]
	if r.method != http.MethodPost || r.path != "/anthropic/v1/messages" || r.query != "beta=true" {
		t.Errorf("sent %s %s?%s", r.method, r.path, r.query)
	}
	checkSigV4(t, r.header, "bedrock-mantle")
	if r.header.Get("Anthropic-Version") != "2023-06-01" {
		t.Errorf("anthropic-version = %q", r.header.Get("Anthropic-Version"))
	}
	// The client-side fallback opts into fallback credit; there is no
	// server-side fallback on Bedrock.
	if beta := r.header.Get("Anthropic-Beta"); !strings.Contains(beta, "fallback-credit-2026-07-01") || strings.Contains(beta, "server-side") {
		t.Errorf("anthropic-beta = %q", beta)
	}
	body := r.json(t)
	if body["model"] != DefaultBedrockModel || body["stream"] != true || body["fallbacks"] != nil || body["thinking"] != nil {
		t.Errorf("model %v, stream %v, fallbacks %v, thinking %v", body["model"], body["stream"], body["fallbacks"], body["thinking"])
	}
	if bytes.Contains(r.body, []byte("eager_input_streaming")) {
		t.Error("eager_input_streaming sent to Bedrock")
	}
	if oc := body["output_config"].(map[string]any); oc["effort"] != "high" {
		t.Errorf("output_config = %v", oc)
	}
	if resp.RequestID != "amzn-req-1" || resp.StopReason != investigate.StopToolUse || len(resp.Content) != 3 {
		t.Errorf("reply %+v", resp)
	}
	if got := cs.list(); len(got) != 1 || got[0] != "bedrock:200" {
		t.Errorf("counted %v", got)
	}
	if c.pins.count() != 1 {
		t.Errorf("%d fallback pins, want one for the run", c.pins.count())
	}
}

// eventStream encodes SSE events as Bedrock's InvokeModelWithResponseStream
// sends them: AWS EventStream chunk messages carrying base64 JSON.
func eventStream(t *testing.T, evs []event) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := eventstream.NewEncoder()
	for _, e := range evs {
		if e.typ == "ping" {
			continue
		}
		payload, _ := json.Marshal(map[string]string{"bytes": base64.StdEncoding.EncodeToString([]byte(e.data))})
		var h eventstream.Headers
		h.Set(":message-type", eventstream.StringValue("event"))
		h.Set(":event-type", eventstream.StringValue("chunk"))
		h.Set(":content-type", eventstream.StringValue("application/json"))
		if err := enc.Encode(&buf, eventstream.Message{Headers: h, Payload: payload}); err != nil {
			t.Fatal(err)
		}
	}
	return buf.Bytes()
}

func TestBedrockRuntime(t *testing.T) {
	awsTestEnv(t)
	const arn = "arn:aws:bedrock:us-east-1:123456789012:inference-profile/us.anthropic.claude-opus-5-5"
	stream := eventStream(t, turnEvents("claude-opus-5-5", "end_turn"))
	f := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.amazon.eventstream")
		w.Header().Set("X-Amzn-Requestid", "amzn-req-2")
		w.WriteHeader(http.StatusOK)
		w.Write(stream)
	})
	c, cs := bedrockClient(t, Config{BedrockAPI: BedrockRuntime, Endpoint: f.srv.URL, Model: arn})
	// An inference-profile ARN has no automatic fallback model.
	if c.Fallback() != FallbackOff || c.pins != nil {
		t.Errorf("fallback %q", c.Fallback())
	}
	resp, err := c.Send(context.Background(), bedrockRequest(arn))
	if err != nil {
		t.Fatal(err)
	}
	r := f.requests()[0]
	wantRaw := "/model/arn%3Aaws%3Abedrock%3Aus-east-1%3A123456789012%3Ainference-profile%2Fus.anthropic.claude-opus-5-5/invoke-with-response-stream"
	if r.method != http.MethodPost || r.rawPath != wantRaw {
		t.Errorf("sent %s path %q raw %q, want raw %q", r.method, r.path, r.rawPath, wantRaw)
	}
	checkSigV4(t, r.header, "bedrock")
	body := r.json(t)
	if body["anthropic_version"] != "bedrock-2023-05-31" || body["model"] != nil || body["stream"] != nil {
		t.Errorf("anthropic_version %v, model %v, stream %v", body["anthropic_version"], body["model"], body["stream"])
	}
	if body["anthropic_beta"] != nil || r.header.Get("Anthropic-Beta") != "" {
		t.Errorf("betas without a fallback: %v %q", body["anthropic_beta"], r.header.Get("Anthropic-Beta"))
	}
	if body["thinking"] != nil || body["output_config"].(map[string]any)["effort"] != "high" || body["max_tokens"] != float64(16000) {
		t.Errorf("thinking %v, output_config %v", body["thinking"], body["output_config"])
	}
	if resp.StopReason != investigate.StopEndTurn || resp.RequestID != "amzn-req-2" || len(resp.Content) != 3 ||
		resp.Content[2].ID != "toolu_01" || string(resp.Content[2].Input) != `{"level":"error"}` {
		t.Errorf("reply %+v", resp)
	}
	if want := (investigate.Usage{Input: 120, Output: 450, CacheRead: 30000, CacheWrite: 2000}); resp.Usage != want {
		t.Errorf("usage %+v", resp.Usage)
	}
	if got := cs.list(); len(got) != 1 || got[0] != "bedrock:200" {
		t.Errorf("counted %v", got)
	}
}

func TestBedrockRuntimeModelIDAndFallback(t *testing.T) {
	awsTestEnv(t)
	stream := eventStream(t, turnEvents("claude-opus-5-5", "end_turn"))
	f := newFake(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.amazon.eventstream")
		w.WriteHeader(http.StatusOK)
		w.Write(stream)
	})
	c, _ := bedrockClient(t, Config{BedrockAPI: BedrockRuntime, Endpoint: f.srv.URL, Model: "us.anthropic.claude-opus-5-5"})
	if c.Fallback() != "client-side, us.anthropic.claude-opus-5" {
		t.Errorf("fallback %q", c.Fallback())
	}
	if _, err := c.Send(context.Background(), bedrockRequest("us.anthropic.claude-opus-5-5")); err != nil {
		t.Fatal(err)
	}
	r := f.requests()[0]
	if r.path != "/model/us.anthropic.claude-opus-5-5/invoke-with-response-stream" {
		t.Errorf("path %q", r.path)
	}
	// InvokeModel takes the betas in the body.
	betas, _ := r.json(t)["anthropic_beta"].([]any)
	if len(betas) == 0 || betas[0] != "fallback-credit-2026-07-01" || r.header.Get("Anthropic-Beta") != "" {
		t.Errorf("anthropic_beta %v, header %q", betas, r.header.Get("Anthropic-Beta"))
	}
}

func TestBedrockErrors(t *testing.T) {
	awsTestEnv(t)
	f := newFake(t, errorReply(http.StatusForbidden, `{"message":"You don't have access to the model with the specified model ID."}`,
		"X-Amzn-ErrorType", "AccessDeniedException:http://internal.amazon.com/coral/com.amazon.bedrock/"))
	c, cs := bedrockClient(t, Config{BedrockAPI: BedrockRuntime, Endpoint: f.srv.URL, Fallback: FallbackOff})
	_, err := c.Send(context.Background(), bedrockRequest(DefaultBedrockModel))
	var ae *investigate.APIError
	if !strings.Contains(err.Error(), "AccessDeniedException") {
		t.Errorf("err = %v", err)
	}
	if !errors.As(err, &ae) || ae.Status != 403 || ae.Type != "AccessDeniedException" || ae.Retryable ||
		ae.Message != "You don't have access to the model with the specified model ID." {
		t.Errorf("api error %+v", ae)
	}
	if got := cs.list(); len(got) != 1 || got[0] != "bedrock:403" {
		t.Errorf("counted %v", got)
	}
}

func TestBedrockConfigChecks(t *testing.T) {
	awsTestEnv(t)
	if _, err := NewBedrock(context.Background(), Config{}); err == nil {
		t.Error("no region accepted")
	}
	if _, err := NewBedrock(context.Background(), Config{Region: "us-east-1", BedrockAPI: "converse"}); err == nil {
		t.Error("an unknown Bedrock API accepted")
	}
	for _, tc := range []struct{ fallback, model, want string }{
		{"", "anthropic.claude-opus-5-5", "anthropic.claude-opus-5"},
		{"auto", "global.anthropic.claude-opus-5-5", "global.anthropic.claude-opus-5"},
		{"auto", "", "anthropic.claude-opus-5"},
		{"auto", "anthropic.claude-sonnet-5-5", ""},
		{"auto", "arn:aws:bedrock:us-east-1:1:application-inference-profile/abc", ""},
		{"off", "anthropic.claude-opus-5-5", ""},
		{"anthropic.claude-opus-4-8", "x", "anthropic.claude-opus-4-8"},
	} {
		if got := bedrockFallback(tc.fallback, tc.model); got != tc.want {
			t.Errorf("bedrockFallback(%q, %q) = %q, want %q", tc.fallback, tc.model, got, tc.want)
		}
	}
}
