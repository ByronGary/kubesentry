package awsauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
)

// The credentials and time of the AWS SigV4 test suite.
var (
	suiteCreds = credentials.NewStaticCredentialsProvider("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "")
	suiteTime  = time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
)

// capture is a base transport that records the signed request.
type capture struct {
	req  *http.Request
	body string
}

func (c *capture) RoundTrip(r *http.Request) (*http.Response, error) {
	c.req = r
	if r.Body != nil {
		b, _ := io.ReadAll(r.Body)
		c.body = string(b)
	}
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("{}")), Header: http.Header{}, Request: r}, nil
}

func newTestTransport(t *testing.T, endpoint string, opts Options) (*Transport, *capture) {
	t.Helper()
	c := &capture{}
	opts.Base = c
	if opts.Credentials == nil {
		opts.Credentials = suiteCreds
	}
	if opts.Now == nil {
		opts.Now = func() time.Time { return suiteTime }
	}
	tr, err := New(context.Background(), endpoint, opts)
	if err != nil {
		t.Fatal(err)
	}
	return tr, c
}

// TestPublishedVectorGetVanilla checks the transport against the "get-vanilla"
// case of the AWS Signature Version 4 test suite.
func TestPublishedVectorGetVanilla(t *testing.T) {
	tr, c := newTestTransport(t, "https://example.amazonaws.com/", Options{Region: "us-east-1", Service: "service"})
	req, _ := http.NewRequest(http.MethodGet, "https://example.amazonaws.com/", nil)
	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatal(err)
	}
	const want = "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, " +
		"SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
	if got := c.req.Header.Get("Authorization"); got != want {
		t.Fatalf("Authorization:\n got %s\nwant %s", got, want)
	}
	if c.req.Header.Get("X-Amz-Date") != "20150830T123600Z" {
		t.Fatalf("X-Amz-Date = %q", c.req.Header.Get("X-Amz-Date"))
	}
	if req.Header.Get("Authorization") != "" {
		t.Fatal("the caller's request was modified")
	}
}

// TestSignsPrometheusFormPost signs a Prometheus query the way the prom
// client sends it and compares with an independent SigV4 implementation.
func TestSignsPrometheusFormPost(t *testing.T) {
	endpoint := "https://aps-workspaces.eu-west-1.amazonaws.com/workspaces/ws-0123abcd"
	tr, c := newTestTransport(t, endpoint, Options{
		Credentials: credentials.NewStaticCredentialsProvider("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "session-token-xyz"),
	})
	form := url.Values{"query": {`max by (pod) (container_memory_working_set_bytes{namespace="a b"})`}, "time": {"1760000000.000"}}.Encode()
	req, _ := http.NewRequest(http.MethodPost, endpoint+"/api/v1/query", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer must-be-replaced")
	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatal(err)
	}

	got := c.req.Header.Get("Authorization")
	want := referenceSign(t, c.req, form, "AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "eu-west-1", "aps")
	if got != want {
		t.Fatalf("Authorization:\n got %s\nwant %s", got, want)
	}
	if !strings.Contains(got, "/eu-west-1/aps/aws4_request") || !strings.Contains(got, "SignedHeaders=content-length;content-type;host;x-amz-date;x-amz-security-token") {
		t.Fatalf("scope or signed headers: %s", got)
	}
	if c.req.Header.Get("X-Amz-Security-Token") != "session-token-xyz" {
		t.Fatal("session token not sent")
	}

	// The body reached the server intact and can be replayed.
	if c.body != form {
		t.Fatalf("body = %q", c.body)
	}
	if c.req.ContentLength != int64(len(form)) {
		t.Fatalf("ContentLength = %d", c.req.ContentLength)
	}
	rc, err := c.req.GetBody()
	if err != nil {
		t.Fatal(err)
	}
	again, _ := io.ReadAll(rc)
	if string(again) != form {
		t.Fatalf("GetBody replay = %q", again)
	}
}

// TestSignatureCoversBody: a different body gives a different signature.
func TestSignatureCoversBody(t *testing.T) {
	tr, c := newTestTransport(t, "https://aps-workspaces.us-east-1.amazonaws.com/workspaces/ws-1", Options{})
	sign := func(body string) string {
		req, _ := http.NewRequest(http.MethodPost, "https://aps-workspaces.us-east-1.amazonaws.com/workspaces/ws-1/api/v1/query", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if _, err := tr.RoundTrip(req); err != nil {
			t.Fatal(err)
		}
		return c.req.Header.Get("Authorization")
	}
	if sign("query=up") == sign("query=down") {
		t.Fatal("signature does not depend on the body")
	}
}

func TestRegionFromURL(t *testing.T) {
	tests := []struct {
		in, region string
		ok         bool
	}{
		{"https://aps-workspaces.us-east-1.amazonaws.com/workspaces/ws-1", "us-east-1", true},
		{"https://aps-workspaces.eu-central-2.amazonaws.com:443/workspaces/ws-1/", "eu-central-2", true},
		{"https://aps-workspaces.cn-north-1.amazonaws.com.cn/workspaces/ws-1", "cn-north-1", true},
		{"https://aps-workspaces.us-gov-west-1.amazonaws.com/workspaces/ws-1", "us-gov-west-1", true},
		{"http://prometheus.monitoring.svc:9090", "", false},
		{"https://aps-workspaces.us-east-1.amazonaws.com.evil.example/x", "", false},
		{"https://evil.example/aps-workspaces.us-east-1.amazonaws.com", "", false},
		{"https://aps.us-east-1.amazonaws.com", "", false},
		{"::not a url", "", false},
	}
	for _, tc := range tests {
		region, ok := RegionFromURL(tc.in)
		if region != tc.region || ok != tc.ok || IsAMP(tc.in) != tc.ok {
			t.Errorf("RegionFromURL(%q) = %q, %v", tc.in, region, ok)
		}
	}
}

func TestRegionPrecedence(t *testing.T) {
	amp := "https://aps-workspaces.ap-southeast-2.amazonaws.com/workspaces/ws-1"
	tr, _ := newTestTransport(t, amp, Options{Region: "us-west-2"})
	if tr.Region() != "us-west-2" {
		t.Errorf("flag should win, got %s", tr.Region())
	}
	tr, _ = newTestTransport(t, amp, Options{})
	if tr.Region() != "ap-southeast-2" {
		t.Errorf("host region, got %s", tr.Region())
	}
	// Neither a flag nor an AMP host: the SDK's default configuration decides.
	t.Setenv("AWS_REGION", "sa-east-1")
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	t.Setenv("AWS_CONFIG_FILE", "/nonexistent")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent")
	tr, err := New(context.Background(), "https://thanos.example", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if tr.Region() != "sa-east-1" {
		t.Errorf("default config region, got %s", tr.Region())
	}
	if _, ok := tr.creds.(*aws.CredentialsCache); !ok {
		t.Errorf("credentials not cached: %T", tr.creds)
	}
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "")
	if _, err := New(context.Background(), "https://thanos.example", Options{}); err == nil {
		t.Error("no region anywhere should fail")
	}
}

// referenceSign is an independent SigV4 implementation (standard library
// only) for the headers this package signs.
func referenceSign(t *testing.T, r *http.Request, body, akid, secret, region, service string) string {
	t.Helper()
	amzDate := r.Header.Get("X-Amz-Date")
	date := amzDate[:8]
	headers := map[string]string{
		"host":           r.URL.Host,
		"content-length": itoa(len(body)),
		"content-type":   r.Header.Get("Content-Type"),
		"x-amz-date":     amzDate,
	}
	if tok := r.Header.Get("X-Amz-Security-Token"); tok != "" {
		headers["x-amz-security-token"] = tok
	}
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)
	var canon strings.Builder
	for _, k := range names {
		canon.WriteString(k + ":" + strings.TrimSpace(headers[k]) + "\n")
	}
	signed := strings.Join(names, ";")
	payload := sha256.Sum256([]byte(body))
	creq := strings.Join([]string{r.Method, r.URL.EscapedPath(), r.URL.RawQuery, canon.String(), signed, hex.EncodeToString(payload[:])}, "\n")
	scope := date + "/" + region + "/" + service + "/aws4_request"
	creqHash := sha256.Sum256([]byte(creq))
	sts := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(creqHash[:])
	mac := func(key []byte, s string) []byte {
		h := hmac.New(sha256.New, key)
		h.Write([]byte(s))
		return h.Sum(nil)
	}
	k := mac([]byte("AWS4"+secret), date)
	k = mac(k, region)
	k = mac(k, service)
	k = mac(k, "aws4_request")
	return "AWS4-HMAC-SHA256 Credential=" + akid + "/" + scope + ", SignedHeaders=" + signed + ", Signature=" + hex.EncodeToString(mac(k, sts))
}

func itoa(n int) string {
	var b [20]byte
	i := len(b)
	for {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
		if n == 0 {
			return string(b[i:])
		}
	}
}
