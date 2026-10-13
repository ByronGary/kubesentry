package awsauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

func newTestTokenSource(t *testing.T, cluster, region string, creds aws.CredentialsProvider) *EKSTokenSource {
	t.Helper()
	if creds == nil {
		creds = suiteCreds
	}
	s, err := NewEKSTokenSource(context.Background(), EKSTokenOptions{
		Cluster: cluster, Region: region, Credentials: creds,
		Now: func() time.Time { return suiteTime },
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// decodeToken checks the token's envelope and returns the presigned URL.
func decodeToken(t *testing.T, tok string) *url.URL {
	t.Helper()
	enc, ok := strings.CutPrefix(tok, EKSTokenPrefix)
	if !ok {
		t.Fatalf("token %q does not start with %s", tok, EKSTokenPrefix)
	}
	if strings.ContainsAny(enc, "+/=") {
		t.Fatalf("token is not unpadded base64url: %q", enc)
	}
	raw, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		t.Fatalf("token payload: %v", err)
	}
	u, err := url.Parse(string(raw))
	if err != nil {
		t.Fatalf("token payload is not a URL: %v", err)
	}
	return u
}

// The token for the SigV4 suite's credentials and time and cluster
// "prod-eks": https://sts.us-east-1.amazonaws.com/?Action=GetCallerIdentity
// &Version=2011-06-15&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=...
// &X-Amz-Date=20150830T123600Z&X-Amz-Expires=60
// &X-Amz-SignedHeaders=host%3Bx-k8s-aws-id&X-Amz-Signature=fce36f9a...
// Any change to it changes what EKS receives; the signature is also checked
// against referencePresign below.
const goldenEKSToken = "k8s-aws-v1." +
	"aHR0cHM6Ly9zdHMudXMtZWFzdC0xLmFtYXpvbmF3cy5jb20vP0FjdGlvbj1HZXRDYWxsZXJJZGVudGl0eSZWZXJzaW9uPTIwMTEtMDYtMTUmWC1BbXotQWxn" +
	"b3JpdGhtPUFXUzQtSE1BQy1TSEEyNTYmWC1BbXotQ3JlZGVudGlhbD1BS0lERVhBTVBMRSUyRjIwMTUwODMwJTJGdXMtZWFzdC0xJTJGc3RzJTJGYXdzNF9y" +
	"ZXF1ZXN0JlgtQW16LURhdGU9MjAxNTA4MzBUMTIzNjAwWiZYLUFtei1FeHBpcmVzPTYwJlgtQW16LVNpZ25lZEhlYWRlcnM9aG9zdCUzQngtazhzLWF3cy1p" +
	"ZCZYLUFtei1TaWduYXR1cmU9ZmNlMzZmOWEyMzdmYjEwOGJiMDkxYzMwZWFiMDQzZTI5NmFiYjMxZGJhNTI5Yzk2MmZlNzM4ZTdhZDk0MTBjOA"

func TestEKSTokenFormat(t *testing.T) {
	s := newTestTokenSource(t, "prod-eks", "us-east-1", nil)
	tok, expiry, err := s.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if want := suiteTime.Add(14 * time.Minute); !expiry.Equal(want) {
		t.Errorf("expiry = %v, want %v (15 minutes, less one)", expiry, want)
	}
	if tok != goldenEKSToken {
		t.Errorf("token changed:\n got %s\nwant %s", tok, goldenEKSToken)
	}

	u := decodeToken(t, tok)
	if u.Scheme != "https" || u.Host != "sts.us-east-1.amazonaws.com" || u.Path != "/" {
		t.Fatalf("presigned URL %s: want https://sts.us-east-1.amazonaws.com/", u)
	}
	q := u.Query()
	for k, want := range map[string]string{
		"Action":              "GetCallerIdentity",
		"Version":             "2011-06-15",
		"X-Amz-Algorithm":     "AWS4-HMAC-SHA256",
		"X-Amz-Credential":    "AKIDEXAMPLE/20150830/us-east-1/sts/aws4_request",
		"X-Amz-Date":          "20150830T123600Z",
		"X-Amz-Expires":       "60",
		"X-Amz-SignedHeaders": "host;x-k8s-aws-id",
	} {
		if got := q.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if q.Has("X-Amz-Security-Token") {
		t.Error("a security token without session credentials")
	}
	want := referencePresign(t, u, "prod-eks", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "us-east-1")
	if got := q.Get("X-Amz-Signature"); got != want {
		t.Errorf("signature = %s, want %s (independent implementation)", got, want)
	}

	// Deterministic: the same inputs give the same token.
	again, _, _ := s.Token(context.Background())
	if again != tok {
		t.Error("the same time and credentials gave another token")
	}
}

// The cluster name is signed: a token for one cluster is refused by another.
func TestEKSTokenNamesTheCluster(t *testing.T) {
	a, _, _ := newTestTokenSource(t, "prod-eks", "us-east-1", nil).Token(context.Background())
	b, _, _ := newTestTokenSource(t, "staging-eks", "us-east-1", nil).Token(context.Background())
	sa, sb := decodeToken(t, a).Query().Get("X-Amz-Signature"), decodeToken(t, b).Query().Get("X-Amz-Signature")
	if sa == sb {
		t.Fatal("the signature does not depend on the cluster")
	}
	ub := decodeToken(t, b)
	if got := referencePresign(t, ub, "staging-eks", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "us-east-1"); got != sb {
		t.Errorf("staging signature = %s, want %s", sb, got)
	}
}

func TestEKSTokenSessionCredentials(t *testing.T) {
	expires := suiteTime.Add(5 * time.Minute)
	creds := aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{
			AccessKeyID: "ASIAEXAMPLE", SecretAccessKey: "secret/with+chars=", SessionToken: "FwoGZXIvYXdzE+/session==",
			CanExpire: true, Expires: expires,
		}, nil
	})
	s := newTestTokenSource(t, "prod-eks", "eu-west-1", creds)
	tok, expiry, err := s.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !expiry.Equal(expires) {
		t.Errorf("expiry = %v, want the credentials' %v", expiry, expires)
	}
	u := decodeToken(t, tok)
	q := u.Query()
	if q.Get("X-Amz-Security-Token") != "FwoGZXIvYXdzE+/session==" {
		t.Errorf("security token = %q", q.Get("X-Amz-Security-Token"))
	}
	if u.Host != "sts.eu-west-1.amazonaws.com" || !strings.Contains(q.Get("X-Amz-Credential"), "/eu-west-1/sts/") {
		t.Errorf("region: host %s, credential %s", u.Host, q.Get("X-Amz-Credential"))
	}
	if got, want := q.Get("X-Amz-Signature"), referencePresign(t, u, "prod-eks", "secret/with+chars=", "eu-west-1"); got != want {
		t.Errorf("signature = %s, want %s", got, want)
	}
}

func TestEKSTokenOptions(t *testing.T) {
	ctx := context.Background()
	for _, name := range []string{"", "-lead", "has space", "dots.not.allowed", strings.Repeat("x", 101)} {
		if _, err := NewEKSTokenSource(ctx, EKSTokenOptions{Cluster: name, Region: "us-east-1", Credentials: suiteCreds}); err == nil {
			t.Errorf("cluster name %q accepted", name)
		}
	}
	s := newTestTokenSource(t, "c_1-x", "cn-north-1", nil)
	tok, _, _ := s.Token(ctx)
	if u := decodeToken(t, tok); u.Host != "sts.cn-north-1.amazonaws.com.cn" {
		t.Errorf("China region host %s", u.Host)
	}
	if s.Cluster() != "c_1-x" || s.Region() != "cn-north-1" {
		t.Errorf("Cluster, Region = %s, %s", s.Cluster(), s.Region())
	}
	failing := aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{}, io.ErrUnexpectedEOF
	})
	if _, _, err := newTestTokenSource(t, "prod", "us-east-1", failing).Token(ctx); err == nil || !strings.Contains(err.Error(), "AWS credentials") {
		t.Errorf("credential failure: %v", err)
	}
}

// A profile (from -kubeconfig's exec env, AWS_PROFILE) picks the region and
// credentials from the shared files.
func TestEKSTokenProfile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, s string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	t.Setenv("AWS_CONFIG_FILE", write("config", "[profile work]\nregion = ap-south-1\n"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", write("credentials", "[work]\naws_access_key_id = AKIDWORK\naws_secret_access_key = s3cret\n"))
	for _, k := range []string{"AWS_REGION", "AWS_DEFAULT_REGION", "AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"} {
		t.Setenv(k, "")
	}
	s, err := NewEKSTokenSource(context.Background(), EKSTokenOptions{Cluster: "prod", Profile: "work"})
	if err != nil {
		t.Fatal(err)
	}
	if s.Region() != "ap-south-1" {
		t.Errorf("region %q, want the profile's", s.Region())
	}
	tok, _, err := s.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cred := decodeToken(t, tok).Query().Get("X-Amz-Credential"); !strings.HasPrefix(cred, "AKIDWORK/") {
		t.Errorf("credential %q, want the profile's key", cred)
	}
}

// eksAPI answers DescribeCluster like the EKS API, recording the request.
type eksAPI struct {
	status  int
	errType string
	body    string
	req     *http.Request
}

func (e *eksAPI) RoundTrip(r *http.Request) (*http.Response, error) {
	e.req = r
	h := http.Header{"Content-Type": {"application/json"}}
	if e.errType != "" {
		h.Set("X-Amzn-ErrorType", e.errType+":http://internal.amazon.com/coral/com.amazonaws.eks/")
	}
	return &http.Response{StatusCode: e.status, Header: h, Body: io.NopCloser(strings.NewReader(e.body)), Request: r}, nil
}

const testCA = "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIBADAKBggqhkjOPQQDAjAAMB4XDTI2MDEwMTAwMDAwMFoX\n-----END CERTIFICATE-----\n"

func TestDescribeEKSCluster(t *testing.T) {
	api := &eksAPI{status: 200, body: `{"cluster":{"name":"prod-eks","arn":"arn:aws:eks:us-west-2:111122223333:cluster/prod-eks",` +
		`"version":"1.33","endpoint":"https://ABCDEF0123.gr7.us-west-2.eks.amazonaws.com","status":"ACTIVE",` +
		`"certificateAuthority":{"data":"` + base64.StdEncoding.EncodeToString([]byte(testCA)) + `"}}}`}
	opts := Options{Region: "us-west-2", Credentials: suiteCreds, Base: api, Now: func() time.Time { return suiteTime }}
	c, err := DescribeEKSCluster(context.Background(), "prod-eks", opts)
	if err != nil {
		t.Fatal(err)
	}
	if c.Endpoint != "https://ABCDEF0123.gr7.us-west-2.eks.amazonaws.com" || string(c.CAData) != testCA || c.Version != "1.33" || c.Status != "ACTIVE" || c.Name != "prod-eks" {
		t.Errorf("cluster = %+v", c)
	}
	if got := api.req.URL.String(); got != "https://eks.us-west-2.amazonaws.com/clusters/prod-eks" {
		t.Errorf("request URL %s", got)
	}
	if api.req.Method != http.MethodGet || !strings.Contains(api.req.Header.Get("Authorization"), "/20150830/us-west-2/eks/aws4_request") {
		t.Errorf("request %s, Authorization %q", api.req.Method, api.req.Header.Get("Authorization"))
	}

	api = &eksAPI{status: 404, errType: "ResourceNotFoundException", body: `{"message":"No cluster found for name: nope."}`}
	opts.Base = api
	_, err = DescribeEKSCluster(context.Background(), "nope", opts)
	if err == nil || !strings.Contains(err.Error(), "HTTP 404 ResourceNotFoundException: No cluster found for name: nope.") {
		t.Errorf("not found: %v", err)
	}

	api = &eksAPI{status: 200, body: `{"cluster":{"name":"new","status":"CREATING"}}`}
	opts.Base = api
	if _, err := DescribeEKSCluster(context.Background(), "new", opts); err == nil || !strings.Contains(err.Error(), "CREATING") {
		t.Errorf("creating cluster: %v", err)
	}
	if _, err := DescribeEKSCluster(context.Background(), "../x", opts); err == nil {
		t.Error("invalid name accepted")
	}
}

// referencePresign computes the SigV4 query signature of an EKS token URL
// independently (standard library only): GET / with the query minus the
// signature, and the signed headers host and x-k8s-aws-id.
func referencePresign(t *testing.T, u *url.URL, cluster, secret, region string) string {
	t.Helper()
	q := u.Query()
	q.Del("X-Amz-Signature")
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var pairs []string
	for _, k := range keys {
		pairs = append(pairs, rfc3986(k)+"="+rfc3986(q.Get(k)))
	}
	amzDate := q.Get("X-Amz-Date")
	date := amzDate[:8]
	payload := sha256.Sum256(nil)
	creq := strings.Join([]string{
		"GET", "/", strings.Join(pairs, "&"),
		"host:" + u.Host + "\nx-k8s-aws-id:" + cluster + "\n",
		"host;x-k8s-aws-id",
		hex.EncodeToString(payload[:]),
	}, "\n")
	scope := date + "/" + region + "/sts/aws4_request"
	creqHash := sha256.Sum256([]byte(creq))
	sts := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(creqHash[:])
	mac := func(key []byte, s string) []byte {
		h := hmac.New(sha256.New, key)
		h.Write([]byte(s))
		return h.Sum(nil)
	}
	k := mac([]byte("AWS4"+secret), date)
	k = mac(k, region)
	k = mac(k, "sts")
	k = mac(k, "aws4_request")
	return hex.EncodeToString(mac(k, sts))
}

// rfc3986 percent-encodes everything but the unreserved characters.
func rfc3986(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
		} else {
			b.WriteString("%" + strings.ToUpper(hex.EncodeToString([]byte{c})))
		}
	}
	return b.String()
}
