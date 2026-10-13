package awsauth

// EKS sign-in without the AWS CLI. The bearer token EKS accepts is a
// presigned STS GetCallerIdentity URL: the API server's authenticator (AWS
// IAM Authenticator) sends that request to STS and learns the caller's IAM
// identity from the answer. The x-k8s-aws-id header, signed into the URL,
// names the cluster, so a token for one cluster is refused by another. This
// is what `aws eks get-token` and aws-iam-authenticator print.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

const (
	// EKSTokenPrefix starts every EKS bearer token; the rest is the
	// presigned URL, base64url-encoded without padding.
	EKSTokenPrefix = "k8s-aws-v1."
	// EKSTokenLifetime is how long a token is reported valid. EKS accepts it
	// for 15 minutes after it was signed; like `aws eks get-token`, kubesentry
	// counts a minute less, and replaces it a minute before that.
	EKSTokenLifetime = 14 * time.Minute

	eksClusterHeader = "x-k8s-aws-id"
	// presignExpires is the X-Amz-Expires of the token's URL, as
	// aws-iam-authenticator sets it; EKS judges the signing time itself.
	presignExpires = "60"
	// emptyPayloadHash is the SHA-256 of an empty body.
	emptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	// ServiceEKS is the signing name of the EKS API.
	ServiceEKS = "eks"
)

// eksClusterName is what EKS allows as a cluster name.
var eksClusterName = regexp.MustCompile(`^[0-9A-Za-z][A-Za-z0-9_-]{0,99}$`)

// EKSTokenOptions configures NewEKSTokenSource.
type EKSTokenOptions struct {
	// Cluster is the EKS cluster name (-eks-cluster).
	Cluster string
	// Region is the STS region to sign for, normally the cluster's
	// (-aws-region). Empty: the SDK's default configuration.
	Region string
	// Profile selects a shared configuration profile; empty uses AWS_PROFILE
	// or the default profile.
	Profile string
	// Credentials replaces the SDK's default chain (tests, static keys).
	Credentials aws.CredentialsProvider
	// Now is the signing clock; default time.Now.
	Now func() time.Time
}

// EKSTokenSource mints EKS bearer tokens from AWS credentials.
type EKSTokenSource struct {
	cluster, region string
	creds           aws.CredentialsProvider
	signer          *v4.Signer
	now             func() time.Time
}

// NewEKSTokenSource resolves the region and credentials. Like New, it only
// reads local configuration: credentials are fetched by the first Token.
func NewEKSTokenSource(ctx context.Context, o EKSTokenOptions) (*EKSTokenSource, error) {
	if !eksClusterName.MatchString(o.Cluster) {
		return nil, fmt.Errorf("EKS cluster name %q: want 1 to 100 letters, digits, hyphens and underscores, starting with a letter or digit", o.Cluster)
	}
	creds, region, err := resolve(ctx, o.Region, o.Profile, o.Credentials)
	if err != nil {
		return nil, err
	}
	s := &EKSTokenSource{cluster: o.Cluster, region: region, creds: creds, signer: v4.NewSigner(), now: o.Now}
	if s.now == nil {
		s.now = time.Now
	}
	return s, nil
}

// Cluster is the cluster the tokens are for.
func (s *EKSTokenSource) Cluster() string { return s.cluster }

// Region is the STS region the tokens are signed for.
func (s *EKSTokenSource) Region() string { return s.region }

// Token returns a new token and when to stop using it: EKSTokenLifetime
// after signing, or when the credentials it was signed with expire, if
// sooner. Each call signs afresh; the caller caches.
func (s *EKSTokenSource) Token(ctx context.Context) (string, time.Time, error) {
	creds, err := s.creds.Retrieve(ctx)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("AWS credentials: %w", err)
	}
	now := s.now().UTC()
	q := url.Values{"Action": {"GetCallerIdentity"}, "Version": {"2011-06-15"}, "X-Amz-Expires": {presignExpires}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+stsHost(s.region)+"/?"+q.Encode(), nil)
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set(eksClusterHeader, s.cluster)
	signed, _, err := s.signer.PresignHTTP(ctx, creds, req, emptyPayloadHash, "sts", s.region, now)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("presign GetCallerIdentity: %w", err)
	}
	expiry := now.Add(EKSTokenLifetime)
	if creds.CanExpire && !creds.Expires.IsZero() && creds.Expires.Before(expiry) {
		expiry = creds.Expires
	}
	return EKSTokenPrefix + base64.RawURLEncoding.EncodeToString([]byte(signed)), expiry, nil
}

// stsHost is the regional STS endpoint, which EKS accepts in tokens.
func stsHost(region string) string {
	return "sts." + region + "." + dnsSuffix(region)
}

// eksHost is the regional EKS API endpoint.
func eksHost(region string) string {
	return "eks." + region + "." + dnsSuffix(region)
}

func dnsSuffix(region string) string {
	if strings.HasPrefix(region, "cn-") {
		return "amazonaws.com.cn"
	}
	return "amazonaws.com"
}

// EKSCluster is what kubesentry needs from DescribeCluster to reach a
// cluster's API server.
type EKSCluster struct {
	Name, Endpoint, Version, Status string
	// CAData is the cluster CA certificate (PEM).
	CAData []byte
}

// eksMaxResponse caps a DescribeCluster answer.
const eksMaxResponse = 1 << 20

// DescribeEKSCluster calls the EKS DescribeCluster API (GET /clusters/<name>,
// IAM eks:DescribeCluster) for the API server endpoint and CA. It is a single
// SigV4-signed request, so kubesentry needs no EKS SDK module for it.
// opts.Service is ignored; opts.Base, when set, sends the request.
func DescribeEKSCluster(ctx context.Context, name string, opts Options) (EKSCluster, error) {
	if !eksClusterName.MatchString(name) {
		return EKSCluster{}, fmt.Errorf("EKS cluster name %q: want 1 to 100 letters, digits, hyphens and underscores, starting with a letter or digit", name)
	}
	opts.Service = ServiceEKS
	t, err := New(ctx, "", opts)
	if err != nil {
		return EKSCluster{}, err
	}
	u := "https://" + eksHost(t.Region()) + "/clusters/" + url.PathEscape(name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return EKSCluster{}, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := (&http.Client{Transport: t, Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return EKSCluster{}, fmt.Errorf("EKS DescribeCluster %s: %w", name, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, eksMaxResponse))
	if err != nil {
		return EKSCluster{}, fmt.Errorf("EKS DescribeCluster %s: read answer: %w", name, err)
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(body, &e)
		kind, _, _ := strings.Cut(resp.Header.Get("X-Amzn-Errortype"), ":")
		return EKSCluster{}, fmt.Errorf("EKS DescribeCluster %s in %s: HTTP %d %s: %s", name, t.Region(), resp.StatusCode, kind, e.Message)
	}
	var out struct {
		Cluster struct {
			Name                 string `json:"name"`
			Endpoint             string `json:"endpoint"`
			Version              string `json:"version"`
			Status               string `json:"status"`
			CertificateAuthority struct {
				Data string `json:"data"`
			} `json:"certificateAuthority"`
		} `json:"cluster"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return EKSCluster{}, fmt.Errorf("EKS DescribeCluster %s: %w", name, err)
	}
	c := out.Cluster
	if c.Endpoint == "" || c.CertificateAuthority.Data == "" {
		return EKSCluster{}, fmt.Errorf("EKS cluster %s (status %s) has no endpoint or CA yet", name, c.Status)
	}
	ca, err := base64.StdEncoding.DecodeString(c.CertificateAuthority.Data)
	if err != nil {
		return EKSCluster{}, fmt.Errorf("EKS cluster %s: certificate authority: %w", name, err)
	}
	if !strings.Contains(string(ca), "-----BEGIN CERTIFICATE-----") {
		return EKSCluster{}, errors.New("EKS cluster " + name + ": certificate authority is not PEM")
	}
	return EKSCluster{Name: c.Name, Endpoint: c.Endpoint, Version: c.Version, Status: c.Status, CAData: ca}, nil
}
