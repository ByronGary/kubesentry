// Package awsauth signs HTTP requests with AWS Signature Version 4, so the
// Prometheus client can query Amazon Managed Prometheus (AMP). It is the only
// package besides the CloudWatch reader that imports the AWS SDK.
//
// Credentials come from the SDK's default chain: EKS Pod Identity and IRSA
// (web identity) in a cluster, environment variables and profiles elsewhere.
// The SDK's credentials cache refreshes them before they expire.
package awsauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/config"
)

// ServiceAPS is the signing name of Amazon Managed Prometheus.
const ServiceAPS = "aps"

// ampHost matches AMP workspace endpoints and captures the region:
// aps-workspaces.<region>.amazonaws.com (.com.cn in the China partitions).
var ampHost = regexp.MustCompile(`^aps-workspaces\.([a-z0-9-]+)\.amazonaws\.com(\.cn)?$`)

// IsAMP reports whether rawURL points at an Amazon Managed Prometheus
// workspace, so the caller can switch SigV4 signing on without a flag.
func IsAMP(rawURL string) bool {
	_, ok := RegionFromURL(rawURL)
	return ok
}

// RegionFromURL returns the region in an AMP workspace URL.
func RegionFromURL(rawURL string) (string, bool) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", false
	}
	m := ampHost.FindStringSubmatch(u.Hostname())
	if m == nil {
		return "", false
	}
	return m[1], true
}

// Options configures New.
type Options struct {
	// Region signs for this region (-aws-region). Empty: taken from an AMP
	// host name, then from the SDK's default configuration (AWS_REGION,
	// profile).
	Region string
	// Service is the signing name; default ServiceAPS.
	Service string
	// Base sends the signed request; default http.DefaultTransport.
	Base http.RoundTripper
	// Credentials replaces the SDK's default chain (tests, static keys). It is
	// wrapped in the SDK's credentials cache unless it already is one.
	Credentials aws.CredentialsProvider
	// Now is the signing clock; default time.Now.
	Now func() time.Time
}

// Transport is an http.RoundTripper that signs every request with SigV4.
type Transport struct {
	base    http.RoundTripper
	creds   aws.CredentialsProvider
	signer  *v4.Signer
	region  string
	service string
	now     func() time.Time
}

// New returns a signing transport for requests to endpoint (the Prometheus
// base URL). It resolves the region and, unless opts.Credentials is set, loads
// the SDK's default configuration, which only reads local configuration: no
// request is made until the first signature needs credentials.
func New(ctx context.Context, endpoint string, opts Options) (*Transport, error) {
	region := opts.Region
	if region == "" {
		region, _ = RegionFromURL(endpoint)
	}
	creds := opts.Credentials
	if creds == nil {
		var load []func(*config.LoadOptions) error
		if region != "" {
			load = append(load, config.WithRegion(region))
		}
		cfg, err := config.LoadDefaultConfig(ctx, load...)
		if err != nil {
			return nil, fmt.Errorf("load AWS configuration: %w", err)
		}
		if region == "" {
			region = cfg.Region
		}
		creds = cfg.Credentials
		if creds == nil {
			return nil, errors.New("no AWS credentials provider configured")
		}
	}
	if region == "" {
		return nil, errors.New("AWS region unknown: set -aws-region or AWS_REGION")
	}
	if _, cached := creds.(*aws.CredentialsCache); !cached {
		creds = aws.NewCredentialsCache(creds)
	}
	t := &Transport{
		base:    opts.Base,
		creds:   creds,
		signer:  v4.NewSigner(),
		region:  region,
		service: opts.Service,
		now:     opts.Now,
	}
	if t.base == nil {
		t.base = http.DefaultTransport
	}
	if t.service == "" {
		t.service = ServiceAPS
	}
	if t.now == nil {
		t.now = time.Now
	}
	return t, nil
}

// Region is the region requests are signed for.
func (t *Transport) Region() string { return t.region }

// RoundTrip signs a copy of req and sends it. The body is read once to hash
// it, then replayed from memory, so the signed copy can be re-read (GetBody)
// by redirects and retries. Any Authorization header already set, such as a
// bearer token, is replaced by the signature.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil && req.Body != http.NoBody {
		b, err := io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("read request body for signing: %w", err)
		}
		body = b
	}
	ctx := req.Context()
	r := req.Clone(ctx)
	if body != nil {
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
		r.ContentLength = int64(len(body))
	} else {
		r.Body, r.GetBody, r.ContentLength = nil, nil, 0
	}
	sum := sha256.Sum256(body)

	creds, err := t.creds.Retrieve(ctx)
	if err != nil {
		return nil, fmt.Errorf("AWS credentials: %w", err)
	}
	r.Header.Del("Authorization")
	if err := t.signer.SignHTTP(ctx, creds, r, hex.EncodeToString(sum[:]), t.service, t.region, t.now()); err != nil {
		return nil, fmt.Errorf("sign request: %w", err)
	}
	return t.base.RoundTrip(r)
}
