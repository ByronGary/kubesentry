// Package kube is the only package that imports client-go. It converts
// Kubernetes API objects into the plain types in internal/model.
//
// Two readers share the same conversions: Source lists the cluster per request
// (kept for -cache=false), and Cache serves everything from shared informers.
package kube

import (
	"errors"
	"fmt"
	"net/http"
	"sync"

	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// ClientOptions tunes the clients ConnectWith builds. Zero values take the
// defaults: QPS 50, Burst 100, UserAgent "kubesentry".
type ClientOptions struct {
	QPS       float32
	Burst     int
	UserAgent string
	// Observe, if set, is told about every API request (for
	// kubesentry_kube_requests_total), including those of NewReviewer.
	Observe RequestObserver

	// Context picks this kubeconfig context instead of the current one
	// (-kube-context). Setting it skips the in-cluster configuration.
	Context string
	// Server, when set, is the API server URL to use instead of any
	// kubeconfig, with CAData (PEM) to verify it: the endpoint and CA of an
	// EKS cluster from DescribeCluster. It needs TokenSource.
	Server string
	CAData []byte
	// TokenSource, if set, authenticates every request with the bearer token
	// it returns, replacing the kubeconfig's credentials (tokens, client
	// certificates, exec and auth provider plugins). This is how kubesentry
	// signs in to EKS by itself (-eks-cluster), without the AWS CLI.
	TokenSource TokenSource
	// ExecFallback, if set, is asked for a TokenSource when the kubeconfig's
	// credentials come from an EKS exec plugin ("aws eks get-token" or
	// "aws-iam-authenticator token") whose command is not installed, as in a
	// container without the AWS CLI. Without it the plugin is kept, and
	// requests fail as kubectl's would.
	ExecFallback func(EKSExec) (TokenSource, error)
}

// Defaults for ClientOptions.
const (
	DefaultQPS       = 50
	DefaultBurst     = 100
	DefaultUserAgent = "kubesentry"
)

func (o ClientOptions) withDefaults() ClientOptions {
	if o.QPS <= 0 {
		o.QPS = DefaultQPS
	}
	if o.Burst <= 0 {
		o.Burst = DefaultBurst
	}
	if o.UserAgent == "" {
		o.UserAgent = DefaultUserAgent
	}
	return o
}

// Clients bundles the clients kubesentry uses. Config is the rest.Config they
// were built from (nil for fakes in tests); NewReviewer copies it to give
// SubjectAccessReviews their own rate limit. InCluster is true when Config
// came from the pod's service account.
type Clients struct {
	CS        kubernetes.Interface
	Dyn       dynamic.Interface
	Disc      discovery.DiscoveryInterface
	Config    *rest.Config
	InCluster bool

	proxyOnce sync.Once
	proxyRT   http.RoundTripper
	proxyErr  error
}

// ConnectWith builds the clients. The configuration comes from, in order:
// o.Server (with o.TokenSource); the kubeconfig at the explicit path or with
// o.Context; the in-cluster service account; the default loading rules
// (KUBECONFIG, ~/.kube/config). The typed clientset speaks protobuf, which
// decodes faster and allocates less than JSON for the large lists informers
// fetch; the dynamic client (cert-manager) and discovery stay on JSON.
func ConnectWith(kubeconfig string, o ClientOptions) (*Clients, error) {
	o = o.withDefaults()
	cfg, inCluster, err := loadConfig(kubeconfig, o)
	if err != nil {
		return nil, fmt.Errorf("load kube config: %w", err)
	}
	if err := applyCredentials(cfg, o); err != nil {
		return nil, err
	}
	cfg.QPS, cfg.Burst, cfg.UserAgent = o.QPS, o.Burst, o.UserAgent
	if o.Observe != nil {
		cfg.Wrap(func(rt http.RoundTripper) http.RoundTripper { return observingTransport{next: rt, observe: o.Observe} })
	}

	typed := rest.CopyConfig(cfg)
	typed.ContentType = "application/vnd.kubernetes.protobuf"
	typed.AcceptContentTypes = "application/vnd.kubernetes.protobuf,application/json"
	cs, err := kubernetes.NewForConfig(typed)
	if err != nil {
		return nil, fmt.Errorf("create clientset: %w", err)
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create dynamic client: %w", err)
	}
	disc, err := discovery.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create discovery client: %w", err)
	}
	return &Clients{CS: cs, Dyn: dyn, Disc: disc, Config: cfg, InCluster: inCluster}, nil
}

// Connect builds a per-request Source from a kubeconfig, resolved as in
// ConnectWith with default client options.
func Connect(kubeconfig string) (*Source, error) {
	c, err := ConnectWith(kubeconfig, ClientOptions{})
	if err != nil {
		return nil, err
	}
	return NewSource(c.CS, c.Dyn), nil
}

// loadConfig resolves the rest.Config as ConnectWith documents, and reports
// whether it is the in-cluster one.
func loadConfig(kubeconfig string, o ClientOptions) (*rest.Config, bool, error) {
	if o.Server != "" {
		if o.TokenSource == nil {
			return nil, false, errors.New("an API server address without a kubeconfig needs a token source")
		}
		return &rest.Config{Host: o.Server, TLSClientConfig: rest.TLSClientConfig{CAData: o.CAData}}, false, nil
	}
	if kubeconfig == "" && o.Context == "" {
		if cfg, err := rest.InClusterConfig(); err == nil {
			return cfg, true, nil
		}
	}
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		rules = &clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfig}
	}
	overrides := &clientcmd.ConfigOverrides{CurrentContext: o.Context}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides).ClientConfig()
	return cfg, false, err
}
