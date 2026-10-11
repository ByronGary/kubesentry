// Package kube is the only package that imports client-go. It converts
// Kubernetes API objects into the plain types in internal/model.
//
// Two readers share the same conversions: Source lists the cluster per request
// (kept for -cache=false), and Cache serves everything from shared informers.
package kube

import (
	"fmt"
	"net/http"

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
// SubjectAccessReviews their own rate limit.
type Clients struct {
	CS     kubernetes.Interface
	Dyn    dynamic.Interface
	Disc   discovery.DiscoveryInterface
	Config *rest.Config
}

// ConnectWith builds the clients from a kubeconfig. Resolution order: an
// explicit kubeconfig path, then the in-cluster service account, then the
// default loading rules (KUBECONFIG, ~/.kube/config). The typed clientset
// speaks protobuf, which decodes faster and allocates less than JSON for the
// large lists informers fetch; the dynamic client (cert-manager) and
// discovery stay on JSON.
func ConnectWith(kubeconfig string, o ClientOptions) (*Clients, error) {
	o = o.withDefaults()
	cfg, err := loadConfig(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("load kube config: %w", err)
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
	return &Clients{CS: cs, Dyn: dyn, Disc: disc, Config: cfg}, nil
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

func loadConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	if cfg, err := rest.InClusterConfig(); err == nil {
		return cfg, nil
	}
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{}).ClientConfig()
}
