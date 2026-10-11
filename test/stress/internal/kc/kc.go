// Package kc builds Kubernetes clients for the stress harness. It runs both
// in-cluster (as a Job on the load-generator node) and from the host with a
// kubeconfig, and it is generous with QPS because the generator creates tens of
// thousands of objects.
package kc

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// StressLabel marks every object the harness creates so it can be deleted.
const (
	StressLabel = "kubesentry.io/stress"
	// LoadLabel marks load-generator Jobs and Deployments; the guard deletes them.
	LoadLabel = "kubesentry.io/stress-load"
)

// Flags are the connection flags every subcommand shares.
type Flags struct {
	Kubeconfig string
	Context    string
	QPS        float64
	Burst      int
}

// Register adds the connection flags to fs.
func (f *Flags) Register(fs *flag.FlagSet, qps float64, burst int) {
	fs.StringVar(&f.Kubeconfig, "kubeconfig", "", "kubeconfig path (default: in-cluster, then $KUBECONFIG, then ~/.kube/config)")
	fs.StringVar(&f.Context, "context", "kind-kubesentry", "kubeconfig context (ignored in-cluster)")
	fs.Float64Var(&f.QPS, "qps", qps, "client-go QPS")
	fs.IntVar(&f.Burst, "burst", burst, "client-go burst")
}

// Clients bundles the typed and dynamic clients.
type Clients struct {
	Config *rest.Config
	CS     kubernetes.Interface
	Dyn    dynamic.Interface
}

// Connect returns clients for the configured cluster.
func (f *Flags) Connect() (*Clients, error) {
	cfg, err := f.config()
	if err != nil {
		return nil, err
	}
	// Pod Security "would violate" warnings for every generated workload are noise here.
	rest.SetDefaultWarningHandler(rest.NoWarnings{})
	cfg.QPS = float32(f.QPS)
	cfg.Burst = f.Burst
	cfg.UserAgent = "kubesentry-stress"
	cfg.Timeout = 5 * time.Minute
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &Clients{Config: cfg, CS: cs, Dyn: dyn}, nil
}

func (f *Flags) config() (*rest.Config, error) {
	if f.Kubeconfig == "" {
		if cfg, err := rest.InClusterConfig(); err == nil {
			return cfg, nil
		}
	}
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if f.Kubeconfig != "" {
		rules.ExplicitPath = f.Kubeconfig
	}
	over := &clientcmd.ConfigOverrides{CurrentContext: f.Context}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, over).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("kubeconfig: %w", err)
	}
	return cfg, nil
}

// InCluster reports whether the process runs in a pod.
func InCluster() bool {
	_, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token")
	return err == nil && os.Getenv("KUBERNETES_SERVICE_HOST") != ""
}

// Labels returns the stress label set plus extra pairs.
func Labels(kv ...string) map[string]string {
	m := map[string]string{StressLabel: "true"}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return m
}

// StressSelector selects everything the harness created.
var StressSelector = metav1.ListOptions{LabelSelector: StressLabel + "=true"}

// Secret reads one key of a Secret.
func Secret(ctx context.Context, cs kubernetes.Interface, ns, name, key string) (string, error) {
	s, err := cs.CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	v, ok := s.Data[key]
	if !ok {
		return "", fmt.Errorf("secret %s/%s has no key %q", ns, name, key)
	}
	return string(v), nil
}
