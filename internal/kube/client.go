// Package kube is the only package that imports client-go. It converts
// Kubernetes API objects into the plain types in internal/model.
package kube

import (
	"fmt"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Connect builds a Source from a kubeconfig. Resolution order: an explicit
// kubeconfig path, then the in-cluster service account, then the default
// kubeconfig loading rules (KUBECONFIG, ~/.kube/config).
func Connect(kubeconfig string) (*Source, error) {
	cfg, err := loadConfig(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("load kube config: %w", err)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create clientset: %w", err)
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create dynamic client: %w", err)
	}
	return NewSource(cs, dyn), nil
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
