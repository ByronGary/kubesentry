package main

// Remote mode: kubesentry running outside the cluster, on a laptop or on
// EC2/ECS. It picks a kubeconfig context, signs in to EKS by itself when the
// AWS CLI is missing, and reaches the in-cluster Prometheus through the API
// server's service proxy, so nothing has to be exposed.

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"

	"github.com/ByronGary/kubesentry/internal/awsauth"
	"github.com/ByronGary/kubesentry/internal/kube"
	"github.com/ByronGary/kubesentry/internal/metrics"
)

// remoteConfig is the flags for running outside the cluster.
type remoteConfig struct {
	kubeContext      string
	eksCluster       string
	promViaAPIServer autoBool
}

func (r *remoteConfig) register(fs *flag.FlagSet) {
	fs.StringVar(&r.kubeContext, "kube-context", "", "kubeconfig context to use instead of the current one")
	fs.StringVar(&r.eksCluster, "eks-cluster", "", "EKS cluster name: sign in with a token kubesentry mints from AWS credentials (no AWS CLI needed; region from -aws-region). "+
		"Without -kubeconfig or -kube-context the endpoint and CA come from eks:DescribeCluster. Also the default -cluster-name")
	fs.Var(&r.promViaAPIServer, "prometheus-via-apiserver", "reach discovered Prometheus Services and -prometheus-service through the API server's service proxy: "+
		"auto (when running outside the cluster), true or false")
}

// viaAPIServer reports whether Prometheus Services are reached through the
// API server's proxy.
func (r *remoteConfig) viaAPIServer(inCluster bool) bool {
	if r.promViaAPIServer.auto() {
		return !inCluster
	}
	return r.promViaAPIServer.on()
}

// autoBool is a flag that is auto (the default), true or false. Given alone
// (-prometheus-via-apiserver) it means true.
type autoBool string

func (a *autoBool) String() string {
	if a == nil || *a == "" {
		return "auto"
	}
	return string(*a)
}

func (a *autoBool) Set(s string) error {
	if s == "auto" {
		*a = ""
		return nil
	}
	b, err := strconv.ParseBool(s)
	if err != nil {
		return fmt.Errorf("want auto, true or false, got %q", s)
	}
	*a = autoBool(strconv.FormatBool(b))
	return nil
}

func (a *autoBool) IsBoolFlag() bool { return true }
func (a autoBool) auto() bool        { return a == "" }
func (a autoBool) on() bool          { return a == "true" }

// connectKube builds the Kubernetes clients: in the cluster, from a
// kubeconfig (-kubeconfig, -kube-context), or for -eks-cluster with
// kubesentry's own EKS token. When the kubeconfig signs in through an EKS
// exec plugin that is not installed (a container without the AWS CLI), the
// token is minted the same way.
func connectKube(ctx context.Context, cfg *config) (*kube.Clients, error) {
	o := kube.ClientOptions{
		QPS: float32(cfg.kubeQPS), Burst: cfg.kubeBurst, UserAgent: "kubesentry/" + version,
		Observe: func(verb, resource, code string) { metrics.KubeRequests.With(verb, resource, code).Inc() },
		Context: cfg.remote.kubeContext,
	}
	if name := cfg.remote.eksCluster; name != "" {
		src, err := awsauth.NewEKSTokenSource(ctx, awsauth.EKSTokenOptions{Cluster: name, Region: cfg.awsRegion})
		if err != nil {
			return nil, fmt.Errorf("-eks-cluster: %w", err)
		}
		o.TokenSource = src.Token
		if cfg.kubeconfig == "" && cfg.remote.kubeContext == "" {
			c, err := awsauth.DescribeEKSCluster(ctx, name, awsauth.Options{Region: src.Region()})
			if err != nil {
				return nil, fmt.Errorf("-eks-cluster: %w (give -kubeconfig or -kube-context to take the endpoint and CA from a kubeconfig instead)", err)
			}
			o.Server, o.CAData = c.Endpoint, c.CAData
			slog.Info("EKS cluster", "name", name, "endpoint", c.Endpoint, "version", c.Version, "status", c.Status)
		}
		slog.Info("signing in to EKS with kubesentry's own token", "cluster", name, "region", src.Region())
	} else {
		o.ExecFallback = func(e kube.EKSExec) (kube.TokenSource, error) {
			if e.RoleARN != "" {
				return nil, fmt.Errorf("the plugin assumes role %s, which kubesentry's token does not: use an AWS profile that assumes it (AWS_PROFILE) with -eks-cluster", e.RoleARN)
			}
			region := e.Region
			if region == "" {
				region = cfg.awsRegion
			}
			src, err := awsauth.NewEKSTokenSource(ctx, awsauth.EKSTokenOptions{Cluster: e.Cluster, Region: region, Profile: e.Profile})
			if err != nil {
				return nil, err
			}
			slog.Warn("the kubeconfig's credential plugin is not installed; kubesentry mints the EKS token itself",
				"command", e.Command, "cluster", e.Cluster, "region", src.Region(), "profile", e.Profile)
			return src.Token, nil
		}
	}
	clients, err := kube.ConnectWith(cfg.kubeconfig, o)
	if err != nil {
		return nil, err
	}
	if clients.InCluster {
		slog.Info("kubernetes", "api", clients.Config.Host, "running", "in cluster")
	} else {
		slog.Info("kubernetes", "api", clients.Config.Host, "running", "outside the cluster", "context", cfg.remote.kubeContext)
	}
	return clients, nil
}

// promDiscovery returns how discovery lists Prometheus candidates, and the
// transport they are reached through: nil for in-cluster Service URLs, or the
// API server's own transport for service proxy URLs
// (https://<apiserver>/api/v1/namespaces/<ns>/services/<name>:<port>/proxy),
// when running outside the cluster or with -prometheus-via-apiserver.
func (c *config) promDiscovery(clients *kube.Clients) (func(context.Context) ([]string, error), http.RoundTripper, error) {
	if !c.remote.viaAPIServer(clients.InCluster) {
		return func(ctx context.Context) ([]string, error) {
			return kube.DiscoverPrometheus(ctx, clients.CS, c.promService)
		}, nil, nil
	}
	rt, err := clients.ProxyTransport()
	if err != nil {
		return nil, nil, fmt.Errorf("API server proxy for Prometheus: %w", err)
	}
	if c.promURL == "" {
		var pinned []any
		if c.promService != "" {
			pinned = []any{"service", c.promService}
		}
		slog.Info("prometheus discovery goes through the API server's service proxy (needs get and create on services/proxy)", pinned...)
		if os.Getenv("PROMETHEUS_TOKEN") != "" {
			slog.Warn("PROMETHEUS_TOKEN is not sent through the API server's proxy: the API server takes the Authorization header as the caller's credentials")
		}
	}
	return func(ctx context.Context) ([]string, error) {
		svcs, err := kube.DiscoverPrometheusServices(ctx, clients.CS, c.promService)
		urls := make([]string, 0, len(svcs))
		for _, s := range svcs {
			u, uerr := clients.ServiceProxyURL(s.Namespace, s.Name, strconv.Itoa(int(s.Port)))
			if uerr != nil {
				err = errors.Join(err, uerr)
				continue
			}
			urls = append(urls, u)
		}
		return urls, err
	}, rt, nil
}
