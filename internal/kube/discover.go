package kube

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
)

// Labels that mark a Prometheus Service: kube-prometheus-stack's operator
// Service and the generic app.kubernetes.io/name used by most charts.
var prometheusLabels = []struct{ key, value string }{
	{"app", "kube-prometheus-stack-prometheus"},
	{"app.kubernetes.io/name", "prometheus"},
}

// prometheusPortNames are preferred in this order; then port 9090, then 80.
var prometheusPortNames = []string{"http-web", "web", "http"}

// PrometheusService is a candidate Prometheus: a Service and its web port.
type PrometheusService struct {
	Namespace, Name string
	Port            int32
}

// URL is the in-cluster base URL, http://name.namespace.svc:port.
func (s PrometheusService) URL() string { return serviceURL(s.Namespace, s.Name, s.Port) }

// DiscoverPrometheus returns candidate in-cluster Prometheus base URLs, best
// first, in the form http://name.namespace.svc:port, for the Services
// DiscoverPrometheusServices finds.
func DiscoverPrometheus(ctx context.Context, cs kubernetes.Interface, pin string) ([]string, error) {
	svcs, err := DiscoverPrometheusServices(ctx, cs, pin)
	var out []string
	for _, s := range svcs {
		out = append(out, s.URL())
	}
	return out, err
}

// DiscoverPrometheusServices returns candidate Prometheus Services, best
// first:
//
//  1. pin ("namespace/name:port", from -prometheus-service), when given;
//  2. Services annotated kubesentry.io/prometheus=true;
//  3. Services labelled app=kube-prometheus-stack-prometheus or
//     app.kubernetes.io/name=prometheus that have a port named http-web, web
//     or http, or port 9090 or 80.
//
// Within each group, Services with a cluster IP come before headless ones,
// then by namespace and name. When listing Services fails, the pin is
// still returned with the error. The caller verifies the candidates.
func DiscoverPrometheusServices(ctx context.Context, cs kubernetes.Interface, pin string) ([]PrometheusService, error) {
	var out []PrometheusService
	seen := map[PrometheusService]bool{}
	add := func(s PrometheusService) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	if pin != "" {
		s, err := pinnedPrometheus(ctx, cs, pin)
		if err != nil {
			return nil, err
		}
		add(s)
	}

	type candidate struct {
		tier     int
		headless bool
		ns, name string
		port     int32
	}
	var cands []candidate
	err := paginate("services", func(o metav1.ListOptions) (string, error) {
		l, err := cs.CoreV1().Services(metav1.NamespaceAll).List(ctx, o)
		if err != nil {
			return "", err
		}
		for i := range l.Items {
			s := &l.Items[i]
			if s.Spec.Type == corev1.ServiceTypeExternalName {
				continue
			}
			annotated := strings.EqualFold(s.Annotations[PrometheusAnnotation], "true")
			labelled := false
			for _, l := range prometheusLabels {
				if s.Labels[l.key] == l.value {
					labelled = true
				}
			}
			if !annotated && !labelled {
				continue
			}
			port, ok := prometheusPort(s.Spec.Ports)
			if !ok && annotated && len(s.Spec.Ports) > 0 {
				// An explicit annotation wins even on an unusual port.
				port, ok = s.Spec.Ports[0].Port, true
			}
			if !ok {
				continue
			}
			tier := 2
			if annotated {
				tier = 1
			}
			cands = append(cands, candidate{tier: tier, headless: s.Spec.ClusterIP == corev1.ClusterIPNone, ns: s.Namespace, name: s.Name, port: port})
		}
		return l.Continue, nil
	})
	if err != nil {
		return out, err
	}
	sort.Slice(cands, func(i, j int) bool {
		a, b := cands[i], cands[j]
		if a.tier != b.tier {
			return a.tier < b.tier
		}
		if a.headless != b.headless {
			return !a.headless
		}
		if a.ns != b.ns {
			return a.ns < b.ns
		}
		return a.name < b.name
	})
	for _, c := range cands {
		add(PrometheusService{Namespace: c.ns, Name: c.name, Port: c.port})
	}
	return out, nil
}

// prometheusPort picks the web port by name, then 9090, then 80.
func prometheusPort(ports []corev1.ServicePort) (int32, bool) {
	for _, name := range prometheusPortNames {
		for _, p := range ports {
			if p.Name == name {
				return p.Port, true
			}
		}
	}
	for _, want := range []int32{9090, 80} {
		for _, p := range ports {
			if p.Port == want {
				return p.Port, true
			}
		}
	}
	return 0, false
}

func serviceURL(ns, name string, port int32) string {
	return fmt.Sprintf("http://%s.%s.svc:%d", name, ns, port)
}

// pinnedPrometheus parses "namespace/name:port". The port may be a number or
// the name of a Service port, which is looked up.
func pinnedPrometheus(ctx context.Context, cs kubernetes.Interface, pin string) (PrometheusService, error) {
	ns, rest, ok := strings.Cut(pin, "/")
	name, port, ok2 := strings.Cut(rest, ":")
	if !ok || !ok2 || port == "" {
		return PrometheusService{}, fmt.Errorf("prometheus service %q: want namespace/name:port", pin)
	}
	for _, part := range []string{ns, name} {
		if errs := validation.IsDNS1123Label(part); len(errs) > 0 {
			return PrometheusService{}, fmt.Errorf("prometheus service %q: %q: %s", pin, part, strings.Join(errs, "; "))
		}
	}
	if n, err := strconv.ParseUint(port, 10, 16); err == nil && n > 0 {
		return PrometheusService{Namespace: ns, Name: name, Port: int32(n)}, nil
	}
	if errs := validation.IsValidPortName(port); len(errs) > 0 {
		return PrometheusService{}, fmt.Errorf("prometheus service %q: port %q: %s", pin, port, strings.Join(errs, "; "))
	}
	s, err := cs.CoreV1().Services(ns).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return PrometheusService{}, fmt.Errorf("prometheus service %s/%s not found", ns, name)
	}
	if err != nil {
		return PrometheusService{}, fmt.Errorf("get prometheus service: %w", err)
	}
	for _, p := range s.Spec.Ports {
		if p.Name == port {
			return PrometheusService{Namespace: ns, Name: name, Port: p.Port}, nil
		}
	}
	return PrometheusService{}, fmt.Errorf("prometheus service %s/%s has no port named %q", ns, name, port)
}
