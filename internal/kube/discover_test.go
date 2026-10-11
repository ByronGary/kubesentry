package kube

import (
	"context"
	"reflect"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func promService(ns, name string, labels, annotations map[string]string, headless bool, ports ...corev1.ServicePort) *corev1.Service {
	s := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: labels, Annotations: annotations},
		Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP, ClusterIP: "10.96.0.1", Ports: ports},
	}
	if headless {
		s.Spec.ClusterIP = corev1.ClusterIPNone
	}
	return s
}

func port(name string, n int32) corev1.ServicePort { return corev1.ServicePort{Name: name, Port: n} }

func TestDiscoverPrometheusRanking(t *testing.T) {
	kps := map[string]string{"app": "kube-prometheus-stack-prometheus"}
	generic := map[string]string{"app.kubernetes.io/name": "prometheus"}
	cs := fake.NewClientset(
		promService("monitoring", "kps-prometheus", kps, nil, false, port("http-web", 9090), port("reloader-web", 8080)),
		promService("monitoring", "prometheus-operated", generic, nil, true, port("web", 9090)),
		promService("abc", "prom-server", generic, nil, false, port("service", 80)),
		promService("obs", "custom", nil, map[string]string{PrometheusAnnotation: "true"}, false, port("api", 8080)),
		promService("x", "node-exporter", map[string]string{"app.kubernetes.io/name": "prometheus-node-exporter"}, nil, false, port("http", 9100)),
		promService("y", "prom-metrics-only", generic, nil, false, port("metrics", 9100)),
		promService("z", "not-annotated", nil, map[string]string{PrometheusAnnotation: "false"}, false, port("web", 9090)),
	)
	ctx := context.Background()

	got, err := DiscoverPrometheus(ctx, cs, "")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"http://custom.obs.svc:8080",                     // annotated, first port
		"http://prom-server.abc.svc:80",                  // labelled, port 80
		"http://kps-prometheus.monitoring.svc:9090",      // labelled, named http-web
		"http://prometheus-operated.monitoring.svc:9090", // headless last
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ranking:\n got %v\nwant %v", got, want)
	}

	// A pin goes first; a named port is resolved; duplicates collapse.
	got, err = DiscoverPrometheus(ctx, cs, "monitoring/kps-prometheus:http-web")
	if err != nil {
		t.Fatal(err)
	}
	if want := append([]string{"http://kps-prometheus.monitoring.svc:9090"}, want[0], want[1], want[3]); !reflect.DeepEqual(got, want) {
		t.Errorf("pinned:\n got %v\nwant %v", got, want)
	}
	got, err = DiscoverPrometheus(ctx, cs, "other/prom:9091")
	if err != nil || got[0] != "http://prom.other.svc:9091" || len(got) != 5 {
		t.Errorf("numeric pin: %v, %v", got, err)
	}

	for _, bad := range []string{"no-slash", "ns/name", "ns/name:", "Bad_NS/prom:9090", "ns/prom:99999x", "monitoring/missing:web", "monitoring/kps-prometheus:nope"} {
		if _, err := DiscoverPrometheus(ctx, cs, bad); err == nil {
			t.Errorf("pin %q should fail", bad)
		}
	}
}
