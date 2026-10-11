package demo

import (
	"context"
	"fmt"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
)

// workload builds a Deployment, StatefulSet or DaemonSet whose pods carry
// app=<name>, fully rolled out with ready of desired replicas ready.
func workload(kind, ns, name string, desired, ready int32, created time.Time, images ...string) model.Workload {
	return model.Workload{
		Kind: kind, Namespace: ns, Name: name, Created: created, Images: images,
		Selector: &model.LabelSelector{MatchLabels: map[string]string{"app": name}},
		Desired:  desired, Ready: ready, Updated: desired, Available: ready,
		Conditions: []model.Condition{{Type: "Progressing", Status: "True", Reason: "NewReplicaSetAvailable"}},
	}
}

// job builds a Job whose pods carry job-name=<name>.
func job(ns, name string, created time.Time, image string, active, succeeded, failed int32, conds ...model.Condition) model.Workload {
	return model.Workload{
		Kind: "Job", Namespace: ns, Name: name, Created: created, Images: []string{image},
		Selector: &model.LabelSelector{MatchLabels: map[string]string{"job-name": name}},
		Desired:  1, Active: active, Succeeded: succeeded, Failed: failed, Conditions: conds,
	}
}

func service(ns, name, typ string, selector map[string]string, ports ...model.ServicePort) model.Service {
	return model.Service{Namespace: ns, Name: name, Type: typ, Selector: selector, Ports: ports}
}

func port(p int32, target string) model.ServicePort {
	return model.ServicePort{Protocol: "TCP", Port: p, TargetPort: target}
}

func node(name string, created time.Time, conds ...model.Condition) model.Node {
	return model.Node{
		Name: name, Ready: true, KubeletVersion: "v1.31.4-eks-aeac579", OSImage: "Amazon Linux 2023.6.20250115",
		ContainerRuntime: "containerd://1.7.25", CPUAllocatableMilli: 3920, MemoryAllocatableBytes: 15*gib + 400<<20,
		PodsAllocatable: 58, Created: created, Roles: []string{},
		Conditions: append([]model.Condition{
			{Type: "Ready", Status: "True", Reason: "KubeletReady", Message: "kubelet is posting ready status"},
		}, conds...),
	}
}

func role(kind, ns, name string, rules ...model.PolicyRule) model.Role {
	return model.Role{Kind: kind, Namespace: ns, Name: name, Rules: rules}
}

func rule(groups, resources, verbs []string) model.PolicyRule {
	return model.PolicyRule{APIGroups: groups, Resources: resources, Verbs: verbs}
}

func binding(ns, name, roleKind, roleName string, subjects ...model.Subject) model.RoleBinding {
	kind := "ClusterRoleBinding"
	if ns != "" {
		kind = "RoleBinding"
	}
	return model.RoleBinding{Kind: kind, Namespace: ns, Name: name, RoleKind: roleKind, RoleName: roleName, Subjects: subjects}
}

func psa(enforce string) map[string]string {
	return map[string]string{"pod-security.kubernetes.io/enforce": enforce}
}

// addInventory fills in everything behind the Map, Workloads, Storage,
// Security and Certificates pages, consistent with the pods and PVCs.
func (c *Cluster) addInventory(now time.Time) {
	at := func(d time.Duration) time.Time { return now.Add(-d) }
	h := time.Hour
	all := []string{"*"}
	read := []string{"get", "list", "watch"}

	checkoutAPI := workload("Deployment", "prod", "checkout-api", 2, 1, at(210*day),
		"registry.example.com/shop/checkout-api:1.14.2", "envoyproxy/envoy:v1.31.2")
	checkoutAPI.Conditions = append(checkoutAPI.Conditions,
		model.Condition{Type: "Available", Status: "False", Reason: "MinimumReplicasUnavailable", Message: "Deployment does not have minimum availability."})
	coredns := workload("Deployment", "kube-system", "coredns", 2, 2, at(400*day), "602401143452.dkr.ecr.us-east-1.amazonaws.com/eks/coredns:v1.11.3-eksbuild.2")
	coredns.Selector = &model.LabelSelector{MatchLabels: map[string]string{"k8s-app": "kube-dns"}}
	kubeProxy := workload("DaemonSet", "kube-system", "kube-proxy", 3, 3, at(400*day), "602401143452.dkr.ecr.us-east-1.amazonaws.com/eks/kube-proxy:v1.31.3-eksbuild.2")
	kubeProxy.Selector = &model.LabelSelector{MatchLabels: map[string]string{"k8s-app": "kube-proxy"}}

	c.workloads = []model.Workload{
		checkoutAPI,
		workload("Deployment", "prod", "payments-worker", 1, 1, at(300*day), "registry.example.com/shop/payments-worker:3.2.0"),
		workload("Deployment", "prod", "checkout-web", 2, 2, at(210*day), "registry.example.com/shop/checkout-web:2.8.1"),
		workload("Deployment", "prod", "catalog-api", 1, 1, at(150*day), "registry.example.com/shop/catalog-api:0.9.7"),
		workload("StatefulSet", "prod", "postgres", 1, 1, at(400*day), "postgres:16.4"),
		workload("StatefulSet", "prod", "redis", 1, 1, at(400*day), "redis:7.4"),
		{Kind: "CronJob", Namespace: "prod", Name: "inventory-sync", Created: at(90 * day), Schedule: "*/30 * * * *",
			Images: []string{"registry.example.com/shop/inventory-sync:1.2.0"}, LastScheduleTime: at(40 * time.Minute), LastSuccessTime: at(38 * time.Minute)},
		job("prod", "inventory-sync-28744320", at(40*time.Minute), "registry.example.com/shop/inventory-sync:1.2.0", 0, 1, 0,
			model.Condition{Type: "Complete", Status: "True"}),
		// The 6-hourly backup failed on its last run.
		{Kind: "CronJob", Namespace: "prod", Name: "db-backup", Created: at(200 * day), Schedule: "0 */6 * * *",
			Images: []string{"postgres:16.4"}, LastScheduleTime: at(2 * h), LastSuccessTime: at(8*h - 10*time.Minute)},
		job("prod", "db-backup-29345678", at(2*h), "postgres:16.4", 0, 0, 1,
			model.Condition{Type: "Failed", Status: "True", Reason: "BackoffLimitExceeded", Message: "Job has reached the specified backoff limit"}),

		workload("StatefulSet", "staging", "search-indexer", 1, 1, at(60*day), "registry.example.com/search/indexer:5.1.0"),
		workload("Deployment", "staging", "checkout-api", 1, 1, at(100*day), "registry.example.com/shop/checkout-api:1.15.0-rc.1"),
		workload("Deployment", "staging", "catalog-api", 1, 1, at(100*day), "registry.example.com/shop/catalog-api:0.9.7"),

		job("data", "etl-batch", at(5*h), "registry.example.com/data/etl:2026.10.1", 1, 0, 0),
		workload("Deployment", "data", "ml-trainer", 1, 1, at(30*day), "registry.example.com/data/ml-trainer:2.3.0", "amazon/aws-cli:2.17.0"),
		{Kind: "CronJob", Namespace: "data", Name: "warehouse-compact", Created: at(120 * day), Schedule: "0 3 * * 0", Suspended: true,
			Images: []string{"registry.example.com/data/etl:2026.10.1"}, LastScheduleTime: at(19 * day), LastSuccessTime: at(19 * day)},

		workload("StatefulSet", "monitoring", "prometheus", 1, 1, at(200*day), "quay.io/prometheus/prometheus:v2.54.1", "quay.io/prometheus-operator/prometheus-config-reloader:v0.77.1"),
		workload("Deployment", "monitoring", "grafana", 1, 1, at(200*day), "grafana/grafana:11.2.2"),
		workload("Deployment", "monitoring", "kube-state-metrics", 1, 1, at(200*day), "registry.k8s.io/kube-state-metrics/kube-state-metrics:v2.13.0"),
		workload("DaemonSet", "monitoring", "log-shipper", 3, 3, at(30*day), "fluent/fluent-bit:3.1.9"),

		coredns,
		kubeProxy,
	}

	web := service("prod", "checkout-web", "LoadBalancer", labels("app", "checkout-web"), port(80, "8080"))
	web.Ports[0].NodePort = 31847
	web.LoadBalancerIngress = []string{"k8s-prod-checkout-3f1c2a9b7e-1234567890.us-east-1.elb.amazonaws.com"}
	pg := service("prod", "postgres", "ClusterIP", labels("app", "postgres"), port(5432, "5432"))
	pg.ClusterIP = "None"
	grafana := service("monitoring", "grafana", "NodePort", labels("app", "grafana"), port(80, "3000"))
	grafana.Ports[0].NodePort = 30300
	dns := service("kube-system", "kube-dns", "ClusterIP", labels("k8s-app", "kube-dns"),
		model.ServicePort{Name: "dns", Protocol: "UDP", Port: 53, TargetPort: "53"}, model.ServicePort{Name: "dns-tcp", Protocol: "TCP", Port: 53, TargetPort: "53"})
	c.services = []model.Service{
		web,
		service("prod", "checkout-api", "ClusterIP", labels("app", "checkout-api"), port(8080, "8080")),
		service("prod", "catalog-api", "ClusterIP", labels("app", "catalog-api"), port(8080, "8080")),
		pg,
		service("prod", "redis", "ClusterIP", labels("app", "redis"), port(6379, "6379")),
		// Left behind when legacy-search was retired: it selects nothing.
		service("prod", "legacy-search", "ClusterIP", labels("app", "legacy-search"), port(9200, "9200")),
		service("staging", "search-indexer", "ClusterIP", labels("app", "search-indexer"), port(9200, "9200")),
		service("staging", "checkout-api", "ClusterIP", labels("app", "checkout-api"), port(8080, "8080")),
		service("staging", "catalog-api", "ClusterIP", labels("app", "catalog-api"), port(8080, "8080")),
		grafana,
		service("monitoring", "prometheus", "ClusterIP", labels("app", "prometheus"), port(9090, "9090")),
		service("monitoring", "kube-state-metrics", "ClusterIP", labels("app", "kube-state-metrics"), port(8080, "8080")),
		dns,
	}
	for i := range c.services {
		c.services[i].Created = at(100 * day)
		if c.services[i].ClusterIP == "" {
			c.services[i].ClusterIP = fmt.Sprintf("10.100.%d.%d", 10+i, 20+3*i)
		}
	}

	c.ingresses = []model.Ingress{
		{Namespace: "prod", Name: "shop", Class: "nginx", Created: at(210 * day),
			Rules: []model.IngressRule{
				{Host: "shop.example.com", Path: "/", Service: "checkout-web", Port: "80"},
				{Host: "shop.example.com", Path: "/api", Service: "checkout-api", Port: "8080"},
			},
			TLS: []model.IngressTLS{{Hosts: []string{"shop.example.com", "www.shop.example.com"}, SecretName: "shop-tls"}}},
		// The certificate search-staging-tls exists, but nobody added the TLS block.
		{Namespace: "staging", Name: "search", Class: "nginx", Created: at(60 * day),
			Rules: []model.IngressRule{{Host: "search.staging.example.com", Path: "/", Service: "search-indexer", Port: "9200"}}},
	}

	ml := node(nodeC, at(12*day),
		model.Condition{Type: "MemoryPressure", Status: "True", Reason: "KubeletHasInsufficientMemory", Message: "kubelet has insufficient memory available"})
	ml.Taints = []string{"dedicated=ml:NoSchedule"}
	c.nodes = []model.Node{node(nodeA, at(47*day)), node(nodeB, at(47*day)), ml}

	c.classes = []model.StorageClass{
		{Name: "gp3", Provisioner: "ebs.csi.aws.com", ReclaimPolicy: "Delete", BindingMode: "WaitForFirstConsumer", AllowExpansion: true, Default: true, Created: at(400 * day)},
		{Name: "io2", Provisioner: "ebs.csi.aws.com", ReclaimPolicy: "Retain", BindingMode: "WaitForFirstConsumer", AllowExpansion: true, Created: at(400 * day)},
	}
	policy := map[string]string{"gp3": "Delete", "io2": "Retain"}
	c.pvs = nil
	for _, p := range c.pvcs {
		if p.Phase != "Bound" {
			continue
		}
		c.pvs = append(c.pvs, model.PV{
			Name: p.VolumeName, StorageClass: p.StorageClass, Phase: "Bound", ReclaimPolicy: policy[p.StorageClass],
			CapacityBytes: p.CapacityBytes, AccessModes: []string{"ReadWriteOnce"}, ClaimNamespace: p.Namespace, ClaimName: p.Name,
			Source: "csi:ebs.csi.aws.com", Created: p.Created,
		})
	}
	// Its claim was deleted months ago; Retain kept the disk, and the bill.
	c.pvs = append(c.pvs, model.PV{
		Name: "pvc-prod-reports-archive", StorageClass: "io2", Phase: "Released", ReclaimPolicy: "Retain",
		CapacityBytes: 300 * gib, AccessModes: []string{"ReadWriteOnce"}, ClaimNamespace: "prod", ClaimName: "reports-archive",
		Source: "csi:ebs.csi.aws.com", Created: at(310 * day),
	})

	c.namespaces = []model.Namespace{
		{Name: "prod", Phase: "Active", Created: at(400 * day),
			Labels: map[string]string{"pod-security.kubernetes.io/enforce": "baseline", "pod-security.kubernetes.io/warn": "restricted"}},
		{Name: "staging", Phase: "Active", Created: at(400 * day)},
		{Name: "data", Phase: "Active", Labels: psa("privileged"), Created: at(300 * day)},
		{Name: "monitoring", Phase: "Active", Created: at(400 * day)},
		{Name: "ci", Phase: "Active", Labels: psa("restricted"), Created: at(400 * day)},
		{Name: "kube-system", Phase: "Active", Created: at(400 * day)},
	}

	c.rbac = model.RBAC{
		Roles: []model.Role{
			role("ClusterRole", "", "cluster-admin", rule(all, all, all), model.PolicyRule{NonResourceURLs: all, Verbs: all}),
			role("ClusterRole", "", "admin", rule([]string{"", "apps", "batch"}, []string{"pods", "deployments", "jobs", "secrets", "services", "configmaps"}, all)),
			role("ClusterRole", "", "edit", rule([]string{"", "apps"}, []string{"pods", "deployments", "secrets", "services", "configmaps"}, all)),
			role("ClusterRole", "", "view", rule([]string{"", "apps"}, []string{"pods", "deployments", "services", "configmaps"}, read)),
			role("ClusterRole", "", "system:public-info-viewer", model.PolicyRule{NonResourceURLs: []string{"/healthz", "/livez", "/readyz", "/version"}, Verbs: []string{"get"}}),
			role("ClusterRole", "", "aws-node", rule([]string{""}, []string{"pods", "nodes", "namespaces"}, read)),
			// nodes/proxy reaches the kubelet API, which can run commands in pods.
			role("ClusterRole", "", "metrics-reader", rule([]string{""}, []string{"nodes/metrics", "nodes/proxy"}, []string{"get"}),
				model.PolicyRule{NonResourceURLs: []string{"/metrics"}, Verbs: []string{"get"}}),
			role("ClusterRole", "", "secret-reader", rule([]string{""}, []string{"secrets"}, read)),
			role("Role", "prod", "ci-deployer", rule([]string{"", "apps"}, all, all)),
		},
		Bindings: []model.RoleBinding{
			binding("", "cluster-admin", "ClusterRole", "cluster-admin", model.Subject{Kind: "Group", Name: "system:masters"}),
			binding("", "system:public-info-viewer", "ClusterRole", "system:public-info-viewer",
				model.Subject{Kind: "Group", Name: "system:authenticated"}, model.Subject{Kind: "Group", Name: "system:unauthenticated"}),
			binding("", "aws-node", "ClusterRole", "aws-node", model.Subject{Kind: "ServiceAccount", Namespace: "kube-system", Name: "aws-node"}),
			binding("", "erin-cluster-admin", "ClusterRole", "cluster-admin", model.Subject{Kind: "User", Name: "erin"}),
			binding("", "metrics-public", "ClusterRole", "metrics-reader", model.Subject{Kind: "Group", Name: "system:unauthenticated"}),
			binding("", "developers-secret-reader", "ClusterRole", "secret-reader", model.Subject{Kind: "Group", Name: "developers"}),
			binding("prod", "developers-view", "ClusterRole", "view", model.Subject{Kind: "Group", Name: "developers"}),
			binding("prod", "ci-deployer", "Role", "ci-deployer", model.Subject{Kind: "ServiceAccount", Namespace: "ci", Name: "deployer"}),
		},
	}

	// cert-manager with a Vault ClusterIssuer using Kubernetes auth, whose
	// service account token cannot be read, so it cannot issue anything.
	const vaultErr = "Failed to initialize Vault client: error reading Kubernetes service account token from cdp-release-cert-manager: permission denied"
	c.certs = model.CertManager{
		Installed: true,
		Issuers: []model.Issuer{
			{Kind: "ClusterIssuer", Name: "letsencrypt-prod", Type: "acme", Server: "https://acme-v02.api.letsencrypt.org/directory",
				Ready: "True", Reason: "ACMEAccountRegistered", Message: "The ACME account was registered with the ACME server", Created: at(400 * day)},
			{Kind: "ClusterIssuer", Name: "vault-intermediate", Type: "vault", Server: "https://vault.internal:8200",
				Ready: "False", Reason: "VaultError", Message: vaultErr, Created: at(14 * day)},
			{Kind: "Issuer", Namespace: "staging", Name: "selfsigned", Type: "selfSigned", Ready: "True", Reason: "IsReady", Created: at(100 * day)},
		},
		Certificates: []model.Certificate{
			{Namespace: "prod", Name: "shop-tls", SecretName: "shop-tls", CommonName: "shop.example.com",
				DNSNames: []string{"shop.example.com", "www.shop.example.com"}, IssuerKind: "ClusterIssuer", IssuerName: "letsencrypt-prod",
				Ready: "True", Reason: "Ready", Message: "Certificate is up to date and has not expired",
				NotBefore: at(30 * day), NotAfter: now.Add(60*day + 6*h), RenewalTime: now.Add(30*day + 6*h), Created: at(210 * day)},
			{Namespace: "prod", Name: "api-internal-tls", SecretName: "api-internal-tls", CommonName: "checkout-api.prod.svc",
				DNSNames: []string{"checkout-api.prod.svc", "checkout-api.prod.svc.cluster.local"}, IssuerKind: "ClusterIssuer", IssuerName: "vault-intermediate",
				Ready: "False", Reason: "DoesNotExist", Message: "Issuing certificate as Secret does not exist", Created: at(3 * h)},
			{Namespace: "staging", Name: "search-staging-tls", SecretName: "search-staging-tls", CommonName: "search.staging.example.com",
				DNSNames: []string{"search.staging.example.com"}, IssuerName: "selfsigned",
				Ready: "True", Reason: "Ready", Message: "Certificate is up to date and has not expired",
				NotBefore: at(70 * day), NotAfter: now.Add(20*day + 6*h), RenewalTime: now.Add(13*day + 6*h), Created: at(100 * day)},
		},
		Requests: []model.CertificateRequest{
			{Namespace: "prod", Name: "api-internal-tls-1", Certificate: "api-internal-tls", IssuerKind: "ClusterIssuer", IssuerName: "vault-intermediate",
				Ready: "False", Reason: "Failed", Message: vaultErr, Approved: true, Created: at(3 * h)},
			{Namespace: "prod", Name: "shop-tls-3", Certificate: "shop-tls", IssuerKind: "ClusterIssuer", IssuerName: "letsencrypt-prod",
				Ready: "True", Reason: "Issued", Approved: true, Created: at(30 * day)},
		},
	}
}

func (c *Cluster) ListWorkloads(context.Context) ([]model.Workload, error) {
	return append([]model.Workload(nil), c.workloads...), nil
}

func (c *Cluster) ListServices(context.Context) ([]model.Service, error) {
	return append([]model.Service(nil), c.services...), nil
}

func (c *Cluster) ListIngresses(context.Context) ([]model.Ingress, error) {
	return append([]model.Ingress(nil), c.ingresses...), nil
}

func (c *Cluster) ListNodes(context.Context) ([]model.Node, error) {
	return append([]model.Node(nil), c.nodes...), nil
}

func (c *Cluster) ListPVs(context.Context) ([]model.PV, error) {
	return append([]model.PV(nil), c.pvs...), nil
}

func (c *Cluster) ListStorageClasses(context.Context) ([]model.StorageClass, error) {
	return append([]model.StorageClass(nil), c.classes...), nil
}

func (c *Cluster) ListNamespaces(context.Context) ([]model.Namespace, error) {
	return append([]model.Namespace(nil), c.namespaces...), nil
}

func (c *Cluster) ListRBAC(context.Context) (model.RBAC, error) { return c.rbac, nil }

func (c *Cluster) CertManager(context.Context) (model.CertManager, error) { return c.certs, nil }
