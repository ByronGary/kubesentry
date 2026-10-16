// Package demo provides a synthetic cluster, metrics and audit trail so the UI
// can be tried without a Kubernetes cluster, Prometheus or audit log. Nothing
// here is real data.
package demo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
)

const (
	gib = int64(1) << 30
	day = 24 * time.Hour
)

// The demo's EKS nodes, one per zone: a managed node group, a Karpenter
// spot node (arm64), the tainted GPU node, short on memory because
// ml-trainer has no memory limit, and a Fargate node running one batch pod.
const (
	nodeA = "ip-10-0-12-34.ec2.internal"
	nodeB = "ip-10-0-45-67.ec2.internal"
	nodeC = "ip-10-0-78-90.ec2.internal"
	nodeF = "fargate-ip-10-0-140-21.ec2.internal"
)

// Cluster is an in-memory snapshot.Source, and the older ClusterSource,
// InventorySource and CertSource.
type Cluster struct {
	pods        []model.Pod
	pvcs        []model.PVC
	workloads   []model.Workload
	replicaSets []model.ReplicaSet
	services    []model.Service
	slices      []model.EndpointSlice
	ingresses   []model.Ingress
	nodes       []model.Node
	pvs         []model.PV
	classes     []model.StorageClass
	namespaces  []model.Namespace
	rbac        model.RBAC
	certs       model.CertManager
	info        model.ClusterInfo
}

func ctr(name string, restarts int32) model.ContainerStatus {
	return model.ContainerStatus{Name: name, RestartCount: restarts}
}

func oomKilled(c model.ContainerStatus, ago time.Duration, now time.Time) model.ContainerStatus {
	c.LastTerminatedReason = "OOMKilled"
	c.LastTerminatedAt = now.Add(-ago)
	c.LastExitCode = 137
	return c
}

// uidOf makes a stable, UUID-shaped UID from an object's identity.
func uidOf(key string) string {
	h := hexOf(key)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// hexOf is 32 stable hex digits derived from key, for synthetic IDs.
func hexOf(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:16])
}

func pod(ns, name, phase string, claims []string, cs ...model.ContainerStatus) model.Pod {
	uid := uidOf(ns + "/" + name)
	for i := range cs {
		id := sha256.Sum256([]byte(ns + "/" + name + "/" + cs[i].Name))
		cs[i].ContainerID = hex.EncodeToString(id[:])
	}
	return model.Pod{UID: uid, Namespace: ns, Name: name, Phase: phase, Claims: claims, Containers: cs}
}

// placed fills in the spec side of a pod: its node, labels, service account,
// start time and container specs.
func placed(p model.Pod, node string, labels map[string]string, sa string, created time.Time, specs ...model.ContainerSpec) model.Pod {
	p.NodeName, p.Labels, p.ServiceAccount, p.Created, p.Specs = node, labels, sa, created, specs
	return p
}

// withToken mounts the service account token, for pods that call the API.
func withToken(p model.Pod) model.Pod {
	p.AutomountToken = true
	return p
}

// onHost gives a pod the node's network and the given host paths.
func onHost(p model.Pod, paths ...string) model.Pod {
	p.HostNetwork = true
	p.HostPaths = paths
	return p
}

func labels(kv ...string) map[string]string {
	m := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return m
}

func i64(v int64) *int64 { return &v }
func no() *bool          { v := false; return &v }

// spec is a container with the hardening a careful team applies: non-root,
// no privilege escalation, a read-only root and requests at half the limits.
// memMiB 0 means no memory limit.
func spec(name, image string, cpuMilli, memMiB int64) model.ContainerSpec {
	return model.ContainerSpec{
		Name: name, Image: image, RunAsNonRoot: true, RunAsUser: i64(10001), AllowPrivilegeEscalation: no(),
		ReadOnlyRootFilesystem: true, CapabilitiesDropAll: true,
		CPURequestMilli: cpuMilli, CPULimitMilli: 2 * cpuMilli,
		MemoryRequestBytes: memMiB << 19, MemoryLimitBytes: memMiB << 20,
	}
}

// asRoot drops the non-root settings, as images that need root do.
func asRoot(c model.ContainerSpec) model.ContainerSpec {
	c.RunAsNonRoot, c.RunAsUser, c.AllowPrivilegeEscalation, c.CapabilitiesDropAll = false, nil, nil, false
	return c
}

func asUser(c model.ContainerSpec, uid int64) model.ContainerSpec {
	c.RunAsUser = i64(uid)
	return c
}

func initContainer(c model.ContainerSpec) model.ContainerSpec {
	c.Init = true
	return c
}

func pvc(ns, name, class, phase string, sizeGiB int64, age time.Duration, now time.Time) model.PVC {
	p := model.PVC{
		Namespace: ns, Name: name, StorageClass: class, Phase: phase,
		CapacityBytes: sizeGiB * gib, VolumeName: "pvc-" + ns + "-" + name, Created: now.Add(-age),
	}
	if phase == "Pending" {
		p.VolumeName = ""
	}
	return p
}

// NewCluster builds the demo cluster. Times are relative to now.
func NewCluster(now time.Time) *Cluster {
	at := func(d time.Duration) time.Time { return now.Add(-d) }
	h := time.Hour
	const (
		checkoutAPI = "registry.example.com/shop/checkout-api:1.14.2"
		envoy       = "envoyproxy/envoy:v1.31.2"
		catalogAPI  = "registry.example.com/shop/catalog-api:0.9.7"
	)
	failedBackup := pod("prod", "db-backup-29345678-k8w2p", "Failed", nil, ctr("backup", 0))
	failedBackup.Containers[0].LastTerminatedReason = "Error"
	failedBackup.Containers[0].LastTerminatedAt = at(2*h - 4*time.Minute)
	failedBackup.Containers[0].LastExitCode = 1

	// Crash-looping since its last deploy: the config it needs is missing.
	recs := pod("prod", "recommendations-6d5f7c8b9-zt4qx", "Running", nil, ctr("api", 14))
	recs.Containers[0] = crashLooping(recs.Containers[0], "back-off 5m0s restarting failed container=api pod=recommendations-6d5f7c8b9-zt4qx_prod", at(3*time.Minute))
	// Evicted when its node ran out of memory; the ReplicaSet replaced it.
	evicted := pod("data", "ml-trainer-6f8c9d7b5-9xq2w", "Failed", nil, ctr("trainer", 0))
	evicted.Reason = "Evicted"
	evicted.Message = "The node was low on resource: memory. Threshold quantity: 750Mi, available: 512004Ki. Container trainer was using 9876544Ki, request is 6Gi, has larger consumption of memory."
	evicted.Containers[0].State, evicted.Containers[0].Reason = "terminated", "ContainerStatusUnknown"
	// The previous checkout-web ReplicaSet scaling down: terminating, still serving.
	oldWeb := pod("prod", "checkout-web-5f9c7d6b4-8kq3z", "Running", nil, ctr("web", 0))
	oldWeb.DeletedAt = now.Add(-20 * time.Second)
	etl := pod("data", "etl-batch-0", "Pending", []string{"etl-scratch"}, ctr("etl", 0))
	etl.Unschedulable = `0/4 nodes are available: persistentvolumeclaim "etl-scratch" not found.`
	trainerRunning := pod("data", "ml-trainer-6f8c9d7b5-r2k7x", "Running", nil, ctr("trainer", 3),
		model.ContainerStatus{Name: "fetch-model", Init: true, State: "terminated", Reason: "Completed"})

	postgres := asUser(spec("postgres", "postgres:16.4", 500, 2048), 999)
	postgres.ReadOnlyRootFilesystem, postgres.AllowPrivilegeEscalation = false, nil // left at the image defaults
	trainer := asRoot(spec("trainer", "registry.example.com/data/ml-trainer:2.3.0", 2000, 0))
	trainer.Privileged = true // for GPU and FUSE mounts, the usual excuse
	trainer.CapabilitiesAdd = []string{"SYS_ADMIN"}
	trainer.MemoryRequestBytes = 6 * gib // and no limit, which is why its node is short of memory
	indexer := asUser(spec("indexer", "registry.example.com/search/indexer:5.1.0", 1000, 0), 1000)
	indexer.MemoryRequestBytes = 2 * gib // no limit: the creeping memory never hits a ceiling
	shipper := asRoot(spec("fluent-bit", "fluent/fluent-bit:3.1.9", 100, 128))
	proxy := asRoot(spec("kube-proxy", "602401143452.dkr.ecr.us-east-1.amazonaws.com/eks/kube-proxy:v1.34.1-eksbuild.2", 100, 0))
	proxy.Privileged = true
	coredns := asRoot(spec("coredns", "602401143452.dkr.ecr.us-east-1.amazonaws.com/eks/coredns:v1.12.3-eksbuild.1", 100, 170))
	coredns.CapabilitiesAdd = []string{"NET_BIND_SERVICE"}

	c := &Cluster{
		pods: []model.Pod{
			// The story pods: a leak that OOMKills, a flapping worker, a stuck batch job.
			placed(pod("prod", "checkout-api-7d9f8b6c4-x2k9p", "Running", nil, oomKilled(ctr("api", 6), 3*h, now), ctr("envoy", 0)),
				nodeA, labels("app", "checkout-api", "pod-template-hash", "7d9f8b6c4"), "checkout-api", at(26*h),
				spec("api", checkoutAPI, 250, 512), spec("envoy", envoy, 100, 256)),
			placed(pod("prod", "payments-worker-5c6d7f9b8-q8wzn", "Running", nil, oomKilled(ctr("worker", 12), 30*h, now)),
				nodeA, labels("app", "payments-worker", "pod-template-hash", "5c6d7f9b8"), "payments-worker", at(9*day),
				spec("worker", "registry.example.com/shop/payments-worker:3.2.0", 500, 1024)),
			// Recreated an hour ago, when dave deleted it.
			placed(pod("staging", "search-indexer-0", "Running", []string{"search-index-0"}, ctr("indexer", 1)),
				nodeB, labels("app", "search-indexer"), "search-indexer", at(h),
				indexer),
			// Unschedulable: its claim etl-scratch does not exist.
			placed(etl, "", labels("job-name", "etl-batch"), "etl", at(5*h),
				spec("etl", "registry.example.com/data/etl:2026.10.1", 1000, 4096)),
			placed(recs, nodeB, labels("app", "recommendations", "pod-template-hash", "6d5f7c8b9"), "recommendations", at(50*time.Minute),
				spec("api", "registry.example.com/shop/recommendations:4.0.0", 200, 512)),
			placed(evicted, nodeC, labels("app", "ml-trainer", "pod-template-hash", "6f8c9d7b5"), "ml-trainer", at(20*h),
				trainer, initContainer(asRoot(spec("fetch-model", "amazon/aws-cli:2.17.0", 100, 256)))),
			placed(oldWeb, nodeB, labels("app", "checkout-web", "pod-template-hash", "5f9c7d6b4"), "checkout-web", at(20*day),
				spec("web", "registry.example.com/shop/checkout-web:2.8.0", 100, 256)),
			// A batch job on Fargate.
			placed(pod("data", "feature-backfill-29345690-q9d2m", "Running", nil, ctr("backfill", 0)),
				nodeF, labels("job-name", "feature-backfill-29345690"), "feature-backfill", at(25*time.Minute),
				spec("backfill", "registry.example.com/data/feature-backfill:1.3.2", 500, 1024)),

			// Healthy workloads, for a realistic list.
			placed(pod("prod", "checkout-api-7d9f8b6c4-h5r8t", "Running", nil, ctr("api", 0), ctr("envoy", 0)),
				nodeB, labels("app", "checkout-api", "pod-template-hash", "7d9f8b6c4"), "checkout-api", at(2*h),
				spec("api", checkoutAPI, 250, 512), spec("envoy", envoy, 100, 256)),
			placed(pod("prod", "postgres-0", "Running", []string{"data-postgres-0"}, ctr("postgres", 0)),
				nodeA, labels("app", "postgres"), "postgres", at(41*day),
				postgres),
			placed(pod("prod", "redis-0", "Running", []string{"data-redis-0"}, ctr("redis", 0)),
				nodeB, labels("app", "redis"), "default", at(41*day),
				asRoot(spec("redis", "redis:7.4", 100, 512))),
			placed(pod("prod", "checkout-web-6b8c9d7f5-4tn2m", "Running", nil, ctr("web", 0)),
				nodeA, labels("app", "checkout-web", "pod-template-hash", "6b8c9d7f5"), "checkout-web", at(6*day),
				spec("web", "registry.example.com/shop/checkout-web:2.8.1", 100, 256)),
			placed(pod("prod", "checkout-web-6b8c9d7f5-j7v9c", "Running", nil, ctr("web", 1)),
				nodeB, labels("app", "checkout-web", "pod-template-hash", "6b8c9d7f5"), "checkout-web", at(6*day),
				spec("web", "registry.example.com/shop/checkout-web:2.8.1", 100, 256)),
			placed(pod("prod", "catalog-api-5f7d8c9b6-m2xk4", "Running", nil, ctr("api", 0)),
				nodeA, labels("app", "catalog-api", "pod-template-hash", "5f7d8c9b6"), "catalog-api", at(13*day),
				spec("api", catalogAPI, 200, 512)),
			withToken(placed(pod("prod", "inventory-sync-28744320-bz6hd", "Succeeded", nil, ctr("sync", 0)),
				nodeB, labels("job-name", "inventory-sync-28744320"), "inventory-sync", at(40*time.Minute),
				spec("sync", "registry.example.com/shop/inventory-sync:1.2.0", 100, 256))),
			placed(failedBackup, nodeA, labels("job-name", "db-backup-29345678"), "db-backup", at(2*h),
				spec("backup", "postgres:16.4", 200, 512)),
			placed(pod("staging", "checkout-api-6c8d7f9b5-p9w2k", "Running", nil, ctr("api", 0)),
				nodeA, labels("app", "checkout-api", "pod-template-hash", "6c8d7f9b5"), "checkout-api", at(3*day),
				spec("api", "registry.example.com/shop/checkout-api:1.15.0-rc.1", 250, 512)),
			placed(pod("staging", "catalog-api-7d9c8b6f4-t5n8j", "Running", nil, ctr("api", 2)),
				nodeB, labels("app", "catalog-api", "pod-template-hash", "7d9c8b6f4"), "catalog-api", at(3*day),
				spec("api", catalogAPI, 200, 512)),
			withToken(placed(pod("monitoring", "prometheus-0", "Running", []string{"prometheus-data"}, ctr("prometheus", 0), ctr("config-reloader", 0)),
				nodeA, labels("app", "prometheus"), "prometheus", at(20*day),
				asUser(spec("prometheus", "quay.io/prometheus/prometheus:v2.54.1", 500, 2048), 65534),
				asUser(spec("config-reloader", "quay.io/prometheus-operator/prometheus-config-reloader:v0.77.1", 50, 64), 65534))),
			placed(pod("monitoring", "grafana-7c9d8f6b5-k4m2x", "Running", nil, ctr("grafana", 0)),
				nodeB, labels("app", "grafana", "pod-template-hash", "7c9d8f6b5"), "grafana", at(20*day),
				asUser(spec("grafana", "grafana/grafana:11.2.2", 100, 256), 472)),
			withToken(placed(pod("monitoring", "kube-state-metrics-8d7c9f6b4-w9n5v", "Running", nil, ctr("kube-state-metrics", 0)),
				nodeB, labels("app", "kube-state-metrics", "pod-template-hash", "8d7c9f6b4"), "kube-state-metrics", at(20*day),
				asUser(spec("kube-state-metrics", "registry.k8s.io/kube-state-metrics/kube-state-metrics:v2.13.0", 100, 256), 65534))),
			withToken(placed(trainerRunning,
				nodeC, labels("app", "ml-trainer", "pod-template-hash", "6f8c9d7b5"), "ml-trainer", at(2*h),
				trainer, initContainer(asRoot(spec("fetch-model", "amazon/aws-cli:2.17.0", 100, 256))))),

			// A log shipper on every node, reading the node's logs.
			withToken(onHost(placed(pod("monitoring", "log-shipper-7xk2p", "Running", nil, ctr("fluent-bit", 0)),
				nodeA, labels("app", "log-shipper"), "log-shipper", at(30*day), shipper), "/var/log")),
			withToken(onHost(placed(pod("monitoring", "log-shipper-m9q4z", "Running", nil, ctr("fluent-bit", 0)),
				nodeB, labels("app", "log-shipper"), "log-shipper", at(30*day), shipper), "/var/log")),
			withToken(onHost(placed(pod("monitoring", "log-shipper-r5t8w", "Running", nil, ctr("fluent-bit", 1)),
				nodeC, labels("app", "log-shipper"), "log-shipper", at(30*day), shipper), "/var/log")),

			// Cluster plumbing: its findings are marked system and hidden by default.
			withToken(placed(pod("kube-system", "coredns-5d78c9869d-8xw4t", "Running", nil, ctr("coredns", 0)),
				nodeA, labels("k8s-app", "kube-dns", "pod-template-hash", "5d78c9869d"), "coredns", at(90*day), coredns)),
			withToken(placed(pod("kube-system", "coredns-5d78c9869d-qz7lp", "Running", nil, ctr("coredns", 0)),
				nodeB, labels("k8s-app", "kube-dns", "pod-template-hash", "5d78c9869d"), "coredns", at(90*day), coredns)),
			withToken(onHost(placed(pod("kube-system", "kube-proxy-2bnx8", "Running", nil, ctr("kube-proxy", 0)),
				nodeA, labels("k8s-app", "kube-proxy"), "kube-proxy", at(90*day), proxy), "/run/xtables.lock", "/lib/modules")),
			withToken(onHost(placed(pod("kube-system", "kube-proxy-6tjk9", "Running", nil, ctr("kube-proxy", 0)),
				nodeB, labels("k8s-app", "kube-proxy"), "kube-proxy", at(90*day), proxy), "/run/xtables.lock", "/lib/modules")),
			withToken(onHost(placed(pod("kube-system", "kube-proxy-w4m7d", "Running", nil, ctr("kube-proxy", 0)),
				nodeC, labels("k8s-app", "kube-proxy"), "kube-proxy", at(90*day), proxy), "/run/xtables.lock", "/lib/modules")),
		},
		pvcs: []model.PVC{
			// In use.
			pvc("prod", "data-postgres-0", "gp3", "Bound", 100, 120*day, now),
			pvc("prod", "data-redis-0", "gp3", "Bound", 10, 120*day, now),
			pvc("staging", "search-index-0", "gp3", "Bound", 200, 60*day, now),
			pvc("monitoring", "prometheus-data", "gp3", "Bound", 50, 200*day, now),
			// Unused: nothing mounts these.
			pvc("staging", "old-es-data-0", "gp3", "Bound", 200, 45*day, now),
			pvc("prod", "backup-scratch", "io2", "Bound", 500, 12*day, now),
			pvc("data", "ml-cache", "gp3", "Bound", 50, 90*day, now),
			pvc("staging", "test-claim-3", "gp3", "Bound", 5, 2*day, now),
			pvc("staging", "new-claim", "gp3", "Bound", 1, 3*time.Hour, now),  // younger than the minimum age, hidden by default
			pvc("data", "shared-models", "efs-sc", "Bound", 100, 30*day, now), // EFS: billed by usage, no estimate
			// Waiting for its first pod, which is normal with WaitForFirstConsumer.
			pvc("data", "feature-store", "gp3", "Pending", 0, 20*time.Minute, now),
		},
	}
	// The shop's services are one app (app.kubernetes.io/part-of), so their
	// incidents are related.
	for i := range c.pods {
		if p := &c.pods[i]; p.Namespace == "prod" && shopApps[p.Labels["app"]] {
			p.Labels["app.kubernetes.io/part-of"] = "shop"
		}
	}
	c.addInventory(now)
	c.link(now)
	return c
}

// shopApps are the shop's services in prod.
var shopApps = map[string]bool{"checkout-web": true, "checkout-api": true, "catalog-api": true, "recommendations": true}

// crashLooping makes a container wait in CrashLoopBackOff after failing.
func crashLooping(c model.ContainerStatus, msg string, lastFailed time.Time) model.ContainerStatus {
	c.State, c.Reason, c.Message = "waiting", "CrashLoopBackOff", msg
	c.LastTerminatedReason, c.LastTerminatedAt, c.LastExitCode = "Error", lastFailed, 1
	return c
}

func (c *Cluster) ListPVCs(context.Context) ([]model.PVC, error) {
	return append([]model.PVC(nil), c.pvcs...), nil
}

func (c *Cluster) ListPods(context.Context) ([]model.Pod, error) {
	return append([]model.Pod(nil), c.pods...), nil
}

func (c *Cluster) GetPod(_ context.Context, ns, name string) (*model.Pod, error) {
	for i := range c.pods {
		if c.pods[i].Namespace == ns && c.pods[i].Name == name {
			p := c.pods[i]
			return &p, nil
		}
	}
	return nil, model.ErrNotFound
}

func (c *Cluster) GetPVC(_ context.Context, ns, name string) (*model.PVC, error) {
	for i := range c.pvcs {
		if c.pvcs[i].Namespace == ns && c.pvcs[i].Name == name {
			p := c.pvcs[i]
			return &p, nil
		}
	}
	return nil, model.ErrNotFound
}
