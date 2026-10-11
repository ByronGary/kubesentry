package detectors

import "time"

// Output types for the Map, Workloads, Storage, Security and Certificates
// pages. Their JSON shapes are mirrored in web/src/types.ts; change both
// together. Status fields use the Status* constants from pod.go.

// SystemNamespaces are treated as cluster plumbing by the entry points that
// predate Policy: findings in them are marked System and hidden by default in
// the UI. It starts as the default policy's set.
//
// Deprecated: use Policy.SystemNamespaces (and SystemNamespaceSet, which also
// applies the namespace label override).
var SystemNamespaces = DefaultPolicy().SystemNamespaces

// WorkloadSummary is one row on the Workloads page.
type WorkloadSummary struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Status    string `json:"status"`
	Detail    string `json:"detail"`
	Desired   int32  `json:"desired"`
	Ready     int32  `json:"ready"`
	Updated   int32  `json:"updated"`
	Available int32  `json:"available"`
	Pods      int    `json:"pods"`     // live pods the workload owns
	Restarts  int32  `json:"restarts"` // summed over those pods
	OOMKilled bool   `json:"oomKilled"`
	NotReady  int    `json:"notReady"` // live pods whose Ready condition is false
	// Waiting counts pods by their worst container waiting reason, e.g.
	// {"CrashLoopBackOff": 2, "ImagePullBackOff": 1}.
	Waiting          map[string]int `json:"waiting,omitempty"`
	Images           []string       `json:"images"`
	Created          time.Time      `json:"created"`
	Schedule         string         `json:"schedule,omitempty"` // CronJob
	Suspended        bool           `json:"suspended,omitempty"`
	LastScheduleTime *time.Time     `json:"lastScheduleTime,omitempty"`
	LastSuccessTime  *time.Time     `json:"lastSuccessTime,omitempty"`
}

// ClaimSummary is one PVC on the Storage page.
type ClaimSummary struct {
	Namespace     string    `json:"namespace"`
	Name          string    `json:"name"`
	Phase         string    `json:"phase"`
	StorageClass  string    `json:"storageClass"`
	VolumeName    string    `json:"volumeName,omitempty"`
	CapacityBytes int64     `json:"capacityBytes"`
	UsedBy        []string  `json:"usedBy"` // names of live pods mounting it
	Status        string    `json:"status"`
	Detail        string    `json:"detail"`
	Created       time.Time `json:"created"`
	// Cost estimate for the claim's capacity; CostKnown is false when no price
	// applies (PriceSource says why, e.g. usage-billed for EFS).
	EstMonthlyCostUSD float64 `json:"estMonthlyCostUSD"`
	CostKnown         bool    `json:"costKnown"`
	PriceSource       string  `json:"priceSource"`
}

// VolumeSummary is one PV on the Storage page.
type VolumeSummary struct {
	Name          string    `json:"name"`
	Phase         string    `json:"phase"`
	StorageClass  string    `json:"storageClass"`
	ReclaimPolicy string    `json:"reclaimPolicy"`
	Source        string    `json:"source"`
	Driver        string    `json:"driver,omitempty"`
	VolumeHandle  string    `json:"volumeHandle,omitempty"`
	Claim         string    `json:"claim,omitempty"` // "namespace/name"
	CapacityBytes int64     `json:"capacityBytes"`
	Status        string    `json:"status"`
	Detail        string    `json:"detail"`
	Created       time.Time `json:"created"`
}

// ClassSummary is one StorageClass on the Storage page.
type ClassSummary struct {
	Name           string `json:"name"`
	Provisioner    string `json:"provisioner"`
	ReclaimPolicy  string `json:"reclaimPolicy"`
	BindingMode    string `json:"bindingMode"`
	AllowExpansion bool   `json:"allowExpansion"`
	Default        bool   `json:"default"`
	Claims         int    `json:"claims"`        // PVCs using the class
	CapacityBytes  int64  `json:"capacityBytes"` // summed capacity of those PVCs
	// Price per GiB-month and where it came from (see the PriceFrom* constants).
	PricePerGiBMonth float64           `json:"pricePerGiBMonth"`
	PriceSource      string            `json:"priceSource"`
	Parameters       map[string]string `json:"parameters,omitempty"`
}

// SecurityFinding is one risk on the Security page.
type SecurityFinding struct {
	ID          string `json:"id"`       // stable: check + subject kind + subject
	Category    string `json:"category"` // "pod", "rbac", "namespace" or "exposure"
	Check       string `json:"check"`    // see the Check* constants
	Severity    string `json:"severity"` // "crit", "warn" or "info"
	Title       string `json:"title"`    // short, e.g. "Privileged container"
	Subject     string `json:"subject"`  // "namespace/name", or the name of a cluster-scoped object
	SubjectKind string `json:"subjectKind"`
	Namespace   string `json:"namespace,omitempty"`
	Detail      string `json:"detail"` // one sentence naming the containers, subjects or ports involved
	System      bool   `json:"system"` // cluster plumbing: hidden by default
}

// Security checks.
const (
	CheckPrivileged          = "privileged"           // crit
	CheckHostNamespaces      = "host-namespaces"      // warn: hostPID, hostNetwork or hostIPC
	CheckHostPath            = "host-path"            // warn
	CheckCapabilities        = "capabilities"         // crit for SYS_ADMIN or ALL, warn for other added capabilities
	CheckRunAsRoot           = "run-as-root"          // warn: runAsNonRoot not set and runAsUser unset or 0
	CheckPrivilegeEscalation = "privilege-escalation" // info: allowPrivilegeEscalation not explicitly false
	CheckNoMemoryLimit       = "no-memory-limit"      // info
	CheckTokenAutomount      = "token-automount"      // info
	CheckClusterAdmin        = "cluster-admin"        // crit: a non-system subject bound to cluster-admin
	CheckAnonymous           = "anonymous-binding"    // crit: a non-default binding to system:anonymous or system:unauthenticated
	CheckWildcard            = "wildcard-rbac"        // warn: a non-system role with "*" verbs or resources
	CheckSecretReaders       = "secret-readers"       // warn for a user or group, info when only service accounts can get/list/watch secrets
	CheckPSAMissing          = "psa-missing"          // warn: no pod-security.kubernetes.io/enforce label
	CheckPSAPrivileged       = "psa-privileged"       // warn: enforce=privileged
	CheckNodePort            = "nodeport"             // warn
	CheckLoadBalancer        = "loadbalancer"         // warn
	CheckExternalIP          = "external-ip"          // warn
	CheckIngressNoTLS        = "ingress-no-tls"       // warn
)

// NamespacePosture is one namespace's Pod Security Admission labels.
type NamespacePosture struct {
	Name    string `json:"name"`
	Enforce string `json:"enforce"` // "" when the label is missing
	Audit   string `json:"audit"`
	Warn    string `json:"warn"`
	System  bool   `json:"system"`
	Status  string `json:"status"` // ok for baseline/restricted, warn for privileged or missing
}

// CertSummary is one Certificate on the Certificates page.
type CertSummary struct {
	Namespace      string     `json:"namespace"`
	Name           string     `json:"name"`
	SecretName     string     `json:"secretName"`
	DNSNames       []string   `json:"dnsNames"`
	IssuerKind     string     `json:"issuerKind"`
	IssuerName     string     `json:"issuerName"`
	Ready          string     `json:"ready"`
	Reason         string     `json:"reason,omitempty"`
	Message        string     `json:"message,omitempty"`
	NotAfter       *time.Time `json:"notAfter,omitempty"`
	RenewalTime    *time.Time `json:"renewalTime,omitempty"`
	ExpiresInHours *float64   `json:"expiresInHours,omitempty"` // negative once expired
	Status         string     `json:"status"`
	Detail         string     `json:"detail"`
}

// IssuerSummary is one Issuer or ClusterIssuer.
type IssuerSummary struct {
	Kind         string `json:"kind"`
	Namespace    string `json:"namespace,omitempty"`
	Name         string `json:"name"`
	Type         string `json:"type"`
	Server       string `json:"server,omitempty"`
	Ready        string `json:"ready"`
	Reason       string `json:"reason,omitempty"`
	Message      string `json:"message,omitempty"`
	Certificates int    `json:"certificates"` // Certificates that reference it
	Status       string `json:"status"`
	Detail       string `json:"detail"`
}

// RequestSummary is a CertificateRequest that is not simply done: pending,
// failed or denied.
type RequestSummary struct {
	Namespace   string    `json:"namespace"`
	Name        string    `json:"name"`
	Certificate string    `json:"certificate"`
	IssuerKind  string    `json:"issuerKind"`
	IssuerName  string    `json:"issuerName"`
	Ready       string    `json:"ready"`
	Reason      string    `json:"reason,omitempty"`
	Message     string    `json:"message,omitempty"`
	Approved    bool      `json:"approved"`
	Denied      bool      `json:"denied"`
	Created     time.Time `json:"created"`
	Status      string    `json:"status"`
}

// Graph is the application topology of one namespace for the Map page.
type Graph struct {
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
}

// GraphNode is one object on the map. ID is "<Kind>/<namespace>/<name>", or
// "Node/<name>" for nodes.
type GraphNode struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"` // Ingress, Service, Deployment, StatefulSet, DaemonSet, Job, CronJob, ReplicaSet (orphaned), Controller (other owners), Pod, PVC, Node
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
	Status    string `json:"status"`
	Detail    string `json:"detail"`
	// OwnerKind is the real kind behind a "Controller" node (e.g. Rollout).
	OwnerKind string `json:"ownerKind,omitempty"`
}

// GraphEdge points from the routing or owning object to the one it routes to,
// runs or uses: Ingress→Service→Workload→Pod→Node, CronJob→Job and Pod→PVC.
type GraphEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	// How the link was found: "owner" (ownerReferences), "endpoints"
	// (EndpointSlices) or "selector" (labels, the fallback).
	How string `json:"how,omitempty"`
	// Endpoints on Service links: how many of the target's endpoints are ready,
	// not ready and terminating.
	Ready       int `json:"ready,omitempty"`
	NotReady    int `json:"notReady,omitempty"`
	Terminating int `json:"terminating,omitempty"`
}

// Association methods for GraphEdge.How and pod ownership.
const (
	HowOwner     = "owner"
	HowEndpoints = "endpoints"
	HowSelector  = "selector"
)

// NodeSummary is one node in the Map page's node view.
type NodeSummary struct {
	Name                   string    `json:"name"`
	Roles                  []string  `json:"roles"`
	Ready                  bool      `json:"ready"`
	Unschedulable          bool      `json:"unschedulable"`
	Status                 string    `json:"status"`
	Detail                 string    `json:"detail"`
	KubeletVersion         string    `json:"kubeletVersion"`
	OSImage                string    `json:"osImage"`
	ContainerRuntime       string    `json:"containerRuntime"`
	Pressure               []string  `json:"pressure"` // MemoryPressure, DiskPressure or PIDPressure conditions that are True
	Taints                 []string  `json:"taints"`
	CPUAllocatableMilli    int64     `json:"cpuAllocatableMilli"`
	CPURequestedMilli      int64     `json:"cpuRequestedMilli"` // summed requests of non-terminated pods
	MemoryAllocatableBytes int64     `json:"memoryAllocatableBytes"`
	MemoryRequestedBytes   int64     `json:"memoryRequestedBytes"`
	PodsAllocatable        int64     `json:"podsAllocatable"`
	Pods                   []NodePod `json:"pods"`
	Placement              Placement `json:"placement"`
	PodCount               int       `json:"podCount"` // live pods, also when Pods is omitted (?summary=true)
}

// Placement is where and on what a node runs, derived from well-known labels
// (EKS managed node groups, Karpenter, Fargate) and the providerID.
type Placement struct {
	Zone         string `json:"zone,omitempty"`
	Region       string `json:"region,omitempty"`
	InstanceType string `json:"instanceType,omitempty"`
	Arch         string `json:"arch,omitempty"`
	OS           string `json:"os,omitempty"`
	Pool         string `json:"pool,omitempty"`         // node group or Karpenter node pool name
	PoolKind     string `json:"poolKind,omitempty"`     // "nodegroup", "karpenter", "fargate" or ""
	CapacityType string `json:"capacityType,omitempty"` // "on-demand" or "spot"
	ProviderID   string `json:"providerID,omitempty"`
}

// NodePod is a pod listed under its node.
type NodePod struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Phase     string `json:"phase"`
	Status    string `json:"status"`
	Workload  string `json:"workload,omitempty"` // "Kind/name" of the owning workload
	Ready     bool   `json:"ready"`
	Reason    string `json:"reason,omitempty"` // worst container waiting reason, e.g. CrashLoopBackOff
}

// LeakReport is the background leak scan: candidates are found with one cheap
// Prometheus query, then only those are analysed in detail.
type LeakReport struct {
	GeneratedAt time.Time     `json:"generatedAt"`
	Window      string        `json:"window"`
	Findings    []LeakFinding `json:"findings"`
	Candidates  int           `json:"candidates"`
	Errors      []string      `json:"errors,omitempty"`
	// Warnings are notices that are not failures, e.g. the candidate cap was hit.
	Warnings []string `json:"warnings,omitempty"`
	// LastAttempt is when the latest scan ran; GeneratedAt stays at the last
	// good scan when a later one fails.
	LastAttempt time.Time `json:"lastAttempt"`
}
