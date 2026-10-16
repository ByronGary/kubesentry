package model

import "time"

// The types below back the Map, Workloads, Storage, Security and Certificates
// pages. Like the rest of this package they carry no client-go types.

// LabelSelector mirrors metav1.LabelSelector. A nil selector matches nothing.
type LabelSelector struct {
	MatchLabels      map[string]string
	MatchExpressions []SelectorRequirement
}

// SelectorRequirement is one matchExpressions entry. Operator is In, NotIn,
// Exists or DoesNotExist.
type SelectorRequirement struct {
	Key      string
	Operator string
	Values   []string
}

// Condition is a status condition of a workload, node or cert-manager object.
type Condition struct {
	Type           string
	Status         string // "True", "False" or "Unknown"
	Reason         string
	Message        string
	LastTransition time.Time
}

// Workload is a Deployment, StatefulSet, DaemonSet, Job or CronJob.
type Workload struct {
	Kind      string // "Deployment", "StatefulSet", "DaemonSet", "Job" or "CronJob"
	Namespace string
	Name      string
	UID       string
	Owners    []OwnerRef // e.g. a Job's CronJob
	Created   time.Time
	Selector  *LabelSelector // nil for CronJob
	Images    []string       // from the pod template, containers then init containers
	// Labels keeps only the app/service tag keys incidents correlate on
	// (app.kubernetes.io/*, app, k8s-app and the configured custom key).
	Labels map[string]string
	// Revision changes on every rollout: the deployment.kubernetes.io/revision
	// annotation for Deployments, status.updateRevision for StatefulSets, and
	// the deprecated.daemonset.template.generation annotation for DaemonSets
	// (DaemonSetStatus has no updateRevision). Empty for Jobs and CronJobs.
	Revision string
	// Desired is spec.replicas (Deployment, StatefulSet), desiredNumberScheduled
	// (DaemonSet) or spec.completions (Job; 1 when unset).
	Desired    int32
	Ready      int32
	Updated    int32
	Available  int32
	Paused     bool        // Deployment
	Conditions []Condition // e.g. Deployment Progressing/Available, Job Complete/Failed
	// Job counters.
	Succeeded int32
	Failed    int32
	Active    int32
	// CronJob fields.
	Schedule         string
	Suspended        bool
	LastScheduleTime time.Time
	LastSuccessTime  time.Time
	// Owner is the team the workload names as its owner (the owner
	// annotation, -owner-annotation, trimmed); "" when it names none and its
	// namespace's owner applies.
	Owner string
}

// Service is a core/v1 Service.
type Service struct {
	Namespace           string
	Name                string
	Type                string            // ClusterIP, NodePort, LoadBalancer or ExternalName
	ClusterIP           string            // "None" for headless services
	Selector            map[string]string // empty when endpoints are managed by hand
	Ports               []ServicePort
	ExternalIPs         []string
	LoadBalancerIngress []string // IPs or hostnames
	LoadBalancerClass   string
	SourceRanges        []string // spec.loadBalancerSourceRanges
	PublishNotReady     bool     // spec.publishNotReadyAddresses
	// Annotations keeps only the keys kubesentry reads (AWS load balancer scheme
	// and type); see internal/kube for the allowlist.
	Annotations map[string]string
	Created     time.Time
	Owner       string // the owner annotation, as on Workload
}

// ServicePort is one port of a Service.
type ServicePort struct {
	Name       string
	Protocol   string
	Port       int32
	TargetPort string // number or named port
	NodePort   int32  // 0 unless NodePort or LoadBalancer
}

// Ingress is a networking.k8s.io/v1 Ingress.
type Ingress struct {
	Namespace      string
	Name           string
	Class          string // spec.ingressClassName, "" when unset
	Rules          []IngressRule
	DefaultBackend string // service name, "" when unset
	TLS            []IngressTLS
	// Annotations keeps only the keys kubesentry reads (ALB scheme, certificate
	// ARN, listen ports); see internal/kube for the allowlist.
	Annotations map[string]string
	Created     time.Time
	Owner       string // the owner annotation, as on Workload
}

// IngressRule is one host/path routed to a service.
type IngressRule struct {
	Host    string // "" matches every host
	Path    string
	Service string
	Port    string // number or name
}

// IngressTLS is one TLS block of an Ingress.
type IngressTLS struct {
	Hosts      []string
	SecretName string
}

// Node is a core/v1 Node.
type Node struct {
	Name                   string
	Roles                  []string // from node-role.kubernetes.io/<role> labels
	Ready                  bool
	Unschedulable          bool
	KubeletVersion         string
	OSImage                string
	ContainerRuntime       string
	CPUAllocatableMilli    int64
	MemoryAllocatableBytes int64
	PodsAllocatable        int64
	Conditions             []Condition
	Taints                 []string // "key=value:Effect"
	// Labels keeps only placement labels (zone, region, instance type, arch, os,
	// node group, Karpenter pool, capacity type, compute type, node roles) plus
	// any keys added with -node-label-keys-add.
	Labels     map[string]string
	ProviderID string // e.g. aws:///us-east-1a/i-0abc...
	InternalIP string
	Created    time.Time
}

// PV is a PersistentVolume.
type PV struct {
	Name           string
	StorageClass   string
	Phase          string // Available, Bound, Released or Failed
	ReclaimPolicy  string // Retain, Delete or Recycle
	CapacityBytes  int64
	AccessModes    []string
	ClaimNamespace string
	ClaimName      string
	Source         string // "csi:<driver>", "hostPath", "local", "nfs", ...
	Driver         string // CSI driver, or the in-tree plugin (e.g. kubernetes.io/aws-ebs)
	VolumeHandle   string // e.g. an EBS vol-... ID
	Created        time.Time
}

// StorageClass is a storage.k8s.io/v1 StorageClass.
type StorageClass struct {
	Name           string
	Provisioner    string
	ReclaimPolicy  string
	BindingMode    string // Immediate or WaitForFirstConsumer
	AllowExpansion bool
	Default        bool              // carries the is-default-class annotation
	Parameters     map[string]string // e.g. type=gp3, iops, throughput
	// PriceAnnotation is the kubesentry.io/price-per-gib-month annotation, "" when unset.
	PriceAnnotation string
	Created         time.Time
}

// Namespace is a core/v1 Namespace.
type Namespace struct {
	Name   string
	Phase  string
	Labels map[string]string
	// Annotations keeps only kubesentry.io/* keys (the owner and alert
	// routing hints) plus the configured owner annotation; see internal/kube
	// for the allowlist.
	Annotations map[string]string
	Created     time.Time
}

// RBAC holds the cluster's roles and bindings.
type RBAC struct {
	Roles    []Role
	Bindings []RoleBinding
}

// Role is a Role or ClusterRole.
type Role struct {
	Kind      string // "Role" or "ClusterRole"
	Namespace string // "" for ClusterRole
	Name      string
	Rules     []PolicyRule
	Owner     string // the owner annotation, as on Workload
}

// PolicyRule is one rule of a Role or ClusterRole.
type PolicyRule struct {
	Verbs           []string
	APIGroups       []string
	Resources       []string
	ResourceNames   []string
	NonResourceURLs []string
}

// RoleBinding is a RoleBinding or ClusterRoleBinding.
type RoleBinding struct {
	Kind      string // "RoleBinding" or "ClusterRoleBinding"
	Namespace string // "" for ClusterRoleBinding
	Name      string
	RoleKind  string // "Role" or "ClusterRole"
	RoleName  string
	Subjects  []Subject
	Owner     string // the owner annotation, as on Workload
}

// Subject is who a binding grants a role to.
type Subject struct {
	Kind      string // "User", "Group" or "ServiceAccount"
	Name      string
	Namespace string // ServiceAccount only
}

// CertManager is the state of cert-manager.io/v1 objects in the cluster.
type CertManager struct {
	Installed    bool // the cert-manager.io/v1 API is served
	Certificates []Certificate
	Issuers      []Issuer // Issuers and ClusterIssuers
	Requests     []CertificateRequest
}

// Certificate is a cert-manager Certificate.
type Certificate struct {
	Namespace   string
	Name        string
	SecretName  string
	CommonName  string
	DNSNames    []string
	IssuerKind  string // "Issuer" (the default) or "ClusterIssuer", or an external kind
	IssuerName  string
	Ready       string // Ready condition status: "True", "False", "Unknown", or "" before the first one
	Reason      string
	Message     string
	NotBefore   time.Time // zero until issued
	NotAfter    time.Time
	RenewalTime time.Time
	Duration    time.Duration // spec.duration; 0 means cert-manager's default (90 days)
	RenewBefore time.Duration // spec.renewBefore; 0 means the default (a third of the duration)
	Created     time.Time
	Owner       string // the owner annotation, as on Workload
}

// Issuer is a cert-manager Issuer or ClusterIssuer.
type Issuer struct {
	Kind      string // "Issuer" or "ClusterIssuer"
	Namespace string // "" for ClusterIssuer
	Name      string
	Type      string // "acme", "ca", "vault", "selfSigned", "venafi", or "unknown"
	Server    string // ACME directory or Vault address, when there is one
	Ready     string
	Reason    string
	Message   string
	Created   time.Time
}

// CertificateRequest is a cert-manager CertificateRequest.
type CertificateRequest struct {
	Namespace   string
	Name        string
	Certificate string // owning Certificate, from the cert-manager.io/certificate-name annotation
	IssuerKind  string
	IssuerName  string
	Ready       string
	Reason      string
	Message     string
	Approved    bool
	Denied      bool
	Created     time.Time
}

// ReplicaSet is kept only to resolve Pod → ReplicaSet → Deployment.
type ReplicaSet struct {
	Namespace string
	Name      string
	UID       string
	Owners    []OwnerRef
	Desired   int32
	Ready     int32
	Created   time.Time
	Revision  string   // deployment.kubernetes.io/revision
	Images    []string // pod template images, containers then init containers
}

// EndpointSlice is a discovery.k8s.io/v1 EndpointSlice, the ground truth for
// which pods back a Service and whether they receive traffic.
type EndpointSlice struct {
	Namespace string
	Name      string
	Service   string // kubernetes.io/service-name label
	ManagedBy string // endpointslice.kubernetes.io/managed-by label
	Endpoints []Endpoint
}

// Endpoint is one address of an EndpointSlice.
type Endpoint struct {
	Addresses   []string
	Ready       bool
	Serving     bool
	Terminating bool
	NodeName    string
	TargetKind  string // usually "Pod"
	TargetName  string
	TargetUID   string
}

// AWSAuth is the parsed kube-system/aws-auth ConfigMap (EKS authentication
// mappings from IAM roles and users to Kubernetes users and groups).
type AWSAuth struct {
	MapRoles []AWSAuthMapping
	MapUsers []AWSAuthMapping
}

// AWSAuthMapping maps one IAM role or user.
type AWSAuthMapping struct {
	ARN      string // rolearn or userarn
	Username string
	Groups   []string
}

// ClusterInfo identifies the cluster kubesentry is looking at.
type ClusterInfo struct {
	Name     string // from -cluster-name; "" when not set
	Version  string // API server git version from discovery
	Platform string // "eks", "kind", ... derived from the version and node provider IDs
	Provider string // providerID scheme of most nodes, e.g. "aws", "kind"
	Region   string // most common topology.kubernetes.io/region across nodes
}

// Inventory is a consistent read of everything the inventory pages need. A
// source that could not be read (for example RBAC is forbidden) is listed in
// Unavailable with the reason, and its slice is empty.
type Inventory struct {
	Pods           []Pod
	PVCs           []PVC
	PVs            []PV
	StorageClasses []StorageClass
	Workloads      []Workload
	ReplicaSets    []ReplicaSet
	Services       []Service
	EndpointSlices []EndpointSlice
	Ingresses      []Ingress
	Nodes          []Node
	Namespaces     []Namespace
	// ServiceAccounts keeps only accounts with an IRSA role annotation.
	ServiceAccounts []ServiceAccount
	// TargetGroupBindings are AWS Load Balancer Controller objects (nil when
	// the CRD is absent).
	TargetGroupBindings []TargetGroupBinding
	RBAC                RBAC
	Certs               CertManager
	AWSAuth             *AWSAuth // nil when not read
	Cluster             ClusterInfo
	Unavailable         map[string]string // source name → reason
	ReadAt              time.Time
}
