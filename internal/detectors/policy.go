package detectors

import "time"

// Policy is every judgement kubesentry makes that someone might want to tune.
// Nothing in it is specific to one cluster: each field has a server flag and a
// Helm value, and some can also be set from the cluster itself (the
// kubesentry.io/system namespace label, the kubesentry.io/price-per-gib-month
// StorageClass annotation). DefaultPolicy matches kubesentry's behaviour on
// EKS and kind out of the box.
type Policy struct {
	// SystemNamespaces are cluster plumbing: their findings are marked System and
	// hidden by default. kubesentry's own namespace is added at startup.
	SystemNamespaces map[string]bool
	// SystemNamespaceLabel on a namespace overrides SystemNamespaces: "true"
	// adds the namespace, "false" removes it.
	SystemNamespaceLabel string
	// SystemPrincipalPrefixes mark users and groups that are Kubernetes or cloud
	// components rather than people (system:..., eks:...). The everyone groups
	// (system:authenticated, system:unauthenticated, system:anonymous,
	// system:serviceaccounts) never count as system.
	SystemPrincipalPrefixes []string
	// BuiltinRBACPrefixes mark Roles and bindings the platform creates
	// (system:..., eks:..., kubeadm:...). Their findings are kept but System.
	BuiltinRBACPrefixes []string
	Thresholds          Thresholds
	Pricing             Pricing
	Leak                LeakOptions
	// OwnerAnnotation on a namespace names the team that owns it, for the
	// Overview's owner filter and attention items (and alert routing).
	// Empty means DefaultOwnerAnnotation.
	OwnerAnnotation string
	// ProductionLabel marks the namespaces that count as production, e.g.
	// for "exec into production". The zero value means
	// DefaultProductionLabel.
	ProductionLabel LabelMatch
}

// LabelMatch is one key=value label requirement.
type LabelMatch struct {
	Key   string
	Value string
}

// DefaultOwnerAnnotation is the namespace annotation naming its owner.
const DefaultOwnerAnnotation = "kubesentry.io/owner"

// DefaultProductionLabel marks production namespaces.
var DefaultProductionLabel = LabelMatch{Key: "environment", Value: "production"}

// Thresholds are the cut-offs between ok, warn and crit.
type Thresholds struct {
	RestartWarn      int32         // restarts summed over a pod's containers
	RestartCrit      int32         //
	OOMRecent        time.Duration // an OOM kill within this is crit, older is warn
	PendingGrace     time.Duration // pods, claims and certificate requests pending longer warn
	NotReadyGrace    time.Duration // a running pod not ready longer than this warns
	TerminatingGrace time.Duration // a pod terminating longer than grace period + this warns
	RecentPod        time.Duration // finished pods newer than this still show on the map
	ActivityWindow   time.Duration // audit look-back for the pod page's activity check
	LeakCritHours    float64       // memory reaching its limit sooner than this is crit
	// Certificates are judged against their own lifetime, so short-lived
	// certificates are not always critical: crit when the time left is below
	// min(CertCritCap, CertCritFraction × duration), warn below
	// min(CertWarnCap, CertWarnFraction × duration), and warn when renewal is
	// overdue by more than CertRenewalGrace.
	CertCritCap      time.Duration
	CertCritFraction float64
	CertWarnCap      time.Duration
	CertWarnFraction float64
	CertRenewalGrace time.Duration
}

// Pricing estimates what an unused volume costs. A price comes, in order, from
// the StorageClass's kubesentry.io/price-per-gib-month annotation, then
// ClassPrices (keyed by StorageClass name), then EBSPrices (keyed by the EBS
// parameters.type) for EBS provisioners, then DefaultPrice. Volumes from
// UsageBilled provisioners (EFS, FSx) are billed on usage, not size, and get
// no estimate.
type Pricing struct {
	ClassPrices     map[string]float64 // USD per GiB-month by StorageClass name
	EBSPrices       map[string]float64 // USD per GiB-month by EBS volume type
	EBSProvisioners []string
	UsageBilled     []string // provisioners billed on bytes used
	DefaultPrice    *float64 // nil: no estimate for classes nothing else prices
}

// Price sources reported with each cost estimate.
const (
	PriceFromAnnotation = "annotation"   // the StorageClass annotation
	PriceFromClassFlag  = "class-price"  // -pvc-class-prices
	PriceFromEBSTable   = "ebs-table"    // EBSPrices by parameters.type
	PriceFromDefault    = "default"      // -pvc-default-price
	PriceUsageBilled    = "usage-billed" // EFS, FSx: no size-based estimate
	PriceUnknown        = "unknown"      // nothing prices this class
)

// DefaultPolicy returns the built-in policy. EBS prices are us-east-1 list
// prices per GiB-month for storage only (gp3 IOPS and throughput above the
// baseline are extra); override them per region with -ebs-prices.
func DefaultPolicy() Policy {
	return Policy{
		SystemNamespaces: map[string]bool{
			"kube-system": true, "kube-public": true, "kube-node-lease": true,
			"local-path-storage": true, // kind
			"amazon-cloudwatch":  true, "amazon-guardduty": true, "aws-observability": true, "karpenter": true,
		},
		SystemNamespaceLabel:    "kubesentry.io/system",
		SystemPrincipalPrefixes: []string{"system:", "eks:"},
		BuiltinRBACPrefixes:     []string{"system:", "eks:", "kubeadm:"},
		Thresholds: Thresholds{
			RestartWarn:      3,
			RestartCrit:      10,
			OOMRecent:        24 * time.Hour,
			PendingGrace:     5 * time.Minute,
			NotReadyGrace:    5 * time.Minute,
			TerminatingGrace: 5 * time.Minute,
			RecentPod:        24 * time.Hour,
			ActivityWindow:   7 * 24 * time.Hour,
			LeakCritHours:    6,
			CertCritCap:      7 * 24 * time.Hour,
			CertCritFraction: 0.1,
			CertWarnCap:      30 * 24 * time.Hour,
			CertWarnFraction: 1.0 / 3,
			CertRenewalGrace: time.Hour,
		},
		Pricing: Pricing{
			EBSPrices:       map[string]float64{"gp3": 0.08, "gp2": 0.10, "io1": 0.125, "io2": 0.125, "st1": 0.045, "sc1": 0.015, "standard": 0.05},
			EBSProvisioners: []string{"ebs.csi.aws.com", "ebs.csi.eks.amazonaws.com", "kubernetes.io/aws-ebs"},
			UsageBilled:     []string{"efs.csi.aws.com", "fsx.csi.aws.com", "fsx.openzfs.csi.aws.com"},
		},
		Leak:            DefaultLeakOptions(),
		OwnerAnnotation: DefaultOwnerAnnotation,
		ProductionLabel: DefaultProductionLabel,
	}
}
