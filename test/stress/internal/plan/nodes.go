package plan

import (
	"fmt"
	"math/rand/v2"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Pool is a group of nodes as EKS would have them: a managed nodegroup, a
// Karpenter NodePool or Fargate.
type Pool struct {
	Name     string
	Kind     string // "nodegroup", "karpenter" or "fargate"
	Weight   float64
	Capacity string // ON_DEMAND / SPOT (nodegroup) or on-demand / spot (Karpenter)
	Types    []InstanceType
	OS       string
	// Taints besides the KWOK taint every fake node carries.
	Taints []corev1.Taint
}

// InstanceType describes an EC2 instance type's allocatable resources.
type InstanceType struct {
	Name    string
	Arch    string
	CPU     string
	Memory  string
	MaxPods string
}

// Region is the fake AWS region.
const Region = "us-east-1"

// Zones are the fake availability zones.
var Zones = []string{"us-east-1a", "us-east-1b", "us-east-1c"}

// Pool names used elsewhere (DaemonSet node selectors, add-ons).
const (
	PoolGeneral = "ng-general"
	PoolArm     = "ng-arm"
	PoolSystem  = "ng-system"
	PoolSpot    = "default"
	PoolBatch   = "batch"
	PoolFargate = "fargate"
	PoolWindows = "ng-windows"
)

// Pools gives about 30% arm64, 5% Fargate and 1% Windows.
var Pools = []Pool{
	{Name: PoolGeneral, Kind: "nodegroup", Weight: 0.30, Capacity: "ON_DEMAND", OS: "linux",
		Types: []InstanceType{{"m6i.2xlarge", "amd64", "8", "31Gi", "58"}, {"m5.2xlarge", "amd64", "8", "31Gi", "58"}}},
	{Name: PoolArm, Kind: "nodegroup", Weight: 0.18, Capacity: "ON_DEMAND", OS: "linux",
		Types: []InstanceType{{"m7g.2xlarge", "arm64", "8", "31Gi", "58"}}},
	{Name: PoolSystem, Kind: "nodegroup", Weight: 0.05, Capacity: "ON_DEMAND", OS: "linux",
		Types:  []InstanceType{{"m6i.xlarge", "amd64", "4", "15Gi", "58"}},
		Taints: []corev1.Taint{{Key: "CriticalAddonsOnly", Value: "true", Effect: corev1.TaintEffectNoSchedule}}},
	{Name: PoolSpot, Kind: "karpenter", Weight: 0.26, Capacity: "spot", OS: "linux",
		Types: []InstanceType{{"c6i.4xlarge", "amd64", "16", "30Gi", "110"}, {"c7g.4xlarge", "arm64", "16", "30Gi", "110"}}},
	{Name: PoolBatch, Kind: "karpenter", Weight: 0.15, Capacity: "on-demand", OS: "linux",
		Types: []InstanceType{{"r6i.2xlarge", "amd64", "8", "62Gi", "58"}}},
	{Name: PoolFargate, Kind: "fargate", Weight: 0.05, OS: "linux",
		Types:  []InstanceType{{"fargate", "amd64", "2", "4Gi", "8"}},
		Taints: []corev1.Taint{{Key: "eks.amazonaws.com/compute-type", Value: "fargate", Effect: corev1.TaintEffectNoSchedule}}},
	{Name: PoolWindows, Kind: "nodegroup", Weight: 0.01, Capacity: "ON_DEMAND", OS: "windows",
		Types:  []InstanceType{{"m5.2xlarge", "amd64", "8", "31Gi", "58"}},
		Taints: []corev1.Taint{{Key: "os", Value: "windows", Effect: corev1.TaintEffectNoSchedule}}},
}

// KwokTaint keeps real pods off fake nodes.
var KwokTaint = corev1.Taint{Key: "kwok.x-k8s.io/node", Value: "fake", Effect: corev1.TaintEffectNoSchedule}

// NodeSpec is the plan for one fake node.
type NodeSpec struct {
	Index    int
	Name     string
	IP       string
	Zone     string
	Pool     *Pool
	Instance InstanceType
}

// NodeAt returns fake node i. It depends only on i, so levels nest.
func NodeAt(i int) NodeSpec {
	n := 10 + i
	ip := fmt.Sprintf("172.19.%d.%d", 100+n/256, n%256)
	r := rand.New(rand.NewPCG(Seed, 1<<40|uint64(i)))
	w := r.Float64()
	pool := &Pools[0]
	acc := 0.0
	for k := range Pools {
		acc += Pools[k].Weight
		if w < acc {
			pool = &Pools[k]
			break
		}
	}
	it := pool.Types[r.IntN(len(pool.Types))]
	return NodeSpec{
		Index: i, IP: ip,
		Name:     fmt.Sprintf("ip-172-19-%d-%d.ec2.internal", 100+n/256, n%256),
		Zone:     Zones[i%len(Zones)],
		Pool:     pool,
		Instance: it,
	}
}

// Nodes returns the first n fake nodes.
func Nodes(n int) []NodeSpec {
	if n > MaxNodes {
		n = MaxNodes
	}
	out := make([]NodeSpec, n)
	for i := range out {
		out[i] = NodeAt(i)
	}
	return out
}

// Object builds the Node. Addresses, capacity and nodeInfo are set at creation:
// KWOK keeps an existing InternalIP, and an address in the kind network keeps
// kindnet's per-node routes valid.
func (n NodeSpec) Object() *corev1.Node {
	p := n.Pool
	labels := map[string]string{
		"type":                             "kwok",
		"kubesentry.io/stress":             "true",
		"kubernetes.io/hostname":           n.Name,
		"kubernetes.io/arch":               n.Instance.Arch,
		"kubernetes.io/os":                 p.OS,
		"beta.kubernetes.io/arch":          n.Instance.Arch,
		"beta.kubernetes.io/os":            p.OS,
		"topology.kubernetes.io/region":    Region,
		"topology.kubernetes.io/zone":      n.Zone,
		"node.kubernetes.io/instance-type": n.Instance.Name,
	}
	osImage, kernel := "Amazon Linux 2023", "6.1.112-122.189.amzn2023.x86_64"
	if n.Instance.Arch == "arm64" {
		kernel = "6.1.112-122.189.amzn2023.aarch64"
	}
	switch p.Kind {
	case "nodegroup":
		labels["eks.amazonaws.com/nodegroup"] = p.Name
		labels["eks.amazonaws.com/capacityType"] = p.Capacity
		labels["eks.amazonaws.com/nodegroup-image"] = "ami-0" + hexOf(uint64(len(p.Name))*7919, 16)
	case "karpenter":
		labels["karpenter.sh/nodepool"] = p.Name
		labels["karpenter.sh/capacity-type"] = p.Capacity
		labels["karpenter.sh/registered"] = "true"
		labels["karpenter.k8s.aws/instance-category"] = n.Instance.Name[:1]
		osImage = "Bottlerocket OS 1.24.0 (aws-k8s-1.36)"
	case "fargate":
		labels["eks.amazonaws.com/compute-type"] = "fargate"
	}
	if p.OS == "windows" {
		osImage, kernel = "Windows Server 2022 Datacenter", "10.0.20348.2700"
		labels["node.kubernetes.io/windows-build"] = "10.0.20348"
	}
	taints := append([]corev1.Taint{KwokTaint}, p.Taints...)
	res := corev1.ResourceList{
		corev1.ResourceCPU:    resource.MustParse(n.Instance.CPU),
		corev1.ResourceMemory: resource.MustParse(n.Instance.Memory),
		corev1.ResourcePods:   resource.MustParse(n.Instance.MaxPods),
	}
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   n.Name,
			Labels: labels,
			Annotations: map[string]string{
				"kwok.x-k8s.io/node":           "fake",
				"node.alpha.kubernetes.io/ttl": "0",
			},
		},
		Spec: corev1.NodeSpec{
			ProviderID: fmt.Sprintf("aws:///%s/i-0%s", n.Zone, hexOf(uint64(n.Index)+0x5eed, 16)),
			Taints:     taints,
		},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: n.IP},
				{Type: corev1.NodeHostName, Address: n.Name},
			},
			Capacity:    res,
			Allocatable: res.DeepCopy(),
			NodeInfo: corev1.NodeSystemInfo{
				Architecture:            n.Instance.Arch,
				OperatingSystem:         p.OS,
				KubeletVersion:          "v1.36.4-eks-fake",
				KubeProxyVersion:        "v1.36.4-eks-fake",
				ContainerRuntimeVersion: "containerd://2.1.4",
				OSImage:                 osImage,
				KernelVersion:           kernel,
			},
		},
	}
}

// hexOf renders a deterministic hex string of length n derived from v.
func hexOf(v uint64, n int) string {
	r := rand.New(rand.NewPCG(Seed^v, v*0x9e3779b97f4a7c15+1))
	const digits = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = digits[r.IntN(16)]
	}
	return string(b)
}

// PoolCount counts the nodes of a pool among the first n.
func PoolCount(n int, pool string) int {
	c := 0
	for _, s := range Nodes(n) {
		if s.Pool.Name == pool {
			c++
		}
	}
	return c
}
