package detectors

import (
	"regexp"
	"sort"
	"strings"

	"github.com/ByronGary/kubesentry/internal/model"
)

// Well-known node labels read for placement.
const (
	labelZone          = "topology.kubernetes.io/zone"
	labelZoneBeta      = "failure-domain.beta.kubernetes.io/zone"
	labelRegion        = "topology.kubernetes.io/region"
	labelRegionBeta    = "failure-domain.beta.kubernetes.io/region"
	labelInstance      = "node.kubernetes.io/instance-type"
	labelInstanceBeta  = "beta.kubernetes.io/instance-type"
	labelArch          = "kubernetes.io/arch"
	labelOS            = "kubernetes.io/os"
	labelNodegroup     = "eks.amazonaws.com/nodegroup"
	labelEKSCapacity   = "eks.amazonaws.com/capacityType"
	labelComputeType   = "eks.amazonaws.com/compute-type"
	labelFargateProf   = "eks.amazonaws.com/fargate-profile"
	labelNodePool      = "karpenter.sh/nodepool"
	labelProvisioner   = "karpenter.sh/provisioner-name" // Karpenter before v1beta1
	labelKarpenterCap  = "karpenter.sh/capacity-type"
	nodeRoleLabelStart = "node-role.kubernetes.io/"
)

// Pool kinds.
const (
	PoolNodegroup = "nodegroup"
	PoolKarpenter = "karpenter"
	PoolFargate   = "fargate"
)

// awsZone matches a regular AWS availability zone such as us-east-1a, so the
// region can be read off it when the region label is missing.
var awsZone = regexp.MustCompile(`^([a-z]{2}(?:-gov)?-[a-z]+-\d)[a-z]$`)

// PlacementOf derives where and on what a node runs from its labels and
// providerID: zone, region, instance type, architecture and OS, and the pool
// it belongs to (an EKS managed node group, a Karpenter node pool, or Fargate)
// with its capacity type normalised to "on-demand" or "spot".
func PlacementOf(n model.Node) Placement {
	l := n.Labels
	pl := Placement{
		Zone:         first(l[labelZone], l[labelZoneBeta]),
		Region:       first(l[labelRegion], l[labelRegionBeta]),
		InstanceType: first(l[labelInstance], l[labelInstanceBeta]),
		Arch:         l[labelArch],
		OS:           l[labelOS],
		ProviderID:   n.ProviderID,
	}
	if pl.Zone == "" {
		// aws:///us-east-1a/i-0abc...
		if rest, ok := strings.CutPrefix(n.ProviderID, "aws:///"); ok {
			if zone, _, ok := strings.Cut(rest, "/"); ok {
				pl.Zone = zone
			}
		}
	}
	if pl.Region == "" {
		if m := awsZone.FindStringSubmatch(pl.Zone); m != nil {
			pl.Region = m[1]
		}
	}
	switch {
	case strings.EqualFold(l[labelComputeType], "fargate") || l[labelFargateProf] != "":
		pl.PoolKind, pl.Pool = PoolFargate, l[labelFargateProf]
	case l[labelNodegroup] != "":
		pl.PoolKind, pl.Pool = PoolNodegroup, l[labelNodegroup]
	case l[labelNodePool] != "":
		pl.PoolKind, pl.Pool = PoolKarpenter, l[labelNodePool]
	case l[labelProvisioner] != "":
		pl.PoolKind, pl.Pool = PoolKarpenter, l[labelProvisioner]
	}
	pl.CapacityType = capacityType(first(l[labelEKSCapacity], l[labelKarpenterCap]))
	return pl
}

// capacityType normalises EKS's ON_DEMAND/SPOT and Karpenter's
// on-demand/spot; other values (Karpenter's "reserved") pass through in lower
// case.
func capacityType(v string) string {
	switch strings.ToLower(strings.ReplaceAll(v, "_", "-")) {
	case "":
		return ""
	case "on-demand", "ondemand":
		return "on-demand"
	case "spot":
		return "spot"
	default:
		return strings.ToLower(v)
	}
}

// NodeRoles returns the node's roles from node-role.kubernetes.io labels. EKS
// nodes usually have none, so the pool stands in: "nodegroup:<name>",
// "nodepool:<name>" or "fargate". Never nil.
func NodeRoles(n model.Node) []string {
	if len(n.Roles) > 0 {
		return append([]string{}, n.Roles...)
	}
	var roles []string
	for k := range n.Labels {
		if r, ok := strings.CutPrefix(k, nodeRoleLabelStart); ok && r != "" {
			roles = append(roles, r)
		}
	}
	if len(roles) > 0 {
		sort.Strings(roles)
		return roles
	}
	pl := PlacementOf(n)
	switch pl.PoolKind {
	case PoolNodegroup:
		return []string{"nodegroup:" + pl.Pool}
	case PoolKarpenter:
		return []string{"nodepool:" + pl.Pool}
	case PoolFargate:
		return []string{"fargate"}
	}
	return []string{}
}

func first(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}
