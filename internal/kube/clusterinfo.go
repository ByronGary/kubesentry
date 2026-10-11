package kube

import (
	"strings"

	"github.com/ByronGary/kubesentry/internal/model"
)

// clusterInfo identifies the cluster from the API server version and the
// nodes: Provider is the most common providerID scheme (aws, kind, gce,
// azure, ...), Region the most common topology.kubernetes.io/region label.
// Platform is "eks" for an EKS version string or AWS nodes, "kind" for kind
// nodes, otherwise the provider, or "kubernetes" when nothing is known.
func clusterInfo(name, version string, nodes []model.Node) model.ClusterInfo {
	providers := map[string]int{}
	regions := map[string]int{}
	for _, n := range nodes {
		if scheme, _, ok := strings.Cut(n.ProviderID, "://"); ok && scheme != "" {
			providers[scheme]++
		}
		if r := n.Labels[regionLabel]; r != "" {
			regions[r]++
		}
	}
	info := model.ClusterInfo{Name: name, Version: version, Provider: mostCommon(providers), Region: mostCommon(regions)}
	switch {
	case strings.Contains(version, "-eks-") || info.Provider == "aws":
		info.Platform = "eks"
	case info.Provider == "kind":
		info.Platform = "kind"
	case info.Provider != "":
		info.Platform = info.Provider
	default:
		info.Platform = "kubernetes"
	}
	return info
}

// mostCommon returns the key with the highest count; ties go to the smaller key.
func mostCommon(counts map[string]int) string {
	best, bestN := "", 0
	for k, n := range counts {
		if n > bestN || (n == bestN && k < best) {
			best, bestN = k, n
		}
	}
	return best
}
