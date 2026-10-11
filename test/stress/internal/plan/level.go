// Package plan computes, deterministically, every object the generator
// creates for a load level: KWOK fake nodes with EKS labels, team and EKS
// add-on namespaces and their workloads, Services, Ingresses, statically bound
// volumes, RBAC and cert-manager Certificates.
//
// The plan is a pure function of the level, so the same level always yields
// the same objects, and a higher level is a superset of a lower one: node i
// and namespace i look the same at every level, only the counts grow. That
// lets the harness ramp L1 → L4 by creating only what is new.
package plan

import (
	"fmt"
	"sort"
)

// Seed fixes every random choice in the plan.
const Seed uint64 = 20261011

// MaxNodes is the number of fake node addresses in 172.19.100.0/22 that the
// plan hands out (172.19.100.10 .. 172.19.103.255).
const MaxNodes = 1014

// Level is one load level.
type Level struct {
	Name  string `json:"name"`
	Index int    `json:"index"`
	Nodes int    `json:"nodes"` // KWOK fake nodes
	// Pods is the target pod count for the whole cluster, including the
	// DaemonSet pods (kindnet, kube-proxy, kubesentry-agent) that land on every
	// fake node and the tricky association cases.
	Pods int `json:"pods"`
}

var levels = []Level{
	{Name: "L0", Index: 0, Nodes: 6, Pods: 400},
	{Name: "L1", Index: 1, Nodes: 100, Pods: 2000},
	{Name: "L2", Index: 2, Nodes: 250, Pods: 5000},
	{Name: "L3", Index: 3, Nodes: 500, Pods: 10000},
	{Name: "L4", Index: 4, Nodes: 1000, Pods: 20000},
}

// Get returns the named level.
func Get(name string) (Level, error) {
	for _, l := range levels {
		if l.Name == name {
			return l, nil
		}
	}
	names := make([]string, 0, len(levels))
	for _, l := range levels {
		names = append(names, l.Name)
	}
	sort.Strings(names)
	return Level{}, fmt.Errorf("unknown level %q (have %v)", name, names)
}

// Levels returns all levels, smallest first.
func Levels() []Level { return append([]Level(nil), levels...) }

// DaemonSetsOnEveryNode is the number of cluster DaemonSets that tolerate
// everything and so get a fake pod on each Linux fake node: kindnet,
// kube-proxy and kubesentry-agent. Windows nodes get only the agent.
const DaemonSetsOnEveryNode = 3

// TrickyPodsEstimate is roughly how many pods the tricky association cases
// add (300 of them are the wide Service on fake nodes).
const TrickyPodsEstimate = 350
