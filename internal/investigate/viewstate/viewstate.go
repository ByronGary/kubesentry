// Package viewstate reads an incident's current workload state from the
// snapshot view, for the investigator's get_workload_state tool. The server
// (cmd/server) and the demo (internal/demo) share it. It lives outside
// package investigate, which stays free of the snapshot package.
package viewstate

import (
	"errors"
	"sort"

	"github.com/ByronGary/kubesentry/internal/incidents"
	"github.com/ByronGary/kubesentry/internal/investigate"
	"github.com/ByronGary/kubesentry/internal/snapshot"
)

// Of returns the incident subject's workload, its pods (and the pods the
// incident names) and the nodes they run on; for a node incident, the node
// alone (the pods on it may belong to namespaces the starter cannot see).
// The view is shared and read-only: values are copied, never changed.
func Of(v *snapshot.View, in *incidents.Incident) (*investigate.WorkloadState, error) {
	if v == nil {
		return nil, errors.New("no cluster view yet")
	}
	st := &investigate.WorkloadState{At: v.Built}
	sub := in.Subject
	nodes := map[string]bool{}
	switch {
	case sub.Kind == incidents.KindNode:
		nodes[sub.Name] = true
	case sub.Namespace != "":
		for i := range v.Inv.Workloads {
			if w := &v.Inv.Workloads[i]; w.Namespace == sub.Namespace && w.Kind == sub.Kind && w.Name == sub.Name {
				c := *w
				st.Workload = &c
				break
			}
		}
		named := map[string]bool{}
		for _, p := range in.Pods {
			named[p] = true
		}
		a := v.Assoc()
		for _, p := range a.PodsIn(sub.Namespace) {
			kind, name := a.RootOf(p)
			if (kind == sub.Kind && name == sub.Name) || named[p.Name] {
				st.Pods = append(st.Pods, *p)
				if p.NodeName != "" {
					nodes[p.NodeName] = true
				}
			}
		}
		sort.Slice(st.Pods, func(i, j int) bool { return st.Pods[i].Name < st.Pods[j].Name })
	}
	for _, n := range v.Inv.Nodes {
		if nodes[n.Name] {
			st.Nodes = append(st.Nodes, n)
		}
	}
	return st, nil
}
