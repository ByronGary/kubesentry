package alerts

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/snapshot"
	"github.com/ByronGary/kubesentry/internal/uilink"
)

// AgentReports is what the node agents reported, as plain data (cmd/server
// copies it from internal/procmon, which alerts does not import).
type AgentReports struct {
	// Interval is how often agents report (-agent-interval).
	Interval time.Duration
	// Last is when each node's agent last reported, by node name. Nodes
	// whose agents have been silent long enough to be forgotten are absent.
	Last map[string]time.Time
}

// Agent-missing rules.
const (
	// agentMissedIntervals: a node whose agent has not reported for this
	// many intervals is missing.
	agentMissedIntervals = 3
	// agentNodeMinAge: nodes younger than this are not expected to report
	// yet (the agent's pod is still starting).
	agentNodeMinAge = 10 * time.Minute
	// maxAgentNodes bounds the nodes the nodes annotation names.
	maxAgentNodes = 20
)

// SplitDaemonSet splits "namespace/name" (-agent-daemonset); ok is false
// unless both parts are set.
func SplitDaemonSet(s string) (ns, name string, ok bool) {
	ns, name, ok = strings.Cut(s, "/")
	return ns, name, ok && ns != "" && name != "" && !strings.Contains(name, "/")
}

// agentCheck finds the nodes running a pod of the agent DaemonSet whose
// agent has not reported for agentMissedIntervals intervals: one finding
// per DaemonSet, cluster-scoped (its name is "namespace/name"), naming the
// silent nodes. Fargate nodes, NotReady nodes and nodes younger than
// agentNodeMinAge are not expected to report. Without reports (agents
// unknown) or with nodes, pods or DaemonSets unreadable, the check is
// skipped; a DaemonSet missing from the view expects nothing.
func agentCheck(v *snapshot.View, rep *AgentReports, daemonSet string, now time.Time, f *Found) {
	dsNS, dsName, ok := SplitDaemonSet(daemonSet)
	if !ok {
		return
	}
	if rep == nil || unavailable(v, "daemonsets", "pods", "nodes") {
		f.Skipped[CheckAgentMissing] = true
		return
	}
	found := false
	for i := range v.Inv.Workloads {
		w := &v.Inv.Workloads[i]
		if w.Kind == "DaemonSet" && w.Namespace == dsNS && w.Name == dsName {
			found = true
			break
		}
	}
	if !found {
		return
	}
	interval := rep.Interval
	if interval <= 0 {
		interval = 15 * time.Second
	}
	nodes := make(map[string]int, len(v.Inv.Nodes))
	for i := range v.Inv.Nodes {
		nodes[v.Inv.Nodes[i].Name] = i
	}
	silent := map[string]bool{}
	for _, p := range v.Assoc().PodsOf(detectors.Ref{Kind: "DaemonSet", Namespace: dsNS, Name: dsName}) {
		if p.NodeName == "" || !p.DeletedAt.IsZero() || p.Phase == "Succeeded" || p.Phase == "Failed" {
			continue
		}
		i, ok := nodes[p.NodeName]
		if !ok {
			continue
		}
		n := v.Inv.Nodes[i]
		if !n.Ready || now.Sub(n.Created) < agentNodeMinAge || detectors.PlacementOf(n).PoolKind == detectors.PoolFargate {
			continue
		}
		if last, ok := rep.Last[n.Name]; ok && now.Sub(last) <= agentMissedIntervals*interval {
			continue
		}
		silent[n.Name] = true
	}
	if len(silent) == 0 {
		return
	}
	names := make([]string, 0, len(silent))
	for n := range silent {
		names = append(names, n)
	}
	sort.Strings(names)
	ds := dsNS + "/" + dsName
	c := Candidate{
		Check: CheckAgentMissing, Kind: "DaemonSet", Name: ds, Severity: SeverityWarning, Link: uilink.Agents(),
		Extra: map[string]string{"nodes": strings.Join(firstN(names, maxAgentNodes), ","), "count": strconv.Itoa(len(names))},
	}
	more := ""
	if len(names) > maxAgentNodes {
		more = fmt.Sprintf(" and %d more", len(names)-maxAgentNodes)
	}
	if len(names) == 1 {
		c.Node = names[0]
		c.Title = "Agent DaemonSet " + ds + ": node " + names[0] + " is not reporting"
	} else {
		c.Title = fmt.Sprintf("Agent DaemonSet %s: %d nodes are not reporting", ds, len(names))
	}
	c.Description = fmt.Sprintf("The kubesentry agent on %s %s%s has not reported for %s (%d report intervals), though %s a pod of DaemonSet %s: process data for %s is missing or stale. Check the agent pod there (crash loop, OOM kill, network policy, the ingest token).",
		plural(len(names), "node", "nodes"), strings.Join(firstN(names, maxAgentNodes), ", "), more, (agentMissedIntervals * interval).String(),
		agentMissedIntervals, plural(len(names), "the node runs", "each runs"), ds, plural(len(names), "its pods", "their pods"))
	f.Candidates = append(f.Candidates, c)
}
