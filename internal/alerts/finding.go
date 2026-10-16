// Package alerts turns kubesentry's findings into alerts: an evaluator on
// one replica (the holder of a Postgres advisory lock, or the only replica
// with the memory store) compares the findings of each snapshot view with
// the stored ones, gives each a lifecycle (open, acknowledged, silenced,
// resolved) and an owner from its namespace, and sends them to Alertmanager.
// kubesentry never writes to the cluster: notifying is all it does.
//
// The package is stdlib only (plus kubesentry's own stdlib packages):
// internal/pgstore implements Store on Postgres, cmd/server wires the
// leadership and the sink's authentication.
package alerts

import (
	"maps"
	"strings"
	"time"
)

// Severities, as Alertmanager routes conventionally name them.
const (
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
	// SeverityInfo is the standing digests' (KubesentryStandingDigest); no
	// finding has it.
	SeverityInfo = "info"
)

// State is where a finding is in its lifecycle.
type State string

// States. Acknowledged and silenced come from people (the actions log,
// marks.go); the evaluator opens and resolves.
const (
	StateOpen         State = "open"
	StateAcknowledged State = "acknowledged"
	StateSilenced     State = "silenced" // until SilencedUntil
	StateResolved     State = "resolved"
)

// Alert names (the alertname label).
const (
	AlertCertificateExpiring = "KubesentryCertificateExpiring"
	AlertCertificateNotReady = "KubesentryCertificateNotReady"
	AlertMemoryLeak          = "KubesentryMemoryLeak"
	AlertWorkloadUnhealthy   = "KubesentryWorkloadUnhealthy"
	AlertPodEvicted          = "KubesentryPodEvicted"
	AlertPodStuckTerminating = "KubesentryPodStuckTerminating"
	AlertRBACDrift           = "KubesentryRBACDrift"
	AlertFindingsDigest      = "KubesentryFindingsDigest"
	AlertExposureChange      = "KubesentryExposureChange"
	AlertPrivilegedWorkload  = "KubesentryPrivilegedWorkload"
	AlertAuditActivity       = "KubesentryAuditActivity"
	AlertAgentMissing        = "KubesentryAgentMissing"
	AlertStandingDigest      = "KubesentryStandingDigest"
)

// Checks (the check label). The RBAC drift, exposure and privileged checks
// reuse the security detector's check names.
const (
	CheckLoadBalancer       = "loadbalancer"
	CheckNodePort           = "nodeport"
	CheckExternalIP         = "external-ip"
	CheckIngressNoTLS       = "ingress-no-tls"
	CheckPrivileged         = "privileged"
	CheckHostNamespaces     = "host-namespaces"
	CheckAuditExec          = "audit-exec"
	CheckAuditSecretRead    = "audit-secret-read"
	CheckAuditRBACChange    = "audit-rbac-change"
	CheckAuditImpersonation = "audit-impersonation"
	CheckAuditDeniedBurst   = "audit-denied-burst"
	CheckAuditAnonymous     = "audit-anonymous"
	CheckAgentMissing       = "agent-missing"
)

const (
	CheckCertExpiring        = "cert-expiring"
	CheckCertNotReady        = "cert-not-ready"
	CheckMemoryLeak          = "memory-leak"
	CheckWorkloadUnhealthy   = "workload-unhealthy"
	CheckPodEvicted          = "pod-evicted"
	CheckPodStuckTerminating = "pod-stuck-terminating"
	CheckClusterAdmin        = "cluster-admin"
	CheckAnonymousBinding    = "anonymous-binding"
	CheckWildcardRBAC        = "wildcard-rbac"
	CheckAWSAuthMasters      = "aws-auth-masters"
	CheckDigest              = "digest"
)

// Finding is one problem kubesentry alerts on, with its lifecycle. It is
// stored by Key; Labels are the label set last sent to Alertmanager, so a
// change of severity, owner or routing hint can resolve the old alert.
type Finding struct {
	// Key is stable for the life of the problem: check/kind/namespace/name.
	Key       string `json:"key"`
	Alert     string `json:"alert"`
	Check     string `json:"check"`
	Kind      string `json:"kind"` // the object's kind: Deployment, Certificate, ClusterRoleBinding, ...
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
	Severity  string `json:"severity"` // warning or critical
	Title     string `json:"title"`
	Owner     string `json:"owner"`
	// Production is set when the namespace carries the production label.
	Production  bool              `json:"production"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`

	State         State      `json:"state"`
	SilencedUntil *time.Time `json:"silencedUntil,omitempty"`
	// Digest is set when the finding was announced in a per-owner digest
	// (storm protection) instead of on its own; it then stays in the digest
	// until it resolves, or leaves it when it turns critical.
	Digest bool `json:"digest,omitempty"`

	FirstSeen    time.Time  `json:"firstSeen"`
	LastSeen     time.Time  `json:"lastSeen"`
	LastNotified *time.Time `json:"lastNotified,omitempty"`
	ResolvedAt   *time.Time `json:"resolvedAt,omitempty"`

	// Who acknowledged the current episode, and when; who silenced the
	// finding, when and why. Derived from the actions log (applyMarks) on
	// every replica, never stored with the finding.
	AckBy         string     `json:"ackBy,omitempty"`
	AckAt         *time.Time `json:"ackAt,omitempty"`
	SilencedBy    string     `json:"silencedBy,omitempty"`
	SilencedAt    *time.Time `json:"silencedAt,omitempty"`
	SilenceReason string     `json:"silenceReason,omitempty"`
	// Link is the UI route of the page that explains the finding, e.g.
	// "#/workloads?namespace=shop&q=checkout" (internal/uilink).
	Link string `json:"link,omitempty"`
	// Quiet findings are reported only in a standing digest: never notified
	// on their own, and never counted by storm protection.
	Quiet bool `json:"quiet,omitempty"`
}

// Key builds a finding's dedupe key.
func Key(check, kind, namespace, name string) string {
	return check + "/" + kind + "/" + namespace + "/" + name
}

// Resolved reports whether the finding is closed.
func (f *Finding) Resolved() bool { return f.State == StateResolved }

// RBAC reports whether the finding is about RBAC, which needs the RBAC
// capabilities to be seen (ViewRBAC in its namespace, ViewClusterRBAC when
// cluster-scoped).
func (f *Finding) RBAC() bool { return f.Gate() == GateRBAC }

// Gate names the capability that, besides the namespace, decides who may
// see a finding (docs/contracts.md, "Visibility by finding kind"):
//
//	gate       namespaced finding              cluster-scoped finding
//	namespace  ViewNamespace                   (ViewNamespace everywhere)
//	rbac       ViewNamespace + ViewRBAC        ViewClusterRBAC
//	audit      ViewNamespace + ViewAudit       ViewClusterAudit
//	node       (ViewNamespace + ViewNodes)     ViewNodes
//	agents     (ViewNamespace + ViewAgents)    ViewAgents
//
// The cases in parentheses do not occur today; internal/api answers them
// failing closed, as shown.
type Gate string

// Gates.
const (
	GateNamespace Gate = "namespace"
	GateRBAC      Gate = "rbac"
	GateAudit     Gate = "audit"
	GateNode      Gate = "node"
	GateAgents    Gate = "agents"
)

// Gate is the finding's gate (GateOf its check and kind).
func (f *Finding) Gate() Gate { return GateOf(f.Check, f.Kind) }

// GateOf maps a check, and the kind of object its finding names, to the
// gate: the RBAC drift checks to rbac, the audit checks (audit-*) to audit,
// the agent check to agents, findings about a Node to node, everything else
// to namespace.
func GateOf(check, kind string) Gate {
	if info, ok := checkInfos[check]; ok && info.gate != "" {
		return info.gate
	}
	switch {
	case strings.HasPrefix(check, "audit-"):
		return GateAudit
	case check == CheckAgentMissing:
		return GateAgents
	case kind == "Node":
		return GateNode
	}
	return GateNamespace
}

// ParseKey splits a dedupe key (Key) into its parts. Checks, kinds and
// namespaces hold no "/", so only the name may; ok is false for anything
// that is not a key.
func ParseKey(key string) (check, kind, namespace, name string, ok bool) {
	parts := strings.SplitN(key, "/", 4)
	if len(parts) != 4 || parts[0] == "" || parts[1] == "" || parts[3] == "" {
		return "", "", "", "", false
	}
	return parts[0], parts[1], parts[2], parts[3], true
}

// incidentURL is the incident link f carries ("" for nil).
func (f *Finding) incidentURL() string {
	if f == nil {
		return ""
	}
	return f.Annotations[AnnotationIncidentURL]
}

// Clone returns a deep copy.
func (f Finding) Clone() Finding {
	f.Labels = maps.Clone(f.Labels)
	f.Annotations = maps.Clone(f.Annotations)
	f.SilencedUntil = cloneTime(f.SilencedUntil)
	f.LastNotified = cloneTime(f.LastNotified)
	f.ResolvedAt = cloneTime(f.ResolvedAt)
	f.AckAt = cloneTime(f.AckAt)
	f.SilencedAt = cloneTime(f.SilencedAt)
	return f
}

func cloneTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := *t
	return &v
}

func timePtr(t time.Time) *time.Time { return &t }

// severityRank orders severities worst first.
func severityRank(s string) int {
	if s == SeverityCritical {
		return 0
	}
	return 1
}

// stateRank orders states as the API lists them: open first, resolved last.
func stateRank(s State) int {
	switch s {
	case StateOpen:
		return 0
	case StateAcknowledged:
		return 1
	case StateSilenced:
		return 2
	}
	return 3
}
