package main

import (
	"errors"
	"io"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/alerts"
	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/model"
	"github.com/ByronGary/kubesentry/internal/procmon"
	"github.com/ByronGary/kubesentry/internal/snapshot"
)

func TestAlertsCatalogFlags(t *testing.T) {
	c, err := parseFlags(nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	a := c.alerts
	if a.disableChecks != "" || a.auditChecks != "all" || a.auditProdOnly != "audit-exec,audit-secret-read" || a.auditHold != time.Hour ||
		a.auditDeniedBurst != 20 || a.auditDeniedWindow != 10*time.Minute || a.agents != "auto" || a.agentDaemonSet != "" || a.agentFanout ||
		a.digestAt != "" || a.digestTZ != "UTC" || a.digestKinds != "rbac-posture,unused-volumes,certificates" || a.certDigestDays != 14 {
		t.Errorf("defaults = %+v", a)
	}
	bad := [][]string{
		{"-alerts", "-alerts-disable-checks=nodeport,no-such-check"},
		{"-alerts", "-alerts-audit=audit-exec,audit-everything"},
		{"-alerts", "-alerts-audit-production-only=nodeport"},
		{"-alerts", "-alerts-audit-hold=5m"},
		{"-alerts", "-alerts-audit-hold=48h"},
		{"-alerts", "-alerts-audit-denied-burst=1"},
		{"-alerts", "-alerts-audit-denied-window=0s"},
		{"-alerts", "-alerts-audit-denied-window=2h"},
		{"-alerts", "-alerts-cert-digest-days=0"},
		{"-alerts", "-alerts-digest-at=Funday 09:00"},
		{"-alerts", "-alerts-digest-at=9am"},
		{"-alerts", "-alerts-digest-at=09:00", "-alerts-digest-tz=Mars/Base"},
		{"-alerts", "-alerts-digest-kinds=rbac-posture,cost-report"},
		{"-alerts", "-alerts-agents=maybe"},
		{"-alerts", "-alerts-agents=on", "-agent-token=t"},                               // no DaemonSet
		{"-alerts", "-alerts-agents=on", "-agent-daemonset=kubesentry/kubesentry-agent"}, // no token
		{"-alerts", "-agent-daemonset=kubesentry-agent"},                                 // no namespace
		{"-alerts", "-agent-daemonset=kubesentry/Agent_1"},                               // not a name
		{"-alerts", "-agent-daemonset=kube/sentry/agent"},
	}
	for _, args := range bad {
		if _, err := parseFlags(args, io.Discard); err == nil {
			t.Errorf("%v should be refused", args)
		}
	}
	good := [][]string{
		{"-alerts", "-alerts-disable-checks=nodeport, ingress-no-tls", "-alerts-audit=none", "-alerts-audit-production-only="},
		{"-alerts", "-alerts-audit=audit-exec,audit-anonymous", "-alerts-audit-hold=2h", "-alerts-audit-denied-burst=50", "-alerts-audit-denied-window=30m"},
		{"-alerts", "-alerts-digest-at=Mon 09:00", "-alerts-digest-tz=Europe/Berlin", "-alerts-digest-kinds=certificates", "-alerts-cert-digest-days=21"},
		{"-alerts", "-alerts-digest-at=08:30", "-alerts-digest-kinds="},
		{"-alerts", "-alerts-agents=on", "-agent-daemonset=kubesentry/kubesentry-agent", "-agent-token=t"},
		{"-alerts", "-alerts-agents=off", "-agent-daemonset=monitoring/kubesentry.agent"},
	}
	for _, args := range good {
		if _, err := parseFlags(args, io.Discard); err != nil {
			t.Errorf("%v: %v", args, err)
		}
	}
}

// -alerts-agents=auto runs agent-missing only where every agent report
// reaches this replica: the memory store's one replica, or -agent-fanout.
// The catalog turns off the audit checks without an audit store, and those
// -alerts-audit leaves out.
func TestAlertsCatalogResolution(t *testing.T) {
	const ds = "-agent-daemonset=kubesentry/kubesentry-agent"
	for _, c := range []struct {
		args []string
		on   bool
	}{
		{[]string{ds, "-agent-token=t"}, true},
		{[]string{ds, "-agent-token=t", "-audit-store=postgres"}, false}, // several replicas may each hear only some agents
		{[]string{ds, "-agent-token=t", "-audit-store=postgres", "-agent-fanout"}, true},
		{[]string{"-agent-token=t"}, false},
		{[]string{ds}, false},
		{[]string{ds, "-agent-token=t", "-alerts-agents=off"}, false},
		{[]string{ds, "-agent-token=t", "-audit-store=postgres", "-alerts-agents=on"}, true},
	} {
		cfg, err := parseFlags(append([]string{"-alerts"}, c.args...), io.Discard)
		if err != nil {
			t.Fatalf("%v: %v", c.args, err)
		}
		if got := cfg.alerts.agentsOn(cfg); got != c.on {
			t.Errorf("%v: agents on = %v", c.args, got)
		}
		o, err := alertsSetup{cfg: cfg, procs: procmon.NewStore()}.catalog()
		if err != nil {
			t.Fatal(err)
		}
		if (o.AgentDaemonSet != "") != c.on || o.Disabled[alerts.CheckAgentMissing] == c.on {
			t.Errorf("%v: daemonset %q, disabled %v", c.args, o.AgentDaemonSet, o.Disabled)
		}
		// No audit store: every audit check is off.
		for _, check := range alerts.AuditChecks() {
			if !o.Disabled[check] {
				t.Errorf("%v: %s runs without an audit store", c.args, check)
			}
		}
	}

	cfg, err := parseFlags([]string{"-alerts", "-alerts-audit=audit-exec,audit-rbac-change", "-alerts-disable-checks=nodeport",
		"-alerts-audit-production-only=audit-exec", "-alerts-digest-at=Mon 09:00", "-alerts-digest-kinds=certificates", "-pvc-min-age=48h"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	o, err := alertsSetup{cfg: cfg, audit: audit.NewMemoryStore(10).AsStore()}.catalog()
	if err != nil {
		t.Fatal(err)
	}
	var off []string
	for c := range o.Disabled {
		off = append(off, c)
	}
	sort.Strings(off)
	if strings.Join(off, ",") != "agent-missing,audit-anonymous,audit-denied-burst,audit-impersonation,audit-secret-read,nodeport" {
		t.Errorf("disabled %v", off)
	}
	if !o.Audit.ProductionOnly[alerts.CheckAuditExec] || len(o.Audit.ProductionOnly) != 1 || o.Audit.Redact == nil ||
		o.Audit.Redact("token=abc123") == "token=abc123" {
		t.Errorf("audit options %+v", o.Audit)
	}
	if !o.Digests.Schedule.Enabled() || strings.Join(o.Digests.Kinds, ",") != "certificates" || o.Digests.CertDays != 14 || o.Digests.PVCMinAge != 48*time.Hour {
		t.Errorf("digests %+v", o.Digests)
	}
}

// The audit store goes into each evaluation only while it is healthy; the
// agents' reports are copied as plain data.
func TestAlertsInput(t *testing.T) {
	v := snapshot.Build(model.Inventory{}, detectors.DefaultPolicy(), time.Now())
	var health error
	procs := procmon.NewStore()
	procs.Update(procmon.Report{Node: "n1"})
	s := alertsSetup{current: func() *snapshot.View { return v },
		leaks:       func() (detectors.LeakReport, time.Duration, bool) { return detectors.LeakReport{}, 0, false },
		audit:       audit.NewMemoryStore(10).AsStore(),
		auditHealth: func() error { return health },
		procs:       procs}
	in, ok := s.input(true)
	if !ok || in.Audit == nil || in.Agents == nil || in.Agents.Interval != 15*time.Second || in.Agents.Last["n1"].IsZero() {
		t.Fatalf("input %+v", in)
	}
	health = errors.New("postgres: connection refused")
	if in, _ := s.input(false); in.Audit != nil || in.Agents != nil {
		t.Errorf("with the store down and agents off: %+v", in)
	}
}
