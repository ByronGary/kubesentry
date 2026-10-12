package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/auth"
	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/model"
	"github.com/ByronGary/kubesentry/internal/snapshot"
)

func TestParseDuration(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"30d": 30 * 24 * time.Hour, "1d12h": 36 * time.Hour, "0.5d": 12 * time.Hour, "90m": 90 * time.Minute, "24h": 24 * time.Hour,
	} {
		if got, err := parseDuration(in); err != nil || got != want {
			t.Errorf("%s = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "d", "xd", "30x", "-1d", "1d-1h"} {
		if _, err := parseDuration(bad); err == nil {
			t.Errorf("%q should not parse", bad)
		}
	}
	if s := formatDuration(30 * 24 * time.Hour); s != "30d" {
		t.Errorf("format = %s", s)
	}
}

func TestFlagsDefaults(t *testing.T) {
	c, err := parseFlags(nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if c.addr != "127.0.0.1:8080" || !c.cache || c.kubeQPS != 50 || c.kubeBurst != 100 || c.authMode != "token" ||
		c.authzQPS != 200 || c.authzCacheTTL != 5*time.Minute || c.authzDenyTTL != 5*time.Minute || c.rateLimit != 20 ||
		c.rateBurst != 40 || c.maxInflight != 512 || c.auditStore != "memory" || c.auditRetention != 30*24*time.Hour ||
		c.cloudwatchPrefix != "kube-apiserver-audit" || c.cloudwatchStart != 24*time.Hour || c.snapshotMinInterval != 2*time.Second ||
		c.snapshotMaxDelay != 10*time.Second || c.pvcMinAge != 24*time.Hour || c.authTrustedProxyCIDRs != "127.0.0.1/32,::1/128" {
		t.Errorf("defaults = %+v", c)
	}
	p, err := c.policy()
	if err != nil {
		t.Fatal(err)
	}
	d := detectors.DefaultPolicy()
	if p.OwnerAnnotation != "kubesentry.io/owner" || p.ProductionLabel != (detectors.LabelMatch{Key: "environment", Value: "production"}) ||
		c.namespaceAnnotationKeys() != nil {
		t.Errorf("owner annotation %q, production label %+v, extra annotation keys %v", p.OwnerAnnotation, p.ProductionLabel, c.namespaceAnnotationKeys())
	}
	if p.Thresholds != d.Thresholds || p.Pricing.DefaultPrice != nil || p.Pricing.EBSPrices["gp3"] != 0.08 ||
		strings.Join(p.SystemPrincipalPrefixes, ",") != "system:,eks:" || strings.Join(p.BuiltinRBACPrefixes, ",") != "system:,eks:,kubeadm:" {
		t.Errorf("default policy = %+v", p)
	}
}

func TestFlagsMapOntoPolicy(t *testing.T) {
	t.Setenv("POD_NAMESPACE", "kubesentry")
	c, err := parseFlags([]string{
		"-system-namespaces=kube-system,ops", "-system-namespaces-add=platform",
		"-system-principal-prefixes=system:,eks:,okta:", "-builtin-rbac-prefixes=system:",
		"-restart-warn=5", "-restart-crit=20", "-oom-recent=2d", "-not-ready-grace=10m", "-activity-window=14d", "-cert-warn-cap=45d",
		"-pvc-default-price=0.1", "-pvc-class-prices=fast=0.2", "-ebs-prices=gp3=0.0952,io2=0.149",
		"-audit-retention=90d", "-pvc-min-age=2d", "-owner-annotation=example.com/team", "-production-label=tier=prod",
	}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.policy()
	if err != nil {
		t.Fatal(err)
	}
	ns := p.SystemNamespaces
	if len(ns) != 4 || !ns["kube-system"] || !ns["ops"] || !ns["platform"] || !ns["kubesentry"] {
		t.Errorf("system namespaces = %v", ns)
	}
	th := p.Thresholds
	if th.RestartWarn != 5 || th.RestartCrit != 20 || th.OOMRecent != 48*time.Hour || th.NotReadyGrace != 10*time.Minute ||
		th.ActivityWindow != 14*24*time.Hour || th.CertWarnCap != 45*24*time.Hour || th.PendingGrace != 5*time.Minute {
		t.Errorf("thresholds = %+v", th)
	}
	if *p.Pricing.DefaultPrice != 0.1 || p.Pricing.ClassPrices["fast"] != 0.2 || p.Pricing.EBSPrices["gp3"] != 0.0952 ||
		p.Pricing.EBSPrices["io2"] != 0.149 || p.Pricing.EBSPrices["st1"] != 0.045 {
		t.Errorf("pricing = %+v", p.Pricing)
	}
	if strings.Join(p.SystemPrincipalPrefixes, ",") != "system:,eks:,okta:" || strings.Join(p.BuiltinRBACPrefixes, ",") != "system:" {
		t.Errorf("prefixes = %v %v", p.SystemPrincipalPrefixes, p.BuiltinRBACPrefixes)
	}
	if c.auditRetention != 90*24*time.Hour || c.pvcMinAge != 48*time.Hour {
		t.Errorf("retention %v min age %v", c.auditRetention, c.pvcMinAge)
	}
	// An owner annotation outside kubesentry.io/ is kept by the informers too.
	if p.OwnerAnnotation != "example.com/team" || p.ProductionLabel != (detectors.LabelMatch{Key: "tier", Value: "prod"}) ||
		strings.Join(c.namespaceAnnotationKeys(), ",") != "example.com/team" {
		t.Errorf("owner %q production %+v keys %v", p.OwnerAnnotation, p.ProductionLabel, c.namespaceAnnotationKeys())
	}
	if _, err := parseFlags([]string{"-ebs-prices=gp3"}, io.Discard); err != nil {
		t.Fatal(err) // parsed lazily
	}
	c, _ = parseFlags([]string{"-ebs-prices=gp3"}, io.Discard)
	if _, err := c.policy(); err == nil {
		t.Error("a malformed price list should fail")
	}
}

func TestFlagValidation(t *testing.T) {
	bad := [][]string{
		{"-auth-mode=none", "-addr=:8080"},
		{"-auth-mode=token", "-addr=0.0.0.0:8080", "-api-token="},
		{"-auth-mode=ldap"},
		{"-tls-cert=x"},
		{"-audit-store=sqlite"},
		{"-audit-store=postgres", "-audit-journal=/tmp/j"},
		{"-audit-store=postgres", "-pg-max-conns=2"},
		{"-audit-store=postgres", "-pg-query-timeout=0s"},
		{"-cloudwatch"},
		{"-kube-qps=0"},
		{"-audit-retention=forever"},
		{"-owner-annotation=not a key"},
		{"-owner-annotation="},
		{"-production-label=production"},
		{"-production-label=env=not valid"},
		{"stray"},
	}
	t.Setenv("KUBESENTRY_API_TOKEN", "")
	for _, args := range bad {
		if _, err := parseFlags(args, io.Discard); err == nil {
			t.Errorf("%v should be refused", args)
		}
	}
	good := [][]string{
		{"-auth-mode=none", "-addr=127.0.0.1:9000"},
		{"-auth-mode=none", "-addr=[::1]:9000"},
		{"-auth-mode=token", "-addr=:8080", "-api-token=s3cret"},
		{"-auth-mode=proxy", "-addr=:8080"},
		{"-cloudwatch", "-cluster-name=prod"},
		{"-audit-store=postgres", "-pg-max-conns=20", "-pg-query-timeout=5s"},
		{"-version"},
	}
	for _, args := range good {
		if _, err := parseFlags(args, io.Discard); err != nil {
			t.Errorf("%v: %v", args, err)
		}
	}
}

func TestAuthenticatorModes(t *testing.T) {
	c, _ := parseFlags([]string{"-auth-mode=proxy", "-addr=:8080", "-api-token=s3cret", "-auth-trusted-proxy-cidrs=10.0.0.0/8"}, io.Discard)
	a, err := c.authenticator()
	if err != nil {
		t.Fatal(err)
	}
	if _, isHeader := a.(auth.HeaderAuthenticator); isHeader {
		t.Error("proxy mode with a token should chain the break-glass token")
	}
	c, _ = parseFlags([]string{"-auth-mode=proxy", "-addr=:8080", "-auth-trusted-proxy-cidrs=nonsense"}, io.Discard)
	if _, err := c.authenticator(); err == nil {
		t.Error("bad CIDRs should fail")
	}
	dir := t.TempDir()
	gm := filepath.Join(dir, "groups.json")
	if err := os.WriteFile(gm, []byte(`{"okta-admins": ["platform-admins"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, _ = parseFlags([]string{"-auth-mode=proxy", "-addr=:8080", "-auth-group-map-file=" + gm}, io.Discard)
	a, err = c.authenticator()
	if h, ok := a.(auth.HeaderAuthenticator); err != nil || !ok || len(h.GroupMap["okta-admins"]) != 1 {
		t.Errorf("group map: %v %+v", err, a)
	}
	c, _ = parseFlags([]string{"-auth-mode=token", "-addr=127.0.0.1:8080", "-api-token="}, io.Discard)
	if a, _ := c.authenticator(); a != (auth.NoneAuthenticator{}) {
		t.Errorf("token mode without a token on loopback = %T", a)
	}
}

func TestCgroupMemoryLimit(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	v2 := write("memory.max", "536870912\n")
	v2max := write("v2max", "max\n")
	v1 := write("limit_in_bytes", "268435456\n")
	v1none := write("v1none", "9223372036854771712\n")
	missing := filepath.Join(dir, "missing")
	cases := []struct {
		files []string
		want  int64
	}{
		{[]string{v2, v1}, 512 << 20},
		{[]string{missing, v1}, 256 << 20},
		{[]string{v2max, v1}, 0},
		{[]string{missing, v1none}, 0},
		{[]string{missing}, 0},
	}
	for i, c := range cases {
		if got := cgroupMemoryLimit(c.files); got != c.want {
			t.Errorf("case %d = %d, want %d", i, got, c.want)
		}
	}
}

func TestIsLoopback(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:8080": true, "localhost:8080": true, "[::1]:8080": true, "127.1.2.3:80": true,
		":8080": false, "0.0.0.0:8080": false, "10.0.0.1:8080": false, "[::]:8080": false, "nonsense": false,
	} {
		if got := isLoopback(addr); got != want {
			t.Errorf("%s = %v", addr, got)
		}
	}
}

// The authorizer's candidates follow whichever view is current.
func TestViewCandidatesFollowTheView(t *testing.T) {
	bind := func(ns string) model.Inventory {
		return model.Inventory{RBAC: model.RBAC{
			Roles: []model.Role{{Kind: "ClusterRole", Name: "view", Rules: []model.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"list"}}}}},
			Bindings: []model.RoleBinding{{Kind: "RoleBinding", Namespace: ns, Name: "b", RoleKind: "ClusterRole", RoleName: "view",
				Subjects: []model.Subject{{Kind: "User", Name: "alice"}}}},
		}}
	}
	var cur *snapshot.View
	c := viewCandidates{func() *snapshot.View { return cur }}
	if got := c.Namespaces("alice", nil, auth.ViewNamespace); got != nil {
		t.Errorf("no view yet = %v", got)
	}
	cur = snapshot.Build(bind("a"), detectors.DefaultPolicy(), time.Now())
	if got := c.Namespaces("alice", nil, auth.ViewNamespace); strings.Join(got, ",") != "a" {
		t.Errorf("first view = %v", got)
	}
	cur = snapshot.Build(bind("b"), detectors.DefaultPolicy(), time.Now())
	if got := c.Namespaces("alice", nil, auth.ViewNamespace); strings.Join(got, ",") != "b" {
		t.Errorf("rebuilt view = %v", got)
	}
}
