package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/runtime"

	"github.com/ByronGary/kubesentry/test/stress/internal/chaos"
	"github.com/ByronGary/kubesentry/test/stress/internal/cwserve"
	"github.com/ByronGary/kubesentry/test/stress/internal/gen"
	"github.com/ByronGary/kubesentry/test/stress/internal/kc"
	"github.com/ByronGary/kubesentry/test/stress/internal/ks"
	"github.com/ByronGary/kubesentry/test/stress/internal/oidc"
	"github.com/ByronGary/kubesentry/test/stress/internal/out"
	"github.com/ByronGary/kubesentry/test/stress/internal/personas"
	"github.com/ByronGary/kubesentry/test/stress/internal/plan"
	"github.com/ByronGary/kubesentry/test/stress/internal/verify"
)

// cmdOIDC serves the test issuer's discovery and JWKS.
func cmdOIDC(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("oidc", flag.ExitOnError)
	listen := fs.String("listen", ":8443", "listen address (HTTPS, self-signed)")
	issuer := fs.String("issuer", oidc.Issuer, "issuer URL (must match the iss claim and oauth2-proxy's --oidc-issuer-url)")
	keyFile := fs.String("key-file", "/etc/oidc/key.pem", "PEM signing key")
	_ = fs.Parse(args)
	b, err := os.ReadFile(*keyFile)
	if err != nil {
		return err
	}
	k, err := oidc.ParseKey(b)
	if err != nil {
		return err
	}
	host := strings.TrimPrefix(strings.TrimPrefix(*issuer, "https://"), "http://")
	host, _, _ = strings.Cut(host, "/")
	host, _, _ = strings.Cut(host, ":")
	tlsCfg, err := oidc.SelfSignedTLS(host, "oidc", "localhost")
	if err != nil {
		return err
	}
	srv := &http.Server{Addr: *listen, Handler: oidc.Handler(*issuer, k), ReadHeaderTimeout: 10 * time.Second, TLSConfig: tlsCfg}
	go func() { <-ctx.Done(); _ = srv.Close() }()
	out.Logf("oidc: issuer %s, key %s, on %s (TLS)", *issuer, k.ID, *listen)
	if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// cmdOIDCKey creates the issuer's signing key Secret if it is missing.
func cmdOIDCKey(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("oidc-key", flag.ExitOnError)
	var kf kc.Flags
	kf.Register(fs, 20, 40)
	_ = fs.Parse(args)
	c, err := kf.Connect()
	if err != nil {
		return err
	}
	k, err := oidc.LoadOrCreate(ctx, c.CS, oidc.Namespace, oidc.SecretName)
	if err != nil {
		return err
	}
	out.Logf("oidc signing key %s in %s/%s", k.ID, oidc.Namespace, oidc.SecretName)
	return nil
}

// cmdPersonas applies the persona RBAC and prints the persona list.
func cmdPersonas(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("personas", flag.ExitOnError)
	var kf kc.Flags
	kf.Register(fs, 100, 200)
	level := fs.String("level", "L3", "level whose team namespaces the personas use")
	n := fs.Int("n", 100, "personas (plus the two edge cases)")
	apply := fs.Bool("apply", false, "create the RoleBindings and ClusterRoleBindings")
	outFile := fs.String("out", "", "write the persona list as JSON")
	_ = fs.Parse(args)
	l, err := plan.Get(*level)
	if err != nil {
		return err
	}
	p := plan.Build(l)
	ps := personas.Build(p.Stats.TeamNamespaces, *n)
	if *apply {
		c, err := kf.Connect()
		if err != nil {
			return err
		}
		a := &gen.Applier{CS: c.CS, Dyn: c.Dyn, Workers: 32, Batch: 1000}
		objs := personas.RBAC(p.Stats.TeamNamespaces)
		a.Apply(ctx, "persona RBAC", append([]runtime.Object(nil), objs...))
		for _, e := range a.Errors() {
			out.Logf("error: %s", e)
		}
	}
	if *outFile != "" {
		b, _ := json.MarshalIndent(ps, "", "  ")
		return os.WriteFile(*outFile, b, 0o644)
	}
	return nil
}

func cwOptions(fs *flag.FlagSet) *cwserve.Options {
	o := &cwserve.Options{}
	fs.StringVar(&o.LogGroup, "log-group", "/aws/eks/kind-kubesentry/cluster", "log group")
	fs.Int64Var(&o.Events, "events", 1_000_000, "audit events")
	fs.Float64Var(&o.Rate, "rate", 500, "events per second")
	fs.Float64Var(&o.Duplicates, "duplicates", 0.005, "share logged twice")
	fs.Float64Var(&o.Late, "late", 0.01, "share delivered 3 minutes late")
	fs.Int64Var(&o.Seed, "seed", 2026, "seed")
	return o
}

// cmdCWFake serves the CloudWatch Logs fake.
func cmdCWFake(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("cwfake", flag.ExitOnError)
	o := cwOptions(fs)
	fs.StringVar(&o.Listen, "listen", ":8080", "listen address")
	start := fs.String("start", "", "RFC 3339 time of event 0")
	_ = fs.Parse(args)
	t, err := time.Parse(time.RFC3339, *start)
	if err != nil {
		return err
	}
	o.Start = t
	return cwserve.Serve(ctx, *o)
}

// cmdVerifyCloudWatch checks that every cwfake event is in Postgres once (host side).
func cmdVerifyCloudWatch(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("verify-cloudwatch", flag.ExitOnError)
	o := cwOptions(fs)
	start := fs.String("start", "", "RFC 3339 time of event 0 (as given to cwfake)")
	kctx := fs.String("context", "kind-kubesentry", "kube context")
	grace := fs.Duration("grace", 4*time.Minute, "ignore events newer than this (ingest delay, late delivery)")
	window := fs.Duration("window", 2*time.Hour, "check only events of the last window (0: all; an endless tail is held in memory)")
	dir := fs.String("out", "", "write cloudwatch.json here")
	name := fs.String("name", "cloudwatch", "result file name")
	_ = fs.Parse(args)
	t, err := time.Parse(time.RFC3339, *start)
	if err != nil {
		return err
	}
	o.Start = t
	res, err := cwserve.Verify(ctx, *o, *kctx, "stress-pg", "postgres-0", "kubesentry", *grace, *window)
	if err != nil {
		return err
	}
	out.Logf("cloudwatch: %d expected, %d found, %d missing, %d duplicated, newest stored %s (lag %.0fs), complete=%v",
		res.Expected, res.Found, res.Missing, res.Duplicated, res.NewestStored.Format(time.RFC3339), res.LagSeconds, res.Complete)
	if *dir != "" {
		return out.WriteJSON(*dir, *name+".json", res)
	}
	return nil
}

// cmdToken prints a bearer JWT for one identity (debugging and host-side checks).
func cmdToken(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("token", flag.ExitOnError)
	var kf kc.Flags
	kf.Register(fs, 20, 40)
	email := fs.String("email", "admin0@corp.example", "email claim")
	groups := fs.String("groups", "stress:admins", "comma-separated groups claim")
	ttl := fs.Duration("ttl", 12*time.Hour, "lifetime")
	_ = fs.Parse(args)
	c, err := kf.Connect()
	if err != nil {
		return err
	}
	k, err := oidc.Load(ctx, c.CS, oidc.Namespace, oidc.SecretName)
	if err != nil {
		return err
	}
	var gs []string
	if *groups != "" {
		gs = strings.Split(*groups, ",")
	}
	tok, err := k.Mint(oidc.Issuer, oidc.Audience, oidc.Claims{Email: *email, Groups: gs, TTL: *ttl}, time.Now())
	if err != nil {
		return err
	}
	_, err = os.Stdout.WriteString(tok + "\n")
	return err
}

// cmdVerifyAuthz checks per-user scoping: 0 items outside each persona's RBAC.
func cmdVerifyAuthz(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("verify authz", flag.ExitOnError)
	var c common
	c.register(fs, 100, 200)
	level := fs.String("level", "L3", "level whose team namespaces the personas use")
	perKind := fs.String("per-kind", "admin=2,viewer=3,team=8,many-groups=1,no-grants=1", "personas sampled per kind")
	name := fs.String("name", "authz", "result file name (authz.json, authz.md)")
	_ = fs.Parse(args)
	cl, err := c.kube.Connect()
	if err != nil {
		return err
	}
	l, err := plan.Get(*level)
	if err != nil {
		return err
	}
	want := map[string]int{}
	for _, kv := range splitList(*perKind) {
		k, v, _ := strings.Cut(kv, "=")
		var n int
		fmt.Sscan(v, &n)
		want[k] = n
	}
	var sample []personas.Persona
	for _, p := range personas.Build(plan.Build(l).Stats.TeamNamespaces, 100) {
		if want[p.Kind] > 0 {
			sample = append(sample, p)
			want[p.Kind]--
		}
	}
	res, err := verify.Authz(ctx, cl.CS, verify.AuthzOptions{
		Client: c.client(32), Sample: sample, Timeout: c.timeout,
		Mint: func(email string, groups []string) (ks.Identity, error) { return c.jwt(ctx, cl, email, groups) },
	})
	if err != nil {
		return err
	}
	if err := out.WriteJSON(c.outDir, *name+".json", res); err != nil {
		return err
	}
	out.Logf("authz: %d personas, %d leaks, %d problems", len(res.Personas), res.Leaks, res.Problems)
	return out.WriteText(c.outDir, *name+".md", res.Markdown())
}

// cmdChaos runs the chaos smoke set (host side).
func cmdChaos(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("chaos", flag.ExitOnError)
	var kf kc.Flags
	kf.Register(fs, 300, 600)
	scen := fs.String("scenarios", "spoof,oversize,prometheus,postgres,apiserver,killreplica,standby", "scenarios, in order")
	dir := fs.String("out", "", "write chaos.json and chaos.md here")
	cw := cwOptions(fs)
	cwStart := fs.String("cw-start", "", "START of the live cwfake tail (RFC 3339)")
	pgDown := fs.Duration("pg-down", 2*time.Minute, "how long Postgres stays down")
	rate := fs.Float64("firehose-rate", 1000, "audit events per second during the Postgres outage")
	dur := fs.Duration("firehose-for", 4*time.Minute, "firehose duration")
	name := fs.String("name", "chaos", "result file name (chaos.json, chaos.md)")
	stopNode := fs.String("stop-node", "kubesentry-worker", "workerstop: kind node container to stop")
	stopFor := fs.Duration("stop-for", 3*time.Minute, "workerstop: how long it stays stopped")
	drainNode := fs.String("drain-node", "kubesentry-worker3", "drain: real worker to drain")
	drainSel := fs.String("drain-selector", "app!=kwok-controller", "drain: pods kubectl drain may evict (KWOK's controller stays)")
	level := fs.String("level", "L3", "rbacstorm: level whose team namespaces get the RoleBindings")
	stormN := fs.Int("storm", 2000, "rbacstorm: RoleBindings")
	stormRate := fs.Float64("storm-rate", 30, "rbacstorm: RoleBindings per second in each phase (create, modify, delete)")
	churnRate := fs.Float64("churn-rate", 50, "churn: pods per second")
	churnFor := fs.Duration("churn-for", 5*time.Minute, "churn: duration")
	churnLife := fs.Duration("churn-life", time.Minute, "churn: pod lifetime")
	rollN := fs.Int("rollout-replicas", 1000, "rollout: Deployment replicas")
	nsdelN := fs.Int("nsdelete-pods", 2000, "nsdelete: pods in the namespace")
	usersFile := fs.String("users-file", "", "coldrestart: users result the concurrent load writes (host path)")
	_ = fs.Parse(args)
	c, err := kf.Connect()
	if err != nil {
		return err
	}
	k, err := oidc.Load(ctx, c.CS, oidc.Namespace, oidc.SecretName)
	if err != nil {
		return err
	}
	mint := func(email string, groups []string) string {
		t, _ := k.Mint(oidc.Issuer, oidc.Audience, oidc.Claims{Email: email, Groups: groups}, time.Now())
		return t
	}
	if *cwStart != "" {
		if cw.Start, err = time.Parse(time.RFC3339, *cwStart); err != nil {
			return err
		}
	}
	agentTok, _ := kc.Secret(ctx, c.CS, "kubesentry", "kubesentry-agent", "token")
	auditTok, _ := kc.Secret(ctx, c.CS, "kubesentry", "kubesentry-audit", "token")
	l, err := plan.Get(*level)
	if err != nil {
		return err
	}
	teamN := plan.Build(l).Stats.TeamNamespaces
	var teamNS []string
	for j := 0; j < teamN; j++ {
		teamNS = append(teamNS, plan.NamespaceName(j))
	}
	// Personas whose pod lists are checked for leaks during the RBAC storm:
	// team members (their own namespaces), the 300-group user and nobody.
	var stormPersonas []chaos.StormPersona
	teams := 0
	for _, p := range personas.Build(teamN, 100) {
		if p.Kind == personas.Team && teams < 4 || p.Kind == personas.ManyGroups || p.Kind == personas.NoGrants {
			if p.Kind == personas.Team {
				teams++
			}
			allowed := map[string]bool{}
			for _, ns := range p.Namespaces {
				allowed[ns] = true
			}
			stormPersonas = append(stormPersonas, chaos.StormPersona{Email: p.Email, Token: mint(p.Email, p.Groups), Allowed: allowed})
		}
	}
	res, err := chaos.Run(ctx, chaos.Options{
		CS: c.CS, Context: kf.Context, ProbeNode: "kubesentry-worker5", ControlPlane: "kubesentry-control-plane", Namespace: "kubesentry",
		AdminToken: mint("admin0@corp.example", []string{personas.GroupAdmins}), NobodyToken: mint("nobody@corp.example", nil),
		AgentToken: strings.TrimSpace(agentTok), AuditToken: strings.TrimSpace(auditTok), CW: *cw,
		Scenarios: splitList(*scen), PGDown: *pgDown, FirehoseRate: *rate, FirehoseFor: *dur,
		StopNode: *stopNode, StopFor: *stopFor, DrainNode: *drainNode, DrainSelector: *drainSel,
		TeamNamespaces: teamNS, StormN: *stormN, StormRate: *stormRate, StormPersonas: stormPersonas, Mint: mint,
		ChurnRate: *churnRate, ChurnFor: *churnFor, ChurnLife: *churnLife, RolloutReplicas: *rollN, NSDeletePods: *nsdelN, UsersFile: *usersFile,
	})
	if err != nil {
		return err
	}
	out.Logf("chaos: %d passed, %d failed", res.Passed, res.Failed)
	if *dir != "" {
		if err := out.WriteJSON(*dir, *name+".json", res); err != nil {
			return err
		}
		return out.WriteText(*dir, *name+".md", res.Markdown())
	}
	return nil
}
