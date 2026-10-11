// Command stress is kubesentry's stress and verification harness.
//
//	stress gen          --level L1 [--delete]       create (or delete) a load level
//	stress expected     --out DIR                   write expected.json for the tricky cases
//	stress verify       --out DIR                   association precision/recall vs ground truth
//	stress connectivity --out DIR                   agnhost mesh, Prometheus, agents, Service reachability
//	stress users        --stages 10:3m,50:3m        virtual dashboard users
//	stress audit        --events 1000000            audit webhook firehose, then query latency
//	stress agents       --agents 500 [--surge]      simulated node agents
//	stress metrics-sim  --series 5000               synthetic container memory exporter
//	stress report       --dir DIR                   report.md/json for a run
//	stress summary      --out FILE DIR...           cross-level summary
//
// Load generators run in-cluster on the load-generator node (hack/stress-run.sh
// launches them as Jobs); gen, report and summary run on the host.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/ByronGary/kubesentry/test/stress/internal/agents"
	"github.com/ByronGary/kubesentry/test/stress/internal/conn"
	"github.com/ByronGary/kubesentry/test/stress/internal/firehose"
	"github.com/ByronGary/kubesentry/test/stress/internal/gen"
	"github.com/ByronGary/kubesentry/test/stress/internal/kc"
	"github.com/ByronGary/kubesentry/test/stress/internal/ks"
	"github.com/ByronGary/kubesentry/test/stress/internal/metricsim"
	"github.com/ByronGary/kubesentry/test/stress/internal/out"
	"github.com/ByronGary/kubesentry/test/stress/internal/plan"
	"github.com/ByronGary/kubesentry/test/stress/internal/report"
	"github.com/ByronGary/kubesentry/test/stress/internal/tricky"
	"github.com/ByronGary/kubesentry/test/stress/internal/users"
	"github.com/ByronGary/kubesentry/test/stress/internal/verify"
)

func usage() {
	fmt.Fprintln(os.Stderr, "usage: stress gen|expected|verify|connectivity|users|audit|agents|metrics-sim|report|summary [flags]")
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "gen":
		err = cmdGen(ctx, args)
	case "expected":
		err = cmdExpected(args)
	case "verify":
		if len(args) > 0 && args[0] == "assoc" {
			args = args[1:]
		}
		err = cmdVerify(ctx, args)
	case "connectivity":
		err = cmdConn(ctx, args)
	case "users":
		err = cmdUsers(ctx, args)
	case "audit":
		err = cmdAudit(ctx, args)
	case "agents":
		err = cmdAgents(ctx, args)
	case "metrics-sim":
		err = cmdMetricsSim(ctx, args)
	case "report":
		err = cmdReport(ctx, args)
	case "summary":
		err = cmdSummary(args)
	default:
		usage()
	}
	out.Must(err)
}

// common holds the flags most subcommands share.
type common struct {
	kube       kc.Flags
	base       string
	outDir     string
	apiToken   string
	auditToken string
	agentToken string
	timeout    time.Duration
}

func (c *common) register(fs *flag.FlagSet, qps float64, burst int) {
	c.kube.Register(fs, qps, burst)
	fs.StringVar(&c.base, "base", "http://kubesentry.kubesentry.svc:8080", "kubesentry base URL")
	fs.StringVar(&c.outDir, "out", "/results", "results directory")
	fs.StringVar(&c.apiToken, "api-token", "", "API token (default $KUBESENTRY_API_TOKEN, else secret kubesentry/kubesentry-api)")
	fs.StringVar(&c.auditToken, "audit-token", "", "audit webhook token (default $KUBESENTRY_AUDIT_TOKEN, else secret kubesentry/kubesentry-audit)")
	fs.StringVar(&c.agentToken, "agent-token", "", "agent token (default $KUBESENTRY_AGENT_TOKEN, else secret kubesentry/kubesentry-agent)")
	fs.DurationVar(&c.timeout, "timeout", 120*time.Second, "per-request timeout")
}

func (c *common) token(ctx context.Context, cl *kc.Clients, flagVal, env, secret string) string {
	if flagVal != "" {
		return flagVal
	}
	if v := os.Getenv(env); v != "" {
		return strings.TrimSpace(v)
	}
	if cl != nil {
		if v, err := kc.Secret(ctx, cl.CS, "kubesentry", secret, "token"); err == nil {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func (c *common) client(maxConns int) *ks.Client {
	return &ks.Client{Base: strings.TrimRight(c.base, "/"), HTTP: ks.NewHTTP(0, maxConns)}
}

func cmdGen(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("gen", flag.ExitOnError)
	var kf kc.Flags
	kf.Register(fs, 200, 400)
	level := fs.String("level", "L1", "load level L0..L4")
	del := fs.Bool("delete", false, "delete everything the harness created")
	workers := fs.Int("workers", 48, "concurrent creates")
	batch := fs.Int("batch", 1000, "objects per batch")
	pause := fs.Duration("pause", 2*time.Second, "pause between batches")
	settle := fs.Duration("settle-timeout", 20*time.Minute, "how long to wait for pods to settle")
	skipSettle := fs.Bool("skip-settle", false, "do not wait for pods")
	noTricky := fs.Bool("no-tricky", false, "skip the tricky association cases")
	static := fs.Bool("static-pod", !kc.InCluster(), "write the static pod manifest with docker exec (host only)")
	outDir := fs.String("out", "", "write gen.json and expected.json here")
	_ = fs.Parse(args)
	c, err := kf.Connect()
	if err != nil {
		return err
	}
	if *del {
		var removeStatic func(context.Context) error
		if *static {
			removeStatic = tricky.RemoveStaticPod
		}
		return gen.Delete(ctx, c.CS, func(ctx context.Context) error {
			gvr := schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}
			return c.Dyn.Resource(gvr).DeleteCollection(ctx, metav1.DeleteOptions{}, kc.StressSelector)
		}, removeStatic)
	}
	l, err := plan.Get(*level)
	if err != nil {
		return err
	}
	var tf func(*gen.Applier) error
	if !*noTricky {
		tf = func(a *gen.Applier) error { return tricky.Apply(ctx, c.CS, c.Dyn, a, *static) }
	}
	res, err := gen.Run(ctx, c, gen.Options{Level: l, Workers: *workers, Batch: *batch, Pause: *pause, SettleTimeout: *settle, SkipSettle: *skipSettle}, tf)
	if err != nil {
		return err
	}
	out.Logf("%s", res.Summary())
	for _, e := range res.Errors {
		out.Logf("error: %s", e)
	}
	if *outDir != "" {
		if err := out.WriteJSON(*outDir, "gen.json", res); err != nil {
			return err
		}
		return out.WriteJSON(*outDir, "expected.json", tricky.ExpectedDoc(l.Name))
	}
	return nil
}

func cmdExpected(args []string) error {
	fs := flag.NewFlagSet("expected", flag.ExitOnError)
	dir := fs.String("out", "results", "directory")
	level := fs.String("level", "", "level label")
	_ = fs.Parse(args)
	return out.WriteJSON(*dir, "expected.json", tricky.ExpectedDoc(*level))
}

func cmdVerify(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	var c common
	c.register(fs, 50, 100)
	mapNS := fs.Int("map-namespaces", 40, "generated namespaces to map besides stress-* (-1: all)")
	_ = fs.Parse(args)
	cl, err := c.kube.Connect()
	if err != nil {
		return err
	}
	tok := c.token(ctx, cl, c.apiToken, "KUBESENTRY_API_TOKEN", "kubesentry-api")
	res, err := verify.Assoc(ctx, cl.CS, verify.AssocOptions{Client: c.client(16), ID: ks.Bearer{Token: tok}, OutDir: c.outDir, MapNS: *mapNS, Timeout: c.timeout})
	if err != nil {
		return err
	}
	if err := out.WriteJSON(c.outDir, "assoc.json", res); err != nil {
		return err
	}
	if err := out.WriteText(c.outDir, "assoc.md", res.Markdown()); err != nil {
		return err
	}
	for k, s := range res.Summary {
		out.Logf("assoc %-28s precision %.3f recall %.3f (truth %d, reported %d)", k, s.Precision, s.Recall, s.Truth, s.Observed)
	}
	return nil
}

func cmdConn(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("connectivity", flag.ExitOnError)
	var c common
	c.register(fs, 20, 40)
	svc := fs.String("kubesentry-svc", "kubesentry.kubesentry.svc.cluster.local:8080", "kubesentry Service host:port probed from every node")
	prom := fs.String("prometheus", "http://kps-kube-prometheus-stack-prometheus.monitoring.svc:9090", "Prometheus URL")
	_ = fs.Parse(args)
	cl, err := c.kube.Connect()
	if err != nil {
		return err
	}
	tok := c.token(ctx, cl, c.apiToken, "KUBESENTRY_API_TOKEN", "kubesentry-api")
	res, err := conn.Run(ctx, cl.CS, conn.Options{Client: c.client(16), APIID: ks.Bearer{Token: tok}, KubesentrySvc: *svc, PrometheusURL: *prom, Timeout: 10 * time.Second})
	if err != nil {
		return err
	}
	if err := out.WriteJSON(c.outDir, "conn.json", res); err != nil {
		return err
	}
	return out.WriteText(c.outDir, "conn.md", res.Markdown())
}

func cmdUsers(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("users", flag.ExitOnError)
	var c common
	c.register(fs, 20, 40)
	stages := fs.String("stages", "10:3m,50:3m,200:5m", "ramp: users:hold,...")
	rampUp := fs.Duration("ramp-up", 30*time.Second, "spread each stage's new users over this")
	thinkMin := fs.Duration("think-min", 5*time.Second, "minimum think time")
	thinkMax := fs.Duration("think-max", 30*time.Second, "maximum think time")
	pageTimeout := fs.Duration("page-timeout", 120*time.Second, "a user waits this long for a page to load")
	abortP99 := fs.Duration("abort-p99", 60*time.Second, "abort when p99 exceeds this ...")
	abortErr := fs.Float64("abort-error-rate", 0.2, "... or the error rate exceeds this ...")
	abortAfter := fs.Duration("abort-after", 2*time.Minute, "... continuously for this long")
	name := fs.String("name", "users", "result file name (users.json)")
	maxPods := fs.Int("target-pods", 3000, "pods sampled for pod pages")
	_ = fs.Parse(args)
	st, err := users.ParseStages(*stages)
	if err != nil {
		return err
	}
	cl, err := c.kube.Connect()
	if err != nil {
		return err
	}
	tok := c.token(ctx, cl, c.apiToken, "KUBESENTRY_API_TOKEN", "kubesentry-api")
	targets, err := podTargets(ctx, cl, *maxPods)
	if err != nil {
		return err
	}
	res := users.Run(ctx, users.Options{
		Client: c.client(20000),
		// One shared token today; Phase 2 swaps in per-user identities here.
		Identities: func(int) ks.Identity { return ks.Bearer{Token: tok} },
		Stages:     st, RampUp: *rampUp, ThinkMin: *thinkMin, ThinkMax: *thinkMax, PageTimeout: *pageTimeout, ReqTimeout: c.timeout,
		Targets: targets, Pages: users.Pages, AbortP99: *abortP99, AbortErrRate: *abortErr, AbortAfter: *abortAfter, Seed: plan.Seed,
	})
	return out.WriteJSON(c.outDir, *name+".json", res)
}

// podTargets samples pods for pod pages: every pod in stress-* namespaces plus
// a deterministic sample of the rest, and the namespaces with pods.
func podTargets(ctx context.Context, cl *kc.Clients, maxPods int) (*users.Targets, error) {
	t := &users.Targets{}
	seen := map[string]bool{}
	var rest []users.PodRef
	opts := metav1.ListOptions{Limit: 2000, ResourceVersion: "0"}
	for {
		l, err := cl.CS.CoreV1().Pods("").List(ctx, opts)
		if err != nil {
			return nil, err
		}
		for _, p := range l.Items {
			ref := users.PodRef{Namespace: p.Namespace, Name: p.Name}
			if !seen[p.Namespace] {
				seen[p.Namespace] = true
				t.Namespaces = append(t.Namespaces, p.Namespace)
			}
			if strings.HasPrefix(p.Namespace, "stress-") || strings.HasPrefix(p.Namespace, "demo-") {
				t.Pods = append(t.Pods, ref)
			} else {
				rest = append(rest, ref)
			}
		}
		if l.Continue == "" {
			break
		}
		opts.Continue, opts.ResourceVersion = l.Continue, ""
	}
	step := 1
	if len(rest) > maxPods {
		step = len(rest)/maxPods + 1
	}
	for i := 0; i < len(rest); i += step {
		t.Pods = append(t.Pods, rest[i])
	}
	out.Logf("users: %d target pods in %d namespaces", len(t.Pods), len(t.Namespaces))
	return t, nil
}

func cmdAudit(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	var c common
	c.register(fs, 20, 40)
	events := fs.Int("events", 1_000_000, "events to send")
	rate := fs.Float64("rate", 3000, "events per second")
	batch := fs.Int("batch", 1000, "events per POST")
	workers := fs.Int("workers", 8, "concurrent POSTs")
	level := fs.String("level", "L1", "level whose namespaces the events name")
	reps := fs.Int("query-reps", 30, "repetitions per query after ingest")
	conc := fs.Int("query-concurrency", 5, "concurrent queries")
	maxRun := fs.Duration("max-run", 20*time.Minute, "stop sending after this long")
	name := fs.String("name", "audit", "result file name (audit.json)")
	_ = fs.Parse(args)
	cl, err := c.kube.Connect()
	if err != nil {
		return err
	}
	l, err := plan.Get(*level)
	if err != nil {
		return err
	}
	p := plan.Build(l)
	res := firehose.Run(ctx, firehose.Options{
		Client: c.client(64), AuditID: ks.Bearer{Label: "audit", Token: c.token(ctx, cl, c.auditToken, "KUBESENTRY_AUDIT_TOKEN", "kubesentry-audit")},
		APIID: ks.Bearer{Token: c.token(ctx, cl, c.apiToken, "KUBESENTRY_API_TOKEN", "kubesentry-api")},
		Total: *events, Rate: *rate, BatchSize: *batch, Workers: *workers, Namespaces: p.Stats.TeamNamespaces,
		QueryReps: *reps, QueryConc: *conc, Seed: plan.Seed, Timeout: c.timeout, MaxRun: *maxRun,
	})
	return out.WriteJSON(c.outDir, *name+".json", res)
}

func cmdAgents(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("agents", flag.ExitOnError)
	var c common
	c.register(fs, 20, 40)
	n := fs.Int("agents", 500, "simulated agents")
	interval := fs.Duration("interval", 15*time.Second, "report interval")
	jitter := fs.Float64("jitter", 0, "± fraction of the interval per report (0: fixed phase per agent)")
	surge := fs.Bool("surge", false, "all agents post at the same instant every interval")
	dur := fs.Duration("duration", 3*time.Minute, "how long to run")
	minKB := fs.Int("min-kb", 50, "minimum report size")
	maxKB := fs.Int("max-kb", 150, "maximum report size")
	check := fs.Int("check-pods", 100, "fake pods whose processes are fetched afterwards")
	name := fs.String("name", "agents", "result file name")
	_ = fs.Parse(args)
	cl, err := c.kube.Connect()
	if err != nil {
		return err
	}
	res, err := agents.Run(ctx, cl.CS, agents.Options{
		Client: c.client(2000), ID: ks.Bearer{Label: "agent", Token: c.token(ctx, cl, c.agentToken, "KUBESENTRY_AGENT_TOKEN", "kubesentry-agent")},
		APIID:  ks.Bearer{Token: c.token(ctx, cl, c.apiToken, "KUBESENTRY_API_TOKEN", "kubesentry-api")},
		Agents: *n, Interval: *interval, Jitter: *jitter, Surge: *surge, Duration: *dur,
		MinBytes: *minKB << 10, MaxBytes: *maxKB << 10, Timeout: c.timeout, CheckPods: *check, Seed: plan.Seed,
	})
	if err != nil {
		return err
	}
	return out.WriteJSON(c.outDir, *name+".json", res)
}

func cmdMetricsSim(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("metrics-sim", flag.ExitOnError)
	var kf kc.Flags
	kf.Register(fs, 20, 40)
	listen := fs.String("listen", ":9100", "listen address")
	series := fs.Int("series", envInt("SERIES", 5000), "series to serve (env SERIES)")
	leak := fs.Float64("leak-share", 0.02, "share of series that leak")
	refresh := fs.Duration("refresh", 2*time.Minute, "how often to re-list pods")
	truthFile := fs.String("truth", "/results/metrics-sim-truth.json", "ground truth file")
	_ = fs.Parse(args)
	cl, err := kf.Connect()
	if err != nil {
		return err
	}
	return metricsim.Run(ctx, cl.CS, metricsim.Options{Listen: *listen, Series: *series, LeakShare: *leak, Refresh: *refresh, TruthFile: *truthFile, Seed: plan.Seed})
}

func envInt(name string, def int) int {
	var v int
	if _, err := fmt.Sscan(os.Getenv(name), &v); err == nil && v > 0 {
		return v
	}
	return def
}

func cmdReport(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	var kf kc.Flags
	kf.Register(fs, 20, 40)
	dir := fs.String("dir", "", "run directory (results/<run>)")
	level := fs.String("level", "", "level")
	variant := fs.String("variant", "baseline", "baseline or after")
	mem := fs.String("memory-limit", "", "kubesentry memory limit during the run")
	cp := fs.String("control-plane", "kubesentry-control-plane", "kind control-plane container (API server audit log)")
	guard := fs.String("guard", "", "guard CSV (default <dir>/../guard.csv)")
	skipAudit := fs.Bool("skip-audit-log", false, "do not read the API server audit log")
	_ = fs.Parse(args)
	if *dir == "" {
		return fmt.Errorf("--dir is required")
	}
	if *guard == "" {
		*guard = filepath.Join(filepath.Dir(*dir), "guard.csv")
	}
	cl, err := kf.Connect()
	if err != nil {
		return err
	}
	r, err := report.Build(ctx, cl.CS, report.Options{Dir: *dir, Run: filepath.Base(*dir), Level: *level, Variant: *variant, MemoryLimit: *mem,
		ControlPlane: *cp, GuardCSV: *guard, SkipAudit: *skipAudit})
	if err != nil {
		return err
	}
	if err := out.WriteJSON(*dir, "report.json", r); err != nil {
		return err
	}
	return out.WriteText(*dir, "report.md", r.Markdown())
}

func cmdSummary(args []string) error {
	fs := flag.NewFlagSet("summary", flag.ExitOnError)
	outFile := fs.String("out", "test/stress/results/summary-tables.md", "output markdown")
	title := fs.String("title", "kubesentry baseline stress test", "title")
	_ = fs.Parse(args)
	var reps []*report.Report
	for _, d := range fs.Args() {
		var r report.Report
		if err := out.ReadJSON(filepath.Join(d, "report.json"), &r); err != nil {
			return fmt.Errorf("%s: %w", d, err)
		}
		reps = append(reps, &r)
	}
	return os.WriteFile(*outFile, []byte(report.Summary(*title, reps)), 0o644)
}
