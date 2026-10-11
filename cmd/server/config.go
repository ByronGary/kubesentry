package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/ByronGary/kubesentry/internal/auth"
	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/pgstore"
	"github.com/ByronGary/kubesentry/internal/snapshot"
)

// config is every server flag, parsed.
type config struct {
	showVersion bool

	addr, ingestAddr, opsAddr string
	pprof                     bool
	tlsCert, tlsKey           string
	shutdownDrain             time.Duration
	shutdownTimeout           time.Duration

	kubeconfig          string
	cache               bool
	kubeQPS             float64
	kubeBurst           int
	snapshotMinInterval time.Duration
	snapshotMaxDelay    time.Duration
	clusterName         string
	awsAuth             bool
	nodeLabelKeysAdd    *listValue

	apiToken, agentToken, auditToken string
	authMode                         string
	authUserHeader, authGroupsHeader string
	authUsernamePrefix               string
	authGroupsPrefix                 string
	authGroupMapFile                 string
	authTrustedProxyCIDRs            string
	signOutURL                       string
	authzQPS                         float64
	authzCacheTTL, authzDenyTTL      time.Duration
	authzShareByGroups               bool
	rateLimit                        float64
	rateBurst, maxInflight           int

	promURL string

	systemNamespaces, systemNamespacesAdd *listValue
	systemPrincipalPrefixes               *listValue
	builtinRBACPrefixes                   *listValue
	thresholds                            detectors.Thresholds
	pvcMinAge                             time.Duration
	pvcDefaultPrice                       optionalFloat
	pvcClassPrices, ebsPrices             string

	auditLogFile        string
	auditFromStart      bool
	auditJournal        string
	auditMaxEvents      int
	auditStore          string
	pgDSN, pgSchema     string
	auditRetention      time.Duration
	auditRedactExecArgs bool
	cloudwatch          bool
	cloudwatchLogGroup  string
	cloudwatchPrefix    string
	cloudwatchStart     time.Duration
	cloudwatchEndpoint  string
	awsRegion           string
}

// parseFlags reads the server's flags from args.
func parseFlags(args []string, out io.Writer) (*config, error) {
	c := &config{
		nodeLabelKeysAdd:        newList(),
		systemNamespaces:        newList(),
		systemNamespacesAdd:     newList(),
		systemPrincipalPrefixes: newList(detectors.DefaultPolicy().SystemPrincipalPrefixes...),
		builtinRBACPrefixes:     newList(detectors.DefaultPolicy().BuiltinRBACPrefixes...),
	}
	fs := flag.NewFlagSet("kubesentry", flag.ContinueOnError)
	fs.SetOutput(out)
	dur := func(p *time.Duration, name string, def time.Duration, usage string) {
		*p = def
		fs.Var((*durationValue)(p), name, usage+" (Go duration; d for days, e.g. 30d)")
	}
	th := &c.thresholds
	*th = detectors.DefaultPolicy().Thresholds

	fs.BoolVar(&c.showVersion, "version", false, "print the version and exit")

	// Listeners.
	fs.StringVar(&c.addr, "addr", "127.0.0.1:8080", "UI and API listen address (use :8080 to listen on all interfaces)")
	fs.StringVar(&c.ingestAddr, "ingest-addr", "", "listen address for POST /agent/report and POST /audit/webhook; empty serves them on -addr")
	fs.StringVar(&c.opsAddr, "ops-addr", "", "listen address for /healthz, /readyz, /metrics (and /debug/pprof/ with -pprof); empty serves the probes on -addr and no metrics")
	fs.BoolVar(&c.pprof, "pprof", false, "serve /debug/pprof/ on -ops-addr")
	fs.StringVar(&c.tlsCert, "tls-cert", "", "TLS certificate for the web and ingest listeners (with -tls-key)")
	fs.StringVar(&c.tlsKey, "tls-key", "", "TLS private key")
	dur(&c.shutdownDrain, "shutdown-drain", 5*time.Second, "on SIGTERM, how long /readyz fails before the listeners stop")
	dur(&c.shutdownTimeout, "shutdown-timeout", 20*time.Second, "how long requests in flight may take to finish at shutdown")

	// Kubernetes.
	fs.StringVar(&c.kubeconfig, "kubeconfig", "", "path to kubeconfig (default: in-cluster, then KUBECONFIG / ~/.kube/config)")
	fs.BoolVar(&c.cache, "cache", true, "serve from shared informers; false lists the cluster on every request (debugging)")
	fs.Float64Var(&c.kubeQPS, "kube-qps", 50, "Kubernetes client queries per second")
	fs.IntVar(&c.kubeBurst, "kube-burst", 100, "Kubernetes client burst")
	dur(&c.snapshotMinInterval, "snapshot-min-interval", snapshot.DefaultMinInterval, "shortest wait between view rebuilds")
	dur(&c.snapshotMaxDelay, "snapshot-max-delay", snapshot.DefaultMaxDelay, "longest a change waits before the view is rebuilt")
	fs.StringVar(&c.clusterName, "cluster-name", "", "cluster name shown in the UI; also names the CloudWatch log group /aws/eks/<name>/cluster")
	fs.BoolVar(&c.awsAuth, "aws-auth", false, "read kube-system/aws-auth (needs the chart's scoped Role)")
	fs.Var(c.nodeLabelKeysAdd, "node-label-keys-add", "extra node labels to keep, comma-separated (\"prefix*\" keeps a prefix)")

	// Authentication and authorization.
	fs.StringVar(&c.apiToken, "api-token", os.Getenv("KUBESENTRY_API_TOKEN"), "break-glass bearer token for /api/ routes, unrestricted (env KUBESENTRY_API_TOKEN)")
	fs.StringVar(&c.authMode, "auth-mode", "token", "token, proxy (identity headers from an SSO proxy, scoped by Kubernetes RBAC) or none (loopback only)")
	fs.StringVar(&c.authUserHeader, "auth-user-header", "X-Forwarded-Email", "proxy mode: header carrying the user")
	fs.StringVar(&c.authGroupsHeader, "auth-groups-header", "X-Forwarded-Groups", "proxy mode: header carrying the groups")
	fs.StringVar(&c.authUsernamePrefix, "auth-username-prefix", "", "prefix for user names, as the API server's --oidc-username-prefix")
	fs.StringVar(&c.authGroupsPrefix, "auth-groups-prefix", "", "prefix for group names, as the API server's --oidc-groups-prefix")
	fs.StringVar(&c.authGroupMapFile, "auth-group-map-file", "", "JSON {\"idp-group\": [\"k8s-group\", ...]} adding Kubernetes groups")
	fs.StringVar(&c.authTrustedProxyCIDRs, "auth-trusted-proxy-cidrs", "127.0.0.1/32,::1/128", "only these addresses may send identity headers")
	fs.StringVar(&c.signOutURL, "auth-sign-out-url", "", "where the UI's Sign out goes (e.g. /oauth2/sign_out)")
	fs.Float64Var(&c.authzQPS, "authz-qps", 200, "SubjectAccessReviews per second (burst twice that)")
	dur(&c.authzCacheTTL, "authz-cache-ttl", auth.DefaultAuthzTTL, "how long an allowed access decision is cached")
	dur(&c.authzDenyTTL, "authz-deny-ttl", auth.DefaultAuthzDenyTTL, "how long a denied access decision is cached")
	fs.BoolVar(&c.authzShareByGroups, "authz-share-by-groups", false, "cache access decisions by group set instead of per user (only when nothing is granted to individual users)")
	fs.Float64Var(&c.rateLimit, "rate-limit", 20, "API requests per second per identity (0 disables)")
	fs.IntVar(&c.rateBurst, "rate-burst", 40, "API request burst per identity")
	fs.IntVar(&c.maxInflight, "max-inflight", 512, "API requests served at once; more get 503 (0 disables)")

	// Data sources.
	fs.StringVar(&c.promURL, "prometheus-url", "", "Prometheus base URL, e.g. http://prometheus:9090 (enables leak detection); PROMETHEUS_TOKEN for bearer auth")
	fs.StringVar(&c.agentToken, "agent-token", os.Getenv("KUBESENTRY_AGENT_TOKEN"), "bearer token node agents send to POST /agent/report; setting it enables process monitoring (env KUBESENTRY_AGENT_TOKEN)")

	// Policy.
	fs.Var(c.systemNamespaces, "system-namespaces", "replace the system namespaces, comma-separated")
	fs.Var(c.systemNamespacesAdd, "system-namespaces-add", "add system namespaces, comma-separated")
	fs.Var(c.systemPrincipalPrefixes, "system-principal-prefixes", "user and group prefixes of platform components")
	fs.Var(c.builtinRBACPrefixes, "builtin-rbac-prefixes", "name prefixes of platform-created roles and bindings")
	restartWarn, restartCrit := int(th.RestartWarn), int(th.RestartCrit)
	fs.IntVar(&restartWarn, "restart-warn", restartWarn, "restarts at which a pod warns")
	fs.IntVar(&restartCrit, "restart-crit", restartCrit, "restarts at which a pod is critical")
	dur(&th.OOMRecent, "oom-recent", th.OOMRecent, "an OOM kill within this is critical, older warns")
	dur(&th.PendingGrace, "pending-grace", th.PendingGrace, "pods, claims and certificate requests pending longer warn")
	dur(&th.NotReadyGrace, "not-ready-grace", th.NotReadyGrace, "a running pod not ready longer than this warns")
	dur(&th.TerminatingGrace, "terminating-grace", th.TerminatingGrace, "a pod still terminating this long after its grace period warns")
	dur(&th.RecentPod, "recent-pod", th.RecentPod, "finished pods newer than this still show on the map")
	dur(&th.ActivityWindow, "activity-window", th.ActivityWindow, "audit look-back for the pod page's activity check")
	dur(&th.CertCritCap, "cert-crit-cap", th.CertCritCap, "a certificate is critical below min(this, a tenth of its lifetime)")
	dur(&th.CertWarnCap, "cert-warn-cap", th.CertWarnCap, "a certificate warns below min(this, a third of its lifetime)")
	dur(&c.pvcMinAge, "pvc-min-age", 24*time.Hour, "ignore unused PVCs younger than this")
	fs.Var(&c.pvcDefaultPrice, "pvc-default-price", "USD per GiB-month for classes nothing else prices; unset means no estimate")
	fs.StringVar(&c.pvcClassPrices, "pvc-class-prices", "", "USD per GiB-month by storage class, e.g. gp3=0.08,io2=0.125")
	fs.StringVar(&c.ebsPrices, "ebs-prices", "", "USD per GiB-month by EBS volume type, overriding the us-east-1 defaults, e.g. gp3=0.0952")

	// Audit.
	fs.StringVar(&c.auditToken, "audit-token", os.Getenv("KUBESENTRY_AUDIT_TOKEN"), "bearer token POST /audit/webhook requires; the webhook is disabled without it (env KUBESENTRY_AUDIT_TOKEN)")
	fs.StringVar(&c.auditLogFile, "audit-log-file", "", "follow this kube-apiserver audit log file (--audit-log-path)")
	fs.BoolVar(&c.auditFromStart, "audit-from-start", false, "with -audit-log-file, read existing content instead of starting at the end")
	fs.StringVar(&c.auditJournal, "audit-journal", "", "memory store: JSONL file that keeps audit history across restarts (not rotated)")
	fs.IntVar(&c.auditMaxEvents, "audit-max-events", 50000, "memory store: audit events kept")
	fs.StringVar(&c.auditStore, "audit-store", "memory", "memory or postgres")
	fs.StringVar(&c.pgDSN, "pg-dsn", "", "Postgres DSN (env "+pgstore.DSNEnv+"; PG* variables fill in the rest)")
	fs.StringVar(&c.pgSchema, "pg-schema", "kubesentry", "Postgres schema, one per cluster")
	dur(&c.auditRetention, "audit-retention", 30*24*time.Hour, "Postgres store: how long audit events are kept")
	fs.BoolVar(&c.auditRedactExecArgs, "audit-redact-exec-args", false, "drop exec command arguments from stored request URIs")
	fs.BoolVar(&c.cloudwatch, "cloudwatch", false, "read EKS audit logs from CloudWatch Logs")
	fs.StringVar(&c.cloudwatchLogGroup, "cloudwatch-log-group", "", "log group (default /aws/eks/<cluster-name>/cluster)")
	fs.StringVar(&c.cloudwatchPrefix, "cloudwatch-stream-prefix", "kube-apiserver-audit", "log stream prefix")
	dur(&c.cloudwatchStart, "cloudwatch-start", 24*time.Hour, "how far back to start without a checkpoint")
	fs.StringVar(&c.cloudwatchEndpoint, "cloudwatch-endpoint", "", "CloudWatch Logs endpoint override (tests, VPC endpoints)")
	fs.StringVar(&c.awsRegion, "aws-region", "", "AWS region (default from the environment, e.g. AWS_REGION)")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	th.RestartWarn, th.RestartCrit = int32(restartWarn), int32(restartCrit)
	return c, c.validate()
}

func (c *config) validate() error {
	if (c.tlsCert == "") != (c.tlsKey == "") {
		return errors.New("-tls-cert and -tls-key must be set together")
	}
	switch c.authMode {
	case "token", "proxy", "none":
	default:
		return fmt.Errorf("-auth-mode %q: use token, proxy or none", c.authMode)
	}
	if c.authMode == "none" && !isLoopback(c.addr) {
		return fmt.Errorf("-auth-mode=none serves everything to anyone, so -addr must be a loopback address, not %q", c.addr)
	}
	if c.authMode == "token" && c.apiToken == "" && !isLoopback(c.addr) {
		return fmt.Errorf("-auth-mode=token needs -api-token (or KUBESENTRY_API_TOKEN) when -addr %q is not loopback", c.addr)
	}
	switch c.auditStore {
	case "memory":
	case "postgres":
		if c.auditJournal != "" {
			return errors.New("-audit-journal keeps the memory store across restarts; Postgres does not need it")
		}
	default:
		return fmt.Errorf("-audit-store %q: use memory or postgres", c.auditStore)
	}
	if c.cloudwatch && c.cloudwatchLogGroup == "" && c.clusterName == "" {
		return errors.New("-cloudwatch needs -cluster-name or -cloudwatch-log-group")
	}
	if c.kubeQPS <= 0 || c.kubeBurst <= 0 || c.authzQPS <= 0 {
		return errors.New("-kube-qps, -kube-burst and -authz-qps must be positive")
	}
	return nil
}

// policy builds the detectors' policy from the flags. The server's own
// namespace (POD_NAMESPACE, set by the chart) is plumbing too.
func (c *config) policy() (detectors.Policy, error) {
	p := detectors.DefaultPolicy()
	if c.systemNamespaces.set {
		p.SystemNamespaces = map[string]bool{}
		for _, ns := range c.systemNamespaces.items {
			p.SystemNamespaces[ns] = true
		}
	}
	for _, ns := range c.systemNamespacesAdd.items {
		p.SystemNamespaces[ns] = true
	}
	if ns := os.Getenv("POD_NAMESPACE"); ns != "" {
		p.SystemNamespaces[ns] = true
	}
	p.SystemPrincipalPrefixes = c.systemPrincipalPrefixes.items
	p.BuiltinRBACPrefixes = c.builtinRBACPrefixes.items
	if p.SystemPrincipalPrefixes == nil {
		p.SystemPrincipalPrefixes = []string{}
	}
	if p.BuiltinRBACPrefixes == nil {
		p.BuiltinRBACPrefixes = []string{}
	}
	p.Thresholds = c.thresholds

	classPrices, err := parsePrices(c.pvcClassPrices)
	if err != nil {
		return p, fmt.Errorf("-pvc-class-prices: %w", err)
	}
	p.Pricing.ClassPrices = classPrices
	ebs, err := parsePrices(c.ebsPrices)
	if err != nil {
		return p, fmt.Errorf("-ebs-prices: %w", err)
	}
	for k, v := range ebs {
		p.Pricing.EBSPrices[k] = v
	}
	p.Pricing.DefaultPrice = c.pvcDefaultPrice.ptr()
	return p, nil
}

// authenticator builds the -auth-mode authenticator. In proxy mode the API
// token stays available as the break-glass identity (reachable only from
// inside the pod network when oauth2-proxy fronts the listener).
func (c *config) authenticator() (auth.Authenticator, error) {
	token := auth.TokenAuthenticator{Token: c.apiToken}
	switch c.authMode {
	case "none":
		slog.Warn("-auth-mode=none: every local caller sees everything")
		return auth.NoneAuthenticator{}, nil
	case "token":
		if c.apiToken == "" {
			slog.Warn("no -api-token on a loopback address: every local caller sees everything")
			return auth.NoneAuthenticator{}, nil
		}
		return token, nil
	}
	cidrs, err := auth.ParseCIDRs(c.authTrustedProxyCIDRs)
	if err != nil {
		return nil, fmt.Errorf("-auth-trusted-proxy-cidrs: %w", err)
	}
	h := auth.HeaderAuthenticator{
		UserHeader: c.authUserHeader, GroupsHeader: c.authGroupsHeader,
		UsernamePrefix: c.authUsernamePrefix, GroupsPrefix: c.authGroupsPrefix, TrustedProxies: cidrs,
	}
	if c.authGroupMapFile != "" {
		if h.GroupMap, err = auth.LoadGroupMap(c.authGroupMapFile); err != nil {
			return nil, err
		}
	}
	if c.apiToken == "" {
		return h, nil
	}
	return auth.Chain(h, token), nil
}
