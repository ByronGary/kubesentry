// Command agent is the kubesentry node agent. Run one per node (a DaemonSet
// with hostPID) and it reports the processes inside pods to the server.
//
// It is read-only: it reads /proc, never writes to the node, never reads
// environment variables, and sends nothing about processes outside pods.
//
// Agents start at a random point in the first interval and jitter every
// interval after, so a fleet never reports in lockstep. Bodies are gzipped.
// On 429, 503 or a network error an agent backs off (honouring Retry-After)
// rather than retrying. With -server-fanout it posts to every server replica
// behind a headless Service.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ByronGary/kubesentry/internal/procmon"
)

func randFloat() float64 { return rand.Float64() }

func main() {
	var (
		server     = flag.String("server", "", "kubesentry server base URL, e.g. https://kubesentry-ingest.kubesentry.svc:8081")
		token      = flag.String("token", os.Getenv("KUBESENTRY_AGENT_TOKEN"), "bearer token for the server (env KUBESENTRY_AGENT_TOKEN)")
		node       = flag.String("node", os.Getenv("NODE_NAME"), "this node's name (env NODE_NAME, set from spec.nodeName)")
		interval   = flag.Duration("interval", 15*time.Second, "time between reports")
		proc       = flag.String("proc", "/proc", "procfs mount to read")
		maxProcs   = flag.Int("max-processes", 5000, "most processes to report per node")
		once       = flag.Bool("once", false, "print one report as JSON to stdout and exit (for trying it out)")
		jitter     = flag.Float64("jitter", 0.2, "spread each interval by up to ± this fraction (0 to 0.9)")
		gz         = flag.Bool("gzip", true, "gzip report bodies (falls back to plain for servers that refuse it)")
		fanout     = flag.String("server-fanout", "", "bare host name of a headless Service (e.g. kubesentry-ingest-headless.kubesentry.svc): post to every address it resolves to, with the scheme and port of -server")
		caFile     = flag.String("ca-file", "", "PEM CA bundle to verify the server certificate (default: system roots)")
		timeout    = flag.Duration("timeout", 10*time.Second, "timeout for one report")
		maxBackoff = flag.Duration("max-backoff", 2*time.Minute, "longest pause after failures or Retry-After")
	)
	flag.Parse()

	sampler := &procmon.Sampler{Opts: procmon.ScanOptions{Root: *proc, MaxProcesses: *maxProcs}}

	if *once {
		// Two samples a second apart so CPU figures are meaningful.
		if _, err := sampler.Sample(); err != nil {
			fatal("scan", err)
		}
		time.Sleep(time.Second)
		procs, err := sampler.Sample()
		if err != nil {
			fatal("scan", err)
		}
		name := *node
		if name == "" {
			name, _ = os.Hostname()
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(procmon.Report{Node: name, Time: time.Now(), Processes: procs})
		return
	}

	if *server == "" || *token == "" || *node == "" {
		fatal("configuration", errors.New("-server, -token and -node are required (NODE_NAME and KUBESENTRY_AGENT_TOKEN also work)"))
	}
	u, err := url.Parse(*server)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		fatal("configuration", fmt.Errorf("-server must be an http(s) URL, got %q", *server))
	}
	if *jitter < 0 || *jitter > 0.9 {
		fatal("configuration", fmt.Errorf("-jitter must be between 0 and 0.9, got %v", *jitter))
	}
	if *interval <= 0 {
		fatal("configuration", errors.New("-interval must be positive"))
	}
	if err := validFanoutHost(*fanout); err != nil {
		fatal("configuration", err)
	}
	if u.Scheme == "http" {
		slog.Warn("reporting over plain http: the token and process list cross the network unencrypted; use https outside a trusted network")
		if *caFile != "" {
			slog.Warn("-ca-file is ignored for an http -server")
		}
	}
	client, err := newHTTPClient(u, *caFile, *timeout)
	if err != nil {
		fatal("configuration", err)
	}
	rep := newReporter(client, u, *fanout, *token, *gz, *interval, *maxBackoff)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Take the CPU baseline now, so the first report after the start delay
	// already has CPU figures.
	if _, err := sampler.Sample(); err != nil {
		slog.Error("scan failed", "err", err)
	}
	logs := &outcomeLog{failing: map[string]bool{}}
	wait := startDelay(*interval, randFloat())
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		procs, err := sampler.Sample()
		if err != nil {
			slog.Error("scan failed", "err", err)
		} else {
			logs.record(rep.report(ctx, procmon.Report{Node: *node, Time: time.Now(), Processes: procs}))
		}
		wait = jittered(*interval, *jitter, randFloat())
	}
}

// outcomeLog logs an endpoint's first failure and every tenth after, so an
// outage does not flood the log, and says once when reporting recovers.
type outcomeLog struct{ failing map[string]bool }

func (l *outcomeLog) record(out []outcome) {
	present := make(map[string]bool, len(out))
	for _, o := range out {
		present[o.url] = true
		switch {
		case o.skipped:
		case o.err != nil:
			if o.failures%10 == 1 {
				slog.Error("report failed", "url", o.url, "err", o.err, "consecutive_failures", o.failures)
			}
			l.failing[o.url] = true
		case l.failing[o.url]:
			slog.Info("reporting restored", "url", o.url)
			delete(l.failing, o.url)
		}
	}
	for u := range l.failing { // replicas that went away
		if !present[u] {
			delete(l.failing, u)
		}
	}
}

func fatal(what string, err error) {
	slog.Error(what, "err", err)
	os.Exit(1)
}
