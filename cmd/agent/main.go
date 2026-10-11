// Command agent is the kubesentry node agent. Run one per node (a DaemonSet
// with hostPID) and it reports the processes inside pods to the server.
//
// It is read-only: it reads /proc, never writes to the node, never reads
// environment variables, and sends nothing about processes outside pods.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ByronGary/kubesentry/internal/procmon"
)

func main() {
	var (
		server   = flag.String("server", "", "kubesentry server base URL, e.g. https://kubesentry.kubesentry.svc:8080")
		token    = flag.String("token", os.Getenv("KUBESENTRY_AGENT_TOKEN"), "bearer token for the server (env KUBESENTRY_AGENT_TOKEN)")
		node     = flag.String("node", os.Getenv("NODE_NAME"), "this node's name (env NODE_NAME, set from spec.nodeName)")
		interval = flag.Duration("interval", 15*time.Second, "time between reports")
		proc     = flag.String("proc", "/proc", "procfs mount to read")
		maxProcs = flag.Int("max-processes", 5000, "most processes to report per node")
		once     = flag.Bool("once", false, "print one report as JSON to stdout and exit (for trying it out)")
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
	if u.Scheme == "http" {
		slog.Warn("reporting over plain http: the token and process list cross the network unencrypted; use https outside a trusted network")
	}
	endpoint := u.JoinPath("agent", "report").String()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	client := &http.Client{Timeout: 10 * time.Second}

	tick := time.NewTicker(*interval)
	defer tick.Stop()
	failures := 0
	for {
		procs, err := sampler.Sample()
		if err != nil {
			slog.Error("scan failed", "err", err)
		} else if err := send(ctx, client, endpoint, *token, procmon.Report{Node: *node, Time: time.Now(), Processes: procs}); err != nil {
			// Log the first failure and then every tenth, so an outage does not flood the log.
			if failures%10 == 0 {
				slog.Error("report failed", "err", err, "consecutive_failures", failures+1)
			}
			failures++
		} else {
			if failures > 0 {
				slog.Info("reporting restored")
			}
			failures = 0
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func send(ctx context.Context, c *http.Client, endpoint, token string, r procmon.Report) error {
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("server answered %s", resp.Status)
	}
	return nil
}

func fatal(what string, err error) {
	slog.Error(what, "err", err)
	os.Exit(1)
}
