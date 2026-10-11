// Command server runs the kubesentry HTTP API.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ByronGary/kubesentry/internal/api"
	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/kube"
	"github.com/ByronGary/kubesentry/internal/procmon"
	"github.com/ByronGary/kubesentry/internal/prom"
	"github.com/ByronGary/kubesentry/internal/web"
)

func main() {
	var (
		addr       = flag.String("addr", "127.0.0.1:8080", "HTTP listen address (use :8080 to listen on all interfaces, together with -api-token)")
		kubeconfig = flag.String("kubeconfig", "", "path to kubeconfig (default: in-cluster, then KUBECONFIG / ~/.kube/config)")
		apiToken   = flag.String("api-token", os.Getenv("KUBESENTRY_API_TOKEN"), "bearer token required on /api/ routes (env KUBESENTRY_API_TOKEN)")
		tlsCert    = flag.String("tls-cert", "", "TLS certificate file (enables HTTPS together with -tls-key)")
		tlsKey     = flag.String("tls-key", "", "TLS private key file")

		promURL    = flag.String("prometheus-url", "", "Prometheus base URL, e.g. http://prometheus:9090 (enables OOM leak detection)")
		minAge     = flag.Duration("pvc-min-age", 24*time.Hour, "ignore unused PVCs younger than this")
		defPrice   = flag.Float64("pvc-default-price", 0.10, "fallback storage price in USD per GiB-month (a rough estimate; override per class)")
		classPrice = flag.String("pvc-class-prices", "", "per storage class prices, e.g. gp3=0.08,io2=0.125")

		auditToken   = flag.String("audit-token", os.Getenv("KUBESENTRY_AUDIT_TOKEN"), "bearer token the POST /audit/webhook endpoint requires; the endpoint is disabled without it (env KUBESENTRY_AUDIT_TOKEN)")
		auditLog     = flag.String("audit-log-file", "", "follow this kube-apiserver audit log file (--audit-log-path)")
		auditStart   = flag.Bool("audit-from-start", false, "with -audit-log-file, read existing content instead of starting at the end")
		auditJournal = flag.String("audit-journal", "", "JSONL file that keeps audit history across restarts (not rotated)")
		auditMax     = flag.Int("audit-max-events", 50000, "number of audit events kept in memory")

		agentToken = flag.String("agent-token", os.Getenv("KUBESENTRY_AGENT_TOKEN"), "bearer token node agents send to POST /agent/report; setting it enables process monitoring (env KUBESENTRY_AGENT_TOKEN)")
	)
	flag.Parse()

	if (*tlsCert == "") != (*tlsKey == "") {
		fatal("tls", errors.New("-tls-cert and -tls-key must be set together"))
	}
	prices, err := parsePrices(*classPrice)
	if err != nil {
		fatal("invalid -pvc-class-prices", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cluster, err := kube.Connect(*kubeconfig)
	if err != nil {
		fatal("kubernetes client", err)
	}

	srv := &api.Server{
		Cluster:   cluster,
		Inventory: cluster,
		Certs:     cluster,
		PVCOptions: detectors.PVCOptions{
			MinAge:                  *minAge,
			PricePerGiBMonth:        prices,
			DefaultPricePerGiBMonth: *defPrice,
		},
		LeakOptions: detectors.DefaultLeakOptions(),
		APIToken:    *apiToken,
		UI:          web.Handler(),
	}
	if *promURL != "" {
		c := prom.New(*promURL)
		c.BearerToken = os.Getenv("PROMETHEUS_TOKEN")
		srv.Metrics = c
	} else {
		slog.Warn("no -prometheus-url set; OOM leak detection disabled (OOMKilled events still work)")
	}

	if *auditLog != "" || *auditToken != "" || *auditJournal != "" {
		ing := &audit.Ingester{Store: audit.NewMemoryStore(*auditMax)}
		if *auditJournal != "" {
			n, err := audit.LoadJournal(*auditJournal, ing.Store)
			if err != nil {
				fatal("load audit journal", err)
			}
			slog.Info("replayed audit journal", "events", n)
			j, err := audit.OpenJournal(*auditJournal)
			if err != nil {
				fatal("open audit journal", err)
			}
			defer j.Close()
			ing.Journal = j
		}
		srv.Audit = ing
		srv.AuditToken = *auditToken
		if *auditToken == "" {
			slog.Warn("no -audit-token set; the POST /audit/webhook endpoint is disabled")
		}
		if *auditLog != "" {
			go func() {
				slog.Info("following audit log", "path", *auditLog)
				err := audit.TailFile(ctx, *auditLog, *auditStart, time.Second, ing.IngestLine)
				if err != nil && !errors.Is(err, context.Canceled) {
					slog.Error("audit log tailer stopped", "err", err)
				}
			}()
		}
		if *apiToken == "" && !isLoopback(*addr) {
			slog.Warn("audit data is exposed without authentication; set -api-token or listen on loopback")
		}
	}

	if *agentToken != "" {
		srv.Processes = procmon.NewStore()
		srv.AgentToken = *agentToken
		if *apiToken == "" && !isLoopback(*addr) {
			slog.Warn("process data is exposed without authentication; set -api-token or listen on loopback")
		}
	}

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()

	slog.Info("kubesentry listening", "addr", *addr, "tls", *tlsCert != "")
	if *tlsCert != "" {
		err = httpSrv.ListenAndServeTLS(*tlsCert, *tlsKey)
	} else {
		err = httpSrv.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		fatal("http server", err)
	}
}

func isLoopback(addr string) bool {
	return strings.HasPrefix(addr, "127.0.0.1:") || strings.HasPrefix(addr, "localhost:") || strings.HasPrefix(addr, "[::1]:")
}

func parsePrices(s string) (map[string]float64, error) {
	out := map[string]float64{}
	if strings.TrimSpace(s) == "" {
		return out, nil
	}
	for _, part := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return nil, fmt.Errorf("entry %q: want class=price", part)
		}
		f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil || f < 0 {
			return nil, fmt.Errorf("entry %q: invalid price", part)
		}
		out[strings.TrimSpace(k)] = f
	}
	return out, nil
}

func fatal(msg string, err error) {
	slog.Error(msg, "err", err)
	os.Exit(1)
}
