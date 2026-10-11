// Command demo runs kubesentry against synthetic data, so you can explore the
// UI without a cluster, Prometheus or audit log.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ByronGary/kubesentry/internal/demo"
	"github.com/ByronGary/kubesentry/internal/web"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "HTTP listen address")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv, err := demo.NewServer(ctx, web.Handler())
	if err != nil {
		slog.Error("build demo server", "err", err)
		os.Exit(1)
	}

	httpSrv := &http.Server{Addr: *addr, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()

	slog.Info("kubesentry demo: synthetic data, not connected to a cluster", "url", "http://"+*addr)
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("http server", "err", err)
		os.Exit(1)
	}
}
