package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/ByronGary/kubesentry/internal/api"
	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/cloudwatch"
	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/metrics"
	"github.com/ByronGary/kubesentry/internal/pgstore"
)

// setupAudit builds the audit pipeline when any source or the Postgres
// store is configured: the ingester and its store, the journal, the file
// tailer and the CloudWatch reader, with their metrics and health checks.
// The returned cleanups flush and close the store.
func setupAudit(ctx context.Context, cfg *config, policy detectors.Policy, srv *api.Server) (closers, error) {
	var cleanup closers
	if cfg.auditLogFile == "" && cfg.auditToken == "" && cfg.auditJournal == "" && !cfg.cloudwatch && cfg.auditStore != "postgres" {
		return cleanup, nil
	}
	ing := &audit.Ingester{SystemPrefixes: policy.SystemPrincipalPrefixes, RedactExecArgs: cfg.auditRedactExecArgs}
	var pg *pgstore.Store
	if cfg.auditStore == "postgres" {
		var err error
		pg, err = pgstore.Open(ctx, pgstore.ResolveDSN(cfg.pgDSN), pgstore.Options{
			Schema: cfg.pgSchema, Retention: cfg.auditRetention, Owner: hostname(), Logger: slog.Default(),
			MaxConns: int32(cfg.pgMaxConns), QueryTimeout: cfg.pgQueryTimeout,
		})
		if err != nil {
			return cleanup, fmt.Errorf("audit store: %w", err)
		}
		cleanup = append(cleanup, func() {
			cctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := pg.Close(cctx); err != nil {
				slog.Warn("closing the audit store", "err", err)
			}
		})
		ing.Backend = pg
		go pg.MaintainLoop(ctx, time.Hour)
		srv.Checks = append(srv.Checks, api.HealthCheck{Name: "postgres", Check: pg.Ping})
		srv.AuditHealth = watchPostgres(ctx, pg, 15*time.Second)
		metrics.AuditQueueDepth.SetFunc(func() float64 { return float64(pg.Stats().Queued) })
		slog.Info("audit store: postgres", "schema", cfg.pgSchema, "retention", formatDuration(cfg.auditRetention))
	} else {
		ing.Store = audit.NewMemoryStore(cfg.auditMaxEvents)
		if cfg.auditJournal != "" {
			n, err := audit.LoadJournal(cfg.auditJournal, ing.Store)
			if err != nil {
				return cleanup, fmt.Errorf("load audit journal: %w", err)
			}
			slog.Info("replayed audit journal", "events", n)
			j, err := audit.OpenJournal(cfg.auditJournal)
			if err != nil {
				return cleanup, fmt.Errorf("open audit journal: %w", err)
			}
			cleanup = append(cleanup, func() { _ = j.Close() })
			ing.Journal = j
		}
	}
	srv.Audit = ing
	srv.AuditToken = cfg.auditToken
	if cfg.auditToken == "" {
		slog.Warn("no -audit-token set; the POST /audit/webhook endpoint is disabled")
	}

	if cfg.auditLogFile != "" {
		go func() {
			slog.Info("following audit log", "path", cfg.auditLogFile)
			// One line is one event; a malformed line is logged and skipped.
			err := audit.TailFile(ctx, cfg.auditLogFile, cfg.auditFromStart, time.Second, func(line []byte) {
				ing.IngestLine(line)
				metrics.AuditIngested.With("file").Inc()
			})
			if err != nil && !errors.Is(err, context.Canceled) {
				slog.Error("audit log tailer stopped", "err", err)
			}
		}()
	}

	var cw *cwRunner
	if cfg.cloudwatch {
		client, err := cloudwatch.New(ctx, cfg.awsRegion, cfg.cloudwatchEndpoint)
		if err != nil {
			return cleanup, err
		}
		group := cfg.cloudwatchLogGroup
		if group == "" {
			group = "/aws/eks/" + cfg.clusterName + "/cluster"
		}
		cw = &cwRunner{
			api: client, logGroup: group, prefix: cfg.cloudwatchPrefix, start: cfg.cloudwatchStart,
			pg: pg, store: ing.Active(),
			ingest: func(b []byte) ([]audit.Event, error) {
				events, err := audit.Parse(bytes.NewReader(b))
				if err == nil {
					ing.Prepare(events)
				}
				return events, err
			},
		}
		go cw.run(ctx)
		srv.Checks = append(srv.Checks, api.HealthCheck{Name: "cloudwatch", Check: func(context.Context) error {
			if st, ok := cw.status(); ok && st.ErrorKind != "" {
				return fmt.Errorf("%s: %s", st.ErrorKind, st.LastError)
			}
			return nil
		}})
		metrics.CloudWatchLag.SetFunc(cw.lagSeconds)
		srv.CloudWatchLag = cw.lag
		slog.Info("reading EKS audit logs from CloudWatch", "logGroup", group, "streamPrefix", cfg.cloudwatchPrefix)
	}
	go pollAuditCounters(ctx, pg, cw)
	return cleanup, nil
}

// pollAuditCounters turns the store's and reader's running totals into the
// store-errors and ingested counters.
func pollAuditCounters(ctx context.Context, pg *pgstore.Store, cw *cwRunner) {
	if pg == nil && cw == nil {
		return
	}
	var lastErrors, lastCW int64
	var lastReader *cloudwatch.Reader
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if pg != nil {
			if n := pg.Stats().Errors; n > lastErrors {
				metrics.AuditStoreErrors.Add(float64(n - lastErrors))
				lastErrors = n
			}
		}
		if cw != nil {
			r := cw.cur.Load()
			if r != lastReader {
				lastReader, lastCW = r, 0
			}
			if r != nil {
				if n := r.Status().EventsIngested; n > lastCW {
					metrics.AuditIngested.With("cloudwatch").Add(float64(n - lastCW))
					lastCW = n
				}
			}
		}
	}
}

// cwRunner keeps one CloudWatch reader running. With Postgres only the
// replica holding the "cloudwatch" advisory lock reads, committing events
// and checkpoint together; the others retry for the lock. With the memory
// store the single replica reads into it.
type cwRunner struct {
	api      cloudwatch.FilterAPI
	logGroup string
	prefix   string
	start    time.Duration
	ingest   func([]byte) ([]audit.Event, error)
	pg       *pgstore.Store // nil: memory store
	store    audit.Store

	cur atomic.Pointer[cloudwatch.Reader]
}

// leaderRetry is how often a standby replica tries for the reader's lock.
const leaderRetry = 30 * time.Second

func (c *cwRunner) reader(store cloudwatch.Committer) *cloudwatch.Reader {
	return &cloudwatch.Reader{API: c.api, Store: store, LogGroup: c.logGroup, StreamPrefix: c.prefix, Start: c.start, Ingest: c.ingest}
}

func (c *cwRunner) run(ctx context.Context) {
	if c.pg == nil {
		r := c.reader(&cloudwatch.StoreCommitter{Store: c.store})
		c.cur.Store(r)
		_ = r.Run(ctx)
		return
	}
	for ctx.Err() == nil {
		l, ok, err := c.pg.TryLead(ctx, "cloudwatch")
		switch {
		case err != nil:
			slog.Warn("cloudwatch reader: could not try for the lock", "err", err)
		case ok:
			c.lead(ctx, l)
			continue
		}
		select {
		case <-ctx.Done():
		case <-time.After(leaderRetry):
		}
	}
}

// leadership is the held lock the reader runs under: *pgstore.Leader.
type leadership interface {
	cloudwatch.Committer
	Lost() <-chan struct{}
	Release(ctx context.Context) error
}

var _ leadership = (*pgstore.Leader)(nil)

// stopWarnAfter is how long lead waits for the reader to stop after the lock
// is lost before it logs that the reader is stuck.
const stopWarnAfter = 10 * time.Second

// lead runs the reader while l is held, and releases it afterwards. The
// moment the lock is lost the reader stops counting as this replica's: its
// status, the lag gauge and the readiness check drop it at once, even if
// Run takes a while to return (a commit stuck on a dead connection), so a
// replica without the lock never reports lag. Run's context is cancelled at
// the same time, and every call it makes honours it.
func (c *cwRunner) lead(ctx context.Context, l leadership) {
	slog.Info("cloudwatch reader: this replica leads")
	lctx, cancel := context.WithCancel(ctx)
	defer cancel()
	r := c.reader(l)
	c.cur.Store(r)
	stopped := make(chan struct{})
	go func() {
		select {
		case <-l.Lost():
			c.cur.CompareAndSwap(r, nil)
			cancel()
		case <-lctx.Done():
		}
		select {
		case <-stopped:
		case <-time.After(stopWarnAfter):
			slog.Warn("cloudwatch reader: still stopping after losing the lock", "waited", stopWarnAfter)
		}
	}()
	err := r.Run(lctx)
	close(stopped)
	c.cur.CompareAndSwap(r, nil)
	rctx, rcancel := context.WithTimeout(context.Background(), 10*time.Second)
	_ = l.Release(rctx)
	rcancel()
	if ctx.Err() == nil {
		slog.Warn("cloudwatch reader: leadership ended; retrying", "err", err)
	}
}

// status is the running reader's status; false on a standby replica and
// from the moment a leader loses its lock.
func (c *cwRunner) status() (cloudwatch.Status, bool) {
	if r := c.cur.Load(); r != nil {
		return r.Status(), true
	}
	return cloudwatch.Status{}, false
}

// lag is how far the reader is behind; ok is false on a replica that is not
// reading, and before its first commit.
func (c *cwRunner) lag() (time.Duration, bool) {
	if st, ok := c.status(); ok && !st.WindowEnd.IsZero() {
		return st.Lag, true
	}
	return 0, false
}

// pinger is what watchPostgres needs of the store.
type pinger interface {
	Ping(ctx context.Context) error
	Stats() pgstore.Stats
}

// watchPostgres pings the store every interval in the background and
// returns its health for the Overview: the last ping's error, else the
// last write error while writes keep failing. Reading it never waits on
// the database.
func watchPostgres(ctx context.Context, pg pinger, interval time.Duration) func() error {
	var last atomic.Pointer[error]
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			pctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			err := pg.Ping(pctx)
			cancel()
			if ctx.Err() == nil {
				last.Store(&err)
			}
		}
	}()
	return func() error {
		if p := last.Load(); p != nil && *p != nil {
			return *p
		}
		if st := pg.Stats(); st.LastError != "" {
			return errors.New(st.LastError)
		}
		return nil
	}
}

// lagSeconds is kubesentry_cloudwatch_lag_seconds: how far the reader is
// behind, 0 on a replica that is not reading.
func (c *cwRunner) lagSeconds() float64 {
	if st, ok := c.status(); ok && !st.WindowEnd.IsZero() {
		return st.Lag.Seconds()
	}
	return 0
}
