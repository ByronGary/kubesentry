// Package pgstore implements audit.Store on Postgres: daily partitions with
// retention, a bounded write queue drained by COPY and an idempotent upsert,
// and advisory-lock leadership for the single-writer jobs (the CloudWatch
// reader, partition maintenance). It is the only package that imports pgx.
//
// Every replica can Add (webhook ingest is idempotent: records are keyed by
// (audit_id, time) and a later stage never loses to an earlier one) and Query.
// Results equal MemoryStore's for the same events and query; the shared
// semantics live in package audit and TestPGMatchesMemory enforces them.
package pgstore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgconn/ctxwatch"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ByronGary/kubesentry/internal/audit"
)

// Options configures a Store. Zero values take the defaults shown.
type Options struct {
	Schema        string        // "kubesentry"; one schema per cluster
	Retention     time.Duration // 30 days; negative keeps partitions forever
	QueueSize     int           // 50,000 events waiting to be written before Add returns ErrBackpressure
	BatchSize     int           // 5,000 events per COPY
	FlushInterval time.Duration // 250ms: a partial batch is written after this long
	// CacheTTL is how long a Summarize or Coverage result counts as fresh
	// (30s). Older results are still served while one refresh per result
	// runs in the background (see cache.go). Negative disables caching.
	CacheTTL time.Duration
	// MaxConns pooled connections (10; leaders hold one more each). Reads
	// share MaxConns-2 of them, so the writer and maintenance always find one.
	MaxConns int32
	// QueryTimeout bounds each read (Query, and the queries behind Summarize
	// and Coverage): past it the read fails with audit.ErrOverloaded and
	// Postgres is asked to cancel the statement. Default 10s.
	QueryTimeout time.Duration
	// AcquireTimeout is how long a read waits for a free read slot before it
	// fails with audit.ErrOverloaded. Default 2s.
	AcquireTimeout time.Duration
	Owner          string // recorded with checkpoints; hostname/pid by default
	Now            func() time.Time
	Logger         *slog.Logger
}

func (o *Options) defaults() error {
	if o.Schema == "" {
		o.Schema = "kubesentry"
	}
	if !schemaRE.MatchString(o.Schema) {
		return fmt.Errorf("pgstore: invalid schema name %q: use letters, digits and underscores", o.Schema)
	}
	if o.Retention == 0 {
		o.Retention = 30 * 24 * time.Hour
	}
	if o.QueueSize <= 0 {
		o.QueueSize = 50_000
	}
	if o.BatchSize <= 0 {
		o.BatchSize = 5_000
	}
	if o.FlushInterval <= 0 {
		o.FlushInterval = 250 * time.Millisecond
	}
	if o.CacheTTL == 0 {
		o.CacheTTL = 30 * time.Second
	}
	if o.MaxConns <= 0 {
		o.MaxConns = 10
	}
	if o.QueryTimeout <= 0 {
		o.QueryTimeout = 10 * time.Second
	}
	if o.AcquireTimeout <= 0 {
		o.AcquireTimeout = 2 * time.Second
	}
	if o.Owner == "" {
		h, _ := os.Hostname()
		o.Owner = fmt.Sprintf("%s/%d", h, os.Getpid())
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return nil
}

var schemaRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,62}$`)

// ErrClosed is returned by Add after Close.
var ErrClosed = errors.New("pgstore: store is closed")

// Store is an audit.Store on Postgres. It is safe for concurrent use.
type Store struct {
	pool *pgxpool.Pool
	o    Options
	log  *slog.Logger

	mu         sync.Mutex
	queue      []audit.Event
	inflight   int
	firstAt    time.Time // when the oldest queued event arrived
	enqueued   uint64    // events accepted by Add, ever
	finished   uint64    // events written or dropped, ever
	progress   chan struct{}
	flushing   int
	closed     bool
	stats      Stats
	wake       chan struct{}
	abortCtx   context.Context // cancelled when Close gives up waiting
	abort      context.CancelFunc
	writerDone chan struct{}

	// readers holds one token per read in flight: at most MaxConns-2.
	readers chan struct{}

	cacheMu    sync.Mutex
	sumCache   map[string]*sumEntry              // by summaryCacheKey
	sumFlights map[string]*flight[audit.Summary] // refreshes in flight, by the same key
	covCache   *covEntry
	covFlight  *flight[audit.Coverage]
	// summarizeFn and coverageFn compute uncached results; nil means
	// s.summarizeNow and s.coverageNow. Tests replace them.
	summarizeFn func(context.Context, audit.Query) (audit.Summary, error)
	coverageFn  func(context.Context) (audit.Coverage, error)
	// exactCountBelow overrides the package's threshold (tests).
	exactCountBelow float64
}

// Stats describes the write path. The server exports Queued as the gauge
// kubesentry_audit_queue_depth and Errors as the counter
// kubesentry_audit_store_errors_total (names fixed in docs/contracts.md; the
// chart's alerts use them).
type Stats struct {
	Queued    int       // events waiting or being written: kubesentry_audit_queue_depth
	Written   int64     // events written (upserted) since Open
	Dropped   int64     // events rejected by Postgres as invalid, or abandoned at Close
	Batches   int64     // batches committed
	Errors    int64     // failed write attempts, each retried: kubesentry_audit_store_errors_total
	LastError string    // most recent write error, "" after a success
	LastWrite time.Time // last successful batch
}

var _ audit.Store = (*Store)(nil)

// Open connects, creates the schema and tables (migrations run once, under an
// advisory lock, so replicas can start together), ensures the partitions
// around today exist, and starts the writer.
func Open(ctx context.Context, dsn string, o Options) (*Store, error) {
	if err := o.defaults(); err != nil {
		return nil, err
	}
	cfg, err := poolConfig(dsn, o)
	if err != nil {
		return nil, err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("pgstore: connect: %w", err)
	}
	s := &Store{
		pool:       pool,
		o:          o,
		log:        o.Logger.With("component", "pgstore"),
		progress:   make(chan struct{}),
		wake:       make(chan struct{}, 1),
		writerDone: make(chan struct{}),
		readers:    make(chan struct{}, max(1, o.MaxConns-2)),
	}
	s.abortCtx, s.abort = context.WithCancel(context.Background())
	if err := s.migrate(ctx); err != nil {
		s.abort()
		pool.Close()
		return nil, err
	}
	if err := s.Maintain(ctx); err != nil {
		s.abort()
		pool.Close()
		return nil, err
	}
	go s.writer()
	if o.CacheTTL > 0 {
		s.warmCoverage() // so the first /info finds it
	}
	return s, nil
}

// DSNEnv names the environment variable that supplies the DSN when the
// -pg-dsn flag is empty; the Helm chart mounts it from a Secret.
const DSNEnv = "KUBESENTRY_PG_DSN"

// ResolveDSN returns flagValue, or $KUBESENTRY_PG_DSN when the flag is empty.
// Whatever the DSN leaves out comes from the libpq environment variables
// (PGHOST, PGUSER, PGPASSWORD, PGSSLMODE, PGSSLROOTCERT, ...), so even an
// empty DSN can be complete.
func ResolveDSN(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	return os.Getenv(DSNEnv)
}

// poolConfig parses dsn with pgxpool.ParseConfig, which applies the libpq
// PG* environment variables for anything the DSN does not set: the chart
// passes RDS TLS as PGSSLMODE=verify-full and PGSSLROOTCERT rather than in the
// DSN. Never assemble the config by hand, or those are silently ignored.
func poolConfig(dsn string, o Options) (*pgxpool.Config, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("pgstore: parse DSN: %w", err)
	}
	cfg.MaxConns = o.MaxConns
	// A cancelled context (a query past QueryTimeout, a request the client
	// gave up on, a leader that lost its lock) sends Postgres a cancel
	// request, so the statement stops there too; pgx's default only closes
	// the socket, and the server keeps running the query until it next
	// writes. The deadline still closes the socket if the server does not
	// answer the cancel.
	cfg.ConnConfig.BuildContextWatcherHandler = func(pc *pgconn.PgConn) ctxwatch.Handler {
		return &pgconn.CancelRequestContextWatcherHandler{Conn: pc, DeadlineDelay: 2 * time.Second}
	}
	rp := cfg.ConnConfig.RuntimeParams
	rp["search_path"] = o.Schema
	rp["timezone"] = "UTC"
	if rp["application_name"] == "" {
		rp["application_name"] = "kubesentry"
	}
	// JIT compiling costs 70-160 ms per summary (measured at 3.2M events)
	// and buys nothing for queries this short.
	if rp["jit"] == "" {
		rp["jit"] = "off"
	}
	return cfg, nil
}

// Pool exposes the connection pool, for readiness checks.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Ping checks that Postgres answers.
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// Add queues events for the writer. It returns audit.ErrBackpressure when the
// queue cannot take them all (nothing is queued then), and ErrClosed after
// Close. Queued events are durable only after Flush returns.
func (s *Store) Add(ctx context.Context, events []audit.Event) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(events) == 0 {
		return nil
	}
	norm := make([]audit.Event, len(events))
	for i, e := range events {
		norm[i] = audit.NormalizeForStore(e)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	pending := len(s.queue) + s.inflight
	// An oversized payload is still taken when nothing else waits, so it can
	// never be refused forever.
	if pending > 0 && pending+len(norm) > s.o.QueueSize {
		return audit.ErrBackpressure
	}
	if len(s.queue) == 0 {
		s.firstAt = time.Now()
	}
	s.queue = append(s.queue, norm...)
	s.enqueued += uint64(len(norm))
	s.signal()
	return nil
}

func (s *Store) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Flush waits until every event queued before the call is written (or
// dropped as invalid). It writes a partial batch at once instead of waiting
// for FlushInterval.
func (s *Store) Flush(ctx context.Context) error {
	s.mu.Lock()
	target := s.enqueued
	s.flushing++
	s.signal()
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.flushing--
		s.mu.Unlock()
	}()
	for {
		s.mu.Lock()
		done, ch, lastErr := s.finished >= target, s.progress, s.stats.LastError
		s.mu.Unlock()
		if done {
			return nil
		}
		select {
		case <-ch:
		case <-s.writerDone:
			s.mu.Lock()
			done = s.finished >= target
			s.mu.Unlock()
			if done {
				return nil
			}
			return ErrClosed
		case <-ctx.Done():
			if lastErr != "" {
				return fmt.Errorf("pgstore: flush: %w (last write error: %s)", ctx.Err(), lastErr)
			}
			return fmt.Errorf("pgstore: flush: %w", ctx.Err())
		}
	}
}

// Close stops accepting events, writes what is queued, and closes the pool.
// If ctx ends first, the remaining events are dropped and counted.
func (s *Store) Close(ctx context.Context) error {
	s.mu.Lock()
	already := s.closed
	s.closed = true
	s.signal()
	s.mu.Unlock()
	if already {
		<-s.writerDone
		return nil
	}
	var err error
	select {
	case <-s.writerDone:
	case <-ctx.Done():
		s.abort()
		<-s.writerDone
		err = fmt.Errorf("pgstore: close: %w; %d events dropped", ctx.Err(), s.Stats().Dropped)
	}
	s.abort()
	s.pool.Close()
	return err
}

// Stats returns write-path counters.
func (s *Store) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.stats
	st.Queued = len(s.queue) + s.inflight
	return st
}

// writer drains the queue in batches until Close.
func (s *Store) writer() {
	defer close(s.writerDone)
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		batch, wait, ok := s.nextBatch()
		if !ok {
			return
		}
		if batch == nil {
			timer.Reset(wait)
			select {
			case <-s.wake:
			case <-timer.C:
			}
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			continue
		}
		written, dropped := s.writeWithRetry(batch)
		s.mu.Lock()
		s.inflight = 0
		s.finished += uint64(len(batch))
		s.stats.Written += int64(written)
		s.stats.Dropped += int64(dropped)
		close(s.progress)
		s.progress = make(chan struct{})
		s.mu.Unlock()
	}
}

// nextBatch returns a batch when one is due, or how long to wait for one, or
// ok=false once closed and drained.
func (s *Store) nextBatch() (batch []audit.Event, wait time.Duration, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.queue)
	if n == 0 {
		if s.closed {
			return nil, 0, false
		}
		return nil, s.o.FlushInterval, true
	}
	age := time.Since(s.firstAt)
	if n < s.o.BatchSize && s.flushing == 0 && !s.closed && age < s.o.FlushInterval {
		return nil, s.o.FlushInterval - age, true
	}
	k := min(n, s.o.BatchSize)
	batch = make([]audit.Event, k)
	copy(batch, s.queue)
	if k == n {
		s.queue = nil
	} else {
		// Copy the remainder so the backing array of written events is freed.
		s.queue = append([]audit.Event(nil), s.queue[k:]...)
	}
	s.inflight = k
	return batch, 0, true
}

// writeWithRetry writes a batch, retrying transient failures with backoff
// (the queue fills meanwhile, and Add pushes back). Rows Postgres rejects as
// invalid are isolated by bisection and dropped so one bad event cannot block
// the rest.
func (s *Store) writeWithRetry(batch []audit.Event) (written, dropped int) {
	backoff := 100 * time.Millisecond
	for {
		ctx, cancel := context.WithTimeout(s.abortCtx, 2*time.Minute)
		err := s.writeBatch(ctx, batch)
		cancel()
		if err == nil {
			s.mu.Lock()
			s.stats.Batches++
			s.stats.LastError = ""
			s.stats.LastWrite = time.Now()
			s.mu.Unlock()
			return len(batch), 0
		}
		s.mu.Lock()
		s.stats.Errors++
		s.stats.LastError = err.Error()
		s.mu.Unlock()
		if isDataError(err) {
			if len(batch) == 1 {
				s.log.Error("dropping audit event Postgres rejects", "auditID", batch[0].AuditID, "err", err)
				return 0, 1
			}
			h := len(batch) / 2
			w1, d1 := s.writeWithRetry(batch[:h])
			w2, d2 := s.writeWithRetry(batch[h:])
			return w1 + w2, d1 + d2
		}
		s.log.Warn("audit batch write failed; retrying", "events", len(batch), "backoff", backoff, "err", err)
		select {
		case <-s.abortCtx.Done():
			return 0, len(batch)
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 5*time.Second)
	}
}

func (s *Store) writeBatch(ctx context.Context, batch []audit.Event) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	if err := upsertEvents(ctx, tx, batch); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// isDataError reports whether Postgres rejected the data itself (bad
// encoding, a value too large to index, a constraint), as opposed to a
// connection or availability problem worth retrying.
func isDataError(err error) bool {
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || len(pe.Code) < 2 {
		return false
	}
	switch pe.Code[:2] {
	case "22", "23", "54":
		return true
	}
	return false
}

var stageColumns = []string{"seq", "audit_id", "time", "stage_rank", "stage", "verb", "username", "actor_kind", "groups", "arn",
	"session_name", "impersonated_user", "source_ips", "user_agent", "api_group", "resource", "subresource", "namespace",
	"name", "request_uri", "status_code", "decision", "tags", "is_read"}

const createStage = `CREATE TEMP TABLE IF NOT EXISTS audit_stage (
  seq int NOT NULL, audit_id text COLLATE "C" NOT NULL, time timestamptz NOT NULL, stage_rank smallint NOT NULL,
  stage text NOT NULL, verb text NOT NULL, username text NOT NULL, actor_kind text NOT NULL, groups text[], arn text,
  session_name text, impersonated_user text, source_ips text[], user_agent text, api_group text, resource text,
  subresource text, namespace text NOT NULL, name text, request_uri text, status_code int, decision text,
  tags text[] NOT NULL, is_read boolean NOT NULL
) ON COMMIT DELETE ROWS`

const eventColumns = `audit_id, time, stage_rank, stage, verb, username, actor_kind, groups, arn, session_name,
  impersonated_user, source_ips, user_agent, api_group, resource, subresource, namespace, name, request_uri,
  status_code, decision, tags, is_read`

// mergeStage upserts the staged rows. Within the batch the highest stage rank
// wins, ties going to the last added (seq); against stored rows an equal or
// higher rank replaces, exactly as MemoryStore.Add does.
const mergeStage = `INSERT INTO audit_events AS a (` + eventColumns + `)
SELECT DISTINCT ON (audit_id, time) ` + eventColumns + `
FROM audit_stage ORDER BY audit_id, time, stage_rank DESC, seq DESC
ON CONFLICT (audit_id, time) DO UPDATE SET
  stage_rank = EXCLUDED.stage_rank, stage = EXCLUDED.stage, verb = EXCLUDED.verb, username = EXCLUDED.username,
  actor_kind = EXCLUDED.actor_kind, groups = EXCLUDED.groups, arn = EXCLUDED.arn, session_name = EXCLUDED.session_name,
  impersonated_user = EXCLUDED.impersonated_user, source_ips = EXCLUDED.source_ips, user_agent = EXCLUDED.user_agent,
  api_group = EXCLUDED.api_group, resource = EXCLUDED.resource, subresource = EXCLUDED.subresource,
  namespace = EXCLUDED.namespace, name = EXCLUDED.name, request_uri = EXCLUDED.request_uri,
  status_code = EXCLUDED.status_code, decision = EXCLUDED.decision, tags = EXCLUDED.tags, is_read = EXCLUDED.is_read,
  ingested_at = now()
WHERE a.stage_rank <= EXCLUDED.stage_rank`

// upsertEvents stages normalized events with COPY and merges them, inside tx.
func upsertEvents(ctx context.Context, tx pgx.Tx, events []audit.Event) error {
	if len(events) == 0 {
		return nil
	}
	if _, err := tx.Exec(ctx, createStage); err != nil {
		return fmt.Errorf("create staging table: %w", err)
	}
	_, err := tx.CopyFrom(ctx, pgx.Identifier{"audit_stage"}, stageColumns, pgx.CopyFromSlice(len(events), func(i int) ([]any, error) {
		e := &events[i]
		tags := e.Tags
		if tags == nil {
			tags = []string{}
		}
		return []any{int32(i), e.AuditID, e.Time, int16(audit.StageRank(e.Stage)), e.Stage, e.Verb, e.Username, e.ActorKind,
			e.Groups, e.ARN, e.SessionName, e.ImpersonatedUser, e.SourceIPs, e.UserAgent, e.APIGroup, e.Resource,
			e.Subresource, e.Namespace, e.Name, e.RequestURI, int32(e.StatusCode), e.Decision, tags, audit.IsRead(e.Verb)}, nil
	}))
	if err != nil {
		return fmt.Errorf("copy audit events: %w", err)
	}
	if _, err := tx.Exec(ctx, mergeStage); err != nil {
		return fmt.Errorf("merge audit events: %w", err)
	}
	return nil
}
