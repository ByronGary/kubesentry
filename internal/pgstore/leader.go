package pgstore

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ByronGary/kubesentry/internal/audit"
)

// Leader is a held session-level advisory lock on a dedicated connection. It
// is how one replica among many runs a single-writer job, such as the
// CloudWatch reader: Commit writes events and the job's checkpoint in one
// transaction on the lock's own connection, after checking the lock is still
// held, so a replica that lost the lock (its connection dropped, Postgres
// failed over) cannot write. Leader satisfies cloudwatch.Committer.
type Leader struct {
	s    *Store
	name string
	key  int64

	mu       sync.Mutex
	conn     *pgx.Conn
	lost     chan struct{}
	once     sync.Once
	stopOnce sync.Once
	stop     chan struct{}
	done     chan struct{}
}

// LeaderCheckInterval is how often a Leader verifies, in the background, that
// it still holds its lock.
var LeaderCheckInterval = 10 * time.Second

// TryLead tries to take the named lock (scoped to the store's schema)
// without waiting. ok is false when another session holds it. The caller must
// Release a returned Leader.
func (s *Store) TryLead(ctx context.Context, name string) (*Leader, bool, error) {
	c, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("pgstore: lead %s: %w", name, err)
	}
	key := lockKey(s.o.Schema, "lead/"+name)
	var ok bool
	if err := c.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", key).Scan(&ok); err != nil {
		c.Release()
		return nil, false, fmt.Errorf("pgstore: lead %s: %w", name, err)
	}
	if !ok {
		c.Release()
		return nil, false, nil
	}
	// The connection now carries the lock: take it out of the pool for good.
	l := &Leader{s: s, name: name, key: key, conn: c.Hijack(), lost: make(chan struct{}), stop: make(chan struct{}), done: make(chan struct{})}
	go l.watch()
	return l, true, nil
}

// Name returns the lock name.
func (l *Leader) Name() string { return l.name }

// Lost is closed once the lock is known to be gone (or after Release).
func (l *Leader) Lost() <-chan struct{} { return l.lost }

func (l *Leader) markLost() {
	l.once.Do(func() { close(l.lost) })
}

func (l *Leader) watch() {
	defer close(l.done)
	t := time.NewTicker(LeaderCheckInterval)
	defer t.Stop()
	for {
		select {
		case <-l.stop:
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			err := l.Check(ctx)
			cancel()
			if err != nil {
				return
			}
		}
	}
}

// Check verifies the lock is still held; on failure the Leader is lost and
// the error wraps audit.ErrLeadershipLost.
func (l *Leader) Check(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conn == nil {
		return fmt.Errorf("pgstore: %s: released: %w", l.name, audit.ErrLeadershipLost)
	}
	held, err := l.held(ctx, l.conn)
	return l.verdict(held, err)
}

type queryRower interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func (l *Leader) held(ctx context.Context, q queryRower) (bool, error) {
	var held bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND granted
  AND pid = pg_backend_pid() AND classid::bigint = $1 AND objid::bigint = $2 AND objsubid = 1)`,
		int64(uint64(l.key)>>32), int64(uint64(l.key)&0xffffffff)).Scan(&held)
	return held, err
}

// verdict turns a lock check into an error, closing the connection and
// marking the Leader lost when the lock is gone or the connection is dead.
// Called with l.mu held.
func (l *Leader) verdict(held bool, err error) error {
	if err == nil && held {
		return nil
	}
	if err != nil && !l.conn.IsClosed() && errors.Is(err, context.Canceled) {
		return err // our caller gave up; the lock may well be fine
	}
	l.conn.Close(context.Background())
	l.conn = nil
	l.markLost()
	if err != nil {
		return fmt.Errorf("pgstore: %s: %v: %w", l.name, err, audit.ErrLeadershipLost)
	}
	return fmt.Errorf("pgstore: %s: lock not held: %w", l.name, audit.ErrLeadershipLost)
}

// Commit stores events and sets the checkpoint of source to position (JSON)
// in one transaction on the lock's connection, after checking the lock is
// still held. Either both are written or neither.
func (l *Leader) Commit(ctx context.Context, events []audit.Event, source string, position []byte) error {
	norm := make([]audit.Event, len(events))
	for i, e := range events {
		norm[i] = audit.NormalizeForStore(e)
	}
	if len(position) == 0 {
		position = []byte("null")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conn == nil {
		return fmt.Errorf("pgstore: %s: released: %w", l.name, audit.ErrLeadershipLost)
	}
	tx, err := l.conn.Begin(ctx)
	if err != nil {
		return l.connErr(err)
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	held, err := l.held(ctx, tx)
	if err != nil || !held {
		return l.verdict(held, err)
	}
	if err := upsertEvents(ctx, tx, norm); err != nil {
		return l.connErr(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO ingest_checkpoints (source, position, owner, updated_at)
VALUES ($1, $2::jsonb, $3, now())
ON CONFLICT (source) DO UPDATE SET position = EXCLUDED.position, owner = EXCLUDED.owner, updated_at = now()`,
		source, string(position), l.s.o.Owner); err != nil {
		return l.connErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return l.connErr(err)
	}
	return nil
}

// connErr marks the Leader lost if the error killed its connection: a new
// connection would not hold the lock.
func (l *Leader) connErr(err error) error {
	if l.conn != nil && l.conn.IsClosed() {
		l.conn = nil
		l.markLost()
		return fmt.Errorf("pgstore: %s: %v: %w", l.name, err, audit.ErrLeadershipLost)
	}
	return fmt.Errorf("pgstore: %s: %w", l.name, err)
}

// Checkpoint returns the position last committed for source, or nil if none.
func (l *Leader) Checkpoint(ctx context.Context, source string) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conn == nil {
		return nil, fmt.Errorf("pgstore: %s: released: %w", l.name, audit.ErrLeadershipLost)
	}
	var pos string
	err := l.conn.QueryRow(ctx, "SELECT position::text FROM ingest_checkpoints WHERE source = $1", source).Scan(&pos)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, l.connErr(err)
	}
	if pos == "null" {
		return nil, nil
	}
	return []byte(pos), nil
}

// Release gives up the lock and closes its connection.
func (l *Leader) Release(ctx context.Context) error {
	l.stopOnce.Do(func() { close(l.stop) })
	<-l.done
	l.mu.Lock()
	defer l.mu.Unlock()
	l.markLost()
	if l.conn == nil {
		return nil
	}
	_, err := l.conn.Exec(ctx, "SELECT pg_advisory_unlock($1)", l.key)
	cerr := l.conn.Close(ctx)
	l.conn = nil
	if err != nil {
		return err
	}
	return cerr
}
