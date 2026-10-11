package pgstore

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const partitionPrefix = "audit_events_"

// MaintainResult reports what one Maintain run changed.
type MaintainResult struct {
	Created     []string // partitions created
	Dropped     []string // partitions dropped for retention
	Moved       int64    // rows moved out of the default partition
	PurgedRows  int64    // rows past retention deleted from the default partition
	Partitions  int      // daily partitions after the run
	DefaultRows int64    // rows left in the default partition (should be 0)
}

// Maintain keeps the daily partitions in shape: it creates audit_events_YYYYMMDD
// (UTC) from yesterday to three days ahead, plus a partition for any day that
// has rows in the default partition (a backfill of old events, clock skew),
// moving those rows into it; drops partitions entirely older than Retention
// and purges such rows from the default partition; then ANALYZEs what it
// created. It is idempotent and serializes itself across replicas with a
// transaction-level advisory lock, so any replica may run it; running it on
// the leader (TryLead) merely avoids redundant work. Open runs it once.
func (s *Store) Maintain(ctx context.Context) error {
	_, err := s.MaintainReport(ctx)
	return err
}

// MaintainReport is Maintain returning what it did.
func (s *Store) MaintainReport(ctx context.Context) (MaintainResult, error) {
	var res MaintainResult
	now := s.o.Now().UTC()
	today := now.Truncate(24 * time.Hour)
	var cutoff time.Time // partitions ending at or before this are past retention
	if s.o.Retention > 0 {
		cutoff = now.Add(-s.o.Retention)
	}

	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", lockKey(s.o.Schema, "maintain")); err != nil {
			return err
		}
		existing, err := listPartitions(ctx, tx, s.o.Schema)
		if err != nil {
			return err
		}
		want := map[time.Time]bool{}
		for d := -1; d <= 3; d++ {
			want[today.AddDate(0, 0, d)] = true
		}
		rows, err := tx.Query(ctx, "SELECT DISTINCT date_trunc('day', time) FROM audit_events_default")
		if err != nil {
			return err
		}
		days, err := pgx.CollectRows(rows, pgx.RowTo[time.Time])
		if err != nil {
			return err
		}
		for _, d := range days {
			want[d.UTC()] = true
		}
		var todo []time.Time
		for d := range want {
			if _, ok := existing[d]; ok {
				continue
			}
			if !cutoff.IsZero() && !d.AddDate(0, 0, 1).After(cutoff) {
				continue // wholly past retention: purged below instead
			}
			todo = append(todo, d)
		}
		sort.Slice(todo, func(i, j int) bool { return todo[i].Before(todo[j]) })
		for _, d := range todo {
			moved, err := createPartition(ctx, tx, d)
			if err != nil {
				return fmt.Errorf("create partition for %s: %w", d.Format("2006-01-02"), err)
			}
			existing[d] = partitionName(d)
			res.Created = append(res.Created, partitionName(d))
			res.Moved += moved
		}
		if !cutoff.IsZero() {
			for d, name := range existing {
				if d.AddDate(0, 0, 1).After(cutoff) {
					continue
				}
				if _, err := tx.Exec(ctx, "DROP TABLE IF EXISTS "+pgx.Identifier{name}.Sanitize()); err != nil {
					return fmt.Errorf("drop partition %s: %w", name, err)
				}
				delete(existing, d)
				res.Dropped = append(res.Dropped, name)
			}
			tag, err := tx.Exec(ctx, "DELETE FROM audit_events_default WHERE time < $1", cutoff.Truncate(24*time.Hour))
			if err != nil {
				return err
			}
			res.PurgedRows = tag.RowsAffected()
		}
		res.Partitions = len(existing)
		return tx.QueryRow(ctx, "SELECT count(*) FROM audit_events_default").Scan(&res.DefaultRows)
	})
	if err != nil {
		return res, fmt.Errorf("pgstore: maintain: %w", err)
	}
	sort.Strings(res.Dropped)
	for _, name := range res.Created {
		if _, err := s.pool.Exec(ctx, "ANALYZE "+pgx.Identifier{name}.Sanitize()); err != nil {
			s.log.Warn("analyze new partition failed", "partition", name, "err", err)
		}
	}
	if len(res.Created) > 0 || len(res.Dropped) > 0 || res.PurgedRows > 0 {
		s.log.Info("audit partitions maintained", "created", res.Created, "dropped", res.Dropped,
			"moved", res.Moved, "purged", res.PurgedRows, "partitions", res.Partitions)
	}
	return res, nil
}

// MaintainLoop runs Maintain every interval (hourly when 0) until ctx ends.
func (s *Store) MaintainLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Hour
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.Maintain(ctx); err != nil && ctx.Err() == nil {
				s.log.Error("audit partition maintenance failed", "err", err)
			}
		}
	}
}

func partitionName(day time.Time) string { return partitionPrefix + day.Format("20060102") }

// listPartitions returns the daily partitions of audit_events by start day.
func listPartitions(ctx context.Context, tx pgx.Tx, schema string) (map[time.Time]string, error) {
	rows, err := tx.Query(ctx, `SELECT c.relname FROM pg_inherits i
JOIN pg_class c ON c.oid = i.inhrelid
JOIN pg_class p ON p.oid = i.inhparent
JOIN pg_namespace n ON n.oid = p.relnamespace
WHERE p.relname = 'audit_events' AND n.nspname = $1`, schema)
	if err != nil {
		return nil, err
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	out := map[time.Time]string{}
	for _, name := range names {
		suffix, ok := strings.CutPrefix(name, partitionPrefix)
		if !ok {
			continue
		}
		d, err := time.Parse("20060102", suffix)
		if err != nil {
			continue // audit_events_default
		}
		out[d] = name
	}
	return out, nil
}

// createPartition creates the partition for day, first moving any rows for
// that day out of the default partition (Postgres refuses to create a
// partition whose range the default partition still holds rows for).
func createPartition(ctx context.Context, tx pgx.Tx, day time.Time) (int64, error) {
	lo, hi := day, day.AddDate(0, 0, 1)
	name := pgx.Identifier{partitionName(day)}.Sanitize()
	if _, err := tx.Exec(ctx, "CREATE TEMP TABLE IF NOT EXISTS audit_moving (LIKE audit_events) ON COMMIT DROP"); err != nil {
		return 0, err
	}
	tag, err := tx.Exec(ctx, `WITH d AS (DELETE FROM audit_events_default WHERE time >= $1 AND time < $2 RETURNING *)
INSERT INTO audit_moving SELECT * FROM d`, lo, hi)
	if err != nil {
		return 0, err
	}
	moved := tag.RowsAffected()
	ddl := fmt.Sprintf("CREATE TABLE %s PARTITION OF audit_events FOR VALUES FROM ('%s') TO ('%s')",
		name, lo.Format("2006-01-02 15:04:05Z07:00"), hi.Format("2006-01-02 15:04:05Z07:00"))
	if _, err := tx.Exec(ctx, ddl); err != nil {
		return 0, err
	}
	if moved > 0 {
		if _, err := tx.Exec(ctx, "INSERT INTO audit_events SELECT * FROM audit_moving"); err != nil {
			return 0, err
		}
		if _, err := tx.Exec(ctx, "TRUNCATE audit_moving"); err != nil {
			return 0, err
		}
	}
	return moved, nil
}
