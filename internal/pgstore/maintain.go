package pgstore

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ByronGary/kubesentry/internal/alerts"
	"github.com/ByronGary/kubesentry/internal/incidents"
)

const partitionPrefix = "audit_events_"

// partitioned is a table partitioned by day on timeCol: daily partitions
// named prefix+YYYYMMDD (UTC) plus parent+"_default".
type partitioned struct {
	parent, prefix, timeCol string
	// retention: partitions wholly older are dropped, and such rows purged
	// from the default partition; zero or less keeps everything.
	retention time.Duration
}

func (p partitioned) name(day time.Time) string { return p.prefix + day.Format("20060102") }

func (p partitioned) defaultPartition() string { return p.parent + "_default" }

// partitionedTables are the tables Maintain keeps: audit_events by time,
// and k8s_events by first_seen. Kubernetes event partitions are kept a day
// past the events retention, since an event's first_seen may be up to a
// day before its last_seen; PruneEvents deletes by last_seen.
func (s *Store) partitionedTables() []partitioned {
	events := s.o.EventsRetention
	if events > 0 {
		events += incidents.MaxRange
	}
	return []partitioned{
		{parent: "audit_events", prefix: partitionPrefix, timeCol: "time", retention: s.o.Retention},
		{parent: "k8s_events", prefix: "k8s_events_", timeCol: "first_seen", retention: events},
	}
}

// PartitionResult reports what Maintain changed in one partitioned table.
type PartitionResult struct {
	Created     []string // partitions created
	Dropped     []string // partitions dropped for retention
	Moved       int64    // rows moved out of the default partition
	PurgedRows  int64    // rows past retention deleted from the default partition
	Partitions  int      // daily partitions after the run
	DefaultRows int64    // rows left in the default partition (should be 0)
}

// MaintainResult reports what one Maintain run changed. The top-level
// partition fields describe audit_events.
type MaintainResult struct {
	Created     []string // partitions created
	Dropped     []string // partitions dropped for retention
	Moved       int64    // rows moved out of the default partition
	PurgedRows  int64    // rows past retention deleted from the default partition
	Partitions  int      // daily partitions after the run
	DefaultRows int64    // rows left in the default partition (should be 0)
	// AlertsPruned counts alert findings deleted because they resolved
	// more than alerts.Retention ago.
	AlertsPruned int
	// KubeEvents describes the k8s_events partitions.
	KubeEvents PartitionResult
	// EventsPruned counts Kubernetes events last seen before the events
	// retention; IncidentsPruned resolved incidents past the incident
	// retention.
	EventsPruned    int
	IncidentsPruned int
}

// Maintain keeps the daily partitions of audit_events and k8s_events in
// shape: it creates <table>_YYYYMMDD (UTC) from yesterday to three days
// ahead, plus a partition for any day that has rows in the default
// partition (a backfill of old events, clock skew), moving those rows into
// it; drops partitions entirely older than their retention and purges such
// rows from the default partition; deletes alert findings resolved more
// than alerts.Retention ago, Kubernetes events last seen before
// EventsRetention and incidents resolved before IncidentRetention; then
// ANALYZEs what it created. It is idempotent and serializes itself across
// replicas with a transaction-level advisory lock, so any replica may run
// it; running it on the leader (TryLead) merely avoids redundant work. Open
// runs it once.
func (s *Store) Maintain(ctx context.Context) error {
	_, err := s.MaintainReport(ctx)
	return err
}

// MaintainReport is Maintain returning what it did.
func (s *Store) MaintainReport(ctx context.Context) (MaintainResult, error) {
	var res MaintainResult
	now := s.o.Now().UTC()
	tables := s.partitionedTables()
	results := make([]PartitionResult, len(tables))
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", lockKey(s.o.Schema, "maintain")); err != nil {
			return err
		}
		for i, p := range tables {
			r, err := maintainTable(ctx, tx, s.o.Schema, p, now)
			if err != nil {
				return fmt.Errorf("%s: %w", p.parent, err)
			}
			results[i] = r
		}
		return nil
	})
	if err != nil {
		return res, fmt.Errorf("pgstore: maintain: %w", err)
	}
	a := results[0]
	res.Created, res.Dropped, res.Moved, res.PurgedRows, res.Partitions, res.DefaultRows = a.Created, a.Dropped, a.Moved, a.PurgedRows, a.Partitions, a.DefaultRows
	res.KubeEvents = results[1]
	if n, err := s.Alerts().Prune(ctx, now.Add(-alerts.Retention)); err != nil {
		s.log.Warn("pruning resolved alert findings failed", "err", err)
	} else {
		res.AlertsPruned = n
	}
	if s.o.EventsRetention > 0 {
		if n, err := s.KubeEvents().PruneEvents(ctx, now.Add(-s.o.EventsRetention)); err != nil {
			s.log.Warn("pruning Kubernetes events failed", "err", err)
		} else {
			res.EventsPruned = n
		}
	}
	if s.o.IncidentRetention > 0 {
		if n, err := s.Incidents().Prune(ctx, now.Add(-s.o.IncidentRetention)); err != nil {
			s.log.Warn("pruning resolved incidents failed", "err", err)
		} else {
			res.IncidentsPruned = n
		}
	}
	for _, r := range results {
		for _, name := range r.Created {
			if _, err := s.pool.Exec(ctx, "ANALYZE "+pgx.Identifier{name}.Sanitize()); err != nil {
				s.log.Warn("analyze new partition failed", "partition", name, "err", err)
			}
		}
	}
	for i, r := range results {
		if len(r.Created) > 0 || len(r.Dropped) > 0 || r.PurgedRows > 0 {
			s.log.Info("partitions maintained", "table", tables[i].parent, "created", r.Created, "dropped", r.Dropped,
				"moved", r.Moved, "purged", r.PurgedRows, "partitions", r.Partitions)
		}
	}
	if res.AlertsPruned > 0 || res.EventsPruned > 0 || res.IncidentsPruned > 0 {
		s.log.Info("pruned past retention", "alerts", res.AlertsPruned, "events", res.EventsPruned, "incidents", res.IncidentsPruned)
	}
	return res, nil
}

// maintainTable creates, moves into, drops and purges p's partitions.
func maintainTable(ctx context.Context, tx pgx.Tx, schema string, p partitioned, now time.Time) (PartitionResult, error) {
	var res PartitionResult
	today := now.Truncate(24 * time.Hour)
	var cutoff time.Time // partitions ending at or before this are past retention
	if p.retention > 0 {
		cutoff = now.Add(-p.retention)
	}
	existing, err := listPartitions(ctx, tx, schema, p)
	if err != nil {
		return res, err
	}
	want := map[time.Time]bool{}
	for d := -1; d <= 3; d++ {
		want[today.AddDate(0, 0, d)] = true
	}
	def := pgx.Identifier{p.defaultPartition()}.Sanitize()
	col := pgx.Identifier{p.timeCol}.Sanitize()
	rows, err := tx.Query(ctx, "SELECT DISTINCT date_trunc('day', "+col+") FROM "+def)
	if err != nil {
		return res, err
	}
	days, err := pgx.CollectRows(rows, pgx.RowTo[time.Time])
	if err != nil {
		return res, err
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
		moved, err := createPartition(ctx, tx, p, d)
		if err != nil {
			return res, fmt.Errorf("create partition for %s: %w", d.Format("2006-01-02"), err)
		}
		existing[d] = p.name(d)
		res.Created = append(res.Created, p.name(d))
		res.Moved += moved
	}
	if !cutoff.IsZero() {
		for d, name := range existing {
			if d.AddDate(0, 0, 1).After(cutoff) {
				continue
			}
			if _, err := tx.Exec(ctx, "DROP TABLE IF EXISTS "+pgx.Identifier{name}.Sanitize()); err != nil {
				return res, fmt.Errorf("drop partition %s: %w", name, err)
			}
			delete(existing, d)
			res.Dropped = append(res.Dropped, name)
		}
		tag, err := tx.Exec(ctx, "DELETE FROM "+def+" WHERE "+col+" < $1", cutoff.Truncate(24*time.Hour))
		if err != nil {
			return res, err
		}
		res.PurgedRows = tag.RowsAffected()
	}
	sort.Strings(res.Dropped)
	res.Partitions = len(existing)
	err = tx.QueryRow(ctx, "SELECT count(*) FROM "+def).Scan(&res.DefaultRows)
	return res, err
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
				s.log.Error("partition maintenance failed", "err", err)
			}
		}
	}
}

// partitionName names an audit_events partition.
func partitionName(day time.Time) string { return partitionPrefix + day.Format("20060102") }

// listPartitions returns the daily partitions of p by start day.
func listPartitions(ctx context.Context, tx pgx.Tx, schema string, p partitioned) (map[time.Time]string, error) {
	rows, err := tx.Query(ctx, `SELECT c.relname FROM pg_inherits i
JOIN pg_class c ON c.oid = i.inhrelid
JOIN pg_class p ON p.oid = i.inhparent
JOIN pg_namespace n ON n.oid = p.relnamespace
WHERE p.relname = $1 AND n.nspname = $2`, p.parent, schema)
	if err != nil {
		return nil, err
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	out := map[time.Time]string{}
	for _, name := range names {
		suffix, ok := strings.CutPrefix(name, p.prefix)
		if !ok {
			continue
		}
		d, err := time.Parse("20060102", suffix)
		if err != nil {
			continue // the default partition
		}
		out[d] = name
	}
	return out, nil
}

// createPartition creates p's partition for day, first moving any rows for
// that day out of the default partition (Postgres refuses to create a
// partition whose range the default partition still holds rows for).
func createPartition(ctx context.Context, tx pgx.Tx, p partitioned, day time.Time) (int64, error) {
	lo, hi := day, day.AddDate(0, 0, 1)
	name := pgx.Identifier{p.name(day)}.Sanitize()
	parent := pgx.Identifier{p.parent}.Sanitize()
	moving := pgx.Identifier{p.parent + "_moving"}.Sanitize()
	def := pgx.Identifier{p.defaultPartition()}.Sanitize()
	col := pgx.Identifier{p.timeCol}.Sanitize()
	if _, err := tx.Exec(ctx, "CREATE TEMP TABLE IF NOT EXISTS "+moving+" (LIKE "+parent+") ON COMMIT DROP"); err != nil {
		return 0, err
	}
	tag, err := tx.Exec(ctx, "WITH d AS (DELETE FROM "+def+" WHERE "+col+" >= $1 AND "+col+" < $2 RETURNING *) INSERT INTO "+moving+" SELECT * FROM d", lo, hi)
	if err != nil {
		return 0, err
	}
	moved := tag.RowsAffected()
	ddl := fmt.Sprintf("CREATE TABLE %s PARTITION OF %s FOR VALUES FROM ('%s') TO ('%s')",
		name, parent, lo.Format("2006-01-02 15:04:05Z07:00"), hi.Format("2006-01-02 15:04:05Z07:00"))
	if _, err := tx.Exec(ctx, ddl); err != nil {
		return 0, err
	}
	if moved > 0 {
		if _, err := tx.Exec(ctx, "INSERT INTO "+parent+" SELECT * FROM "+moving); err != nil {
			return 0, err
		}
		if _, err := tx.Exec(ctx, "TRUNCATE "+moving); err != nil {
			return 0, err
		}
	}
	return moved, nil
}
