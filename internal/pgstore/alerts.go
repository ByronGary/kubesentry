package pgstore

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ByronGary/kubesentry/internal/alerts"
	"github.com/ByronGary/kubesentry/internal/audit"
)

// AlertStore is alerts.Store on Postgres (tables alert_findings and
// alert_baseline, migration 0003). One from Store.Alerts reads and writes
// through the pool; one from Leader.Alerts writes on the lock's own
// connection, in a transaction that first checks the lock is still held,
// so a replica that lost the "alerts" lock cannot write.
type AlertStore struct {
	s *Store
	l *Leader // nil: writes go through the pool
}

var _ alerts.Store = (*AlertStore)(nil)

// Alerts returns the alert store on s.
func (s *Store) Alerts() *AlertStore { return &AlertStore{s: s} }

// Alerts returns the alert store whose writes require l to be held.
func (l *Leader) Alerts() *AlertStore { return &AlertStore{s: l.s, l: l} }

// alertReadTimeout bounds a Load; the evaluator retries at its next run.
const alertReadTimeout = 30 * time.Second

const alertColumns = `key, alert, check_name, kind, namespace, name, severity, title, owner, production,
  labels::text, annotations::text, state, silenced_until, digest, first_seen, last_seen, last_notified, resolved_at`

// Load implements alerts.Store.
func (a *AlertStore) Load(ctx context.Context, resolvedSince time.Time) ([]alerts.Finding, error) {
	ctx, cancel := context.WithTimeout(ctx, alertReadTimeout)
	defer cancel()
	rows, err := a.s.pool.Query(ctx, `SELECT `+alertColumns+` FROM alert_findings
WHERE state <> 'resolved' OR resolved_at >= $1 ORDER BY key`, resolvedSince)
	if err != nil {
		return nil, fmt.Errorf("pgstore: load alerts: %w", err)
	}
	out, err := pgx.CollectRows(rows, scanFinding)
	if err != nil {
		return nil, fmt.Errorf("pgstore: load alerts: %w", err)
	}
	return out, nil
}

func scanFinding(row pgx.CollectableRow) (alerts.Finding, error) {
	var f alerts.Finding
	var state, labels, annotations string
	err := row.Scan(&f.Key, &f.Alert, &f.Check, &f.Kind, &f.Namespace, &f.Name, &f.Severity, &f.Title, &f.Owner, &f.Production,
		&labels, &annotations, &state, &f.SilencedUntil, &f.Digest, &f.FirstSeen, &f.LastSeen, &f.LastNotified, &f.ResolvedAt)
	if err != nil {
		return f, err
	}
	f.State = alerts.State(state)
	if err := json.Unmarshal([]byte(labels), &f.Labels); err != nil {
		return f, fmt.Errorf("labels of %s: %w", f.Key, err)
	}
	if err := json.Unmarshal([]byte(annotations), &f.Annotations); err != nil {
		return f, fmt.Errorf("annotations of %s: %w", f.Key, err)
	}
	if f.Labels == nil {
		f.Labels = map[string]string{}
	}
	if f.Annotations == nil {
		f.Annotations = map[string]string{}
	}
	f.FirstSeen, f.LastSeen = f.FirstSeen.UTC(), f.LastSeen.UTC()
	f.SilencedUntil, f.LastNotified, f.ResolvedAt = utcPtr(f.SilencedUntil), utcPtr(f.LastNotified), utcPtr(f.ResolvedAt)
	return f, nil
}

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	v := t.UTC()
	return &v
}

// Baselines implements alerts.Store.
func (a *AlertStore) Baselines(ctx context.Context) (map[string][]string, error) {
	ctx, cancel := context.WithTimeout(ctx, alertReadTimeout)
	defer cancel()
	rows, err := a.s.pool.Query(ctx, `SELECT check_name, keys FROM alert_baseline`)
	if err != nil {
		return nil, fmt.Errorf("pgstore: load alert baselines: %w", err)
	}
	out := map[string][]string{}
	var check string
	var keys []string
	_, err = pgx.ForEachRow(rows, []any{&check, &keys}, func() error {
		if keys == nil {
			keys = []string{}
		}
		out[check] = slices.Clone(keys)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("pgstore: load alert baselines: %w", err)
	}
	return out, nil
}

const upsertFinding = `INSERT INTO alert_findings (key, alert, check_name, kind, namespace, name, severity, title, owner, production,
  labels, annotations, state, silenced_until, digest, first_seen, last_seen, last_notified, resolved_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12::jsonb, $13, $14, $15, $16, $17, $18, $19, now())
ON CONFLICT (key) DO UPDATE SET alert = EXCLUDED.alert, check_name = EXCLUDED.check_name, kind = EXCLUDED.kind,
  namespace = EXCLUDED.namespace, name = EXCLUDED.name, severity = EXCLUDED.severity, title = EXCLUDED.title,
  owner = EXCLUDED.owner, production = EXCLUDED.production, labels = EXCLUDED.labels, annotations = EXCLUDED.annotations,
  state = EXCLUDED.state, silenced_until = EXCLUDED.silenced_until, digest = EXCLUDED.digest,
  first_seen = EXCLUDED.first_seen, last_seen = EXCLUDED.last_seen, last_notified = EXCLUDED.last_notified,
  resolved_at = EXCLUDED.resolved_at, updated_at = now()`

const upsertBaseline = `INSERT INTO alert_baseline (check_name, keys, updated_at) VALUES ($1, $2, now())
ON CONFLICT (check_name) DO UPDATE SET keys = EXCLUDED.keys, updated_at = now()`

// Commit implements alerts.Store: one transaction, on the lock's connection
// for a Leader's store.
func (a *AlertStore) Commit(ctx context.Context, c alerts.Commit) error {
	if c.Empty() {
		return nil
	}
	b := &pgx.Batch{}
	for _, f := range c.Findings {
		labels, err := json.Marshal(nonNil(f.Labels))
		if err != nil {
			return err
		}
		annotations, err := json.Marshal(nonNil(f.Annotations))
		if err != nil {
			return err
		}
		b.Queue(upsertFinding, f.Key, f.Alert, f.Check, f.Kind, f.Namespace, f.Name, f.Severity, f.Title, f.Owner, f.Production,
			string(labels), string(annotations), string(f.State), f.SilencedUntil, f.Digest, f.FirstSeen, f.LastSeen, f.LastNotified, f.ResolvedAt)
	}
	checks := make([]string, 0, len(c.Baselines))
	for k := range c.Baselines {
		checks = append(checks, k)
	}
	sort.Strings(checks)
	for _, k := range checks {
		keys := slices.Clone(c.Baselines[k])
		sort.Strings(keys)
		keys = slices.Compact(keys)
		if keys == nil {
			keys = []string{}
		}
		b.Queue(upsertBaseline, k, keys)
	}
	if a.l == nil {
		err := pgx.BeginFunc(ctx, a.s.pool, func(tx pgx.Tx) error { return tx.SendBatch(ctx, b).Close() })
		if err != nil {
			return fmt.Errorf("pgstore: commit alerts: %w", err)
		}
		return nil
	}
	l := a.l
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
	if err := tx.SendBatch(ctx, b).Close(); err != nil {
		return l.connErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return l.connErr(err)
	}
	return nil
}

func nonNil(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

const pruneAlerts = `DELETE FROM alert_findings WHERE state = 'resolved' AND resolved_at < $1`

// Prune implements alerts.Store. Any replica may prune: it only deletes
// rows resolved long ago.
func (a *AlertStore) Prune(ctx context.Context, before time.Time) (int, error) {
	tag, err := a.s.pool.Exec(ctx, pruneAlerts, before)
	if err != nil {
		return 0, fmt.Errorf("pgstore: prune alerts: %w", err)
	}
	return int(tag.RowsAffected()), nil
}
