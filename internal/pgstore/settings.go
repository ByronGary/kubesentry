package pgstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ByronGary/kubesentry/internal/settings"
)

// SettingsStore is settings.Store on Postgres (tables settings and
// settings_audit, migration 0007). Every replica reads and writes through
// the pool; a write applies only when the stored version is the one the
// writer saw, and its audit entry goes in the same transaction.
type SettingsStore struct{ s *Store }

var _ settings.Store = (*SettingsStore)(nil)

// Settings returns the settings store on s.
func (s *Store) Settings() *SettingsStore { return &SettingsStore{s: s} }

// settingsTimeout bounds one statement.
const settingsTimeout = 10 * time.Second

// Get implements settings.Store.
func (st *SettingsStore) Get(ctx context.Context, name string) (*settings.Record, error) {
	ctx, cancel := context.WithTimeout(ctx, settingsTimeout)
	defer cancel()
	var r settings.Record
	var value string
	err := st.s.pool.QueryRow(ctx, `SELECT name, value::text, version, updated_at, updated_by FROM settings WHERE name = $1`, name).
		Scan(&r.Name, &value, &r.Version, &r.UpdatedAt, &r.UpdatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, settings.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("pgstore: settings %s: %w", name, err)
	}
	r.Value, r.UpdatedAt = json.RawMessage(value), r.UpdatedAt.UTC()
	return &r, nil
}

// Put implements settings.Store.
func (st *SettingsStore) Put(ctx context.Context, rec settings.Record, expect int64, entry settings.AuditEntry) (*settings.Record, error) {
	if !json.Valid(rec.Value) {
		return nil, errors.New("settings: the value is not JSON")
	}
	changes, err := json.Marshal(entry.Changes)
	if err != nil {
		return nil, err
	}
	if entry.Changes == nil {
		changes = []byte("[]")
	}
	ctx, cancel := context.WithTimeout(ctx, settingsTimeout)
	defer cancel()
	var out settings.Record
	err = pgx.BeginFunc(ctx, st.s.pool, func(tx pgx.Tx) error {
		var value string
		var row pgx.Row
		if expect == 0 {
			row = tx.QueryRow(ctx, `INSERT INTO settings (name, value, version, updated_at, updated_by) VALUES ($1, $2::jsonb, 1, $3, $4)
ON CONFLICT (name) DO NOTHING RETURNING name, value::text, version, updated_at, updated_by`,
				rec.Name, string(rec.Value), rec.UpdatedAt.UTC().Truncate(time.Microsecond), rec.UpdatedBy)
		} else {
			row = tx.QueryRow(ctx, `UPDATE settings SET value = $2::jsonb, version = version + 1, updated_at = $3, updated_by = $4
WHERE name = $1 AND version = $5 RETURNING name, value::text, version, updated_at, updated_by`,
				rec.Name, string(rec.Value), rec.UpdatedAt.UTC().Truncate(time.Microsecond), rec.UpdatedBy, expect)
		}
		if err := row.Scan(&out.Name, &value, &out.Version, &out.UpdatedAt, &out.UpdatedBy); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return settings.ErrConflict
			}
			return err
		}
		out.Value, out.UpdatedAt = json.RawMessage(value), out.UpdatedAt.UTC()
		_, err := tx.Exec(ctx, `INSERT INTO settings_audit (name, at, actor, action, version, changes, egress_acknowledged, egress_ack_by_platform)
VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8)`,
			rec.Name, entry.At.UTC().Truncate(time.Microsecond), entry.Actor, entry.Action, out.Version, string(changes), entry.EgressAcknowledged, entry.EgressAckByPlatform)
		return err
	})
	if errors.Is(err, settings.ErrConflict) {
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("pgstore: save settings %s: %w", rec.Name, err)
	}
	return &out, nil
}

// Audit implements settings.Store.
func (st *SettingsStore) Audit(ctx context.Context, name string, limit int) ([]settings.AuditEntry, error) {
	ctx, cancel := context.WithTimeout(ctx, settingsTimeout)
	defer cancel()
	if limit <= 0 {
		limit = 1000
	}
	rows, err := st.s.pool.Query(ctx, `SELECT id, name, at, actor, action, version, changes::text, egress_acknowledged, egress_ack_by_platform
FROM settings_audit WHERE name = $1 ORDER BY id DESC LIMIT $2`, name, limit)
	if err != nil {
		return nil, fmt.Errorf("pgstore: settings audit: %w", err)
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (settings.AuditEntry, error) {
		var e settings.AuditEntry
		var changes string
		if err := row.Scan(&e.ID, &e.Name, &e.At, &e.Actor, &e.Action, &e.Version, &changes, &e.EgressAcknowledged, &e.EgressAckByPlatform); err != nil {
			return e, err
		}
		e.At = e.At.UTC()
		if err := json.Unmarshal([]byte(changes), &e.Changes); err != nil {
			return e, fmt.Errorf("changes of settings audit entry %d: %w", e.ID, err)
		}
		if e.Changes == nil {
			e.Changes = []settings.Change{}
		}
		return e, nil
	})
	if err != nil {
		return nil, fmt.Errorf("pgstore: settings audit: %w", err)
	}
	if out == nil {
		out = []settings.AuditEntry{}
	}
	return out, nil
}
