package pgstore

import (
	"context"
	"embed"
	"fmt"
	"hash/fnv"
	"io/fs"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

//go:embed migrations/*.sql
var migrations embed.FS

// lockKey maps a name to a session advisory lock key, scoped by schema so
// clusters sharing a database do not contend.
func lockKey(schema, name string) int64 {
	h := fnv.New64a()
	h.Write([]byte("kubesentry/" + schema + "/" + name))
	return int64(h.Sum64())
}

// migrate creates the schema and applies pending migrations in order, each in
// its own transaction, while holding an advisory lock so concurrent replicas
// apply each one exactly once. Migrations are forward-only.
func (s *Store) migrate(ctx context.Context) error {
	c, err := s.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("pgstore: migrate: %w", err)
	}
	defer c.Release()
	key := lockKey(s.o.Schema, "migrate")
	if _, err := c.Exec(ctx, "SELECT pg_advisory_lock($1)", key); err != nil {
		return fmt.Errorf("pgstore: migration lock: %w", err)
	}
	defer c.Exec(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", key)

	var exists bool
	if err := c.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = $1)", s.o.Schema).Scan(&exists); err != nil {
		return fmt.Errorf("pgstore: migrate: %w", err)
	}
	if !exists {
		// Checked first: CREATE SCHEMA IF NOT EXISTS still needs the CREATE
		// privilege, which a least-privilege role on an existing schema lacks.
		if _, err := c.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS "+pgx.Identifier{s.o.Schema}.Sanitize()); err != nil {
			return fmt.Errorf("pgstore: create schema %s: %w", s.o.Schema, err)
		}
	}
	if _, err := c.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
  version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return fmt.Errorf("pgstore: migrate: %w", err)
	}
	names, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, name := range names {
		version := strings.TrimSuffix(strings.TrimPrefix(name, "migrations/"), ".sql")
		var done bool
		if err := c.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)", version).Scan(&done); err != nil {
			return fmt.Errorf("pgstore: migrate: %w", err)
		}
		if done {
			continue
		}
		body, err := migrations.ReadFile(name)
		if err != nil {
			return err
		}
		err = pgx.BeginFunc(ctx, c, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, string(body)); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, "INSERT INTO schema_migrations (version) VALUES ($1)", version)
			return err
		})
		if err != nil {
			return fmt.Errorf("pgstore: migration %s: %w", version, err)
		}
		s.log.Info("applied audit store migration", "version", version, "schema", s.o.Schema)
	}
	return nil
}
