-- Audit events, partitioned by day on time. Runs with search_path set to the
-- store's schema, under an advisory lock, once (see migrate.go).
--
-- Two deliberate refinements of the DDL in docs/contracts.md:
--   * audit_id uses COLLATE "C", so ordering and the keyset cursor compare
--     bytes exactly as the in-memory store does, whatever the database locale.
--   * the default-view partial index has the default view's exact predicate
--     (system actors hidden unless tagged, reads hidden unless tagged), so the
--     planner can prove a default-view query implies it, and carries audit_id
--     for the newest-first tie-break.
CREATE TABLE IF NOT EXISTS audit_events (
  audit_id text COLLATE "C" NOT NULL, time timestamptz NOT NULL, stage_rank smallint NOT NULL, stage text NOT NULL,
  verb text NOT NULL, username text NOT NULL, actor_kind text NOT NULL, groups text[], arn text,
  session_name text, impersonated_user text, source_ips text[], user_agent text, api_group text,
  resource text, subresource text, namespace text NOT NULL DEFAULT '', name text, request_uri text,
  status_code int, decision text, tags text[] NOT NULL DEFAULT '{}', is_read boolean NOT NULL,
  ingested_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (audit_id, time)
) PARTITION BY RANGE (time);
CREATE INDEX IF NOT EXISTS audit_events_time ON audit_events (time DESC, audit_id DESC);
CREATE INDEX IF NOT EXISTS audit_events_user ON audit_events (username, time DESC);
CREATE INDEX IF NOT EXISTS audit_events_obj ON audit_events (namespace, resource, name, time DESC);
CREATE INDEX IF NOT EXISTS audit_events_tags ON audit_events USING gin (tags);
CREATE INDEX IF NOT EXISTS audit_events_default_view ON audit_events (time DESC, audit_id DESC)
  WHERE (actor_kind <> 'system' OR tags <> '{}') AND (NOT is_read OR tags <> '{}');
CREATE TABLE IF NOT EXISTS audit_events_default PARTITION OF audit_events DEFAULT;
CREATE TABLE IF NOT EXISTS ingest_checkpoints (
  source text PRIMARY KEY, position jsonb NOT NULL, owner text, updated_at timestamptz NOT NULL DEFAULT now()
);
