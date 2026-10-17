-- AI investigations of incidents (docs/contracts.md "AI investigator"):
-- one row per run, written through the pool by the replica running the job
-- after every turn (updated_at is its heartbeat; a running row older than 2
-- minutes reads as failed, "interrupted"). Rows go with their incident.
-- At most one running run per incident (the partial unique index); the
-- quotas count rows per requester and in total; a completed run answers a
-- start with the same input hash for 24 hours.

CREATE TABLE IF NOT EXISTS incident_investigations (
  id                 text PRIMARY KEY,
  incident_id        text COLLATE "C" NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
  namespace          text NOT NULL DEFAULT '',
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  finished_at        timestamptz,
  requested_by       text NOT NULL,
  provider           text NOT NULL,
  model              text NOT NULL,
  effort             text NOT NULL,
  prompt_version     text NOT NULL,
  input_sha256       text NOT NULL,
  cached_from        text,
  access             jsonb NOT NULL,
  omitted            jsonb NOT NULL DEFAULT '{}',
  status             text NOT NULL CHECK (status IN ('running', 'completed', 'refused', 'failed', 'cancelled')),
  error              text,
  refusal            jsonb,
  progress           jsonb NOT NULL DEFAULT '[]',
  report             jsonb,
  evidence           jsonb,
  input_tokens       bigint NOT NULL DEFAULT 0,
  output_tokens      bigint NOT NULL DEFAULT 0,
  cache_read_tokens  bigint NOT NULL DEFAULT 0,
  cache_write_tokens bigint NOT NULL DEFAULT 0,
  turns              int NOT NULL DEFAULT 0,
  tool_calls         int NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS incident_investigations_incident ON incident_investigations (incident_id, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS incident_investigations_running ON incident_investigations (incident_id) WHERE status = 'running';
CREATE INDEX IF NOT EXISTS incident_investigations_quota ON incident_investigations (requested_by, created_at);
CREATE INDEX IF NOT EXISTS incident_investigations_hash ON incident_investigations (input_sha256, created_at DESC) WHERE status = 'completed';
