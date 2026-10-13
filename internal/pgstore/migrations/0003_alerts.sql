-- Alerting (phase B): the findings kubesentry alerts on, with their
-- lifecycle, and the baselines of the change-based checks (RBAC drift).
-- Only the replica holding the "alerts" advisory lock writes them, on the
-- lock's own connection after checking it is still held; every replica
-- reads them for GET /api/v1/alerts.

-- One row per finding, keyed by its dedupe key (check/kind/namespace/name).
-- labels are the label set last sent to Alertmanager. Resolved rows are
-- kept 30 days (the maintenance loop deletes older ones); key uses
-- COLLATE "C" so Load orders by bytes, as the memory store does.
CREATE TABLE IF NOT EXISTS alert_findings (
  key            text COLLATE "C" PRIMARY KEY,
  alert          text NOT NULL,
  check_name     text NOT NULL,
  kind           text NOT NULL,
  namespace      text NOT NULL DEFAULT '',
  name           text NOT NULL,
  severity       text NOT NULL,
  title          text NOT NULL,
  owner          text NOT NULL,
  production     boolean NOT NULL DEFAULT false,
  labels         jsonb NOT NULL DEFAULT '{}',
  annotations    jsonb NOT NULL DEFAULT '{}',
  state          text NOT NULL,
  silenced_until timestamptz,
  digest         boolean NOT NULL DEFAULT false,
  first_seen     timestamptz NOT NULL,
  last_seen      timestamptz NOT NULL,
  last_notified  timestamptz,
  resolved_at    timestamptz,
  updated_at     timestamptz NOT NULL DEFAULT now()
);
-- Load reads what is not resolved, plus what resolved recently.
CREATE INDEX IF NOT EXISTS alert_findings_unresolved ON alert_findings (key) WHERE state <> 'resolved';
CREATE INDEX IF NOT EXISTS alert_findings_resolved ON alert_findings (resolved_at) WHERE state = 'resolved';

-- The key set each change-based check saw at its last evaluation. No row:
-- no baseline yet, so the first evaluation records one without notifying.
CREATE TABLE IF NOT EXISTS alert_baseline (
  check_name text PRIMARY KEY,
  keys       text[] NOT NULL DEFAULT '{}',
  updated_at timestamptz NOT NULL DEFAULT now()
);
