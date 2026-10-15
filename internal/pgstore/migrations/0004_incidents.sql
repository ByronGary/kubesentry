-- Incidents: one row per incident (a workload root's critical and warning
-- signals, grouped), its signals, the pollers' checkpoints, and the raw
-- Kubernetes events kept for the incident windows. Only the replica holding
-- the "incidents" advisory lock writes incidents, signals and checkpoints,
-- on the lock's own connection after checking it is still held; every
-- replica reads them. IDs use COLLATE "C" so ordering and the keyset cursor
-- compare bytes, as the memory store does.

CREATE TABLE IF NOT EXISTS incidents (
  id             text COLLATE "C" PRIMARY KEY,
  subject_kind   text NOT NULL,
  namespace      text NOT NULL DEFAULT '',
  subject_name   text NOT NULL,
  title          text NOT NULL,
  severity       text NOT NULL,
  peak_severity  text NOT NULL,
  state          text NOT NULL,
  started_at     timestamptz NOT NULL,
  last_signal_at timestamptz NOT NULL,
  resolved_at    timestamptz,
  capped         boolean NOT NULL DEFAULT false,
  previous       text NOT NULL DEFAULT '',
  owner          text NOT NULL DEFAULT '',
  production     boolean NOT NULL DEFAULT false,
  tags           jsonb NOT NULL DEFAULT '{}',
  services       text[] NOT NULL DEFAULT '{}',
  pods           text[] NOT NULL DEFAULT '{}',
  nodes          text[] NOT NULL DEFAULT '{}',
  signal_types   text[] NOT NULL DEFAULT '{}',
  counts         jsonb NOT NULL DEFAULT '{}',
  updated_at     timestamptz NOT NULL DEFAULT now()
);
-- Lists are newest first with a (started_at, id) keyset cursor; team users
-- list their own namespaces; the board and a new leader read the open ones;
-- the type filter uses the GIN index; pruning finds old resolved ones.
CREATE INDEX IF NOT EXISTS incidents_started ON incidents (started_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS incidents_namespace ON incidents (namespace, started_at DESC);
CREATE INDEX IF NOT EXISTS incidents_open ON incidents (started_at DESC) WHERE state = 'open';
CREATE INDEX IF NOT EXISTS incidents_types ON incidents USING gin (signal_types);
CREATE INDEX IF NOT EXISTS incidents_resolved ON incidents (resolved_at) WHERE state = 'resolved';

-- A signal belongs to one incident (the same signal ID may join several,
-- one row each); body is the whole signal as JSON.
CREATE TABLE IF NOT EXISTS incident_signals (
  incident_id text COLLATE "C" NOT NULL REFERENCES incidents (id) ON DELETE CASCADE,
  signal_id   text COLLATE "C" NOT NULL,
  type        text NOT NULL,
  role        text NOT NULL,
  started_at  timestamptz NOT NULL,
  body        jsonb NOT NULL,
  PRIMARY KEY (incident_id, signal_id)
);

-- The audit and CloudTrail pollers' positions, opaque bytes (a CloudTrail
-- source's checkpoint need not be JSON), committed with the signals they
-- produced.
CREATE TABLE IF NOT EXISTS incident_checkpoints (
  source     text PRIMARY KEY,
  position   bytea NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- Kubernetes events, partitioned by day on first_seen (Maintain creates and
-- drops the partitions, as for audit_events). The events producer keeps
-- first_seen within a day of last_seen, so a series recurring for days stays
-- in a live partition; an upsert by uid moves it when first_seen changes.
CREATE TABLE IF NOT EXISTS k8s_events (
  uid                 text COLLATE "C" NOT NULL,
  first_seen          timestamptz NOT NULL,
  last_seen           timestamptz NOT NULL,
  namespace           text NOT NULL DEFAULT '',
  type                text NOT NULL,
  reason              text NOT NULL,
  message             text NOT NULL,
  count               integer NOT NULL,
  regarding_kind      text NOT NULL DEFAULT '',
  regarding_namespace text NOT NULL DEFAULT '',
  regarding_name      text NOT NULL DEFAULT '',
  regarding_uid       text NOT NULL DEFAULT '',
  source              text NOT NULL DEFAULT '',
  subject_kind        text,
  subject_namespace   text,
  subject_name        text,
  PRIMARY KEY (uid, first_seen)
) PARTITION BY RANGE (first_seen);
CREATE INDEX IF NOT EXISTS k8s_events_subject ON k8s_events (subject_namespace, subject_kind, subject_name, last_seen DESC);
CREATE INDEX IF NOT EXISTS k8s_events_regarding ON k8s_events (regarding_namespace, regarding_kind, regarding_name, last_seen DESC);
CREATE INDEX IF NOT EXISTS k8s_events_last_seen ON k8s_events (last_seen DESC);
CREATE TABLE IF NOT EXISTS k8s_events_default PARTITION OF k8s_events DEFAULT;
