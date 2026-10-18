-- Settings admins change at run time (docs/contracts.md "Settings (M7b)"):
-- one row per setting (today "investigator"), its JSON value and a version
-- that rises with every write (optimistic concurrency; every replica polls
-- it and applies a new version). Written through the pool by any replica.
CREATE TABLE IF NOT EXISTS settings (
  name       text COLLATE "C" PRIMARY KEY,
  value      jsonb       NOT NULL,
  version    bigint      NOT NULL CHECK (version > 0),
  updated_at timestamptz NOT NULL DEFAULT now(),
  updated_by text        NOT NULL
);

-- Every write: who, when, what changed (old -> new), and the data egress
-- acknowledgement. Append-only: the trigger refuses updates and deletes.
CREATE TABLE IF NOT EXISTS settings_audit (
  id                     bigserial PRIMARY KEY,
  name                   text COLLATE "C" NOT NULL,
  at                     timestamptz NOT NULL DEFAULT now(),
  actor                  text        NOT NULL,
  action                 text        NOT NULL CHECK (action IN ('save', 'reset')),
  version                bigint      NOT NULL,
  changes                jsonb       NOT NULL DEFAULT '[]',
  egress_acknowledged    boolean     NOT NULL DEFAULT false,
  egress_ack_by_platform boolean     NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS settings_audit_name ON settings_audit (name, id DESC);

CREATE OR REPLACE FUNCTION settings_audit_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'settings_audit is append-only';
END
$$;
DROP TRIGGER IF EXISTS settings_audit_append_only ON settings_audit;
CREATE TRIGGER settings_audit_append_only BEFORE UPDATE OR DELETE ON settings_audit
  FOR EACH ROW EXECUTE FUNCTION settings_audit_append_only();
