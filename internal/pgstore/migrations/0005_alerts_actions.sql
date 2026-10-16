-- Alerting phase C: the UI route of each finding (link), findings reported
-- only in a standing digest (quiet), the actions people take on findings
-- (acknowledge, silence, and lifting either), and when each standing digest
-- was last sent.
--
-- alert_actions is an append-only log written through the pool by any
-- replica (not the alerts lock's connection): the leader rewrites
-- alert_findings from its own memory on every commit, so an action written
-- there by another replica would be undone. Every replica reads the log and
-- applies it (alerts.applyMarks). alert_findings and alert_digest_runs stay
-- leader-only. The maintenance loop deletes actions older than the
-- findings' retention plus a day.
ALTER TABLE alert_findings ADD COLUMN IF NOT EXISTS link  text    NOT NULL DEFAULT '';
ALTER TABLE alert_findings ADD COLUMN IF NOT EXISTS quiet boolean NOT NULL DEFAULT false;
CREATE TABLE IF NOT EXISTS alert_actions (
  id bigserial PRIMARY KEY, key text COLLATE "C" NOT NULL, first_seen timestamptz NOT NULL,
  action text NOT NULL CHECK (action IN ('ack','unack','silence','unsilence')),
  actor text NOT NULL, reason text NOT NULL DEFAULT '', until timestamptz,
  severity text NOT NULL, at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS alert_actions_key ON alert_actions (key, id);
CREATE INDEX IF NOT EXISTS alert_actions_at  ON alert_actions (at);
CREATE TABLE IF NOT EXISTS alert_digest_runs (name text PRIMARY KEY, last_sent timestamptz NOT NULL);
