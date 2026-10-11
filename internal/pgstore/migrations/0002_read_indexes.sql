-- Two indexes for reads scoped to a few namespaces (stress checkpoint D):
-- team users see the audit summary and the event list of their own
-- namespaces, and before these each such read cost in proportion to the
-- whole window, not to the scope. Numbers below are at 3.2M events over 26h
-- in 300 namespaces.
--
-- Creating them on the partitioned table builds them on every partition
-- under a SHARE lock: writes wait meanwhile (about 5 s per 3M events), and
-- the write queue and the webhook's 503 + Retry-After absorb that.
-- Partitions created later get them automatically.

-- The summary groups the events of humans and service accounts by user and
-- tag. A few-namespace 24h summary read every matching row from the heap
-- through audit_events_obj: one random heap page per row, ~370 ms cold for
-- ~8,000 rows, and every distinct scope paid it. With this index it is an
-- index-only scan of ~130 pages (~9 ms); the cluster-wide summary scans it
-- instead of the heap too (7x fewer pages). The predicate holds for every
-- summary that leaves system components out: where() writes known actor
-- kinds as literals (actor_kind IN ('serviceaccount', 'user')), which the
-- planner proves implies actor_kind <> 'system'. INCLUDE carries every other
-- column the summary reads.
CREATE INDEX IF NOT EXISTS audit_events_summary ON audit_events (namespace, time DESC)
  INCLUDE (username, actor_kind, verb, tags, is_read)
  WHERE actor_kind <> 'system';

-- A page of the default event view in a few namespaces (scopedPageSQL reads
-- one newest-first range per namespace and merges them). With only the
-- default view's time index the planner walked the window newest first,
-- filtering by namespace: 25,000 rows read for a page of 201 at 2 of 300
-- namespaces, and the whole window for a quiet namespace. The predicate is
-- the default view's, as on audit_events_default_view.
CREATE INDEX IF NOT EXISTS audit_events_scoped_view ON audit_events (namespace, time DESC, audit_id DESC)
  WHERE (actor_kind <> 'system' OR tags <> '{}') AND (NOT is_read OR tags <> '{}');
