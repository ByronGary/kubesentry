package pgstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/incidents"
)

// IncidentStore is incidents.Store on Postgres (tables incidents,
// incident_signals and incident_checkpoints, migration 0004). One from
// Store.Incidents reads and writes through the pool; one from
// Leader.Incidents writes on the lock's own connection, in a transaction that
// first checks the lock is still held, so a replica that lost the
// "incidents" lock cannot write. Reads always use the pool.
type IncidentStore struct {
	s *Store
	l *Leader // nil: writes go through the pool
}

var (
	_ incidents.Store         = (*IncidentStore)(nil)
	_ incidents.SignalsLoader = (*IncidentStore)(nil)
)

// Incidents returns the incident store on s.
func (s *Store) Incidents() *IncidentStore { return &IncidentStore{s: s} }

// Incidents returns the incident store whose writes require l to be held.
func (l *Leader) Incidents() *IncidentStore { return &IncidentStore{s: l.s, l: l} }

// incidentReadTimeout bounds a read; the board's next refresh retries.
const incidentReadTimeout = 30 * time.Second

const incidentColumns = `id, subject_kind, namespace, subject_name, title, severity, peak_severity, state, started_at, last_signal_at,
  resolved_at, capped, previous, owner, production, tags::text, services, pods, nodes, signal_types, counts::text`

func scanIncident(row pgx.CollectableRow) (incidents.Incident, error) {
	var in incidents.Incident
	var sev, peak, state, tags, counts string
	err := row.Scan(&in.ID, &in.Subject.Kind, &in.Subject.Namespace, &in.Subject.Name, &in.Title, &sev, &peak, &state, &in.Start,
		&in.LastSignal, &in.End, &in.Capped, &in.Previous, &in.Owner, &in.Production, &tags, &in.Services, &in.Pods, &in.Nodes,
		&in.Types, &counts)
	if err != nil {
		return in, err
	}
	in.Severity, in.PeakSeverity, in.State = incidents.Severity(sev), incidents.Severity(peak), incidents.State(state)
	if err := json.Unmarshal([]byte(tags), &in.Tags); err != nil {
		return in, fmt.Errorf("tags of %s: %w", in.ID, err)
	}
	if err := json.Unmarshal([]byte(counts), &in.Counts); err != nil {
		return in, fmt.Errorf("counts of %s: %w", in.ID, err)
	}
	in.Start, in.LastSignal, in.End = in.Start.UTC(), in.LastSignal.UTC(), utcPtr(in.End)
	return incidents.NormalizeIncident(in), nil
}

// LoadOpen implements incidents.Store.
func (st *IncidentStore) LoadOpen(ctx context.Context) ([]incidents.Incident, map[string][]incidents.Signal, error) {
	ctx, cancel := context.WithTimeout(ctx, incidentReadTimeout)
	defer cancel()
	rows, err := st.s.pool.Query(ctx, `SELECT `+incidentColumns+` FROM incidents WHERE state = 'open' ORDER BY started_at DESC, id DESC`)
	if err != nil {
		return nil, nil, fmt.Errorf("pgstore: load open incidents: %w", err)
	}
	open, err := pgx.CollectRows(rows, scanIncident)
	if err != nil {
		return nil, nil, fmt.Errorf("pgstore: load open incidents: %w", err)
	}
	if len(open) == 0 {
		open = nil
	}
	ids := make([]string, len(open))
	for i := range open {
		ids[i] = open[i].ID
	}
	sigs, err := st.signalsOf(ctx, ids)
	if err != nil {
		return nil, nil, fmt.Errorf("pgstore: load open incidents: %w", err)
	}
	return open, sigs, nil
}

// SignalsOf implements incidents.SignalsLoader.
func (st *IncidentStore) SignalsOf(ctx context.Context, ids []string) (map[string][]incidents.Signal, error) {
	ctx, cancel := context.WithTimeout(ctx, incidentReadTimeout)
	defer cancel()
	out, err := st.signalsOf(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("pgstore: incident signals: %w", err)
	}
	return out, nil
}

func (st *IncidentStore) signalsOf(ctx context.Context, ids []string) (map[string][]incidents.Signal, error) {
	out := map[string][]incidents.Signal{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := st.s.pool.Query(ctx, `SELECT incident_id, body::text FROM incident_signals WHERE incident_id = ANY($1)
ORDER BY incident_id, started_at, signal_id`, ids)
	if err != nil {
		return nil, err
	}
	var id, body string
	_, err = pgx.ForEachRow(rows, []any{&id, &body}, func() error {
		s, err := decodeSignal(body)
		if err != nil {
			return fmt.Errorf("signal of %s: %w", id, err)
		}
		out[id] = append(out[id], s)
		return nil
	})
	return out, err
}

func decodeSignal(body string) (incidents.Signal, error) {
	var s incidents.Signal
	if err := json.Unmarshal([]byte(body), &s); err != nil {
		return s, err
	}
	return incidents.NormalizeSignal(s), nil
}

// Get implements incidents.Store.
func (st *IncidentStore) Get(ctx context.Context, id string) (incidents.Incident, []incidents.Signal, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, incidentReadTimeout)
	defer cancel()
	rows, err := st.s.pool.Query(ctx, `SELECT `+incidentColumns+` FROM incidents WHERE id = $1`, id)
	if err != nil {
		return incidents.Incident{}, nil, false, fmt.Errorf("pgstore: get incident: %w", err)
	}
	in, err := pgx.CollectExactlyOneRow(rows, scanIncident)
	if errors.Is(err, pgx.ErrNoRows) {
		return incidents.Incident{}, nil, false, nil
	}
	if err != nil {
		return incidents.Incident{}, nil, false, fmt.Errorf("pgstore: get incident: %w", err)
	}
	sigs, err := st.signalsOf(ctx, []string{id})
	if err != nil {
		return incidents.Incident{}, nil, false, fmt.Errorf("pgstore: get incident: %w", err)
	}
	return in, sigs[id], true, nil
}

// List implements incidents.Store with the same semantics as
// incidents.Query.Matches, newest first.
func (st *IncidentStore) List(ctx context.Context, q incidents.Query) ([]incidents.Incident, error) {
	ctx, cancel := context.WithTimeout(ctx, incidentReadTimeout)
	defer cancel()
	sql, args := listIncidentsSQL(q)
	rows, err := st.s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("pgstore: list incidents: %w", err)
	}
	out, err := pgx.CollectRows(rows, scanIncident)
	if err != nil {
		return nil, fmt.Errorf("pgstore: list incidents: %w", err)
	}
	if len(out) == 0 {
		return nil, nil // as the memory store says it
	}
	return out, nil
}

func listIncidentsSQL(q incidents.Query) (string, []any) {
	var where []string
	var args []any
	arg := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}
	if !q.From.IsZero() {
		where = append(where, "(resolved_at IS NULL OR resolved_at >= "+arg(incidents.NormalTime(q.From))+")")
	}
	if !q.To.IsZero() {
		where = append(where, "started_at <= "+arg(incidents.NormalTime(q.To)))
	}
	if q.Severity != "" {
		where = append(where, "peak_severity = "+arg(string(q.Severity)))
	}
	if len(q.Types) > 0 {
		where = append(where, "signal_types && "+arg(q.Types)+"::text[]")
	}
	if q.State != "" {
		where = append(where, "state = "+arg(string(q.State)))
	}
	if q.Namespaces != nil {
		nss := make([]string, 0, len(q.Namespaces))
		for ns, ok := range q.Namespaces {
			if ok && ns != "" {
				nss = append(nss, ns)
			}
		}
		sort.Strings(nss)
		c := "(namespace <> '' AND namespace = ANY(" + arg(nss) + "::text[]))"
		if q.ClusterScoped {
			c = "(" + c + " OR namespace = '')"
		}
		where = append(where, c)
	}
	if q.Owner != "" {
		where = append(where, "owner = "+arg(q.Owner))
	}
	if q.App != "" {
		where = append(where, "tags->>'"+incidents.TagApp+"' = "+arg(q.App))
	}
	if q.Service != "" {
		where = append(where, arg(q.Service)+" = ANY(services)")
	}
	if len(q.Tags) > 0 {
		b, _ := json.Marshal(q.Tags)
		where = append(where, "tags @> "+arg(string(b))+"::jsonb")
	}
	if q.Before != nil {
		where = append(where, "(started_at, id) < ("+arg(incidents.NormalTime(q.Before.Start))+", "+arg(q.Before.ID)+"::text COLLATE \"C\")")
	}
	sql := `SELECT ` + incidentColumns + ` FROM incidents`
	if len(where) > 0 {
		sql += " WHERE " + strings.Join(where, " AND ")
	}
	sql += " ORDER BY started_at DESC, id DESC"
	if q.Limit > 0 {
		sql += " LIMIT " + arg(q.Limit)
	}
	return sql, args
}

const upsertIncident = `INSERT INTO incidents (id, subject_kind, namespace, subject_name, title, severity, peak_severity, state,
  started_at, last_signal_at, resolved_at, capped, previous, owner, production, tags, services, pods, nodes, signal_types, counts, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16::jsonb, $17, $18, $19, $20, $21::jsonb, now())
ON CONFLICT (id) DO UPDATE SET subject_kind = EXCLUDED.subject_kind, namespace = EXCLUDED.namespace,
  subject_name = EXCLUDED.subject_name, title = EXCLUDED.title, severity = EXCLUDED.severity,
  peak_severity = EXCLUDED.peak_severity, state = EXCLUDED.state, started_at = EXCLUDED.started_at,
  last_signal_at = EXCLUDED.last_signal_at, resolved_at = EXCLUDED.resolved_at, capped = EXCLUDED.capped,
  previous = EXCLUDED.previous, owner = EXCLUDED.owner, production = EXCLUDED.production, tags = EXCLUDED.tags,
  services = EXCLUDED.services, pods = EXCLUDED.pods, nodes = EXCLUDED.nodes, signal_types = EXCLUDED.signal_types,
  counts = EXCLUDED.counts, updated_at = now()`

const upsertSignal = `INSERT INTO incident_signals (incident_id, signal_id, type, role, started_at, body)
VALUES ($1, $2, $3, $4, $5, $6::jsonb)
ON CONFLICT (incident_id, signal_id) DO UPDATE SET type = EXCLUDED.type, role = EXCLUDED.role,
  started_at = EXCLUDED.started_at, body = EXCLUDED.body`

const upsertIncidentCheckpoint = `INSERT INTO incident_checkpoints (source, position, updated_at) VALUES ($1, $2, now())
ON CONFLICT (source) DO UPDATE SET position = EXCLUDED.position, updated_at = now()`

func orEmpty(l []string) []string {
	if l == nil {
		return []string{}
	}
	return l
}

// Commit implements incidents.Store: one transaction, on the lock's
// connection for a Leader's store. A signal's incident must exist or be in
// the commit (a foreign key).
func (st *IncidentStore) Commit(ctx context.Context, c incidents.Commit) error {
	if len(c.Incidents) == 0 && len(c.Signals) == 0 && len(c.Checkpoints) == 0 {
		return nil
	}
	b := &pgx.Batch{}
	for _, in := range c.Incidents {
		in = incidents.NormalizeIncident(in)
		tags := in.Tags
		if tags == nil {
			tags = map[string]string{}
		}
		tj, err := json.Marshal(tags)
		if err != nil {
			return err
		}
		cj, err := json.Marshal(in.Counts)
		if err != nil {
			return err
		}
		b.Queue(upsertIncident, in.ID, in.Subject.Kind, in.Subject.Namespace, in.Subject.Name, in.Title, string(in.Severity),
			string(in.PeakSeverity), string(in.State), in.Start, in.LastSignal, in.End, in.Capped, in.Previous, in.Owner, in.Production,
			string(tj), orEmpty(in.Services), orEmpty(in.Pods), orEmpty(in.Nodes), orEmpty(in.Types), string(cj))
	}
	ids := make([]string, 0, len(c.Signals))
	for id := range c.Signals {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		for _, s := range c.Signals[id] {
			s = incidents.NormalizeSignal(s)
			body, err := json.Marshal(s)
			if err != nil {
				return err
			}
			b.Queue(upsertSignal, id, s.ID, s.Type, string(s.Role), s.Start, string(body))
		}
	}
	srcs := make([]string, 0, len(c.Checkpoints))
	for k := range c.Checkpoints {
		srcs = append(srcs, k)
	}
	sort.Strings(srcs)
	for _, k := range srcs {
		pos := c.Checkpoints[k]
		if pos == nil {
			pos = []byte{}
		}
		b.Queue(upsertIncidentCheckpoint, k, pos)
	}
	if st.l == nil {
		err := pgx.BeginFunc(ctx, st.s.pool, func(tx pgx.Tx) error { return tx.SendBatch(ctx, b).Close() })
		if err != nil {
			return fmt.Errorf("pgstore: commit incidents: %w", err)
		}
		return nil
	}
	return st.l.commitBatch(ctx, b)
}

// commitBatch runs b in one transaction on the lock's connection, after
// checking the lock is still held.
func (l *Leader) commitBatch(ctx context.Context, b *pgx.Batch) error {
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

// Checkpoint implements incidents.Store.
func (st *IncidentStore) Checkpoint(ctx context.Context, source string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, incidentReadTimeout)
	defer cancel()
	var pos []byte
	err := st.s.pool.QueryRow(ctx, `SELECT position FROM incident_checkpoints WHERE source = $1`, source).Scan(&pos)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("pgstore: incident checkpoint: %w", err)
	}
	return pos, nil
}

// Prune implements incidents.Store: resolved incidents that ended before
// before go, with their signals. Any replica may prune.
func (st *IncidentStore) Prune(ctx context.Context, before time.Time) (int, error) {
	tag, err := st.s.pool.Exec(ctx, `DELETE FROM incidents WHERE state = 'resolved' AND resolved_at < $1`, before)
	if err != nil {
		return 0, fmt.Errorf("pgstore: prune incidents: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// KubeEventStore is incidents.EventStore on Postgres (table k8s_events,
// partitioned by day on first_seen; Maintain keeps the partitions). Only the
// incidents leader writes, but writes are idempotent upserts by uid, so
// they go through the pool.
type KubeEventStore struct {
	s *Store
}

var _ incidents.EventStore = (*KubeEventStore)(nil)

// KubeEvents returns the Kubernetes event store on s.
func (s *Store) KubeEvents() *KubeEventStore { return &KubeEventStore{s: s} }

// AddEvents implements incidents.EventStore: events upsert by uid, and a
// report never replaces one seen later (last_seen). A report whose
// first_seen moved replaces the row under the old one.
func (k *KubeEventStore) AddEvents(ctx context.Context, evs []incidents.StoredEvent) error {
	// Fold the batch as the memory store applies it, in order.
	byUID := map[string]int{}
	var batch []incidents.StoredEvent
	for _, e := range evs {
		e = incidents.NormalizeEvent(e)
		if e.UID == "" || e.LastSeen.IsZero() {
			continue
		}
		if i, ok := byUID[e.UID]; ok {
			if !batch[i].LastSeen.After(e.LastSeen) {
				batch[i] = e
			}
			continue
		}
		byUID[e.UID] = len(batch)
		batch = append(batch, e)
	}
	if len(batch) == 0 {
		return nil
	}
	n := len(batch)
	uid, ns, typ, reason, msg, src := make([]string, n), make([]string, n), make([]string, n), make([]string, n), make([]string, n), make([]string, n)
	rk, rns, rn, ru := make([]string, n), make([]string, n), make([]string, n), make([]string, n)
	sk, sns, sn := make([]*string, n), make([]*string, n), make([]*string, n)
	first, last := make([]time.Time, n), make([]time.Time, n)
	count := make([]int32, n)
	for i, e := range batch {
		uid[i], ns[i], typ[i], reason[i], msg[i], src[i] = e.UID, e.Namespace, e.Type, e.Reason, e.Message, e.Source
		rk[i], rns[i], rn[i], ru[i] = e.Regarding.Kind, e.Regarding.Namespace, e.Regarding.Name, e.Regarding.UID
		first[i], last[i], count[i] = e.FirstSeen, e.LastSeen, e.Count
		if e.Subject != nil {
			s := *e.Subject
			sk[i], sns[i], sn[i] = &s.Kind, &s.Namespace, &s.Name
		}
	}
	err := pgx.BeginFunc(ctx, k.s.pool, func(tx pgx.Tx) error {
		// A newer report of a series whose first_seen moved: drop the old row.
		if _, err := tx.Exec(ctx, `DELETE FROM k8s_events e USING unnest($1::text[], $2::timestamptz[], $3::timestamptz[]) AS n(uid, fs, ls)
WHERE e.uid = n.uid AND e.first_seen <> n.fs AND e.last_seen <= n.ls`, uid, first, last); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO k8s_events (uid, first_seen, last_seen, namespace, type, reason, message, count,
  regarding_kind, regarding_namespace, regarding_name, regarding_uid, source, subject_kind, subject_namespace, subject_name)
SELECT n.* FROM unnest($1::text[], $2::timestamptz[], $3::timestamptz[], $4::text[], $5::text[], $6::text[], $7::text[], $8::int[],
  $9::text[], $10::text[], $11::text[], $12::text[], $13::text[], $14::text[], $15::text[], $16::text[])
  AS n(uid, first_seen, last_seen, namespace, type, reason, message, count, regarding_kind, regarding_namespace, regarding_name,
       regarding_uid, source, subject_kind, subject_namespace, subject_name)
WHERE NOT EXISTS (SELECT 1 FROM k8s_events e WHERE e.uid = n.uid AND e.last_seen > n.last_seen)
ON CONFLICT (uid, first_seen) DO UPDATE SET last_seen = EXCLUDED.last_seen, namespace = EXCLUDED.namespace, type = EXCLUDED.type,
  reason = EXCLUDED.reason, message = EXCLUDED.message, count = EXCLUDED.count, regarding_kind = EXCLUDED.regarding_kind,
  regarding_namespace = EXCLUDED.regarding_namespace, regarding_name = EXCLUDED.regarding_name,
  regarding_uid = EXCLUDED.regarding_uid, source = EXCLUDED.source, subject_kind = EXCLUDED.subject_kind,
  subject_namespace = EXCLUDED.subject_namespace, subject_name = EXCLUDED.subject_name
WHERE k8s_events.last_seen <= EXCLUDED.last_seen`,
			uid, first, last, ns, typ, reason, msg, count, rk, rns, rn, ru, src, sk, sns, sn)
		return err
	})
	if err != nil {
		return fmt.Errorf("pgstore: add events: %w", err)
	}
	return nil
}

const kubeEventColumns = `uid, first_seen, last_seen, namespace, type, reason, message, count, regarding_kind, regarding_namespace,
  regarding_name, regarding_uid, source, subject_kind, subject_namespace, subject_name`

func scanEvent(row pgx.CollectableRow) (incidents.StoredEvent, error) {
	var e incidents.StoredEvent
	var sk, sns, sn *string
	err := row.Scan(&e.UID, &e.FirstSeen, &e.LastSeen, &e.Namespace, &e.Type, &e.Reason, &e.Message, &e.Count, &e.Regarding.Kind,
		&e.Regarding.Namespace, &e.Regarding.Name, &e.Regarding.UID, &e.Source, &sk, &sns, &sn)
	if err != nil {
		return e, err
	}
	if sk != nil && sns != nil && sn != nil {
		e.Subject = &incidents.Subject{Kind: *sk, Namespace: *sns, Name: *sn}
	}
	e.FirstSeen, e.LastSeen = e.FirstSeen.UTC(), e.LastSeen.UTC()
	return e, nil
}

// Events implements incidents.EventStore with the semantics of
// incidents.EventQuery.Matches, the most recently seen first.
func (k *KubeEventStore) Events(ctx context.Context, q incidents.EventQuery) ([]incidents.StoredEvent, error) {
	ctx, cancel := context.WithTimeout(ctx, incidentReadTimeout)
	defer cancel()
	var where []string
	var args []any
	arg := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}
	if q.Namespace != "" {
		where = append(where, "namespace = "+arg(q.Namespace))
	}
	if s := q.Subject; s != nil {
		where = append(where, "subject_kind = "+arg(s.Kind), "subject_namespace = "+arg(s.Namespace), "subject_name = "+arg(s.Name))
	}
	if o := q.Object; o != nil {
		where = append(where, "regarding_kind = "+arg(o.Kind), "regarding_namespace = "+arg(o.Namespace), "regarding_name = "+arg(o.Name))
		if o.UID != "" {
			where = append(where, "regarding_uid = "+arg(o.UID))
		}
	}
	if !q.From.IsZero() {
		where = append(where, "last_seen >= "+arg(incidents.NormalTime(q.From)))
	}
	if !q.To.IsZero() {
		where = append(where, "first_seen <= "+arg(incidents.NormalTime(q.To)))
	}
	sql := `SELECT ` + kubeEventColumns + ` FROM k8s_events`
	if len(where) > 0 {
		sql += " WHERE " + strings.Join(where, " AND ")
	}
	sql += " ORDER BY last_seen DESC, uid"
	if q.Limit > 0 {
		sql += " LIMIT " + arg(q.Limit)
	}
	rows, err := k.s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("pgstore: events: %w", err)
	}
	out, err := pgx.CollectRows(rows, scanEvent)
	if err != nil {
		return nil, fmt.Errorf("pgstore: events: %w", err)
	}
	if len(out) == 0 {
		return nil, nil // as the memory store says it
	}
	return out, nil
}

// PruneEvents implements incidents.EventStore: events last seen before
// before go (Maintain also drops whole partitions past retention).
func (k *KubeEventStore) PruneEvents(ctx context.Context, before time.Time) (int, error) {
	tag, err := k.s.pool.Exec(ctx, `DELETE FROM k8s_events WHERE last_seen < $1`, before)
	if err != nil {
		return 0, fmt.Errorf("pgstore: prune events: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// IncidentLease is a held "incidents" lock as an incidents.Lease: its store
// writes only while the lock is held.
type IncidentLease struct{ *Leader }

// Store implements incidents.Lease.
func (l IncidentLease) Store() incidents.Store { return l.Incidents() }

var _ incidents.Lease = IncidentLease{}

// IncidentsLock is the advisory lock name the incidents leader holds.
const IncidentsLock = "incidents"

// IncidentElector tries for the incidents lock without waiting.
func (s *Store) IncidentElector() incidents.Elector {
	return func(ctx context.Context) (incidents.Lease, bool, error) {
		l, ok, err := s.TryLead(ctx, IncidentsLock)
		if err != nil || !ok {
			return nil, false, err
		}
		return IncidentLease{l}, true, nil
	}
}
