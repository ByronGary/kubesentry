package pgstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ByronGary/kubesentry/internal/incidents"
	"github.com/ByronGary/kubesentry/internal/investigate"
)

// InvestigationStore is investigate.Store on Postgres (table
// incident_investigations, migration 0006). Every replica reads and writes
// through the pool: the replica running a job writes its progress, any
// replica answers a poll, a cancel or a start. At most one run per
// incident is running (the partial unique index), and an update applies
// only while the stored run is still running.
type InvestigationStore struct{ s *Store }

var _ investigate.Store = (*InvestigationStore)(nil)

// Investigations returns the investigation store on s.
func (s *Store) Investigations() *InvestigationStore { return &InvestigationStore{s: s} }

// investigationTimeout bounds one statement; the job's next write retries.
const investigationTimeout = 15 * time.Second

const investigationColumns = `id, incident_id, namespace, created_at, updated_at, finished_at, requested_by, provider, model, effort,
  prompt_version, input_sha256, coalesce(cached_from, ''), access::text, omitted::text, status, coalesce(error, ''), refusal::text,
  progress::text, report::text, evidence::text, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens, turns, tool_calls`

func scanInvestigation(row pgx.CollectableRow) (*investigate.Investigation, error) {
	var inv investigate.Investigation
	var status, access, omitted, progress string
	var refusal, report, evidence *string
	err := row.Scan(&inv.ID, &inv.IncidentID, &inv.Namespace, &inv.CreatedAt, &inv.UpdatedAt, &inv.FinishedAt, &inv.RequestedBy,
		&inv.Provider, &inv.Model, &inv.Effort, &inv.PromptVersion, &inv.InputSHA256, &inv.CachedFrom, &access, &omitted, &status,
		&inv.Error, &refusal, &progress, &report, &evidence, &inv.Usage.Input, &inv.Usage.Output, &inv.Usage.CacheRead,
		&inv.Usage.CacheWrite, &inv.Turns, &inv.ToolCalls)
	if err != nil {
		return nil, err
	}
	inv.Status = investigate.Status(status)
	inv.CreatedAt, inv.UpdatedAt, inv.FinishedAt = inv.CreatedAt.UTC(), inv.UpdatedAt.UTC(), utcPtr(inv.FinishedAt)
	dec := func(what, s string, v any) error {
		if err := json.Unmarshal([]byte(s), v); err != nil {
			return fmt.Errorf("%s of investigation %s: %w", what, inv.ID, err)
		}
		return nil
	}
	if err := dec("access", access, &inv.Access); err != nil {
		return nil, err
	}
	if err := dec("omitted", omitted, &inv.Omitted); err != nil {
		return nil, err
	}
	if len(inv.Omitted) == 0 {
		inv.Omitted = nil
	}
	if err := dec("progress", progress, &inv.Steps); err != nil {
		return nil, err
	}
	if len(inv.Steps) == 0 {
		inv.Steps = nil
	}
	for i := range inv.Steps {
		inv.Steps[i].At = inv.Steps[i].At.UTC()
	}
	if refusal != nil {
		if err := dec("refusal", *refusal, &inv.Refusal); err != nil {
			return nil, err
		}
	}
	if report != nil {
		if err := dec("report", *report, &inv.Report); err != nil {
			return nil, err
		}
	}
	if evidence != nil {
		if err := dec("evidence", *evidence, &inv.Evidence); err != nil {
			return nil, err
		}
	}
	if len(inv.Evidence) == 0 {
		inv.Evidence = nil
	}
	return &inv, nil
}

// mutable are the columns Update writes: a run's status, heartbeat,
// outcome and progress.
type mutable struct {
	status                         string
	updated                        time.Time
	finished                       *time.Time
	errText                        *string
	refusal, progress              []byte
	report, evidence               []byte
	in, out, cacheRead, cacheWrite int64
	turns, toolCalls               int
}

func mutableOf(inv *investigate.Investigation) (mutable, error) {
	m := mutable{status: string(inv.Status), updated: incidents.NormalTime(inv.UpdatedAt), in: inv.Usage.Input, out: inv.Usage.Output,
		cacheRead: inv.Usage.CacheRead, cacheWrite: inv.Usage.CacheWrite, turns: inv.Turns, toolCalls: inv.ToolCalls}
	if inv.FinishedAt != nil {
		t := incidents.NormalTime(*inv.FinishedAt)
		m.finished = &t
	}
	if inv.Error != "" {
		e := inv.Error
		m.errText = &e
	}
	steps := make([]investigate.Step, len(inv.Steps))
	for i, s := range inv.Steps {
		s.At = incidents.NormalTime(s.At)
		steps[i] = s
	}
	var err error
	if m.progress, err = json.Marshal(steps); err != nil {
		return m, err
	}
	if inv.Refusal != nil {
		if m.refusal, err = json.Marshal(inv.Refusal); err != nil {
			return m, err
		}
	}
	if inv.Report != nil {
		if m.report, err = json.Marshal(inv.Report); err != nil {
			return m, err
		}
	}
	if len(inv.Evidence) > 0 {
		if m.evidence, err = json.Marshal(inv.Evidence); err != nil {
			return m, err
		}
	}
	return m, nil
}

// jsonbArg passes nil bytes as SQL NULL and others as jsonb text.
func jsonbArg(b []byte) any {
	if b == nil {
		return nil
	}
	return string(b)
}

// Create implements investigate.Store.
func (st *InvestigationStore) Create(ctx context.Context, inv *investigate.Investigation) error {
	ctx, cancel := context.WithTimeout(ctx, investigationTimeout)
	defer cancel()
	m, err := mutableOf(inv)
	if err != nil {
		return fmt.Errorf("pgstore: create investigation: %w", err)
	}
	access, err := json.Marshal(inv.Access)
	if err != nil {
		return err
	}
	omitted := []byte("{}")
	if len(inv.Omitted) > 0 {
		if omitted, err = json.Marshal(inv.Omitted); err != nil {
			return err
		}
	}
	var cachedFrom *string
	if inv.CachedFrom != "" {
		cachedFrom = &inv.CachedFrom
	}
	_, err = st.s.pool.Exec(ctx, `INSERT INTO incident_investigations (id, incident_id, namespace, created_at, updated_at, finished_at,
  requested_by, provider, model, effort, prompt_version, input_sha256, cached_from, access, omitted, status, error, refusal, progress,
  report, evidence, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens, turns, tool_calls)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14::jsonb, $15::jsonb, $16, $17, $18::jsonb, $19::jsonb, $20::jsonb,
  $21::jsonb, $22, $23, $24, $25, $26, $27)`,
		inv.ID, inv.IncidentID, inv.Namespace, incidents.NormalTime(inv.CreatedAt), m.updated, m.finished, inv.RequestedBy, inv.Provider,
		inv.Model, inv.Effort, inv.PromptVersion, inv.InputSHA256, cachedFrom, string(access), string(omitted), m.status, m.errText,
		jsonbArg(m.refusal), string(m.progress), jsonbArg(m.report), jsonbArg(m.evidence), m.in, m.out, m.cacheRead, m.cacheWrite,
		m.turns, m.toolCalls)
	var pe *pgconn.PgError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &pe) && pe.Code == "23505" && pe.ConstraintName == "incident_investigations_running":
		cur, gerr := st.Running(ctx, inv.IncidentID)
		if gerr != nil {
			return &investigate.ConflictError{}
		}
		return &investigate.ConflictError{RunningID: cur.ID}
	case errors.As(err, &pe) && pe.Code == "23505":
		return fmt.Errorf("investigate: investigation %s exists", inv.ID)
	case errors.As(err, &pe) && pe.Code == "23503":
		// The incident is gone (pruned), or not stored yet.
		return investigate.ErrIncidentNotFound
	}
	return fmt.Errorf("pgstore: create investigation: %w", err)
}

// Update implements investigate.Store: only while the stored run is
// running.
func (st *InvestigationStore) Update(ctx context.Context, inv *investigate.Investigation) error {
	ctx, cancel := context.WithTimeout(ctx, investigationTimeout)
	defer cancel()
	m, err := mutableOf(inv)
	if err != nil {
		return fmt.Errorf("pgstore: update investigation: %w", err)
	}
	tag, err := st.s.pool.Exec(ctx, `UPDATE incident_investigations SET status = $2, updated_at = $3, finished_at = $4, error = $5,
  refusal = $6::jsonb, progress = $7::jsonb, report = $8::jsonb, evidence = $9::jsonb, input_tokens = $10, output_tokens = $11,
  cache_read_tokens = $12, cache_write_tokens = $13, turns = $14, tool_calls = $15
WHERE id = $1 AND status = 'running'`,
		inv.ID, m.status, m.updated, m.finished, m.errText, jsonbArg(m.refusal), string(m.progress), jsonbArg(m.report),
		jsonbArg(m.evidence), m.in, m.out, m.cacheRead, m.cacheWrite, m.turns, m.toolCalls)
	var pe *pgconn.PgError
	switch {
	case errors.As(err, &pe) && pe.Code == "23505":
		// Back to running while another run of the incident runs.
		return &investigate.ConflictError{}
	case err != nil:
		return fmt.Errorf("pgstore: update investigation: %w", err)
	case tag.RowsAffected() == 1:
		return nil
	}
	var exists bool
	if err := st.s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM incident_investigations WHERE id = $1)`, inv.ID).Scan(&exists); err != nil {
		return fmt.Errorf("pgstore: update investigation: %w", err)
	}
	if exists {
		return investigate.ErrNotRunning
	}
	return investigate.ErrNotFound
}

// one reads the newest run matching where.
func (st *InvestigationStore) one(ctx context.Context, where string, args ...any) (*investigate.Investigation, error) {
	ctx, cancel := context.WithTimeout(ctx, investigationTimeout)
	defer cancel()
	rows, err := st.s.pool.Query(ctx, `SELECT `+investigationColumns+` FROM incident_investigations WHERE `+where+
		` ORDER BY created_at DESC, id COLLATE "C" DESC LIMIT 1`, args...)
	if err != nil {
		return nil, fmt.Errorf("pgstore: read investigation: %w", err)
	}
	inv, err := pgx.CollectExactlyOneRow(rows, scanInvestigation)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return nil, investigate.ErrNotFound
	case err != nil:
		return nil, fmt.Errorf("pgstore: read investigation: %w", err)
	}
	return inv, nil
}

// Get implements investigate.Store.
func (st *InvestigationStore) Get(ctx context.Context, id string) (*investigate.Investigation, error) {
	return st.one(ctx, `id = $1`, id)
}

// Running implements investigate.Store.
func (st *InvestigationStore) Running(ctx context.Context, incidentID string) (*investigate.Investigation, error) {
	return st.one(ctx, `incident_id = $1 AND status = 'running'`, incidentID)
}

// Cached implements investigate.Store.
func (st *InvestigationStore) Cached(ctx context.Context, inputSHA256 string, since time.Time) (*investigate.Investigation, error) {
	return st.one(ctx, `input_sha256 = $1 AND status = 'completed' AND cached_from IS NULL AND created_at >= $2`, inputSHA256,
		incidents.NormalTime(since))
}

// List implements investigate.Store.
func (st *InvestigationStore) List(ctx context.Context, incidentID string, limit int) ([]*investigate.Investigation, error) {
	ctx, cancel := context.WithTimeout(ctx, investigationTimeout)
	defer cancel()
	q := `SELECT ` + investigationColumns + ` FROM incident_investigations WHERE incident_id = $1 ORDER BY created_at DESC, id COLLATE "C" DESC`
	args := []any{incidentID}
	if limit > 0 {
		q += ` LIMIT $2`
		args = append(args, limit)
	}
	rows, err := st.s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("pgstore: list investigations: %w", err)
	}
	out, err := pgx.CollectRows(rows, scanInvestigation)
	if err != nil {
		return nil, fmt.Errorf("pgstore: list investigations: %w", err)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// CountSince implements investigate.Store.
func (st *InvestigationStore) CountSince(ctx context.Context, requestedBy string, since time.Time) (int, time.Time, error) {
	ctx, cancel := context.WithTimeout(ctx, investigationTimeout)
	defer cancel()
	var n int
	var oldest *time.Time
	err := st.s.pool.QueryRow(ctx, `SELECT count(*), min(created_at) FROM incident_investigations
WHERE cached_from IS NULL AND created_at >= $1 AND ($2 = '' OR requested_by = $2)`, incidents.NormalTime(since), requestedBy).Scan(&n, &oldest)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("pgstore: count investigations: %w", err)
	}
	if oldest == nil {
		return n, time.Time{}, nil
	}
	return n, oldest.UTC(), nil
}
