package pgstore

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/settings"
)

// TestPGSettingsMatchMemory runs the same writes on both stores and
// compares every answer.
func TestPGSettingsMatchMemory(t *testing.T) {
	testDSN(t)
	ctx := context.Background()
	s := openTest(t, Options{})
	pg, mem := s.Settings(), settings.NewMemoryStore()
	base := time.Date(2026, 10, 18, 9, 0, 0, 123456789, time.UTC)
	type write struct {
		name   string
		value  string
		expect int64
		entry  settings.AuditEntry
	}
	writes := []write{
		{settings.Name, `{"values": {"enabled": true}, "fields": {"enabled": {"by": "alice", "at": "2026-10-18T09:00:00Z"}}}`, 0,
			settings.AuditEntry{Actor: "alice", Action: settings.ActionSave, EgressAcknowledged: true,
				Changes: []settings.Change{{Field: "enabled", Old: "false", New: "true"}}}},
		{settings.Name, `{"values": {}}`, 0, settings.AuditEntry{Actor: "bob", Action: settings.ActionSave}}, // conflict: exists
		{settings.Name, `{"values": {"enabled": false}, "fields": {}}`, 1, settings.AuditEntry{Actor: "bob", Action: settings.ActionReset,
			Changes: []settings.Change{{Field: "enabled", Old: "true", New: "false"}}}},
		{settings.Name, `{"values": {}}`, 1, settings.AuditEntry{Actor: "carol", Action: settings.ActionSave}}, // conflict: stale
		{"other", `{"x": [1, 2]}`, 0, settings.AuditEntry{Actor: "dave", Action: settings.ActionSave, EgressAckByPlatform: true}},
		{settings.Name, `{"values": {"effort": "max"}, "fields": {"effort": {"by": "erin", "at": "2026-10-18T10:00:00Z"}}}`, 2,
			settings.AuditEntry{Actor: "erin", Action: settings.ActionSave, Changes: []settings.Change{{Field: "effort", Old: "high", New: "max"}}}},
	}
	for _, st := range []settings.Store{pg, mem} {
		if _, err := st.Get(ctx, settings.Name); !errors.Is(err, settings.ErrNotFound) {
			t.Fatalf("%T empty: %v", st, err)
		}
	}
	for i, w := range writes {
		at := base.Add(time.Duration(i) * time.Minute)
		w.entry.At = at
		rec := settings.Record{Name: w.name, Value: json.RawMessage(w.value), UpdatedAt: at, UpdatedBy: w.entry.Actor}
		gotPG, errPG := pg.Put(ctx, rec, w.expect, w.entry)
		gotMem, errMem := mem.Put(ctx, rec, w.expect, w.entry)
		if !errors.Is(errPG, errMem) && (errPG == nil) != (errMem == nil) {
			t.Fatalf("write %d: postgres %v, memory %v", i, errPG, errMem)
		}
		if errPG != nil {
			if !errors.Is(errPG, settings.ErrConflict) {
				t.Fatalf("write %d: %v", i, errPG)
			}
			continue
		}
		sameRecord(t, i, gotPG, gotMem)
		r1, err1 := pg.Get(ctx, w.name)
		r2, err2 := mem.Get(ctx, w.name)
		if err1 != nil || err2 != nil {
			t.Fatal(err1, err2)
		}
		sameRecord(t, i, r1, r2)
	}
	for _, name := range []string{settings.Name, "other", "none"} {
		for _, limit := range []int{0, 1, 2} {
			a1, err1 := pg.Audit(ctx, name, limit)
			a2, err2 := mem.Audit(ctx, name, limit)
			if err1 != nil || err2 != nil {
				t.Fatal(err1, err2)
			}
			// IDs differ in kind (bigserial across names, a counter); compare
			// the rest.
			for i := range a1 {
				a1[i].ID = 0
			}
			for i := range a2 {
				a2[i].ID = 0
			}
			if !reflect.DeepEqual(a1, a2) {
				t.Errorf("audit %s limit %d:\npostgres %+v\nmemory   %+v", name, limit, a1, a2)
			}
		}
	}
	got, _ := pg.Audit(ctx, settings.Name, 0)
	if len(got) != 3 || got[0].Actor != "erin" || got[0].Version != 3 || !got[2].EgressAcknowledged || got[2].Changes[0].Field != "enabled" {
		t.Errorf("postgres audit %+v", got)
	}
	// The audit is append-only.
	if _, err := s.pool.Exec(ctx, `UPDATE settings_audit SET actor = 'mallory'`); err == nil {
		t.Error("an audit entry was updated")
	}
	if _, err := s.pool.Exec(ctx, `DELETE FROM settings_audit`); err == nil {
		t.Error("an audit entry was deleted")
	}
}

func sameRecord(t *testing.T, i int, a, b *settings.Record) {
	t.Helper()
	var va, vb any
	_ = json.Unmarshal(a.Value, &va)
	_ = json.Unmarshal(b.Value, &vb)
	if !reflect.DeepEqual(va, vb) || a.Version != b.Version || !a.UpdatedAt.Equal(b.UpdatedAt) || a.UpdatedBy != b.UpdatedBy || a.Name != b.Name {
		t.Errorf("write %d:\npostgres %+v %s\nmemory   %+v %s", i, a, a.Value, b, b.Value)
	}
}

// Two replicas on one Postgres: a save on one is applied by the other at
// its next poll; a stale save conflicts.
func TestPGSettingsReplicas(t *testing.T) {
	testDSN(t)
	ctx := context.Background()
	s := openTest(t, Options{})
	other, err := Open(ctx, testDSN(t), s.o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { other.Close(context.Background()) })
	helm := settings.Investigator{Provider: settings.ProviderBedrock, Effort: "high", BedrockAPI: settings.BedrockMantle, Fallback: "auto",
		Limits: settings.Limits{PerHour: 10, PerHourTotal: 60, Concurrency: 2, MaxTurns: 16, MaxToolCalls: 24, MaxTokens: 1_500_000,
			Timeout: settings.Duration(10 * time.Minute)}}
	type replica struct {
		m       *settings.Manager
		applied settings.Investigator
	}
	mk := func(st settings.Store) *replica {
		r := &replica{}
		m, err := settings.NewManager(settings.ManagerConfig{Store: st, Helm: helm, PlatformAck: true,
			Env: func() settings.Env { return settings.Env{Incidents: true, DefaultRegion: "us-east-1"} },
			Apply: func(_ context.Context, s settings.Investigator) (settings.Commit, error) {
				return func() { r.applied = s }, nil
			}})
		if err != nil {
			t.Fatal(err)
		}
		if err := m.Load(ctx); err != nil {
			t.Fatal(err)
		}
		r.m = m
		return r
	}
	a, b := mk(s.Settings()), mk(other.Settings())
	on := helm
	on.Enabled, on.Model = true, "us.anthropic.claude-opus-5-5"
	st, err := a.m.Save(ctx, settings.SaveRequest{Actor: "alice", Values: on})
	if err != nil {
		t.Fatal(err)
	}
	if !a.applied.Enabled || b.applied.Enabled || st.Version != 1 {
		t.Fatalf("after the save: a %+v, b %+v", a.applied, b.applied)
	}
	if err := b.m.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if !b.applied.Enabled || b.applied.Model != on.Model {
		t.Errorf("b after its poll: %+v", b.applied)
	}
	if _, err := b.m.Save(ctx, settings.SaveRequest{Actor: "bob", Version: 0, Values: helm}); !errors.Is(err, settings.ErrConflict) {
		t.Errorf("stale save: %v", err)
	}
	bs, err := b.m.State(ctx)
	if err != nil || bs.Sources["model"].By != "alice" || len(bs.Audit) != 1 || !bs.Audit[0].EgressAckByPlatform {
		t.Errorf("b's state %+v %v", bs, err)
	}
}
