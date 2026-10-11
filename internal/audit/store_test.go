package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

// mk builds a classified event at t0+offset minutes.
func mk(id, stage, verb, user, resource string, status int, offsetMin int) Event {
	e := Event{
		AuditID:    id,
		Time:       t0.Add(time.Duration(offsetMin) * time.Minute),
		Stage:      stage,
		Verb:       verb,
		Username:   user,
		ActorKind:  actorKind(user),
		Resource:   resource,
		StatusCode: status,
	}
	e.Tags = Classify(e)
	return e
}

func ids(events []Event) string {
	var s []string
	for _, e := range events {
		s = append(s, e.AuditID)
	}
	return strings.Join(s, ",")
}

func TestStoreUpsertKeepsLaterStage(t *testing.T) {
	s := NewMemoryStore(10)
	s.Add(mk("x", "ResponseStarted", "create", "alice", "pods", 101, 0))
	s.Add(mk("x", "ResponseComplete", "create", "alice", "pods", 200, 0))
	if s.Len() != 1 || s.Query(Query{})[0].Stage != "ResponseComplete" {
		t.Fatalf("want one ResponseComplete record, got len=%d %+v", s.Len(), s.Query(Query{}))
	}
	// A late-arriving earlier stage must not overwrite the later one.
	s.Add(mk("x", "ResponseStarted", "create", "alice", "pods", 101, 0))
	if got := s.Query(Query{})[0]; got.Stage != "ResponseComplete" || got.StatusCode != 200 {
		t.Errorf("late ResponseStarted overwrote the record: %+v", got)
	}
}

func TestStoreEvictsOldest(t *testing.T) {
	s := NewMemoryStore(3)
	for i, id := range []string{"a", "b", "c", "d", "e"} {
		s.Add(mk(id, "ResponseComplete", "create", "alice", "pods", 200, i))
	}
	if s.Len() != 3 || ids(s.Query(Query{})) != "e,d,c" {
		t.Fatalf("got len=%d ids=%s, want 3 and e,d,c", s.Len(), ids(s.Query(Query{})))
	}
	// "a" was evicted, so re-adding it is a new record, not an upsert of a ghost.
	s.Add(mk("a", "ResponseComplete", "create", "alice", "pods", 200, 9))
	if got := ids(s.Query(Query{})); got != "a,e,d" {
		t.Errorf("ids = %s, want a,e,d", got)
	}
}

func TestQueryDefaultViewHidesNoise(t *testing.T) {
	s := NewMemoryStore(100)
	s.Add(
		mk("write", "ResponseComplete", "create", "alice", "deployments", 201, 1),
		mk("sa-write", "ResponseComplete", "update", "system:serviceaccount:ci:deployer", "deployments", 200, 2),
		mk("user-read", "ResponseComplete", "get", "alice", "pods", 200, 3),
		mk("secret-read", "ResponseComplete", "get", "alice", "secrets", 200, 4),
		mk("system-read", "ResponseComplete", "get", "system:kube-scheduler", "pods", 200, 5),
		mk("system-write", "ResponseComplete", "update", "system:kube-controller-manager", "pods", 200, 6),
		mk("anon", "ResponseComplete", "get", "system:anonymous", "pods", 403, 7),
	)

	if got := ids(s.Query(Query{})); got != "anon,secret-read,sa-write,write" {
		// system-write is hidden: system actor with no tags. anon stays: it is tagged.
		t.Errorf("default view = %s", got)
	}
	if got := ids(s.Query(Query{IncludeReads: true})); got != "anon,secret-read,user-read,sa-write,write" {
		t.Errorf("with reads = %s", got)
	}
	if got := ids(s.Query(Query{Actors: map[string]bool{"system": true}, IncludeReads: true})); got != "anon,system-write,system-read" {
		t.Errorf("system actors = %s", got)
	}
	// Asking for a read verb explicitly shows reads without IncludeReads.
	if got := ids(s.Query(Query{Verb: "get", User: "alice"})); got != "secret-read,user-read" {
		t.Errorf("verb=get = %s", got)
	}
	if got := ids(s.Query(Query{Tag: TagDenied})); got != "anon" {
		t.Errorf("tag=denied = %s", got)
	}
	if got := ids(s.Query(Query{Since: t0.Add(3 * time.Minute)})); got != "anon,secret-read" {
		t.Errorf("since = %s", got)
	}
	if got := ids(s.Query(Query{IncludeReads: true, Limit: 2})); got != "anon,secret-read" {
		t.Errorf("limit = %s", got)
	}
}

func TestSummarize(t *testing.T) {
	events := []Event{
		mk("1", "ResponseComplete", "create", "alice", "deployments", 201, 1),
		mk("2", "ResponseComplete", "get", "alice", "secrets", 200, 2),
		mk("3", "ResponseComplete", "get", "alice", "pods", 403, 3),
		mk("4", "ResponseComplete", "delete", "bob", "pods", 200, 4),
	}
	events[0].Tags = nil
	s := Summarize(events)
	if s.TotalEvents != 4 || s.ByTag[TagSecretAccess] != 1 || s.ByTag[TagDenied] != 1 || s.ByTag[TagDelete] != 1 {
		t.Errorf("unexpected summary: %+v", s)
	}
	if len(s.Users) != 2 || s.Users[0].Username != "alice" {
		t.Fatalf("users = %+v", s.Users)
	}
	a := s.Users[0]
	if a.Total != 3 || a.Writes != 1 || a.SecretAccess != 1 || a.Denied != 1 || !a.LastSeen.Equal(t0.Add(3*time.Minute)) {
		t.Errorf("alice = %+v", a)
	}
	if empty := Summarize(nil); empty.Users == nil || empty.ByTag == nil {
		t.Error("empty summary should have non-nil collections for JSON")
	}
}

func TestJournalRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	j, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	in := []Event{
		mk("1", "ResponseStarted", "create", "alice", "pods", 101, 1),
		mk("1", "ResponseComplete", "create", "alice", "pods", 200, 1),
		mk("2", "ResponseComplete", "delete", "bob", "pods", 200, 2),
	}
	if err := j.Append(in); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	// Simulate a crash that left a truncated final line.
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString(`{"auditID":"3","verb":"cre`)
	f.Close()

	s := NewMemoryStore(10)
	n, err := LoadJournal(path, s)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 || s.Len() != 2 {
		t.Errorf("replayed %d lines into %d records, want 3 and 2 (upsert collapses id 1)", n, s.Len())
	}
	if got := s.Query(Query{Verb: "create"})[0]; got.Stage != "ResponseComplete" {
		t.Errorf("replay lost the later stage: %+v", got)
	}

	if n, err := LoadJournal(filepath.Join(t.TempDir(), "missing"), s); n != 0 || err != nil {
		t.Errorf("missing journal = %d, %v; want 0, nil", n, err)
	}
}

func TestIngesterAtomicOnBadPayload(t *testing.T) {
	in := &Ingester{Store: NewMemoryStore(10)}
	n, err := in.IngestReader(strings.NewReader(execEvent + "\n{broken"))
	if err == nil || n != 0 || in.Store.Len() != 0 {
		t.Errorf("bad payload stored data: n=%d err=%v len=%d", n, err, in.Store.Len())
	}
	if n, err := in.IngestReader(strings.NewReader(execEvent)); err != nil || n != 1 || in.Store.Len() != 1 {
		t.Errorf("good payload: n=%d err=%v len=%d", n, err, in.Store.Len())
	}
}
