package audit

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

const eksEvent = `{"kind":"Event","apiVersion":"audit.k8s.io/v1","auditID":"e1","stage":"ResponseComplete","verb":"update",
"user":{"username":"eks:addon-manager"},"objectRef":{"resource":"deployments","apiGroup":"apps","namespace":"kube-system","name":"coredns"},
"responseStatus":{"code":200},"requestReceivedTimestamp":"2026-10-10T14:01:00Z"}`

func TestIngesterBackendPolicy(t *testing.T) {
	mem := NewMemoryStore(10)
	in := &Ingester{Backend: mem.AsStore(), SystemPrefixes: []string{"system:", "eks:"}, RedactExecArgs: true}
	n, err := in.IngestReader(strings.NewReader(execEvent + "\n" + eksEvent))
	if err != nil || n != 2 {
		t.Fatalf("ingest = %d, %v", n, err)
	}
	if in.Store != nil || mem.Len() != 2 {
		t.Fatalf("events should go to the Backend: len=%d", mem.Len())
	}
	all := in.Query(Query{IncludeReads: true, Actors: map[string]bool{"user": true, "serviceaccount": true, "system": true}})
	if len(all) != 2 {
		t.Fatalf("query through the ingester = %d events", len(all))
	}
	for _, e := range all {
		switch e.AuditID {
		case "e1":
			if e.ActorKind != "system" {
				t.Errorf("eks: user classified %q, want system", e.ActorKind)
			}
		case "a1":
			if e.ActorKind != "user" {
				t.Errorf("admin:alice classified %q", e.ActorKind)
			}
			if want := "/api/v1/namespaces/prod/pods/web-0/exec?command=sh&container=web&stdin=true"; e.RequestURI != want {
				t.Errorf("redacted URI = %q, want %q", e.RequestURI, want)
			}
		}
	}
	// The default view hides the untagged eks: write, as it hides system: ones.
	if got := in.Query(Query{}); len(got) != 1 || got[0].AuditID != "a1" {
		t.Errorf("default view = %+v", got)
	}
	if in.Active() == nil {
		t.Error("Active should return the Backend")
	}

	// Without configuration, eks: is a user and arguments are kept.
	plain := &Ingester{Store: NewMemoryStore(10)}
	if _, err := plain.IngestReader(strings.NewReader(execEvent + "\n" + eksEvent)); err != nil {
		t.Fatal(err)
	}
	for _, e := range plain.Query(Query{IncludeReads: true, Actors: map[string]bool{"user": true, "serviceaccount": true, "system": true}}) {
		if e.AuditID == "e1" && e.ActorKind != "user" {
			t.Errorf("default prefixes classify eks: as %q", e.ActorKind)
		}
		if e.AuditID == "a1" && !strings.Contains(e.RequestURI, "command=sh") {
			t.Errorf("unredacted URI lost the command: %q", e.RequestURI)
		}
	}
	if got, ok := MemoryOf(plain.Active()); !ok || got != plain.Store {
		t.Error("Active should wrap Store when there is no Backend")
	}
}

// busyStore refuses the first n Adds with ErrBackpressure.
type busyStore struct {
	Store
	mu   sync.Mutex
	n    int
	adds int
}

func (b *busyStore) Add(ctx context.Context, events []Event) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.n > 0 {
		b.n--
		return ErrBackpressure
	}
	b.adds++
	return b.Store.Add(ctx, events)
}

func TestIngesterBackpressure(t *testing.T) {
	busy := &busyStore{Store: NewMemoryStore(10).AsStore(), n: 1}
	in := &Ingester{Backend: busy}
	n, err := in.IngestReader(strings.NewReader(execEvent))
	if !errors.Is(err, ErrBackpressure) || n != 0 {
		t.Fatalf("busy backend: n=%d err=%v, want ErrBackpressure", n, err)
	}
	if n, err := in.IngestReader(strings.NewReader(execEvent)); err != nil || n != 1 {
		t.Fatalf("after the queue drained: n=%d err=%v", n, err)
	}

	// The file tailer waits out backpressure instead of dropping lines.
	busy = &busyStore{Store: NewMemoryStore(10).AsStore(), n: 3}
	in = &Ingester{Backend: busy, BackpressureWait: 5 * time.Second}
	in.IngestLine([]byte(strings.ReplaceAll(execEvent, "\n", "")))
	if busy.adds != 1 {
		t.Errorf("IngestLine stored %d times, want once after retrying", busy.adds)
	}
}

func TestRedactExecArgs(t *testing.T) {
	cases := map[string]string{
		"/api/v1/namespaces/p/pods/x/exec?command=sh&command=-c&command=echo+s3cret&container=c&stdin=true": "/api/v1/namespaces/p/pods/x/exec?command=sh&container=c&stdin=true",
		"/api/v1/namespaces/p/pods/x/exec?command=psql%20-U%20app%20-pPASS&container=c":                     "/api/v1/namespaces/p/pods/x/exec?command=psql&container=c",
		"/api/v1/namespaces/p/pods/x/exec?container=c&%63ommand=env&command=SECRET=1":                       "/api/v1/namespaces/p/pods/x/exec?container=c&command=env",
		"/api/v1/namespaces/p/pods/x/exec":                          "/api/v1/namespaces/p/pods/x/exec",
		"/api/v1/namespaces/p/pods/x/log?command=keep":              "/api/v1/namespaces/p/pods/x/log?command=keep",
		"/api/v1/namespaces/p/pods/x/exec?command=%ZZbad&command=x": "/api/v1/namespaces/p/pods/x/exec?command=",
	}
	for in, want := range cases {
		if got := RedactExecArgs(in); got != want {
			t.Errorf("RedactExecArgs(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClassifyActor(t *testing.T) {
	eks := []string{"system:", "eks:"}
	cases := []struct {
		user     string
		prefixes []string
		want     string
	}{
		{"system:serviceaccount:ci:deployer", eks, "serviceaccount"},
		{"system:serviceaccount:ci:deployer", []string{"system:serviceaccount:"}, "serviceaccount"},
		{"system:kube-scheduler", DefaultSystemPrefixes, "system"},
		{"eks:node-manager", DefaultSystemPrefixes, "user"},
		{"eks:node-manager", eks, "system"},
		{"alice", eks, "user"},
		{"alice", []string{""}, "user"},
	}
	for _, c := range cases {
		if got := ClassifyActor(c.user, c.prefixes); got != c.want {
			t.Errorf("ClassifyActor(%q, %v) = %q, want %q", c.user, c.prefixes, got, c.want)
		}
	}
}

func TestNormalizeForStore(t *testing.T) {
	e := NormalizeForStore(Event{
		Time:      time.Date(2026, 10, 10, 12, 0, 0, 123456789, time.FixedZone("x", 3600)),
		Verb:      "get",
		Username:  "bad\x00name\xff",
		Groups:    []string{},
		SourceIPs: []string{"10.0.0.1"},
		Tags:      []string{},
	})
	if want := time.Date(2026, 10, 10, 11, 0, 0, 123456000, time.UTC); e.Time != want {
		t.Errorf("time = %v, want %v", e.Time, want)
	}
	if e.Username != "bad�name�" {
		t.Errorf("username = %q", e.Username)
	}
	if e.Groups != nil || e.Tags != nil || len(e.SourceIPs) != 1 {
		t.Errorf("slices = %#v %#v %#v", e.Groups, e.Tags, e.SourceIPs)
	}
	if !strings.HasPrefix(e.AuditID, "gen-") || NormalizeForStore(e).AuditID != e.AuditID {
		t.Errorf("derived AuditID = %q", e.AuditID)
	}
	other := e
	other.AuditID, other.Verb = "", "list"
	if NormalizeForStore(other).AuditID == e.AuditID {
		t.Error("different events derived the same AuditID")
	}
}
