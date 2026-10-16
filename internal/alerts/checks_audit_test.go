package alerts

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/audit"
)

// fakeAudit is an audit store whose reads can fail and are counted.
type fakeAudit struct {
	mu      sync.Mutex
	store   *audit.MemoryStore
	fail    bool
	queries []audit.Query
	n       int
}

func newFakeAudit() *fakeAudit { return &fakeAudit{store: audit.NewMemoryStore(100_000)} }

func (f *fakeAudit) Query(_ context.Context, q audit.Query) ([]audit.Event, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queries = append(f.queries, q)
	if f.fail {
		return nil, errors.New("connection refused")
	}
	return f.store.Query(q), nil
}

// add stores an event, tagged as the ingester tags it.
func (f *fakeAudit) add(e audit.Event) {
	f.mu.Lock()
	f.n++
	if e.AuditID == "" {
		e.AuditID = fmt.Sprintf("ev-%05d", f.n)
	}
	f.mu.Unlock()
	if e.Stage == "" {
		e.Stage = "ResponseComplete"
	}
	if e.StatusCode == 0 {
		e.StatusCode = 200
	}
	if e.ActorKind == "" {
		e.ActorKind = audit.ClassifyActor(e.Username, audit.DefaultSystemPrefixes)
	}
	e.Tags = audit.Classify(e)
	f.store.Add(e)
}

func execEv(at time.Time, user, ns, pod, cmd string) audit.Event {
	return audit.Event{Time: at, Verb: "create", Username: user, Resource: "pods", Subresource: "exec", Namespace: ns, Name: pod,
		RequestURI: "/api/v1/namespaces/" + ns + "/pods/" + pod + "/exec?command=" + cmd + "&container=app&stdin=true",
		SourceIPs:  []string{"198.51.100.23"}, UserAgent: "kubectl/v1.33.0 (linux/amd64)"}
}

func secretRead(at time.Time, user, ns string) audit.Event {
	return audit.Event{Time: at, Verb: "get", Username: user, Resource: "secrets", Namespace: ns, Name: "db-password"}
}

func denied(at time.Time, user string) audit.Event {
	return audit.Event{Time: at, Verb: "list", Username: user, Resource: "secrets", Namespace: "team-a", StatusCode: 403, Decision: "forbid"}
}

// auditHarness evaluates the fixture with an audit store and every audit
// check on.
func auditHarness(t *testing.T, o Options) (*harness, *fakeAudit) {
	h := newHarness(t, o)
	fa := newFakeAudit()
	h.audit = fa
	return h, fa
}

func auditFindings(h *harness) map[string]Finding {
	out := map[string]Finding{}
	for _, f := range h.ev.Findings() {
		if strings.HasPrefix(f.Check, "audit-") {
			out[f.Key] = f
		}
	}
	return out
}

// Exec and secret reads count only people, and only in production
// namespaces by default; RBAC changes only people, anywhere; anonymous
// requests only when they were allowed, and not the public endpoints.
func TestAuditChecksFilters(t *testing.T) {
	h, fa := auditHarness(t, Options{Audit: AuditOptions{Redact: func(s string) string {
		return strings.ReplaceAll(s, "hunter2", "[REDACTED]")
	}}})
	at := t0.Add(-10 * time.Minute)
	fa.add(execEv(at, "alice@example.com", "payments", "api-0", "env+PASSWORD%3Dhunter2"))
	fa.add(execEv(at.Add(time.Minute), "alice@example.com", "payments", "api-1", "sh"))
	fa.add(execEv(at, "alice@example.com", "team-a", "img-0", "sh"))                   // not production
	fa.add(execEv(at, "system:serviceaccount:ci:deployer", "payments", "api-0", "sh")) // not a person
	fa.add(secretRead(at, "bob@example.com", "payments"))                              // production
	fa.add(secretRead(at, "bob@example.com", "team-a"))                                // not production
	fa.add(secretRead(at, "system:serviceaccount:payments:app", "payments"))           // not a person
	pf := execEv(at, "carol@example.com", "payments", "api-0", "")
	pf.Subresource, pf.StatusCode, pf.Decision = "portforward", 403, "forbid" // denied: not exec activity
	fa.add(pf)
	fa.add(audit.Event{Time: at, Verb: "create", Username: "dave@example.com", APIGroup: "rbac.authorization.k8s.io", Resource: "clusterrolebindings", Name: "dave-admin"})
	fa.add(audit.Event{Time: at, Verb: "create", Username: "system:serviceaccount:argocd:controller", APIGroup: "rbac.authorization.k8s.io", Resource: "rolebindings", Namespace: "team-a", Name: "x"})
	fa.add(audit.Event{Time: at, Verb: "get", Username: "system:serviceaccount:ops:bot", ImpersonatedUser: "erin", Resource: "pods", Namespace: "team-a"})
	fa.add(audit.Event{Time: at, Verb: "list", Username: "system:anonymous", Groups: []string{"system:unauthenticated"}, Resource: "pods", Namespace: "team-a"})
	fa.add(audit.Event{Time: at, Verb: "list", Username: "system:anonymous", Groups: []string{"system:unauthenticated"}, Resource: "secrets", Namespace: "payments", StatusCode: 403})
	fa.add(audit.Event{Time: at, Verb: "get", Username: "system:anonymous", Groups: []string{"system:unauthenticated"}, RequestURI: "/healthz"})

	_, sent := h.at(0)
	fs := auditFindings(h)
	want := map[string]string{
		"audit-exec/User/payments/alice@example.com":                    SeverityWarning,
		"audit-secret-read/User/payments/bob@example.com":               SeverityWarning,
		"audit-rbac-change/User//dave@example.com":                      SeverityWarning,
		"audit-impersonation/User/team-a/system:serviceaccount:ops:bot": SeverityWarning,
		"audit-anonymous/User/team-a/system:anonymous":                  SeverityCritical,
	}
	for k, sev := range want {
		f, ok := fs[k]
		if !ok {
			t.Errorf("no finding %s", k)
			continue
		}
		if f.Severity != sev {
			t.Errorf("%s: severity %s", k, f.Severity)
		}
	}
	for k := range fs {
		if _, ok := want[k]; !ok {
			t.Errorf("unexpected finding %s", k)
		}
	}
	a := sentByKey(sent)["audit-exec/User/payments/alice@example.com"]
	ann := a.Annotations
	if a.Labels["alertname"] != AlertAuditActivity || a.Labels["object"] != "User/alice@example.com" || a.Labels["namespace"] != "payments" ||
		a.Labels["production"] != "true" || ann["actor"] != "alice@example.com" || ann["actor_kind"] != "user" || ann["count"] != "2" ||
		ann["first_at"] != at.Format(time.RFC3339) || ann["last_at"] != at.Add(time.Minute).Format(time.RFC3339) || ann["verbs"] != "create pods/exec" {
		t.Errorf("exec alert %+v", a)
	}
	if ex := ann["examples"]; strings.Count(ex, "\n") != 1 || !strings.Contains(ex, "payments/api-0: env PASSWORD=[REDACTED]") || strings.Contains(ex, "hunter2") {
		t.Errorf("examples %q", ex)
	}
	for _, x := range sent {
		for k, v := range x.Annotations {
			if strings.Contains(v, "198.51.100.23") || strings.Contains(v, "kubectl/") {
				t.Errorf("%s: annotation %s holds the source IP or user agent: %q", x.Annotations["dedupe_key"], k, v)
			}
		}
	}
	if g := GateOf(CheckAuditRBACChange, "User"); g != GateAudit {
		t.Errorf("gate %s", g)
	}
	// Exec in any namespace once production-only is lifted, and without a
	// redactor no command is quoted.
	h2, fa2 := auditHarness(t, Options{Audit: AuditOptions{ProductionOnly: map[string]bool{}}})
	fa2.add(execEv(at, "alice@example.com", "team-a", "img-0", "cat+%2Fetc%2Fsecret"))
	_, sent = h2.at(0)
	a = sentByKey(sent)["audit-exec/User/team-a/alice@example.com"]
	if a.Labels == nil || strings.Contains(a.Annotations["examples"], "cat") {
		t.Errorf("exec without production-only, no redactor: %+v", a)
	}
}

// A denied burst needs DeniedBurst denials by one actor within the window;
// the finding is cluster-scoped.
func TestAuditDeniedBurst(t *testing.T) {
	h, fa := auditHarness(t, Options{})
	for i := 0; i < 19; i++ {
		fa.add(denied(t0.Add(-5*time.Minute+time.Duration(i)*10*time.Second), "mallory"))
	}
	for i := 0; i < 25; i++ { // spread out: never 20 within 10 minutes
		fa.add(denied(t0.Add(-30*time.Minute+time.Duration(i)*time.Minute), "slow"))
	}
	h.at(0)
	if fs := auditFindings(h); len(fs) != 0 {
		t.Fatalf("below the threshold: %v", fs)
	}
	fa.add(denied(t0.Add(20*time.Second), "mallory")) // the 20th within 10 minutes of the first
	h.at(30 * time.Second)
	f, ok := auditFindings(h)["audit-denied-burst/User//mallory"]
	if !ok || f.Annotations["count"] != "20" || f.Namespace != "" {
		t.Fatalf("burst finding %+v (%v)", f, auditFindings(h))
	}
	// Later denials join it while it holds.
	fa.add(denied(t0, "mallory"))
	h.at(time.Minute)
	if f := auditFindings(h)["audit-denied-burst/User//mallory"]; f.Annotations["count"] != "21" {
		t.Errorf("count after another denial = %s", f.Annotations["count"])
	}
}

// Re-reading the overlap counts nothing twice; while the store cannot be
// read the findings neither refresh nor resolve; once the newest event is
// older than the hold the finding resolves (after the grace).
func TestAuditHoldSkipAndDedupe(t *testing.T) {
	h, fa := auditHarness(t, Options{})
	fa.add(execEv(t0.Add(-time.Minute), "alice@example.com", "payments", "api-0", "sh"))
	h.at(0)
	for _, d := range []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute} {
		h.at(d)
	}
	const key = "audit-exec/User/payments/alice@example.com"
	if f := auditFindings(h)[key]; f.Annotations["count"] != "1" {
		t.Fatalf("count after overlapping polls = %s", f.Annotations["count"])
	}
	if q := fa.queries[0]; !q.Since.Equal(t0.Add(-time.Hour)) || q.Tag != audit.TagExec || !q.Actors["user"] || len(q.Actors) != 1 {
		t.Errorf("first query %+v: the whole hold window, people only", q)
	}
	if q := fa.queries[len(fa.queries)-1]; q.Since.Before(t0.Add(2*time.Minute - auditMaxLag - auditOverlap)) {
		t.Errorf("a later query reads from %s", q.Since)
	}

	// The store is down (no querier): skipped, kept open well past the hold.
	h.audit = nil
	res, _ := h.at(90 * time.Minute)
	if f := auditFindings(h)[key]; f.Resolved() || res.Resolved != 0 {
		t.Fatalf("resolved while the store was down: %+v", f)
	}
	// Reads failing: the same, and a warning.
	h.audit = fa
	fa.fail = true
	res, _ = h.at(95 * time.Minute)
	if f := auditFindings(h)[key]; f.Resolved() || len(res.Warnings) == 0 {
		t.Fatalf("failing reads: %+v warnings %v", f, res.Warnings)
	}
	// Readable again: the event is past the hold, so it resolves.
	fa.fail = false
	res, sent := h.at(100 * time.Minute)
	if f := auditFindings(h)[key]; !f.Resolved() || len(resolvedOf(sent, h.clk.t)) != 1 {
		t.Fatalf("after the hold: %+v (resolved %d)", f, res.Resolved)
	}
}

// A new leadership term reads the whole hold window, so a finding outlives
// a failover with its count intact.
func TestAuditNewTermReadsTheHoldWindow(t *testing.T) {
	h, fa := auditHarness(t, Options{})
	for i := 0; i < 3; i++ {
		fa.add(execEv(t0.Add(-time.Duration(50-i)*time.Minute), "alice@example.com", "payments", "api-0", "sh"))
	}
	h.at(0)
	h.ev = NewEvaluator(h.store, h.sink, Options{Now: h.clk.now})
	h.at(30 * time.Second)
	if f := auditFindings(h)["audit-exec/User/payments/alice@example.com"]; f.Annotations["count"] != "3" || f.Resolved() {
		t.Errorf("after the take-over: %+v", f)
	}
}

// -alerts-audit leaves checks out (through Disabled): they are not read.
func TestAuditDisabledChecksAreNotRead(t *testing.T) {
	disabled := map[string]bool{}
	for _, c := range AuditChecks() {
		if c != CheckAuditRBACChange {
			disabled[c] = true
		}
	}
	h, fa := auditHarness(t, Options{Disabled: disabled})
	h.at(0)
	for _, q := range fa.queries {
		if q.Tag != audit.TagRBACChange {
			t.Errorf("read tag %s", q.Tag)
		}
	}
	if len(fa.queries) != 1 {
		t.Errorf("%d queries", len(fa.queries))
	}
}
