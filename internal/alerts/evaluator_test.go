package alerts

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
)

var update = flag.Bool("update", false, "rewrite testdata/*.golden.json")

// clock is a settable time for an evaluator.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

type harness struct {
	t     *testing.T
	clk   *clock
	store Store
	sink  *recordSink
	ev    *Evaluator
	inv   model.Inventory
	leaks bool
}

func newHarness(t *testing.T, o Options) *harness {
	h := &harness{t: t, clk: &clock{t: t0}, store: NewMemoryStore(), sink: &recordSink{}, inv: fixture(), leaks: true}
	o.Now = h.clk.now
	h.ev = NewEvaluator(h.store, h.sink, o)
	return h
}

// at evaluates the inventory at t0+d and returns what was sent.
func (h *harness) at(d time.Duration) (Result, []Alert) {
	h.t.Helper()
	h.clk.t = t0.Add(d)
	in := Input{View: view(h.inv, h.clk.t), Now: h.clk.t}
	if h.leaks {
		in.Leaks = leakReport(h.clk.t)
	}
	res, err := h.ev.Evaluate(context.Background(), in)
	if err != nil {
		h.t.Fatalf("evaluate at +%s: %v", d, err)
	}
	return res, h.sink.take()
}

func names(as []Alert) []string {
	var out []string
	for _, a := range as {
		out = append(out, a.Annotations["dedupe_key"]+"@"+a.Labels["severity"])
	}
	sort.Strings(out)
	return out
}

// The lifecycle on a fixed clock: standing problems fire at once, pending
// ones after their check's pending time, the RBAC baseline is recorded
// without notifying, open alerts are re-posted every Resend with endsAt
// 4×Resend ahead, and a fixed problem resolves after the grace.
func TestEvaluatorLifecycleTiming(t *testing.T) {
	h := newHarness(t, Options{ExternalURL: "https://ks.example.com", Cluster: "prod-eks"})

	res, sent := h.at(0)
	if strings.Join(res.Baselined, ",") != "anonymous-binding,cluster-admin,wildcard-rbac" {
		t.Errorf("baselined = %v", res.Baselined)
	}
	want := []string{
		"cert-expiring/Certificate/payments/api-tls@critical",
		"memory-leak/Deployment/payments/cache@critical",
		"pod-evicted/Deployment/payments/batch@warning",
		"pod-stuck-terminating/Deployment/payments/web@warning",
	}
	if got := names(sent); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("first run sent %v, want %v (RBAC baselined, workloads and lost-tls pending)", got, want)
	}
	for _, a := range sent {
		if !a.StartsAt.Equal(t0) || !a.EndsAt.Equal(t0.Add(4*time.Minute)) {
			t.Errorf("%s: startsAt %s endsAt %s", a.Labels["alertname"], a.StartsAt, a.EndsAt)
		}
	}

	// 30s later nothing is due.
	if _, sent := h.at(30 * time.Second); len(sent) != 0 {
		t.Errorf("+30s sent %v", names(sent))
	}
	// At +1m the open alerts are re-posted, endsAt pushed out.
	_, sent = h.at(time.Minute)
	if len(sent) != 4 || !sent[0].EndsAt.Equal(t0.Add(5*time.Minute)) || !sent[0].StartsAt.Equal(t0) {
		t.Fatalf("+1m resend = %v (%+v)", names(sent), sent)
	}
	// At +5m the workloads have been unhealthy for their pending time.
	_, sent = h.at(5 * time.Minute)
	gotNew := map[string]Alert{}
	for _, a := range sent {
		if strings.HasPrefix(a.Annotations["dedupe_key"], "workload-unhealthy/") {
			gotNew[a.Annotations["dedupe_key"]] = a
		}
	}
	if len(gotNew) != 3 {
		t.Fatalf("+5m workloads = %v", names(sent))
	}
	if a := gotNew["workload-unhealthy/Deployment/payments/api"]; !a.StartsAt.Equal(t0) {
		t.Errorf("a pending alert starts when it was first seen: %s", a.StartsAt)
	}
	// lost-tls waits 10 minutes.
	_, sent = h.at(10 * time.Minute)
	if !strings.Contains(strings.Join(names(sent), " "), "cert-not-ready/Certificate/team-a/lost-tls@critical") {
		t.Fatalf("+10m = %v, want lost-tls", names(sent))
	}

	// The crash loop is fixed after +10m, the last evaluation that saw it:
	// still open (resent) until the grace has passed since then.
	for i := range h.inv.Pods {
		if p := &h.inv.Pods[i]; p.Namespace == "payments" && strings.HasPrefix(p.Name, "api-") {
			p.Ready, p.Containers[0] = true, model.ContainerStatus{Name: "api", State: "running", Ready: true}
		}
	}
	h.inv.Workloads[0].Ready = 4
	const apiKey = "workload-unhealthy/Deployment/payments/api"
	for _, d := range []time.Duration{11 * time.Minute, 12 * time.Minute, 14*time.Minute + 59*time.Second} {
		res, sent := h.at(d)
		if res.Resolved != 0 || len(resolvedOf(sent, h.clk.t)) != 0 {
			t.Fatalf("+%s: resolved %d (%v) within the grace", d, res.Resolved, names(resolvedOf(sent, h.clk.t)))
		}
	}
	res, sent = h.at(15 * time.Minute)
	gone := resolvedOf(sent, h.clk.t)
	if res.Resolved != 1 || len(gone) != 1 || gone[0].Annotations["dedupe_key"] != apiKey || !gone[0].EndsAt.Equal(h.clk.t) || !gone[0].StartsAt.Equal(t0) {
		t.Fatalf("+15m resolved %d: %+v", res.Resolved, gone)
	}
	// ...once.
	if _, sent := h.at(17 * time.Minute); strings.Contains(strings.Join(names(sent), " "), apiKey) {
		t.Errorf("a resolved alert was sent again: %v", names(sent))
	}
	stored, _ := h.store.Load(context.Background(), time.Time{})
	for _, f := range stored {
		if f.Key == apiKey && (f.State != StateResolved || f.ResolvedAt == nil || !f.ResolvedAt.Equal(t0.Add(15*time.Minute))) {
			t.Errorf("stored %+v", f)
		}
	}

	// It comes back: a new alert, starting now.
	h.inv = fixture()
	if _, sent := h.at(20 * time.Minute); len(names(sent)) == 0 || strings.Contains(strings.Join(names(sent), " "), apiKey) {
		t.Errorf("+20m: back, but must wait its pending time again: %v", names(sent))
	}
	_, sent = h.at(25 * time.Minute)
	for _, a := range sent {
		if a.Annotations["dedupe_key"] == apiKey && !a.StartsAt.Equal(t0.Add(20*time.Minute)) {
			t.Errorf("reopened alert starts %s", a.StartsAt)
		}
	}
}

// A problem that blinks out of one view and back within the grace neither
// resolves nor fires again.
func TestEvaluatorNoFlapWithinGrace(t *testing.T) {
	h := newHarness(t, Options{})
	h.at(0)
	h.leaks = false // the scan is unknown for a while: leak findings stay as they are
	full := h.inv
	h.inv = fixture()
	h.inv.Certs.Certificates = h.inv.Certs.Certificates[1:] // api-tls gone for one view
	res, sent := h.at(30 * time.Second)
	if res.Resolved != 0 || len(sent) != 0 {
		t.Fatalf("blink: resolved %d, sent %v", res.Resolved, names(sent))
	}
	h.inv = full
	_, sent = h.at(2 * time.Minute)
	for _, a := range sent {
		if !a.StartsAt.Equal(t0) {
			t.Errorf("%s restarted at %s", a.Annotations["dedupe_key"], a.StartsAt)
		}
	}
	// The leak stayed open the whole time the scan was unknown.
	h.at(10 * time.Minute)
	fs := h.ev.Findings()
	for _, f := range fs {
		if f.Check == CheckMemoryLeak && f.Resolved() {
			t.Errorf("leak resolved while the scan was unknown: %+v", f)
		}
	}
}

// RBAC drift: the first evaluation records the baseline; a binding added
// later fires (critical), stays open DriftHold while it exists, then
// resolves and stays quiet. Standing bindings never fire.
func TestEvaluatorRBACDrift(t *testing.T) {
	h := newHarness(t, Options{DriftHold: time.Hour})
	h.at(0)
	h.inv = withBinding(h.inv, "mallory-admin", "mallory")
	_, sent := h.at(time.Minute)
	const key = "cluster-admin/ClusterRoleBinding//mallory-admin"
	var drift *Alert
	for i, a := range sent {
		if a.Annotations["dedupe_key"] == key {
			drift = &sent[i]
		}
		if strings.Contains(a.Annotations["dedupe_key"], "erin-admin") {
			t.Errorf("standing binding fired: %+v", a)
		}
	}
	if drift == nil || drift.Labels["alertname"] != AlertRBACDrift || drift.Labels["severity"] != SeverityCritical ||
		drift.Labels["owner"] != "platform" || drift.Labels["object"] != "ClusterRoleBinding/mallory-admin" || drift.Labels["namespace"] != "" {
		t.Fatalf("drift alert = %+v (sent %v)", drift, names(sent))
	}
	// Still open (re-posted) within the hold.
	_, sent = h.at(30 * time.Minute)
	if f := firing(sent, h.clk.t); len(f) == 0 || !strings.Contains(strings.Join(names(sent), " "), key) {
		t.Errorf("+30m: drift not re-posted: %v", names(sent))
	}
	// After the hold (an hour from +1m) it resolves once the grace has
	// passed, and stays quiet.
	h.at(60 * time.Minute)
	if _, sent := h.at(61 * time.Minute); len(resolvedOf(sent, h.clk.t)) != 0 {
		t.Fatalf("+61m resolved %v within the grace", names(resolvedOf(sent, h.clk.t)))
	}
	_, sent = h.at(65 * time.Minute)
	if r := resolvedOf(sent, h.clk.t); len(r) != 1 || r[0].Annotations["dedupe_key"] != key {
		t.Fatalf("+65m resolved %v", names(r))
	}
	if _, sent := h.at(90 * time.Minute); strings.Contains(strings.Join(names(sent), " "), key) {
		t.Errorf("drift fired again on standing state: %v", names(sent))
	}
	// Removed and added again: that is a change, so it fires again.
	h.inv = fixture()
	h.at(91 * time.Minute)
	h.inv = withBinding(h.inv, "mallory-admin", "mallory")
	if _, sent := h.at(92 * time.Minute); !strings.Contains(strings.Join(names(sent), " "), key) {
		t.Errorf("re-added binding did not fire: %v", names(sent))
	}
}

// Storm protection: more new alerts than MaxNew go out as one digest per
// owner; the digest is re-posted while its findings are open and resolved
// when they are gone; later new findings fire on their own again.
func TestEvaluatorStormDigest(t *testing.T) {
	h := newHarness(t, Options{MaxNew: 2})
	res, sent := h.at(0)
	if !res.Digest || res.New != 4 {
		t.Fatalf("result %+v", res)
	}
	byOwner := map[string]Alert{}
	for _, a := range sent {
		if a.Labels["kubesentry_digest"] != "true" || a.Labels["alertname"] != AlertFindingsDigest {
			t.Fatalf("not a digest: %+v", a)
		}
		byOwner[a.Labels["owner"]] = a
	}
	pay, ok := byOwner["payments"]
	if len(sent) != 1 || !ok || pay.Annotations["findings"] != "4" || !strings.Contains(pay.Annotations["description"], "KubesentryMemoryLeak ×1") {
		t.Fatalf("digests = %+v", sent)
	}
	// Re-posted every Resend; the digested findings are never sent alone.
	if _, sent := h.at(30 * time.Second); len(sent) != 0 {
		t.Errorf("+30s sent %v", names(sent))
	}
	_, sent = h.at(time.Minute)
	if len(sent) != 1 || sent[0].Labels["kubesentry_digest"] != "true" {
		t.Errorf("+1m = %+v", sent)
	}
	// Later new findings (the 3 workloads at +5m) fit under MaxNew... no: 3 > 2, another digest.
	res, sent = h.at(5 * time.Minute)
	if !res.Digest {
		t.Errorf("+5m: 3 new > MaxNew 2 should digest: %+v %v", res, names(sent))
	}
	// One new finding alone fires on its own.
	_, sent = h.at(10 * time.Minute) // lost-tls
	var alone bool
	for _, a := range sent {
		alone = alone || a.Annotations["dedupe_key"] == "cert-not-ready/Certificate/team-a/lost-tls"
	}
	if !alone {
		t.Errorf("+10m: a single new finding was not sent alone: %+v", sent)
	}
	// Everything of payments' digest resolves: the digest ends.
	inv := fixture()
	inv.Pods, inv.Certs = nil, model.CertManager{}
	h.inv = inv
	h.at(11 * time.Minute)
	_, sent = h.at(17 * time.Minute)
	var ended bool
	for _, a := range sent {
		if a.Labels["kubesentry_digest"] == "true" && a.Labels["owner"] == "payments" && !a.EndsAt.After(h.clk.t) {
			ended = !a.StartsAt.After(a.EndsAt)
		}
	}
	if !ended {
		t.Errorf("+17m: payments' digest not ended: %+v", sent)
	}
}

// A label change (here the severity) retires the old label set and fires
// the new one at once.
func TestEvaluatorLabelChangeRetiresOldAlert(t *testing.T) {
	h := newHarness(t, Options{})
	h.at(0)                  // the leak fires critical: 3h from its limit, under 6h
	h.ev.o.LeakCritHours = 2 // now 3h is a warning
	_, sent := h.at(30 * time.Second)
	var old, cur bool
	for _, a := range sent {
		if a.Annotations["dedupe_key"] != "memory-leak/Deployment/payments/cache" {
			continue
		}
		switch {
		case a.Labels["severity"] == SeverityCritical && !a.EndsAt.After(h.clk.t):
			old = true
		case a.Labels["severity"] == SeverityWarning && a.EndsAt.After(h.clk.t):
			cur = true
		}
	}
	if !old || !cur {
		t.Fatalf("severity change: old resolved %v, new firing %v: %+v", old, cur, sent)
	}
}

// A failed commit (the lock was lost) sends nothing; the next evaluation
// starts again from the store and notifies.
func TestEvaluatorSendsOnlyAfterCommit(t *testing.T) {
	h := newHarness(t, Options{})
	fs := &failStore{Store: h.store, fail: true}
	h.ev = NewEvaluator(fs, h.sink, Options{Now: h.clk.now})
	if _, err := h.ev.Evaluate(context.Background(), Input{View: view(h.inv, t0), Leaks: leakReport(t0), Now: t0}); err == nil {
		t.Fatal("commit failure not reported")
	}
	if sent := h.sink.take(); len(sent) != 0 {
		t.Fatalf("sent %v after a failed commit", names(sent))
	}
	fs.fail = false
	_, sent := h.at(30 * time.Second)
	if len(sent) != 4 {
		t.Fatalf("after recovery sent %v", names(sent))
	}
}

// A new evaluator (another replica took over, or a restart) on the same
// store carries on: nothing re-fires before its Resend is due.
func TestEvaluatorTakeOverCarriesOn(t *testing.T) {
	h := newHarness(t, Options{})
	h.at(0)
	h.ev = NewEvaluator(h.store, h.sink, Options{Now: h.clk.now})
	if res, sent := h.at(30 * time.Second); len(sent) != 0 || res.New != 0 || len(res.Baselined) != 0 {
		t.Fatalf("take-over at +30s: %+v sent %v", res, names(sent))
	}
	if _, sent := h.at(time.Minute); len(sent) != 4 {
		t.Errorf("take-over resend at +1m: %v", names(sent))
	}
}

// Golden payload: every label and annotation of the alerts the fixture
// raises, and the first evaluation's digest (testdata/*.golden.json; go
// test -update rewrites them).
func TestAlertPayloadGolden(t *testing.T) {
	h := newHarness(t, Options{ExternalURL: "https://kubesentry.example.com/", Cluster: "prod-eks"})
	h.at(0)
	_, a1 := h.at(10 * time.Minute) // every alert due: resends plus the pending ones
	sort.Slice(a1, func(i, j int) bool { return a1[i].Annotations["dedupe_key"] < a1[j].Annotations["dedupe_key"] })
	golden(t, "alerts", a1)

	d := newHarness(t, Options{MaxNew: 1, ExternalURL: "https://kubesentry.example.com", Cluster: "prod-eks"})
	_, a2 := d.at(0)
	golden(t, "digest", a2)
}

func golden(t *testing.T, name string, v any) {
	t.Helper()
	got, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("testdata", name+".golden.json")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(got, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test -update)", err)
	}
	if strings.TrimSpace(string(want)) != string(got) {
		t.Errorf("%s differs from %s (run go test -update after an intended change):\n%s", name, path, got)
	}
}
