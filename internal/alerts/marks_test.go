package alerts

import (
	"context"
	"strings"
	"testing"
	"time"
)

// The fixture's findings that fire at once (t0).
const (
	keyCert    = "cert-expiring/Certificate/payments/api-tls"
	keyLeak    = "memory-leak/Deployment/payments/cache"
	keyEvicted = "pod-evicted/Deployment/payments/batch"
	keyStuck   = "pod-stuck-terminating/Deployment/payments/web"
)

// act records a as another replica would: straight into the store.
func (h *harness) act(a Action) {
	h.t.Helper()
	if a.At.IsZero() {
		a.At = h.clk.t
	}
	if _, err := h.store.AddAction(context.Background(), a); err != nil {
		h.t.Fatal(err)
	}
}

// finding returns the evaluator's finding with key.
func (h *harness) finding(key string) Finding {
	h.t.Helper()
	for _, f := range h.ev.Findings() {
		if f.Key == key {
			return f
		}
	}
	h.t.Fatalf("no finding %s", key)
	return Finding{}
}

// alertsAbout returns the alerts about key.
func alertsAbout(as []Alert, key string) []Alert {
	var out []Alert
	for _, a := range as {
		if a.Annotations["dedupe_key"] == key {
			out = append(out, a)
		}
	}
	return out
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// An ack keeps the alert firing, re-posted with who acknowledged it and
// when (at once, then every Resend); it covers only the episode it was taken
// on, and no longer once a warning it was taken on turns critical.
func TestEvaluatorAck(t *testing.T) {
	h := newHarness(t, Options{LeakCritHours: 2}) // the leak, 3h from its limit, is a warning
	h.at(0)
	if f := h.finding(keyLeak); f.Severity != SeverityWarning {
		t.Fatalf("leak severity %s", f.Severity)
	}
	ackAt := t0.Add(10 * time.Second)
	for _, k := range []string{keyEvicted, keyLeak, keyCert} {
		h.act(Action{Key: k, FirstSeen: t0, Action: ActionAck, Actor: "alice", Severity: h.finding(k).Severity, At: ackAt})
	}
	_, sent := h.at(30 * time.Second)
	for _, k := range []string{keyEvicted, keyLeak, keyCert} {
		as := alertsAbout(sent, k)
		if len(as) != 1 || as[0].Annotations[AnnotationAckBy] != "alice" || as[0].Annotations[AnnotationAckAt] != stamp(ackAt) || !as[0].EndsAt.After(h.clk.t) {
			t.Fatalf("%s after the ack: %+v", k, as)
		}
		if f := h.finding(k); f.State != StateAcknowledged || f.AckBy != "alice" || !f.AckAt.Equal(ackAt) {
			t.Fatalf("%s = %+v", k, f)
		}
	}
	if as := alertsAbout(sent, keyStuck); len(as) != 0 {
		t.Errorf("an alert nobody acted on went out early: %+v", as)
	}
	// Acknowledged alerts keep being re-posted, annotations and all.
	_, sent = h.at(90 * time.Second)
	if as := alertsAbout(sent, keyEvicted); len(as) != 1 || as[0].Annotations[AnnotationAckBy] != "alice" || !as[0].EndsAt.After(h.clk.t) {
		t.Fatalf("acknowledged resend: %+v", as)
	}
	stored, _ := h.store.Load(context.Background(), time.Time{})
	for _, f := range stored {
		if f.Key == keyEvicted && (f.State != StateAcknowledged || f.AckBy != "") {
			t.Errorf("stored %+v: the state, not the details", f)
		}
	}

	// The leak turns critical: an ack taken at warning does not cover it.
	h.ev.o.LeakCritHours = 6
	_, sent = h.at(2 * time.Minute)
	cur := firing(alertsAbout(sent, keyLeak), h.clk.t)
	if len(cur) != 1 {
		t.Fatalf("escalated leak: %+v", alertsAbout(sent, keyLeak))
	}
	for _, a := range cur {
		if a.Labels["severity"] != SeverityCritical || a.Annotations[AnnotationAckBy] != "" {
			t.Errorf("escalated leak still acknowledged: %+v", a)
		}
	}
	if f := h.finding(keyLeak); f.State != StateOpen || f.AckBy != "" {
		t.Errorf("escalated leak = %+v", f)
	}
	// A critical ack (the certificate's) is not affected.
	if f := h.finding(keyCert); f.State != StateAcknowledged {
		t.Errorf("certificate = %+v", f)
	}

	// The certificate is renewed, resolves, and the problem comes back: a
	// new episode, which the old ack does not cover.
	certs := h.inv.Certs.Certificates
	h.inv.Certs.Certificates = certs[1:]
	h.at(3 * time.Minute)
	h.at(8 * time.Minute)
	if f := h.finding(keyCert); !f.Resolved() {
		t.Fatalf("certificate not resolved: %+v", f)
	}
	h.inv.Certs.Certificates = certs
	_, sent = h.at(10 * time.Minute)
	as := alertsAbout(sent, keyCert)
	if len(as) != 1 || !as[0].StartsAt.Equal(t0.Add(10*time.Minute)) || as[0].Annotations[AnnotationAckBy] != "" {
		t.Fatalf("new episode: %+v", as)
	}
	if f := h.finding(keyCert); f.State != StateOpen || f.AckBy != "" {
		t.Errorf("new episode = %+v", f)
	}
}

// A silence ends the alert once (with who silenced it, until when and why)
// and then leaves it alone, across a resolve and a reopen; when it expires,
// or is lifted, the alert fires again at once.
func TestEvaluatorSilence(t *testing.T) {
	h := newHarness(t, Options{})
	h.at(0)
	until := t0.Add(time.Hour)
	h.act(Action{Key: keyStuck, FirstSeen: t0, Action: ActionSilence, Actor: "bob", Reason: "node drain", Until: &until,
		Severity: SeverityWarning, At: t0.Add(10 * time.Second)})
	_, sent := h.at(30 * time.Second)
	as := alertsAbout(sent, keyStuck)
	if len(as) != 1 || !as[0].EndsAt.Equal(h.clk.t) || as[0].Annotations[AnnotationSilencedBy] != "bob" ||
		as[0].Annotations[AnnotationSilencedUntil] != stamp(until) || as[0].Annotations[AnnotationSilenceReason] != "node drain" {
		t.Fatalf("silencing sent %+v", as)
	}
	if f := h.finding(keyStuck); f.State != StateSilenced || f.SilencedBy != "bob" || f.SilencedUntil == nil || !f.SilencedUntil.Equal(until) {
		t.Fatalf("silenced finding = %+v", f)
	}
	_, sent = h.at(time.Minute)
	if as := alertsAbout(sent, keyStuck); len(as) != 0 || len(sent) != 3 {
		t.Fatalf("+1m sent %v", names(sent))
	}

	// The pods finish terminating: it resolves without a word (Alertmanager
	// already has it ended) ...
	for i := range h.inv.Pods {
		h.inv.Pods[i].DeletedAt = time.Time{}
	}
	h.at(2 * time.Minute)
	_, sent = h.at(6 * time.Minute)
	if f := h.finding(keyStuck); !f.Resolved() || len(alertsAbout(sent, keyStuck)) != 0 {
		t.Fatalf("+6m: %+v, sent %v", f, names(sent))
	}
	// ... comes back, still silenced: nothing is sent.
	h.inv = fixture()
	_, sent = h.at(7 * time.Minute)
	if f := h.finding(keyStuck); f.State != StateSilenced || !f.FirstSeen.Equal(t0.Add(7*time.Minute)) || len(alertsAbout(sent, keyStuck)) != 0 {
		t.Fatalf("reopened while silenced: %+v, sent %v", f, names(alertsAbout(sent, keyStuck)))
	}
	if _, sent := h.at(30 * time.Minute); len(alertsAbout(sent, keyStuck)) != 0 {
		t.Fatalf("+30m sent %+v", alertsAbout(sent, keyStuck))
	}
	// The silence expires: it fires at once, without the silence's annotations.
	_, sent = h.at(time.Hour + 10*time.Second)
	as = alertsAbout(sent, keyStuck)
	if len(as) != 1 || !as[0].EndsAt.After(h.clk.t) || !as[0].StartsAt.Equal(t0.Add(7*time.Minute)) || as[0].Annotations[AnnotationSilencedBy] != "" {
		t.Fatalf("expired silence: %+v", as)
	}
	if f := h.finding(keyStuck); f.State != StateOpen || f.SilencedUntil != nil || f.SilencedBy != "" {
		t.Fatalf("after the silence: %+v", f)
	}

	// Lifted early: fires at once too.
	later := t0.Add(5 * time.Hour)
	h.act(Action{Key: keyCert, FirstSeen: t0, Action: ActionSilence, Actor: "bob", Reason: "renewing", Until: &later, Severity: SeverityCritical})
	_, sent = h.at(time.Hour + 20*time.Second)
	if as := alertsAbout(sent, keyCert); len(as) != 1 || !as[0].EndsAt.Equal(h.clk.t) {
		t.Fatalf("certificate silenced: %+v", as)
	}
	h.act(Action{Key: keyCert, FirstSeen: t0, Action: ActionUnsilence, Actor: "carol", Severity: SeverityCritical})
	_, sent = h.at(time.Hour + 30*time.Second)
	if as := alertsAbout(sent, keyCert); len(as) != 1 || !as[0].EndsAt.After(h.clk.t) || as[0].Annotations[AnnotationSilencedBy] != "" {
		t.Fatalf("unsilenced: %+v", as)
	}
}

// An action another replica records (through the store) shows on its own
// board at once and applies at the leader's next evaluation.
func TestFollowerActionReachesTheLeader(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, Options{})
	h.at(0)
	follower := &Runner{Store: h.store, Options: Options{Now: h.clk.now}}
	follower.Reload(ctx)
	v := follower.Board().Version
	res, err := follower.Act(ctx, Action{Key: keyEvicted, Action: ActionAck, Actor: "carol"})
	if err != nil || len(res) != 1 || res[0].Err != nil || res[0].Finding.State != StateAcknowledged || res[0].Finding.AckBy != "carol" {
		t.Fatalf("act = %+v, %v", res, err)
	}
	b := follower.Board()
	if f, ok := b.Find(keyEvicted); !ok || f.State != StateAcknowledged || b.Version <= v {
		t.Fatalf("follower board v%d: %+v", b.Version, f)
	}
	_, sent := h.at(10 * time.Second)
	if as := alertsAbout(sent, keyEvicted); len(as) != 1 || as[0].Annotations[AnnotationAckBy] != "carol" {
		t.Fatalf("leader sent %+v", as)
	}
	if f := h.finding(keyEvicted); f.State != StateAcknowledged {
		t.Errorf("leader's finding = %+v", f)
	}
	// The follower's next read agrees with the leader's stored state.
	follower.Reload(ctx)
	if f, _ := follower.Board().Find(keyEvicted); f.State != StateAcknowledged || f.AckBy != "carol" {
		t.Errorf("follower after reload = %+v", f)
	}
}

// A new leader carries acknowledgements and silences on without sending
// anything early, and keeps re-posting acknowledged alerts with their
// annotations.
func TestEvaluatorTakeOverKeepsMarks(t *testing.T) {
	h := newHarness(t, Options{})
	h.at(0)
	until := t0.Add(time.Hour)
	h.act(Action{Key: keyEvicted, FirstSeen: t0, Action: ActionAck, Actor: "alice", Severity: SeverityWarning})
	h.act(Action{Key: keyStuck, FirstSeen: t0, Action: ActionSilence, Actor: "bob", Reason: "drain", Until: &until, Severity: SeverityWarning})
	if _, sent := h.at(30 * time.Second); len(alertsAbout(sent, keyEvicted)) != 1 || len(alertsAbout(sent, keyStuck)) != 1 {
		t.Fatalf("+30s sent %v", names(sent))
	}
	h.ev = NewEvaluator(h.store, h.sink, Options{Now: h.clk.now})
	if _, sent := h.at(40 * time.Second); len(sent) != 0 {
		t.Fatalf("the new leader sent %v at once", names(sent))
	}
	if f := h.finding(keyEvicted); f.State != StateAcknowledged || f.AckBy != "alice" {
		t.Errorf("after the take-over: %+v", f)
	}
	_, sent := h.at(90 * time.Second)
	if as := alertsAbout(sent, keyEvicted); len(as) != 1 || as[0].Annotations[AnnotationAckBy] != "alice" {
		t.Errorf("resend after the take-over: %+v", as)
	}
	if as := alertsAbout(sent, keyStuck); len(as) != 0 {
		t.Errorf("silenced alert sent after the take-over: %+v", as)
	}
}

// Each owner gets OwnerMaxNew new alerts on their own per OwnerWindow (the
// criticals first); the rest join that owner's digest. Another owner's
// budget is untouched.
func TestEvaluatorOwnerBudget(t *testing.T) {
	h := newHarness(t, Options{OwnerMaxNew: 2})
	res, sent := h.at(0)
	if res.Digested[DigestOwnerBudget] != 2 || res.Digested[DigestMaxNew] != 0 || !res.Digest {
		t.Fatalf("result %+v", res)
	}
	var alone []string
	var digest *Alert
	for i, a := range sent {
		if a.Labels["kubesentry_digest"] == "true" {
			digest = &sent[i]
			continue
		}
		alone = append(alone, a.Annotations["dedupe_key"])
	}
	if strings.Join(alone, " ") != keyCert+" "+keyLeak || digest == nil || digest.Labels["owner"] != "payments" || digest.Annotations["findings"] != "2" {
		t.Fatalf("alone %v, digest %+v", alone, digest)
	}
	// +5m: team-a's two workloads (owner platform) fire on their own; the
	// payments workload joins payments' digest.
	res, sent = h.at(5 * time.Minute)
	got := map[string]bool{}
	for _, a := range sent {
		got[a.Annotations["dedupe_key"]] = true
	}
	if !got["workload-unhealthy/Deployment/team-a/img"] || !got["workload-unhealthy/Pod/team-a/huge"] || got["workload-unhealthy/Deployment/payments/api"] ||
		res.Digested[DigestOwnerBudget] != 1 {
		t.Fatalf("+5m sent %v, result %+v", names(sent), res)
	}
	if f := h.finding("workload-unhealthy/Deployment/payments/api"); !f.Digest {
		t.Errorf("payments' third new finding not in its digest: %+v", f)
	}
	// +10m: platform has had its two; lost-tls joins platform's digest.
	res, _ = h.at(10 * time.Minute)
	if f := h.finding("cert-not-ready/Certificate/team-a/lost-tls"); !f.Digest || res.Digested[DigestOwnerBudget] != 1 {
		t.Errorf("+10m: %+v, %+v", f, res)
	}
}

// A digested finding that turns critical leaves the digest and fires on
// its own; silenced findings leave the digest too.
func TestEvaluatorPromotionAndSilencedDigest(t *testing.T) {
	h := newHarness(t, Options{MaxNew: 2, LeakCritHours: 2})
	res, _ := h.at(0)
	if res.Digested[DigestMaxNew] != 4 {
		t.Fatalf("result %+v", res)
	}
	h.ev.o.LeakCritHours = 6 // the leak turns critical
	res, sent := h.at(30 * time.Second)
	as := alertsAbout(sent, keyLeak)
	if res.Promoted != 1 || len(as) != 1 || as[0].Labels["severity"] != SeverityCritical || !as[0].EndsAt.After(h.clk.t) {
		t.Fatalf("promotion: %+v, sent %+v", res, sent)
	}
	if f := h.finding(keyLeak); f.Digest {
		t.Errorf("promoted finding still digested: %+v", f)
	}
	// Silenced: out of the digest, and never sent alone.
	until := t0.Add(time.Hour)
	h.act(Action{Key: keyEvicted, FirstSeen: t0, Action: ActionSilence, Actor: "bob", Reason: "known", Until: &until, Severity: SeverityWarning})
	_, sent = h.at(time.Minute)
	var digest *Alert
	for i, a := range sent {
		if a.Labels["kubesentry_digest"] == "true" {
			digest = &sent[i]
		}
	}
	if digest == nil || digest.Annotations["findings"] != "2" || len(alertsAbout(sent, keyEvicted)) != 0 {
		t.Fatalf("+1m sent %+v", sent)
	}
	if f := h.finding(keyEvicted); f.State != StateSilenced {
		t.Errorf("evicted = %+v", f)
	}
}

// An object's own owner annotation wins over its namespace's, which wins
// over the default; the namespace's routing hints go only with its own
// owner.
func TestEvaluatorObjectOwners(t *testing.T) {
	h := newHarness(t, Options{})
	for i := range h.inv.Workloads {
		w := &h.inv.Workloads[i]
		switch w.Namespace + "/" + w.Name {
		case "payments/cache":
			w.Owner = "storage"
		case "payments/batch":
			w.Owner = "payments"
		case "team-a/img":
			w.Owner = "imaging"
		}
	}
	h.inv.Certs.Certificates[0].Owner = "certs"
	h.at(0)
	h.at(5 * time.Minute)
	for key, want := range map[string]struct {
		owner string
		hint  bool
	}{
		keyLeak:    {"storage", false},
		keyEvicted: {"payments", true},
		keyStuck:   {"payments", true},
		keyCert:    {"certs", false},
		"workload-unhealthy/Deployment/team-a/img": {"imaging", false},
		"workload-unhealthy/Pod/team-a/huge":       {"platform", false},
	} {
		f := h.finding(key)
		_, hint := f.Labels["kubesentry_slack_channel"]
		if f.Owner != want.owner || f.Labels["owner"] != want.owner || hint != want.hint {
			t.Errorf("%s: owner %q (label %q), hint %v; want %+v", key, f.Owner, f.Labels["owner"], hint, want)
		}
	}
	if f := h.finding(keyLeak); f.Link != "#/pods/payments/cache-7d9f-0" {
		t.Errorf("leak link %q", f.Link)
	}
	if f := h.finding(keyCert); f.Link != "#/certificates?q=payments%2Fapi-tls" {
		t.Errorf("certificate link %q", f.Link)
	}
}

// Runner.Act checks each action against its finding, records it with the
// episode and severity, shortens a silence to MaxSilence, publishes a new
// board, and lists what was done; another replica reading the store sees
// the same.
func TestRunnerAct(t *testing.T) {
	ctx := context.Background()
	clk := &clock{t: t0}
	st := NewMemoryStore()
	gone := t0.Add(-time.Minute)
	open := Finding{Key: Key(CheckPodEvicted, "Deployment", "a", "x"), Check: CheckPodEvicted, Kind: "Deployment", Namespace: "a", Name: "x",
		Severity: SeverityWarning, State: StateOpen, FirstSeen: t0.Add(-time.Hour), LastSeen: t0}
	resolved := Finding{Key: Key(CheckPodEvicted, "Deployment", "a", "y"), Check: CheckPodEvicted, Kind: "Deployment", Namespace: "a", Name: "y",
		Severity: SeverityWarning, State: StateResolved, FirstSeen: t0.Add(-time.Hour), LastSeen: gone, ResolvedAt: &gone}
	if err := st.Commit(ctx, Commit{Findings: []Finding{open, resolved}}); err != nil {
		t.Fatal(err)
	}
	r := &Runner{Store: st, Options: Options{Now: clk.now, MaxSilence: time.Hour}}
	r.Reload(ctx)
	v := r.Board().Version
	res, err := r.Act(ctx,
		Action{Key: open.Key, Action: ActionUnack, Actor: "alice"},
		Action{Key: "nope/Deployment/a/z", Action: ActionAck, Actor: "alice"},
		Action{Key: resolved.Key, Action: ActionAck, Actor: "alice"},
		Action{Key: open.Key, Action: ActionAck, Actor: "alice"},
	)
	if err != nil || res[0].Err != ErrInvalid || res[1].Err != ErrNotFound || res[2].Err != ErrResolved || res[3].Err != nil ||
		res[3].Finding.State != StateAcknowledged || res[3].Finding.AckBy != "alice" {
		t.Fatalf("act = %+v, %v", res, err)
	}
	if b := r.Board(); b.Version <= v {
		t.Errorf("board version %d after %d", b.Version, v)
	}
	acts, _ := st.Actions(ctx, 0)
	if len(acts) != 1 || !acts[0].FirstSeen.Equal(open.FirstSeen) || acts[0].Severity != SeverityWarning || !acts[0].At.Equal(t0) || acts[0].ID != 1 {
		t.Fatalf("stored actions %+v", acts)
	}

	// A silence past the maximum ends at the maximum.
	far := t0.Add(48 * time.Hour)
	res, _ = r.Act(ctx, Action{Key: open.Key, Action: ActionSilence, Actor: "bob", Reason: "deploy", Until: &far})
	if f := res[0].Finding; res[0].Err != nil || f.State != StateSilenced || !f.SilencedUntil.Equal(t0.Add(time.Hour)) || f.AckBy != "alice" {
		t.Fatalf("silence = %+v", res[0])
	}
	past := t0.Add(-time.Second)
	if res, _ = r.Act(ctx, Action{Key: open.Key, Action: ActionSilence, Actor: "bob", Reason: "x", Until: &past}); res[0].Err != ErrInvalid {
		t.Errorf("a silence ending in the past = %+v", res[0])
	}
	// A resolved finding's silence may still be lifted.
	until := t0.Add(time.Hour)
	if _, err := st.AddAction(ctx, Action{Key: resolved.Key, FirstSeen: resolved.FirstSeen, Action: ActionSilence, Actor: "bob", Until: &until, At: t0}); err != nil {
		t.Fatal(err)
	}
	r.Reload(ctx)
	if f, _ := r.Board().Find(resolved.Key); f.SilencedBy != "bob" || !f.Resolved() {
		t.Fatalf("resolved and silenced = %+v", f)
	}
	if res, _ = r.Act(ctx, Action{Key: resolved.Key, Action: ActionUnsilence, Actor: "carol"}); res[0].Err != nil || res[0].Finding.SilencedBy != "" {
		t.Errorf("unsilence a resolved finding = %+v", res[0])
	}

	// Another replica reading the store sees the same marks.
	other := &Runner{Store: st, Options: Options{Now: clk.now}}
	other.Reload(ctx)
	if f, _ := other.Board().Find(open.Key); f.State != StateSilenced || f.AckBy != "alice" || f.SilencedBy != "bob" {
		t.Errorf("other replica = %+v", f)
	}
	// Newest first, per key or across keys.
	if got := r.Actions(open.Key, 10, nil); len(got) != 2 || got[0].Action != ActionSilence || got[1].Action != ActionAck {
		t.Errorf("actions on %s = %+v", open.Key, got)
	}
	if got := r.Actions("", 2, nil); len(got) != 2 || got[0].Action != ActionUnsilence {
		t.Errorf("latest actions = %+v", got)
	}
	if got := r.Actions("", 10, func(a *Action) bool { return a.Key == resolved.Key }); len(got) != 2 {
		t.Errorf("filtered actions = %+v", got)
	}
}

// applyMarks, case by case.
func TestApplyMarks(t *testing.T) {
	at := t0
	until := at.Add(time.Hour)
	ack := func(first time.Time, sev string) *Action {
		return &Action{Action: ActionAck, Actor: "a", FirstSeen: first, Severity: sev, At: at}
	}
	silence := &Action{Action: ActionSilence, Actor: "s", Reason: "r", Until: &until, At: at}
	base := Finding{State: StateOpen, Severity: SeverityWarning, FirstSeen: at.Add(-time.Hour)}
	for _, c := range []struct {
		name  string
		f     Finding
		m     marks
		now   time.Time
		state State
		acked bool
	}{
		{"nothing", base, marks{}, at, StateOpen, false},
		{"ack", base, marks{ack: ack(base.FirstSeen, SeverityWarning)}, at, StateAcknowledged, true},
		{"ack of another episode", base, marks{ack: ack(at, SeverityWarning)}, at, StateOpen, false},
		{"ack at warning, now critical", Finding{State: StateOpen, Severity: SeverityCritical, FirstSeen: base.FirstSeen},
			marks{ack: ack(base.FirstSeen, SeverityWarning)}, at, StateOpen, false},
		{"ack at critical, now warning", base, marks{ack: ack(base.FirstSeen, SeverityCritical)}, at, StateAcknowledged, true},
		{"silenced and acked", base, marks{ack: ack(base.FirstSeen, SeverityWarning), silence: silence}, at, StateSilenced, true},
		{"silence expired", base, marks{silence: silence}, until, StateOpen, false},
		{"was silenced, no marks", Finding{State: StateSilenced, Severity: SeverityWarning, SilencedUntil: &until}, marks{}, at, StateOpen, false},
		{"resolved stays resolved", Finding{State: StateResolved, Severity: SeverityWarning}, marks{silence: silence}, at, StateResolved, false},
	} {
		f := c.f
		applyMarks(&f, c.m, c.now)
		if f.State != c.state || (f.AckBy != "") != c.acked {
			t.Errorf("%s: state %s, acked %v", c.name, f.State, f.AckBy != "")
		}
		silenced := c.m.silence != nil && c.now.Before(until)
		if (f.SilencedUntil != nil) != silenced || (f.SilencedBy != "") != silenced {
			t.Errorf("%s: silenced until %v by %q", c.name, f.SilencedUntil, f.SilencedBy)
		}
	}
	// A silence set further out than MaxSilenceCap ends there.
	far := at.Add(90 * 24 * time.Hour)
	f := base
	applyMarks(&f, marks{silence: &Action{Action: ActionSilence, Until: &far, At: at}}, at)
	if !f.SilencedUntil.Equal(at.Add(MaxSilenceCap)) {
		t.Errorf("capped silence until %v", f.SilencedUntil)
	}
}

// Actions that commit out of ID order are still applied in ID order, and
// the read position moves on only past what settled.
func TestActionLogOrder(t *testing.T) {
	l := newActionLog()
	until := t0.Add(time.Hour)
	l.merge([]Action{{ID: 2, Key: "k", Action: ActionUnsilence, At: t0}}, t0)
	l.merge([]Action{{ID: 1, Key: "k", Action: ActionSilence, Until: &until, At: t0}, {ID: 2, Key: "k", Action: ActionUnsilence, At: t0}}, t0)
	if m := l.mark("k"); m.silence != nil {
		t.Errorf("the later unsilence did not win: %+v", m.silence)
	}
	if len(l.list("k", 10, nil)) != 2 {
		t.Errorf("duplicates kept: %+v", l.list("k", 10, nil))
	}
	if l.after != 0 {
		t.Errorf("read position %d within the settle window", l.after)
	}
	l.merge(nil, t0.Add(settleWindow+time.Second))
	if l.after != 2 {
		t.Errorf("read position %d once settled", l.after)
	}
	// Past the retention (and a day) they are forgotten.
	l.merge(nil, t0.Add(Retention+25*time.Hour))
	if got := l.list("", 10, nil); len(got) != 0 || l.after != 2 {
		t.Errorf("after the retention: %+v, read position %d", got, l.after)
	}
}
