package alerts

import (
	"sort"
	"strings"
	"testing"
	"time"
	_ "time/tzdata" // the schedule tests load Europe/Berlin wherever they run

	"github.com/ByronGary/kubesentry/internal/model"
)

func mustSchedule(t *testing.T, at, tz string) DigestSchedule {
	t.Helper()
	s, err := ParseDigestSchedule(at, tz)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Weekly and daily schedules, in UTC and in a zone with daylight saving.
func TestDigestSchedule(t *testing.T) {
	if t0.Weekday() != time.Monday {
		t.Fatalf("the fixtures' clock is a %s", t0.Weekday())
	}
	mon := mustSchedule(t, "Mon 09:00", "")
	for _, c := range []struct{ now, latest, next time.Time }{
		{t0, t0.Add(-3 * time.Hour), t0.Add(7*24*time.Hour - 3*time.Hour)},                                    // Mon 12:00
		{t0.Add(-3 * time.Hour), t0.Add(-3 * time.Hour), t0.Add(7*24*time.Hour - 3*time.Hour)},                // Mon 09:00 sharp
		{t0.Add(-3*time.Hour - time.Second), t0.Add(-7*24*time.Hour - 3*time.Hour), t0.Add(-3 * time.Hour)},   // just before
		{t0.Add(3 * 24 * time.Hour), t0.Add(-3 * time.Hour), t0.Add(7*24*time.Hour - 3*time.Hour)},            // Thursday
		{t0.Add(6*24*time.Hour + 20*time.Hour), t0.Add(-3 * time.Hour), t0.Add(7*24*time.Hour - 3*time.Hour)}, // Sunday night
	} {
		if got := mon.Latest(c.now); !got.Equal(c.latest) {
			t.Errorf("weekly Latest(%s) = %s, want %s", c.now, got, c.latest)
		}
		if got := mon.Next(c.now); !got.Equal(c.next) {
			t.Errorf("weekly Next(%s) = %s, want %s", c.now, got, c.next)
		}
	}
	if s := mustSchedule(t, "monday 09:00", ""); s != mon || s.String() != "Mon 09:00 UTC" {
		t.Errorf("full weekday name: %v", s)
	}

	daily := mustSchedule(t, "09:00", "")
	if got := daily.Latest(t0); !got.Equal(t0.Add(-3 * time.Hour)) {
		t.Errorf("daily Latest = %s", got)
	}
	if got := daily.Latest(t0.Add(-4 * time.Hour)); !got.Equal(t0.Add(-27 * time.Hour)) {
		t.Errorf("daily Latest before 09:00 = %s", got)
	}
	if got := daily.Next(t0); !got.Equal(t0.Add(21 * time.Hour)) {
		t.Errorf("daily Next = %s", got)
	}

	// 09:00 in Berlin is 07:00 UTC in summer time, 08:00 UTC after the
	// change on 25 October 2026.
	berlin := mustSchedule(t, "09:00", "Europe/Berlin")
	if got := berlin.Latest(t0); !got.Equal(time.Date(2026, 10, 12, 7, 0, 0, 0, time.UTC)) {
		t.Errorf("Berlin Latest = %s", got.UTC())
	}
	if got := berlin.Next(time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)); !got.Equal(time.Date(2026, 10, 25, 8, 0, 0, 0, time.UTC)) {
		t.Errorf("Berlin Next across the change = %s", got.UTC())
	}

	if off := mustSchedule(t, "", "Europe/Berlin"); off.Enabled() || !off.Next(t0).IsZero() || off.String() != "off" {
		t.Errorf("empty schedule: %v", off)
	}
	for _, bad := range [][2]string{{"Funday 09:00", ""}, {"9:00", ""}, {"25:00", ""}, {"Mon", ""}, {"09:00 Mon", ""}, {"Mon 09:00:00", ""}, {"09:00", "Mars/Base"}, {"Mo 09:00", ""}} {
		if _, err := ParseDigestSchedule(bad[0], bad[1]); err == nil {
			t.Errorf("%q in %q accepted", bad[0], bad[1])
		}
	}
}

// standingFixture adds to the fixture what the standing digests report:
// a namespaced cluster-admin binding in payments (besides erin's
// cluster-wide one), unused claims in payments and team-a, and a payments
// certificate whose renewal is overdue with 80 days left (quiet).
func standingFixture() model.Inventory {
	inv := fixture()
	inv.RBAC.Bindings = append(inv.RBAC.Bindings, model.RoleBinding{Kind: "RoleBinding", Namespace: "payments", Name: "pat-admin", RoleKind: "ClusterRole",
		RoleName: "cluster-admin", Subjects: []model.Subject{{Kind: "User", Name: "pat"}}})
	inv.StorageClasses = []model.StorageClass{{Name: "gp3", Provisioner: "ebs.csi.aws.com", PriceAnnotation: "0.08"}}
	inv.PVCs = []model.PVC{
		{Namespace: "payments", Name: "old-data", StorageClass: "gp3", Phase: "Bound", CapacityBytes: 100 << 30, Created: t0.Add(-30 * 24 * time.Hour)},
		{Namespace: "payments", Name: "small", StorageClass: "gp3", Phase: "Bound", CapacityBytes: 10 << 30, Created: t0.Add(-30 * 24 * time.Hour)},
		{Namespace: "team-a", Name: "scratch", StorageClass: "standard", Phase: "Bound", CapacityBytes: 512 << 20, Created: t0.Add(-3 * 24 * time.Hour)},
		{Namespace: "team-a", Name: "fresh", StorageClass: "gp3", Phase: "Bound", CapacityBytes: 1 << 30, Created: t0.Add(-time.Hour)},
	}
	inv.Certs.Certificates = append(inv.Certs.Certificates, model.Certificate{Namespace: "payments", Name: "far-tls", SecretName: "far-tls",
		DNSNames: []string{"far.example.com"}, IssuerKind: "ClusterIssuer", IssuerName: "le", Ready: "True",
		NotBefore: t0.Add(-100 * 24 * time.Hour), NotAfter: t0.Add(80 * 24 * time.Hour), RenewalTime: t0.Add(-2 * 24 * time.Hour)})
	return inv
}

// standing returns the standing digest alerts among as, sorted by kind and
// owner.
func standing(as []Alert) []Alert {
	var out []Alert
	for _, a := range as {
		if a.Labels["alertname"] == AlertStandingDigest {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Labels["digest"] != out[j].Labels["digest"] {
			return out[i].Labels["digest"] < out[j].Labels["digest"]
		}
		return out[i].Labels["owner"] < out[j].Labels["owner"]
	})
	return out
}

func digestNames(as []Alert) []string {
	var out []string
	for _, a := range as {
		out = append(out, a.Labels["digest"]+"/"+a.Labels["owner"])
	}
	return out
}

// The standing digests go out at the scheduled time, once per owner and
// kind; a run is persisted, so a new leader does not send them again, and a
// leader that missed slots catches up only the latest, once.
func TestStandingDigestsScheduleAndCatchUp(t *testing.T) {
	o := Options{ExternalURL: "https://kubesentry.example.com", Cluster: "prod-eks",
		Digests: DigestOptions{Schedule: mustSchedule(t, "Mon 09:00", ""), PVCMinAge: 24 * time.Hour}}
	h := newHarness(t, o)
	o.Now = h.clk.now
	h.inv = standingFixture()
	// Monday 12:00, after the slot: a first start waits for the next one.
	if res, sent := h.at(0); len(standing(sent)) != 0 || len(res.StandingDigests) != 0 {
		t.Fatalf("a first start sent %v", digestNames(standing(sent)))
	}
	if runs, _ := h.store.DigestRuns(t.Context()); len(runs) != 0 {
		t.Fatalf("runs before any digest: %v", runs)
	}
	week := 7 * 24 * time.Hour
	slot := week - 3*time.Hour // next Monday 09:00
	h.at(slot - time.Minute)
	res, sent := h.at(slot + 10*time.Second)
	got := standing(sent)
	if strings.Join(digestNames(got), " ") != "certificates/payments rbac-posture/payments rbac-posture/platform unused-volumes/payments unused-volumes/platform" {
		t.Fatalf("digests at the slot: %v", digestNames(got))
	}
	if res.StandingDigests[DigestRBACPosture] != 2 || res.StandingDigests[DigestUnusedVolumes] != 2 || res.StandingDigests[DigestCertificates] != 1 {
		t.Errorf("counts %v", res.StandingDigests)
	}
	for _, a := range got {
		if !a.StartsAt.Equal(h.clk.t) || !a.EndsAt.Equal(h.clk.t.Add(time.Hour)) || a.Labels["kubesentry_digest"] != "true" || a.Labels["severity"] != SeverityInfo {
			t.Errorf("digest %v: %+v", digestNames([]Alert{a}), a)
		}
	}
	runs, _ := h.store.DigestRuns(t.Context())
	if len(runs) != 3 || !runs[DigestCertificates].Equal(NormalTime(h.clk.t)) {
		t.Errorf("runs %v", runs)
	}
	if !h.ev.LastDigest().Equal(NormalTime(h.clk.t)) {
		t.Errorf("last digest %s", h.ev.LastDigest())
	}
	// Sent once.
	if _, sent := h.at(slot + time.Minute); len(standing(sent)) != 0 {
		t.Errorf("sent again: %v", digestNames(standing(sent)))
	}
	// A new leader reads the runs: nothing again.
	h.ev = NewEvaluator(h.store, h.sink, o)
	if _, sent := h.at(slot + 2*time.Minute); len(standing(sent)) != 0 {
		t.Errorf("a new leader sent again: %v", digestNames(standing(sent)))
	}
	// Leaderless for three weeks: the next leader catches up once, at once.
	h.ev = NewEvaluator(h.store, h.sink, o)
	late := 3*week + slot + 2*24*time.Hour // Wednesday, two slots missed
	if _, sent := h.at(late); len(standing(sent)) != 5 {
		t.Errorf("catch-up sent %v", digestNames(standing(sent)))
	}
	if _, sent := h.at(late + time.Minute); len(standing(sent)) != 0 {
		t.Errorf("caught up twice: %v", digestNames(standing(sent)))
	}
}

// The digests' content, per owner (testdata/standing-digests.golden.json).
func TestStandingDigestsGolden(t *testing.T) {
	h := newHarness(t, Options{ExternalURL: "https://kubesentry.example.com", Cluster: "prod-eks",
		Digests: DigestOptions{Schedule: mustSchedule(t, "09:00", ""), PVCMinAge: 24 * time.Hour}})
	h.inv = standingFixture()
	h.at(0)
	_, sent := h.at(21*time.Hour + time.Second) // Tuesday 09:00:01
	got := standing(sent)
	if len(got) != 5 {
		t.Fatalf("digests %v", digestNames(got))
	}
	golden(t, "standing-digests", got)
}

// A silenced finding is left out of the standing digests.
func TestStandingDigestsLeaveOutSilenced(t *testing.T) {
	h := newHarness(t, Options{Digests: DigestOptions{Schedule: mustSchedule(t, "09:00", ""), Kinds: []string{DigestCertificates}}})
	h.inv = standingFixture()
	h.at(0)
	until := t0.Add(48 * time.Hour)
	if _, err := h.store.AddAction(t.Context(), Action{Key: "cert-expiring/Certificate/payments/far-tls", FirstSeen: t0, Action: ActionSilence,
		Actor: "alice", Reason: "renewing by hand", Until: &until, Severity: SeverityWarning, At: t0.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if _, sent := h.at(21*time.Hour + time.Second); len(standing(sent)) != 0 {
		t.Errorf("a silenced certificate is in the digest: %+v", standing(sent))
	}
}

// Certificates with more than CertDays left are quiet while the
// certificates digest is on: never sent alone, never counted by storm
// protection, listed in the digest; once fewer days are left, each fires on
// its own, once. Without the digest they fire at once.
func TestQuietCertificates(t *testing.T) {
	const key = "cert-expiring/Certificate/payments/soon-tls"
	inv := fixture()
	inv.Certs.Certificates = append(inv.Certs.Certificates, model.Certificate{Namespace: "payments", Name: "soon-tls", SecretName: "soon-tls",
		IssuerKind: "ClusterIssuer", IssuerName: "le", Ready: "True",
		NotBefore: t0.Add(-70 * 24 * time.Hour), NotAfter: t0.Add(20 * 24 * time.Hour), RenewalTime: t0.Add(-10 * 24 * time.Hour)})

	loud := newHarness(t, Options{})
	loud.inv = inv
	if _, sent := loud.at(0); sentByKey(sent)[key].Labels == nil {
		t.Fatalf("without the digest the certificate does not fire: %v", names(sent))
	}

	h := newHarness(t, Options{OwnerMaxNew: 1, Digests: DigestOptions{Schedule: mustSchedule(t, "09:00", ""), Kinds: []string{DigestCertificates}}})
	h.inv = inv
	res, sent := h.at(0)
	if sentByKey(sent)[key].Labels != nil {
		t.Fatalf("a quiet certificate was sent: %v", names(sent))
	}
	var f Finding
	for _, x := range h.ev.Findings() {
		if x.Key == key {
			f = x
		}
	}
	if !f.Quiet || f.Resolved() {
		t.Fatalf("finding %+v", f)
	}
	// payments' one alert of the window (OwnerMaxNew 1) went to another
	// finding: the quiet one used none of it.
	if res.Digested[DigestOwnerBudget] != 3 {
		t.Errorf("digested %v (payments' 4 loud findings, 1 alone)", res.Digested)
	}
	// The next day's digest lists it.
	_, sent = h.at(21*time.Hour + time.Second)
	d := standing(sent)
	if len(d) != 1 || d[0].Labels["digest"] != DigestCertificates || !strings.Contains(d[0].Annotations["findings"], "payments/soon-tls") {
		t.Fatalf("certificates digest %+v", d)
	}
	// Six days later fewer than 14 days are left: it fires alone, once.
	cross := 6*24*time.Hour + time.Hour
	_, sent = h.at(cross)
	a := sentByKey(sent)[key]
	if a.Labels == nil || a.Labels["alertname"] != AlertCertificateExpiring || !a.EndsAt.After(h.clk.t) {
		t.Fatalf("crossing the threshold: %v", names(sent))
	}
	_, sent = h.at(cross + 30*time.Second)
	if sentByKey(sent)[key].Labels != nil {
		t.Errorf("fired twice: %v", names(sent))
	}
	// And it has left the certificates digest.
	_, sent = h.at(7*24*time.Hour - 3*time.Hour + time.Second)
	for _, a := range standing(sent) {
		if strings.Contains(a.Annotations["findings"], "soon-tls") {
			t.Errorf("a loud certificate is in the digest: %+v", a)
		}
	}
}
