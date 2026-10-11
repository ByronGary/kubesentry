package detectors

import (
	"strings"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
)

func TestContainersCheck(t *testing.T) {
	p := DefaultPolicy()
	base := func() model.Pod {
		return model.Pod{Phase: "Running", Ready: true, ReadyChanged: podNow.Add(-time.Hour),
			Containers: []model.ContainerStatus{{Name: "web", State: "running", Ready: true}}}
	}
	crash := base()
	crash.Ready = false
	crash.Containers = []model.ContainerStatus{
		{Name: "setup", Init: true, State: "waiting", Reason: "ImagePullBackOff", Message: `Back-off pulling image "registry/x:bad"`},
		{Name: "web", State: "waiting", Reason: "CrashLoopBackOff", Message: "back-off 5m0s restarting failed container"},
	}
	initOnly := base()
	initOnly.Phase = "Pending"
	initOnly.Containers = []model.ContainerStatus{{Name: "migrate", Init: true, State: "waiting", Reason: "CreateContainerConfigError", Message: `secret "db" not found`}}
	creating := base()
	creating.Ready, creating.Phase = false, "Pending"
	creating.Containers = []model.ContainerStatus{{Name: "web", State: "waiting", Reason: "ContainerCreating"}}
	slowReady := base()
	slowReady.Ready, slowReady.ReadyChanged = false, podNow.Add(-20*time.Minute)
	slowReady.Containers = []model.ContainerStatus{{Name: "web", State: "running"}, {Name: "proxy", State: "running", Ready: true}}
	justStarted := base()
	justStarted.Ready, justStarted.ReadyChanged = false, podNow.Add(-time.Minute)
	stuckTerm := base()
	stuckTerm.DeletedAt = podNow.Add(-30 * time.Minute)
	terminating := base()
	terminating.DeletedAt = podNow.Add(time.Second * 20)
	unknownReadiness := model.Pod{Phase: "Running", Containers: []model.ContainerStatus{{Name: "web"}}}

	cases := []struct {
		name   string
		pod    model.Pod
		status string
		inText string
	}{
		{"healthy", base(), StatusOK, "All containers ready."},
		{"crash loop and image pull", crash, StatusCrit, "Stuck: setup (init): ImagePullBackOff, web: CrashLoopBackOff. back-off 5m0s"},
		{"init config error", initOnly, StatusCrit, `migrate (init): CreateContainerConfigError. secret "db" not found.`},
		{"still creating", creating, StatusOK, "No container is stuck."},
		{"not ready too long", slowReady, StatusWarn, "Running but not ready for 20m: web."},
		{"not ready within grace", justStarted, StatusOK, "No container is stuck."},
		{"stuck terminating", stuckTerm, StatusWarn, "Still terminating 30m after its deletion time"},
		{"terminating in grace", terminating, StatusOK, "Terminating."},
		{"readiness not reported", unknownReadiness, StatusOK, "No container is stuck."},
	}
	for _, c := range cases {
		checks := DiagnosePodWith(PodInput{Pod: c.pod, Now: podNow}, p)
		got := checks[1]
		if got.ID != "containers" || got.Status != c.status || !strings.Contains(got.Detail, c.inText) {
			t.Errorf("%s: %s %s %q, want %s containing %q", c.name, got.ID, got.Status, got.Detail, c.status, c.inText)
		}
	}

	// A pod the kubelet gave up on carries its own reason, which beats any
	// container state.
	evicted := model.Pod{Namespace: "a", Name: "web-x", Phase: "Failed", Reason: "Evicted",
		Message:    "The node was low on resource: memory. Container web was using 2Gi, which exceeds its request of 512Mi.",
		Containers: []model.ContainerStatus{{Name: "web", State: "terminated", Reason: "ContainerStatusUnknown"}}}
	if c := DiagnosePodWith(PodInput{Pod: evicted, Now: podNow}, p)[1]; c.Status != StatusCrit || !strings.HasPrefix(c.Detail, "Evicted: The node was low on resource: memory.") {
		t.Errorf("evicted containers check = %+v", c)
	}
	if r := PodReason(&evicted); r != "Evicted" {
		t.Errorf("PodReason = %q, want Evicted", r)
	}
	if s := PodSummaryOf(&evicted, nil); s.Reason != "Evicted" {
		t.Errorf("pod summary reason = %q", s.Reason)
	}
	if st, detail := podStatus(&evicted, p.Thresholds, podNow); st != StatusCrit || detail != "Evicted." {
		t.Errorf("map status = %s %q", st, detail)
	}

	pending := model.Pod{Phase: "Pending", Unschedulable: "0/3 nodes are available: 3 Insufficient memory"}
	if c := phaseCheck(pending); c.Status != StatusWarn || c.Detail != "Pod is Pending. Unschedulable: 0/3 nodes are available: 3 Insufficient memory." {
		t.Errorf("phase = %+v", c)
	}
}

func TestDiagnosePodUsesPolicyThresholds(t *testing.T) {
	p := DefaultPolicy()
	p.Thresholds.RestartWarn, p.Thresholds.RestartCrit = 1, 2
	p.Thresholds.OOMRecent = time.Hour
	p.Thresholds.ActivityWindow = 24 * time.Hour
	p.Thresholds.LeakCritHours = 1
	in := PodInput{
		Pod: model.Pod{Phase: "Running", Containers: []model.ContainerStatus{
			{Name: "web", RestartCount: 2, LastTerminatedReason: "OOMKilled", LastTerminatedAt: podNow.Add(-2 * time.Hour)},
		}},
		Leaks:            []LeakFinding{{ContainerKey: model.ContainerKey{Container: "web"}, SlopeBytesPerHour: 1 << 20, TimeToLimitHours: f64(3)}},
		MetricsAvailable: true, AuditAvailable: true, ExecCount: 1, Now: podNow,
	}
	m := map[string]Check{}
	for _, c := range DiagnosePodWith(in, p) {
		m[c.ID] = c
	}
	if m["restarts"].Status != StatusCrit || m["oom"].Status != StatusWarn || m["memory"].Status != StatusWarn {
		t.Errorf("thresholds not applied: %+v", m)
	}
	if !strings.HasSuffix(m["activity"].Detail, "in the last day.") {
		t.Errorf("activity window text = %q", m["activity"].Detail)
	}
	// The defaults still say 7 days.
	d := map[string]Check{}
	for _, c := range DiagnosePod(in) {
		d[c.ID] = c
	}
	if !strings.HasSuffix(d["activity"].Detail, "in the last 7 days.") || d["oom"].Status != StatusCrit {
		t.Errorf("defaults = %+v", d)
	}
}

func TestWorkloadReadinessAndWaiting(t *testing.T) {
	mk := func(name, reason string, ready bool) model.Pod {
		p := runningPod("a", name, ctrl("ReplicaSet", "web-1"), labels("app", "web"))
		p.Ready = ready
		if reason != "" {
			p.Containers = []model.ContainerStatus{{Name: "c", State: "waiting", Reason: reason}}
		}
		return p
	}
	inv := model.Inventory{
		Workloads:   []model.Workload{{Kind: "Deployment", Namespace: "a", Name: "web", UID: "uid-web", Desired: 4, Ready: 4, Updated: 4}},
		ReplicaSets: []model.ReplicaSet{replicaSet("a", "web-1", ctrl("Deployment", "web"))},
		Pods: []model.Pod{
			mk("p1", "", true), mk("p2", "CrashLoopBackOff", false), mk("p3", "CrashLoopBackOff", false), mk("p4", "ImagePullBackOff", false),
			mk("p5", "ContainerCreating", false),
		},
	}
	p := DefaultPolicy()
	got := SummarizeWorkloadsWith(inv.Workloads, Associate(inv, p), p, podNow)[0]
	if got.Pods != 5 || got.NotReady != 4 || got.Waiting["CrashLoopBackOff"] != 2 || got.Waiting["ImagePullBackOff"] != 1 || got.Waiting["ContainerCreating"] != 1 {
		t.Errorf("summary = %+v", got)
	}
	if got.Status != StatusWarn || got.Detail != "4 of 4 ready. 2 pods in CrashLoopBackOff, 1 in ImagePullBackOff." {
		t.Errorf("status = %s %q", got.Status, got.Detail)
	}

	ps := PodSummaryOf(&inv.Pods[1], Associate(inv, p))
	if ps.Ready || ps.Reason != "CrashLoopBackOff" || ps.Workload != "Deployment/web" || ps.Node != "n1" {
		t.Errorf("pod summary = %+v", ps)
	}
	if ps := PodSummaryOf(&model.Pod{Phase: "Pending", Unschedulable: "no nodes"}, nil); ps.Reason != "Unschedulable" || ps.Workload != "" {
		t.Errorf("pending pod summary = %+v", ps)
	}
}

func TestCertThresholdsFollowLifetime(t *testing.T) {
	h := time.Hour
	day := 24 * h
	cert := func(name string, life, left time.Duration) model.Certificate {
		return model.Certificate{Namespace: "a", Name: name, IssuerKind: "External", Ready: "True",
			NotBefore: podNow.Add(left - life), NotAfter: podNow.Add(left)}
	}
	overdue := cert("overdue", 90*day, 20*day+h)
	overdue.RenewalTime = podNow.Add(-2 * day)
	inGrace := cert("in-grace", 90*day, 40*day)
	inGrace.RenewalTime = podNow.Add(-30 * time.Minute)
	specOnly := model.Certificate{Namespace: "a", Name: "spec-only", IssuerKind: "External", Ready: "True", Duration: 24 * h, NotAfter: podNow.Add(5 * h)}

	cases := []struct {
		c      model.Certificate
		status string
		detail string
	}{
		{cert("day-cert-fresh", day, 20*h), StatusOK, "Valid for 20 hours more."},
		{cert("day-cert-third", day, 6*h), StatusWarn, "Expires in 6 hours."}, // under a third of a day
		{cert("day-cert-end", day, 2*h), StatusCrit, "Expires in 2 hours."},   // under a tenth of a day
		{cert("90d-at-20d", 90*day, 20*day+h), StatusWarn, "Expires in 20 days."},
		{cert("90d-at-8d", 90*day, 8*day), StatusWarn, "Expires in 8 days."},
		{cert("90d-at-6d", 90*day, 6*day), StatusCrit, "Expires in 6 days."},
		{cert("1y-at-40d", 365*day, 40*day), StatusOK, "Valid for 40 more days."},
		{overdue, StatusWarn, "Renewal is overdue by 2 days; expires in 20 days."},
		{inGrace, StatusOK, "Valid for 40 more days."},
		{specOnly, StatusWarn, "Expires in 5 hours."}, // a third of 24h is 8h
	}
	for _, c := range cases {
		certs, _, _ := SummarizeCertsWith(model.CertManager{Certificates: []model.Certificate{c.c}}, DefaultPolicy(), podNow)
		if got := certs[0]; got.Status != c.status || got.Detail != c.detail {
			t.Errorf("%s: %s %q, want %s %q", c.c.Name, got.Status, got.Detail, c.status, c.detail)
		}
	}
}
