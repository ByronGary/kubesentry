package detectors

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
)

// Ordinary init containers arrive in Pod.Containers with Init set; native
// sidecars arrive like app containers (and are treated as such if a source
// marks them Init but they are running).
func initFixture() model.Inventory {
	completed := model.ContainerStatus{Name: "migrate", Init: true, State: "terminated", Reason: "Completed",
		RestartCount: 3, LastTerminatedReason: "OOMKilled", LastTerminatedAt: podNow.Add(-time.Hour)}
	healthy := runningPod("a", "web-1-ok", ctrl("ReplicaSet", "web-1"), labels("app", "web"))
	healthy.Containers = []model.ContainerStatus{
		{Name: "app", State: "running", Ready: true, Started: true, RestartCount: 1},
		{Name: "mesh", State: "running", Ready: true, Started: true, RestartCount: 2},            // sidecar, as internal/kube reports it
		{Name: "log", Init: true, State: "running", Ready: true, Started: true, RestartCount: 1}, // sidecar marked Init
		completed,
	}
	slow := runningPod("a", "web-1-slow", ctrl("ReplicaSet", "web-1"), labels("app", "web"))
	slow.Ready, slow.ReadyChanged = false, podNow.Add(-time.Hour)
	slow.Containers = []model.ContainerStatus{{Name: "app", State: "running"}, completed}

	pending := func(name string, init model.ContainerStatus) model.Pod {
		p := runningPod("a", name, ctrl("ReplicaSet", "web-1"), labels("app", "web"))
		p.Phase, p.Ready = "Pending", false
		p.Containers = []model.ContainerStatus{init, {Name: "app", State: "waiting", Reason: "PodInitializing"}}
		return p
	}
	return model.Inventory{
		Workloads:   []model.Workload{{Kind: "Deployment", Namespace: "a", Name: "web", UID: "uid-web", Desired: 6, Ready: 1, Updated: 6}},
		ReplicaSets: []model.ReplicaSet{replicaSet("a", "web-1", ctrl("Deployment", "web"))},
		Pods: []model.Pod{
			healthy,
			slow,
			pending("web-1-crash", model.ContainerStatus{Name: "setup", Init: true, State: "waiting", Reason: "CrashLoopBackOff", RestartCount: 5, Message: "back-off 40s"}),
			pending("web-1-pull", model.ContainerStatus{Name: "setup", Init: true, State: "waiting", Reason: "ImagePullBackOff"}),
			pending("web-1-error", model.ContainerStatus{Name: "setup", Init: true, State: "terminated", Reason: "Error", RestartCount: 1}),
			pending("web-1-init", model.ContainerStatus{Name: "setup", Init: true, State: "running"}),
		},
	}
}

func TestInitContainers(t *testing.T) {
	inv := initFixture()
	p := DefaultPolicy()
	a := Associate(inv, p)
	checks := func(i int) map[string]Check {
		m := map[string]Check{}
		for _, c := range DiagnosePodWith(PodInput{Pod: inv.Pods[i], Now: podNow}, p) {
			m[c.ID] = c
		}
		return m
	}

	// A completed init container is not ready, restarted and was OOMKilled,
	// none of which is held against the running pod.
	h := checks(0)
	if h["containers"].Status != StatusOK || h["containers"].Detail != "All containers ready." {
		t.Errorf("healthy containers = %+v", h["containers"])
	}
	if h["restarts"].Status != StatusWarn || h["restarts"].Detail != "4 restarts across 3 containers." {
		t.Errorf("restarts count app containers and sidecars only: %+v", h["restarts"])
	}
	if h["oom"].Status != StatusOK {
		t.Errorf("an init container's OOM kill is not the pod's: %+v", h["oom"])
	}
	if s := PodSummaryOf(&inv.Pods[0], a); s.Containers != 3 || s.Restarts != 4 || s.OOMKilled || s.Reason != "" {
		t.Errorf("pod summary = %+v", s)
	}
	if got := FindOOMKills(inv.Pods, time.Time{}); len(got) != 0 {
		t.Errorf("OOM list = %+v", got)
	}

	if c := checks(1)["containers"]; c.Status != StatusWarn || c.Detail != "Running but not ready for 1h: app." {
		t.Errorf("not-ready names leave out init containers: %+v", c)
	}

	want := map[int]string{
		2: "crit Stuck: setup (init): CrashLoopBackOff. back-off 40s.",
		3: "crit Stuck: setup (init): ImagePullBackOff.",
		4: "crit Stuck: setup (init): Error.",
		5: "ok No container is stuck.",
	}
	for i, w := range want {
		if c := checks(i)["containers"]; c.Status+" "+c.Detail != w {
			t.Errorf("%s: %q, want %q", inv.Pods[i].Name, c.Status+" "+c.Detail, w)
		}
	}
	reasons := map[string]string{"web-1-crash": "CrashLoopBackOff", "web-1-pull": "ImagePullBackOff", "web-1-error": "Error", "web-1-init": "PodInitializing", "web-1-ok": ""}
	for i := range inv.Pods {
		if w, ok := reasons[inv.Pods[i].Name]; ok {
			if got := PodReason(&inv.Pods[i]); got != w {
				t.Errorf("%s reason = %q, want %q", inv.Pods[i].Name, got, w)
			}
		}
	}
	benign := model.Pod{Phase: "Pending", Containers: []model.ContainerStatus{{Name: "setup", Init: true, State: "waiting", Reason: "ContainerCreating"}}}
	if r := WaitingReason(&benign); r != "" {
		t.Errorf("an init container's benign wait is not a waiting reason: %q", r)
	}
	// An init container that failed in a pod that went on to run is history.
	ran := model.Pod{Phase: "Running", Containers: []model.ContainerStatus{{Name: "setup", Init: true, State: "terminated", Reason: "Error"}}}
	if stuck, _, _ := stuckContainers(&ran); len(stuck) != 0 {
		t.Errorf("stuck = %v", stuck)
	}

	ws := SummarizeWorkloadsWith(inv.Workloads, a, p, podNow)[0]
	// The crash-looping and failed init containers' restarts show as stuck
	// containers, not in the total: only app containers and sidecars count.
	if ws.Restarts != 4 || ws.OOMKilled {
		t.Errorf("workload restarts = %d, OOMKilled = %v", ws.Restarts, ws.OOMKilled)
	}
	if ws.Waiting["CrashLoopBackOff"] != 1 || ws.Waiting["ImagePullBackOff"] != 1 || ws.Waiting["PodInitializing"] != 2 || ws.NotReady != 5 {
		t.Errorf("workload waiting = %v notReady = %d", ws.Waiting, ws.NotReady)
	}
	if !strings.Contains(ws.Detail, "1 pod in CrashLoopBackOff, 1 in ImagePullBackOff") {
		t.Errorf("workload detail = %q", ws.Detail)
	}

	g := BuildTopologyWith("a", a, p, podNow)
	st := nodeMap(g)
	if n := st["Pod/a/web-1-error"]; n.Status != StatusCrit || n.Detail != "setup (init): Error." {
		t.Errorf("map pod = %+v", n)
	}
	if n := st["Pod/a/web-1-ok"]; n.Status != StatusWarn || n.Detail != "4 restarts." {
		t.Errorf("map pod = %+v", n)
	}
}

// The detectors read the inventory a cache shares between calls; they must not
// sort, append to or otherwise change it.
func TestDetectorsLeaveInputsUntouched(t *testing.T) {
	in := topologyInput()
	in.Pods = append(in.Pods, initFixture().Pods...)
	// Reverse everything so an accidental in-place sort would show.
	for _, s := range []func(){
		func() { reverse(in.Pods) }, func() { reverse(in.Workloads) }, func() { reverse(in.Services) }, func() { reverse(in.Nodes) },
		func() { reverse(in.PVCs) }, func() { reverse(in.Ingresses) },
	} {
		s()
	}
	in.Nodes[0].Roles = []string{"z-role", "a-role"}
	in.Nodes[0].Taints = []string{"z=1:NoSchedule", "a=1:NoSchedule"}
	in.Workloads[0].Images = []string{"z:1", "a:1"}
	before, _ := json.Marshal(in)

	p := DefaultPolicy()
	BuildTopology("shop", in)
	SummarizeNodes(in.Nodes, in.Pods, in.Workloads, podNow)
	SummarizeWorkloads(in.Workloads, in.Pods, podNow)
	SummarizeStorage(in.PVCs, nil, in.StorageClasses, in.Pods, podNow)
	FindUnusedPVCs(in.PVCs, in.Pods, podNow, PVCOptions{})
	AuditSecurity(SecurityInput{Pods: in.Pods, Workloads: in.Workloads, Services: in.Services, Ingresses: in.Ingresses})
	FindOOMKills(in.Pods, time.Time{})
	for i := range in.Pods {
		DiagnosePodWith(PodInput{Pod: in.Pods[i], Now: podNow}, p)
		PodSummaryOf(&in.Pods[i], nil)
	}
	if after, _ := json.Marshal(in); string(after) != string(before) {
		t.Error("a detector modified its input")
	}
}

func reverse[T any](s []T) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}
