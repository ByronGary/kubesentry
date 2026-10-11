package detectors

import (
	"strings"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
)

func TestSummarizeWorkloadsStatus(t *testing.T) {
	h := time.Hour
	deploy := func(desired, ready, updated int32) model.Workload {
		return model.Workload{Kind: "Deployment", Namespace: "app", Name: "web", Desired: desired, Ready: ready, Updated: updated}
	}
	stuck := deploy(3, 1, 1)
	stuck.Conditions = []model.Condition{{Type: "Progressing", Status: "False", Reason: "ProgressDeadlineExceeded", Message: `ReplicaSet "web-1" has timed out progressing.`}}
	paused := deploy(2, 2, 2)
	paused.Paused = true
	job := func(active int32, conds ...model.Condition) model.Workload {
		return model.Workload{Kind: "Job", Namespace: "app", Name: "batch", Desired: 1, Active: active, Conditions: conds}
	}
	cron := func(suspended bool, scheduled, succeeded time.Duration) model.Workload {
		w := model.Workload{Kind: "CronJob", Namespace: "app", Name: "nightly", Suspended: suspended}
		if scheduled > 0 {
			w.LastScheduleTime = podNow.Add(-scheduled)
		}
		if succeeded > 0 {
			w.LastSuccessTime = podNow.Add(-succeeded)
		}
		return w
	}

	cases := []struct {
		name   string
		w      model.Workload
		status string
		detail string
	}{
		{"scaled to zero", deploy(0, 0, 0), StatusOK, "Scaled to zero."},
		{"daemonset on no nodes", model.Workload{Kind: "DaemonSet", Name: "agent"}, StatusOK, "No nodes to run on."},
		{"progress deadline", stuck, StatusCrit, `Rollout stuck: ReplicaSet "web-1" has timed out progressing.`},
		{"none ready", deploy(2, 0, 2), StatusCrit, "0 of 2 ready."},
		{"some ready", deploy(2, 1, 2), StatusWarn, "1 of 2 ready."},
		{"rolling out", deploy(3, 3, 1), StatusWarn, "Rollout in progress: 1 of 3 updated."},
		{"paused", paused, StatusWarn, "Rollout paused."},
		{"healthy", deploy(3, 3, 3), StatusOK, "3 of 3 ready."},
		{"statefulset healthy", model.Workload{Kind: "StatefulSet", Name: "db", Desired: 1, Ready: 1, Updated: 1}, StatusOK, "1 of 1 ready."},
		{"job failed", job(0, model.Condition{Type: "Failed", Status: "True", Reason: "BackoffLimitExceeded", Message: "Job has reached the specified backoff limit"}), StatusCrit, "Failed: Job has reached the specified backoff limit."},
		{"job failed without message", job(0, model.Condition{Type: "Failed", Status: "True", Reason: "DeadlineExceeded"}), StatusCrit, "Failed: DeadlineExceeded."},
		{"job complete", job(0, model.Condition{Type: "Complete", Status: "True"}), StatusOK, "Completed."},
		{"job running", job(1), StatusOK, "Running."},
		{"job idle", job(0), StatusWarn, "Not running and not complete."},
		{"cron suspended", cron(true, h, h), StatusWarn, "Suspended."},
		{"cron last run failed", cron(false, h, 25*h), StatusWarn, "Last run did not succeed."},
		{"cron fine", cron(false, 3*h, 3*h-2*time.Minute), StatusOK, "Last run 3h ago."},
		{"cron success unknown", cron(false, 3*h, 0), StatusOK, "Last run 3h ago."},
		{"cron never run", cron(false, 0, 0), StatusOK, "Never run."},
	}
	for _, c := range cases {
		got := SummarizeWorkloads([]model.Workload{c.w}, nil, podNow)
		if len(got) != 1 || got[0].Status != c.status || got[0].Detail != c.detail {
			t.Errorf("%s: got %+v, want %s %q", c.name, got, c.status, c.detail)
		}
	}
}

func TestSummarizeWorkloadsPodsAndOrder(t *testing.T) {
	ws := []model.Workload{
		{Kind: "Deployment", Namespace: "b", Name: "fine", Desired: 1, Ready: 1, Updated: 1, Selector: sel("app", "fine")},
		{Kind: "Deployment", Namespace: "a", Name: "web", Desired: 2, Ready: 1, Updated: 2, Selector: sel("app", "web"), Images: []string{"web:1"}},
		{Kind: "Job", Namespace: "a", Name: "etl", Desired: 1, Active: 1, Selector: sel("job", "etl")},
		{Kind: "CronJob", Namespace: "a", Name: "sync", Schedule: "0 * * * *", LastScheduleTime: podNow.Add(-2 * time.Hour), LastSuccessTime: podNow.Add(-3 * time.Hour)},
		{Kind: "Job", Namespace: "a", Name: "sync-29000000", Desired: 1, Active: 1, Selector: sel("job", "sync")},
		{Kind: "Deployment", Namespace: "a", Name: "down", Desired: 1, Selector: sel("app", "down")},
	}
	pods := []model.Pod{
		{Namespace: "a", Name: "web-1", Phase: "Running", Labels: map[string]string{"app": "web"},
			Containers: []model.ContainerStatus{{Name: "web", RestartCount: 2}, {Name: "proxy", RestartCount: 1}}},
		{Namespace: "a", Name: "web-2", Phase: "Running", Labels: map[string]string{"app": "web"},
			Containers: []model.ContainerStatus{{Name: "web", RestartCount: 4, LastTerminatedReason: "OOMKilled"}}},
		// Terminated pods are not counted and their restarts are ignored.
		{Namespace: "a", Name: "web-old", Phase: "Failed", Labels: map[string]string{"app": "web"},
			Containers: []model.ContainerStatus{{Name: "web", RestartCount: 50}}},
		// A terminating pod is on its way out: not counted, as in Deployment status.
		{Namespace: "a", Name: "web-going", Phase: "Running", Labels: map[string]string{"app": "web"}, DeletedAt: podNow.Add(-time.Minute),
			Containers: []model.ContainerStatus{{Name: "web", RestartCount: 9}}},
		{Namespace: "a", Name: "etl-x", Phase: "Pending", Labels: map[string]string{"job": "etl"}},
		{Namespace: "a", Name: "sync-29000000-q", Phase: "Running", Labels: map[string]string{"job": "sync"}},
		{Namespace: "b", Name: "fine-1", Phase: "Running", Labels: map[string]string{"app": "fine"}},
	}
	got := SummarizeWorkloads(ws, pods, podNow)

	var order []string
	for _, s := range got {
		order = append(order, s.Namespace+"/"+s.Name+"="+s.Status)
	}
	want := "a/down=crit a/etl=warn a/web=warn a/sync=ok a/sync-29000000=ok b/fine=ok"
	if strings.Join(order, " ") != want {
		t.Errorf("order = %v\nwant    %s", order, want)
	}

	by := map[string]WorkloadSummary{}
	for _, s := range got {
		by[s.Name] = s
	}
	web := by["web"]
	if web.Pods != 2 || web.Restarts != 7 || !web.OOMKilled || len(web.Images) != 1 {
		t.Errorf("web = %+v", web)
	}
	if by["etl"].Detail != "1 pod pending." {
		t.Errorf("a Job whose only pod is pending is stuck: %+v", by["etl"])
	}
	if s := by["sync"]; s.Detail != "Running now." || s.LastScheduleTime == nil || s.LastSuccessTime == nil || s.Schedule == "" {
		t.Errorf("a CronJob with a running Job is not failing: %+v", s)
	}
	if by["down"].Images == nil {
		t.Error("images must encode as [] not null")
	}
	if by["fine"].LastScheduleTime != nil {
		t.Error("zero times must be omitted")
	}
}

func TestCronJobOf(t *testing.T) {
	ws := []model.Workload{{Kind: "CronJob", Namespace: "a", Name: "db-backup"}}
	cases := map[string]bool{
		"db-backup-29012345": true,
		"db-backup-manual":   false,
		"db-backup-":         false,
		"other-29012345":     false,
		"29012345":           false,
	}
	for job, want := range cases {
		if _, ok := cronJobOf("a", job, ws); ok != want {
			t.Errorf("%s: got %v, want %v", job, ok, want)
		}
	}
	if _, ok := cronJobOf("b", "db-backup-29012345", ws); ok {
		t.Error("a CronJob only creates Jobs in its own namespace")
	}
}
