package detectors

import (
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
)

func TestPodState(t *testing.T) {
	th := DefaultPolicy().Thresholds
	old := podNow.Add(-time.Hour)
	cases := []struct {
		name          string
		pod           model.Pod
		state, reason string
	}{
		{"running", model.Pod{Phase: "Running", Created: old, Containers: []model.ContainerStatus{{Name: "a", State: "running"}}}, PodRunning, ""},
		{"crash loop in a running pod is failing, not running", model.Pod{Phase: "Running", Created: old,
			Containers: []model.ContainerStatus{{Name: "a", State: "waiting", Reason: "CrashLoopBackOff"}}}, PodFailing, "CrashLoopBackOff"},
		{"image pull while pending", model.Pod{Phase: "Pending", Created: podNow,
			Containers: []model.ContainerStatus{{Name: "a", State: "waiting", Reason: "ImagePullBackOff"}}}, PodFailing, "ImagePullBackOff"},
		{"evicted", model.Pod{Phase: "Failed", Created: old, Reason: "Evicted"}, PodFailing, "Evicted"},
		{"failed without a reason", model.Pod{Phase: "Failed", Created: old}, PodFailing, "Failed"},
		{"failed long ago is off the map", model.Pod{Phase: "Failed", Created: podNow.Add(-72 * time.Hour)}, "", ""},
		{"pending past the grace", model.Pod{Phase: "Pending", Created: old, Unschedulable: "0/3 nodes are available"}, PodPending, "Unschedulable"},
		{"pending past the grace without a reason", model.Pod{Phase: "Pending", Created: old}, PodPending, "Pending"},
		{"just created", model.Pod{Phase: "Pending", Created: podNow.Add(-time.Minute),
			Containers: []model.ContainerStatus{{Name: "a", State: "waiting", Reason: "ContainerCreating"}}}, "", ""},
		{"completed", model.Pod{Phase: "Succeeded", Created: old}, "", ""},
	}
	for _, c := range cases {
		state, reason := PodState(&c.pod, th, podNow)
		if state != c.state || reason != c.reason {
			t.Errorf("%s: PodState = %q, %q; want %q, %q", c.name, state, reason, c.state, c.reason)
		}
	}
}

func TestOwnerAndProductionPolicy(t *testing.T) {
	p := DefaultPolicy()
	ns := model.Namespace{Name: "shop", Labels: map[string]string{"environment": "production"},
		Annotations: map[string]string{"kubesentry.io/owner": " team-shop ", "example.com/team": "shop@example.com"}}
	if p.OwnerOf(ns) != "team-shop" || !p.IsProduction(ns) {
		t.Errorf("default policy: owner %q, production %v", p.OwnerOf(ns), p.IsProduction(ns))
	}
	p.OwnerAnnotation = "example.com/team"
	p.ProductionLabel = LabelMatch{Key: "tier", Value: "prod"}
	if p.OwnerOf(ns) != "shop@example.com" || p.IsProduction(ns) {
		t.Errorf("custom policy: owner %q, production %v", p.OwnerOf(ns), p.IsProduction(ns))
	}
	if (Policy{}).WithDefaults().OwnerAnnotation != DefaultOwnerAnnotation || (Policy{}).WithDefaults().ProductionLabel != DefaultProductionLabel {
		t.Error("WithDefaults leaves the owner annotation or production label empty")
	}
	if (Policy{}).IsProduction(model.Namespace{Labels: map[string]string{"environment": "staging"}}) {
		t.Error("staging counts as production")
	}

	for in, want := range map[string]LabelMatch{
		"environment=production": {"environment", "production"},
		"example.com/tier=prod":  {"example.com/tier", "prod"},
		"prod=":                  {"prod", ""},
	} {
		got, err := ParseLabelMatch(in)
		if err != nil || got != want || got.String() != in {
			t.Errorf("ParseLabelMatch(%q) = %+v, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "environment", "=production", "bad key=x", "k=bad value", "k=-x"} {
		if _, err := ParseLabelMatch(bad); err == nil {
			t.Errorf("ParseLabelMatch(%q) accepted", bad)
		}
	}
	if !ValidLabelKey("kubesentry.io/owner") || ValidLabelKey("Bad.Prefix/owner") || ValidLabelKey("") {
		t.Error("ValidLabelKey")
	}
}
