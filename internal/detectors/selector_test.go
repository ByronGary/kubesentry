package detectors

import (
	"testing"

	"github.com/ByronGary/kubesentry/internal/model"
)

func expr(key, op string, values ...string) *model.LabelSelector {
	return &model.LabelSelector{MatchExpressions: []model.SelectorRequirement{{Key: key, Operator: op, Values: values}}}
}

func sel(kv ...string) *model.LabelSelector {
	m := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return &model.LabelSelector{MatchLabels: m}
}

func TestMatchSelector(t *testing.T) {
	labels := map[string]string{"app": "web", "tier": "front"}
	cases := []struct {
		name   string
		sel    *model.LabelSelector
		labels map[string]string
		want   bool
	}{
		{"nil matches nothing", nil, labels, false},
		{"empty matches everything", &model.LabelSelector{}, labels, true},
		{"empty matches unlabelled pod", &model.LabelSelector{}, nil, true},
		{"matchLabels", sel("app", "web"), labels, true},
		{"matchLabels wrong value", sel("app", "api"), labels, false},
		{"matchLabels missing key", sel("env", "prod"), labels, false},
		{"In", expr("tier", "In", "back", "front"), labels, true},
		{"In other value", expr("tier", "In", "back"), labels, false},
		{"In missing key", expr("env", "In", "prod"), labels, false},
		{"NotIn", expr("tier", "NotIn", "back"), labels, true},
		{"NotIn listed value", expr("tier", "NotIn", "front"), labels, false},
		{"NotIn missing key", expr("env", "NotIn", "prod"), labels, true},
		{"Exists", expr("app", "Exists"), labels, true},
		{"Exists missing key", expr("env", "Exists"), labels, false},
		{"DoesNotExist", expr("env", "DoesNotExist"), labels, true},
		{"DoesNotExist present key", expr("app", "DoesNotExist"), labels, false},
		{"unknown operator", expr("app", "Gt", "1"), labels, false},
		{"labels and expressions must both hold", &model.LabelSelector{
			MatchLabels:      map[string]string{"app": "web"},
			MatchExpressions: []model.SelectorRequirement{{Key: "tier", Operator: "In", Values: []string{"back"}}},
		}, labels, false},
	}
	for _, c := range cases {
		if got := MatchSelector(c.sel, c.labels); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestPodsFor(t *testing.T) {
	pods := []model.Pod{
		{Namespace: "app", Name: "web-1", Labels: map[string]string{"app": "web"}},
		{Namespace: "app", Name: "api-1", Labels: map[string]string{"app": "api"}},
		{Namespace: "other", Name: "web-1", Labels: map[string]string{"app": "web"}},
	}
	got := PodsFor(model.Workload{Kind: "Deployment", Namespace: "app", Name: "web", Selector: sel("app", "web")}, pods)
	if len(got) != 1 || got[0].Namespace != "app" || got[0].Name != "web-1" {
		t.Errorf("deployment pods = %+v", got)
	}
	if got := PodsFor(model.Workload{Kind: "CronJob", Namespace: "app", Selector: &model.LabelSelector{}}, pods); len(got) != 0 {
		t.Errorf("a CronJob owns no pods directly, got %+v", got)
	}
	if got := PodsFor(model.Workload{Kind: "Deployment", Namespace: "app"}, pods); len(got) != 0 {
		t.Errorf("a nil selector matches nothing, got %+v", got)
	}
}

func TestOwnerOf(t *testing.T) {
	pod := model.Pod{Namespace: "app", Name: "web-1", Labels: map[string]string{"app": "web", "job": "x"}}
	cases := []struct {
		name      string
		ws        []model.Workload
		kind, own string
		ok        bool
	}{
		{"none", nil, "", "", false},
		{"other namespace", []model.Workload{{Kind: "Deployment", Namespace: "other", Name: "web", Selector: sel("app", "web")}}, "", "", false},
		{"cronjob never owns", []model.Workload{{Kind: "CronJob", Namespace: "app", Name: "nightly", Selector: &model.LabelSelector{}}}, "", "", false},
		{"deployment beats job", []model.Workload{
			{Kind: "Job", Namespace: "app", Name: "a-job", Selector: sel("job", "x")},
			{Kind: "Deployment", Namespace: "app", Name: "web", Selector: sel("app", "web")},
		}, "Deployment", "web", true},
		{"job alone", []model.Workload{{Kind: "Job", Namespace: "app", Name: "a-job", Selector: sel("job", "x")}}, "Job", "a-job", true},
		{"tie broken by name", []model.Workload{
			{Kind: "StatefulSet", Namespace: "app", Name: "zeta", Selector: sel("app", "web")},
			{Kind: "StatefulSet", Namespace: "app", Name: "alpha", Selector: sel("app", "web")},
		}, "StatefulSet", "alpha", true},
	}
	for _, c := range cases {
		kind, name, ok := OwnerOf(pod, c.ws)
		if kind != c.kind || name != c.own || ok != c.ok {
			t.Errorf("%s: got %q %q %v, want %q %q %v", c.name, kind, name, ok, c.kind, c.own, c.ok)
		}
	}
}
