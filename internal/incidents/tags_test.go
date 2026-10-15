package incidents

import (
	"reflect"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
)

func TestTagsOf(t *testing.T) {
	inv := fixture()
	// The pods of front carry a team label; one disagrees.
	inv = withPod(inv, "front-1-x", func(p *model.Pod) { p.Labels = map[string]string{"app": "front", "team": "web"} })
	extra := model.Pod{UID: "uid-front-1-y", Namespace: "web", Name: "front-1-y", Phase: "Running", NodeName: "node-1",
		Owners: []model.OwnerRef{{Kind: "ReplicaSet", Name: "front-1", UID: "uid-front-1", Controller: true}},
		Labels: map[string]string{"app": "front", "team": "growth"}}
	third := extra
	third.UID, third.Name, third.Labels = "uid-front-1-z", "front-1-z", map[string]string{"app": "front", "team": "web"}
	inv.Pods = append(inv.Pods, extra, third)
	v := view(inv, t0)
	cases := []struct {
		s      Subject
		custom string
		want   map[string]string
	}{
		{apiSubject, "", map[string]string{"app.kubernetes.io/name": "api", "app.kubernetes.io/part-of": "store", TagService: "api",
			TagIngress: "api-ing", TagApp: "api"}},
		{dbSubject, "", map[string]string{"app": "db", "app.kubernetes.io/part-of": "store", TagService: "db", TagApp: "db"}},
		{frontSubject, "", map[string]string{"app": "front", TagService: "front", TagApp: "front"}},
		{frontSubject, "team", map[string]string{"app": "front", "team": "web", TagService: "front", TagApp: "web"}},
		{Subject{Kind: "DaemonSet", Namespace: "kube-system", Name: "aws-node"}, "", map[string]string{TagApp: "aws-node"}},
	}
	for _, c := range cases {
		if got := TagsOf(v, c.s, nil, c.custom); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s (custom %q): %v, want %v", c.s.Name, c.custom, got, c.want)
		}
	}
	if got := TagsOf(v, Subject{Kind: "Deployment", Namespace: "shop", Name: "nope"}, nil, ""); got != nil {
		t.Errorf("unknown subject: %v", got)
	}
	// The map is the caller's.
	TagsOf(v, apiSubject, nil, "")[TagApp] = "changed"
	if TagsOf(v, apiSubject, nil, "")[TagApp] != "api" {
		t.Error("the memo was modified")
	}
}

func TestRelated(t *testing.T) {
	end := func(m float64) *time.Time { return timePtr(at(m)) }
	in := Incident{ID: "a", Subject: apiSubject, Start: at(0), State: Open,
		Tags: map[string]string{"app.kubernetes.io/part-of": "store"}, Services: []string{"api"}}
	cands := []Incident{
		in,
		{ID: "db", Subject: dbSubject, Start: at(-30), End: end(5), Tags: map[string]string{"app.kubernetes.io/part-of": "store"}},
		{ID: "db-old", Subject: dbSubject, Start: at(-90), End: end(-60), Tags: map[string]string{"app.kubernetes.io/part-of": "store"}},
		{ID: "front", Subject: frontSubject, Start: at(1), State: Open, Tags: map[string]string{"app.kubernetes.io/part-of": "web"}},
		{ID: "canary", Subject: Subject{Kind: "Deployment", Namespace: "shop", Name: "api-canary"}, Start: at(2), State: Open, Services: []string{"api"}},
		{ID: "other-ns", Subject: Subject{Kind: "Deployment", Namespace: "web", Name: "api"}, Start: at(2), State: Open, Services: []string{"api"}},
		{ID: "team", Subject: Subject{Kind: "Deployment", Namespace: "shop", Name: "x"}, Start: at(3), State: Open, Tags: map[string]string{"team": "a"}},
	}
	in.Tags["team"] = "a"
	got := Related(in, cands, "", at(10))
	var ids []string
	for _, r := range got {
		ids = append(ids, r.ID)
	}
	if want := []string{"canary", "db"}; !reflect.DeepEqual(ids, want) {
		t.Errorf("related = %v, want %v", ids, want)
	}
	got = Related(in, cands, "team", at(10))
	ids = nil
	for _, r := range got {
		ids = append(ids, r.ID)
	}
	if want := []string{"team", "canary", "db"}; !reflect.DeepEqual(ids, want) {
		t.Errorf("related with the custom key = %v, want %v", ids, want)
	}
}

// The engine fills owner, production, tags, pods, nodes and Services from
// the view, and leaves out system namespaces and namespaces not listed.
func TestEngineEnrichesFromTheView(t *testing.T) {
	h := newHarness(t, Options{})
	h.e.SetView(view(fixture(), t0))
	oom := Signal{ID: "oom", Type: TypeOOMKill, Source: SourceView, Role: Trigger, Severity: Critical, Start: at(0), Subject: apiSubject,
		Object: model.ObjectRef{Kind: "Pod", Namespace: "shop", Name: "api-7d9f-gone"}}
	sys := oom
	sys.ID, sys.Subject = "sys", Subject{Kind: "DaemonSet", Namespace: "kube-system", Name: "aws-node"}
	h.step(0, oom, sys)
	in := h.only()
	if in.Owner != "payments" || !in.Production || in.Tags[TagApp] != "api" || in.Tags["app.kubernetes.io/part-of"] != "store" {
		t.Errorf("owner and tags: %+v", in)
	}
	if !reflect.DeepEqual(in.Pods, []string{"api-7d9f-a", "api-7d9f-b", "api-7d9f-gone"}) || !reflect.DeepEqual(in.Nodes, []string{"node-1", "node-2"}) ||
		!reflect.DeepEqual(in.Services, []string{"api"}) {
		t.Errorf("lists: pods %v nodes %v services %v", in.Pods, in.Nodes, in.Services)
	}
	if in.Title != "api: OOM kill" {
		t.Errorf("title %q", in.Title)
	}

	h2 := newHarness(t, Options{IncludeSystem: true, Namespaces: []string{"kube-system"}, DefaultOwner: "platform"})
	h2.e.SetView(view(fixture(), t0))
	h2.step(0, oom, sys)
	if in := h2.only(); in.Subject != sys.Subject || in.Owner != "platform" {
		t.Errorf("with system namespaces: %s owner %q", describe([]Incident{in}), in.Owner)
	}
}
