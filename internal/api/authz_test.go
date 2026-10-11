package api

import (
	"context"
	"errors"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/ByronGary/kubesentry/internal/auth"
)

// azFake answers from fixed tables: scopes[user][resource] and
// cluster[user][resource].
type azFake struct {
	scopes  map[string]map[string]auth.Scope
	cluster map[string]map[string]bool
	err     error
	calls   int
}

func (f *azFake) Scope(_ context.Context, id auth.Identity, c auth.Capability) (auth.Scope, error) {
	f.calls++
	if f.err != nil {
		return auth.Scope{}, f.err
	}
	return f.scopes[id.User][c.Resource], nil
}

func (f *azFake) Allowed(_ context.Context, id auth.Identity, c auth.Capability, ns string) (bool, error) {
	f.calls++
	if f.err != nil {
		return false, f.err
	}
	if ns == "" {
		return f.cluster[id.User][c.Resource], nil
	}
	return f.scopes[id.User][c.Resource].Has(ns), nil
}

func azCtx(user string, unrestricted bool) context.Context {
	return auth.WithIdentity(context.Background(), auth.Identity{User: user, Source: "proxy", Unrestricted: unrestricted})
}

func azScope(ns ...string) auth.Scope {
	s := auth.Scope{Namespaces: map[string]bool{}}
	for _, n := range ns {
		s.Namespaces[n] = true
	}
	return s
}

func newAzFake() *azFake {
	return &azFake{
		scopes: map[string]map[string]auth.Scope{
			"alice": {"pods": azScope("a", "b"), "processes": azScope("a")},
			"bob":   {"pods": azScope("b", "a")},
			"carol": {"pods": azScope("c")},
		},
		cluster: map[string]map[string]bool{"bob": {"nodes": true}},
	}
}

func TestScopeOf(t *testing.T) {
	f := newAzFake()
	if _, err := scopeOf(context.Background(), f, auth.ViewNamespace); !errors.Is(err, errNoIdentity) {
		t.Fatalf("no identity: %v", err)
	}
	if s, err := scopeOf(azCtx("root", true), nil, auth.ViewNamespace); err != nil || !s.All {
		t.Fatalf("unrestricted: %+v %v", s, err)
	}
	if _, err := scopeOf(azCtx("alice", false), nil, auth.ViewNamespace); !errors.Is(err, errNoAuthorizer) {
		t.Fatalf("no authorizer: %v", err)
	}
	s, err := scopeOf(azCtx("alice", false), f, auth.ViewProcesses)
	if err != nil || s.All || !s.Has("a") || s.Has("b") {
		t.Fatalf("alice processes: %+v %v", s, err)
	}
	f.err = errors.New("apiserver down")
	if _, err := scopeOf(azCtx("alice", false), f, auth.ViewNamespace); err == nil {
		t.Fatal("error swallowed")
	}
}

func TestAllowedHelper(t *testing.T) {
	f := newAzFake()
	for i, tc := range []struct {
		ctx  context.Context
		a    auth.Authorizer
		c    auth.Capability
		ns   string
		want bool
	}{
		{azCtx("alice", false), f, auth.ViewNamespace, "a", true},
		{azCtx("alice", false), f, auth.ViewNamespace, "c", false},
		{azCtx("bob", false), f, auth.ViewNodes, "", true},
		{azCtx("alice", false), f, auth.ViewNodes, "", false},
		{azCtx("root", true), nil, auth.ViewNodes, "", true},
		{context.Background(), f, auth.ViewNamespace, "a", false},
		{azCtx("alice", false), nil, auth.ViewNamespace, "a", false},
	} {
		if got := allowed(tc.ctx, tc.a, tc.c, tc.ns); got != tc.want {
			t.Errorf("case %d (%s %q): %v", i, tc.c.Resource, tc.ns, got)
		}
	}
	f.err = errors.New("down")
	if allowed(azCtx("alice", false), f, auth.ViewNamespace, "a") {
		t.Fatal("error allowed")
	}
}

func TestFilterByNamespace(t *testing.T) {
	type item struct{ ns, name string }
	items := []item{{"a", "1"}, {"b", "2"}, {"", "cluster"}, {"c", "3"}, {"a", "4"}}
	nsOf := func(i item) string { return i.ns }
	if got := filterByNamespace(items, nsOf, auth.Scope{All: true}); len(got) != 5 {
		t.Fatalf("all: %v", got)
	}
	got := filterByNamespace(items, nsOf, azScope("a", "c"))
	if !reflect.DeepEqual(got, []item{{"a", "1"}, {"c", "3"}, {"a", "4"}}) {
		t.Fatalf("got %v", got)
	}
	if got := filterByNamespace(items, nsOf, auth.Scope{}); got == nil || len(got) != 0 {
		t.Fatalf("empty scope: %#v (want a non-nil empty slice)", got)
	}
}

func TestScopeKey(t *testing.T) {
	f := newAzFake()
	key := func(user string, caps ...auth.Capability) string {
		t.Helper()
		k, err := ScopeKey(azCtx(user, false), f, caps...)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	// alice and bob hold list pods in the same namespaces (maps in a different order).
	if key("alice") != key("bob") {
		t.Fatal("same scope, different keys")
	}
	if key("alice") == key("carol") {
		t.Fatal("different scopes, same key")
	}
	// Bob can list nodes; alice cannot: keys differ once nodes matter.
	if key("alice", auth.ViewNamespace, auth.ViewNodes) == key("bob", auth.ViewNamespace, auth.ViewNodes) {
		t.Fatal("cluster capability ignored")
	}
	if key("alice", auth.ViewNamespace, auth.ViewProcesses) == key("bob", auth.ViewNamespace, auth.ViewProcesses) {
		t.Fatal("second namespaced capability ignored")
	}
	if k, err := ScopeKey(azCtx("root", true), nil); k != "all" || err != nil {
		t.Fatalf("unrestricted %q %v", k, err)
	}
	if _, err := ScopeKey(context.Background(), f); err == nil {
		t.Fatal("no identity accepted")
	}
	f.err = errors.New("down")
	if _, err := ScopeKey(azCtx("alice", false), f); err == nil {
		t.Fatal("error swallowed")
	}
}

func TestCacheKeyFunc(t *testing.T) {
	f := newAzFake()
	version := uint64(1)
	kf := CacheKeyFunc(f, func() uint64 { return version })
	keyOf := func(user, target string) (string, bool) {
		r := httptest.NewRequest("GET", target, nil)
		if user != "" {
			r = r.WithContext(azCtx(user, false))
		}
		return kf(r)
	}
	k1, ok := keyOf("alice", "/api/v1/pods?namespace=a&limit=10")
	k2, _ := keyOf("alice", "/api/v1/pods?limit=10&namespace=a")
	if !ok || k1 != k2 {
		t.Fatalf("query order matters: %q %q", k1, k2)
	}
	if k3, _ := keyOf("bob", "/api/v1/pods?namespace=a&limit=10"); k3 != k1 {
		t.Fatal("same scope not shared")
	}
	if k4, _ := keyOf("carol", "/api/v1/pods?namespace=a&limit=10"); k4 == k1 {
		t.Fatal("different scope shared")
	}
	version = 2
	if k5, _ := keyOf("alice", "/api/v1/pods?namespace=a&limit=10"); k5 == k1 {
		t.Fatal("version ignored")
	}
	if _, ok := keyOf("", "/api/v1/pods"); ok {
		t.Fatal("anonymous request cacheable")
	}
}
