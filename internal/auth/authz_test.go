package auth

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"reflect"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeReviewer grants "resource@namespace" to users and groups; a grant in
// namespace "" is cluster-wide and covers every namespace.
type fakeReviewer struct {
	mu     sync.Mutex
	grants map[string]map[string]bool // subject -> resource@ns
	calls  map[string]int             // user|resource|ns -> reviews
	total  atomic.Int64

	delay       time.Duration
	gate        chan struct{} // when set, reviews wait for it to close
	entered     chan struct{} // signalled once per review start, if set
	inflight    atomic.Int64
	maxInflight atomic.Int64
	failNext    atomic.Int64  // number of reviews to fail
	hold        func(n int64) // called with each review's sequence number after it decided, if set
}

func newFakeReviewer() *fakeReviewer {
	return &fakeReviewer{grants: map[string]map[string]bool{}, calls: map[string]int{}}
}

func (f *fakeReviewer) grant(subject, resource, ns string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.grants[subject] == nil {
		f.grants[subject] = map[string]bool{}
	}
	f.grants[subject][resource+"@"+ns] = true
}

func (f *fakeReviewer) Review(ctx context.Context, user string, groups []string, verb, group, resource, ns string) (bool, error) {
	n := f.inflight.Add(1)
	defer f.inflight.Add(-1)
	for {
		m := f.maxInflight.Load()
		if n <= m || f.maxInflight.CompareAndSwap(m, n) {
			break
		}
	}
	seq := f.total.Add(1)
	ok, err := f.decide(user, groups, resource, ns)
	if f.entered != nil {
		select {
		case f.entered <- struct{}{}:
		default:
		}
	}
	if f.hold != nil {
		f.hold(seq)
	}
	if f.gate != nil {
		<-f.gate
	}
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	return ok, err
}

func (f *fakeReviewer) decide(user string, groups []string, resource, ns string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[user+"|"+resource+"|"+ns]++
	if f.failNext.Load() > 0 {
		f.failNext.Add(-1)
		return false, errors.New("apiserver unavailable")
	}
	for _, s := range append([]string{user}, groups...) {
		if f.grants[s][resource+"@"] || (ns != "" && f.grants[s][resource+"@"+ns]) {
			return true, nil
		}
	}
	return false, nil
}

func (f *fakeReviewer) revoke(subject, resource, ns string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.grants[subject], resource+"@"+ns)
}

func (f *fakeReviewer) count(user, resource, ns string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[user+"|"+resource+"|"+ns]
}

// fakeCandidates proposes namespaces per user (any capability).
type fakeCandidates map[string][]string

func (f fakeCandidates) Namespaces(user string, _ []string, _ Capability) []string { return f[user] }

// podCandidates proposes namespaces only for list pods, as an RBAC index
// would for users whose roles grant nothing in kubesentry.io.
type podCandidates map[string][]string

func (f podCandidates) Namespaces(user string, _ []string, c Capability) []string {
	if c.Resource != "pods" {
		return nil
	}
	return f[user]
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type countingObserver struct {
	mu      sync.Mutex
	reviews map[string]int
	cache   map[string]int
}

func (o *countingObserver) ObserveReview(r string) {
	o.mu.Lock()
	o.reviews[r]++
	o.mu.Unlock()
}

func (o *countingObserver) ObserveCache(r string) {
	o.mu.Lock()
	o.cache[r]++
	o.mu.Unlock()
}

func user(name string, groups ...string) Identity {
	return Identity{User: name, Groups: append(groups, GroupAuthenticated), Source: "proxy"}
}

func newAuthz(rv *fakeReviewer, c Candidates) (*SARAuthorizer, *fakeClock) {
	clk := &fakeClock{t: time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)}
	return &SARAuthorizer{Reviewer: rv, Candidates: c, Now: clk.Now}, clk
}

func nsList(s Scope) []string {
	var out []string
	for ns, ok := range s.Namespaces {
		if ok {
			out = append(out, ns)
		}
	}
	sort.Strings(out)
	return out
}

var ctx = context.Background()

func TestScopeClusterWideGrant(t *testing.T) {
	rv := newFakeReviewer()
	rv.grant("admins", "pods", "")
	a, _ := newAuthz(rv, fakeCandidates{"alice": {"a", "b"}})
	s, err := a.Scope(ctx, user("alice", "admins"), ViewNamespace)
	if err != nil || !s.All {
		t.Fatalf("scope %+v err %v", s, err)
	}
	if n := rv.total.Load(); n != 1 {
		t.Fatalf("%d reviews, want 1 cluster-wide review", n)
	}
	if rv.count("alice", "pods", "") != 1 {
		t.Fatal("cluster-wide review not made with namespace \"\"")
	}
}

func TestScopeConfirmsCandidates(t *testing.T) {
	rv := newFakeReviewer()
	rv.grant("team-a", "pods", "a")
	rv.grant("alice", "pods", "c")
	// "b" is a candidate (a binding exists) but the review denies it, e.g.
	// the bound role does not grant list pods.
	a, _ := newAuthz(rv, fakeCandidates{"alice": {"a", "b", "c", "a", ""}})
	s, err := a.Scope(ctx, user("alice", "team-a"), ViewNamespace)
	if err != nil {
		t.Fatal(err)
	}
	if s.All || !reflect.DeepEqual(nsList(s), []string{"a", "c"}) {
		t.Fatalf("scope %+v", s)
	}
	if n := rv.total.Load(); n != 4 { // cluster-wide + a, b, c (duplicates and "" dropped)
		t.Fatalf("%d reviews, want 4", n)
	}
	// Cached: no more reviews, and Allowed answers from the scope.
	if _, err := a.Scope(ctx, user("alice", "team-a"), ViewNamespace); err != nil {
		t.Fatal(err)
	}
	if ok, _ := a.Allowed(ctx, user("alice", "team-a"), ViewNamespace, "a"); !ok {
		t.Fatal("a not allowed")
	}
	if ok, _ := a.Allowed(ctx, user("alice", "team-a"), ViewNamespace, "b"); ok {
		t.Fatal("b allowed")
	}
	if n := rv.total.Load(); n != 4 {
		t.Fatalf("%d reviews after cached lookups, want 4", n)
	}
	// Not a namespaced capability: candidates are ignored.
	if s, _ := a.Scope(ctx, user("alice", "team-a"), ViewNodes); s.All || len(s.Namespaces) != 0 {
		t.Fatalf("nodes scope %+v", s)
	}
}

func TestAllowedNonCandidateNamespace(t *testing.T) {
	rv := newFakeReviewer()
	rv.grant("alice", "pods", "a")
	rv.grant("alice", "pods", "webhook-granted") // invisible to the RBAC index
	a, _ := newAuthz(rv, fakeCandidates{"alice": {"a"}})
	alice := user("alice")
	s, _ := a.Scope(ctx, alice, ViewNamespace)
	if s.Has("webhook-granted") {
		t.Fatal("scope includes a namespace that was never a candidate")
	}
	before := rv.total.Load()
	ok, err := a.Allowed(ctx, alice, ViewNamespace, "webhook-granted")
	if err != nil || !ok {
		t.Fatalf("Allowed = %v, %v", ok, err)
	}
	if d := rv.total.Load() - before; d != 1 {
		t.Fatalf("%d reviews for a direct visit, want 1", d)
	}
	a.Allowed(ctx, alice, ViewNamespace, "webhook-granted")
	if ok, _ := a.Allowed(ctx, alice, ViewNamespace, "other"); ok {
		t.Fatal("other allowed")
	}
	if d := rv.total.Load() - before; d != 2 {
		t.Fatalf("%d reviews, want 2 (one per distinct namespace)", d)
	}
}

func TestAllowedClusterScopedIgnoresNamespace(t *testing.T) {
	rv := newFakeReviewer()
	rv.grant("alice", "nodes", "kube-system") // a RoleBinding naming nodes grants nothing cluster-wide
	a, _ := newAuthz(rv, nil)
	if ok, _ := a.Allowed(ctx, user("alice"), ViewNodes, "kube-system"); ok {
		t.Fatal("namespaced grant allowed a cluster-scoped resource")
	}
	if rv.count("alice", "nodes", "") != 1 || rv.count("alice", "nodes", "kube-system") != 0 {
		t.Fatal("review not made cluster-wide")
	}
}

func TestUnrestrictedSkipsReviews(t *testing.T) {
	rv := newFakeReviewer()
	a, _ := newAuthz(rv, nil)
	id := Identity{User: TokenUser, Source: "token", Unrestricted: true}
	if s, _ := a.Scope(ctx, id, ViewNamespace); !s.All {
		t.Fatal("not all")
	}
	if ok, _ := a.Allowed(ctx, id, ViewNodes, ""); !ok {
		t.Fatal("not allowed")
	}
	caps := a.Capabilities(ctx, id)
	if len(caps) != 9 {
		t.Fatalf("caps %v", caps)
	}
	for k, v := range caps {
		if !v {
			t.Errorf("%s false", k)
		}
	}
	if rv.total.Load() != 0 {
		t.Fatal("reviews made for an unrestricted identity")
	}
}

func TestTTLAndDenyTTL(t *testing.T) {
	rv := newFakeReviewer()
	rv.grant("alice", "pods", "a")
	a, clk := newAuthz(rv, nil)
	a.DenyTTL = time.Minute
	alice := user("alice")
	check := func(ns string, want bool) {
		t.Helper()
		if ok, err := a.Allowed(ctx, alice, ViewNamespace, ns); err != nil || ok != want {
			t.Fatalf("Allowed(%s) = %v, %v", ns, ok, err)
		}
	}
	check("a", true)
	check("b", false)
	if rv.total.Load() != 2 {
		t.Fatalf("reviews %d", rv.total.Load())
	}
	clk.Advance(30 * time.Second)
	check("a", true)
	check("b", false)
	if rv.total.Load() != 2 {
		t.Fatalf("reviews %d after 30s, want cached", rv.total.Load())
	}
	clk.Advance(31 * time.Second) // 61s: the denial expired, the grant did not
	check("a", true)
	check("b", false)
	if rv.count("alice", "pods", "a") != 1 || rv.count("alice", "pods", "b") != 2 {
		t.Fatalf("a %d b %d", rv.count("alice", "pods", "a"), rv.count("alice", "pods", "b"))
	}
	clk.Advance(4*time.Minute + 1*time.Second) // 5m2s: the grant expired too
	check("a", true)
	if rv.count("alice", "pods", "a") != 2 {
		t.Fatalf("a reviewed %d times", rv.count("alice", "pods", "a"))
	}
}

func TestScopeExpiresWithShortestDecision(t *testing.T) {
	rv := newFakeReviewer()
	rv.grant("alice", "pods", "a")
	a, clk := newAuthz(rv, fakeCandidates{"alice": {"a"}})
	a.DenyTTL = time.Minute
	alice := user("alice")
	a.Scope(ctx, alice, ViewNamespace) // cluster-wide deny (1m) + a allowed (5m)
	clk.Advance(61 * time.Second)
	s, _ := a.Scope(ctx, alice, ViewNamespace)
	if !s.Has("a") {
		t.Fatal("lost a")
	}
	if rv.count("alice", "pods", "") != 2 || rv.count("alice", "pods", "a") != 1 {
		t.Fatalf("cluster %d a %d: want the cluster-wide denial re-checked and a still cached",
			rv.count("alice", "pods", ""), rv.count("alice", "pods", "a"))
	}
	// A grant revoked in the meantime disappears once its TTL passes.
	rv.revoke("alice", "pods", "a")
	clk.Advance(5 * time.Minute)
	if s, _ := a.Scope(ctx, alice, ViewNamespace); s.Has("a") {
		t.Fatal("revoked grant still in scope after TTL")
	}
}

func TestShareByGroups(t *testing.T) {
	rv := newFakeReviewer()
	rv.grant("team-a", "pods", "a")
	cands := fakeCandidates{"alice": {"a"}, "bob": {"a"}, "carol": {"a"}}
	a, _ := newAuthz(rv, cands)
	a.ShareByGroups = true
	a.Scope(ctx, user("alice", "team-a", "devs"), ViewNamespace)
	n := rv.total.Load()
	s, _ := a.Scope(ctx, Identity{User: "bob", Groups: []string{"devs", GroupAuthenticated, "team-a", "devs"}, Source: "proxy"}, ViewNamespace)
	if !s.Has("a") || rv.total.Load() != n {
		t.Fatalf("same group set not shared: %d -> %d reviews", n, rv.total.Load())
	}
	a.Scope(ctx, user("carol", "team-a"), ViewNamespace)
	if rv.total.Load() == n {
		t.Fatal("different group set shared")
	}

	// Per user (the default), the same groups do not share.
	rv2 := newFakeReviewer()
	rv2.grant("team-a", "pods", "a")
	b, _ := newAuthz(rv2, cands)
	b.Scope(ctx, user("alice", "team-a"), ViewNamespace)
	n = rv2.total.Load()
	b.Scope(ctx, user("bob", "team-a"), ViewNamespace)
	if rv2.total.Load() != 2*n {
		t.Fatalf("per-user cache shared: %d -> %d", n, rv2.total.Load())
	}
}

func TestSingleflight(t *testing.T) {
	rv := newFakeReviewer()
	rv.grant("alice", "pods", "a")
	rv.gate = make(chan struct{})
	rv.entered = make(chan struct{}, 1)
	obs := &countingObserver{reviews: map[string]int{}, cache: map[string]int{}}
	a, _ := newAuthz(rv, nil)
	a.Metrics = obs
	var wg sync.WaitGroup
	var allowedN atomic.Int64
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, err := a.Allowed(ctx, user("alice"), ViewNamespace, "a"); ok && err == nil {
				allowedN.Add(1)
			}
		}()
	}
	<-rv.entered
	time.Sleep(20 * time.Millisecond) // let the others pile up behind the first
	close(rv.gate)
	wg.Wait()
	if rv.total.Load() != 1 || allowedN.Load() != 100 {
		t.Fatalf("%d reviews, %d allowed; want 1 and 100", rv.total.Load(), allowedN.Load())
	}
	if obs.reviews["allowed"] != 1 || obs.cache["miss"] != 1 || obs.cache["coalesced"]+obs.cache["hit"] != 99 {
		t.Fatalf("observer %+v", obs)
	}

	// The same for Scope: 100 callers, one review per key.
	rv2 := newFakeReviewer()
	rv2.grant("alice", "pods", "a")
	rv2.delay = 5 * time.Millisecond
	b, _ := newAuthz(rv2, fakeCandidates{"alice": {"a", "b", "c"}})
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b.Scope(ctx, user("alice"), ViewNamespace)
		}()
	}
	wg.Wait()
	if rv2.total.Load() != 4 {
		t.Fatalf("%d reviews for 100 concurrent Scope calls, want 4", rv2.total.Load())
	}
}

func TestMaxParallel(t *testing.T) {
	rv := newFakeReviewer()
	rv.delay = 2 * time.Millisecond
	var cands []string
	for i := range 60 {
		ns := fmt.Sprintf("ns-%d", i)
		cands = append(cands, ns)
		rv.grant("alice", "pods", ns)
		rv.grant("bob", "pods", ns)
	}
	a, _ := newAuthz(rv, fakeCandidates{"alice": cands, "bob": cands})
	a.MaxParallel = 4
	var wg sync.WaitGroup
	for _, u := range []string{"alice", "bob"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := a.Scope(ctx, user(u), ViewNamespace)
			if err != nil || len(s.Namespaces) != 60 {
				t.Errorf("%s: %d namespaces, %v", u, len(s.Namespaces), err)
			}
		}()
	}
	wg.Wait()
	if m := rv.maxInflight.Load(); m > 4 || m < 2 {
		t.Fatalf("max in-flight reviews %d, want 2..4", m)
	}
}

func TestErrorsAreNotCached(t *testing.T) {
	rv := newFakeReviewer()
	rv.grant("alice", "pods", "a")
	a, _ := newAuthz(rv, fakeCandidates{"alice": {"a"}})
	rv.failNext.Store(1)
	if _, err := a.Allowed(ctx, user("alice"), ViewNamespace, "a"); err == nil {
		t.Fatal("no error")
	}
	if ok, err := a.Allowed(ctx, user("alice"), ViewNamespace, "a"); err != nil || !ok {
		t.Fatalf("retry: %v %v", ok, err)
	}
	// A failed candidate review fails the scope instead of silently shrinking it.
	rv.failNext.Store(1)
	if _, err := a.Scope(ctx, user("alice"), ViewNamespace); err == nil {
		t.Fatal("scope swallowed the review error")
	}
	if s, err := a.Scope(ctx, user("alice"), ViewNamespace); err != nil || !s.Has("a") {
		t.Fatalf("scope retry: %+v %v", s, err)
	}
	// No reviewer: fail closed.
	b := &SARAuthorizer{}
	if ok, err := b.Allowed(ctx, user("alice"), ViewNodes, ""); ok || err == nil {
		t.Fatal("allowed without a reviewer")
	}
}

func TestCallerCancellationDoesNotPoisonTheCache(t *testing.T) {
	rv := newFakeReviewer()
	rv.grant("alice", "pods", "a")
	rv.gate = make(chan struct{})
	rv.entered = make(chan struct{}, 1)
	a, _ := newAuthz(rv, nil)
	cctx, cancel := context.WithCancel(ctx)
	done := make(chan error)
	go func() {
		_, err := a.Allowed(cctx, user("alice"), ViewNamespace, "a")
		done <- err
	}()
	<-rv.entered
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
	close(rv.gate)
	// The detached review completes and is cached for the next caller.
	deadline := time.Now().Add(2 * time.Second)
	for a.cache.len() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if ok, err := a.Allowed(ctx, user("alice"), ViewNamespace, "a"); !ok || err != nil || rv.total.Load() != 1 {
		t.Fatalf("ok %v err %v reviews %d", ok, err, rv.total.Load())
	}
}

func TestCapabilities(t *testing.T) {
	rv := newFakeReviewer()
	rv.grant("viewers", "nodes", "")
	rv.grant("alice", "processes", "a")
	rv.grant("alice", "auditevents", "b") // not a candidate: the UI flag needs a candidate
	a, _ := newAuthz(rv, fakeCandidates{"alice": {"a"}})
	got := a.Capabilities(ctx, user("alice", "viewers"))
	want := map[string]bool{
		"nodes": true, "pvs": false, "storageClasses": false, "clusterRBAC": false, "clusterIssuers": false,
		"agents": false, "clusterAudit": false, "processes": true, "audit": false,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}

func TestDefaultTTLs(t *testing.T) {
	a := &SARAuthorizer{}
	for range 100 {
		if d := a.ttl(true); d > 5*time.Minute || d < 4*time.Minute+30*time.Second {
			t.Fatalf("allow TTL %v", d)
		}
		if d := a.ttl(false); d > 5*time.Minute || d < 4*time.Minute+30*time.Second {
			t.Fatalf("deny TTL %v", d)
		}
	}
}

func TestForgetClearsOnlyThatIdentity(t *testing.T) {
	rv := newFakeReviewer()
	rv.grant("alice", "pods", "a")
	rv.grant("bob", "pods", "a")
	a, _ := newAuthz(rv, fakeCandidates{"alice": {"a", "b"}, "bob": {"a", "b"}})
	alice, bob := user("alice"), user("bob")
	for _, id := range []Identity{alice, bob} {
		a.Scope(ctx, id, ViewNamespace)             // cluster deny, a allow, b deny, scope
		a.Allowed(ctx, id, ViewNodes, "")           // cluster deny
		a.Allowed(ctx, id, ViewNamespace, "direct") // namespace deny outside the candidates
	}
	entries := a.cache.len()
	reviews := rv.total.Load()

	a.Forget(alice)
	if n := a.cache.len(); n != entries/2 {
		t.Fatalf("%d entries after Forget, want %d (bob's)", n, entries/2)
	}
	// Bob is untouched: everything still cached.
	a.Scope(ctx, bob, ViewNamespace)
	a.Allowed(ctx, bob, ViewNodes, "")
	a.Allowed(ctx, bob, ViewNamespace, "direct")
	if rv.total.Load() != reviews {
		t.Fatalf("bob re-reviewed: %d -> %d", reviews, rv.total.Load())
	}
	// Alice's allows and denials are both gone.
	if ok, _ := a.Allowed(ctx, alice, ViewNamespace, "a"); !ok || rv.count("alice", "pods", "a") != 2 {
		t.Fatalf("allow not re-reviewed: %d", rv.count("alice", "pods", "a"))
	}
	if ok, _ := a.Allowed(ctx, alice, ViewNamespace, "b"); ok || rv.count("alice", "pods", "b") != 2 {
		t.Fatalf("denial not re-reviewed: %d", rv.count("alice", "pods", "b"))
	}
	a.Allowed(ctx, alice, ViewNodes, "")
	if rv.count("alice", "nodes", "") != 2 {
		t.Fatal("cluster-wide denial not re-reviewed")
	}
	// Unrestricted identities have nothing cached; Forget is a no-op.
	a.Forget(Identity{User: TokenUser, Source: "token", Unrestricted: true})
}

func TestForgetThenScopeReReviews(t *testing.T) {
	rv := newFakeReviewer()
	rv.grant("alice", "pods", "a")
	cands := fakeCandidates{"alice": {"a"}}
	a, _ := newAuthz(rv, cands)
	alice := user("alice")
	if s, _ := a.Scope(ctx, alice, ViewNamespace); !reflect.DeepEqual(nsList(s), []string{"a"}) {
		t.Fatalf("scope %v", nsList(s))
	}
	n := rv.total.Load() // cluster-wide + a
	// RBAC changes: a new binding in b. The cached scope does not know yet.
	rv.grant("alice", "pods", "b")
	cands["alice"] = []string{"a", "b"}
	a.Scope(ctx, alice, ViewNamespace)
	if rv.total.Load() != n {
		t.Fatal("cached scope re-reviewed before Forget")
	}
	a.Forget(alice)
	s, err := a.Scope(ctx, alice, ViewNamespace)
	if err != nil || !reflect.DeepEqual(nsList(s), []string{"a", "b"}) {
		t.Fatalf("scope after Forget %v %v", nsList(s), err)
	}
	if d := rv.total.Load() - n; d != 3 {
		t.Fatalf("%d reviews after Forget, want 3 (cluster-wide, a, b)", d)
	}

	// With ShareByGroups, Forget clears the group set's entries for everyone in it.
	rv2 := newFakeReviewer()
	rv2.grant("team", "pods", "a")
	b, _ := newAuthz(rv2, fakeCandidates{"carol": {"a"}, "dave": {"a"}})
	b.ShareByGroups = true
	b.Scope(ctx, user("carol", "team"), ViewNamespace)
	m := rv2.total.Load()
	b.Forget(user("carol", "team"))
	b.Scope(ctx, user("dave", "team"), ViewNamespace)
	if rv2.total.Load() == m {
		t.Fatal("group-set entries survived Forget")
	}
}

func TestForgetRacingSingleflight(t *testing.T) {
	for _, kind := range []string{"decision", "scope"} {
		t.Run(kind, func(t *testing.T) {
			rv := newFakeReviewer()
			release := make(chan struct{})
			held := make(chan struct{})
			rv.hold = func(n int64) {
				if n == 1 { // the first review has decided "denied" and is still in flight
					close(held)
					<-release
				}
			}
			a, _ := newAuthz(rv, fakeCandidates{"alice": {"a"}})
			alice := user("alice")
			lookup := func() bool {
				if kind == "scope" {
					// Granted cluster-wide below; the first review is the cluster-wide one.
					s, err := a.Scope(ctx, alice, ViewNamespace)
					return err == nil && s.All
				}
				ok, err := a.Allowed(ctx, alice, ViewNamespace, "a")
				return ok && err == nil
			}
			oldResult := make(chan bool)
			go func() { oldResult <- lookup() }()
			<-held

			// The grant arrives and the user asks for a recheck while the old
			// lookup is still in flight.
			rv.grant("alice", "pods", "")
			a.Forget(alice)
			if !lookup() {
				t.Fatal("lookup after Forget joined the stale flight or used its answer")
			}

			close(release)
			if <-oldResult {
				t.Fatal("old lookup should have returned its own (denied) answer")
			}
			// The stale denial must not have been written back over the new
			// grant, and the fresh answer stays cached.
			reviews := rv.total.Load()
			for range 3 {
				if !lookup() {
					t.Fatal("stale denial resurrected after the in-flight lookup finished")
				}
			}
			if rv.total.Load() != reviews {
				t.Fatalf("fresh answer not cached: %d -> %d reviews", reviews, rv.total.Load())
			}
		})
	}
}

func TestForgetMarksArePruned(t *testing.T) {
	rv := newFakeReviewer()
	a, clk := newAuthz(rv, nil)
	a.Forget(user("alice"))
	a.Forget(user("bob"))
	clk.Advance(2 * time.Hour)
	a.Forget(user("carol"))
	a.forgetMu.RLock()
	defer a.forgetMu.RUnlock()
	if len(a.forgotten) != 1 {
		t.Fatalf("%d forget marks kept", len(a.forgotten))
	}
}

func TestCacheIsBounded(t *testing.T) {
	rv := newFakeReviewer()
	a, _ := newAuthz(rv, nil)
	a.MaxEntries = 64
	for i := range 1000 {
		a.Allowed(ctx, user("alice"), ViewNamespace, fmt.Sprintf("ns-%d", i))
	}
	if n := a.cache.len(); n > 64 {
		t.Fatalf("%d entries, bound 64", n)
	}
}

// BenchmarkAuthorizer models 2,000 users over 300 namespaces, each holding
// list pods in 1-10 namespaces through bindings the RBAC index proposes,
// plus up to 3 candidates whose bound role does not grant it. Each
// iteration is one page view: Scope(ViewNamespace), Allowed on one of the
// user's namespaces, and the nine UI capability flags.
//
// Reported: reviews/identity-cold is the cost of a user's first page view;
// hit-rate is the share of cache lookups answered without a review once
// warm. The steady variants advance a fake clock so every user views a page
// every 10s for 10 minutes (TTLs expire as in production) and report
// reviews/identity/min and reviews/s, with the default 5m deny TTL and with
// a 1m one: denials (mostly the cluster-wide checks) dominate the rate.
func BenchmarkAuthorizer(b *testing.B) {
	const users, namespaces = 2000, 300
	type userData struct {
		id     Identity
		grants []string
	}
	setup := func() (*SARAuthorizer, *fakeReviewer, *fakeClock, *countingObserver, []userData) {
		rnd := rand.New(rand.NewPCG(1, 2))
		rv := newFakeReviewer()
		cands := podCandidates{}
		var us []userData
		for i := range users {
			name := fmt.Sprintf("user-%d@example.com", i)
			n := 1 + rnd.IntN(10)
			perm := rnd.Perm(namespaces)
			var grants, cs []string
			for _, j := range perm[:n] {
				ns := fmt.Sprintf("team-%d", j)
				grants = append(grants, ns)
				rv.grant(name, "pods", ns)
			}
			cs = append(cs, grants...)
			for _, j := range perm[n : n+rnd.IntN(4)] {
				cs = append(cs, fmt.Sprintf("team-%d", j))
			}
			cands[name] = cs
			us = append(us, userData{id: user(name, "org:all", fmt.Sprintf("dept-%d", i%40)), grants: grants})
		}
		a, clk := newAuthz(rv, cands)
		obs := &countingObserver{reviews: map[string]int{}, cache: map[string]int{}}
		a.Metrics = obs
		return a, rv, clk, obs, us
	}
	view := func(a *SARAuthorizer, u userData, k int) {
		if _, err := a.Scope(ctx, u.id, ViewNamespace); err != nil {
			b.Fatal(err)
		}
		if ok, _ := a.Allowed(ctx, u.id, ViewNamespace, u.grants[k%len(u.grants)]); !ok {
			b.Fatal("granted namespace denied")
		}
		a.Capabilities(ctx, u.id)
	}
	hitRate := func(o *countingObserver) float64 {
		o.mu.Lock()
		defer o.mu.Unlock()
		h, m := float64(o.cache["hit"]), float64(o.cache["miss"]+o.cache["coalesced"])
		return h / (h + m)
	}

	b.Run("warm", func(b *testing.B) {
		a, rv, _, obs, us := setup()
		for _, u := range us {
			view(a, u, 0)
		}
		cold := float64(rv.total.Load()) / users
		obs.cache = map[string]int{}
		before := rv.total.Load()
		b.ResetTimer()
		for i := range b.N {
			view(a, us[i%users], i)
		}
		b.StopTimer()
		b.ReportMetric(cold, "reviews/identity-cold")
		b.ReportMetric(hitRate(obs), "hit-rate")
		b.ReportMetric(float64(rv.total.Load()-before)/float64(b.N), "reviews/op")
	})

	steady := func(denyTTL time.Duration) func(b *testing.B) {
		return func(b *testing.B) {
			for range b.N {
				a, rv, clk, obs, us := setup()
				a.DenyTTL = denyTTL
				for _, u := range us { // cold start: everyone at once
					view(a, u, 0)
				}
				warm := rv.total.Load()
				obs.cache = map[string]int{}
				const minutes, every = 10, 10 * time.Second
				steps := int(minutes * time.Minute / every)
				for s := range steps {
					clk.Advance(every)
					for _, u := range us {
						view(a, u, s)
					}
				}
				b.ReportMetric(float64(rv.total.Load()-warm)/users/minutes, "reviews/identity/min")
				b.ReportMetric(float64(rv.total.Load()-warm)/(minutes*60), "reviews/s")
				b.ReportMetric(hitRate(obs), "hit-rate")
				b.ReportMetric(float64(a.cache.len()), "cache-entries")
			}
		}
	}
	b.Run("steady", steady(0)) // default deny TTL, 5m
	b.Run("steady-deny1m", steady(time.Minute))
}
