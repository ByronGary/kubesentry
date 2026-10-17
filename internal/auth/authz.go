package auth

import (
	"container/list"
	"context"
	"crypto/sha256"
	"fmt"
	"hash/fnv"
	"math/rand/v2"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Observer receives authorization events, for metrics. internal/metrics
// provides one (metrics.AuthzObserver).
type Observer interface {
	// ObserveReview is called once per SubjectAccessReview with "allowed",
	// "denied" or "error".
	ObserveReview(result string)
	// ObserveCache is called once per cache lookup with "hit", "miss" or
	// "coalesced" (a miss that joined a lookup already in flight).
	ObserveCache(result string)
}

// Defaults for SARAuthorizer's zero fields.
const (
	DefaultAuthzTTL           = 5 * time.Minute
	DefaultAuthzDenyTTL       = 5 * time.Minute
	DefaultAuthzMaxParallel   = 32
	DefaultAuthzMaxEntries    = 100_000
	DefaultAuthzReviewTimeout = 10 * time.Second
)

// SARAuthorizer answers Authorizer questions with SubjectAccessReviews and
// caches the answers.
//
// Scope first asks one cluster-wide review (namespace ""); if that allows,
// the scope is All. Otherwise, for a namespaced capability, Candidates
// proposes the namespaces where the identity's bindings might grant it and
// each candidate is confirmed by its own review, in parallel. Only confirmed
// namespaces are in the scope. Allowed answers one namespace from the cache
// or with a single review, so a namespace granted by something the RBAC
// index cannot see (a webhook authorizer such as EKS access policies) still
// opens when visited directly.
//
// Decisions are cached in a bounded LRU for TTL (allowed) or DenyTTL
// (denied), keyed by subject, capability and namespace; concurrent identical
// lookups share one review. Errors are never cached. Forget drops one
// identity's cached answers, e.g. when a user asks for a recheck after an
// RBAC change. Use a pointer; the zero value of the unexported state is
// initialised on first use.
type SARAuthorizer struct {
	Reviewer Reviewer
	// Candidates proposes namespaces to confirm (detectors.RBACIndex). Nil
	// limits Scope to cluster-wide grants; Allowed still works per namespace.
	Candidates Candidates

	TTL           time.Duration // allowed decisions; default 5m
	DenyTTL       time.Duration // denied decisions; default 5m
	MaxParallel   int           // reviews in flight at once, across all callers; default 32
	MaxEntries    int           // cache bound; default 100,000
	ReviewTimeout time.Duration // per review, including the wait for a slot; default 10s
	// ShareByGroups caches by the identity's sorted group set instead of per
	// user, so everyone in the same groups shares one set of reviews. Correct
	// only when access is granted to groups, never to individual users (no
	// user-subject bindings, no authorizer that decides by user name): the
	// first member's answer is served to the others.
	ShareByGroups bool
	Now           func() time.Time // default time.Now
	Metrics       Observer         // optional

	initOnce sync.Once
	cache    *lruCache
	flights  flightGroup
	sem      chan struct{}

	// epoch orders lookups against Forget: a lookup notes the epoch when it
	// starts, and its result is stored only if its subject has not been
	// forgotten since. Stores hold forgetMu for reading, Forget for writing.
	epoch     atomic.Uint64
	forgetMu  sync.RWMutex
	forgotten map[string]forgetMark // subject -> last Forget
}

type forgetMark struct {
	epoch uint64
	at    time.Time
}

// forgetRetention is how long a Forget is remembered to fence off lookups
// that started before it. Every review is bounded by ReviewTimeout, so no
// lookup runs anywhere near this long.
const forgetRetention = time.Hour

func (a *SARAuthorizer) init() {
	a.initOnce.Do(func() {
		n := a.MaxEntries
		if n <= 0 {
			n = DefaultAuthzMaxEntries
		}
		a.cache = newLRU(n)
		p := a.MaxParallel
		if p <= 0 {
			p = DefaultAuthzMaxParallel
		}
		a.sem = make(chan struct{}, p)
	})
}

func (a *SARAuthorizer) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// ttl returns the cache lifetime of a decision, shortened by up to 10% at
// random so that entries created together (a cold start) do not all expire
// together. It never exceeds the configured TTL.
func (a *SARAuthorizer) ttl(allowed bool) time.Duration {
	d := a.TTL
	if d <= 0 {
		d = DefaultAuthzTTL
	}
	if !allowed {
		d = a.DenyTTL
		if d <= 0 {
			d = DefaultAuthzDenyTTL
		}
	}
	return d - time.Duration(rand.Float64()*0.1*float64(d))
}

func (a *SARAuthorizer) observeCache(result string) {
	if a.Metrics != nil {
		a.Metrics.ObserveCache(result)
	}
}

func (a *SARAuthorizer) observeReview(result string) {
	if a.Metrics != nil {
		a.Metrics.ObserveReview(result)
	}
}

// subject is the cache key part for an identity: a digest, so identities
// with hundreds of groups do not make every cache key kilobytes long.
func (a *SARAuthorizer) subject(id Identity) string {
	h := sha256.New()
	if a.ShareByGroups && !a.hasUserBindings(id.User) {
		gs := append([]string(nil), id.Groups...)
		sort.Strings(gs)
		h.Write([]byte("groups"))
		prev := ""
		for i, g := range gs {
			if i > 0 && g == prev {
				continue
			}
			prev = g
			h.Write([]byte{0})
			h.Write([]byte(g))
		}
	} else {
		h.Write([]byte("user\x00" + id.Source + "\x00" + id.User))
		for _, g := range id.Groups {
			h.Write([]byte{0})
			h.Write([]byte(g))
		}
	}
	return string(h.Sum(nil)[:16])
}

// hasUserBindings reports whether any binding names the user as a subject,
// so that ShareByGroups must not share their answers with their groups.
// Candidates that cannot tell (no UserBindings) count as no: ShareByGroups
// then rests on its documented assumption that only groups are granted.
func (a *SARAuthorizer) hasUserBindings(user string) bool {
	if ub, ok := a.Candidates.(UserBindings); ok {
		return ub.HasUserBindings(user)
	}
	return false
}

// candidatesReady reports whether Candidates can propose namespaces yet. A
// scope computed while they cannot is too narrow, so it is used but not
// cached.
func (a *SARAuthorizer) candidatesReady() bool {
	if r, ok := a.Candidates.(CandidatesReadiness); ok {
		return r.Ready()
	}
	return true
}

// capKey names the whole capability, Subresource and Namespaced included:
// ViewAudit and ViewClusterAudit share verb, group and resource, and a
// namespaced scope must never answer for the cluster-wide capability (or the
// other way); likewise get pods never answers for get pods/log.
func capKey(c Capability) string {
	ns := "cluster"
	if c.Namespaced {
		ns = "namespaced"
	}
	return c.Verb + "/" + c.Group + "/" + c.Resource + "/" + c.Subresource + "/" + ns
}

func decisionKey(subj string, c Capability, ns string) string {
	if ns == "" {
		ns = "*"
	}
	return "d\x00" + subj + "\x00" + capKey(c) + "\x00" + ns
}

func scopeKey(subj string, c Capability) string { return "s\x00" + subj + "\x00" + capKey(c) }

// Scope implements Authorizer. The returned Namespaces map is shared with
// the cache and must not be modified.
func (a *SARAuthorizer) Scope(ctx context.Context, id Identity, c Capability) (Scope, error) {
	if id.Unrestricted {
		return Scope{All: true}, nil
	}
	a.init()
	subj := a.subject(id)
	key := scopeKey(subj, c)
	if v, _, ok := a.cache.get(key, a.now()); ok {
		a.observeCache("hit")
		return v.(Scope), nil
	}
	v, coalesced, err := a.flights.do(ctx, key, func(ctx context.Context) (any, error) {
		start := a.epoch.Load()
		if v, _, ok := a.cache.get(key, a.now()); ok {
			return v, nil
		}
		return a.computeScope(ctx, subj, key, id, c, start)
	})
	a.observeMiss(coalesced)
	if err != nil {
		return Scope{}, err
	}
	return v.(Scope), nil
}

func (a *SARAuthorizer) observeMiss(coalesced bool) {
	if coalesced {
		a.observeCache("coalesced")
	} else {
		a.observeCache("miss")
	}
}

// computeScope builds a scope from decisions. start is the epoch the lookup
// began in (see store).
func (a *SARAuthorizer) computeScope(ctx context.Context, subj, key string, id Identity, c Capability, start uint64) (Scope, error) {
	// Asked before the candidates are read: if they become ready meanwhile,
	// this scope may still lack them.
	ready := !c.Namespaced || a.Candidates == nil || a.candidatesReady()
	all, exp, err := a.decide(ctx, subj, id, c, "")
	if err != nil {
		return Scope{}, err
	}
	if all {
		s := Scope{All: true}
		a.store(subj, key, s, exp, start)
		return s, nil
	}
	s := Scope{Namespaces: map[string]bool{}}
	var cands []string
	if c.Namespaced && a.Candidates != nil {
		seen := map[string]bool{"": true}
		for _, ns := range a.Candidates.Namespaces(id.User, id.Groups, c) {
			if !seen[ns] {
				seen[ns] = true
				cands = append(cands, ns)
			}
		}
	}
	if len(cands) > 0 {
		type result struct {
			ok  bool
			exp time.Time
			err error
		}
		results := make([]result, len(cands))
		workers := min(cap(a.sem), len(cands))
		next := make(chan int)
		var wg sync.WaitGroup
		for range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range next {
					ok, exp, err := a.decide(ctx, subj, id, c, cands[i])
					results[i] = result{ok, exp, err}
				}
			}()
		}
		for i := range cands {
			next <- i
		}
		close(next)
		wg.Wait()
		for i, r := range results {
			if r.err != nil {
				return Scope{}, fmt.Errorf("review %s in %s: %w", capKey(c), cands[i], r.err)
			}
			if r.ok {
				s.Namespaces[cands[i]] = true
			}
			if r.exp.Before(exp) {
				exp = r.exp
			}
		}
	}
	// The scope lives no longer than the shortest-lived decision it is made
	// of, so a revoked grant or a new one shows up within the decision TTLs.
	// Without candidates (no RBAC index yet) it is not cached at all: the
	// decisions it confirmed are, and the next lookup proposes the rest.
	if ready {
		a.store(subj, key, s, exp, start)
	}
	return s, nil
}

// Allowed implements Authorizer. For a cluster-scoped capability the
// namespace is ignored.
func (a *SARAuthorizer) Allowed(ctx context.Context, id Identity, c Capability, namespace string) (bool, error) {
	if id.Unrestricted {
		return true, nil
	}
	a.init()
	if !c.Namespaced {
		namespace = ""
	}
	subj := a.subject(id)
	now := a.now()
	// A cached scope that includes the namespace answers without a review.
	// One that does not include it proves nothing: something other than the
	// RBAC index (a webhook authorizer) may grant it.
	if v, _, ok := a.cache.get(scopeKey(subj, c), now); ok && v.(Scope).Has(namespace) {
		return true, nil
	}
	if namespace != "" {
		if v, _, ok := a.cache.get(decisionKey(subj, c, ""), now); ok && v.(bool) {
			return true, nil
		}
	}
	ok, _, err := a.decide(ctx, subj, id, c, namespace)
	return ok, err
}

type decision struct {
	ok  bool
	exp time.Time
}

// decide returns one cached or reviewed decision and when it expires.
func (a *SARAuthorizer) decide(ctx context.Context, subj string, id Identity, c Capability, ns string) (bool, time.Time, error) {
	key := decisionKey(subj, c, ns)
	if v, exp, ok := a.cache.get(key, a.now()); ok {
		a.observeCache("hit")
		return v.(bool), exp, nil
	}
	v, coalesced, err := a.flights.do(ctx, key, func(ctx context.Context) (any, error) {
		start := a.epoch.Load()
		// A flight that finished between our miss and now has filled the cache.
		if v, exp, ok := a.cache.get(key, a.now()); ok {
			return decision{v.(bool), exp}, nil
		}
		ok, err := a.review(ctx, id, c, ns)
		if err != nil {
			return nil, err
		}
		exp := a.now().Add(a.ttl(ok))
		a.store(subj, key, ok, exp, start)
		return decision{ok, exp}, nil
	})
	a.observeMiss(coalesced)
	if err != nil {
		return false, time.Time{}, err
	}
	d := v.(decision)
	return d.ok, d.exp, nil
}

// store caches a lookup result unless the subject was forgotten after the
// lookup started: a review begun before Forget may reflect the old RBAC
// state and must not come back as a cached answer.
func (a *SARAuthorizer) store(subj, key string, val any, exp time.Time, start uint64) {
	a.forgetMu.RLock()
	defer a.forgetMu.RUnlock()
	if f, ok := a.forgotten[subj]; ok && f.epoch > start {
		return
	}
	a.cache.set(key, val, exp)
}

// Forget drops every cached decision and scope for the identity's subject
// (with ShareByGroups, for everyone with the same groups), so the next
// lookups ask the API server again. Lookups already in flight finish for
// the callers waiting on them but are not cached; later callers start new
// ones. It scans the cache, so callers should rate-limit it.
func (a *SARAuthorizer) Forget(id Identity) {
	if id.Unrestricted {
		return
	}
	a.init()
	subj := a.subject(id)
	prefixes := [2]string{"d\x00" + subj + "\x00", "s\x00" + subj + "\x00"}
	match := func(key string) bool {
		return strings.HasPrefix(key, prefixes[0]) || strings.HasPrefix(key, prefixes[1])
	}
	now := a.now()
	a.forgetMu.Lock()
	defer a.forgetMu.Unlock()
	// Under the write lock no lookup can store, so after the scan the cache
	// holds nothing for subj, and the epoch bump fences off every lookup
	// that started before it.
	a.cache.deleteFunc(match)
	a.flights.forget(match)
	if a.forgotten == nil {
		a.forgotten = map[string]forgetMark{}
	}
	for s, f := range a.forgotten {
		if now.Sub(f.at) > forgetRetention {
			delete(a.forgotten, s)
		}
	}
	a.forgotten[subj] = forgetMark{epoch: a.epoch.Add(1), at: now}
}

func (a *SARAuthorizer) review(ctx context.Context, id Identity, c Capability, ns string) (bool, error) {
	if a.Reviewer == nil {
		return false, fmt.Errorf("no SubjectAccessReview client configured")
	}
	t := a.ReviewTimeout
	if t <= 0 {
		t = DefaultAuthzReviewTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, t)
	defer cancel()
	select {
	case a.sem <- struct{}{}:
	case <-ctx.Done():
		a.observeReview("error")
		return false, ctx.Err()
	}
	defer func() { <-a.sem }()
	ok, err := a.Reviewer.Review(ctx, id.User, id.Groups, c.Verb, c.Group, c.Resource, c.Subresource, ns)
	switch {
	case err != nil:
		a.observeReview("error")
	case ok:
		a.observeReview("allowed")
	default:
		a.observeReview("denied")
	}
	return ok, err
}

// Capabilities returns the flags the UI needs (web/src/types.ts Capability).
func (a *SARAuthorizer) Capabilities(ctx context.Context, id Identity) map[string]bool {
	return Capabilities(ctx, a, id)
}

// uiCapabilities maps the UI's capability names to what they check. The
// namespaced ones are true when held in at least one namespace.
var uiCapabilities = []struct {
	name string
	cap  Capability
}{
	{"nodes", ViewNodes},
	{"pvs", ViewPVs},
	{"storageClasses", ViewStorageClass},
	{"clusterRBAC", ViewClusterRBAC},
	{"clusterIssuers", ViewClusterIssuer},
	{"agents", ViewAgents},
	{"clusterAudit", ViewClusterAudit},
	{"processes", ViewProcesses},
	{"audit", ViewAudit},
	{"podLogs", ViewPodLogs},
	{"cloudtrail", ViewCloudTrail},
	{"alertsUpdate", UpdateAlerts},
	{"investigate", InvestigateIncidents},
}

// Capabilities asks a for every capability the UI gates on and returns the
// flags keyed like web/src/types.ts Capability. A capability whose check
// fails is reported as not held.
func Capabilities(ctx context.Context, a Authorizer, id Identity) map[string]bool {
	out := make(map[string]bool, len(uiCapabilities))
	if id.Unrestricted {
		for _, u := range uiCapabilities {
			out[u.name] = true
		}
		return out
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, u := range uiCapabilities {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var held bool
			if u.cap.Namespaced {
				s, err := a.Scope(ctx, id, u.cap)
				held = err == nil && (s.All || len(s.Namespaces) > 0)
			} else {
				ok, err := a.Allowed(ctx, id, u.cap, "")
				held = err == nil && ok
			}
			mu.Lock()
			out[u.name] = held
			mu.Unlock()
		}()
	}
	wg.Wait()
	return out
}

// flightGroup runs one call per key at a time; callers that arrive while it
// runs wait for its result. The call runs detached from the callers'
// cancellation (it may serve many of them); each caller stops waiting when
// its own context ends.
type flightGroup struct {
	mu sync.Mutex
	m  map[string]*flight
}

type flight struct {
	done chan struct{}
	val  any
	err  error
}

func (g *flightGroup) do(ctx context.Context, key string, fn func(context.Context) (any, error)) (val any, coalesced bool, err error) {
	g.mu.Lock()
	if g.m == nil {
		g.m = map[string]*flight{}
	}
	f, coalesced := g.m[key]
	if !coalesced {
		f = &flight{done: make(chan struct{})}
		g.m[key] = f
		go func() {
			defer func() {
				if p := recover(); p != nil {
					f.err = fmt.Errorf("authorization lookup panicked: %v", p)
				}
				g.mu.Lock()
				if g.m[key] == f { // Forget may have replaced it
					delete(g.m, key)
				}
				g.mu.Unlock()
				close(f.done)
			}()
			f.val, f.err = fn(context.WithoutCancel(ctx))
		}()
	}
	g.mu.Unlock()
	select {
	case <-f.done:
		return f.val, coalesced, f.err
	case <-ctx.Done():
		return nil, coalesced, ctx.Err()
	}
}

const lruShards = 16

// lruCache is a sharded, size-bounded LRU with per-entry expiry.
type lruCache struct {
	shards [lruShards]lruShard
}

type lruShard struct {
	mu  sync.Mutex
	max int
	ll  list.List
	m   map[string]*list.Element
}

type lruEntry struct {
	key string
	val any
	exp time.Time
}

func newLRU(maxEntries int) *lruCache {
	c := &lruCache{}
	per := max(1, (maxEntries+lruShards-1)/lruShards)
	for i := range c.shards {
		c.shards[i].max = per
		c.shards[i].m = map[string]*list.Element{}
	}
	return c
}

func (c *lruCache) shard(key string) *lruShard {
	h := fnv.New32a()
	h.Write([]byte(key))
	return &c.shards[h.Sum32()%lruShards]
}

func (c *lruCache) get(key string, now time.Time) (any, time.Time, bool) {
	s := c.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	el, ok := s.m[key]
	if !ok {
		return nil, time.Time{}, false
	}
	e := el.Value.(*lruEntry)
	if !now.Before(e.exp) {
		s.ll.Remove(el)
		delete(s.m, key)
		return nil, time.Time{}, false
	}
	s.ll.MoveToFront(el)
	return e.val, e.exp, true
}

func (c *lruCache) set(key string, val any, exp time.Time) {
	s := c.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	if el, ok := s.m[key]; ok {
		e := el.Value.(*lruEntry)
		e.val, e.exp = val, exp
		s.ll.MoveToFront(el)
		return
	}
	s.m[key] = s.ll.PushFront(&lruEntry{key: key, val: val, exp: exp})
	for s.ll.Len() > s.max {
		old := s.ll.Back()
		s.ll.Remove(old)
		delete(s.m, old.Value.(*lruEntry).key)
	}
}

// forget detaches the flights whose key matches: callers already waiting
// keep waiting for them, new callers start fresh ones.
func (g *flightGroup) forget(match func(key string) bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for k := range g.m {
		if match(k) {
			delete(g.m, k)
		}
	}
}

// deleteFunc removes every entry whose key matches.
func (c *lruCache) deleteFunc(match func(key string) bool) {
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		for k, el := range s.m {
			if match(k) {
				s.ll.Remove(el)
				delete(s.m, k)
			}
		}
		s.mu.Unlock()
	}
}

func (c *lruCache) len() int {
	n := 0
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		n += s.ll.Len()
		s.mu.Unlock()
	}
	return n
}
