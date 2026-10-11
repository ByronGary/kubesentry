// Package audittest generates random audit events and queries, and holds the
// naive reference implementation every audit.Store is checked against. The
// memory store's property test and the Postgres parity test share it.
package audittest

import (
	"fmt"
	"math/rand"
	"sort"
	"time"

	"github.com/ByronGary/kubesentry/internal/audit"
)

// Base is the reference time random events are spread after.
var Base = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

var (
	Users      = []string{"alice", "bob", "carol@corp.example", "system:kube-scheduler", "system:serviceaccount:ci:deployer", "system:serviceaccount:prod:app", "eks:addon-manager", "system:anonymous", "", "zoë"}
	Namespaces = []string{"", "prod", "staging", "ci", "kube-system", "team-a"}
	Names      = []string{"", "web-0", "web-1", "db", "checkout-api"}
	Verbs      = []string{"get", "list", "watch", "create", "update", "patch", "delete", "deletecollection", "impersonate"}
	Stages     = []string{"ResponseStarted", "ResponseComplete", "ResponseComplete", "Panic", ""}
	Tags       = []string{audit.TagExec, audit.TagPortForward, audit.TagDebug, audit.TagSecretAccess, audit.TagSecretChange,
		audit.TagRBACChange, audit.TagDelete, audit.TagImpersonate, audit.TagTokenRequest, audit.TagDenied, audit.TagAnonymous, "none"}
	resources = []struct{ group, resource, sub string }{
		{"", "pods", ""}, {"", "pods", "exec"}, {"", "pods", "attach"}, {"", "pods", "portforward"},
		{"", "pods", "ephemeralcontainers"}, {"", "secrets", ""}, {"apps", "deployments", ""},
		{"rbac.authorization.k8s.io", "clusterrolebindings", ""}, {"rbac.authorization.k8s.io", "roles", ""},
		{"", "serviceaccounts", "token"}, {"", "configmaps", ""}, {"", "nodes", ""}, {"example.com", "secrets", ""},
	}
	Resources = []string{"pods", "secrets", "deployments", "clusterrolebindings", "roles", "serviceaccounts", "configmaps", "nodes", "widgets"}
	statuses  = []int{200, 200, 200, 201, 101, 403, 401, 404, 500}
)

// Events returns n random events spread over about span after Base, in a
// random arrival order that is mostly but not entirely chronological. Some
// share an AuditID and time (stages of one request, with ranks in any
// order), some share only the AuditID, many share a time.
func Events(rng *rand.Rand, n int, span time.Duration) []audit.Event {
	type rec struct {
		t time.Time
		e audit.Event
	}
	var seen []rec
	out := make([]audit.Event, 0, n)
	for i := 0; i < n; i++ {
		var t time.Time
		switch r := rng.Intn(10); {
		case r < 6: // roughly chronological
			t = Base.Add(time.Duration(float64(span) * float64(i) / float64(n))).Add(time.Duration(rng.Intn(5000)) * time.Microsecond)
		case r < 8: // late arrival
			t = Base.Add(time.Duration(rng.Int63n(int64(span) + 1))).Truncate(time.Microsecond)
		default: // on a coarse grid, so times collide
			t = Base.Add(time.Duration(rng.Intn(20)) * time.Second)
		}
		if t.Nanosecond()%1000 == 0 && rng.Intn(4) == 0 {
			t = t.Add(time.Duration(rng.Intn(1000))) // sub-microsecond noise the stores must drop alike
		}
		e := randomEvent(rng, t, i)
		if len(seen) > 0 && rng.Intn(5) == 0 {
			prev := seen[rng.Intn(len(seen))]
			switch rng.Intn(3) {
			case 0: // another stage of the same request: same id and time, possibly new status and tags
				e = prev.e
				e.Stage = Stages[rng.Intn(len(Stages))]
				e.StatusCode = statuses[rng.Intn(len(statuses))]
				e.Tags = audit.Classify(e)
			case 1: // exact duplicate (replayed delivery)
				e = prev.e
			default: // id reused at another time: a distinct record
				e.AuditID = prev.e.AuditID
			}
		}
		if rng.Intn(50) == 0 {
			e.AuditID = "" // the stores derive one from the content
		}
		seen = append(seen, rec{t, e})
		out = append(out, e)
	}
	return out
}

func randomEvent(rng *rand.Rand, t time.Time, i int) audit.Event {
	r := resources[rng.Intn(len(resources))]
	user := Users[rng.Intn(len(Users))]
	prefixes := audit.DefaultSystemPrefixes
	if rng.Intn(2) == 0 {
		prefixes = []string{"system:", "eks:"}
	}
	e := audit.Event{
		AuditID:     fmt.Sprintf("%08x-%04d", rng.Uint32()%4096, i),
		Time:        t,
		Stage:       Stages[rng.Intn(len(Stages))],
		Verb:        Verbs[rng.Intn(len(Verbs))],
		Username:    user,
		ActorKind:   audit.ClassifyActor(user, prefixes),
		APIGroup:    r.group,
		Resource:    r.resource,
		Subresource: r.sub,
		Namespace:   Namespaces[rng.Intn(len(Namespaces))],
		Name:        Names[rng.Intn(len(Names))],
		StatusCode:  statuses[rng.Intn(len(statuses))],
		UserAgent:   []string{"kubectl/v1.36.0", "", "argocd/2.13", "Mozilla/5.0 (ünïcode)"}[rng.Intn(4)],
	}
	if rng.Intn(3) == 0 {
		e.Groups = []string{"system:authenticated", "team-" + string(rune('a'+rng.Intn(3)))}
	}
	if rng.Intn(2) == 0 {
		e.SourceIPs = []string{fmt.Sprintf("10.0.%d.%d", rng.Intn(4), rng.Intn(255))}
	} else if rng.Intn(4) == 0 {
		e.SourceIPs = []string{}
	}
	if rng.Intn(10) == 0 {
		e.ImpersonatedUser = "system:serviceaccount:data:etl"
	}
	if rng.Intn(8) == 0 {
		e.ARN = "arn:aws:iam::111122223333:role/Admin"
		e.SessionName = e.Username
	}
	switch rng.Intn(5) {
	case 0:
		e.Decision = "forbid"
	case 1, 2:
		e.Decision = "allow"
	}
	if e.Subresource == "exec" {
		e.RequestURI = fmt.Sprintf("/api/v1/namespaces/%s/pods/%s/exec?command=sh&command=-c&command=echo+hi&container=c", e.Namespace, e.Name)
	} else {
		e.RequestURI = fmt.Sprintf("/apis/%s/%s/%s", e.APIGroup, e.Resource, e.Name)
	}
	e.Tags = audit.Classify(e)
	if rng.Intn(40) == 0 {
		e.Tags = append(e.Tags, "custom")
	}
	return e
}

// Busy returns n events shaped like a busy cluster, one every step from start
// (with up to 4s of jitter, so arrival is not quite chronological): mostly
// node and service-account reads, 15% of traffic from 500 people, 300 team
// namespaces, a few denials. AuditIDs are unique.
func Busy(rng *rand.Rand, n int, start time.Time, step time.Duration) []audit.Event {
	verbs := []string{"get", "list", "watch", "get", "list", "watch", "update", "patch", "create", "delete"}
	resources := []string{"pods", "configmaps", "secrets", "deployments", "leases"}
	out := make([]audit.Event, n)
	for i := range out {
		var user string
		switch r := rng.Intn(100); {
		case r < 60:
			user = fmt.Sprintf("system:node:ip-10-0-%d-%d", rng.Intn(4), rng.Intn(250))
		case r < 85:
			user = fmt.Sprintf("system:serviceaccount:team-%d:sa", rng.Intn(300))
		default:
			user = fmt.Sprintf("user-%d@corp.example", rng.Intn(500))
		}
		e := audit.Event{
			AuditID:    fmt.Sprintf("%016x-%x", rng.Uint64(), i),
			Time:       start.Add(time.Duration(i) * step).Add(time.Duration(rng.Intn(4000)) * time.Millisecond),
			Stage:      "ResponseComplete",
			Verb:       verbs[rng.Intn(len(verbs))],
			Username:   user,
			ActorKind:  audit.ClassifyActor(user, audit.DefaultSystemPrefixes),
			Groups:     []string{"system:authenticated"},
			SourceIPs:  []string{fmt.Sprintf("10.0.%d.%d", rng.Intn(4), rng.Intn(250))},
			UserAgent:  "kubectl/v1.36.0 (linux/amd64) kubernetes/abcdef",
			Resource:   resources[rng.Intn(len(resources))],
			Namespace:  fmt.Sprintf("team-%d", rng.Intn(300)),
			Name:       fmt.Sprintf("obj-%d", rng.Intn(50)),
			StatusCode: []int{200, 200, 200, 200, 201, 403}[rng.Intn(6)],
		}
		e.RequestURI = "/api/v1/namespaces/" + e.Namespace + "/" + e.Resource + "/" + e.Name
		e.Tags = audit.Classify(e)
		out[i] = e
	}
	return out
}

// NamedQuery is one benchmark case.
type NamedQuery struct {
	Name    string
	Q       audit.Query
	Summary bool // benchmark Summarize instead of Query
}

// BenchQueries are the dashboard's typical queries over Busy events ending at
// end; deep is a cursor some thousands of events back.
func BenchQueries(end time.Time, deep audit.Cursor) []NamedQuery {
	all := map[string]bool{"user": true, "serviceaccount": true, "system": true}
	scope := map[string]bool{}
	for i := 0; i < 20; i++ {
		scope[fmt.Sprintf("team-%d", i*7)] = true
	}
	day := end.Add(-24 * time.Hour)
	return []NamedQuery{
		{Name: "default-24h-100", Q: audit.Query{Limit: 100, Since: day}},
		{Name: "all-reads-100", Q: audit.Query{Limit: 100, IncludeReads: true, Actors: all}},
		{Name: "user-24h-100", Q: audit.Query{Limit: 100, Since: day, User: "user-7@corp.example", IncludeReads: true}},
		{Name: "tag-denied-100", Q: audit.Query{Limit: 100, Tag: audit.TagDenied}},
		{Name: "object-50", Q: audit.Query{Limit: 50, Since: end.Add(-6 * time.Hour), Namespace: "team-3", Resource: "pods", Name: "obj-1", IncludeReads: true, Actors: all}},
		{Name: "scope-20ns-100", Q: audit.Query{Limit: 100, Since: day, Namespaces: scope}},
		{Name: "page-after-5000", Q: audit.Query{Limit: 100, Before: deep}},
		{Name: "since-1h-unlimited", Q: audit.Query{Since: end.Add(-time.Hour)}},
		{Name: "summary-24h", Q: audit.Query{Since: day, IncludeReads: true, Actors: map[string]bool{"user": true, "serviceaccount": true}}, Summary: true},
	}
}

// Query returns a random query over events made by Events.
func Query(rng *rand.Rand, span time.Duration) audit.Query {
	var q audit.Query
	pick := func(p int) bool { return rng.Intn(p) == 0 }
	if pick(2) {
		q.Since = Base.Add(time.Duration(rng.Int63n(int64(span) + 1)))
	}
	if pick(4) {
		q.User = Users[rng.Intn(len(Users))]
	}
	if pick(4) {
		q.Namespace = Namespaces[rng.Intn(len(Namespaces))]
	}
	if pick(5) {
		q.Resource = Resources[rng.Intn(len(Resources))]
	}
	if pick(5) {
		q.Name = Names[rng.Intn(len(Names))]
	}
	if pick(6) {
		q.Verb = Verbs[rng.Intn(len(Verbs))]
	}
	if pick(4) {
		q.Tag = Tags[rng.Intn(len(Tags))]
	}
	if pick(3) {
		q.Actors = map[string]bool{}
		for _, k := range []string{"user", "serviceaccount", "system"} {
			if pick(2) {
				q.Actors[k] = true
			} else if pick(4) {
				q.Actors[k] = false
			}
		}
	}
	q.IncludeReads = pick(2)
	if pick(2) {
		q.Limit = 1 + rng.Intn(40)
	}
	if pick(3) {
		q.Namespaces = map[string]bool{}
		for _, ns := range Namespaces {
			if pick(2) {
				q.Namespaces[ns] = true
			}
		}
		q.ClusterScoped = pick(2)
	}
	if pick(5) {
		q.Before = audit.Cursor{Time: Base.Add(time.Duration(rng.Int63n(int64(span) + 1)))}
		if pick(2) {
			q.Before.AuditID = fmt.Sprintf("%08x", rng.Uint32()%4096)
		}
	}
	return q
}

// Records applies the store semantics to a sequence of added events: each is
// normalized, and records are keyed by (AuditID, Time), where a later add of
// an equal or higher stage rank replaces the record.
func Records(added []audit.Event) []audit.Event {
	type key struct {
		id string
		t  int64
	}
	idx := map[key]int{}
	var out []audit.Event
	for _, e := range added {
		e = audit.NormalizeForStore(e)
		k := key{e.AuditID, e.Time.UnixNano()}
		if i, ok := idx[k]; ok {
			if audit.StageRank(e.Stage) >= audit.StageRank(out[i].Stage) {
				out[i] = e
			}
			continue
		}
		idx[k] = len(out)
		out = append(out, e)
	}
	return out
}

// Naive answers q over records (from Records) by filtering and sorting.
func Naive(records []audit.Event, q audit.Query) []audit.Event {
	out := []audit.Event{}
	for i := range records {
		if q.Matches(&records[i]) {
			out = append(out, records[i])
		}
	}
	SortNewestFirst(out)
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out
}

// NaiveSummary summarizes the records matching q (Limit ignored).
func NaiveSummary(records []audit.Event, q audit.Query) audit.Summary {
	q.Limit = 0
	return audit.Summarize(Naive(records, q))
}

// SortNewestFirst sorts by time, then AuditID, both descending.
func SortNewestFirst(events []audit.Event) {
	sort.Slice(events, func(i, j int) bool {
		a, b := events[i], events[j]
		if !a.Time.Equal(b.Time) {
			return a.Time.After(b.Time)
		}
		return a.AuditID > b.AuditID
	})
}

// Describe renders a query compactly for failure messages.
func Describe(q audit.Query) string {
	s := fmt.Sprintf("%+v", q)
	if len(s) > 600 {
		s = s[:600] + "..."
	}
	return s
}
