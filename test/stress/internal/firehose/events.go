// Package firehose posts synthetic Kubernetes audit events to kubesentry's
// webhook at a fixed rate and then measures audit query latency.
package firehose

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/ByronGary/kubesentry/test/stress/internal/plan"
)

// Event is the audit.k8s.io/v1 Event wire format (Metadata level: no bodies).
type Event struct {
	Kind                     string            `json:"kind"`
	APIVersion               string            `json:"apiVersion"`
	Level                    string            `json:"level"`
	AuditID                  string            `json:"auditID"`
	Stage                    string            `json:"stage"`
	RequestURI               string            `json:"requestURI"`
	Verb                     string            `json:"verb"`
	User                     UserInfo          `json:"user"`
	ImpersonatedUser         *UserInfo         `json:"impersonatedUser,omitempty"`
	SourceIPs                []string          `json:"sourceIPs"`
	UserAgent                string            `json:"userAgent"`
	ObjectRef                *ObjectRef        `json:"objectRef,omitempty"`
	ResponseStatus           *Status           `json:"responseStatus,omitempty"`
	RequestReceivedTimestamp string            `json:"requestReceivedTimestamp"`
	StageTimestamp           string            `json:"stageTimestamp"`
	Annotations              map[string]string `json:"annotations,omitempty"`
}

// UserInfo is the authenticated user.
type UserInfo struct {
	Username string              `json:"username"`
	UID      string              `json:"uid,omitempty"`
	Groups   []string            `json:"groups,omitempty"`
	Extra    map[string][]string `json:"extra,omitempty"`
}

// ObjectRef is the object acted on.
type ObjectRef struct {
	Resource    string `json:"resource,omitempty"`
	Namespace   string `json:"namespace,omitempty"`
	Name        string `json:"name,omitempty"`
	APIGroup    string `json:"apiGroup,omitempty"`
	APIVersion  string `json:"apiVersion,omitempty"`
	Subresource string `json:"subresource,omitempty"`
}

// Status is the response status.
type Status struct {
	Metadata map[string]string `json:"metadata"`
	Code     int               `json:"code"`
	Status   string            `json:"status,omitempty"`
	Reason   string            `json:"reason,omitempty"`
}

// EventList is what the API server's webhook backend posts.
type EventList struct {
	Kind       string            `json:"kind"`
	APIVersion string            `json:"apiVersion"`
	Metadata   map[string]string `json:"metadata"`
	Items      []Event           `json:"items"`
}

type actor struct {
	user  UserInfo
	agent string
	ip    string
}

// Gen produces realistic events: users, namespaces and resources from the
// plan, every tag type, exec stage pairs and a share of exact duplicates.
type Gen struct {
	r          *rand.Rand
	namespaces []string
	people     []actor
	sas        []actor
	system     []actor
	anon       actor
	recent     []Event
	pending    []Event // second stage of an exec, emitted next
	DupShare   float64
	Spread     time.Duration // event times are spread over the last Spread
	n          int64
	// Counts by kind of event, for the report.
	Counts map[string]int64
}

// NewGen returns a generator for the namespaces of a level.
func NewGen(seed uint64, namespaces int) *Gen {
	g := &Gen{r: rand.New(rand.NewPCG(seed, 99)), DupShare: 0.005, Spread: 2 * time.Hour, Counts: map[string]int64{}}
	if namespaces < 1 {
		namespaces = 1
	}
	for i := 0; i < namespaces; i++ {
		g.namespaces = append(g.namespaces, plan.NamespaceName(i))
	}
	g.namespaces = append(g.namespaces, plan.AddonNamespaces...)
	for i := 0; i < 400; i++ {
		team := plan.Teams[i%len(plan.Teams)]
		u := UserInfo{Username: fmt.Sprintf("%s.%d@corp.example", team, i%17), Groups: []string{team + ":developers", "oidc:" + team + "-oncall", "system:authenticated"}}
		if i%5 == 0 {
			// IAM role users, as aws-iam-authenticator maps them.
			sess := fmt.Sprintf("%s-%d", team, i)
			u = UserInfo{Username: "dev:" + sess, Groups: []string{team + ":developers", "system:authenticated"}, Extra: map[string][]string{
				"arn":         {"arn:aws:sts::123456789012:assumed-role/developers/" + sess},
				"sessionName": {sess}, "accessKeyId": {"ASIA" + fmt.Sprintf("%016X", i)},
			}}
		}
		g.people = append(g.people, actor{u, "kubectl/v1.36.4 (linux/amd64) kubernetes/abcdef0", fmt.Sprintf("10.%d.%d.%d", 8+i%4, i%250, 10+i%200)})
	}
	g.people = append(g.people,
		actor{UserInfo{Username: "alice@corp.example", Groups: []string{"system:masters", "system:authenticated"}}, "kubectl/v1.36.4", "10.8.0.5"},
		actor{UserInfo{Username: "platform-admin:bob", Groups: []string{"system:masters", "system:authenticated"},
			Extra: map[string][]string{"arn": {"arn:aws:sts::123456789012:assumed-role/platform-admin/bob"}, "sessionName": {"bob"}}}, "k9s/0.40", "10.8.0.6"})
	for _, ns := range g.namespaces {
		for _, sa := range []string{"app", "ci-deployer"} {
			g.sas = append(g.sas, actor{UserInfo{Username: "system:serviceaccount:" + ns + ":" + sa,
				Groups: []string{"system:serviceaccounts", "system:serviceaccounts:" + ns, "system:authenticated"}}, "argocd-application-controller/v2.13", "10.240.1.20"})
		}
	}
	for _, s := range []string{"system:kube-controller-manager", "system:kube-scheduler", "system:apiserver", "eks:addon-manager", "eks:k8s-metrics", "eks:fargate-manager"} {
		g.system = append(g.system, actor{UserInfo{Username: s, Groups: []string{"system:authenticated"}}, "kube-controller-manager/v1.36.4", "172.19.0.11"})
	}
	for i := 0; i < 50; i++ {
		g.system = append(g.system, actor{UserInfo{Username: fmt.Sprintf("system:node:%s", plan.NodeAt(i).Name), Groups: []string{"system:nodes", "system:authenticated"}}, "kubelet/v1.36.4-eks", plan.NodeAt(i).IP})
	}
	g.anon = actor{UserInfo{Username: "system:anonymous", Groups: []string{"system:unauthenticated"}}, "curl/8.9.1", "203.0.113.7"}
	return g
}

func (g *Gen) uuid() string {
	a, b := g.r.Uint64(), g.r.Uint64()
	return fmt.Sprintf("%08x-%04x-4%03x-a%03x-%012x", uint32(a), uint16(a>>32), uint16(a>>48)&0xfff, uint16(b)&0xfff, b>>16&0xffffffffffff)
}

type kindSpec struct {
	name   string
	weight float64
}

// Event kinds and their share of traffic.
var kinds = []kindSpec{
	{"read", 50}, {"write", 13}, {"delete", 5}, {"exec", 3}, {"portforward", 1}, {"debug", 0.5},
	{"secret-read", 5}, {"secret-write", 1}, {"rbac", 2}, {"impersonate", 1}, {"token", 2},
	{"denied", 3}, {"anonymous", 0.5}, {"system", 13},
}

var resources = []struct{ group, resource string }{
	{"", "pods"}, {"apps", "deployments"}, {"", "services"}, {"", "configmaps"}, {"apps", "statefulsets"},
	{"batch", "jobs"}, {"batch", "cronjobs"}, {"networking.k8s.io", "ingresses"}, {"", "persistentvolumeclaims"}, {"", "events"},
}

// Next returns the next event.
func (g *Gen) Next(now time.Time) Event {
	g.n++
	if len(g.pending) > 0 {
		e := g.pending[0]
		g.pending = g.pending[1:]
		g.Counts["exec-complete"]++
		return e
	}
	if len(g.recent) > 0 && g.r.Float64() < g.DupShare {
		g.Counts["duplicate"]++
		return g.recent[g.r.IntN(len(g.recent))]
	}
	e := g.fresh(now)
	if len(g.recent) < 1000 {
		g.recent = append(g.recent, e)
	} else {
		g.recent[g.r.IntN(len(g.recent))] = e
	}
	return e
}

func (g *Gen) pick() string {
	total := 0.0
	for _, k := range kinds {
		total += k.weight
	}
	x := g.r.Float64() * total
	for _, k := range kinds {
		x -= k.weight
		if x < 0 {
			return k.name
		}
	}
	return "read"
}

func (g *Gen) fresh(now time.Time) Event {
	kind := g.pick()
	g.Counts[kind]++
	ns := g.namespaces[g.r.IntN(len(g.namespaces))]
	a := g.people[g.r.IntN(len(g.people))]
	if g.r.Float64() < 0.35 {
		a = g.sas[g.r.IntN(len(g.sas))]
	}
	res := resources[g.r.IntN(len(resources))]
	verb := []string{"get", "list", "watch"}[g.r.IntN(3)]
	name := fmt.Sprintf("%s-%d", []string{"api", "web", "worker", "cache", "sync"}[g.r.IntN(5)], g.r.IntN(40))
	sub := ""
	code := 200
	ann := map[string]string{"authorization.k8s.io/decision": "allow", "authorization.k8s.io/reason": "RBAC: allowed by RoleBinding \"developer-0/" + ns + "\""}
	var imp *UserInfo
	switch kind {
	case "write":
		verb = []string{"create", "update", "patch"}[g.r.IntN(3)]
		code = map[string]int{"create": 201, "update": 200, "patch": 200}[verb]
	case "delete":
		verb = "delete"
	case "exec":
		res, verb, sub = resources[0], "create", "exec"
		code = 101
	case "portforward":
		res, verb, sub = resources[0], "create", "portforward"
		code = 101
	case "debug":
		res, verb, sub = resources[0], "patch", "ephemeralcontainers"
	case "secret-read":
		res.group, res.resource = "", "secrets"
		name = "db-credentials"
	case "secret-write":
		res.group, res.resource, verb = "", "secrets", "update"
		name = "db-credentials"
	case "rbac":
		res.group, res.resource = "rbac.authorization.k8s.io", []string{"roles", "rolebindings", "clusterroles", "clusterrolebindings"}[g.r.IntN(4)]
		verb = []string{"create", "update", "patch", "delete"}[g.r.IntN(4)]
		if res.resource == "clusterroles" || res.resource == "clusterrolebindings" {
			ns = ""
		}
	case "impersonate":
		imp = &UserInfo{Username: "system:serviceaccount:" + ns + ":app"}
	case "token":
		res.group, res.resource, verb, sub, name = "", "serviceaccounts", "create", "token", "app"
		code = 201
	case "denied":
		code = 403
		ann = map[string]string{"authorization.k8s.io/decision": "forbid", "authorization.k8s.io/reason": ""}
		if g.r.IntN(2) == 0 {
			res.group, res.resource, name = "", "secrets", "prod-tls"
		}
	case "anonymous":
		a = g.anon
		code = 403
		ann = map[string]string{"authorization.k8s.io/decision": "forbid", "authorization.k8s.io/reason": ""}
	case "system":
		a = g.system[g.r.IntN(len(g.system))]
		verb = []string{"get", "list", "update", "patch", "watch"}[g.r.IntN(5)]
	}
	if verb == "list" || verb == "watch" {
		name = ""
	}
	t := now.Add(-time.Duration(g.r.Int64N(int64(g.Spread))))
	uri := "/api/v1/namespaces/" + ns + "/" + res.resource
	if res.group != "" {
		uri = "/apis/" + res.group + "/v1/namespaces/" + ns + "/" + res.resource
	}
	if ns == "" {
		uri = "/apis/" + res.group + "/v1/" + res.resource
	}
	if name != "" {
		uri += "/" + name
	}
	if sub != "" {
		uri += "/" + sub
	}
	if sub == "exec" {
		uri += "?command=sh&command=-c&command=cat+%2Fetc%2Fpasswd&container=main&stdin=true&stdout=true&tty=true"
	}
	e := Event{
		Kind: "Event", APIVersion: "audit.k8s.io/v1", Level: "Metadata", AuditID: g.uuid(), Stage: "ResponseComplete",
		RequestURI: uri, Verb: verb, User: a.user, ImpersonatedUser: imp, SourceIPs: []string{a.ip}, UserAgent: a.agent,
		ObjectRef:                &ObjectRef{Resource: res.resource, Namespace: ns, Name: name, APIGroup: res.group, APIVersion: "v1", Subresource: sub},
		ResponseStatus:           &Status{Metadata: map[string]string{}, Code: code},
		RequestReceivedTimestamp: t.UTC().Format(time.RFC3339Nano), StageTimestamp: t.Add(time.Duration(5+g.r.IntN(200)) * time.Millisecond).UTC().Format(time.RFC3339Nano),
		Annotations: ann,
	}
	if code == 403 {
		e.ResponseStatus.Status, e.ResponseStatus.Reason = "Failure", "Forbidden"
	}
	if kind == "exec" || kind == "portforward" {
		// Long-running requests log ResponseStarted, then ResponseComplete
		// with the same auditID when the session ends.
		e.Stage = "ResponseStarted"
		done := e
		done.Stage = "ResponseComplete"
		done.StageTimestamp = t.Add(time.Duration(30+g.r.IntN(600)) * time.Second).UTC().Format(time.RFC3339Nano)
		g.pending = append(g.pending, done)
	}
	return e
}

// Batch returns n events as an EventList body.
func (g *Gen) Batch(n int, now time.Time) ([]byte, error) {
	b, _, err := g.BatchIDs(n, now)
	return b, err
}

// BatchIDs is Batch, also returning the auditIDs in it.
func (g *Gen) BatchIDs(n int, now time.Time) ([]byte, []string, error) {
	l := EventList{Kind: "EventList", APIVersion: "audit.k8s.io/v1", Metadata: map[string]string{}, Items: make([]Event, n)}
	ids := make([]string, n)
	for i := range l.Items {
		l.Items[i] = g.Next(now)
		ids[i] = l.Items[i].AuditID
	}
	b, err := json.Marshal(l)
	return b, ids, err
}
