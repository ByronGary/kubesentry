package demo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/url"
	"time"

	"github.com/ByronGary/kubesentry/internal/audit"
)

// event describes one synthetic audit record.
type event struct {
	id          string // default demo-<n>
	ago         time.Duration
	user        string
	verb        string
	resource    string
	sub         string
	ns          string
	name        string
	code        int
	cmd         string // exec command
	impersonate string
}

var people = map[string]string{
	"alice": "Developer",
	"bob":   "SRE",
	"carol": "DataEngineer",
	"dave":  "Developer",
	"erin":  "Contractor",
}

func apiGroup(resource string) string {
	switch resource {
	case "deployments", "statefulsets":
		return "apps"
	case "clusterrolebindings", "clusterroles", "rolebindings", "roles":
		return "rbac.authorization.k8s.io"
	}
	return ""
}

func rawEvent(id string, now time.Time, e event) map[string]any {
	ts := now.Add(-e.ago).UTC().Format(time.RFC3339Nano)
	uri := fmt.Sprintf("/api/v1/namespaces/%s/%s/%s", e.ns, e.resource, e.name)
	stage := "ResponseComplete"
	if e.sub != "" {
		uri += "/" + e.sub
	}
	if e.sub == "exec" {
		stage = "ResponseStarted"
		uri += "?command=" + url.QueryEscape(e.cmd) + "&container=api&stdin=true&tty=true"
	}
	user := map[string]any{"username": e.user, "groups": []string{"system:authenticated"}}
	if role, ok := people[e.user]; ok {
		user["extra"] = map[string][]string{
			"arn":         {"arn:aws:iam::111122223333:role/" + role},
			"sessionName": {e.user},
		}
	}
	decision := "allow"
	if e.code == 403 {
		decision = "forbid"
	}
	obj := map[string]any{"resource": e.resource, "apiGroup": apiGroup(e.resource), "namespace": e.ns, "name": e.name}
	if e.sub != "" {
		obj["subresource"] = e.sub
	}
	out := map[string]any{
		"kind": "Event", "apiVersion": "audit.k8s.io/v1", "level": "Metadata",
		"auditID": id, "stage": stage, "requestURI": uri, "verb": e.verb,
		"user": user, "sourceIPs": []string{"10.0.12.34"}, "userAgent": "kubectl/v1.31.0",
		"objectRef":                obj,
		"responseStatus":           map[string]any{"code": e.code},
		"requestReceivedTimestamp": ts, "stageTimestamp": ts,
		"annotations": map[string]string{"authorization.k8s.io/decision": decision},
	}
	if e.impersonate != "" {
		out["impersonatedUser"] = map[string]string{"username": e.impersonate}
	}
	return out
}

// SeedAudit loads a day of synthetic activity through the real ingestion path.
func SeedAudit(ing *audit.Ingester, now time.Time) error {
	const api = "checkout-api-7d9f8b6c4-x2k9p"
	min := time.Minute
	h := time.Hour

	events := []event{
		// The interesting ones.
		{ago: 45 * min, user: "alice", verb: "create", resource: "pods", sub: "exec", ns: "prod", name: api, code: 101, cmd: "sh"},
		{ago: 22 * min, user: "alice", verb: "create", resource: "pods", sub: "exec", ns: "prod", name: api, code: 101, cmd: "cat /proc/meminfo"},
		{ago: 50 * min, user: "alice", verb: "get", resource: "secrets", ns: "prod", name: "checkout-db-credentials", code: 200},
		{ago: 5 * h, user: "bob", verb: "create", resource: "clusterrolebindings", ns: "", name: "tmp-admin", code: 201},
		{ago: 4*h + 45*min, user: "bob", verb: "delete", resource: "clusterrolebindings", ns: "", name: "tmp-admin", code: 200},
		{ago: 7 * h, user: "bob", verb: "patch", resource: "pods", sub: "ephemeralcontainers", ns: "prod", name: "payments-worker-5c6d7f9b8-q8wzn", code: 200},
		{ago: 2 * h, user: "system:serviceaccount:ci:deployer", verb: "update", resource: "deployments", ns: "prod", name: "checkout-api", code: 200},
		{ago: 2 * h, user: "system:serviceaccount:ci:deployer", verb: "delete", resource: "pods", ns: "prod", name: "checkout-api-7d9f8b6c4-old01", code: 200},
		{ago: 3 * h, user: "system:anonymous", verb: "get", resource: "pods", ns: "prod", name: "", code: 403},
		{ago: 3*h - 4*min, user: "system:anonymous", verb: "list", resource: "secrets", ns: "prod", name: "", code: 403},
		{ago: 6 * h, user: "carol", verb: "get", resource: "secrets", ns: "data", name: "warehouse-creds", code: 200, impersonate: "system:serviceaccount:data:etl"},
		{ago: 1 * h, user: "dave", verb: "delete", resource: "pods", ns: "staging", name: "search-indexer-0", code: 200},
		{ago: 8 * h, user: "erin", verb: "create", resource: "serviceaccounts", sub: "token", ns: "prod", name: "checkout", code: 201},
		{ago: 9 * h, user: "erin", verb: "get", resource: "secrets", ns: "kube-system", name: "bootstrap-token", code: 403},
		{ago: 10 * h, user: "alice", verb: "create", resource: "pods", sub: "exec", ns: "prod", name: "postgres-0", code: 101, cmd: "psql -U app"},
		{ago: 12 * h, user: "bob", verb: "update", resource: "secrets", ns: "prod", name: "checkout-db-credentials", code: 200},
	}

	// Background reads and system chatter, mostly hidden by the default view.
	rng := rand.New(rand.NewSource(7))
	readers := []string{"alice", "bob", "carol", "dave", "erin"}
	resources := []string{"pods", "deployments", "services", "configmaps"}
	namespaces := []string{"prod", "staging", "monitoring"}
	for i := 0; i < 40; i++ {
		events = append(events, event{
			ago:  time.Duration(rng.Intn(23*60)) * min,
			user: readers[rng.Intn(len(readers))], verb: []string{"get", "list"}[rng.Intn(2)],
			resource: resources[rng.Intn(len(resources))], ns: namespaces[rng.Intn(len(namespaces))],
			name: "", code: 200,
		})
	}
	for i := 0; i < 12; i++ {
		events = append(events, event{
			ago:  time.Duration(rng.Intn(23*60)) * min,
			user: "system:kube-controller-manager", verb: "update", resource: "deployments",
			ns: "prod", name: "checkout-web", code: 200,
		})
	}

	// The edit that precedes the checkout-web incident (incidents.go).
	events = append(events, event{id: configPatchAuditID, ago: configPatchAgo, user: "dave", verb: "patch", resource: "configmaps",
		ns: "prod", name: "checkout-web-config", code: 200})

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf) // one JSON document per line, like an audit log file
	for i, e := range events {
		id := e.id
		if id == "" {
			id = fmt.Sprintf("demo-%03d", i+1)
		}
		if err := enc.Encode(rawEvent(id, now, e)); err != nil {
			return err
		}
	}
	_, err := ing.IngestReader(&buf)
	return err
}
