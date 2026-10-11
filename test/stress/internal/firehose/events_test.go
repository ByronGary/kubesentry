package firehose

import (
	"encoding/json"
	"math"
	"testing"
	"time"
)

// tags mirrors kubesentry's audit.Classify closely enough to check coverage.
func tags(e Event) []string {
	var out []string
	o := e.ObjectRef
	if o == nil {
		o = &ObjectRef{}
	}
	if o.Resource == "pods" {
		switch o.Subresource {
		case "exec", "attach":
			out = append(out, "exec")
		case "portforward":
			out = append(out, "portforward")
		case "ephemeralcontainers":
			out = append(out, "debug-container")
		}
	}
	if o.Resource == "secrets" && o.APIGroup == "" {
		switch e.Verb {
		case "get", "list", "watch":
			out = append(out, "secret-access")
		default:
			out = append(out, "secret-change")
		}
	}
	if o.APIGroup == "rbac.authorization.k8s.io" && e.Verb != "get" && e.Verb != "list" && e.Verb != "watch" {
		out = append(out, "rbac-change")
	}
	if e.Verb == "delete" {
		out = append(out, "delete")
	}
	if e.ImpersonatedUser != nil {
		out = append(out, "impersonate")
	}
	if o.Resource == "serviceaccounts" && o.Subresource == "token" {
		out = append(out, "token-request")
	}
	if e.ResponseStatus != nil && (e.ResponseStatus.Code == 403 || e.ResponseStatus.Code == 401) || e.Annotations["authorization.k8s.io/decision"] == "forbid" {
		out = append(out, "denied")
	}
	if e.User.Username == "system:anonymous" {
		out = append(out, "anonymous")
	}
	return out
}

func TestGeneratorCoversEveryTagAndPairsExecStages(t *testing.T) {
	g := NewGen(1, 30)
	now := time.Now()
	seen := map[string]int{}
	ids := map[string][]string{}
	const n = 200000
	dups := 0
	full := map[string]bool{}
	for i := 0; i < n; i++ {
		e := g.Next(now)
		for _, tg := range tags(e) {
			seen[tg]++
		}
		key := e.AuditID + e.Stage
		if full[key] {
			dups++
		}
		full[key] = true
		ids[e.AuditID] = append(ids[e.AuditID], e.Stage)
		ts, err := time.Parse(time.RFC3339Nano, e.RequestReceivedTimestamp)
		if err != nil || ts.After(now) || now.Sub(ts) > g.Spread {
			t.Fatalf("bad timestamp %q", e.RequestReceivedTimestamp)
		}
	}
	for _, tg := range []string{"exec", "portforward", "debug-container", "secret-access", "secret-change", "rbac-change", "delete", "impersonate", "token-request", "denied", "anonymous"} {
		if seen[tg] == 0 {
			t.Errorf("tag %s never generated", tg)
		}
	}
	if share := float64(dups) / n; math.Abs(share-0.005) > 0.002 {
		t.Errorf("duplicate share %.4f, want about 0.005", share)
	}
	pairs := 0
	for _, stages := range ids {
		hasStarted, hasComplete := false, false
		for _, s := range stages {
			hasStarted = hasStarted || s == "ResponseStarted"
			hasComplete = hasComplete || s == "ResponseComplete"
		}
		if hasStarted {
			if !hasComplete {
				// The last few sessions may still be pending.
				continue
			}
			pairs++
		}
	}
	if pairs < 1000 {
		t.Errorf("only %d ResponseStarted+ResponseComplete pairs", pairs)
	}
}

func TestBatchIsAnEventList(t *testing.T) {
	g := NewGen(2, 5)
	b, err := g.Batch(1000, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var l struct {
		Kind  string            `json:"kind"`
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(b, &l); err != nil || l.Kind != "EventList" || len(l.Items) != 1000 {
		t.Fatalf("kind %q, %d items, err %v", l.Kind, len(l.Items), err)
	}
	if per := len(b) / 1000; per < 300 || per > 2000 {
		t.Errorf("%d bytes per event", per)
	}
}
