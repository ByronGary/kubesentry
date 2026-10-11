package audit

import (
	"reflect"
	"strings"
	"testing"
)

const execEvent = `{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"Metadata","auditID":"a1","stage":"ResponseStarted",
"requestURI":"/api/v1/namespaces/prod/pods/web-0/exec?command=sh&container=web&stdin=true",
"verb":"create","user":{"username":"admin:alice","groups":["system:masters","system:authenticated"],
"extra":{"arn":["arn:aws:iam::111122223333:role/Admin"],"sessionName":["alice"]}},
"sourceIPs":["10.1.2.3"],"userAgent":"kubectl/v1.31.0",
"objectRef":{"resource":"pods","namespace":"prod","name":"web-0","apiVersion":"v1","subresource":"exec"},
"responseStatus":{"metadata":{},"code":101},
"requestReceivedTimestamp":"2026-10-10T14:00:00.123456Z","stageTimestamp":"2026-10-10T14:00:00.2Z",
"annotations":{"authorization.k8s.io/decision":"allow"}}`

const receivedEvent = `{"kind":"Event","auditID":"a1","stage":"RequestReceived","verb":"create",
"user":{"username":"admin:alice"},"requestReceivedTimestamp":"2026-10-10T14:00:00Z","stageTimestamp":"2026-10-10T14:00:00Z"}`

func TestParseSingleEventNormalizes(t *testing.T) {
	got, err := Parse(strings.NewReader(execEvent))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d events, want 1", len(got))
	}
	e := got[0]
	checks := map[string][2]string{
		"auditID":     {e.AuditID, "a1"},
		"stage":       {e.Stage, "ResponseStarted"},
		"username":    {e.Username, "admin:alice"},
		"actorKind":   {e.ActorKind, "user"},
		"arn":         {e.ARN, "arn:aws:iam::111122223333:role/Admin"},
		"sessionName": {e.SessionName, "alice"},
		"resource":    {e.Resource, "pods"},
		"subresource": {e.Subresource, "exec"},
		"namespace":   {e.Namespace, "prod"},
		"name":        {e.Name, "web-0"},
		"decision":    {e.Decision, "allow"},
		"userAgent":   {e.UserAgent, "kubectl/v1.31.0"},
	}
	for k, c := range checks {
		if c[0] != c[1] {
			t.Errorf("%s = %q, want %q", k, c[0], c[1])
		}
	}
	if e.StatusCode != 101 {
		t.Errorf("status = %d, want 101", e.StatusCode)
	}
	if !strings.Contains(e.RequestURI, "command=sh") {
		t.Errorf("requestURI should keep the exec command: %q", e.RequestURI)
	}
	if e.Time.Format("2006-01-02T15:04:05") != "2026-10-10T14:00:00" {
		t.Errorf("time = %v, want requestReceivedTimestamp", e.Time)
	}
	if !reflect.DeepEqual(e.Tags, []string{TagExec}) {
		t.Errorf("tags = %v, want [exec]", e.Tags)
	}
}

func TestParseEventList(t *testing.T) {
	list := `{"kind":"EventList","apiVersion":"audit.k8s.io/v1","items":[` + execEvent + `,` + receivedEvent + `,
	{"auditID":"b2","stage":"ResponseComplete","verb":"get","user":{"username":"system:kube-scheduler"},
	 "requestReceivedTimestamp":"2026-10-10T14:01:00Z"}]}`
	got, err := Parse(strings.NewReader(list))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d events, want 2 (RequestReceived dropped)", len(got))
	}
	if got[1].ActorKind != "system" {
		t.Errorf("actorKind = %q, want system", got[1].ActorKind)
	}
}

func TestParseNDJSONAndJunk(t *testing.T) {
	ndjson := strings.ReplaceAll(execEvent, "\n", "") + "\n" +
		strings.ReplaceAll(receivedEvent, "\n", "") + "\n" +
		`{}` + "\n" +
		`{"auditID":"c3","stage":"ResponseComplete","verb":"delete","user":{"username":"system:serviceaccount:ci:deployer"},
		 "objectRef":{"resource":"deployments","apiGroup":"apps","namespace":"ci","name":"x"},"responseStatus":{"code":200},
		 "requestReceivedTimestamp":"2026-10-10T14:02:00Z"}` + "\n"
	got, err := Parse(strings.NewReader(ndjson))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d events, want 2 (RequestReceived and {} dropped)", len(got))
	}
	if got[1].ActorKind != "serviceaccount" || !reflect.DeepEqual(got[1].Tags, []string{TagDelete}) {
		t.Errorf("unexpected second event: %+v", got[1])
	}
}

func TestParseMalformedReturnsNothing(t *testing.T) {
	got, err := Parse(strings.NewReader(execEvent + "\n{not json"))
	if err == nil || got != nil {
		t.Fatalf("want error and no events, got %v, %v", got, err)
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		e    Event
		want []string
	}{
		{"secret read", Event{Verb: "get", Resource: "secrets"}, []string{TagSecretAccess}},
		{"secret list", Event{Verb: "list", Resource: "secrets"}, []string{TagSecretAccess}},
		{"secret write", Event{Verb: "update", Resource: "secrets"}, []string{TagSecretChange}},
		{"secret delete", Event{Verb: "delete", Resource: "secrets"}, []string{TagSecretChange, TagDelete}},
		{"attach", Event{Verb: "create", Resource: "pods", Subresource: "attach"}, []string{TagExec}},
		{"portforward", Event{Verb: "create", Resource: "pods", Subresource: "portforward"}, []string{TagPortForward}},
		{"kubectl debug", Event{Verb: "patch", Resource: "pods", Subresource: "ephemeralcontainers"}, []string{TagDebug}},
		{"rbac binding", Event{Verb: "create", APIGroup: "rbac.authorization.k8s.io", Resource: "clusterrolebindings"}, []string{TagRBACChange}},
		{"rbac read is quiet", Event{Verb: "get", APIGroup: "rbac.authorization.k8s.io", Resource: "clusterroles"}, nil},
		{"impersonation", Event{Verb: "get", Resource: "pods", ImpersonatedUser: "bob"}, []string{TagImpersonate}},
		{"token request", Event{Verb: "create", Resource: "serviceaccounts", Subresource: "token"}, []string{TagTokenRequest}},
		{"forbidden", Event{Verb: "get", Resource: "pods", StatusCode: 403}, []string{TagDenied}},
		{"anonymous denied", Event{Verb: "get", Username: "system:anonymous", StatusCode: 403}, []string{TagDenied, TagAnonymous}},
		{"plain read", Event{Verb: "get", Resource: "pods", StatusCode: 200}, nil},
		{"CRD named secrets is not a Secret", Event{Verb: "get", Resource: "secrets", APIGroup: "example.com"}, nil},
	}
	for _, c := range cases {
		if got := Classify(c.e); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: tags = %v, want %v", c.name, got, c.want)
		}
	}
}
