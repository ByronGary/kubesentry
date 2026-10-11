package prom

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
)

func TestParseMatchers(t *testing.T) {
	tests := []struct {
		in, want string // want is the canonical String(); "" with ok=false means an error
		ok       bool
	}{
		{``, ``, true},
		{`cluster="prod"`, `cluster="prod"`, true},
		{`cluster="prod",env=~"p.*"`, `cluster="prod",env=~"p.*"`, true},
		{` { cluster = "prod" , env !~ 'dev|test' , } `, `cluster="prod",env!~"dev|test"`, true},
		{`region!="eu-west-1"`, `region!="eu-west-1"`, true},
		{"raw=~`a\\d+`", `raw=~"a\\d+"`, true},
		{`q="say \"hi\"\n"`, `q="say \"hi\"\n"`, true},
		{`q='it\'s "fine"'`, `q="it's \"fine\""`, true},
		{`u="ét\xc3\xa9"`, `u="été"`, true},
		{`_x1="a"`, `_x1="a"`, true},
		// Rejected.
		{`cluster`, ``, false},
		{`cluster=prod`, ``, false},
		{`cluster=="prod"`, ``, false},
		{`cluster<"prod"`, ``, false},
		{`1abc="x"`, ``, false},
		{`a-b="x"`, ``, false},
		{`__name__="up"`, ``, false},
		{`__tenant="x"`, ``, false},
		{`a="unterminated`, ``, false},
		{`a="bad \q escape"`, ``, false},
		{`a=~"(unclosed"`, ``, false},
		{`a="x" b="y"`, ``, false},
		{`{a="x"`, ``, false},
		{`{}`, ``, false},
		{`a="x"} or vector(1) {b="y"`, ``, false},
		{"a=\"line\nbreak\"", ``, false},
	}
	for _, tc := range tests {
		got, err := ParseMatchers(tc.in)
		if (err == nil) != tc.ok {
			t.Errorf("ParseMatchers(%q) err = %v, want ok=%v", tc.in, err, tc.ok)
			continue
		}
		if tc.ok && got.String() != tc.want {
			t.Errorf("ParseMatchers(%q) = %q, want %q", tc.in, got.String(), tc.want)
		}
	}
}

// recorder is a fake Prometheus that records each query and answers with an
// empty result of the right type.
type recorder struct {
	mu      sync.Mutex
	queries []string
}

func (r *recorder) handler(w http.ResponseWriter, req *http.Request) {
	_ = req.ParseForm()
	r.mu.Lock()
	r.queries = append(r.queries, req.PostForm.Get("query"))
	r.mu.Unlock()
	if strings.HasSuffix(req.URL.Path, "query_range") {
		w.Write([]byte(`{"status":"success","data":{"resultType":"matrix","result":[]}}`))
		return
	}
	w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`))
}

func (r *recorder) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.queries...)
}

func TestSelectorInjectedIntoEveryBuiltQuery(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(rec.handler))
	defer srv.Close()
	m, err := ParseMatchers(`cluster="prod",env=~"p.*"`)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewClient(srv.URL, Options{Selector: m, KSMLimits: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := c.ContainerMemory(ctx, time.Hour, time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ContainerMemoryLimits(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.PodMemory(ctx, "app", "web-0", time.Hour, time.Minute); err != nil {
		t.Fatal(err)
	}
	want := []string{
		`max by (namespace, pod, container) (container_memory_working_set_bytes{container!="",container!="POD",cluster="prod",env=~"p.*"})`,
		`max by (namespace, pod, container) (kube_pod_container_resource_limits{resource="memory",cluster="prod",env=~"p.*"})`,
		`max by (namespace, pod, container) (container_memory_working_set_bytes{namespace="app",pod="web-0",container!="",container!="POD",cluster="prod",env=~"p.*"})`,
		`max by (namespace, pod, container) (kube_pod_container_resource_limits{namespace="app",pod="web-0",resource="memory",cluster="prod",env=~"p.*"})`,
	}
	got := rec.all()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("queries:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestLeakScanQueriesCarrySelector(t *testing.T) {
	m, _ := ParseMatchers(`cluster="prod"`)
	c, _ := NewClient("http://prom:9090", Options{Selector: m})
	s := NewLeakScanner(c, nil, LeakScanOptions{})
	want := `topk(5001, max by (namespace, pod, container) (deriv(container_memory_working_set_bytes{container!="",container!="POD",cluster="prod"}[24h:6m])) > 145.63555555555556)`
	if got := s.CandidateQuery(); got != want {
		t.Errorf("candidate query:\n got %s\nwant %s", got, want)
	}

	keys := []model.ContainerKey{
		{Namespace: "b", Pod: "api-1", Container: "app"},
		{Namespace: "a", Pod: "web.0", Container: "app"},
		{Namespace: "a", Pod: "web-1", Container: "sidecar"},
		{Namespace: "a", Pod: "web.0", Container: "sidecar"},
	}
	wantChunk := `max by (namespace, pod, container) (` +
		`container_memory_working_set_bytes{namespace="a",pod=~"web-1|web\\.0",container=~"app|sidecar",cluster="prod"}` +
		` or container_memory_working_set_bytes{namespace="b",pod="api-1",container="app",cluster="prod"})`
	if got := c.chunkQuery(memMetric, keys); got != wantChunk {
		t.Errorf("chunk query:\n got %s\nwant %s", got, wantChunk)
	}
	wantKSM := `max by (namespace, pod, container) (kube_pod_container_resource_limits{namespace="b",pod="api-1",container="app",resource="memory",cluster="prod"})`
	if got := c.chunkQuery("kube_pod_container_resource_limits", keys[:1], `resource="memory"`); got != wantKSM {
		t.Errorf("ksm chunk query:\n got %s\nwant %s", got, wantKSM)
	}
}

func TestNewClientRejectsBadURLs(t *testing.T) {
	for _, u := range []string{"", "prometheus:9090", "ftp://x", "http://"} {
		if _, err := NewClient(u, Options{}); err == nil {
			t.Errorf("NewClient(%q) accepted", u)
		}
	}
}
