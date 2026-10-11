package prom

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestQueryRangeParsesMatrixAndSkipsNaN(t *testing.T) {
	var gotAuth, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_ = r.ParseForm()
		gotQuery = r.PostForm.Get("query")
		if r.URL.Path != "/api/v1/query_range" {
			t.Errorf("path = %s", r.URL.Path)
		}
		w.Write([]byte(`{"status":"success","data":{"resultType":"matrix","result":[
			{"metric":{"namespace":"app","pod":"web-0","container":"web"},
			 "values":[[1760000000,"100"],[1760000060,"NaN"],[1760000120,"300"]]}]}}`))
	}))
	defer srv.Close()

	c := New(srv.URL + "/")
	c.BearerToken = "tok"
	now := time.Now()
	got, err := c.QueryRange(context.Background(), "up", now.Add(-time.Hour), now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer tok" || gotQuery != "up" {
		t.Errorf("auth=%q query=%q", gotAuth, gotQuery)
	}
	if len(got) != 1 || len(got[0].Samples) != 2 {
		t.Fatalf("want 1 series with 2 samples (NaN skipped), got %+v", got)
	}
	if got[0].Samples[1].V != 300 || got[0].Samples[0].T.Unix() != 1760000000 {
		t.Errorf("bad samples: %+v", got[0].Samples)
	}
}

func TestQueryInstantAndLimits(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[
			{"metric":{"namespace":"app","pod":"web-0","container":"web"},"value":[1760000000,"536870912"]}]}}`))
	}))
	defer srv.Close()

	limits, err := New(srv.URL).ContainerMemoryLimits(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(limits) != 1 {
		t.Fatalf("got %d limits", len(limits))
	}
	for k, v := range limits {
		if k.Pod != "web-0" || v != 536870912 {
			t.Errorf("limit %+v = %v", k, v)
		}
	}
}

// A caller restricted to some namespaces never makes the server query the
// whole cluster: every query names namespaces, only valid ones, and long
// lists are split so each query stays under ~8 KiB.
func TestContainerMemoryInRestrictsAndChunks(t *testing.T) {
	var mu sync.Mutex
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		queries = append(queries, r.PostForm.Get("query"))
		mu.Unlock()
		w.Write([]byte(`{"status":"success","data":{"resultType":"matrix","result":[]}}`))
	}))
	defer srv.Close()
	c, err := NewClient(srv.URL, Options{KSMLimits: true, Selector: Matchers{{Name: "cluster", Op: "=", Value: "prod"}}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if _, err := c.ContainerMemoryIn(ctx, nil, time.Hour, time.Minute); err != nil || len(queries) != 0 {
		t.Fatalf("no namespaces: %d queries, %v", len(queries), err)
	}
	var nss []string
	for i := 0; i < 600; i++ {
		nss = append(nss, fmt.Sprintf("team-%03d.payments-production-eu-west-1", i))
	}
	nss = append(nss, "Bad_Namespace", `x"}or{y`, "team-000.payments-production-eu-west-1")
	if _, err := c.ContainerMemoryIn(ctx, nss, time.Hour, time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ContainerMemoryLimitsIn(ctx, nss); err != nil {
		t.Fatal(err)
	}
	if len(queries) < 4 {
		t.Fatalf("600 long namespaces fit in %d queries; want them split", len(queries))
	}
	seen := map[string]int{}
	for _, q := range queries {
		if len(q) > 8<<10 {
			t.Errorf("query of %d bytes", len(q))
		}
		if !strings.Contains(q, `namespace=~"`) && !strings.Contains(q, `namespace="`) {
			t.Errorf("query without a namespace matcher: %.200s", q)
		}
		if !strings.Contains(q, `cluster="prod"`) {
			t.Errorf("query without the selector: %.200s", q)
		}
		if strings.Contains(q, "Bad_Namespace") || strings.Contains(q, "or{y") {
			t.Errorf("invalid namespace reached PromQL: %.200s", q)
		}
		for _, ns := range nss[:600] {
			if strings.Contains(q, regexp.QuoteMeta(ns)) || strings.Contains(q, strings.ReplaceAll(regexp.QuoteMeta(ns), `\`, `\\`)) {
				seen[ns]++
			}
		}
	}
	for _, ns := range nss[:600] {
		if seen[ns] != 2 { // once for memory, once for limits
			t.Errorf("%s queried %d times, want 2", ns, seen[ns])
			break
		}
	}
}

// User info in the URL is sent as basic auth but never shown.
func TestURLCredentialsAreSentButNotShown(t *testing.T) {
	var user, pass string
	var ok bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok = r.BasicAuth()
		w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`))
	}))
	defer srv.Close()
	raw := strings.Replace(srv.URL, "http://", "http://kubesentry:s3cret@", 1) + "/prom/"
	c, err := NewClient(raw, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(c.BaseURL(), "s3cret") || strings.Contains(c.BaseURL(), "kubesentry@") || !c.HasURLCredentials() {
		t.Errorf("BaseURL = %q, credentials %v", c.BaseURL(), c.HasURLCredentials())
	}
	if want := srv.URL + "/prom"; c.BaseURL() != want {
		t.Errorf("BaseURL = %q, want %q", c.BaseURL(), want)
	}
	if _, err := c.Query(context.Background(), "up", time.Now()); err != nil {
		t.Fatal(err)
	}
	if !ok || user != "kubesentry" || pass != "s3cret" {
		t.Errorf("basic auth = %q %q %v", user, pass, ok)
	}
	// A bearer token wins over URL credentials.
	c, _ = NewClient(raw, Options{BearerToken: "tok"})
	ok = false
	c.Query(context.Background(), "up", time.Now())
	if ok {
		t.Error("basic auth sent along with a bearer token")
	}
	for in, want := range map[string]string{
		"https://u:p@h/x": "https://h/x", "https://h/x": "https://h/x", "https://u@h": "https://h",
	} {
		if got := Redact(in); got != want {
			t.Errorf("Redact(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := NewClient("ftp://u:secret@h", Options{}); err == nil || strings.Contains(err.Error(), "secret") {
		t.Errorf("bad URL error = %v", err)
	}
}

func TestErrorResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"status":"error","errorType":"bad_data","error":"parse error"}`))
	}))
	defer srv.Close()

	if _, err := New(srv.URL).Query(context.Background(), "((", time.Now()); err == nil {
		t.Fatal("expected error")
	}
}
