package prom

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPodMemoryScopesQueriesAndQuotesNames(t *testing.T) {
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		queries = append(queries, r.PostForm.Get("query"))
		if strings.HasSuffix(r.URL.Path, "query_range") {
			w.Write([]byte(`{"status":"success","data":{"resultType":"matrix","result":[
				{"metric":{"namespace":"app","pod":"web-0","container":"web"},"values":[[1760000000,"100"],[1760000060,"200"]]}]}}`))
			return
		}
		w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[
			{"metric":{"namespace":"app","pod":"web-0","container":"web"},"value":[1760000000,"1024"]}]}}`))
	}))
	defer srv.Close()

	series, limits, err := New(srv.URL).PodMemory(context.Background(), "app", "web-0", time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(series) != 1 || len(series[0].Samples) != 2 || len(limits) != 1 {
		t.Fatalf("series=%+v limits=%v", series, limits)
	}
	if len(queries) != 2 || !strings.Contains(queries[0], `namespace="app",pod="web-0"`) || !strings.Contains(queries[1], `namespace="app",pod="web-0"`) {
		t.Errorf("queries not scoped to the pod: %q", queries)
	}

	// A hostile pod name stays inside its string literal.
	queries = nil
	_, _, _ = New(srv.URL).PodMemory(context.Background(), "app", `x"} or vector(1) #`, time.Hour, time.Minute)
	if len(queries) == 0 || !strings.Contains(queries[0], `pod="x\"} or vector(1) #"`) {
		t.Errorf("name was not quoted: %q", queries)
	}
}
