package prom

import (
	"context"
	"net/http"
	"net/http/httptest"
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
