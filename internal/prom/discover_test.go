package prom

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// fakeServer serves buildinfo (when set), runtimeinfo and count(up).
func fakeServer(t *testing.T, buildinfo, queryResp string, queryStatus int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/api/v1/status/buildinfo"):
			if buildinfo == "" {
				http.NotFound(w, r)
				return
			}
			w.Write([]byte(buildinfo))
		case strings.HasSuffix(r.URL.Path, "/api/v1/status/runtimeinfo"):
			w.Write([]byte(`{"status":"success","data":{"storageRetention":"15d or 50GiB"}}`))
		case strings.HasSuffix(r.URL.Path, "/api/v1/query"):
			_ = r.ParseForm()
			if r.PostForm.Get("query") != "count(up)" {
				t.Errorf("probe query %q", r.PostForm.Get("query"))
			}
			w.WriteHeader(queryStatus)
			w.Write([]byte(queryResp))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

const upOK = `{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1760000000,"42"]}]}}`

func TestProbeIdentifiesFlavours(t *testing.T) {
	tests := []struct {
		name, buildinfo, query string
		flavor, version        string
		retention              float64
	}{
		{"prometheus", `{"status":"success","data":{"version":"3.5.0","revision":"abc","goVersion":"go1.24"}}`, upOK, FlavorPrometheus, "3.5.0", 360},
		{"thanos", `{"status":"success","data":{"version":"0.39.2","revision":"abc","goVersion":"go1.24"}}`, upOK, FlavorThanos, "0.39.2", 0},
		{"mimir", `{"status":"success","data":{"application":"Grafana Mimir","version":"2.16.0","revision":"x","goVersion":"go1.24"}}`, upOK, FlavorMimir, "2.16.0", 0},
		{"victoriametrics buildinfo", `{"status":"success","data":{"version":"2.24.0"}}`, upOK, FlavorVictoriaMetrics, "", 0},
		{"victoriametrics stats", "", `{"status":"success","isPartial":false,"data":{"resultType":"vector","result":[]},"stats":{"seriesFetched":"0"}}`, FlavorVictoriaMetrics, "", 0},
		{"query only", "", upOK, FlavorUnknown, "", 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := fakeServer(t, tc.buildinfo, tc.query, http.StatusOK)
			info, err := Probe(context.Background(), srv.URL+"/", nil)
			if err != nil {
				t.Fatal(err)
			}
			if info.Flavor != tc.flavor || info.Version != tc.version || info.RetentionHours != tc.retention || info.URL != srv.URL {
				t.Fatalf("got %+v", info)
			}
			if tc.query == upOK && info.UpTargets != 42 {
				t.Errorf("up targets = %d", info.UpTargets)
			}
		})
	}
}

func TestProbeRecognisesAMPByHost(t *testing.T) {
	srv := fakeServer(t, "", upOK, http.StatusOK)
	target, _ := url.Parse(srv.URL)
	// Route the AMP hostname to the fake, as a SigV4 transport would carry it to AWS.
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		r = r.Clone(r.Context())
		r.URL.Scheme, r.URL.Host = target.Scheme, target.Host
		return http.DefaultTransport.RoundTrip(r)
	})}
	info, err := Probe(context.Background(), "https://aps-workspaces.eu-west-1.amazonaws.com/workspaces/ws-1234", client)
	if err != nil {
		t.Fatal(err)
	}
	if info.Flavor != FlavorAMP {
		t.Fatalf("got %+v", info)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestProbeRejections(t *testing.T) {
	denied := fakeServer(t, "", `{"status":"error","errorType":"auth","error":"denied"}`, http.StatusForbidden)
	html := fakeServer(t, "", `<html>grafana</html>`, http.StatusOK)
	broken := fakeServer(t, "", `{"status":"error","errorType":"execution","error":"boom"}`, http.StatusInternalServerError)
	for _, tc := range []struct{ url, want string }{
		{denied.URL, "HTTP 403"},
		{html.URL, "not a Prometheus query API"},
		{broken.URL, "boom"},
		{"http://127.0.0.1:1", "unreachable"},
		{"prometheus:9090", "not an http(s) URL"},
	} {
		_, err := Probe(context.Background(), tc.url, nil)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("Probe(%s) = %v, want %q", tc.url, err, tc.want)
		}
	}
}

func TestChooseFirstHealthyInOrder(t *testing.T) {
	bad := fakeServer(t, "", `nope`, http.StatusNotFound)
	good1 := fakeServer(t, `{"status":"success","data":{"version":"3.5.0","revision":"a","goVersion":"go"}}`, upOK, http.StatusOK)
	good2 := fakeServer(t, "", upOK, http.StatusOK)

	info, rejected, err := Choose(context.Background(), []string{bad.URL, good1.URL, "http://127.0.0.1:1", good2.URL}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if info.URL != good1.URL || info.Flavor != FlavorPrometheus {
		t.Fatalf("chose %+v", info)
	}
	if len(rejected) != 2 || rejected[0].URL != bad.URL || rejected[1].URL != "http://127.0.0.1:1" || rejected[0].Reason == "" {
		t.Fatalf("rejected: %+v", rejected)
	}

	_, rejected, err = Choose(context.Background(), []string{bad.URL}, nil)
	if err == nil || len(rejected) != 1 || !strings.Contains(err.Error(), bad.URL) {
		t.Fatalf("all bad: %v %+v", err, rejected)
	}
	if _, _, err := Choose(context.Background(), nil, nil); err == nil {
		t.Fatal("no candidates should fail")
	}
}

func TestParseRetention(t *testing.T) {
	for in, want := range map[string]float64{
		"15d": 360, "6h": 6, "6h30m": 6.5, "1y": 8760, "2w": 336, "15d or 50GiB": 360, "50GiB": 0, "": 0, "abc": 0,
	} {
		if got := parseRetention(in); got != want {
			t.Errorf("parseRetention(%q) = %v, want %v", in, got, want)
		}
	}
}
