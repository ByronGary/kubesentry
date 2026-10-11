package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A Prometheus that cannot be queried shows in /info's unavailable and in
// the ops /readyz's degraded, without failing readiness: it is optional.
func TestPrometheusOutageShows(t *testing.T) {
	var down error
	s := newServer(fakeCluster{}, nil)
	s.PrometheusHealth = func() error { return down }
	ops := s.Serve(Parts{Probes: true})
	readyz := func(h http.Handler) (int, readyResponse) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		var r readyResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &r)
		return rec.Code, r
	}

	var info infoResponse
	get(t, s, "/api/v1/info", &info)
	if _, ok := info.Unavailable["prometheus"]; ok {
		t.Errorf("unavailable = %v while Prometheus answers", info.Unavailable)
	}
	if code, r := readyz(ops); code != 200 || len(r.Degraded) != 0 {
		t.Errorf("readyz = %d %+v while Prometheus answers", code, r)
	}

	down = errors.New("queries fail: HTTP 503 Service Unavailable")
	info = infoResponse{}
	get(t, s, "/api/v1/info", &info)
	if info.Unavailable["prometheus"] != down.Error() {
		t.Errorf("unavailable = %v, want prometheus: %v", info.Unavailable, down)
	}
	code, r := readyz(ops)
	if code != 200 || r.Status != "ready" || r.Degraded["prometheus"] != down.Error() {
		t.Errorf("readyz = %d %+v, want 200 with degraded prometheus", code, r)
	}
	// The web listener's /readyz keeps dependency errors to itself.
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != 200 || strings.Contains(rec.Body.String(), "prometheus") {
		t.Errorf("web readyz = %d %s", rec.Code, rec.Body.String())
	}
}
