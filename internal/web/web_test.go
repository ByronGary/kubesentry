package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func do(method, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

func TestServesIndexUncached(t *testing.T) {
	rec := do(http.MethodGet, "/")
	if rec.Code != 200 || !strings.Contains(strings.ToLower(rec.Body.String()), "<!doctype html>") {
		t.Fatalf("GET / = %d %q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-cache" {
		t.Errorf("index Cache-Control = %q, want no-cache", got)
	}
}

func TestUnknownPathsAre404(t *testing.T) {
	for _, p := range []string{"/nope.js", "/api/v1/unknown", "/audit/unknown", "/assets/missing.js"} {
		if code := do(http.MethodGet, p).Code; code != 404 {
			t.Errorf("GET %s = %d, want 404", p, code)
		}
	}
}

func TestOnlyReadMethods(t *testing.T) {
	if code := do(http.MethodPost, "/").Code; code != http.StatusMethodNotAllowed {
		t.Errorf("POST / = %d, want 405", code)
	}
	if code := do(http.MethodHead, "/").Code; code != 200 {
		t.Errorf("HEAD / = %d, want 200", code)
	}
}
