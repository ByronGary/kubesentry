package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/audit"
)

// overloadedStore fails every read the way pgstore does when its read slots
// stay busy or a query runs past its limit; its Coverage hangs until the
// caller gives up.
type overloadedStore struct{}

func (overloadedStore) Add(context.Context, []audit.Event) error { return nil }

func (overloadedStore) Query(context.Context, audit.Query) ([]audit.Event, error) {
	return nil, fmt.Errorf("pgstore: query: %w: all 8 read slots stayed busy for 2s", audit.ErrOverloaded)
}

func (overloadedStore) Summarize(context.Context, audit.Query) (audit.Summary, error) {
	return audit.Summary{}, fmt.Errorf("pgstore: summarize: %w: no answer within 10s", audit.ErrOverloaded)
}

func (overloadedStore) Coverage(ctx context.Context) (audit.Coverage, error) {
	<-ctx.Done()
	return audit.Coverage{}, ctx.Err()
}

// An overloaded audit store answers 503 with Retry-After at once, rather
// than holding the request until the route or the SSO proxy times out (502
// at oauth2-proxy in stress checkpoint D). /info never waits on it.
func TestAuditStoreOverloadIs503(t *testing.T) {
	s := newServer(fakeCluster{}, nil)
	s.Audit = activeBackend{overloadedStore{}}
	h := s.Handler()
	for _, path := range []string{"/api/v1/audit/events", "/api/v1/audit/summary"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
			t.Errorf("%s = %d (Retry-After %q), want 503 with Retry-After", path, rec.Code, rec.Header().Get("Retry-After"))
		}
		if strings.Contains(rec.Body.String(), "slots") || strings.Contains(rec.Body.String(), "pgstore") {
			t.Errorf("%s leaks store internals: %s", path, rec.Body.String())
		}
	}

	start := time.Now()
	var info infoResponse
	if code := get(t, s, "/api/v1/info", &info); code != 200 {
		t.Fatalf("info = %d", code)
	}
	if took := time.Since(start); took > time.Second {
		t.Errorf("/info took %s waiting for the audit coverage; it may wait %s", took, infoCoverageWait)
	}
	if info.AuditStore != nil {
		t.Errorf("auditStore = %+v, want it left out while the store cannot say", info.AuditStore)
	}
}
