package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ByronGary/kubesentry/internal/audit"
)

func ev(id, verb, user, resource, ns string, code int, ts string) string {
	return fmt.Sprintf(`{"auditID":%q,"stage":"ResponseComplete","verb":%q,"user":{"username":%q},`+
		`"objectRef":{"resource":%q,"namespace":%q},"responseStatus":{"code":%d},"requestReceivedTimestamp":%q}`,
		id, verb, user, resource, ns, code, ts)
}

func eventList(events ...string) string {
	return `{"kind":"EventList","apiVersion":"audit.k8s.io/v1","items":[` + strings.Join(events, ",") + `]}`
}

func doReq(t *testing.T, s *Server, method, path, token, body string, out any) int {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if out != nil {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			t.Fatalf("decode %q: %v", rec.Body.String(), err)
		}
	}
	return rec.Code
}

func auditServer(t *testing.T) *Server {
	t.Helper()
	s := newServer(fakeCluster{}, nil)
	s.Audit = &audit.Ingester{Store: audit.NewMemoryStore(100)}
	s.AuditToken = "webhook-secret"

	payload := eventList(
		ev("e1", "create", "alice", "deployments", "prod", 201, "2026-10-10T10:00:00Z"),
		ev("e2", "get", "alice", "secrets", "prod", 200, "2026-10-10T10:05:00Z"),
		ev("e3", "get", "alice", "pods", "prod", 200, "2026-10-10T10:10:00Z"),
		ev("e4", "update", "system:kube-controller-manager", "leases", "kube-system", 200, "2026-10-10T10:15:00Z"),
		ev("e5", "delete", "system:serviceaccount:ci:deployer", "pods", "ci", 200, "2026-10-10T10:20:00Z"),
		ev("e6", "get", "system:anonymous", "pods", "prod", 403, "2026-10-10T10:30:00Z"),
		ev("old", "create", "alice", "pods", "prod", 201, "2026-10-08T10:00:00Z"),
	)
	if code := doReq(t, s, http.MethodPost, "/audit/webhook", "webhook-secret", payload, nil); code != 200 {
		t.Fatalf("seeding webhook returned %d", code)
	}
	return s
}

func auditIDs(t *testing.T, s *Server, query string) string {
	t.Helper()
	var resp auditEventsResponse
	if code := doReq(t, s, http.MethodGet, "/api/v1/audit/events"+query, "", "", &resp); code != 200 {
		t.Fatalf("GET events%s = %d", query, code)
	}
	var ids []string
	for _, e := range resp.Items {
		ids = append(ids, e.AuditID)
	}
	if resp.Count != len(ids) {
		t.Errorf("count %d != len(items) %d", resp.Count, len(ids))
	}
	return strings.Join(ids, ",")
}

func TestAuditWebhookAuth(t *testing.T) {
	s := newServer(fakeCluster{}, nil)
	s.Audit = &audit.Ingester{Store: audit.NewMemoryStore(10)}
	body := eventList(ev("x", "create", "alice", "pods", "a", 201, "2026-10-10T10:00:00Z"))

	// Fails closed with no token configured, even for a request that sends one.
	if code := doReq(t, s, http.MethodPost, "/audit/webhook", "anything", body, nil); code != http.StatusServiceUnavailable {
		t.Errorf("no token configured: status %d, want 503", code)
	}

	s.AuditToken = "right"
	if code := doReq(t, s, http.MethodPost, "/audit/webhook", "", body, nil); code != http.StatusUnauthorized {
		t.Errorf("missing token: status %d, want 401", code)
	}
	if code := doReq(t, s, http.MethodPost, "/audit/webhook", "wrong", body, nil); code != http.StatusUnauthorized {
		t.Errorf("wrong token: status %d, want 401", code)
	}

	var ok map[string]int
	if code := doReq(t, s, http.MethodPost, "/audit/webhook", "right", body, &ok); code != 200 || ok["accepted"] != 1 {
		t.Errorf("valid request: status %d, body %v", code, ok)
	}
	if code := doReq(t, s, http.MethodPost, "/audit/webhook", "right", "{nope", nil); code != http.StatusBadRequest {
		t.Errorf("malformed payload: status %d, want 400", code)
	}
	// The API token must not open the webhook, and vice versa.
	s.APIToken = "reader"
	if code := doReq(t, s, http.MethodPost, "/audit/webhook", "reader", body, nil); code != http.StatusUnauthorized {
		t.Errorf("api token on webhook: status %d, want 401", code)
	}
}

func TestAuditEventsDefaultViewAndFilters(t *testing.T) {
	s := auditServer(t)

	// Newest first. Hidden: e3 (untagged read), e4 (system actor), old (outside 24h).
	if got := auditIDs(t, s, ""); got != "e6,e5,e2,e1" {
		t.Errorf("default view = %s, want e6,e5,e2,e1", got)
	}
	if got := auditIDs(t, s, "?includeReads=true"); got != "e6,e5,e3,e2,e1" {
		t.Errorf("includeReads = %s", got)
	}
	if got := auditIDs(t, s, "?since=100h"); got != "e6,e5,e2,e1,old" {
		t.Errorf("since=100h = %s", got)
	}
	if got := auditIDs(t, s, "?actors=system&includeReads=true"); got != "e6,e4" {
		t.Errorf("actors=system = %s", got)
	}
	if got := auditIDs(t, s, "?user=alice"); got != "e2,e1" {
		t.Errorf("user=alice = %s", got)
	}
	if got := auditIDs(t, s, "?tag=denied"); got != "e6" {
		t.Errorf("tag=denied = %s", got)
	}
	if got := auditIDs(t, s, "?namespace=ci"); got != "e5" {
		t.Errorf("namespace=ci = %s", got)
	}
	if got := auditIDs(t, s, "?limit=2"); got != "e6,e5" {
		t.Errorf("limit=2 = %s", got)
	}
	var none auditEventsResponse
	doReq(t, s, http.MethodGet, "/api/v1/audit/events?user=nobody", "", "", &none)
	if none.Items == nil || none.Count != 0 {
		t.Errorf("empty result should be [] not null: %+v", none)
	}
}

func TestAuditEventsBadParams(t *testing.T) {
	s := auditServer(t)
	for _, q := range []string{"?actors=root", "?limit=0", "?limit=-1", "?limit=x", "?since=tomorrow", "?since=1s", "?includeReads=maybe", "?continue=garbage", "?continue=djE6MDp4"} {
		if code := doReq(t, s, http.MethodGet, "/api/v1/audit/events"+q, "", "", nil); code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", q, code)
		}
	}
	// A limit above the maximum is clamped, not refused.
	if code := doReq(t, s, http.MethodGet, "/api/v1/audit/events?limit=5000", "", "", nil); code != http.StatusOK {
		t.Errorf("limit=5000: status %d, want 200", code)
	}
}

func TestAuditSummary(t *testing.T) {
	s := auditServer(t)
	var sum auditSummaryResponse
	if code := doReq(t, s, http.MethodGet, "/api/v1/audit/summary", "", "", &sum); code != 200 {
		t.Fatalf("status %d", code)
	}
	// Counts reads, covers users and service accounts, skips system components.
	if sum.TotalEvents != 4 || sum.Window != "24h0m0s" {
		t.Errorf("summary = %+v", sum)
	}
	if len(sum.Users) != 2 || sum.Users[0].Username != "alice" || sum.Users[0].Total != 3 || sum.Users[0].SecretAccess != 1 {
		t.Errorf("users = %+v", sum.Users)
	}
	if sum.ByTag[audit.TagSecretAccess] != 1 || sum.ByTag[audit.TagDelete] != 1 {
		t.Errorf("byTag = %v", sum.ByTag)
	}
}

func TestAPITokenGuardsReadRoutesOnly(t *testing.T) {
	s := auditServer(t)
	s.APIToken = "reader"
	for _, path := range []string{"/api/v1/audit/events", "/api/v1/audit/summary", "/api/v1/oom", "/api/v1/pvcs/unused"} {
		if code := doReq(t, s, http.MethodGet, path, "", "", nil); code != http.StatusUnauthorized {
			t.Errorf("%s without token: %d, want 401", path, code)
		}
		if code := doReq(t, s, http.MethodGet, path, "reader", "", nil); code != 200 {
			t.Errorf("%s with token: %d, want 200", path, code)
		}
	}
	if code := doReq(t, s, http.MethodGet, "/healthz", "", "", nil); code != 200 {
		t.Errorf("/healthz should stay open, got %d", code)
	}
}

func TestAuditRoutesAbsentWhenDisabled(t *testing.T) {
	s := newServer(fakeCluster{}, nil)
	if code := doReq(t, s, http.MethodGet, "/api/v1/audit/events", "", "", nil); code != http.StatusNotFound {
		t.Errorf("status %d, want 404 when audit is disabled", code)
	}
}
