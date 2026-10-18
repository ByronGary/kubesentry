package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/auth"
	"github.com/ByronGary/kubesentry/internal/investigate"
	"github.com/ByronGary/kubesentry/internal/settings"
)

// fakeSettings is SettingsService over a real manager, with a canned
// environment and connection test.
type fakeSettings struct {
	m     *settings.Manager
	mu    sync.Mutex
	tests []settings.Investigator
}

func (f *fakeSettings) State(ctx context.Context) (*settings.State, error) { return f.m.State(ctx) }
func (f *fakeSettings) Mode() string                                       { return f.m.Mode() }
func (f *fakeSettings) Save(ctx context.Context, r settings.SaveRequest) (*settings.State, error) {
	return f.m.Save(ctx, r)
}
func (f *fakeSettings) Context(context.Context) (settings.Environment, settings.Credentials) {
	return settings.Environment{Kind: settings.EnvEKS, Cluster: "prod-eks", Region: "us-east-1", Namespace: "kubesentry", ServiceAccount: "kubesentry"},
		settings.Credentials{Kind: settings.CredIRSA, RoleARN: "arn:aws:iam::111122223333:role/kubesentry", AccountID: "111122223333"}
}
func (f *fakeSettings) Test(_ context.Context, s settings.Investigator) settings.TestResult {
	f.mu.Lock()
	f.tests = append(f.tests, s)
	f.mu.Unlock()
	return settings.TestResult{OK: true, Provider: s.Provider, Model: s.ModelID(), IdentityARN: "arn:aws:sts::111122223333:assumed-role/kubesentry/x"}
}

func helmSettings() settings.Investigator {
	return settings.Investigator{Provider: settings.ProviderBedrock, Effort: "high", BedrockAPI: settings.BedrockMantle, Fallback: "auto",
		Limits: settings.Limits{PerHour: 10, PerHourTotal: 60, Concurrency: 2, MaxTurns: 16, MaxToolCalls: 24, MaxTokens: 1_500_000,
			Timeout: settings.Duration(10 * time.Minute)}}
}

func newFakeSettings(t *testing.T, mode string, applied *[]settings.Investigator) *fakeSettings {
	t.Helper()
	m, err := settings.NewManager(settings.ManagerConfig{Store: settings.NewMemoryStore(), Helm: helmSettings(), Mode: mode,
		Env: func() settings.Env { return settings.Env{Incidents: true, DefaultRegion: "us-east-1"} },
		Apply: func(_ context.Context, s settings.Investigator) (settings.Commit, error) {
			return func() {
				if applied != nil {
					*applied = append(*applied, s)
				}
			}, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	return &fakeSettings{m: m}
}

// settingsServer is the tenant server with settings; erin holds
// EditSettings, alice and carol do not.
func settingsServer(t *testing.T, mode string, applied *[]settings.Investigator) (*Server, *fakeSettings) {
	t.Helper()
	s := tenantServer(t)
	g := tenantGrants()
	g[grant("erin", auth.EditSettings, "")] = true
	s.Authorizer = &auth.SARAuthorizer{Reviewer: g, Candidates: s.Authorizer.(*auth.SARAuthorizer).Candidates}
	fs := newFakeSettings(t, mode, applied)
	s.Settings = fs
	return s, fs
}

func sendAs(t *testing.T, h http.Handler, method, user, path, body string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if user != "" {
		req.Header.Set("X-Forwarded-Email", user)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

type settingsJSON struct {
	Values      settings.Investigator      `json:"values"`
	Sources     map[string]settings.Source `json:"sources"`
	Version     int64                      `json:"version"`
	Locked      bool                       `json:"locked"`
	Audit       []settings.AuditEntry      `json:"audit"`
	Credentials settings.Credentials       `json:"credentials"`
	Environment settings.Environment       `json:"environment"`
	Setup       settings.Guide             `json:"setup"`
	Applied     settings.Applied           `json:"applied"`
	Options     map[string][]string        `json:"options"`
}

func TestSettingsRoutes(t *testing.T) {
	var applied []settings.Investigator
	s, fs := settingsServer(t, settings.ModeUI, &applied)
	h := s.Handler()
	const path = "/api/v1/settings/investigator"

	rec := sendAs(t, h, http.MethodGet, "erin", path, "", nil)
	var got settingsJSON
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &got) != nil {
		t.Fatalf("GET = %d %s", rec.Code, rec.Body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" || got.Version != 0 || got.Values.Enabled || got.Sources["enabled"].Source != "helm" ||
		got.Credentials.Kind != settings.CredIRSA || got.Environment.Kind != settings.EnvEKS || got.Setup.Recommended != settings.TabIRSA ||
		len(got.Setup.Tabs) != 4 || len(got.Options["efforts"]) != 5 {
		t.Errorf("GET: %s", rec.Body)
	}
	// /info names the page.
	var info map[string]any
	getAs(t, h, "erin", "/api/v1/info", &info)
	if st, _ := info["settings"].(map[string]any); st["investigator"] != true || st["mode"] != "ui" {
		t.Errorf("/info settings = %v", info["settings"])
	}
	if caps, _ := info["capabilities"].(map[string]any); caps["settings"] != true {
		t.Errorf("erin's capabilities %v", info["capabilities"])
	}

	on := got.Values
	on.Enabled = true
	body := func(v any) string { b, _ := json.Marshal(v); return string(b) }
	// Turning it on needs the acknowledgement.
	rec = sendAs(t, h, http.MethodPut, "erin", path, body(map[string]any{"version": 0, "values": on}), nil)
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), `"egressAckRequired":true`) {
		t.Errorf("no ack: %d %s", rec.Code, rec.Body)
	}
	rec = sendAs(t, h, http.MethodPut, "erin", path, body(map[string]any{"version": 0, "values": on, "egressAcknowledged": true}), nil)
	got = settingsJSON{}
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &got) != nil || got.Version != 1 || !got.Values.Enabled ||
		got.Sources["enabled"].By != "erin" || len(got.Audit) != 1 || !got.Audit[0].EgressAcknowledged || !got.Applied.Enabled {
		t.Fatalf("save: %d %s", rec.Code, rec.Body)
	}
	if len(applied) != 2 || !applied[1].Enabled {
		t.Errorf("applied %+v", applied)
	}
	// A stale version is 409 with the current one.
	rec = sendAs(t, h, http.MethodPut, "erin", path, body(map[string]any{"version": 0, "values": on}), nil)
	if rec.Code != 409 || !strings.Contains(rec.Body.String(), `"version":1`) {
		t.Errorf("stale: %d %s", rec.Code, rec.Body)
	}
	// Invalid values name their fields.
	bad := on
	bad.Limits.MaxTurns = 0
	rec = sendAs(t, h, http.MethodPut, "erin", path, body(map[string]any{"version": 1, "values": bad}), nil)
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), `"field":"limits.maxTurns"`) {
		t.Errorf("invalid: %d %s", rec.Code, rec.Body)
	}
	// The body rules: JSON, known fields.
	if rec := sendAs(t, h, http.MethodPut, "erin", path, `{"version":1,"apiKey":"sk-ant-x"}`, nil); rec.Code != 400 {
		t.Errorf("unknown field: %d", rec.Code)
	}
	if rec := sendAs(t, h, http.MethodPut, "erin", path, `{"version":1}`, nil); rec.Code != 400 {
		t.Errorf("no values: %d", rec.Code)
	}
	if rec := sendAs(t, h, http.MethodPut, "erin", path, `{}`, map[string]string{"Content-Type": "text/plain"}); rec.Code != 415 {
		t.Errorf("text body: %d", rec.Code)
	}
	// Reset to the Helm values.
	rec = sendAs(t, h, http.MethodPut, "erin", path, `{"version":1,"reset":true}`, nil)
	got = settingsJSON{}
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &got) != nil || got.Values.Enabled || got.Version != 2 || got.Audit[0].Action != "reset" {
		t.Errorf("reset: %d %s", rec.Code, rec.Body)
	}

	// Test connection: the posted values, unsaved; once per 10s.
	rt := on
	rt.Model = "us.anthropic.claude-opus-5-5"
	rec = sendAs(t, h, http.MethodPost, "erin", path+"/test", body(map[string]any{"values": rt}), nil)
	var res settings.TestResult
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &res) != nil || !res.OK || res.Model != "us.anthropic.claude-opus-5-5" {
		t.Errorf("test: %d %s", rec.Code, rec.Body)
	}
	rec = sendAs(t, h, http.MethodPost, "erin", path+"/test", "", nil)
	if rec.Code != 429 || rec.Header().Get("Retry-After") == "" {
		t.Errorf("second test: %d %v", rec.Code, rec.Header())
	}
	if len(fs.tests) != 1 {
		t.Errorf("tests run: %d", len(fs.tests))
	}
	s.Now = func() time.Time { return now.Add(11 * time.Second) }
	if rec := sendAs(t, h, http.MethodPost, "erin", path+"/test", "", nil); rec.Code != 200 || len(fs.tests) != 2 || fs.tests[1].Enabled {
		t.Errorf("test after 11s (current values): %d", rec.Code)
	}
	bad.Limits.MaxTurns = 0
	s.Now = func() time.Time { return now.Add(30 * time.Second) }
	if rec := sendAs(t, h, http.MethodPost, "erin", path+"/test", body(map[string]any{"values": bad}), nil); rec.Code != 400 {
		t.Errorf("test of invalid values: %d", rec.Code)
	}

	// Without EditSettings: 403 everywhere, reading included.
	for _, user := range []string{"alice", "carol"} {
		for _, c := range []struct{ method, path, body string }{
			{http.MethodGet, path, ""}, {http.MethodPut, path, `{"version":2,"reset":true}`}, {http.MethodPost, path + "/test", ""},
		} {
			if rec := sendAs(t, h, c.method, user, c.path, c.body, nil); rec.Code != 403 || strings.Contains(rec.Body.String(), "arn:") {
				t.Errorf("%s %s as %s = %d %s", c.method, c.path, user, rec.Code, rec.Body)
			}
		}
	}
	// Cross-origin writes are refused before anything else.
	for _, hdr := range []map[string]string{{"Origin": "https://evil.example"}, {"Sec-Fetch-Site": "cross-site"}} {
		if rec := sendAs(t, h, http.MethodPut, "erin", path, `{"version":2,"reset":true}`, hdr); rec.Code != 403 ||
			!strings.Contains(rec.Body.String(), "cross-origin") {
			t.Errorf("cross-origin %v: %d %s", hdr, rec.Code, rec.Body)
		}
		if rec := sendAs(t, h, http.MethodPost, "erin", path+"/test", "", hdr); rec.Code != 403 {
			t.Errorf("cross-origin test %v: %d", hdr, rec.Code)
		}
	}
}

func TestSettingsLocked(t *testing.T) {
	s, _ := settingsServer(t, settings.ModeLocked, nil)
	h := s.Handler()
	var got settingsJSON
	rec := sendAs(t, h, http.MethodGet, "erin", "/api/v1/settings/investigator", "", nil)
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &got) != nil || !got.Locked {
		t.Fatalf("GET locked: %d %s", rec.Code, rec.Body)
	}
	rec = sendAs(t, h, http.MethodPut, "erin", "/api/v1/settings/investigator", `{"version":0,"reset":true}`, nil)
	if rec.Code != 409 || !strings.Contains(rec.Body.String(), `"locked":true`) || !strings.Contains(rec.Body.String(), "locked by Helm") {
		t.Errorf("PUT locked: %d %s", rec.Code, rec.Body)
	}
	var info map[string]any
	getAs(t, h, "erin", "/api/v1/info", &info)
	if st, _ := info["settings"].(map[string]any); st["mode"] != "locked" {
		t.Errorf("/info settings %v", info["settings"])
	}
}

// Off, the investigator answers starts 404 and leaves /info, but its past
// runs stay readable.
func TestInvestigatorDisabled(t *testing.T) {
	s, _, _ := investigatorServer(t, submitting(), invOpts{}, grant("alice", auth.InvestigateIncidents, "team-a"))
	runs := seedInvestigations(t, s)
	h := s.Handler()
	if err := s.Investigations.(*investigate.Service).Reconfigure(nil); err != nil {
		t.Fatal(err)
	}
	rec := postAs(t, h, "alice", invPath(incidentID("team-a")), "", nil)
	if rec.Code != 404 || !strings.Contains(rec.Body.String(), "the AI investigator is off") {
		t.Errorf("start while off: %d %s", rec.Code, rec.Body)
	}
	var info map[string]any
	getAs(t, h, "alice", "/api/v1/info", &info)
	if _, ok := info["investigator"]; ok {
		t.Errorf("/info investigator while off: %v", info["investigator"])
	}
	if rec := getAs(t, h, "alice", invPath(incidentID("team-a"), "/", runs[incidentID("team-a")]), nil); rec.Code != 200 {
		t.Errorf("a past run while off: %d", rec.Code)
	}
}
