package demo

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/settings"
)

func send(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

type demoSettingsJSON struct {
	Values      settings.Investigator `json:"values"`
	Version     int64                 `json:"version"`
	Locked      bool                  `json:"locked"`
	Environment settings.Environment  `json:"environment"`
	Credentials settings.Credentials  `json:"credentials"`
	Setup       settings.Guide        `json:"setup"`
}

// The demo's Settings page: as if in EKS with IRSA; turning the
// investigator off hides it at once; the connection test is canned.
func TestDemoSettings(t *testing.T) {
	srv, err := NewServerWith(t.Context(), nil, Options{InvestigatorDelay: 5 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()
	const path = "/api/v1/settings/investigator"
	var st demoSettingsJSON
	getJSON(t, h, path, &st)
	if !st.Values.Enabled || st.Environment.Kind != settings.EnvEKS || st.Environment.Cluster != "demo-eks" || st.Credentials.Kind != settings.CredIRSA ||
		st.Setup.Recommended != settings.TabIRSA || st.Locked {
		t.Fatalf("settings %+v", st)
	}
	off := st.Values
	off.Enabled = false
	b, _ := json.Marshal(map[string]any{"version": st.Version, "values": off})
	if rec := send(t, h, http.MethodPut, path, string(b)); rec.Code != 200 {
		t.Fatalf("turn off: %d %s", rec.Code, rec.Body)
	}
	var info map[string]any
	getJSON(t, h, "/api/v1/info", &info)
	if _, ok := info["investigator"]; ok {
		t.Error("/info.investigator while off")
	}
	var list demoIncidentList
	getJSON(t, h, "/api/v1/incidents", &list)
	if rec := postJSON(t, h, "/api/v1/incidents/"+url.PathEscape(list.Items[0].ID)+"/investigations", ""); rec.Code != 404 {
		t.Errorf("start while off: %d", rec.Code)
	}
	// On again needs the acknowledgement.
	b, _ = json.Marshal(map[string]any{"version": st.Version + 1, "values": st.Values, "egressAcknowledged": true})
	if rec := send(t, h, http.MethodPut, path, string(b)); rec.Code != 200 {
		t.Fatalf("turn on: %d %s", rec.Code, rec.Body)
	}
	getJSON(t, h, "/api/v1/info", &info)
	if _, ok := info["investigator"]; !ok {
		t.Error("no /info.investigator once on")
	}
	var res settings.TestResult
	rec := send(t, h, http.MethodPost, path+"/test", "")
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &res) != nil || !res.OK || !strings.Contains(res.IdentityARN, "assumed-role/kubesentry-investigator") {
		t.Errorf("test: %d %s", rec.Code, rec.Body)
	}
}

func TestDemoSettingsCannedErrorsAndLocked(t *testing.T) {
	srv, err := NewServerWith(t.Context(), nil, Options{InvestigatorDelay: 5 * time.Millisecond, SettingsMode: settings.ModeLocked})
	if err != nil {
		t.Fatal(err)
	}
	st := srv.Settings.(*demoSettings)
	st.testDelay = 0
	if rec := send(t, srv.Handler(), http.MethodPut, "/api/v1/settings/investigator", `{"version":0,"reset":true}`); rec.Code != 409 {
		t.Errorf("locked PUT: %d", rec.Code)
	}
	v := demoHelm()
	v.Region = "eu-west-1"
	if r := st.Test(t.Context(), v); r.OK || r.Error == nil || r.Error.Kind != "model_access" {
		t.Errorf("eu-west-1: %+v", r)
	}
	v.Provider = settings.ProviderAnthropic
	if r := st.Test(t.Context(), v); r.OK || r.Error == nil || r.Error.Kind != "auth" || r.IdentityARN != "" {
		t.Errorf("anthropic: %+v", r)
	}
}
