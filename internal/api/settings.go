package api

// The Settings page's routes (docs/contracts.md "Settings (M7b)"):
// GET /api/v1/settings/investigator shows the AI investigator's settings,
// where each value comes from, the detected environment and credential
// source, the generated setup steps and the newest audit entries; PUT saves
// an admin's change (optimistic concurrency on the version); POST …/test
// tests the connection with the current or the posted, unsaved values.
// Everything needs EditSettings cluster-wide (reading too: role ARNs and the
// audit) and answers no-store.

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/ByronGary/kubesentry/internal/auth"
	"github.com/ByronGary/kubesentry/internal/settings"
)

// SettingsService is the investigator's settings (cmd/server's wiring of a
// settings.Manager, the environment and the connection test).
type SettingsService interface {
	State(ctx context.Context) (*settings.State, error)
	// Mode is ui or locked (cheap: /info asks).
	Mode() string
	Save(ctx context.Context, req settings.SaveRequest) (*settings.State, error)
	// Context is where kubesentry runs and where its credentials come from,
	// as detected now.
	Context(ctx context.Context) (settings.Environment, settings.Credentials)
	// Test tests the connection with s (not saved).
	Test(ctx context.Context, s settings.Investigator) settings.TestResult
}

const (
	settingsRoute     = "GET /api/v1/settings/investigator"
	settingsSaveRoute = "PUT /api/v1/settings/investigator"
	settingsTestRoute = "POST /api/v1/settings/investigator/test"
)

// SettingsTestInterval is how often one identity may test the connection.
const SettingsTestInterval = 10 * time.Second

// settingsOptions are the choices the page offers.
type settingsOptions struct {
	Providers   []string `json:"providers"`
	BedrockAPIs []string `json:"bedrockAPIs"`
	Efforts     []string `json:"efforts"`
	Fields      []string `json:"fields"`
}

// investigatorSettingsResponse mirrors web/src/types.ts
// InvestigatorSettings.
type investigatorSettingsResponse struct {
	*settings.State
	Environment settings.Environment `json:"environment"`
	Credentials settings.Credentials `json:"credentials"`
	Setup       settings.Guide       `json:"setup"`
	Options     settingsOptions      `json:"options"`
}

// infoSettings is /info's settings field.
type infoSettings struct {
	// Investigator: the investigator's settings page exists.
	Investigator bool `json:"investigator"`
	// Mode is ui or locked.
	Mode string `json:"mode"`
}

func (s *Server) infoSettings() *infoSettings {
	if s.Settings == nil {
		return nil
	}
	return &infoSettings{Investigator: true, Mode: s.Settings.Mode()}
}

func (s *Server) settingsRoutes(mux *http.ServeMux, t, long time.Duration) {
	s.route(mux, settingsRoute, "settings_investigator", t, s.settingsGet)
	mux.Handle(settingsSaveRoute, Compose(WithMetrics("settings_investigator_save"), WithTimeout(long))(http.HandlerFunc(s.settingsSave)))
	mux.Handle(settingsTestRoute, Compose(WithMetrics("settings_investigator_test"), WithTimeout(long))(http.HandlerFunc(s.settingsTest)))
}

// maySettings answers 403 unless the caller holds EditSettings.
func (s *Server) maySettings(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Cache-Control", "no-store")
	if !s.can(r, auth.EditSettings) {
		writeError(w, http.StatusForbidden, "the settings need update on settings.kubesentry.io (the kubesentry settings admin role)")
		return false
	}
	return true
}

func (s *Server) settingsResponse(ctx context.Context, st *settings.State) investigatorSettingsResponse {
	env, creds := s.Settings.Context(ctx)
	return investigatorSettingsResponse{State: st, Environment: env, Credentials: creds,
		Setup: settings.Setup(settings.SetupInput{Env: env, Creds: creds, Settings: st.Values, DefaultRegion: st.DefaultRegion}),
		Options: settingsOptions{Providers: []string{settings.ProviderBedrock, settings.ProviderAnthropic},
			BedrockAPIs: []string{settings.BedrockMantle, settings.BedrockRuntime}, Efforts: settings.Efforts, Fields: settings.Fields()}}
}

func (s *Server) settingsGet(w http.ResponseWriter, r *http.Request) {
	if !s.maySettings(w, r) {
		return
	}
	st, err := s.Settings.State(r.Context())
	if err != nil {
		upstreamError(w, "the settings store", err)
		return
	}
	writeJSON(w, http.StatusOK, s.settingsResponse(r.Context(), st))
}

// settingsSaveRequest mirrors web/src/types.ts InvestigatorSettingsSave.
type settingsSaveRequest struct {
	Version            int64                  `json:"version"`
	Values             *settings.Investigator `json:"values,omitempty"`
	Reset              bool                   `json:"reset,omitempty"`
	EgressAcknowledged bool                   `json:"egressAcknowledged,omitempty"`
}

func (s *Server) settingsSave(w http.ResponseWriter, r *http.Request) {
	if !s.maySettings(w, r) {
		return
	}
	var req settingsSaveRequest
	if !decodeJSON(w, r, maxJSONBody, &req) {
		return
	}
	if req.Values == nil && !req.Reset {
		writeError(w, http.StatusBadRequest, "give values, or reset: true")
		return
	}
	sr := settings.SaveRequest{Actor: identityName(r), Version: req.Version, Reset: req.Reset, EgressAcknowledged: req.EgressAcknowledged}
	if req.Values != nil {
		sr.Values = *req.Values
	}
	st, err := s.Settings.Save(r.Context(), sr)
	var ve *settings.ValidationError
	var ae *settings.ApplyError
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, s.settingsResponse(r.Context(), st))
	case errors.Is(err, settings.ErrLocked):
		writeJSON(w, http.StatusConflict, map[string]any{"error": "the settings are locked by Helm (incidents.investigator.settings: locked): change the chart's values instead",
			"locked": true})
	case errors.Is(err, settings.ErrConflict):
		body := map[string]any{"error": "the settings were changed by someone else since you loaded them; reload and try again"}
		if cur, err := s.Settings.State(r.Context()); err == nil {
			body["version"] = cur.Version
		}
		writeJSON(w, http.StatusConflict, body)
	case errors.Is(err, settings.ErrEgressAck):
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "turning the investigator on needs the data egress acknowledgement",
			"egressAckRequired": true})
	case errors.As(err, &ve):
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": ve.Error(), "fields": ve.Fields})
	case errors.As(err, &ae):
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": ae.Error()})
	default:
		upstreamError(w, "the settings store", err)
	}
}

// settingsTestRequest mirrors web/src/types.ts InvestigatorSettingsTest.
type settingsTestRequest struct {
	Values *settings.Investigator `json:"values,omitempty"`
}

// testLimiter lets each identity test once per interval.
type testLimiter struct {
	mu   sync.Mutex
	last map[string]time.Time
}

// allow reports whether key may test now, or how long to wait.
func (l *testLimiter) allow(key string, now time.Time, every time.Duration) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.last == nil {
		l.last = map[string]time.Time{}
	}
	for k, t := range l.last {
		if now.Sub(t) >= every {
			delete(l.last, k)
		}
	}
	if t, ok := l.last[key]; ok {
		return false, every - now.Sub(t)
	}
	l.last[key] = now
	return true, 0
}

func (s *Server) settingsTest(w http.ResponseWriter, r *http.Request) {
	if !s.maySettings(w, r) {
		return
	}
	var req settingsTestRequest
	if !optionalJSON(w, r, &req) {
		return
	}
	key := auth.AnonymousUser
	if id, ok := auth.FromContext(r.Context()); ok {
		key = id.Key()
	}
	if ok, wait := s.settingsTests.allow(key, s.now(), SettingsTestInterval); !ok {
		retryAfter(w, wait)
		writeError(w, http.StatusTooManyRequests, "test the connection at most once every 10 seconds")
		return
	}
	st, err := s.Settings.State(r.Context())
	if err != nil {
		upstreamError(w, "the settings store", err)
		return
	}
	values := st.Values
	if req.Values != nil {
		values = *req.Values
		check := values
		check.Enabled = false // a test of settings that are off is fine
		var ve *settings.ValidationError
		if err := check.Validate(settings.Env{}); errors.As(err, &ve) {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": ve.Error(), "fields": ve.Fields})
			return
		}
	}
	writeJSON(w, http.StatusOK, s.Settings.Test(r.Context(), values))
}
