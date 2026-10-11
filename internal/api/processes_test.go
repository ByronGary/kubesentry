package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/model"
	"github.com/ByronGary/kubesentry/internal/procmon"
)

const cid = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

func procServer() (*Server, *procmon.Store) {
	st := procmon.NewStore()
	st.Now = func() time.Time { return now.Add(-10 * time.Second) }
	s := newServer(fakeCluster{pods: []model.Pod{
		{Namespace: "app", Name: "web-0", UID: "uid-web", Phase: "Running", Containers: []model.ContainerStatus{{Name: "web", ContainerID: cid}}},
		{Namespace: "app", Name: "quiet-0", UID: "uid-quiet", Phase: "Running"},
		{Namespace: "app", Name: "nouid-0", Phase: "Running"},
	}}, nil)
	s.Processes = st
	s.AgentToken = "agent-secret"
	return s, st
}

func post(s *Server, path, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func TestAgentReportAuthAndValidation(t *testing.T) {
	s, _ := procServer()
	good := `{"node":"n1","processes":[{"pid":1,"podUID":"uid-web"}]}`
	if rec := post(s, "/agent/report", "", good); rec.Code != 401 {
		t.Errorf("no token: %d, want 401", rec.Code)
	}
	if rec := post(s, "/agent/report", "wrong", good); rec.Code != 401 {
		t.Errorf("wrong token: %d, want 401", rec.Code)
	}
	if rec := post(s, "/agent/report", "agent-secret", good); rec.Code != 204 {
		t.Errorf("good: %d, want 204", rec.Code)
	}
	if rec := post(s, "/agent/report", "agent-secret", `{"processes":[]}`); rec.Code != 400 {
		t.Errorf("missing node: %d, want 400", rec.Code)
	}
	if rec := post(s, "/agent/report", "agent-secret", `not json`); rec.Code != 400 {
		t.Errorf("bad json: %d, want 400", rec.Code)
	}
	big := bytes.Repeat([]byte(" "), maxAgentBody+10)
	if rec := post(s, "/agent/report", "agent-secret", string(big)); rec.Code != 413 {
		t.Errorf("oversized: %d, want 413", rec.Code)
	}
}

func TestAgentEndpointFailsClosedWithoutToken(t *testing.T) {
	s, _ := procServer()
	s.AgentToken = ""
	if rec := post(s, "/agent/report", "", `{"node":"n"}`); rec.Code != 503 {
		t.Errorf("got %d, want 503", rec.Code)
	}
}

func TestPodProcesses(t *testing.T) {
	s, st := procServer()
	st.Update(procmon.Report{Node: "n1", Processes: []procmon.Process{
		{PID: 10, Name: "node", PodUID: "uid-web", ContainerID: cid, RSSBytes: 5 << 20, CPUMillis: 120},
		{PID: 1, Name: "pause", PodUID: "uid-web"},
		{PID: 11, Name: "sidecar", PodUID: "uid-web", ContainerID: strings.Repeat("d", 64), RSSBytes: 1 << 20},
		{PID: 99, Name: "other", PodUID: "uid-other"},
	}})

	var resp processesResponse
	if code := get(t, s, "/api/v1/pods/app/web-0/processes", &resp); code != 200 {
		t.Fatalf("status %d", code)
	}
	if !resp.Available || resp.Node != "n1" || resp.Stale || len(resp.Processes) != 3 {
		t.Fatalf("unexpected: %+v", resp)
	}
	byName := map[string]string{}
	for _, p := range resp.Processes {
		byName[p.Name] = p.Container
	}
	if byName["node"] != "web" || byName["pause"] != "pod sandbox" || byName["sidecar"] != strings.Repeat("d", 12) {
		t.Errorf("container labels wrong: %v", byName)
	}
	if resp.Processes[0].Name != "node" {
		t.Errorf("want biggest memory first, got %v", resp.Processes[0].Name)
	}

	// No agent data for the pod, a pod without a UID, an unknown pod.
	for _, path := range []string{"/api/v1/pods/app/quiet-0/processes", "/api/v1/pods/app/nouid-0/processes"} {
		var r processesResponse
		if code := get(t, s, path, &r); code != 200 || r.Available || r.Processes == nil {
			t.Errorf("%s: code %d resp %+v", path, code, r)
		}
	}
	if code := get(t, s, "/api/v1/pods/app/missing/processes", nil); code != 404 {
		t.Errorf("unknown pod: %d, want 404", code)
	}
	if code := get(t, s, "/api/v1/pods/Bad_NS/web-0/processes", nil); code != 400 {
		t.Errorf("bad name: %d, want 400", code)
	}
}

func TestPodProcessesStale(t *testing.T) {
	s, st := procServer()
	st.Now = func() time.Time { return now.Add(-10 * time.Minute) }
	st.Update(procmon.Report{Node: "n1", Processes: []procmon.Process{{PID: 1, PodUID: "uid-web"}}})
	var resp processesResponse
	get(t, s, "/api/v1/pods/app/web-0/processes", &resp)
	if !resp.Available || !resp.Stale {
		t.Fatalf("want available and stale, got %+v", resp)
	}
}

func TestProcessRoutesAbsentWhenDisabled(t *testing.T) {
	s := newServer(fakeCluster{}, nil)
	if rec := post(s, "/agent/report", "x", `{}`); rec.Code == 204 || rec.Code == 200 {
		t.Errorf("agent endpoint should not exist, got %d", rec.Code)
	}
	var info map[string]bool
	get(t, s, "/api/v1/info", &info)
	if info["processes"] {
		t.Error("info.processes should be false")
	}
}
