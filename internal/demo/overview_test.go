package demo

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// demoOverview is the part of the overview response the demo test reads.
type demoOverview struct {
	Scope struct {
		Owner      string `json:"owner"`
		Namespaces int    `json:"namespaces"`
	} `json:"scope"`
	Nodes *struct {
		Total, NotReady int
		Pools           []struct {
			Name, Kind      string
			Nodes           int
			CPURequestedPct *float64 `json:"cpuRequestedPct"`
		} `json:"pools"`
		Zones []struct{ Name string } `json:"zones"`
	} `json:"nodes"`
	Pods struct {
		Failing  int            `json:"failing"`
		ByReason map[string]int `json:"byReason"`
	} `json:"pods"`
	Certificates *struct{ ExpiringSoon, NotReady int } `json:"certificates"`
	Security     struct {
		Crit        int  `json:"crit"`
		NewSince24h *int `json:"newSince24h"`
	} `json:"security"`
	Attention []struct{ Severity, Kind, Namespace, Name, Title, Owner, Href string } `json:"attention"`
	Activity  *struct {
		Exec, ExecProduction, SecretReads, RBACChanges, Denied int
		Latest                                                 []struct{ Username, Namespace string }
	} `json:"activity"`
	Waste struct {
		UnusedPVCs  int     `json:"unusedPVCs"`
		MonthlyUSD  float64 `json:"monthlyUSD"`
		UsageBilled int     `json:"usageBilled"`
	} `json:"waste"`
	Owners []string `json:"owners"`
	Badges map[string]struct {
		Count    int
		Severity string
	} `json:"badges"`
	History struct {
		StepSeconds int                `json:"stepSeconds"`
		Series      map[string][]int64 `json:"series"`
	} `json:"history"`
}

// The demo's overview tells the same story as its pages: owners on most
// namespaces, exec into production, a crash loop and leaks needing
// attention, and a day of history.
func TestDemoOverview(t *testing.T) {
	srv, err := NewServer(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/overview", nil))
	var pretty bytes.Buffer
	_ = json.Indent(&pretty, rec.Body.Bytes(), "", "  ")
	t.Logf("GET /api/v1/overview (%d bytes):\n%s", rec.Body.Len(), pretty.String())

	var o demoOverview
	getJSON(t, h, "/api/v1/overview", &o)
	if strings.Join(o.Owners, ",") != "team-data,team-platform,team-shop" {
		t.Errorf("owners = %v", o.Owners)
	}
	if a := o.Activity; a == nil || a.ExecProduction != 3 || a.Exec != 3 || a.RBACChanges < 1 || a.SecretReads < 1 || len(a.Latest) == 0 {
		t.Errorf("activity = %+v", o.Activity)
	}
	if len(o.Attention) == 0 || o.Attention[0].Severity != "crit" {
		t.Fatalf("attention = %+v", o.Attention)
	}
	kinds := map[string]bool{}
	for _, a := range o.Attention {
		kinds[a.Kind] = true
		if a.Namespace == "prod" && a.Owner != "team-shop" {
			t.Errorf("prod item without its owner: %+v", a)
		}
	}
	for _, k := range []string{"crashloop", "leak"} {
		if !kinds[k] {
			t.Errorf("no %s item in %+v", k, o.Attention)
		}
	}
	if o.Pods.Failing == 0 || o.Pods.ByReason["CrashLoopBackOff"] == 0 {
		t.Errorf("pods = %+v", o.Pods)
	}
	if o.Nodes == nil || o.Nodes.Total != 4 || len(o.Nodes.Zones) != 3 {
		t.Errorf("nodes = %+v", o.Nodes)
	}
	for _, p := range o.Nodes.Pools {
		if (p.Kind == "fargate") != (p.CPURequestedPct == nil) {
			t.Errorf("pool %+v: only Fargate goes unmetered", p)
		}
	}
	if o.Certificates == nil || o.Certificates.NotReady == 0 || o.Waste.UnusedPVCs == 0 || o.Waste.MonthlyUSD <= 0 {
		t.Errorf("certificates %+v waste %+v", o.Certificates, o.Waste)
	}
	for _, b := range []string{"workloads", "pods", "findings", "memory", "security", "certificates"} {
		if o.Badges[b].Count == 0 {
			t.Errorf("no %s badge: %v", b, o.Badges)
		}
	}
	if o.History.StepSeconds != 300 || len(o.History.Series["failingPods"]) != 288 || o.Security.NewSince24h == nil || *o.Security.NewSince24h < 1 {
		t.Errorf("history step %d, %d buckets, newSince24h %v", o.History.StepSeconds, len(o.History.Series["failingPods"]), o.Security.NewSince24h)
	}

	// A team's view: only its namespaces, no cluster-scoped findings.
	var data demoOverview
	getJSON(t, h, "/api/v1/overview?owner=team-data", &data)
	if data.Scope.Owner != "team-data" || data.Scope.Namespaces != 1 || data.Activity == nil || data.Activity.ExecProduction != 0 {
		t.Errorf("team-data: scope %+v activity %+v", data.Scope, data.Activity)
	}
	for _, a := range data.Attention {
		if a.Namespace != "data" && a.Namespace != "" {
			t.Errorf("team-data sees %+v", a)
		}
	}
}
