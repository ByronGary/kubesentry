package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/audit"
	"github.com/ByronGary/kubesentry/internal/auth"
	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/model"
	"github.com/ByronGary/kubesentry/internal/snapshot"
)

// overviewFixture is a 10,000-pod cluster: 250 namespaces of 8 Deployments
// with 5 pods each, owned by 25 teams, on 200 nodes in three pools and
// zones; every 17th Deployment crash-loops, every 50th runs privileged, a
// tenth of the certificates expire soon, one unused claim per namespace.
func overviewFixture() model.Inventory {
	inv := model.Inventory{Unavailable: map[string]string{}}
	old := now.Add(-72 * time.Hour)
	pools := []struct{ label, value string }{{"eks.amazonaws.com/nodegroup", "general"}, {"karpenter.sh/nodepool", "default"}, {"eks.amazonaws.com/compute-type", "fargate"}}
	for i := 0; i < 200; i++ {
		p := pools[0]
		switch {
		case i >= 190:
			p = pools[2]
		case i >= 120:
			p = pools[1]
		}
		inv.Nodes = append(inv.Nodes, model.Node{Name: fmt.Sprintf("node-%03d", i), Ready: i != 7, CPUAllocatableMilli: 3920, MemoryAllocatableBytes: 15 << 30,
			Labels: map[string]string{p.label: p.value, "topology.kubernetes.io/zone": "us-east-1" + string(rune('a'+i%3))}})
	}
	inv.StorageClasses = []model.StorageClass{{Name: "gp3", Provisioner: "ebs.csi.aws.com", Parameters: map[string]string{"type": "gp3"}}}
	inv.Certs.Installed = true
	pod := 0
	for n := 0; n < 250; n++ {
		ns := fmt.Sprintf("ns-%03d", n)
		nsObj := model.Namespace{Name: ns, Annotations: map[string]string{"kubesentry.io/owner": fmt.Sprintf("team-%02d", n/10)},
			Labels: map[string]string{"pod-security.kubernetes.io/enforce": "baseline"}}
		if n%5 == 0 {
			nsObj.Labels["environment"] = "production"
		}
		inv.Namespaces = append(inv.Namespaces, nsObj)
		for d := 0; d < 8; d++ {
			name := fmt.Sprintf("app-%d", d)
			k := n*8 + d
			crash := k%17 == 0
			ready := int32(5)
			if crash {
				ready = 3
			}
			inv.Workloads = append(inv.Workloads, model.Workload{Kind: "Deployment", Namespace: ns, Name: name, UID: ns + name, Desired: 5, Ready: ready,
				Updated: 5, Available: ready, Created: old, Selector: &model.LabelSelector{MatchLabels: map[string]string{"app": name}}})
			for p := 0; p < 5; p++ {
				pd := model.Pod{UID: fmt.Sprintf("pod-%d", pod), Namespace: ns, Name: fmt.Sprintf("%s-%d", name, p), Phase: "Running", Ready: true,
					NodeName: fmt.Sprintf("node-%03d", pod%200), Labels: map[string]string{"app": name}, Created: old,
					Specs:      []model.ContainerSpec{{Name: "c", CPURequestMilli: 100, MemoryRequestBytes: 256 << 20, Privileged: k%50 == 0}},
					Containers: []model.ContainerStatus{{Name: "c", State: "running", Ready: true}}}
				if crash && p < 2 {
					pd.Ready, pd.ReadyChanged = false, now.Add(-time.Hour)
					pd.Containers[0] = model.ContainerStatus{Name: "c", State: "waiting", Reason: "CrashLoopBackOff", RestartCount: 12}
				}
				inv.Pods = append(inv.Pods, pd)
				pod++
			}
		}
		expires := now.Add(60 * 24 * time.Hour)
		if n%10 == 0 {
			expires = now.Add(5 * 24 * time.Hour)
		}
		inv.Certs.Certificates = append(inv.Certs.Certificates, model.Certificate{Namespace: ns, Name: "tls", IssuerKind: "External", Ready: "True", NotAfter: expires})
		inv.PVCs = append(inv.PVCs, model.PVC{Namespace: ns, Name: "orphan", Phase: "Bound", StorageClass: "gp3", CapacityBytes: 20 << 30, Created: old})
	}
	return inv
}

// overviewBenchServer serves the fixture to an unrestricted caller ("") and
// to "team", who sees 10 namespaces (audit there too), with a day of history
// and an audit store, but no response cache: every request runs the handler.
func overviewBenchServer(tb testing.TB) (*Server, *snapshot.View) {
	v := snapshot.Build(overviewFixture(), detectors.DefaultPolicy(), now)
	team := azScope()
	for i := 0; i < 10; i++ {
		team.Namespaces[fmt.Sprintf("ns-%03d", i)] = true
	}
	az := &azFake{scopes: map[string]map[string]auth.Scope{"team": {"pods": team, "auditevents": team}}}
	hist := snapshot.NewHistory(0, 0)
	for i := 287; i >= 0; i-- {
		hist.RecordCounts(now.Add(-time.Duration(i)*snapshot.DefaultHistoryStep), v.Counts())
	}
	st := audit.NewMemoryStore(50000)
	for i := 0; i < 2000; i++ {
		e := audit.Event{AuditID: fmt.Sprint(i), Time: now.Add(-time.Duration(i) * 30 * time.Second), Verb: "get", Username: "alice", ActorKind: "user",
			Resource: "secrets", Namespace: fmt.Sprintf("ns-%03d", i%250), StatusCode: 200}
		if i%7 == 0 {
			e.Resource, e.Subresource, e.Verb = "pods", "exec", "create"
		}
		e.Tags = audit.Classify(e)
		st.Add(e)
	}
	return &Server{
		Views: currentView{v}, Now: func() time.Time { return now }, History: hist, Audit: &audit.Ingester{Store: st},
		Authenticator: auth.Chain(auth.HeaderAuthenticator{UserHeader: "X-Forwarded-Email", TrustedProxies: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}},
			openAuthenticator{}),
		Authorizer: az,
	}, v
}

// TestOverviewPayloadSize keeps the answer for the 10,000-pod fixture under
// 30 KB for every kind of caller.
func TestOverviewPayloadSize(t *testing.T) {
	s, _ := overviewBenchServer(t)
	h := s.Handler()
	for _, user := range []string{"", "team"} {
		rec := getAs(t, h, user, "/api/v1/overview", nil)
		if rec.Code != 200 {
			t.Fatalf("%q: %d %s", user, rec.Code, rec.Body.String())
		}
		t.Logf("caller %q: %d bytes", user, rec.Body.Len())
		if rec.Body.Len() > 30<<10 {
			t.Errorf("caller %q: %d bytes, want under 30 KB", user, rec.Body.Len())
		}
	}
}

func BenchmarkOverview(b *testing.B) {
	s, v := overviewBenchServer(b)
	b.Run("index-per-view", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			buildOverviewIndex(v)
		}
	})
	idx := overviewIndex(v)
	for _, user := range []string{"", "team"} {
		name := map[string]string{"": "all", "team": "team"}[user]
		ctx := context.Background()
		r := httptest.NewRequest(http.MethodGet, "/api/v1/overview", nil)
		id := auth.Identity{User: user, Source: "proxy", Unrestricted: user == ""}
		r = r.WithContext(auth.WithIdentity(ctx, id))
		b.Run("base-per-scope/"+name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				rr := r.WithContext(context.WithValue(r.Context(), authzMemoKey{}, &authzMemo{}))
				s.buildOverviewBase(v, idx, s.overviewSelection(rr, idx, "", ""))
			}
		})
		h := s.Handler()
		b.Run("request-memo-warm/"+name, func(b *testing.B) {
			b.ReportAllocs()
			var size int
			for b.Loop() {
				req := httptest.NewRequest(http.MethodGet, "/api/v1/overview", nil)
				if user != "" {
					req.Header.Set("X-Forwarded-Email", user)
				}
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				if rec.Code != 200 {
					b.Fatalf("%d %s", rec.Code, rec.Body.String())
				}
				size = rec.Body.Len()
			}
			b.ReportMetric(float64(size), "bytes/resp")
		})
	}
}
