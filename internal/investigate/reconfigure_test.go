package investigate_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/investigate"
	"github.com/ByronGary/kubesentry/internal/investigate/investigatetest"
)

// Reconfigure swaps the model live: a running run finishes on the model it
// started with, new starts use the new one, and a disabled service refuses
// starts but still serves its runs.
func TestServiceReconfigure(t *testing.T) {
	release := make(chan struct{})
	oldLLM := investigatetest.New(investigatetest.Gate(release, investigatetest.Submit(investigatetest.Report())))
	oldLLM.Name = "old"
	src, src2 := source(), source()
	src2.in.ID = "inc-2"
	multi := &multiSource{byID: map[string]*fakeSource{"inc-1": src, "inc-2": src2}}
	svc := newService(t, oldLLM, multi, &svcOpts{concurrency: 2})
	ctx := context.Background()
	first, _, err := svc.Start(ctx, investigate.StartRequest{IncidentID: "inc-1", RequestedBy: "alice", Access: allAccess})
	if err != nil {
		t.Fatal(err)
	}
	newLLM := investigatetest.New(investigatetest.Submit(investigatetest.Report()))
	newLLM.Name = "new"
	if err := svc.Reconfigure(&investigate.Runtime{LLM: newLLM, Options: investigate.Options{Model: "model-b", Effort: "max"}, PerHour: 7}); err != nil {
		t.Fatal(err)
	}
	if svc.Provider() != "new" || svc.Options().Model != "model-b" || svc.PerHour() != 7 || !svc.Enabled() {
		t.Errorf("after the swap: %s %+v %d", svc.Provider(), svc.Options(), svc.PerHour())
	}
	second, _, err := svc.Start(ctx, investigate.StartRequest{IncidentID: "inc-2", RequestedBy: "alice", Access: allAccess})
	if err != nil {
		t.Fatal(err)
	}
	if second.Provider != "new" || second.Model != "model-b" || second.Effort != "max" {
		t.Errorf("new start: %s %s %s", second.Provider, second.Model, second.Effort)
	}
	// Off: no new starts; the running run goes on.
	if err := svc.Reconfigure(nil); err != nil {
		t.Fatal(err)
	}
	if svc.Enabled() {
		t.Error("still enabled")
	}
	if _, _, err := svc.Start(ctx, investigate.StartRequest{IncidentID: "inc-2", RequestedBy: "bob", Access: allAccess, Fresh: true}); !errors.Is(err, investigate.ErrDisabled) {
		t.Errorf("start while off: %v", err)
	}
	close(release)
	got := waitDone(t, svc, first.ID, allAccess)
	if got.Status != investigate.Completed || got.Provider != "old" || oldLLM.Calls() != 1 {
		t.Errorf("the first run: %s on %s, old calls %d", got.Status, got.Provider, oldLLM.Calls())
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		inv, err := svc.Get(ctx, "inc-2", second.ID, allAccess)
		if err != nil {
			t.Fatal(err)
		}
		if inv.Status != investigate.Running {
			if inv.Status != investigate.Completed || newLLM.Calls() != 1 {
				t.Errorf("the second run: %s, new calls %d", inv.Status, newLLM.Calls())
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("second run still running")
		}
		time.Sleep(2 * time.Millisecond)
	}
	// Past runs stay readable while off.
	if items, _, err := svc.List(ctx, "inc-1", allAccess); err != nil || len(items) != 1 {
		t.Errorf("list while off: %d %v", len(items), err)
	}
	if err := svc.Reconfigure(&investigate.Runtime{}); err == nil {
		t.Error("a runtime without a model accepted")
	}
}

// A service may start off, without a model.
func TestServiceStartsDisabled(t *testing.T) {
	svc, err := investigate.NewService(investigate.Config{Disabled: true, Source: source(), Store: investigate.NewMemoryStore(0), Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Shutdown(context.Background())
	if svc.Enabled() || svc.Provider() != "" {
		t.Errorf("enabled %v provider %q", svc.Enabled(), svc.Provider())
	}
	if _, _, err := svc.Start(context.Background(), investigate.StartRequest{IncidentID: "inc-1", RequestedBy: "a", Access: allAccess}); !errors.Is(err, investigate.ErrDisabled) {
		t.Errorf("start: %v", err)
	}
	if err := svc.Reconfigure(&investigate.Runtime{LLM: happyScript()}); err != nil || !svc.Enabled() {
		t.Errorf("turned on: %v", err)
	}
	if inv := startAndWait(t, svc, allAccess); inv.Status != investigate.Completed {
		t.Errorf("run: %s %s", inv.Status, inv.Error)
	}
}
