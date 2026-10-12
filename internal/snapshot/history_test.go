package snapshot

import (
	"reflect"
	"testing"
	"time"

	"github.com/ByronGary/kubesentry/internal/detectors"
	"github.com/ByronGary/kubesentry/internal/model"
)

var t0 = time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)

func counts(kv ...any) map[CountKey]Counts {
	out := map[CountKey]Counts{}
	for i := 0; i < len(kv); i += 2 {
		out[kv[i].(CountKey)] = kv[i+1].(Counts)
	}
	return out
}

func ns(name string) CountKey { return CountKey{Namespace: name} }

func series(w HistoryWindow, s int) []int64 { return w.Series[s] }

// Samples fall into five-minute buckets; a bucket keeps the highest value
// sampled in it, empty buckets repeat the sample before them, and buckets
// after the latest sample repeat it up to now.
func TestHistoryBuckets(t *testing.T) {
	h := NewHistory(5*time.Minute, 6)
	h.RecordCounts(t0.Add(time.Minute), counts(ns("a"), Counts{UnhealthyWorkloads: 2}))
	h.RecordCounts(t0.Add(3*time.Minute), counts(ns("a"), Counts{UnhealthyWorkloads: 5})) // same bucket: max
	h.RecordCounts(t0.Add(4*time.Minute), counts(ns("a"), Counts{UnhealthyWorkloads: 1})) // lower: the bucket keeps 5
	h.RecordCounts(t0.Add(16*time.Minute), counts(ns("a"), Counts{UnhealthyWorkloads: 3}))

	w := h.Window(t0.Add(22*time.Minute), nil)
	if !w.Start.Equal(t0) || w.Step != 5*time.Minute || w.Full {
		t.Fatalf("window start %v step %v full %v", w.Start, w.Step, w.Full)
	}
	// Buckets 0:00 (max 5), 0:05 and 0:10 (carried 1, the last sample of 0:00),
	// 0:15 (3), 0:20 (carried to now).
	if got, want := series(w, UnhealthyWorkloads), []int64{5, 1, 1, 3, 3}; !reflect.DeepEqual(got, want) {
		t.Errorf("unhealthy = %v, want %v", got, want)
	}
	if got := series(w, FailingPods); !reflect.DeepEqual(got, []int64{0, 0, 0, 0, 0}) {
		t.Errorf("failing = %v", got)
	}
	// A sample from the past counts towards the latest bucket.
	h.RecordCounts(t0, counts(ns("a"), Counts{UnhealthyWorkloads: 9}))
	if got := series(h.Window(t0.Add(16*time.Minute), nil), UnhealthyWorkloads); got[3] != 9 {
		t.Errorf("late sample: %v", got)
	}
}

// The ring rolls over: only the last n buckets are kept, the window says
// when it covers all of them, and old values never reappear.
func TestHistoryRollover(t *testing.T) {
	h := NewHistory(5*time.Minute, 4)
	for i := 0; i < 10; i++ {
		h.RecordCounts(t0.Add(time.Duration(i)*5*time.Minute), counts(ns("a"), Counts{FailingPods: int32(i + 1)}))
	}
	w := h.Window(t0.Add(45*time.Minute), nil)
	if !w.Full || !w.Start.Equal(t0.Add(30*time.Minute)) {
		t.Errorf("start %v full %v", w.Start, w.Full)
	}
	if got, want := series(w, FailingPods), []int64{7, 8, 9, 10}; !reflect.DeepEqual(got, want) {
		t.Errorf("failing = %v, want %v", got, want)
	}
	// A gap longer than the window: every bucket repeats the last sample.
	h.RecordCounts(t0.Add(3*time.Hour), counts(ns("a"), Counts{FailingPods: 2}))
	if got, want := series(h.Window(t0.Add(3*time.Hour), nil), FailingPods), []int64{10, 10, 10, 2}; !reflect.DeepEqual(got, want) {
		t.Errorf("after a gap = %v, want %v", got, want)
	}
	// Asking later than the latest sample carries it forward.
	if got, want := series(h.Window(t0.Add(3*time.Hour+10*time.Minute), nil), FailingPods), []int64{10, 2, 2, 2}; !reflect.DeepEqual(got, want) {
		t.Errorf("carried = %v, want %v", got, want)
	}
}

// Window sums only the keys the caller may see; keys gone quiet for a whole
// window are dropped, and the unfiltered sum agrees with summing every key.
func TestHistoryScopeSumming(t *testing.T) {
	h := NewHistory(5*time.Minute, 3)
	rbacA := CountKey{Namespace: "a", RBAC: true}
	cluster := CountKey{}
	h.RecordCounts(t0, counts(ns("a"), Counts{SecurityCrit: 1, CertsExpiringSoon: 2}, ns("b"), Counts{SecurityCrit: 10},
		rbacA, Counts{SecurityWarn: 4}, cluster, Counts{SecurityCrit: 100}))
	h.RecordCounts(t0.Add(5*time.Minute), counts(ns("a"), Counts{SecurityCrit: 2}, ns("b"), Counts{SecurityCrit: 20}))

	now := t0.Add(5 * time.Minute)
	onlyA := h.Window(now, func(k CountKey) bool { return k.Namespace == "a" && !k.RBAC })
	if got := series(onlyA, SecurityCrit); !reflect.DeepEqual(got, []int64{1, 2}) {
		t.Errorf("a's crit = %v", got)
	}
	if got := series(onlyA, SecurityWarn); !reflect.DeepEqual(got, []int64{0, 0}) {
		t.Errorf("a without ViewRBAC sees RBAC warnings: %v", got)
	}
	withRBAC := h.Window(now, func(k CountKey) bool { return k.Namespace == "a" })
	if got := series(withRBAC, SecurityWarn); !reflect.DeepEqual(got, []int64{4, 0}) {
		t.Errorf("a with ViewRBAC warn = %v", got)
	}
	all := h.Window(now, func(CountKey) bool { return true })
	if total := h.Window(now, nil); !reflect.DeepEqual(all.Series, total.Series) {
		t.Errorf("sum of keys %v != total %v", all.Series, total.Series)
	}
	if got := series(all, SecurityCrit); !reflect.DeepEqual(got, []int64{111, 22}) {
		t.Errorf("all crit = %v", got)
	}

	// The cluster-scoped and RBAC keys went quiet at 0:05, b at 0:10; after a
	// whole window of zeros each is dropped.
	h.RecordCounts(t0.Add(10*time.Minute), counts(ns("a"), Counts{SecurityCrit: 2}))
	if h.Keys() != 4 {
		t.Errorf("keys = %d before the window passed", h.Keys())
	}
	h.RecordCounts(t0.Add(15*time.Minute), counts(ns("a"), Counts{SecurityCrit: 2}))
	if h.Keys() != 2 {
		t.Errorf("keys = %d, want a and b", h.Keys())
	}
	if got := series(h.Window(t0.Add(15*time.Minute), nil), SecurityCrit); !reflect.DeepEqual(got, []int64{20 + 2, 2, 2}) {
		t.Errorf("total after dropping = %v", got)
	}
	h.RecordCounts(t0.Add(20*time.Minute), counts(ns("a"), Counts{SecurityCrit: 2}))
	if h.Keys() != 1 {
		t.Errorf("keys = %d, want only a", h.Keys())
	}
	if got := series(h.Window(t0.Add(20*time.Minute), func(CountKey) bool { return true }), SecurityCrit); !reflect.DeepEqual(got, []int64{2, 2, 2}) {
		t.Errorf("keys after dropping = %v", got)
	}
}

func TestHistoryEmpty(t *testing.T) {
	w := NewHistory(0, 0).Window(t0, nil)
	if !w.Start.IsZero() || w.Series[0] != nil || w.Full || w.Step != DefaultHistoryStep {
		t.Errorf("empty window = %+v", w)
	}
}

// View.Counts and History.Record agree with the detectors on a real view.
func TestViewCounts(t *testing.T) {
	now := t0
	inv := model.Inventory{
		Namespaces: []model.Namespace{{Name: "a"}},
		Workloads: []model.Workload{{Kind: "Deployment", Namespace: "a", Name: "web", Desired: 2, Ready: 0,
			Selector: &model.LabelSelector{MatchLabels: map[string]string{"app": "web"}}}},
		Pods: []model.Pod{{Namespace: "a", Name: "web-1", Phase: "Running", Labels: map[string]string{"app": "web"}, Created: now.Add(-time.Hour),
			Containers: []model.ContainerStatus{{Name: "web", State: "waiting", Reason: "CrashLoopBackOff"}},
			Specs:      []model.ContainerSpec{{Name: "web", Privileged: true}}}},
		Certs: model.CertManager{Installed: true, Certificates: []model.Certificate{
			{Namespace: "a", Name: "soon", IssuerKind: "External", Ready: "True", NotAfter: now.Add(48 * time.Hour)},
			{Namespace: "a", Name: "later", IssuerKind: "External", Ready: "True", NotAfter: now.Add(60 * 24 * time.Hour)},
		}},
	}
	v := Build(inv, detectors.DefaultPolicy(), now)
	c := v.Counts()[ns("a")]
	if c[UnhealthyWorkloads] != 1 || c[FailingPods] != 1 || c[SecurityCrit] != 1 || c[CertsExpiringSoon] != 1 {
		t.Errorf("counts = %v", c)
	}
	h := NewHistory(0, 0)
	h.Record(v)
	if got := h.Window(now, nil).Series[FailingPods]; !reflect.DeepEqual(got, []int64{1}) {
		t.Errorf("recorded failing = %v", got)
	}
}
