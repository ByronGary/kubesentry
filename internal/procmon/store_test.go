package procmon

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func uidFor(node, pod int) string {
	return fmt.Sprintf("%08x-0000-4000-8000-%012x", node, pod)
}

func nodeReport(node, pods, procsPerPod int) Report {
	r := Report{Node: fmt.Sprintf("node-%04d", node)}
	for p := range pods {
		for i := range procsPerPod {
			r.Processes = append(r.Processes, Process{PID: p*100 + i + 1, PodUID: uidFor(node, p), RSSBytes: int64(i+1) << 20, Name: "proc", Cmdline: "proc --flag"})
		}
	}
	return r
}

func TestStoreIndexMovesWithReports(t *testing.T) {
	st := NewStore()
	now := time.Unix(10_000, 0)
	st.Now = func() time.Time { return now }

	st.Update(nodeReport(1, 3, 2))
	st.Update(nodeReport(2, 3, 2))
	v, ok := st.ForPod(uidFor(2, 1))
	if !ok || v.Node != "node-0002" || len(v.Processes) != 2 || v.Processes[0].RSSBytes != 2<<20 {
		t.Fatalf("ForPod: %+v %v", v, ok)
	}
	// The caller owns the slice.
	v.Processes[0].Name = "changed"
	if again, _ := st.ForPod(uidFor(2, 1)); again.Processes[0].Name != "proc" {
		t.Fatal("ForPod returned the store's own slice")
	}

	// A newer report from node 1 with one pod gone drops it from the index and
	// leaves node 2's pods alone.
	st.Update(nodeReport(1, 2, 2))
	if _, ok := st.ForPod(uidFor(1, 2)); ok {
		t.Fatal("pod missing from the newer report is still indexed")
	}
	if _, ok := st.ForPod(uidFor(2, 2)); !ok {
		t.Fatal("another node's pod was dropped")
	}

	// A pod UID that another node now reports (it should not happen, but a
	// stale node must not delete the live owner's entry).
	moved := Report{Node: "node-0003", Processes: []Process{{PID: 9, PodUID: uidFor(1, 0)}}}
	st.Update(moved)
	st.Update(nodeReport(1, 0, 0)) // node 1 now reports nothing
	if v, ok := st.ForPod(uidFor(1, 0)); !ok || v.Node != "node-0003" {
		t.Fatalf("moved pod lost: %+v %v", v, ok)
	}
}

func TestStoreAgentsStaleAndEviction(t *testing.T) {
	st := NewStoreWithOptions(StoreOptions{Interval: 10 * time.Second})
	o := st.Options()
	if o.StaleAfter != 80*time.Second || o.EvictAfter != 400*time.Second || o.MaxNodes != 5000 || o.MaxProcessesPerNode != 20000 {
		t.Fatalf("defaults: %+v", o)
	}
	start := time.Unix(10_000, 0).UTC()
	now := start
	st.Now = func() time.Time { return now }

	r := nodeReport(1, 2, 3)
	r.Bytes = 1234
	st.Update(r)
	now = now.Add(30 * time.Second)
	st.Update(nodeReport(2, 1, 1))

	now = start.Add(100 * time.Second) // node 1 is 100s old: stale; node 2 is 70s: fresh
	want := []AgentStatus{
		{Node: "node-0001", LastReport: start, Processes: 6, Bytes: 1234, Stale: true},
		{Node: "node-0002", LastReport: start.Add(30 * time.Second), Processes: 1, Stale: false},
	}
	if got := st.Agents(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Agents:\n got %+v\nwant %+v", got, want)
	}
	if st.Reporting() != 1 {
		t.Fatalf("reporting = %d", st.Reporting())
	}

	// JSON field names match web/src/types.ts AgentStatus.
	b, _ := json.Marshal(want[0])
	if string(b) != `{"node":"node-0001","lastReport":"1970-01-01T02:46:40Z","processes":6,"bytes":1234,"stale":true}` {
		t.Fatalf("json: %s", b)
	}

	// Past EvictAfter a silent node disappears from reads at once, and the
	// next sweep removes it and its pods.
	now = start.Add(401 * time.Second)
	if _, ok := st.ForPod(uidFor(1, 0)); ok {
		t.Fatal("evicted node's pod still served")
	}
	if got := st.Agents(); len(got) != 1 || got[0].Node != "node-0002" {
		t.Fatalf("agents after eviction: %+v", got)
	}
	st.Sweep()
	if st.Nodes() != 1 || len(st.pods) != 1 {
		t.Fatalf("sweep left nodes=%d pods=%d", st.Nodes(), len(st.pods))
	}
}

func TestStoreBounds(t *testing.T) {
	st := NewStoreWithOptions(StoreOptions{MaxNodes: 3, MaxProcessesPerNode: 4})
	now := time.Unix(10_000, 0)
	st.Now = func() time.Time { return now }

	// Per-node cap keeps the largest processes.
	st.Update(nodeReport(1, 2, 5)) // 10 processes, RSS 1..5 MiB per pod
	if a := st.Agents(); a[0].Processes != 4 {
		t.Fatalf("kept %d processes", a[0].Processes)
	}
	total := 0
	for p := range 2 {
		v, _ := st.ForPod(uidFor(1, p))
		for _, pr := range v.Processes {
			if pr.RSSBytes < 4<<20 {
				t.Errorf("kept a small process: %+v", pr)
			}
		}
		total += len(v.Processes)
	}
	if total != 4 {
		t.Fatalf("indexed %d processes", total)
	}

	// Node cap: a fourth node replaces the one silent longest.
	for n := 2; n <= 4; n++ {
		now = now.Add(time.Second)
		st.Update(nodeReport(n, 1, 1))
	}
	if st.Nodes() != 3 {
		t.Fatalf("nodes = %d", st.Nodes())
	}
	if _, ok := st.ForPod(uidFor(1, 0)); ok {
		t.Fatal("oldest node not evicted")
	}
	if _, ok := st.ForPod(uidFor(4, 0)); !ok {
		t.Fatal("newest node missing")
	}
}

func TestStoreConcurrentReadersAndWriters(t *testing.T) {
	st := NewStore()
	var wg sync.WaitGroup
	var hits atomic.Int64
	for n := range 8 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for range 50 {
				st.Update(nodeReport(n, 5, 3))
			}
		}()
		go func() {
			defer wg.Done()
			for i := range 500 {
				if _, ok := st.ForPod(uidFor(n, i%5)); ok {
					hits.Add(1)
				}
				_ = st.Agents()
			}
		}()
	}
	wg.Wait()
	if st.Nodes() != 8 || hits.Load() == 0 {
		t.Fatalf("nodes=%d hits=%d", st.Nodes(), hits.Load())
	}
}

func gz(t testing.TB, b []byte) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	zw.Close()
	return buf.Bytes()
}

func TestDecodeReport(t *testing.T) {
	rep := nodeReport(7, 3, 4)
	plain, _ := json.Marshal(rep)
	zipped := gz(t, plain)
	req := func(body []byte, enc string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/agent/report", bytes.NewReader(body))
		if enc != "" {
			r.Header.Set("Content-Encoding", enc)
		}
		return r
	}

	for _, tc := range []struct {
		name string
		body []byte
		enc  string
	}{{"plain", plain, ""}, {"gzip", zipped, "gzip"}, {"identity", plain, "identity"}} {
		got, err := DecodeReport(req(tc.body, tc.enc), 1<<20)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got.Node != rep.Node || len(got.Processes) != 12 || got.Bytes != int64(len(tc.body)) {
			t.Fatalf("%s: node=%s procs=%d bytes=%d", tc.name, got.Node, len(got.Processes), got.Bytes)
		}
	}

	// A gzip bomb: tiny on the wire, huge decompressed.
	bomb := gz(t, append([]byte(`{"node":"x","processes":[`), bytes.Repeat([]byte(" "), 4<<20)...))
	if len(bomb) > 64<<10 {
		t.Fatalf("bomb fixture is %d bytes", len(bomb))
	}
	tests := []struct {
		name string
		r    *http.Request
		max  int64
		want error
	}{
		{"gzip bomb", req(bomb, "gzip"), 1 << 20, ErrTooLarge},
		{"wire too large", req(plain, ""), int64(len(plain)) - 1, ErrTooLarge},
		{"compressed too large", req(zipped, "gzip"), int64(len(zipped)) - 1, ErrTooLarge},
		{"exact fit", req(plain, ""), int64(len(plain)), nil},
		{"brotli", req(plain, "br"), 1 << 20, ErrUnsupportedEncoding},
		{"not gzip", req(plain, "gzip"), 1 << 20, ErrInvalidReport},
		{"bad json", req([]byte(`{"node":`), ""), 1 << 20, ErrInvalidReport},
		{"trailing data", req(append(append([]byte{}, plain...), `{"node":"y"}`...), ""), 1 << 20, ErrInvalidReport},
		{"corrupt gzip", req(append(zipped[:len(zipped)-8:len(zipped)-8], 1, 2, 3, 4, 5, 6, 7, 8), "gzip"), 1 << 20, ErrInvalidReport},
	}
	for _, tc := range tests {
		_, err := DecodeReport(tc.r, tc.max)
		if !errors.Is(err, tc.want) && !(tc.want == nil && err == nil) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
	}

	// http.MaxBytesReader in front (as the handler may keep) maps to ErrTooLarge too.
	r := req(plain, "")
	r.Body = http.MaxBytesReader(httptest.NewRecorder(), r.Body, 10)
	if _, err := DecodeReport(r, 1<<20); !errors.Is(err, ErrTooLarge) {
		t.Errorf("MaxBytesReader: %v", err)
	}
}

// BenchmarkStore: 500 nodes × 50 processes, readers looking up pods while
// every node keeps reporting.
func BenchmarkStoreForPod(b *testing.B) {
	const nodes, pods, procs = 500, 10, 5 // 50 processes per node
	st := NewStore()
	reports := make([]Report, nodes)
	var uids []string
	for n := range nodes {
		reports[n] = nodeReport(n, pods, procs)
		st.Update(reports[n])
		for p := range pods {
			uids = append(uids, uidFor(n, p))
		}
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { // one writer replaying reports, ~as 500 agents at 15s would, but flat out
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
				st.Update(reports[i%nodes])
			}
		}
	}()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			if _, ok := st.ForPod(uids[i%len(uids)]); !ok {
				b.Error("miss")
			}
			i++
		}
	})
	b.StopTimer()
	close(stop)
	wg.Wait()
}

func BenchmarkStoreUpdate(b *testing.B) {
	const nodes = 500
	st := NewStore()
	reports := make([]Report, nodes)
	for n := range nodes {
		reports[n] = nodeReport(n, 10, 5)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		st.Update(reports[i%nodes])
	}
}

func BenchmarkStoreAgents(b *testing.B) {
	st := NewStore()
	for n := range 500 {
		st.Update(nodeReport(n, 10, 5))
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if len(st.Agents()) != 500 {
			b.Fatal("agents")
		}
	}
}

// BenchmarkScanAllNodes is the old ForPod for comparison: a scan of every
// node's processes per lookup.
func BenchmarkScanAllNodes(b *testing.B) {
	reports := map[string]Report{}
	var uids []string
	for n := range 500 {
		r := nodeReport(n, 10, 5)
		reports[r.Node] = r
		for p := range 10 {
			uids = append(uids, uidFor(n, p))
		}
	}
	b.ResetTimer()
	for i := range b.N {
		uid := uids[i%len(uids)]
		found := false
		for _, r := range reports {
			for _, p := range r.Processes {
				if p.PodUID == uid {
					found = true
				}
			}
			if found {
				break
			}
		}
	}
}
