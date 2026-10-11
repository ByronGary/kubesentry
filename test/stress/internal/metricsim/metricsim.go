// Package metricsim serves synthetic container_memory_working_set_bytes for
// pods on KWOK fake nodes (which have no kubelet or cAdvisor), so kubesentry's
// OOM and leak detection has real work at scale. A deterministic share of the
// series leaks in a sawtooth; the list of those is the ground truth.
package metricsim

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"math"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/ByronGary/kubesentry/test/stress/internal/out"
)

// Series is one simulated container.
type Series struct {
	Namespace string  `json:"namespace"`
	Pod       string  `json:"pod"`
	Container string  `json:"container"`
	Leak      bool    `json:"leak"`
	BaseMiB   float64 `json:"baseMiB"`
	SlopeMiBh float64 `json:"slopeMiBPerHour,omitempty"`
	PeriodMin float64 `json:"periodMinutes,omitempty"`
	phase     float64 // seconds
	noise     float64
}

// Options configure the exporter.
type Options struct {
	Listen    string
	Series    int
	LeakShare float64
	Refresh   time.Duration
	TruthFile string
	Seed      uint64
}

// Server holds the current series set.
type Server struct {
	o      Options
	cs     kubernetes.Interface
	mu     sync.RWMutex
	series []Series
	pods   int
}

func h64(parts ...string) uint64 {
	f := fnv.New64a()
	for _, p := range parts {
		f.Write([]byte(p))
		f.Write([]byte{0})
	}
	return f.Sum64()
}

func unit(h uint64) float64 { return float64(h%1_000_003) / 1_000_003 }

// Plan picks n containers from cands, deterministically and stably (a
// container keeps its role while its pod exists), and marks a leakShare of
// them as leaking.
func Plan(cands []Series, n int, leakShare float64, seed uint64) []Series {
	type keyed struct {
		k uint64
		s Series
	}
	ks := make([]keyed, len(cands))
	for i, c := range cands {
		ks[i] = keyed{h64(fmt.Sprint(seed), c.Namespace, c.Pod, c.Container), c}
	}
	sort.Slice(ks, func(i, j int) bool { return ks[i].k < ks[j].k })
	if len(ks) > n {
		ks = ks[:n]
	}
	out := make([]Series, len(ks))
	for i, k := range ks {
		s := k.s
		u := func(salt string) float64 { return unit(h64(salt, fmt.Sprint(k.k))) }
		s.BaseMiB = 50 + 350*u("base")
		s.noise = 0.01 + 0.02*u("noise")
		s.Leak = u("leak") < leakShare
		if s.Leak {
			s.PeriodMin = 40 + 80*u("period")
			s.SlopeMiBh = 30 + 90*u("slope")
			// The drop at each restart must exceed kubesentry's 30% restart
			// threshold, so the sawtooth reads as process lifetimes.
			if minSlope := 0.6 * s.BaseMiB / (s.PeriodMin / 60); s.SlopeMiBh < minSlope {
				s.SlopeMiBh = minSlope
			}
			s.phase = u("phase") * s.PeriodMin * 60
		}
		out[i] = s
	}
	return out
}

// Value is the series value at t, in bytes.
func (s *Series) Value(t time.Time) float64 {
	sec := float64(t.Unix())
	v := s.BaseMiB * (1 + s.noise*math.Sin(sec/97+float64(len(s.Pod))))
	if s.Leak {
		period := s.PeriodMin * 60
		age := math.Mod(sec+s.phase, period)
		v += s.SlopeMiBh * age / 3600
	}
	return v * (1 << 20)
}

// Run serves until ctx ends.
func Run(ctx context.Context, cs kubernetes.Interface, o Options) error {
	s := &Server{o: o, cs: cs}
	if err := s.refresh(ctx); err != nil {
		out.Logf("metrics-sim: first refresh: %v", err)
	}
	go func() {
		t := time.NewTicker(o.Refresh)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := s.refresh(ctx); err != nil {
					out.Logf("metrics-sim: refresh: %v", err)
				}
			}
		}
	}()
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", s.metrics)
	mux.HandleFunc("/truth", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.truth())
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	srv := &http.Server{Addr: o.Listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { <-ctx.Done(); _ = srv.Close() }()
	out.Logf("metrics-sim: listening on %s", o.Listen)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (s *Server) refresh(ctx context.Context) error {
	nodes, err := s.cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: "type=kwok"})
	if err != nil {
		return err
	}
	fake := map[string]bool{}
	for _, n := range nodes.Items {
		fake[n.Name] = true
	}
	var cands []Series
	pods := 0
	opts := metav1.ListOptions{Limit: 2000, ResourceVersion: "0"}
	for {
		l, err := s.cs.CoreV1().Pods("").List(ctx, opts)
		if err != nil {
			return err
		}
		for _, p := range l.Items {
			if !fake[p.Spec.NodeName] || p.Status.Phase != corev1.PodRunning {
				continue
			}
			pods++
			for _, c := range p.Spec.Containers {
				cands = append(cands, Series{Namespace: p.Namespace, Pod: p.Name, Container: c.Name})
			}
		}
		if l.Continue == "" {
			break
		}
		opts.Continue, opts.ResourceVersion = l.Continue, ""
	}
	set := Plan(cands, s.o.Series, s.o.LeakShare, s.o.Seed)
	s.mu.Lock()
	s.series, s.pods = set, pods
	s.mu.Unlock()
	t := s.truth()
	out.Logf("metrics-sim: %d series (%d leaking) over %d fake pods", t.Series, t.Leaking, pods)
	if s.o.TruthFile != "" {
		b, _ := json.MarshalIndent(t, "", "  ")
		if err := os.WriteFile(s.o.TruthFile, b, 0o644); err != nil {
			out.Logf("metrics-sim: write truth: %v", err)
		}
	}
	return nil
}

// Truth is the ground truth document.
type Truth struct {
	Updated  time.Time `json:"updated"`
	Series   int       `json:"series"`
	Leaking  int       `json:"leaking"`
	FakePods int       `json:"fakePods"`
	Leaks    []Series  `json:"leaks"`
}

func (s *Server) truth() Truth {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t := Truth{Updated: time.Now().UTC(), Series: len(s.series), FakePods: s.pods, Leaks: []Series{}}
	for _, x := range s.series {
		if x.Leak {
			t.Leaks = append(t.Leaks, x)
		}
	}
	t.Leaking = len(t.Leaks)
	return t
}

func (s *Server) metrics(w http.ResponseWriter, _ *http.Request) {
	now := time.Now()
	s.mu.RLock()
	defer s.mu.RUnlock()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	var b strings.Builder
	b.WriteString("# HELP container_memory_working_set_bytes Simulated working set of containers on KWOK fake nodes.\n")
	b.WriteString("# TYPE container_memory_working_set_bytes gauge\n")
	for i := range s.series {
		x := &s.series[i]
		fmt.Fprintf(&b, "container_memory_working_set_bytes{namespace=%q,pod=%q,container=%q,stress_sim=\"true\"} %.0f\n", x.Namespace, x.Pod, x.Container, x.Value(now))
		if b.Len() > 1<<20 {
			_, _ = w.Write([]byte(b.String()))
			b.Reset()
		}
	}
	_, _ = w.Write([]byte(b.String()))
}
