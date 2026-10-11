// Package agents simulates kubesentry node agents on the KWOK fake nodes: each
// posts a procmon.Report for the pods on its node every interval.
package agents

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/ByronGary/kubesentry/test/stress/internal/hist"
	"github.com/ByronGary/kubesentry/test/stress/internal/ks"
	"github.com/ByronGary/kubesentry/test/stress/internal/out"
)

// Process mirrors procmon.Process.
type Process struct {
	PID         int     `json:"pid"`
	PPID        int     `json:"ppid"`
	Name        string  `json:"name"`
	Cmdline     string  `json:"cmdline"`
	PodUID      string  `json:"podUID"`
	ContainerID string  `json:"containerID"`
	RSSBytes    int64   `json:"rssBytes"`
	Threads     int     `json:"threads"`
	CPUMillis   float64 `json:"cpuMillicores"`
}

// Report mirrors procmon.Report.
type Report struct {
	Node      string    `json:"node"`
	Time      time.Time `json:"time"`
	Processes []Process `json:"processes"`
}

// Options configure a run.
type Options struct {
	Client    *ks.Client
	Ingest    *ks.Client  // where /agent/report is (default Client)
	Fanout    string      // headless Service: post each report to every replica, like -server-fanout
	Gzip      bool        // Content-Encoding: gzip, like the new agent's default
	ID        ks.Identity // agent token
	APIID     ks.Identity // API token for the freshness check
	Agents    int
	Interval  time.Duration
	Jitter    float64 // ± fraction of the interval per report
	Surge     bool    // every agent posts at the same instant
	Duration  time.Duration
	MinBytes  int
	MaxBytes  int
	Timeout   time.Duration
	CheckPods int
	Seed      uint64
}

// Result is agents.json.
type Result struct {
	Started      time.Time          `json:"started"`
	Seconds      float64            `json:"seconds"`
	Mode         string             `json:"mode"`
	Agents       int                `json:"agents"`
	RealNodes    int                `json:"realNodeNames"`
	SimNodes     int                `json:"syntheticNodeNames"`
	PodsCovered  int                `json:"podsCovered"`
	Processes    int                `json:"processesPerRound"`
	ReportBytes  hist.Summary       `json:"reportKB"`
	Interval     string             `json:"interval"`
	Posts        []hist.RouteReport `json:"posts"`
	Success      int64              `json:"success"`
	Status429    int64              `json:"status429"`
	Status5xx    int64              `json:"status5xx"`
	Timeouts     int64              `json:"timeouts"`
	SuccessRate  float64            `json:"successRate"`
	Freshness    []hist.RouteReport `json:"freshnessCheck"`
	Fresh        int                `json:"fresh"`
	Stale        int                `json:"stale"`
	Unavailable  int                `json:"unavailable"`
	CheckErrors  int                `json:"checkErrors"`
	CheckedPods  int                `json:"checkedPods"`
	PostsPerSec  float64            `json:"postsPerSecond"`
	MBytesPerSec float64            `json:"mbytesPerSecond"`
	Targets      int                `json:"replicaTargets"` // replicas each report went to
	Gzip         bool               `json:"gzip"`
}

// fanout resolves a headless Service to one URL per replica, refreshed
// every 30 seconds, as the agent's -server-fanout does.
type fanout struct {
	host, scheme, port string
	base               string
	mu                 sync.Mutex
	cached             []string
	at                 time.Time
}

func newFanout(host, base string) *fanout {
	f := &fanout{host: host, base: base, scheme: "http", port: "8081"}
	if u, err := url.Parse(base); err == nil {
		f.scheme = u.Scheme
		if p := u.Port(); p != "" {
			f.port = p
		}
	}
	return f
}

func (f *fanout) urls() []string {
	if f.host == "" {
		return []string{f.base}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if time.Since(f.at) < 30*time.Second && len(f.cached) > 0 {
		return f.cached
	}
	ips, err := net.LookupHost(f.host)
	if err != nil || len(ips) == 0 {
		return []string{f.base}
	}
	sort.Strings(ips)
	f.cached = f.cached[:0]
	for _, ip := range ips {
		f.cached = append(f.cached, f.scheme+"://"+net.JoinHostPort(ip, f.port))
	}
	f.at = time.Now()
	return f.cached
}

type agent struct {
	node string
	body []byte
	pods []*corev1.Pod
}

func hex(r *rand.Rand, n int) string {
	const d = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = d[r.IntN(16)]
	}
	return string(b)
}

var procNames = []string{"java", "node", "python3", "envoy", "nginx", "gunicorn", "sidekiq", "pause", "sh", "tini"}

// buildReport fills a report for pods, padded to about target bytes with
// extra worker processes.
func buildReport(r *rand.Rand, node string, pods []*corev1.Pod, target int) ([]byte, int) {
	rep := Report{Node: node, Time: time.Now()}
	pid := 1000
	type ctr struct{ uid, cid, name string }
	var ctrs []ctr
	for _, p := range pods {
		rep.Processes = append(rep.Processes, Process{PID: pid, PPID: 1, Name: "pause", Cmdline: "/pause", PodUID: string(p.UID), RSSBytes: 400 << 10, Threads: 1})
		pid++
		for i, c := range p.Spec.Containers {
			cid := ""
			if i < len(p.Status.ContainerStatuses) {
				cid = p.Status.ContainerStatuses[i].ContainerID
				if j := strings.Index(cid, "://"); j >= 0 {
					cid = cid[j+3:]
				}
			}
			if cid == "" {
				cid = hex(r, 64)
			}
			ctrs = append(ctrs, ctr{string(p.UID), cid, c.Name})
		}
	}
	addProc := func(c ctr, parent int) int {
		name := procNames[r.IntN(len(procNames))]
		rep.Processes = append(rep.Processes, Process{
			PID: pid, PPID: parent, Name: name,
			Cmdline: fmt.Sprintf("/usr/bin/%s --config=/etc/%s/config.yaml --listen=0.0.0.0:8080 --log-level=info --metrics-port=9090 --worker-id=%d --password=*** %s", name, c.name, pid, strings.Repeat("-Dflag.x=y ", r.IntN(12))),
			PodUID:  c.uid, ContainerID: c.cid,
			RSSBytes: int64(20+r.IntN(900)) << 20, Threads: 1 + r.IntN(64), CPUMillis: float64(r.IntN(2000)),
		})
		pid++
		return pid - 1
	}
	mains := map[int]int{}
	for i, c := range ctrs {
		mains[i] = addProc(c, 1)
	}
	if len(ctrs) == 0 {
		b, _ := json.Marshal(rep)
		return b, len(rep.Processes)
	}
	// Pad with worker processes until the body reaches the target size.
	for {
		b, _ := json.Marshal(rep)
		if len(b) >= target || len(rep.Processes) >= 19000 {
			return b, len(rep.Processes)
		}
		// Close half the gap per round, at the current average process size.
		need := (target - len(b)) / (len(b)/len(rep.Processes) + 1) / 2
		for k := 0; k < max(1, need); k++ {
			i := r.IntN(len(ctrs))
			addProc(ctrs[i], mains[i])
		}
	}
}

// Run simulates the agents for o.Duration.
func Run(ctx context.Context, cs kubernetes.Interface, o Options) (*Result, error) {
	r := rand.New(rand.NewPCG(o.Seed, 5))
	nodes, err := cs.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: "type=kwok"})
	if err != nil {
		return nil, err
	}
	var names []string
	for _, n := range nodes.Items {
		if n.Labels["kubernetes.io/os"] == "windows" || n.Labels["eks.amazonaws.com/compute-type"] == "fargate" {
			continue // the agent DaemonSet would not run there on EKS
		}
		names = append(names, n.Name)
	}
	sort.Strings(names)
	byNode := map[string][]*corev1.Pod{}
	opts := metav1.ListOptions{Limit: 2000}
	for {
		l, err := cs.CoreV1().Pods("").List(ctx, opts)
		if err != nil {
			return nil, err
		}
		for i := range l.Items {
			p := &l.Items[i]
			if p.Spec.NodeName != "" && p.Status.Phase == corev1.PodRunning {
				byNode[p.Spec.NodeName] = append(byNode[p.Spec.NodeName], p)
			}
		}
		if l.Continue == "" {
			break
		}
		opts.Continue = l.Continue
	}
	res := &Result{Started: time.Now().UTC(), Agents: o.Agents, Interval: o.Interval.String(), Mode: "staggered", Gzip: o.Gzip}
	if o.Surge {
		res.Mode = "surge"
	} else if o.Jitter > 0 {
		res.Mode = fmt.Sprintf("staggered, ±%.0f%% jitter", 100*o.Jitter)
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("no fake nodes")
	}
	sizes := hist.New()
	agents := make([]*agent, o.Agents)
	covered := map[string]bool{}
	for i := range agents {
		real := names[i%len(names)]
		name := real
		if i >= len(names) {
			// More agents than fake nodes: extra agents report under their own
			// node name for the pods of a real fake node.
			name = fmt.Sprintf("sim-%d-%s", i/len(names), real)
			res.SimNodes++
		} else {
			res.RealNodes++
		}
		target := o.MinBytes + r.IntN(o.MaxBytes-o.MinBytes+1)
		body, procs := buildReport(r, name, byNode[real], target)
		if o.Gzip {
			var zb bytes.Buffer
			zw := gzip.NewWriter(&zb)
			_, _ = zw.Write(body)
			_ = zw.Close()
			body = zb.Bytes()
		}
		agents[i] = &agent{node: name, body: body, pods: byNode[real]}
		sizes.Add(float64(len(body)) / 1024)
		res.Processes += procs
		for _, p := range byNode[real] {
			covered[string(p.UID)] = true
		}
	}
	res.PodsCovered = len(covered)
	res.ReportBytes = sizes.Summarize()
	out.Logf("agents: %d agents (%d real node names), %d pods covered, %d processes per round, report KB p50 %.0f max %.0f",
		o.Agents, res.RealNodes, res.PodsCovered, res.Processes, res.ReportBytes.P50, res.ReportBytes.Max)

	if o.Ingest == nil {
		o.Ingest = o.Client
	}
	headers := map[string]string{"Content-Type": "application/json"}
	if o.Gzip {
		headers["Content-Encoding"] = "gzip"
	}
	targets := newFanout(o.Fanout, o.Ingest.Base)
	rec := hist.NewRecorder()
	var sent atomic.Int64
	runCtx, cancel := context.WithTimeout(ctx, o.Duration)
	defer cancel()
	start := time.Now()
	var wg sync.WaitGroup
	for i, a := range agents {
		phase := time.Duration(0)
		if !o.Surge {
			phase = time.Duration(r.Int64N(int64(o.Interval)))
		}
		seed := uint64(i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			ar := rand.New(rand.NewPCG(o.Seed, seed))
			next := start.Add(phase)
			for {
				select {
				case <-time.After(time.Until(next)):
				case <-runCtx.Done():
					return
				}
				for _, target := range targets.urls() {
					rctx, c := context.WithTimeout(runCtx, o.Timeout)
					resp := o.Ingest.DoH(rctx, o.ID, http.MethodPost, target+"/agent/report", a.body, headers, false)
					c()
					oc := hist.Classify(resp.Err, runCtx.Err())
					if oc == hist.Aborted && runCtx.Err() != nil {
						return
					}
					rec.Record("POST /agent/report", resp.Status, int64(len(a.body)), resp.Elapsed, oc, resp.Err)
					sent.Add(int64(len(a.body)))
				}
				d := o.Interval
				if o.Jitter > 0 && !o.Surge {
					d += time.Duration((ar.Float64()*2 - 1) * o.Jitter * float64(o.Interval))
				}
				next = next.Add(d)
				if o.Surge {
					// Stay aligned to the interval grid like agents restarted together.
					next = start.Add(time.Since(start).Truncate(o.Interval) + o.Interval)
				}
			}
		}()
	}
	t := time.NewTicker(15 * time.Second)
loop:
	for {
		select {
		case <-runCtx.Done():
			break loop
		case <-t.C:
			w := rec.Window(15 * time.Second)
			out.Logf("agents: last 15s %d posts, %d errors, p99 %.0fms", w.Requests, w.Errors, w.P99)
		}
	}
	t.Stop()
	wg.Wait()
	res.Seconds = time.Since(start).Seconds()
	res.Posts = rec.Report()
	for _, p := range res.Posts {
		for k, v := range p.Status {
			switch {
			case k == "204" || k == "200":
				res.Success += v
			case k == "429":
				res.Status429 += v
			case strings.HasPrefix(k, "5"):
				res.Status5xx += v
			case k == "timeout":
				res.Timeouts += v
			}
		}
		if p.Requests > 0 {
			res.SuccessRate = float64(res.Success) / float64(p.Requests-p.Aborted)
		}
		res.PostsPerSec = float64(p.Requests) / res.Seconds
	}
	res.MBytesPerSec = float64(sent.Load()) / res.Seconds / (1 << 20)
	res.Targets = len(targets.urls())

	// Freshness: are the simulated pods' processes served, and fresh?
	var pods []*corev1.Pod
	for _, a := range agents[:min(len(agents), len(names))] {
		pods = append(pods, a.pods...)
	}
	r.Shuffle(len(pods), func(i, j int) { pods[i], pods[j] = pods[j], pods[i] })
	if len(pods) > o.CheckPods {
		pods = pods[:o.CheckPods]
	}
	frec := hist.NewRecorder()
	for _, p := range pods {
		var pr ks.ProcessesResponse
		cctx, c := context.WithTimeout(ctx, o.Timeout)
		resp, err := o.Client.GetJSON(cctx, o.APIID, fmt.Sprintf("/api/v1/pods/%s/%s/processes", url.PathEscape(p.Namespace), url.PathEscape(p.Name)), &pr)
		c()
		frec.Record("GET processes (fake pod)", resp.Status, resp.Bytes, resp.Elapsed, hist.Classify(resp.Err, ctx.Err()), resp.Err)
		res.CheckedPods++
		switch {
		case err != nil:
			res.CheckErrors++
		case !pr.Available:
			res.Unavailable++
		case pr.Stale:
			res.Stale++
		default:
			res.Fresh++
		}
	}
	res.Freshness = frec.Report()
	out.Logf("agents: %d posts, success %.1f%%, 429 %d, 5xx %d, timeouts %d; freshness %d fresh, %d stale, %d unavailable, %d errors of %d",
		res.Success+res.Status429+res.Status5xx+res.Timeouts, 100*res.SuccessRate, res.Status429, res.Status5xx, res.Timeouts, res.Fresh, res.Stale, res.Unavailable, res.CheckErrors, res.CheckedPods)
	return res, nil
}
