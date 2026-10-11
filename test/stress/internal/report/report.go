package report

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"k8s.io/client-go/kubernetes"

	"github.com/ByronGary/kubesentry/test/stress/internal/agents"
	"github.com/ByronGary/kubesentry/test/stress/internal/conn"
	"github.com/ByronGary/kubesentry/test/stress/internal/firehose"
	"github.com/ByronGary/kubesentry/test/stress/internal/gen"
	"github.com/ByronGary/kubesentry/test/stress/internal/hist"
	"github.com/ByronGary/kubesentry/test/stress/internal/out"
	"github.com/ByronGary/kubesentry/test/stress/internal/users"
	"github.com/ByronGary/kubesentry/test/stress/internal/verify"
)

// Step is one line of steps.tsv, written by hack/stress-run.sh.
type Step struct {
	Name          string    `json:"name"`
	Start         time.Time `json:"start"`
	End           time.Time `json:"end"`
	Status        string    `json:"status"`
	RestartsStart int       `json:"restartsStart"`
	RestartsEnd   int       `json:"restartsEnd"`
	LastReason    string    `json:"lastTerminationReason,omitempty"`
	Note          string    `json:"note,omitempty"`
}

// ReadSteps parses steps.tsv: name, start epoch, end epoch, status,
// restarts at start, restarts at end, last termination reason, note.
func ReadSteps(path string) ([]Step, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Step
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Split(sc.Text(), "\t")
		if len(parts) < 4 || strings.HasPrefix(parts[0], "#") {
			continue
		}
		s := Step{Name: parts[0], Status: parts[3]}
		a, _ := strconv.ParseInt(parts[1], 10, 64)
		b, _ := strconv.ParseInt(parts[2], 10, 64)
		s.Start, s.End = time.Unix(a, 0).UTC(), time.Unix(b, 0).UTC()
		if len(parts) > 5 {
			s.RestartsStart, _ = strconv.Atoi(parts[4])
			s.RestartsEnd, _ = strconv.Atoi(parts[5])
		}
		if len(parts) > 6 {
			s.LastReason = parts[6]
		}
		if len(parts) > 7 {
			s.Note = parts[7]
		}
		out = append(out, s)
	}
	return out, sc.Err()
}

// Usage is resource use of one component over a step.
type Usage struct {
	MemMiB Stat `json:"memMiB"`
	CPU    Stat `json:"cpuCores"`
}

// StepReport is everything measured during one step.
type StepReport struct {
	Step
	Seconds         float64          `json:"seconds"`
	Usage           map[string]Usage `json:"usage"` // kubesentry, kube-apiserver, etcd, prometheus, kwok, controller-manager
	KubesentryAPI   *APILoad         `json:"kubesentryAPI,omitempty"`
	APIServerRPS    Stat             `json:"apiserverRequestsPerSecond"`
	HostAvailMinMiB float64          `json:"hostAvailableMinMiB"`
	Restarts        int              `json:"kubesentryRestarts"` // restartCount delta; LastReason says whether OOMKilled
}

// Report is report.json.
type Report struct {
	Run           string                      `json:"run"`
	Level         string                      `json:"level"`
	Variant       string                      `json:"variant"`
	Generated     time.Time                   `json:"generated"`
	MemoryLimit   string                      `json:"kubesentryMemoryLimit"`
	Steps         []StepReport                `json:"steps"`
	Gen           *gen.Result                 `json:"gen,omitempty"`
	Assoc         *verify.AssocResult         `json:"assoc,omitempty"`
	Conn          *conn.Result                `json:"conn,omitempty"`
	Users         map[string]*users.Result    `json:"users,omitempty"`
	Audit         *firehose.Result            `json:"audit,omitempty"`
	AuditExtra    map[string]*firehose.Result `json:"auditExtra,omitempty"` // e.g. audit-1Gi.json
	Agents        map[string]*agents.Result   `json:"agents,omitempty"`
	KubesentryMem []Point                     `json:"kubesentryMemMiB"`
	OOMQuery      *OOMQuery                   `json:"oomQuery,omitempty"`
	Errors        []string                    `json:"errors,omitempty"`
}

// OOMQuery sizes the Prometheus answer behind /api/v1/oom?window=24h.
type OOMQuery struct {
	Bytes          int     `json:"bytes"`
	Series         int     `json:"series"`
	Points         int     `json:"points"`
	BytesPerPoint  float64 `json:"bytesPerPoint"`
	Projected24hMB float64 `json:"projected24hMB"` // with 240 points per series (24h of history at the 6m step)
	CapMB          float64 `json:"capMB"`
	Error          string  `json:"error,omitempty"`
}

// Options configure a report.
type Options struct {
	Dir          string
	Run          string
	Level        string
	Variant      string
	MemoryLimit  string
	ControlPlane string
	GuardCSV     string
	SkipAudit    bool
}

var components = map[string]string{
	"kubesentry":         `namespace="kubesentry",container="server"`,
	"kube-apiserver":     `namespace="kube-system",container="kube-apiserver"`,
	"etcd":               `namespace="kube-system",container="etcd"`,
	"prometheus":         `namespace="monitoring",container="prometheus"`,
	"kwok":               `namespace="kube-system",container="kwok-controller"`,
	"controller-manager": `namespace="kube-system",container="kube-controller-manager"`,
	"stress-load":        `namespace="stress-load"`,
	"oauth2-proxy":       `namespace="kubesentry",container="oauth2-proxy"`,
	"postgres":           `namespace="stress-pg",container="postgres"`,
}

// Build gathers everything for a run directory.
func Build(ctx context.Context, cs kubernetes.Interface, o Options) (*Report, error) {
	r := &Report{Run: o.Run, Level: o.Level, Variant: o.Variant, Generated: time.Now().UTC(), MemoryLimit: o.MemoryLimit,
		Users: map[string]*users.Result{}, Agents: map[string]*agents.Result{}}
	steps, err := ReadSteps(filepath.Join(o.Dir, "steps.tsv"))
	if err != nil {
		return nil, err
	}
	load := func(name string, v any) bool {
		if err := out.ReadJSON(filepath.Join(o.Dir, name), v); err != nil {
			if !os.IsNotExist(err) {
				r.Errors = append(r.Errors, name+": "+err.Error())
			}
			return false
		}
		return true
	}
	var g gen.Result
	if load("gen.json", &g) {
		r.Gen = &g
	}
	var a verify.AssocResult
	if load("assoc.json", &a) {
		r.Assoc = &a
	}
	var c conn.Result
	if load("conn.json", &c) {
		r.Conn = &c
	}
	var fh firehose.Result
	if load("audit.json", &fh) {
		r.Audit = &fh
	}
	r.AuditExtra = map[string]*firehose.Result{}
	extra, _ := filepath.Glob(filepath.Join(o.Dir, "audit-*.json"))
	for _, f := range extra {
		var a firehose.Result
		if load(filepath.Base(f), &a) {
			r.AuditExtra[strings.TrimSuffix(filepath.Base(f), ".json")] = &a
		}
	}
	files, _ := filepath.Glob(filepath.Join(o.Dir, "users*.json"))
	for _, f := range files {
		var u users.Result
		if load(filepath.Base(f), &u) {
			r.Users[strings.TrimSuffix(filepath.Base(f), ".json")] = &u
		}
	}
	files, _ = filepath.Glob(filepath.Join(o.Dir, "agents*.json"))
	for _, f := range files {
		var ag agents.Result
		if load(filepath.Base(f), &ag) {
			r.Agents[strings.TrimSuffix(filepath.Base(f), ".json")] = &ag
		}
	}
	if len(steps) == 0 {
		return r, nil
	}
	from, to := steps[0].Start, steps[len(steps)-1].End
	for _, s := range steps {
		if s.End.After(to) {
			to = s.End
		}
	}
	step := 15 * time.Second
	if to.Sub(from) > 3*time.Hour {
		step = 30 * time.Second
	}
	p := &Prom{CS: cs, Namespace: "monitoring", Service: "kps-kube-prometheus-stack-prometheus", Port: "9090"}
	mem, cpu := map[string][]Point{}, map[string][]Point{}
	for name, sel := range components {
		ms, err := p.Range(ctx, fmt.Sprintf(`sum(container_memory_working_set_bytes{%s,container!="",container!="POD"}) / 1048576`, sel), from.Add(-time.Minute), to.Add(time.Minute), step)
		if err != nil {
			r.Errors = append(r.Errors, err.Error())
		} else {
			mem[name] = Sum(ms)
		}
		cs, err := p.Range(ctx, fmt.Sprintf(`sum(rate(container_cpu_usage_seconds_total{%s,container!="",container!="POD"}[1m]))`, sel), from.Add(-time.Minute), to.Add(time.Minute), step)
		if err != nil {
			r.Errors = append(r.Errors, err.Error())
		} else {
			cpu[name] = Sum(cs)
		}
	}
	var apiRPS []Point
	if s, err := p.Range(ctx, `sum(rate(apiserver_request_total[1m]))`, from, to, step); err == nil {
		apiRPS = Sum(s)
	} else {
		r.Errors = append(r.Errors, err.Error())
	}
	for _, pt := range mem["kubesentry"] {
		if len(r.KubesentryMem) == 0 || pt.T.Sub(r.KubesentryMem[len(r.KubesentryMem)-1].T) >= time.Minute {
			r.KubesentryMem = append(r.KubesentryMem, pt)
		}
	}
	guard := readGuard(o.GuardCSV)
	{
		// Same query and step as kubesentry's findLeaks for window=24h.
		oq := &OOMQuery{CapMB: 64}
		b, ser, pts, err := p.RawSize(ctx, `max by (namespace, pod, container) (container_memory_working_set_bytes{container!="",container!="POD"})`, to, 24*time.Hour, 6*time.Minute)
		oq.Bytes, oq.Series, oq.Points = b, ser, pts
		if err != nil {
			oq.Error = err.Error()
		}
		if pts > 0 {
			oq.BytesPerPoint = float64(b) / float64(pts)
			oq.Projected24hMB = oq.BytesPerPoint * float64(ser) * 240 / (1 << 20)
		}
		r.OOMQuery = oq
	}

	windows := map[string][2]time.Time{}
	for _, s := range steps {
		windows[s.Name] = [2]time.Time{s.Start, s.End}
	}
	var loads map[string]*APILoad
	if !o.SkipAudit && o.ControlPlane != "" {
		loads, err = AuditLog(ctx, o.ControlPlane, "system:serviceaccount:kubesentry:kubesentry", windows)
		if err != nil {
			r.Errors = append(r.Errors, "audit log: "+err.Error())
		}
	}
	for _, s := range steps {
		sr := StepReport{Step: s, Seconds: s.End.Sub(s.Start).Seconds(), Usage: map[string]Usage{}}
		for name := range components {
			sr.Usage[name] = Usage{MemMiB: StatOf(mem[name], s.Start, s.End), CPU: StatOf(cpu[name], s.Start, s.End)}
		}
		sr.APIServerRPS = StatOf(apiRPS, s.Start, s.End)
		sr.Restarts = s.RestartsEnd - s.RestartsStart
		if sr.Restarts < 0 { // a new pod (e.g. the memory limit changed): its own count
			sr.Restarts = s.RestartsEnd
		}
		if loads != nil {
			sr.KubesentryAPI = loads[s.Name]
		}
		sr.HostAvailMinMiB = guardMin(guard, s.Start, s.End)
		r.Steps = append(r.Steps, sr)
	}
	return r, nil
}

func sortPoints(p []Point) { sort.Slice(p, func(i, j int) bool { return p[i].T.Before(p[j].T) }) }

type guardSample struct {
	t     time.Time
	avail float64
}

// readGuard reads hack/stress-guard.sh samples: epoch,iso,total,available,...
func readGuard(path string) []guardSample {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []guardSample
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Split(sc.Text(), ",")
		if len(parts) < 4 {
			continue
		}
		e, err1 := strconv.ParseInt(parts[0], 10, 64)
		a, err2 := strconv.ParseFloat(parts[3], 64)
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, guardSample{time.Unix(e, 0), a})
	}
	return out
}

func guardMin(g []guardSample, from, to time.Time) float64 {
	m := 0.0
	for _, s := range g {
		if s.t.Before(from) || s.t.After(to) {
			continue
		}
		if m == 0 || s.avail < m {
			m = s.avail
		}
	}
	return m
}

// MainRoutes are the routes shown in latency tables.
var MainRoutes = []string{"info", "pods", "diagnostics", "processes", "oom", "pvcs-unused", "workloads", "nodes", "map", "security", "storage", "certificates", "audit-events", "audit-summary"}

func routeOf(rs []hist.RouteReport, name string) *hist.RouteReport {
	for i := range rs {
		if rs[i].Route == name {
			return &rs[i]
		}
	}
	return nil
}

func ms(v float64) string {
	switch {
	case v == 0:
		return "-"
	case v >= 10000:
		return fmt.Sprintf("%.0fs", v/1000)
	case v >= 1000:
		return fmt.Sprintf("%.1fs", v/1000)
	}
	return fmt.Sprintf("%.0fms", v)
}

// Markdown renders report.md.
func (r *Report) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Stress report: %s (%s, level %s)\n\nGenerated %s. kubesentry memory limit: %s.\n\n", r.Run, r.Variant, r.Level, r.Generated.Format(time.RFC3339), r.MemoryLimit)
	if g := r.Gen; g != nil {
		fmt.Fprintf(&b, "## Cluster\n\n- Plan: %d fake nodes (%v), %d team + %d add-on namespaces, %d Deployments, %d StatefulSets, %d DaemonSets, %d Jobs, %d CronJobs, %d bare pods\n",
			g.Plan.Nodes, g.Plan.NodesByPool, g.Plan.TeamNamespaces, g.Plan.AddonNamespaces, g.Plan.Deployments, g.Plan.StatefulSets, g.Plan.DaemonSets, g.Plan.Jobs, g.Plan.CronJobs, g.Plan.BarePods)
		fmt.Fprintf(&b, "- Services %v, Ingresses %v, %d PVCs / %d PVs, %d Roles, %d RoleBindings, %d ClusterRoles, %d ClusterRoleBindings, %d Certificates\n",
			g.Plan.Services, g.Plan.Ingresses, g.Plan.PVCs, g.Plan.PVs, g.Plan.Roles, g.Plan.RoleBindings, g.Plan.ClusterRoles, g.Plan.ClusterRoleBindings, g.Plan.Certificates)
		fmt.Fprintf(&b, "- After settling: %d nodes (%d fake, %d ready), %d pods %v; generator: %d created, %d existed, %d failed; phases %v\n\n",
			g.Settle.Nodes, g.Settle.FakeNodes, g.Settle.FakeNodesReady, g.Settle.Pods, g.Settle.PodsByPhase, g.Created, g.Existed, g.Failed, g.PhaseSeconds)
	}
	fmt.Fprintf(&b, "## Steps and resource use\n\n| Step | Status | Duration | kubesentry mem avg/max MiB | kubesentry CPU avg/max | restarts | last termination | kubesentry API req/s avg (peak min) | apiserver mem max MiB | apiserver CPU max | etcd mem max | Prometheus mem max | Postgres mem / CPU max | oauth2-proxy CPU max | host avail min MiB |\n|---|---|---:|---|---|---:|---|---|---:|---:|---:|---:|---|---:|---:|\n")
	for _, s := range r.Steps {
		k := s.Usage["kubesentry"]
		api := "-"
		if s.KubesentryAPI != nil {
			api = fmt.Sprintf("%.2f (%.2f)", s.KubesentryAPI.PerSecond, s.KubesentryAPI.PeakPerSec)
		}
		pg := "-"
		if u := s.Usage["postgres"]; u.MemMiB.N > 0 {
			pg = fmt.Sprintf("%.0f / %.2f", u.MemMiB.Max, u.CPU.Max)
		}
		fmt.Fprintf(&b, "| %s | %s | %.0fs | %.0f / %.0f | %.2f / %.2f | %d | %s | %s | %.0f | %.2f | %.0f | %.0f | %s | %.2f | %.0f |\n",
			s.Name, s.Status, s.Seconds, k.MemMiB.Avg, k.MemMiB.Max, k.CPU.Avg, k.CPU.Max, s.Restarts, s.LastReason, api,
			s.Usage["kube-apiserver"].MemMiB.Max, s.Usage["kube-apiserver"].CPU.Max, s.Usage["etcd"].MemMiB.Max, s.Usage["prometheus"].MemMiB.Max,
			pg, s.Usage["oauth2-proxy"].CPU.Max, s.HostAvailMinMiB)
	}
	for _, s := range r.Steps {
		if s.KubesentryAPI == nil || s.KubesentryAPI.Requests == 0 {
			continue
		}
		type kv struct {
			k string
			v int
		}
		var top []kv
		for k, v := range s.KubesentryAPI.ByVerbRes {
			top = append(top, kv{k, v})
		}
		sort.Slice(top, func(i, j int) bool { return top[i].v > top[j].v })
		if len(top) > 8 {
			top = top[:8]
		}
		var parts []string
		for _, t := range top {
			parts = append(parts, fmt.Sprintf("%s %d", t.k, t.v))
		}
		fmt.Fprintf(&b, "\n- kubesentry → API server during **%s**: %d requests (%.2f/s, peak minute %.2f/s), codes %v, server time p50 %s p99 %s; top: %s",
			s.Name, s.KubesentryAPI.Requests, s.KubesentryAPI.PerSecond, s.KubesentryAPI.PeakPerSec, s.KubesentryAPI.Codes,
			ms(s.KubesentryAPI.ServerTimeMs.P50), ms(s.KubesentryAPI.ServerTimeMs.P99), strings.Join(parts, ", "))
		if s.KubesentryAPI.Truncated {
			fmt.Fprintf(&b, " (audit log rotated: oldest line %s)", s.KubesentryAPI.OldestSeen.Format(time.RFC3339))
		}
	}
	b.WriteString("\n\n")
	if a := r.Assoc; a != nil {
		fmt.Fprintf(&b, "## Association (verify assoc)\n\n| Relation@source | Precision | Recall | Truth | Reported |\n|---|---:|---:|---:|---:|\n")
		keys := make([]string, 0, len(a.Summary))
		for k := range a.Summary {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			s := a.Summary[k]
			fmt.Fprintf(&b, "| %s | %.1f%% | %.1f%% | %d | %d |\n", k, 100*s.Precision, 100*s.Recall, s.Truth, s.Observed)
		}
		pass, total := 0, 0
		for _, c := range a.Cases {
			total++
			if c.OK {
				pass++
			}
		}
		fmt.Fprintf(&b, "\nTricky-case expectations kubesentry meets: %d/%d. Top mismatch categories:\n\n", pass, total)
		gs := append([]verify.Group(nil), a.Mismatches...)
		sort.Slice(gs, func(i, j int) bool { return gs[i].Count > gs[j].Count })
		for i, g := range gs {
			if i >= 15 {
				break
			}
			fmt.Fprintf(&b, "- %s: %s ×%d (e.g. %s)\n", g.Case, g.Category, g.Count, first(g.Samples))
		}
		fmt.Fprintf(&b, "\nSee assoc.md for the full case table.\n\n")
	}
	if q := r.OOMQuery; q != nil {
		fmt.Fprintf(&b, "## /oom and Prometheus\n\nThe range query behind /api/v1/oom?window=24h, run for the end of this run, returned %.1f MB (%d series, %d points, %.0f bytes/point; Prometheus keeps 6h here). With 24h of history (240 points per series) it would be about **%.0f MB** against kubesentry's %.0f MiB read cap.%s\n\n",
			float64(q.Bytes)/1e6, q.Series, q.Points, q.BytesPerPoint, q.Projected24hMB, q.CapMB, map[bool]string{true: " Error: " + q.Error, false: ""}[q.Error != ""])
	}
	if c := r.Conn; c != nil {
		fmt.Fprintf(&b, "## Connectivity\n\n%d passed, %d failed: %v. Prometheus: info.metrics=%v, /oom metricsAvailable=%v (%s). Agents fresh on real nodes: %d/%d. See conn.md.\n\n",
			c.Passed, c.Failed, c.ByCheck, c.Prometheus.InfoMetrics, c.Prometheus.OOMOK, ms(c.Prometheus.OOMMs), countAgents(c.Agents), len(c.Agents))
	}
	names := make([]string, 0, len(r.Users))
	for n := range r.Users {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		u := r.Users[n]
		fmt.Fprintf(&b, "## Users: %s\n\nStages %s, think %s, request timeout %s.", n, u.Options.Stages, u.Options.Think, u.Options.ReqTimeout)
		if u.Aborted {
			fmt.Fprintf(&b, " **Aborted:** %s.", u.Reason)
		}
		fmt.Fprintf(&b, "\n\nLatency p50 / p95 / p99 over all requests; timeouts, superseded and abandoned requests count at their elapsed time (a lower bound). Error rate = 5xx, 429, timeouts, transport errors and superseded polls (still running when the page's next poll replaced it, as the browser does) over requests not abandoned by navigation.\n\n| Users | req/s |")
		for _, rt := range MainRoutes {
			fmt.Fprintf(&b, " %s |", rt)
		}
		b.WriteString(" errors | timeouts | superseded | abandoned |\n|---:|---:|")
		for range MainRoutes {
			b.WriteString("---|")
		}
		b.WriteString("---:|---:|---:|---:|\n")
		for _, s := range u.Stages {
			var reqs, bad, tos, ab, sup int64
			fmt.Fprintf(&b, "| %d | %.1f |", s.Users, s.RPS)
			for _, rn := range MainRoutes {
				rr := routeOf(s.Routes, rn)
				if rr == nil {
					b.WriteString(" - |")
					continue
				}
				fmt.Fprintf(&b, " %s / %s / %s |", ms(rr.All.P50), ms(rr.All.P95), ms(rr.All.P99))
			}
			for _, rr := range s.Routes {
				reqs += rr.Requests - rr.Aborted
				bad += int64(rr.ErrorRate * float64(rr.Requests-rr.Aborted))
				tos += rr.Timeouts
				ab += rr.Aborted
				sup += rr.Superseded
			}
			er := 0.0
			if reqs > 0 {
				er = float64(bad) / float64(reqs)
			}
			fmt.Fprintf(&b, " %.1f%% | %d | %d | %d |\n", 100*er, tos, sup, ab)
		}
		for _, s := range u.Stages {
			fmt.Fprintf(&b, "\n%d users, page loads:", s.Users)
			for _, pl := range s.PageLoads {
				fmt.Fprintf(&b, " %s p50 %s p95 %s (%d, %d not loaded within the page timeout);", strings.TrimPrefix(pl.Route, "page:"), ms(pl.All.P50), ms(pl.All.P95), pl.Requests, pl.Timeouts)
			}
			fmt.Fprintf(&b, "\n%d users, status codes:", s.Users)
			for _, rr := range s.Routes {
				fmt.Fprintf(&b, " %s %v (%.0f KB avg);", rr.Route, rr.Status, float64(rr.MeanBytes)/1024)
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	audits := []struct {
		name string
		a    *firehose.Result
	}{{"audit", r.Audit}}
	for n, a := range r.AuditExtra {
		audits = append(audits, struct {
			name string
			a    *firehose.Result
		}{n, a})
	}
	for _, au := range audits {
		a := au.a
		if a == nil {
			continue
		}
		fmt.Fprintf(&b, "## Audit firehose: %s\n\n", au.name)
		fmt.Fprintf(&b, "%d of %d events accepted in %.0fs: **%.0f events/s** (target %.0f/s, batches of %d), %d failed batches, %.0f MB sent.",
			a.AcceptedEvents, a.SentEvents, a.Seconds, a.AchievedRate, a.TargetRate, a.BatchSize, a.FailedBatches, float64(a.PayloadBytes)/1e6)
		if a.Stopped != "" {
			fmt.Fprintf(&b, " Stopped: %s.", a.Stopped)
		}
		for _, in := range a.Ingest {
			fmt.Fprintf(&b, " Webhook latency p50 %s p95 %s p99 %s max %s, status %v.", ms(in.All.P50), ms(in.All.P95), ms(in.All.P99), ms(in.All.Max), in.Status)
		}
		for _, d := range a.DuringIngest {
			fmt.Fprintf(&b, " Findings audit query during ingest: p50 %s p99 %s (%d).", ms(d.All.P50), ms(d.All.P99), d.Requests)
		}
		fmt.Fprintf(&b, "\n\n| Query (store full) | n | status | p50 | p95 | p99 | max | KB | returned |\n|---|---:|---|---:|---:|---:|---:|---:|---:|\n")
		for _, q := range a.Queries {
			fmt.Fprintf(&b, "| %s | %d | %v %v | %s | %s | %s | %s | %.0f | %d |\n", q.Route, q.Requests, q.Status, q.Errors, ms(q.All.P50), ms(q.All.P95), ms(q.All.P99), ms(q.All.Max), float64(q.MeanBytes)/1024, a.StoreView[q.Route])
		}
		b.WriteString("\n")
	}
	names = names[:0]
	for n := range r.Agents {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		ag := r.Agents[n]
		fmt.Fprintf(&b, "## Agents: %s (%s)\n\n%d agents (%d real fake-node names, %d synthetic), %d pods covered, %d processes per round, report size p50 %.0f KB max %.0f KB, every %s for %.0fs: %.1f posts/s, %.1f MB/s.\n",
			n, ag.Mode, ag.Agents, ag.RealNodes, ag.SimNodes, ag.PodsCovered, ag.Processes, ag.ReportBytes.P50, ag.ReportBytes.Max, ag.Interval, ag.Seconds, ag.PostsPerSec, ag.MBytesPerSec)
		for _, p := range ag.Posts {
			fmt.Fprintf(&b, "POST /agent/report: %d posts, success %.1f%%, 429 %d, 5xx %d, timeouts %d; latency p50 %s p95 %s p99 %s max %s; status %v.\n",
				p.Requests, 100*ag.SuccessRate, ag.Status429, ag.Status5xx, ag.Timeouts, ms(p.All.P50), ms(p.All.P95), ms(p.All.P99), ms(p.All.Max), p.Status)
		}
		for _, f := range ag.Freshness {
			fmt.Fprintf(&b, "Freshness check of %d fake pods: %d fresh, %d stale, %d unavailable, %d errors; GET processes p50 %s p99 %s.\n",
				ag.CheckedPods, ag.Fresh, ag.Stale, ag.Unavailable, ag.CheckErrors, ms(f.All.P50), ms(f.All.P99))
		}
		b.WriteString("\n")
	}
	if len(r.Errors) > 0 {
		fmt.Fprintf(&b, "## Collection errors\n\n")
		for _, e := range r.Errors {
			fmt.Fprintf(&b, "- %s\n", e)
		}
	}
	return b.String()
}

func first(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return strings.ReplaceAll(s[0], "|", " → ")
}

func countAgents(a []conn.AgentCheck) int {
	n := 0
	for _, x := range a {
		if x.OK {
			n++
		}
	}
	return n
}
