// Package chaos runs chaos scenarios against a running kubesentry on the kind
// cluster: the checkpoint-D smoke set (a replica killed: CloudWatch lock and
// agents; Prometheus down and up; Postgres down for two minutes under an
// audit firehose; an API server restart; identity headers spoofed through
// kubectl port-forward; oversized agent reports) and the Phase 4 set in
// phase4.go (worker stop, drain, RBAC storm, pod churn, a big rollout, a big
// namespace deleted, a cold restart under load). It runs on the host: it needs
// docker exec into the kind nodes and kubectl. Probes go from inside a node
// (curl to ClusterIPs and pod IPs), so they keep working while the API server
// is down.
package chaos

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/ByronGary/kubesentry/test/stress/internal/cwserve"
	"github.com/ByronGary/kubesentry/test/stress/internal/firehose"
	"github.com/ByronGary/kubesentry/test/stress/internal/ks"
	"github.com/ByronGary/kubesentry/test/stress/internal/out"
)

// Options configure the run.
type Options struct {
	CS           kubernetes.Interface
	Context      string
	ProbeNode    string // kind node container the probes run from
	ControlPlane string
	Namespace    string // kubesentry's
	AdminToken   string
	NobodyToken  string
	AgentToken   string
	AuditToken   string
	CW           cwserve.Options // the live cwfake tail, for the lock-move check
	Scenarios    []string
	PGDown       time.Duration
	FirehoseRate float64
	FirehoseFor  time.Duration

	// Phase 4 scenarios.
	StopNode        string        // workerstop: kind node container to stop
	StopFor         time.Duration // ... and how long
	DrainNode       string        // drain: real worker to drain
	DrainSelector   string        // ... pods kubectl drain may evict
	TeamNamespaces  []string      // rbacstorm: where the RoleBindings go
	StormN          int
	StormRate       float64 // RoleBindings per second per phase
	StormPersonas   []StormPersona
	Mint            func(email string, groups []string) string
	ChurnRate       float64
	ChurnFor        time.Duration
	ChurnLife       time.Duration
	RolloutReplicas int
	NSDeletePods    int
	UsersFile       string // coldrestart: the users result written by the concurrent load
}

// Step is one timed observation.
type Step struct {
	At     string `json:"at"`
	What   string `json:"what"`
	Detail string `json:"detail"`
}

// Scenario is one chaos experiment.
type Scenario struct {
	Name     string         `json:"name"`
	Started  time.Time      `json:"started"`
	Ended    time.Time      `json:"ended"`
	Pass     bool           `json:"pass"`
	Seconds  float64        `json:"seconds"`
	Summary  string         `json:"summary"`
	Numbers  map[string]any `json:"numbers,omitempty"`
	Problems []string       `json:"problems,omitempty"`
	Timeline []Step         `json:"timeline,omitempty"`
}

// Result is chaos.json.
type Result struct {
	Started   time.Time  `json:"started"`
	Scenarios []Scenario `json:"scenarios"`
	Passed    int        `json:"passed"`
	Failed    int        `json:"failed"`
}

type runner struct {
	o         Options
	webIP     string // web Service ClusterIP (oauth2-proxy, 4180)
	ingestIP  string
	start     time.Time
	scenario  *Scenario
	scenStart time.Time
}

func (r *runner) note(what, detail string) {
	s := Step{At: fmt.Sprintf("+%.0fs", time.Since(r.scenStart).Seconds()), What: what, Detail: detail}
	r.scenario.Timeline = append(r.scenario.Timeline, s)
	out.Logf("chaos %s %s: %s %s", r.scenario.Name, s.At, what, detail)
}

func (r *runner) fail(format string, args ...any) {
	r.scenario.Problems = append(r.scenario.Problems, fmt.Sprintf(format, args...))
}

func (r *runner) kubectl(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "kubectl", append([]string{"--context", r.o.Context}, args...)...)
	b, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(b)), err
}

// curl runs curl inside the probe node and returns the status and body.
func (r *runner) curl(ctx context.Context, method, url string, headers map[string]string, body []byte) (int, string) {
	args := []string{"exec", "-i", r.o.ProbeNode, "curl", "-s", "-m", "30", "-X", method, "-o", "-", "-w", "\n%{http_code}"}
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		args = append(args, "-H", k+": "+headers[k])
	}
	if body != nil {
		args = append(args, "--data-binary", "@-")
	}
	args = append(args, url)
	cmd := exec.CommandContext(ctx, "docker", args...)
	if body != nil {
		cmd.Stdin = bytes.NewReader(body)
	}
	b, _ := cmd.Output()
	s := string(b)
	i := strings.LastIndexByte(s, '\n')
	if i < 0 {
		return 0, s
	}
	code, _ := strconv.Atoi(strings.TrimSpace(s[i+1:]))
	return code, s[:i]
}

func (r *runner) api(ctx context.Context, token, path string) (int, string) {
	return r.curl(ctx, "GET", "http://"+r.webIP+":4180"+path, map[string]string{"Authorization": "Bearer " + token}, nil)
}

type pod struct{ name, ip string }

func (r *runner) serverPods(ctx context.Context) []pod {
	l, err := r.o.CS.CoreV1().Pods(r.o.Namespace).List(ctx, metav1.ListOptions{LabelSelector: "app.kubernetes.io/component=server"})
	if err != nil {
		return nil
	}
	var out []pod
	for _, p := range l.Items {
		if p.DeletionTimestamp == nil && p.Status.PodIP != "" {
			out = append(out, pod{p.Name, p.Status.PodIP})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out
}

// metric reads one kubesentry metric from a pod's ops listener (from the node).
func (r *runner) metric(ctx context.Context, p pod, name string) (float64, bool) {
	code, body := r.curl(ctx, "GET", "http://"+p.ip+":9090/metrics", nil, nil)
	if code != 200 {
		return 0, false
	}
	sc := bufio.NewScanner(strings.NewReader(body))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		l := sc.Text()
		if strings.HasPrefix(l, name+" ") || strings.HasPrefix(l, name+"{") {
			f := strings.Fields(l)
			v, err := strconv.ParseFloat(f[len(f)-1], 64)
			return v, err == nil
		}
	}
	return 0, false
}

func (r *runner) readyz(ctx context.Context, p pod) (int, string) {
	return r.curl(ctx, "GET", "http://"+p.ip+":9090/readyz", nil, nil)
}

// Run runs the selected scenarios in order.
func Run(ctx context.Context, o Options) (*Result, error) {
	r := &runner{o: o, start: time.Now()}
	svc, err := o.CS.CoreV1().Services(o.Namespace).Get(ctx, "kubesentry", metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	r.webIP = svc.Spec.ClusterIP
	isvc, err := o.CS.CoreV1().Services(o.Namespace).Get(ctx, "kubesentry-ingest", metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	r.ingestIP = isvc.Spec.ClusterIP
	res := &Result{Started: time.Now().UTC()}
	all := map[string]func(context.Context){
		"spoof":       r.spoof,
		"oversize":    r.oversize,
		"prometheus":  r.prometheus,
		"postgres":    r.postgres,
		"apiserver":   r.apiserver,
		"killreplica": r.killReplica,
		"standby":     r.standbyTakeover,
		"workerstop":  r.workerStop,
		"drain":       r.drain,
		"rbacstorm":   r.rbacStorm,
		"churn":       r.churn,
		"rollout":     r.rollout,
		"nsdelete":    r.nsDelete,
		"coldrestart": r.coldRestart,
	}
	for _, name := range o.Scenarios {
		f, ok := all[name]
		if !ok {
			return nil, fmt.Errorf("unknown scenario %q", name)
		}
		r.scenario = &Scenario{Name: name, Numbers: map[string]any{}}
		r.scenStart = time.Now()
		r.scenario.Started = r.scenStart.UTC()
		f(ctx)
		r.scenario.Ended = time.Now().UTC()
		r.scenario.Seconds = time.Since(r.scenStart).Seconds()
		r.scenario.Pass = len(r.scenario.Problems) == 0
		if r.scenario.Pass {
			res.Passed++
		} else {
			res.Failed++
		}
		out.Logf("chaos %s: pass=%v %s %v", name, r.scenario.Pass, r.scenario.Summary, r.scenario.Problems)
		res.Scenarios = append(res.Scenarios, *r.scenario)
	}
	return res, nil
}

var forwarding = regexp.MustCompile(`Forwarding from 127\.0\.0\.1:(\d+)`)

// portForward starts kubectl port-forward to target's port and returns the
// local port and a stop function, or an error when it cannot forward.
func (r *runner) portForward(ctx context.Context, target string, port int) (int, func(), error) {
	pctx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(pctx, "kubectl", "--context", r.o.Context, "-n", r.o.Namespace, "port-forward", target, fmt.Sprintf("0:%d", port))
	stdout, _ := cmd.StdoutPipe()
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		cancel()
		return 0, nil, err
	}
	stop := func() { cancel(); _ = cmd.Wait() }
	ch := make(chan int, 1)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			if m := forwarding.FindStringSubmatch(sc.Text()); m != nil {
				p, _ := strconv.Atoi(m[1])
				ch <- p
				return
			}
		}
		close(ch)
	}()
	select {
	case p, ok := <-ch:
		if !ok {
			stop()
			return 0, nil, fmt.Errorf("port-forward %s:%d: %s", target, port, strings.TrimSpace(stderr.String()))
		}
		return p, stop, nil
	case <-time.After(15 * time.Second):
		stop()
		return 0, nil, fmt.Errorf("port-forward %s:%d: timeout", target, port)
	}
}

func localGet(ctx context.Context, port int, path string, headers map[string]string) (int, string, error) {
	args := []string{"-s", "-m", "15", "-o", "-", "-w", "\n%{http_code}"}
	for k, v := range headers {
		args = append(args, "-H", k+": "+v)
	}
	args = append(args, fmt.Sprintf("http://127.0.0.1:%d%s", port, path))
	b, err := exec.CommandContext(ctx, "curl", args...).Output()
	s := string(b)
	i := strings.LastIndexByte(s, '\n')
	if i < 0 {
		return 0, s, err
	}
	code, _ := strconv.Atoi(strings.TrimSpace(s[i+1:]))
	return code, s[:i], nil
}

// spoof: kubectl port-forward straight to a server pod must not let forged
// identity headers through. The web listener is a Unix socket, so only the
// sidecar (which strips and sets the headers) and the token-guarded ingest
// and ops ports can be reached.
func (r *runner) spoof(ctx context.Context) {
	pods := r.serverPods(ctx)
	if len(pods) == 0 {
		r.fail("no server pods")
		return
	}
	forged := map[string]string{
		"X-Forwarded-Email": "admin0@corp.example", "X-Forwarded-User": "admin0", "X-Forwarded-Preferred-Username": "admin0",
		"X-Forwarded-Groups": "stress:admins,system:masters", "X-Auth-Request-Email": "admin0@corp.example", "X-Remote-User": "admin0@corp.example",
	}
	target := "pod/" + pods[0].name
	checks := 0
	// 8080: there is no TCP web listener with the sidecar.
	if p, stop, err := r.portForward(ctx, target, 8080); err == nil {
		code, body, cerr := localGet(ctx, p, "/api/v1/info", forged)
		stop()
		checks++
		r.note("port 8080", fmt.Sprintf("HTTP %d %v", code, cerr))
		if code == 200 && strings.Contains(body, "admin0") {
			r.fail("port-forward to 8080 served /api/v1/info as the forged identity")
		}
	} else {
		r.note("port 8080", "no listener: "+err.Error())
	}
	// 4180: oauth2-proxy. Forged headers alone get 401; with a real token for
	// a user with no grants, the identity is that user, not the forged one.
	if p, stop, err := r.portForward(ctx, target, 4180); err == nil {
		noTok, _, _ := localGet(ctx, p, "/api/v1/info", forged)
		checks++
		r.note("port 4180 forged headers, no token", fmt.Sprintf("HTTP %d", noTok))
		r.scenario.Numbers["sidecarForgedHeadersNoToken"] = noTok
		if noTok != 401 {
			r.fail("oauth2-proxy answered %d to forged headers without a token", noTok)
		}
		h := map[string]string{"Authorization": "Bearer " + r.o.NobodyToken}
		for k, v := range forged {
			h[k] = v
		}
		code, body, _ := localGet(ctx, p, "/api/v1/info", h)
		var info ks.InfoFull
		_ = json.Unmarshal([]byte(body), &info)
		user, groups := "", []string(nil)
		if info.Identity != nil {
			user, groups = info.Identity.User, info.Identity.Groups
		}
		r.note("port 4180 forged headers + nobody's token", fmt.Sprintf("HTTP %d user %q groups %v caps %v", code, user, groups, info.Capabilities))
		if user != "nobody@corp.example" || strings.Contains(strings.Join(groups, ","), "admins") || info.Capabilities["nodes"] {
			r.fail("forged headers changed the identity behind a valid token: user %q groups %v", user, groups)
		}
		r.scenario.Numbers["sidecarForgedHeadersWithNobodysToken"] = fmt.Sprintf("HTTP %d as %s", code, user)
		stop()
	} else {
		r.fail("port-forward 4180: %v", err)
	}
	// 8081 and 9090: no /api routes there.
	for _, port := range []int{8081, 9090} {
		p, stop, err := r.portForward(ctx, target, port)
		if err != nil {
			r.fail("port-forward %d: %v", port, err)
			continue
		}
		code, body, _ := localGet(ctx, p, "/api/v1/pods", forged)
		stop()
		checks++
		r.note(fmt.Sprintf("port %d /api/v1/pods with forged headers", port), fmt.Sprintf("HTTP %d", code))
		if code == 200 && strings.Contains(body, "items") {
			r.fail("port %d served /api/v1/pods to forged headers", port)
		}
	}
	r.scenario.Summary = fmt.Sprintf("%d port-forward probes; forged identity headers never reached kubesentry", checks)
}

func processes(n int, cmdlineBytes int) []map[string]any {
	ps := make([]map[string]any, n)
	cmd := strings.Repeat("x", cmdlineBytes)
	for i := range ps {
		ps[i] = map[string]any{"pid": 1000 + i, "ppid": 1, "name": "sh", "cmdline": cmd, "podUID": "00000000-0000-0000-0000-000000000000", "containerID": "", "rssBytes": 1 << 20, "threads": 1, "cpuMillicores": 0}
	}
	return ps
}

// oversize: agent reports past the limits get 413 (or 415), never a crash.
func (r *runner) oversize(ctx context.Context) {
	url := "http://" + r.ingestIP + ":8081/agent/report"
	auth := map[string]string{"Authorization": "Bearer " + r.o.AgentToken, "Content-Type": "application/json"}
	cases := []struct {
		name    string
		body    func() []byte
		headers map[string]string
		want    int
	}{
		{"9 MiB body", func() []byte {
			b, _ := json.Marshal(map[string]any{"node": "chaos-node", "time": time.Now(), "processes": processes(2300, 4000)})
			return b
		}, nil, 413},
		{"25,000 processes", func() []byte {
			b, _ := json.Marshal(map[string]any{"node": "chaos-node", "time": time.Now(), "processes": processes(25000, 1)})
			return b
		}, nil, 413},
		{"gzip bomb (64 MiB inflated)", func() []byte {
			var zb bytes.Buffer
			zw, _ := gzip.NewWriterLevel(&zb, gzip.BestCompression)
			_, _ = zw.Write([]byte(`{"node":"chaos-node","processes":[{"pid":1,"name":"`))
			chunk := bytes.Repeat([]byte("A"), 1<<20)
			for i := 0; i < 64; i++ {
				_, _ = zw.Write(chunk)
			}
			_, _ = zw.Write([]byte(`"}]}`))
			_ = zw.Close()
			return zb.Bytes()
		}, map[string]string{"Content-Encoding": "gzip"}, 413},
		{"unsupported encoding", func() []byte { return []byte(`{"node":"chaos-node","processes":[]}`) }, map[string]string{"Content-Encoding": "br"}, 415},
	}
	for _, c := range cases {
		h := map[string]string{}
		for k, v := range auth {
			h[k] = v
		}
		for k, v := range c.headers {
			h[k] = v
		}
		body := c.body()
		code, resp := r.curl(ctx, "POST", url, h, body)
		r.note(c.name, fmt.Sprintf("%d bytes sent: HTTP %d %s", len(body), code, strings.TrimSpace(resp)))
		r.scenario.Numbers[c.name] = code
		if code != c.want {
			r.fail("%s: HTTP %d, want %d", c.name, code, c.want)
		}
	}
	// The server survived: both replicas still ready.
	for _, p := range r.serverPods(ctx) {
		if code, _ := r.readyz(ctx, p); code != 200 {
			r.fail("%s /readyz %d after oversized reports", p.name, code)
		}
	}
	r.scenario.Summary = fmt.Sprintf("413/413/413/415 expected; got %v", r.scenario.Numbers)
}

// prometheus: Prometheus down, then up. kubesentry keeps serving, says so,
// and recovers.
func (r *runner) prometheus(ctx context.Context) {
	patch := func(n int) error {
		_, err := r.kubectl(ctx, "-n", "monitoring", "patch", "prometheus", "kps-kube-prometheus-stack-prometheus", "--type", "merge", "-p", fmt.Sprintf(`{"spec":{"replicas":%d}}`, n))
		return err
	}
	if err := patch(0); err != nil {
		r.fail("scale Prometheus down: %v", err)
		return
	}
	r.note("Prometheus scaled to 0", "")
	defer func() {
		if err := patch(1); err != nil {
			r.fail("scale Prometheus up: %v", err)
		}
	}()
	// Wait for the pod to go.
	for i := 0; i < 60; i++ {
		l, _ := r.o.CS.CoreV1().Pods("monitoring").List(ctx, metav1.ListOptions{LabelSelector: "app.kubernetes.io/name=prometheus"})
		if l != nil && len(l.Items) == 0 {
			break
		}
		time.Sleep(2 * time.Second)
	}
	r.note("Prometheus pod gone", "")
	time.Sleep(10 * time.Second)
	code, body := r.api(ctx, r.o.AdminToken, "/api/v1/oom?window=1h")
	var oom ks.OOMResponse
	_ = json.Unmarshal([]byte(body), &oom)
	r.note("/oom?window=1h while down", fmt.Sprintf("HTTP %d metricsAvailable=%v warnings=%v", code, oom.MetricsAvailable, oom.Warnings))
	r.scenario.Numbers["oomWhileDown"] = code
	if code != 200 {
		r.fail("/oom answered %d while Prometheus was down (want 200 with a warning)", code)
	} else if oom.MetricsAvailable && len(oom.Warnings) == 0 {
		r.fail("/oom claimed metrics with Prometheus down")
	}
	code24, _ := r.api(ctx, r.o.AdminToken, "/api/v1/oom?window=24h")
	r.note("/oom?window=24h while down", fmt.Sprintf("HTTP %d", code24))
	codeInfo, infoBody := r.api(ctx, r.o.AdminToken, "/api/v1/info")
	r.note("/info while down", fmt.Sprintf("HTTP %d %s", codeInfo, excerpt(infoBody, "unavailable")))
	if code, _ := r.api(ctx, r.o.AdminToken, "/api/v1/pods?limit=5"); code != 200 {
		r.fail("/pods answered %d while Prometheus was down", code)
	}
	for _, p := range r.serverPods(ctx) {
		c, b := r.readyz(ctx, p)
		r.note(p.name+" /readyz while down", fmt.Sprintf("%d %s", c, b))
		if c != 200 {
			r.fail("%s not ready while only Prometheus is down (%d)", p.name, c)
		}
	}
	if err := patch(1); err != nil {
		r.fail("scale Prometheus up: %v", err)
		return
	}
	up := time.Now()
	r.note("Prometheus scaled to 1", "")
	recovered := false
	for time.Since(up) < 6*time.Minute {
		code, body := r.api(ctx, r.o.AdminToken, "/api/v1/oom?window=1h")
		var o ks.OOMResponse
		_ = json.Unmarshal([]byte(body), &o)
		if code == 200 && o.MetricsAvailable && len(o.Warnings) == 0 {
			recovered = true
			break
		}
		time.Sleep(5 * time.Second)
	}
	rec := time.Since(up).Seconds()
	r.scenario.Numbers["recoverySeconds"] = rec
	r.note("metrics back", fmt.Sprintf("%v after %.0fs", recovered, rec))
	if !recovered {
		r.fail("/oom did not report metrics within 6 minutes of Prometheus coming back")
	}
	r.scenario.Summary = fmt.Sprintf("served throughout (/oom %d with warning while down); metrics back %.0fs after Prometheus restarted", code, rec)
}

func firstN(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func excerpt(body, key string) string {
	i := strings.Index(body, key)
	if i < 0 {
		return ""
	}
	j := min(len(body), i+200)
	return body[i:j]
}

// postgres: the audit store's database is down for PGDown while an audit
// firehose runs through the webhook. Backpressure (503 + Retry-After) is fine;
// once it is back every accepted event must be stored exactly once.
func (r *runner) postgres(ctx context.Context) {
	p, stop, err := r.portForward(ctx, "svc/kubesentry-ingest", 8081)
	if err != nil {
		r.fail("port-forward ingest: %v", err)
		return
	}
	defer stop()
	idsFile := "/tmp/kubesentry-chaos-pg-ids.txt"
	total := int(r.o.FirehoseRate * r.o.FirehoseFor.Seconds())
	done := make(chan *firehose.Result, 1)
	go func() {
		ing := &ks.Client{Base: fmt.Sprintf("http://127.0.0.1:%d", p), HTTP: ks.NewHTTP(0, 16)}
		done <- firehose.Run(ctx, firehose.Options{
			Client: ing, Ingest: ing, AuditID: ks.Bearer{Token: r.o.AuditToken}, APIID: ks.Bearer{},
			Total: total, Rate: r.o.FirehoseRate, BatchSize: 500, Workers: 4, Namespaces: 150, QueryReps: 0, QueryConc: 1,
			Seed: uint64(time.Now().UnixNano()), Timeout: 60 * time.Second, IDsFile: idsFile, MaxRetries: 120, NoQueries: true,
		})
	}()
	r.note("firehose started", fmt.Sprintf("%d events at %.0f/s through a port-forward to the ingest Service", total, r.o.FirehoseRate))
	time.Sleep(45 * time.Second)
	if _, err := r.kubectl(ctx, "-n", "stress-pg", "scale", "statefulset/postgres", "--replicas=0"); err != nil {
		r.fail("scale Postgres down: %v", err)
	}
	down := time.Now()
	r.note("Postgres scaled to 0", "")
	maxQueue := 0.0
	degraded := map[string]bool{}
	lastReady := map[string]string{}
	for time.Since(down) < r.o.PGDown {
		for _, sp := range r.serverPods(ctx) {
			if v, ok := r.metric(ctx, sp, "kubesentry_audit_queue_depth"); ok && v > maxQueue {
				maxQueue = v
			}
			c, b := r.readyz(ctx, sp)
			if c != 200 || strings.Contains(b, "postgres") {
				degraded[sp.name] = true
			}
			state := fmt.Sprintf("%d degraded=%v", c, strings.Contains(b, "postgres"))
			if lastReady[sp.name] != state {
				lastReady[sp.name] = state
				r.note(sp.name+" /readyz", fmt.Sprintf("%d %s", c, firstN(b, 160)))
			}
		}
		time.Sleep(10 * time.Second)
	}
	if _, err := r.kubectl(ctx, "-n", "stress-pg", "scale", "statefulset/postgres", "--replicas=1"); err != nil {
		r.fail("scale Postgres up: %v", err)
	}
	r.note("Postgres scaled to 1", fmt.Sprintf("after %.0fs; max audit queue depth %.0f; replicas reporting postgres degraded: %d", time.Since(down).Seconds(), maxQueue, len(degraded)))
	_, _ = r.kubectl(ctx, "-n", "stress-pg", "rollout", "status", "statefulset/postgres", "--timeout=180s")
	fh := <-done
	r.note("firehose finished", fmt.Sprintf("accepted %d of %d, backpressure responses %d, retried batches %d, gave up %d, failed %d",
		fh.AcceptedEvents, fh.SentEvents, fh.Backpressure, fh.Retried, fh.GaveUp, fh.FailedBatches))
	// Let the queue drain.
	for i := 0; i < 60; i++ {
		q := 0.0
		for _, sp := range r.serverPods(ctx) {
			if v, ok := r.metric(ctx, sp, "kubesentry_audit_queue_depth"); ok {
				q += v
			}
		}
		if q == 0 {
			break
		}
		time.Sleep(5 * time.Second)
	}
	found, missing, dups, err := r.checkIDs(ctx, idsFile)
	if err != nil {
		r.fail("checking the store: %v", err)
	}
	r.scenario.Numbers = map[string]any{"events": total, "accepted": fh.AcceptedEvents, "distinctAccepted": fh.DistinctIDs, "backpressure503": fh.Backpressure,
		"retriedBatches": fh.Retried, "gaveUpBatches": fh.GaveUp, "failedBatches": fh.FailedBatches, "maxQueueDepth": maxQueue,
		"found": found, "missing": missing, "duplicated": dups, "downSeconds": r.o.PGDown.Seconds()}
	if missing > 0 || dups > 0 {
		r.fail("%d accepted events missing, %d stored twice", missing, dups)
	}
	if fh.GaveUp > 0 || fh.FailedBatches > 0 {
		r.fail("%d batches given up, %d failed", fh.GaveUp, fh.FailedBatches)
	}
	r.scenario.Summary = fmt.Sprintf("%d accepted (%d distinct); %d backpressure answers; stored %d, missing %d, duplicated %d",
		fh.AcceptedEvents, fh.DistinctIDs, fh.Backpressure, found, missing, dups)
}

// checkIDs counts how often each auditID in the file is stored.
func (r *runner) checkIDs(ctx context.Context, file string) (found, missing, dups int, err error) {
	ids, err := exec.CommandContext(ctx, "cat", file).Output()
	if err != nil {
		return 0, 0, 0, err
	}
	script := "CREATE TEMP TABLE ids(id text COLLATE \"C\");\nCOPY ids FROM STDIN;\n" + string(ids) + "\\.\n" +
		"SELECT count(*) FILTER (WHERE n = 1), count(*) FILTER (WHERE n = 0), count(*) FILTER (WHERE n > 1) FROM " +
		"(SELECT i.id, count(e.audit_id) n FROM ids i LEFT JOIN kubesentry.audit_events e ON e.audit_id = i.id GROUP BY i.id) x;\n"
	cmd := exec.CommandContext(ctx, "kubectl", "--context", r.o.Context, "-n", "stress-pg", "exec", "-i", "postgres-0", "--",
		"psql", "-U", "kubesentry", "-d", "kubesentry", "-At", "-q", "-v", "ON_ERROR_STOP=1")
	cmd.Stdin = strings.NewReader(script)
	b, err := cmd.CombinedOutput()
	if err != nil {
		return 0, 0, 0, fmt.Errorf("psql: %v: %s", err, b)
	}
	f := strings.Split(strings.TrimSpace(string(b)), "|")
	if len(f) != 3 {
		return 0, 0, 0, fmt.Errorf("psql output %q", b)
	}
	found, _ = strconv.Atoi(f[0])
	missing, _ = strconv.Atoi(f[1])
	dups, _ = strconv.Atoi(f[2])
	return found, missing, dups, nil
}

// apiserver: restart the kube-apiserver container. kubesentry keeps serving
// its last view and catches up afterwards.
func (r *runner) apiserver(ctx context.Context) {
	pods := r.serverPods(ctx)
	type sample struct {
		ok      bool
		age     float64
		stale   bool
		readyOK int
	}
	stopProbe := make(chan struct{})
	samples := make(chan sample, 1000)
	go func() {
		defer close(samples)
		for {
			select {
			case <-stopProbe:
				return
			case <-time.After(2 * time.Second):
			}
			code, body := r.api(ctx, r.o.AdminToken, "/api/v1/info")
			var info ks.InfoFull
			_ = json.Unmarshal([]byte(body), &info)
			s := sample{ok: code == 200}
			if info.Snapshot != nil {
				s.age, s.stale = info.Snapshot.AgeSeconds, info.Snapshot.Stale
			}
			if c, _ := r.api(ctx, r.o.AdminToken, "/api/v1/pods?limit=5"); c != 200 {
				s.ok = false
			}
			for _, p := range pods {
				if c, _ := r.readyz(ctx, p); c == 200 {
					s.readyOK++
				}
			}
			samples <- s
		}
	}()
	time.Sleep(6 * time.Second)
	b, err := exec.CommandContext(ctx, "docker", "exec", r.o.ControlPlane, "sh", "-c", "crictl ps --name kube-apiserver -q | head -1 | xargs -r crictl stop").CombinedOutput()
	if err != nil {
		r.fail("stop kube-apiserver: %v %s", err, b)
	}
	stopped := time.Now()
	r.note("kube-apiserver container stopped", strings.TrimSpace(string(b)))
	// Wait for the API server to answer again.
	back := time.Time{}
	for time.Since(stopped) < 5*time.Minute {
		if _, err := r.kubectl(ctx, "get", "--raw", "/readyz", "--request-timeout=3s"); err == nil {
			back = time.Now()
			break
		}
		time.Sleep(2 * time.Second)
	}
	if back.IsZero() {
		r.fail("API server not back within 5 minutes")
		close(stopProbe)
		return
	}
	r.note("API server ready again", fmt.Sprintf("after %.0fs", back.Sub(stopped).Seconds()))
	// Then until kubesentry's view is fresh.
	fresh := time.Time{}
	for time.Since(back) < 5*time.Minute {
		_, body := r.api(ctx, r.o.AdminToken, "/api/v1/info")
		var info ks.InfoFull
		_ = json.Unmarshal([]byte(body), &info)
		if info.Snapshot != nil && info.Snapshot.AgeSeconds < 15 && !info.Snapshot.Stale {
			fresh = time.Now()
			break
		}
		time.Sleep(3 * time.Second)
	}
	time.Sleep(4 * time.Second)
	close(stopProbe)
	var n, okN, readyMin int
	readyMin = len(pods)
	maxAge := 0.0
	staleSeen := false
	for s := range samples {
		n++
		if s.ok {
			okN++
		}
		if s.age > maxAge {
			maxAge = s.age
		}
		staleSeen = staleSeen || s.stale
		if s.readyOK < readyMin {
			readyMin = s.readyOK
		}
	}
	freshAfter := -1.0
	if !fresh.IsZero() {
		freshAfter = fresh.Sub(back).Seconds()
	}
	// The API server's RBAC caches warm up after a restart: kubesentry's
	// ServiceAccount can see a moment of "forbidden" on its watches.
	since := fmt.Sprintf("--since-time=%s", stopped.UTC().Format(time.RFC3339))
	logs, _ := r.kubectl(ctx, "-n", r.o.Namespace, "logs", "-l", "app.kubernetes.io/component=server", "-c", "server", "--prefix", since, "--tail=-1")
	forbidden := 0
	var firstForbidden string
	for _, l := range strings.Split(logs, "\n") {
		if strings.Contains(l, "forbidden") {
			forbidden++
			if firstForbidden == "" {
				firstForbidden = firstN(l, 220)
			}
		}
	}
	r.scenario.Numbers["serverLogForbiddenLines"] = forbidden
	if forbidden > 0 {
		r.note("caution: transient forbidden errors in kubesentry's log after the restart", fmt.Sprintf("%d lines, e.g. %s", forbidden, firstForbidden))
	}
	r.scenario.Numbers = map[string]any{"apiserverDownSeconds": back.Sub(stopped).Seconds(), "probes": n, "probesOK": okN,
		"maxSnapshotAgeSeconds": maxAge, "staleReported": staleSeen, "minReadyReplicas": readyMin, "freshSecondsAfterAPIServer": freshAfter}
	r.scenario.Numbers["serverLogForbiddenLines"] = forbidden
	r.note("probes", fmt.Sprintf("%d/%d answered 200; snapshot age max %.0fs, stale shown %v; ready replicas never below %d", okN, n, maxAge, staleSeen, readyMin))
	if okN < n {
		r.fail("%d of %d probes failed while the API server restarted", n-okN, n)
	}
	if fresh.IsZero() {
		r.fail("the view did not become fresh within 5 minutes of the API server coming back")
	}
	r.scenario.Summary = fmt.Sprintf("API server down %.0fs; kubesentry answered %d/%d probes, max snapshot age %.0fs, fresh again %.0fs later",
		back.Sub(stopped).Seconds(), okN, n, maxAge, freshAfter)
}

// advisoryHolders returns, per granted advisory lock in the kubesentry
// database, the client address holding it (pg_locks joined to pg_stat_activity).
func (r *runner) advisoryHolders(ctx context.Context) (map[string]string, error) {
	out, err := r.kubectl(ctx, "-n", "stress-pg", "exec", "postgres-0", "--", "psql", "-U", "kubesentry", "-d", "kubesentry", "-At", "-c",
		"select l.objid, host(a.client_addr) from pg_locks l join pg_stat_activity a on a.pid = l.pid where l.locktype = 'advisory' and l.granted")
	if err != nil {
		return nil, fmt.Errorf("%v: %s", err, out)
	}
	m := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Split(strings.TrimSpace(l), "|"); len(f) == 2 {
			m[f[0]] = f[1]
		}
	}
	return m, nil
}

// cloudwatchLeader finds the replica holding the CloudWatch reader's lock:
// the advisory lock held by a server pod whose lag gauge is set, or the only
// advisory lock held by a server pod. It also reports pods whose lag gauge is
// set although they do not hold the lock (a stale gauge).
func (r *runner) cloudwatchLeader(ctx context.Context, lockID string) (leader pod, id string, staleGauge []string, err error) {
	holders, err := r.advisoryHolders(ctx)
	if err != nil {
		return pod{}, "", nil, err
	}
	pods := r.serverPods(ctx)
	byIP := map[string]pod{}
	for _, p := range pods {
		byIP[p.ip] = p
	}
	lag := map[string]float64{}
	for _, p := range pods {
		if v, ok := r.metric(ctx, p, "kubesentry_cloudwatch_lag_seconds"); ok {
			lag[p.name] = v
		}
	}
	if lockID != "" {
		if p, ok := byIP[holders[lockID]]; ok {
			leader, id = p, lockID
		}
	} else {
		var cands []string
		for obj, ip := range holders {
			if _, ok := byIP[ip]; ok {
				cands = append(cands, obj)
			}
		}
		sort.Strings(cands)
		for _, obj := range cands {
			p := byIP[holders[obj]]
			if lag[p.name] > 0 || len(cands) == 1 {
				leader, id = p, obj
			}
		}
	}
	for _, p := range pods {
		if p.name != leader.name && lag[p.name] > 0 {
			staleGauge = append(staleGauge, fmt.Sprintf("%s=%.0fs", p.name, lag[p.name]))
		}
	}
	return leader, id, staleGauge, nil
}

// killReplica deletes the replica holding the CloudWatch lock. Any other
// replica (the standby, or the Deployment's replacement pod) must take the
// lock, CloudWatch events must stay complete, and agents keep reporting.
func (r *runner) killReplica(ctx context.Context) {
	r.lockMove(ctx, false)
}

// standbyTakeover removes the leader without a replacement (pod-deletion-cost
// and a scale to 1), so only the standby can take the lock, within its 30s
// retry.
func (r *runner) standbyTakeover(ctx context.Context) {
	r.lockMove(ctx, true)
}

func (r *runner) lockMove(ctx context.Context, standbyOnly bool) {
	pods := r.serverPods(ctx)
	if len(pods) < 2 {
		r.fail("need 2 replicas, have %d", len(pods))
		return
	}
	leader, lockID, stale, err := r.cloudwatchLeader(ctx, "")
	if err != nil || leader.name == "" {
		r.fail("could not find the CloudWatch lock holder: %v", err)
		return
	}
	if len(stale) > 0 {
		r.note("stale lag gauge", "set on a replica that does not hold the lock: "+strings.Join(stale, ", "))
		r.scenario.Numbers["staleLagGaugeBefore"] = stale
	}
	var other pod
	for _, p := range pods {
		if p.name != leader.name {
			other = p
		}
	}
	agentsBefore, _ := r.metric(ctx, other, "kubesentry_agent_nodes_reporting")
	r.note("leader (pg_locks)", fmt.Sprintf("%s %s holds advisory lock %s; standby %s", leader.name, leader.ip, lockID, other.name))
	if standbyOnly {
		if _, err := r.kubectl(ctx, "-n", r.o.Namespace, "annotate", "pod", leader.name, "controller.kubernetes.io/pod-deletion-cost=-1000", "--overwrite"); err != nil {
			r.fail("annotate %s: %v", leader.name, err)
			return
		}
		if _, err := r.kubectl(ctx, "-n", r.o.Namespace, "scale", "deployment/kubesentry", "--replicas=1"); err != nil {
			r.fail("scale to 1: %v", err)
			return
		}
		r.note("scaled to 1 with the leader marked cheapest to delete", "")
		defer func() {
			if _, err := r.kubectl(ctx, "-n", r.o.Namespace, "scale", "deployment/kubesentry", "--replicas=2"); err != nil {
				r.fail("scale back to 2: %v", err)
			}
			_, _ = r.kubectl(ctx, "-n", r.o.Namespace, "rollout", "status", "deployment/kubesentry", "--timeout=5m")
			r.note("scaled back to 2", "")
		}()
	} else {
		if _, err := r.kubectl(ctx, "-n", r.o.Namespace, "delete", "pod", leader.name, "--wait=false"); err != nil {
			r.fail("delete %s: %v", leader.name, err)
			return
		}
		r.note("deleted the leader", "the Deployment creates a replacement")
	}
	killed := time.Now()
	var took time.Time
	var newHolder string
	minAgents := agentsBefore
	apiErrors := 0
	for time.Since(killed) < 3*time.Minute {
		if h, err := r.advisoryHolders(ctx); err == nil && took.IsZero() {
			if ip := h[lockID]; ip != "" && ip != leader.ip {
				took, newHolder = time.Now(), ip
				who := "the replacement pod"
				if ip == other.ip {
					who = "the standby"
				}
				for _, p := range r.serverPods(ctx) {
					if p.ip == ip {
						who += " " + p.name
					}
				}
				r.note("lock taken", fmt.Sprintf("by %s (%s) after %.1fs", who, ip, took.Sub(killed).Seconds()))
			}
		}
		if v, ok := r.metric(ctx, other, "kubesentry_agent_nodes_reporting"); ok && v < minAgents {
			minAgents = v
		}
		if c, _ := r.api(ctx, r.o.AdminToken, "/api/v1/agents"); c != 200 {
			apiErrors++
		}
		if !took.IsZero() && time.Since(took) > 20*time.Second {
			break
		}
		time.Sleep(2 * time.Second)
	}
	takeover := -1.0
	if !took.IsZero() {
		takeover = took.Sub(killed).Seconds()
	}
	switch {
	case took.IsZero():
		r.fail("no replica took the CloudWatch lock within 3 minutes")
	case standbyOnly && newHolder != other.ip:
		r.fail("the lock went to %s, not the standby %s", newHolder, other.ip)
	case standbyOnly && takeover > 45:
		r.fail("the standby took the lock after %.0fs (want ≤ 45s; it retries every 30s)", takeover)
	}
	// After the move: a stale gauge on a replica that no longer leads?
	if _, _, staleAfter, err := r.cloudwatchLeader(ctx, lockID); err == nil && len(staleAfter) > 0 {
		r.note("stale lag gauge after the move", strings.Join(staleAfter, ", "))
		r.scenario.Numbers["staleLagGaugeAfter"] = staleAfter
	}
	code, body := r.api(ctx, r.o.AdminToken, "/api/v1/agents")
	var ag []struct {
		Node  string `json:"node"`
		Stale bool   `json:"stale"`
	}
	_ = json.Unmarshal([]byte(body), &ag)
	fresh := 0
	for _, a := range ag {
		if !a.Stale {
			fresh++
		}
	}
	r.note("agents after", fmt.Sprintf("HTTP %d, %d agents, %d fresh; nodes reporting to %s never below %.0f", code, len(ag), fresh, other.name, minAgents))
	r.note("waiting for CloudWatch late deliveries", "4m")
	time.Sleep(4 * time.Minute)
	cw, err := cwserve.Verify(ctx, r.o.CW, r.o.Context, "stress-pg", "postgres-0", "kubesentry", 4*time.Minute, 30*time.Minute)
	if err != nil {
		r.fail("CloudWatch check: %v", err)
	} else {
		r.note("CloudWatch events", fmt.Sprintf("%d expected, %d found, %d missing, %d duplicated", cw.Expected, cw.Found, cw.Missing, cw.Duplicated))
		if cw.Missing > 0 || cw.Duplicated > 0 {
			r.fail("CloudWatch events across the lock move: %d missing, %d duplicated", cw.Missing, cw.Duplicated)
		}
	}
	if minAgents < agentsBefore {
		r.fail("nodes reporting to the surviving replica dropped from %.0f to %.0f", agentsBefore, minAgents)
	}
	if fresh == 0 {
		r.fail("no fresh agents after the move")
	}
	r.scenario.Numbers["lockTakeoverSeconds"] = takeover
	r.scenario.Numbers["newHolderIP"] = newHolder
	r.scenario.Numbers["standbyIP"] = other.ip
	r.scenario.Numbers["agentsBefore"], r.scenario.Numbers["agentsMinOnSurvivor"], r.scenario.Numbers["agentsFreshAfter"] = agentsBefore, minAgents, fresh
	r.scenario.Numbers["webErrorsDuringMove"] = apiErrors
	if cw != nil {
		r.scenario.Numbers["cloudwatchMissing"], r.scenario.Numbers["cloudwatchDuplicated"], r.scenario.Numbers["cloudwatchExpected"] = cw.Missing, cw.Duplicated, cw.Expected
	}
	who := "replacement or standby"
	if newHolder == other.ip {
		who = "standby"
	} else if newHolder != "" {
		who = "replacement pod"
	}
	r.scenario.Summary = fmt.Sprintf("lock moved to the %s in %.1fs; agents on the survivor %.0f→%.0f, %d fresh after; web errors %d", who, takeover, agentsBefore, minAgents, fresh, apiErrors)
}

// Markdown renders chaos.md.
func (res *Result) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Chaos smoke set\n\n%d passed, %d failed.\n\n| Scenario | Result | Seconds | Summary |\n|---|---|---:|---|\n", res.Passed, res.Failed)
	for _, s := range res.Scenarios {
		v := "pass"
		if !s.Pass {
			v = "FAIL: " + strings.Join(s.Problems, "; ")
		}
		fmt.Fprintf(&b, "| %s | %s | %.0f | %s |\n", s.Name, v, s.Seconds, s.Summary)
	}
	for _, s := range res.Scenarios {
		fmt.Fprintf(&b, "\n## %s\n\nNumbers: %v\n\n", s.Name, s.Numbers)
		for _, t := range s.Timeline {
			fmt.Fprintf(&b, "- %s %s %s\n", t.At, t.What, t.Detail)
		}
	}
	return b.String()
}
