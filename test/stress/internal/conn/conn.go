// Package conn checks connectivity across the real nodes with an agnhost
// netexec mesh, and kubesentry's own paths: to Prometheus, from the agents,
// and to its Service from every node.
package conn

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"

	"github.com/ByronGary/kubesentry/test/stress/internal/ks"
	"github.com/ByronGary/kubesentry/test/stress/internal/out"
)

// Namespace and image of the mesh.
const (
	NS    = "stress-conn"
	Image = "registry.k8s.io/e2e-test-images/agnhost:2.53"
)

// Options configure the check.
type Options struct {
	Client        *ks.Client
	APIID         ks.Identity
	KubesentrySvc string // host:port of the kubesentry Service, by DNS name
	PrometheusURL string
	Timeout       time.Duration
	// IngestURL (e.g. http://kubesentry-ingest.kubesentry.svc:8081) is probed
	// from every node too; OpsURL gives /readyz and /metrics. Both optional.
	IngestURL string
	OpsURL    string
}

// Cell is one source → target probe.
type Cell struct {
	From  string  `json:"from"` // node
	Net   string  `json:"net"`  // "pod" or "host"
	Check string  `json:"check"`
	To    string  `json:"to"`
	OK    bool    `json:"ok"`
	Ms    float64 `json:"ms"`
	Error string  `json:"error,omitempty"`
}

// Result is conn.json.
type Result struct {
	Started    time.Time         `json:"started"`
	Nodes      []string          `json:"nodes"`
	Cells      []Cell            `json:"cells"`
	Passed     int               `json:"passed"`
	Failed     int               `json:"failed"`
	ByCheck    map[string][2]int `json:"byCheck"` // check → [passed, total]
	Prometheus PromCheck         `json:"prometheus"`
	Agents     []AgentCheck      `json:"agents"`
	Web        *WebCheck         `json:"web,omitempty"`
}

// WebCheck is the authenticated path through the web Service (oauth2-proxy →
// Unix socket → kubesentry on the chart) and the ops listener.
type WebCheck struct {
	InfoStatus       int             `json:"infoStatus"`
	IdentitySource   string          `json:"identitySource"`
	IdentityUser     string          `json:"identityUser"`
	Groups           []string        `json:"groups"`
	Capabilities     map[string]bool `json:"capabilities"`
	AnonymousStatus  int             `json:"anonymousStatus"`  // no credentials: want 401
	SpoofedStatus    int             `json:"spoofedStatus"`    // forged X-Forwarded-Email without a token: want 401
	ReadyzStatus     int             `json:"readyzStatus"`     // ops /readyz
	Readyz           string          `json:"readyz,omitempty"` // body
	MetricsSeries    int             `json:"kubesentryMetricLines"`
	SnapshotAge      float64         `json:"snapshotAgeSeconds"`
	AuditBackend     string          `json:"auditBackend"`
	PrometheusSource string          `json:"prometheusSource"`
	OK               bool            `json:"ok"`
	Problems         []string        `json:"problems,omitempty"`
}

// PromCheck is kubesentry → Prometheus, and Prometheus' own targets.
type PromCheck struct {
	InfoMetrics      bool           `json:"infoMetrics"`
	OOMOK            bool           `json:"oomMetricsAvailable"`
	OOMWarnings      []string       `json:"oomWarnings,omitempty"`
	OOMMs            float64        `json:"oomMs"`
	OOMBytes         int64          `json:"oomBytes"`
	OOMError         string         `json:"oomError,omitempty"`
	TargetsUp        map[string]int `json:"targetsUp"`
	TargetsDown      map[string]int `json:"targetsDown"`
	TargetsError     string         `json:"targetsError,omitempty"`
	DownSample       []string       `json:"downSample,omitempty"`
	SimulatedSeries  int            `json:"simulatedSeries"`
	SimulatedQueryMs float64        `json:"simulatedQueryMs"`
}

// AgentCheck is one real node's agent freshness, seen through kubesentry.
type AgentCheck struct {
	Node      string  `json:"node"`
	Pod       string  `json:"pod"`
	Available bool    `json:"available"`
	Stale     bool    `json:"stale"`
	Reporter  string  `json:"reporter"`
	Processes int     `json:"processes"`
	OK        bool    `json:"ok"`
	Ms        float64 `json:"ms"`
	Error     string  `json:"error,omitempty"`
}

func ptr[T any](v T) *T { return &v }

func meshDS(name string, host bool, port int32) *appsv1.DaemonSet {
	labels := map[string]string{"app": name, "kubesentry.io/stress": "true"}
	spec := corev1.PodSpec{
		HostNetwork: host,
		DNSPolicy:   corev1.DNSClusterFirst,
		Affinity: &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
			NodeSelectorTerms: []corev1.NodeSelectorTerm{{MatchExpressions: []corev1.NodeSelectorRequirement{{Key: "type", Operator: corev1.NodeSelectorOpNotIn, Values: []string{"kwok"}}}}}}}},
		Tolerations:                   []corev1.Toleration{{Operator: corev1.TolerationOpExists}},
		TerminationGracePeriodSeconds: ptr(int64(1)),
		Containers: []corev1.Container{{
			Name: "netexec", Image: Image, ImagePullPolicy: corev1.PullIfNotPresent,
			Args:  []string{"netexec", fmt.Sprintf("--http-port=%d", port), "--udp-port=-1"},
			Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: port}},
			// /healthz stays 412 without the UDP server, so probe /hostname.
			ReadinessProbe: &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/hostname", Port: intstr.FromInt32(port)}},
				PeriodSeconds: 2},
			Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("5m"), corev1.ResourceMemory: resource.MustParse("16Mi")},
				Limits: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("64Mi")}},
		}},
	}
	if host {
		spec.DNSPolicy = corev1.DNSClusterFirstWithHostNet
	}
	return &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: NS, Name: name, Labels: labels},
		Spec: appsv1.DaemonSetSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": name}},
			Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels}, Spec: spec}},
	}
}

// Deploy creates the mesh (idempotent) and waits until a pod runs on every real node.
func Deploy(ctx context.Context, cs kubernetes.Interface) error {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: NS, Labels: map[string]string{"kubesentry.io/stress": "true",
		"pod-security.kubernetes.io/enforce": "privileged"}}}
	if _, err := cs.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	for _, ds := range []*appsv1.DaemonSet{meshDS("mesh", false, 8080), meshDS("mesh-host", true, 18080)} {
		if _, err := cs.AppsV1().DaemonSets(NS).Create(ctx, ds, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
			return err
		}
	}
	svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Namespace: NS, Name: "mesh", Labels: map[string]string{"kubesentry.io/stress": "true"}},
		Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "mesh"}, Ports: []corev1.ServicePort{{Name: "http", Port: 8080, TargetPort: intstr.FromInt32(8080)}}}}
	if _, err := cs.CoreV1().Services(NS).Create(ctx, svc, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	return wait.PollUntilContextTimeout(ctx, 3*time.Second, 4*time.Minute, true, func(ctx context.Context) (bool, error) {
		ready := 0
		for _, n := range []string{"mesh", "mesh-host"} {
			d, err := cs.AppsV1().DaemonSets(NS).Get(ctx, n, metav1.GetOptions{})
			if err != nil || d.Status.DesiredNumberScheduled == 0 || d.Status.NumberReady < d.Status.DesiredNumberScheduled {
				return false, nil
			}
			ready++
		}
		return ready == 2, nil
	})
}

type dialResp struct {
	Responses []string `json:"responses"`
	Errors    []string `json:"errors"`
}

// dial asks the netexec at srcAddr to GET http://target/request.
func dial(ctx context.Context, hc *http.Client, srcAddr, target string, port int, request string) (string, time.Duration, error) {
	q := url.Values{"request": {request}, "protocol": {"http"}, "host": {target}, "port": {fmt.Sprint(port)}, "tries": {"1"}}
	start := time.Now()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+srcAddr+"/dial?"+q.Encode(), nil)
	resp, err := hc.Do(req)
	if err != nil {
		return "", time.Since(start), err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var d dialResp
	if err := json.Unmarshal(b, &d); err != nil {
		return "", time.Since(start), fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if len(d.Responses) == 0 {
		return "", time.Since(start), fmt.Errorf("no response: %v", d.Errors)
	}
	return d.Responses[0], time.Since(start), nil
}

// Run deploys the mesh and runs every check.
func Run(ctx context.Context, cs kubernetes.Interface, o Options) (*Result, error) {
	if err := Deploy(ctx, cs); err != nil {
		return nil, fmt.Errorf("deploy mesh: %w", err)
	}
	res := &Result{Started: time.Now().UTC(), ByCheck: map[string][2]int{}}
	pods, err := cs.CoreV1().Pods(NS).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	svc, err := cs.CoreV1().Services(NS).Get(ctx, "mesh", metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	type src struct{ node, net, addr, pod, podIP string }
	var srcs []src
	podByNode := map[string]corev1.Pod{}
	for _, p := range pods.Items {
		if p.Status.PodIP == "" || p.DeletionTimestamp != nil {
			continue
		}
		switch p.Labels["app"] {
		case "mesh":
			srcs = append(srcs, src{p.Spec.NodeName, "pod", p.Status.PodIP + ":8080", p.Name, p.Status.PodIP})
			podByNode[p.Spec.NodeName] = p
		case "mesh-host":
			srcs = append(srcs, src{p.Spec.NodeName, "host", p.Status.PodIP + ":18080", p.Name, p.Status.PodIP})
		}
	}
	sort.Slice(srcs, func(i, j int) bool { return srcs[i].node+srcs[i].net < srcs[j].node+srcs[j].net })
	for n := range podByNode {
		res.Nodes = append(res.Nodes, n)
	}
	sort.Strings(res.Nodes)

	hc := &http.Client{Timeout: o.Timeout}
	var mu sync.Mutex
	var wg sync.WaitGroup
	add := func(c Cell) {
		mu.Lock()
		res.Cells = append(res.Cells, c)
		bc := res.ByCheck[c.Check]
		bc[1]++
		if c.OK {
			bc[0]++
			res.Passed++
		} else {
			res.Failed++
		}
		res.ByCheck[c.Check] = bc
		mu.Unlock()
	}
	probe := func(s src, check, to, target string, port int, request string, ok func(string) bool) {
		defer wg.Done()
		cctx, cancel := context.WithTimeout(ctx, o.Timeout)
		defer cancel()
		got, d, err := dial(cctx, hc, s.addr, target, port, request)
		c := Cell{From: s.node, Net: s.net, Check: check, To: to, Ms: float64(d.Microseconds()) / 1000}
		if err != nil {
			c.Error = err.Error()
		} else if c.OK = ok(got); !c.OK {
			c.Error = "unexpected response: " + got
		}
		add(c)
	}
	ksHost, ksPortS, _ := strings.Cut(o.KubesentrySvc, ":")
	ksPort := 8080
	fmt.Sscan(ksPortS, &ksPort)
	// The chart puts oauth2-proxy on the web port (4180): probe its /ping.
	ksPath := "healthz"
	if ksPort == 4180 {
		ksPath = "ping"
	}
	var inHost string
	inPort := 8081
	if o.IngestURL != "" {
		hp := strings.TrimPrefix(strings.TrimPrefix(o.IngestURL, "http://"), "https://")
		hp, _, _ = strings.Cut(hp, "/")
		var ps string
		inHost, ps, _ = strings.Cut(hp, ":")
		fmt.Sscan(ps, &inPort)
	}
	for _, s := range srcs {
		for _, node := range res.Nodes {
			t := podByNode[node]
			wg.Add(1)
			go probe(s, "pod→pod", node, t.Status.PodIP, 8080, "hostname", func(r string) bool { return r == t.Name })
		}
		wg.Add(3)
		go probe(s, "pod→ClusterIP", "mesh ClusterIP", svc.Spec.ClusterIP, 8080, "hostname", func(r string) bool { return strings.HasPrefix(r, "mesh-") })
		go probe(s, "DNS→Service", "mesh.stress-conn.svc.cluster.local", "mesh."+NS+".svc.cluster.local", 8080, "hostname", func(r string) bool { return strings.HasPrefix(r, "mesh-") })
		go probe(s, "→kubesentry", o.KubesentrySvc, ksHost, ksPort, ksPath, func(r string) bool { return strings.Contains(strings.ToLower(r), "ok") })
		if inHost != "" {
			// Any HTTP answer proves the ingest Service reaches a replica (GET is not allowed there).
			wg.Add(1)
			go probe(s, "→ingest", inHost+":"+fmt.Sprint(inPort), inHost, inPort, "agent/report", func(r string) bool { return r != "" })
		}
	}
	wg.Wait()
	sort.Slice(res.Cells, func(i, j int) bool {
		a, b := res.Cells[i], res.Cells[j]
		return a.Check+a.From+a.Net+a.To < b.Check+b.From+b.Net+b.To
	})

	res.Prometheus = promCheck(ctx, o, hc)
	res.Web = webCheck(ctx, o, hc)
	res.Agents = agentCheck(ctx, o, podByNode, res.Nodes)
	out.Logf("connectivity: %d passed, %d failed; prometheus metrics=%v oom=%v; agents fresh %d/%d", res.Passed, res.Failed,
		res.Prometheus.InfoMetrics, res.Prometheus.OOMOK, countOK(res.Agents), len(res.Agents))
	return res, nil
}

func countOK(a []AgentCheck) int {
	n := 0
	for _, x := range a {
		if x.OK {
			n++
		}
	}
	return n
}

func promCheck(ctx context.Context, o Options, hc *http.Client) PromCheck {
	var pc PromCheck
	var info ks.Info
	if _, err := o.Client.GetJSON(ctx, o.APIID, "/api/v1/info", &info); err == nil {
		pc.InfoMetrics = info.Metrics
	}
	var oom ks.OOMResponse
	cctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	r, err := o.Client.GetJSON(cctx, o.APIID, "/api/v1/oom?window=1h", &oom)
	cancel()
	pc.OOMMs, pc.OOMBytes = float64(r.Elapsed.Microseconds())/1000, r.Bytes
	if err != nil {
		pc.OOMError = err.Error()
	} else {
		pc.OOMOK, pc.OOMWarnings = oom.MetricsAvailable && len(oom.Warnings) == 0, oom.Warnings
	}
	pc.TargetsUp, pc.TargetsDown = map[string]int{}, map[string]int{}
	resp, err := hc.Get(o.PrometheusURL + "/api/v1/targets?state=active")
	if err != nil {
		pc.TargetsError = err.Error()
		return pc
	}
	defer resp.Body.Close()
	var t struct {
		Data struct {
			ActiveTargets []struct {
				Labels    map[string]string `json:"labels"`
				Health    string            `json:"health"`
				ScrapeURL string            `json:"scrapeUrl"`
				LastError string            `json:"lastError"`
			} `json:"activeTargets"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&t); err != nil {
		pc.TargetsError = err.Error()
		return pc
	}
	for _, at := range t.Data.ActiveTargets {
		job := at.Labels["job"]
		if at.Health == "up" {
			pc.TargetsUp[job]++
		} else {
			pc.TargetsDown[job]++
			if len(pc.DownSample) < 10 {
				pc.DownSample = append(pc.DownSample, job+" "+at.ScrapeURL+": "+at.LastError)
			}
		}
	}
	start := time.Now()
	q := url.Values{"query": {`count(container_memory_working_set_bytes{stress_sim="true"})`}}
	if resp, err := hc.Get(o.PrometheusURL + "/api/v1/query?" + q.Encode()); err == nil {
		var v struct {
			Data struct {
				Result []struct {
					Value [2]any `json:"value"`
				} `json:"result"`
			} `json:"data"`
		}
		if json.NewDecoder(resp.Body).Decode(&v) == nil && len(v.Data.Result) > 0 {
			fmt.Sscan(fmt.Sprint(v.Data.Result[0].Value[1]), &pc.SimulatedSeries)
		}
		resp.Body.Close()
	}
	pc.SimulatedQueryMs = float64(time.Since(start).Microseconds()) / 1000
	return pc
}

func webCheck(ctx context.Context, o Options, hc *http.Client) *WebCheck {
	w := &WebCheck{}
	var info ks.InfoFull
	r, err := o.Client.GetJSON(ctx, o.APIID, "/api/v1/info", &info)
	w.InfoStatus = r.Status
	if err != nil {
		w.Problems = append(w.Problems, "info: "+err.Error())
	} else {
		if info.Identity != nil {
			w.IdentitySource, w.IdentityUser, w.Groups = info.Identity.Source, info.Identity.User, info.Identity.Groups
		}
		w.Capabilities = info.Capabilities
		if info.Snapshot != nil {
			w.SnapshotAge = info.Snapshot.AgeSeconds
		}
		if info.AuditStore != nil {
			w.AuditBackend = info.AuditStore.Backend
		}
		if info.Prometheus != nil {
			w.PrometheusSource = info.Prometheus.Source
		}
	}
	w.AnonymousStatus = o.Client.Do(ctx, nil, http.MethodGet, "/api/v1/info", nil, "", false).Status
	w.SpoofedStatus = o.Client.DoH(ctx, nil, http.MethodGet, "/api/v1/info", nil,
		map[string]string{"X-Forwarded-Email": "admin0@corp.example", "X-Forwarded-Groups": "stress:admins,system:masters", "X-Forwarded-User": "admin0"}, false).Status
	if o.OpsURL != "" {
		if resp, err := hc.Get(o.OpsURL + "/readyz"); err == nil {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			w.ReadyzStatus, w.Readyz = resp.StatusCode, strings.TrimSpace(string(b))
		} else {
			w.Problems = append(w.Problems, "readyz: "+err.Error())
		}
		if resp, err := hc.Get(o.OpsURL + "/metrics"); err == nil {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
			resp.Body.Close()
			for _, l := range strings.Split(string(b), "\n") {
				if strings.HasPrefix(l, "kubesentry_") {
					w.MetricsSeries++
				}
			}
		}
	}
	switch {
	case w.InfoStatus != 200:
		w.Problems = append(w.Problems, fmt.Sprintf("info HTTP %d", w.InfoStatus))
	case o.OpsURL != "" && w.IdentitySource != "proxy":
		w.Problems = append(w.Problems, "identity source "+w.IdentitySource+", want proxy")
	}
	if w.AnonymousStatus != 401 {
		w.Problems = append(w.Problems, fmt.Sprintf("no credentials answered %d", w.AnonymousStatus))
	}
	if w.SpoofedStatus != 401 {
		w.Problems = append(w.Problems, fmt.Sprintf("forged identity headers answered %d", w.SpoofedStatus))
	}
	if o.OpsURL != "" && w.ReadyzStatus != 200 {
		w.Problems = append(w.Problems, fmt.Sprintf("readyz %d", w.ReadyzStatus))
	}
	w.OK = len(w.Problems) == 0
	return w
}

// agentCheck asks kubesentry for the processes of the mesh pod on each real
// node; the real agent on that node must have reported them recently.
func agentCheck(ctx context.Context, o Options, podByNode map[string]corev1.Pod, nodes []string) []AgentCheck {
	var out []AgentCheck
	for _, n := range nodes {
		p := podByNode[n]
		ac := AgentCheck{Node: n, Pod: p.Name}
		deadline := time.Now().Add(60 * time.Second) // agents report every 15s
		for {
			var pr ks.ProcessesResponse
			r, err := o.Client.GetJSON(ctx, o.APIID, fmt.Sprintf("/api/v1/pods/%s/%s/processes", NS, p.Name), &pr)
			ac.Ms = float64(r.Elapsed.Microseconds()) / 1000
			ac.Error = ""
			if err != nil {
				ac.Error = err.Error()
			} else {
				ac.Available, ac.Stale, ac.Reporter, ac.Processes = pr.Available, pr.Stale, pr.Node, len(pr.Processes)
				ac.OK = pr.Available && !pr.Stale && pr.Node == n
			}
			if ac.OK || time.Now().After(deadline) || ctx.Err() != nil {
				break
			}
			time.Sleep(5 * time.Second)
		}
		out = append(out, ac)
	}
	return out
}

// Markdown renders the matrix.
func (r *Result) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Connectivity\n\n%d probes passed, %d failed.\n\n", r.Passed, r.Failed)
	checks := make([]string, 0, len(r.ByCheck))
	for c := range r.ByCheck {
		checks = append(checks, c)
	}
	sort.Strings(checks)
	fmt.Fprintf(&b, "| Check | Passed |\n|---|---|\n")
	for _, c := range checks {
		fmt.Fprintf(&b, "| %s | %d/%d |\n", c, r.ByCheck[c][0], r.ByCheck[c][1])
	}
	fmt.Fprintf(&b, "\n## pod→pod matrix (rows: source node and network, columns: target node; ms or FAIL)\n\n| from \\ to |")
	for _, n := range r.Nodes {
		fmt.Fprintf(&b, " %s |", strings.TrimPrefix(n, "kubesentry-"))
	}
	fmt.Fprintf(&b, " ClusterIP | DNS | kubesentry | ingest |\n|---|")
	for range r.Nodes {
		b.WriteString("---|")
	}
	b.WriteString("---|---|---|---|\n")
	type key struct{ from, net string }
	rows := map[key]map[string]Cell{}
	var keys []key
	for _, c := range r.Cells {
		k := key{c.From, c.Net}
		if rows[k] == nil {
			rows[k] = map[string]Cell{}
			keys = append(keys, k)
		}
		col := c.To
		switch c.Check {
		case "pod→ClusterIP":
			col = "ClusterIP"
		case "DNS→Service":
			col = "DNS"
		case "→kubesentry":
			col = "kubesentry"
		case "→ingest":
			col = "ingest"
		}
		rows[k][col] = c
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].from+keys[i].net < keys[j].from+keys[j].net })
	cell := func(c Cell, ok bool) string {
		if !ok {
			return "-"
		}
		if c.OK {
			return fmt.Sprintf("%.0f", c.Ms)
		}
		return "FAIL"
	}
	for _, k := range keys {
		fmt.Fprintf(&b, "| %s (%s) |", strings.TrimPrefix(k.from, "kubesentry-"), k.net)
		for _, n := range append(append([]string{}, r.Nodes...), "ClusterIP", "DNS", "kubesentry", "ingest") {
			c, ok := rows[k][n]
			fmt.Fprintf(&b, " %s |", cell(c, ok))
		}
		b.WriteString("\n")
	}
	var fails []string
	for _, c := range r.Cells {
		if !c.OK {
			fails = append(fails, fmt.Sprintf("- %s %s (%s) → %s: %s", c.Check, c.From, c.Net, c.To, c.Error))
		}
	}
	if len(fails) > 0 {
		fmt.Fprintf(&b, "\nFailures:\n\n%s\n", strings.Join(fails, "\n"))
	}
	p := r.Prometheus
	fmt.Fprintf(&b, "\n## kubesentry → Prometheus\n\n- /api/v1/info metrics: %v\n- /api/v1/oom?window=1h: metricsAvailable=%v, warnings %v, %.0f ms, %d bytes %s\n- Prometheus targets up %v, down %v\n- simulated series (metrics-sim): %d\n",
		p.InfoMetrics, p.OOMOK, p.OOMWarnings, p.OOMMs, p.OOMBytes, p.OOMError, p.TargetsUp, p.TargetsDown, p.SimulatedSeries)
	for _, d := range p.DownSample {
		fmt.Fprintf(&b, "  - down: %s\n", d)
	}
	if w := r.Web; w != nil {
		fmt.Fprintf(&b, "\n## Web path and ops listener\n\n- /api/v1/info as the harness identity: HTTP %d, identity %s (%s, groups %v), capabilities %v\n- no credentials: HTTP %d (want 401); forged X-Forwarded-Email without a token: HTTP %d (want 401)\n- ops /readyz: HTTP %d %s\n- kubesentry_* metric lines: %d; snapshot age %.1fs; audit store %s; Prometheus %s\n- verdict: %v %v\n",
			w.InfoStatus, w.IdentityUser, w.IdentitySource, w.Groups, w.Capabilities, w.AnonymousStatus, w.SpoofedStatus, w.ReadyzStatus, w.Readyz, w.MetricsSeries, w.SnapshotAge, w.AuditBackend, w.PrometheusSource, w.OK, w.Problems)
	}
	fmt.Fprintf(&b, "\n## Agent freshness (real nodes)\n\n| Node | Pod | available | stale | reported by | processes | ok |\n|---|---|---|---|---|---:|---|\n")
	for _, a := range r.Agents {
		fmt.Fprintf(&b, "| %s | %s | %v | %v | %s | %d | %v %s |\n", a.Node, a.Pod, a.Available, a.Stale, a.Reporter, a.Processes, a.OK, a.Error)
	}
	return b.String()
}
