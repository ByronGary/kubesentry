package chaos

// Phase 4 scenarios: a worker container stopped and started, a real worker
// cordoned and drained, an RBAC storm, pod churn, a rolling update of a
// 1,000-replica Deployment, deleting a namespace of 2,000 pods, and a cold
// restart of both replicas under user load. Each one keeps a probe running
// against kubesentry (through oauth2-proxy, from a kind node) and compares
// kubesentry's view with the API server's.

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/ByronGary/kubesentry/test/stress/internal/hist"
	"github.com/ByronGary/kubesentry/test/stress/internal/ks"
	"github.com/ByronGary/kubesentry/test/stress/internal/users"
)

// StormPersona is a persona whose pod list is checked for leaks during the
// RBAC storm: Allowed are the namespaces its own bindings grant.
type StormPersona struct {
	Email   string
	Token   string
	Allowed map[string]bool
}

const stressLabel = "kubesentry.io/stress"

// ---- probing -----------------------------------------------------------

// probe samples kubesentry every interval while a scenario runs: /info (the
// snapshot age) and a small pods page, through oauth2-proxy.
type probe struct {
	stop     chan struct{}
	done     chan struct{}
	n, ok    atomic.Int64
	age      *hist.Hist
	stale    atomic.Int64
	mu       sync.Mutex
	failures []string
}

type probeStats struct {
	Probes     int64   `json:"probes"`
	OK         int64   `json:"ok"`
	OKRatio    float64 `json:"okRatio"`
	AgeP99     float64 `json:"snapshotAgeP99Seconds"`
	AgeMax     float64 `json:"snapshotAgeMaxSeconds"`
	Stale      int64   `json:"staleAnswers"`
	FirstFails string  `json:"firstFailures,omitempty"`
}

func (r *runner) startProbe(ctx context.Context, every time.Duration) *probe {
	p := &probe{stop: make(chan struct{}), done: make(chan struct{}), age: hist.New()}
	go func() {
		defer close(p.done)
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-p.stop:
				return
			case <-ctx.Done():
				return
			case <-t.C:
			}
			p.n.Add(1)
			code, body := r.api(ctx, r.o.AdminToken, "/api/v1/info")
			var info ks.InfoFull
			_ = json.Unmarshal([]byte(body), &info)
			okInfo := code == 200
			if info.Snapshot != nil {
				p.age.Add(info.Snapshot.AgeSeconds * 1000)
				if info.Snapshot.Stale {
					p.stale.Add(1)
				}
			}
			c2, _ := r.api(ctx, r.o.AdminToken, "/api/v1/pods?limit=5")
			if okInfo && c2 == 200 {
				p.ok.Add(1)
			} else {
				p.mu.Lock()
				if len(p.failures) < 5 {
					p.failures = append(p.failures, fmt.Sprintf("%s info %d pods %d", time.Now().UTC().Format("15:04:05"), code, c2))
				}
				p.mu.Unlock()
			}
		}
	}()
	return p
}

func (p *probe) finish() probeStats {
	close(p.stop)
	<-p.done
	s := probeStats{Probes: p.n.Load(), OK: p.ok.Load(), Stale: p.stale.Load()}
	if s.Probes > 0 {
		s.OKRatio = float64(s.OK) / float64(s.Probes)
	}
	s.AgeP99, s.AgeMax = p.age.Quantile(0.99)/1000, p.age.Quantile(1)/1000
	p.mu.Lock()
	s.FirstFails = strings.Join(p.failures, "; ")
	p.mu.Unlock()
	return s
}

// judge records the probe numbers and the usual pass criteria: every probe
// answered (minOK) and the snapshot stayed fresh (p99 < 15s).
func (r *runner) judge(s probeStats, minOK float64) {
	r.scenario.Numbers["probes"] = s
	if s.OKRatio < minOK {
		r.fail("%d of %d probes failed (want ≥ %.0f%% ok): %s", s.Probes-s.OK, s.Probes, 100*minOK, s.FirstFails)
	}
	if s.AgeP99 >= 15 {
		r.fail("snapshot age p99 %.1fs (want < 15s)", s.AgeP99)
	}
}

// ---- kubesentry views ----------------------------------------------------

type ksPod struct{ Node, Workload, Phase string }

// ksPodsIn pages through /api/v1/pods?namespace=ns as the admin.
func (r *runner) ksPodsIn(ctx context.Context, ns string) (map[string]ksPod, error) {
	out := map[string]ksPod{}
	cont := ""
	for page := 0; page < 40; page++ {
		path := "/api/v1/pods?limit=1000&namespace=" + ns
		if cont != "" {
			path += "&continue=" + url.QueryEscape(cont)
		}
		code, body := r.api(ctx, r.o.AdminToken, path)
		if code != 200 {
			return out, fmt.Errorf("pods?namespace=%s: HTTP %d", ns, code)
		}
		var pr ks.PodsResponse
		if err := json.Unmarshal([]byte(body), &pr); err != nil {
			return out, err
		}
		for _, it := range pr.Items {
			if it.Namespace == ns {
				out[it.Name] = ksPod{it.Node, it.Workload, it.Phase}
			}
		}
		if pr.Continue == "" {
			return out, nil
		}
		cont = pr.Continue
	}
	return out, nil
}

type ksNode struct {
	Name          string `json:"name"`
	Ready         bool   `json:"ready"`
	Unschedulable bool   `json:"unschedulable"`
	Status        string `json:"status"`
	PodCount      int    `json:"podCount"`
}

func (r *runner) ksNode(ctx context.Context, name string) (ksNode, bool) {
	code, body := r.api(ctx, r.o.AdminToken, "/api/v1/nodes?summary=true")
	if code != 200 {
		return ksNode{}, false
	}
	var v struct {
		Items []ksNode `json:"items"`
	}
	_ = json.Unmarshal([]byte(body), &v)
	for _, n := range v.Items {
		if n.Name == name {
			return n, true
		}
	}
	return ksNode{}, false
}

func (r *runner) ksAgent(ctx context.Context, node string) (stale, found bool) {
	code, body := r.api(ctx, r.o.AdminToken, "/api/v1/agents")
	if code != 200 {
		return false, false
	}
	var ag []struct {
		Node  string `json:"node"`
		Stale bool   `json:"stale"`
	}
	_ = json.Unmarshal([]byte(body), &ag)
	for _, a := range ag {
		if a.Node == node {
			return a.Stale, true
		}
	}
	return false, false
}

func nodeReady(n *corev1.Node) bool {
	for _, c := range n.Status.Conditions {
		if c.Type == corev1.NodeReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}

func since(t0, t time.Time) float64 {
	if t.IsZero() {
		return -1
	}
	return math.Round(t.Sub(t0).Seconds()*10) / 10
}

// ---- worker stop / start ---------------------------------------------------

// workerStop stops a real worker's container for StopFor, then starts it.
// kubesentry must keep serving, show the node NotReady and Ready again close
// behind the API server, and mark the node's agent stale and then fresh.
func (r *runner) workerStop(ctx context.Context) {
	node := r.o.StopNode
	pr := r.startProbe(ctx, 3*time.Second)
	if n, ok := r.ksNode(ctx, node); !ok || !n.Ready {
		r.fail("%s not ready in kubesentry before the test (%+v)", node, n)
	}
	if b, err := exec.CommandContext(ctx, "docker", "stop", node).CombinedOutput(); err != nil {
		r.fail("docker stop %s: %v %s", node, err, b)
		pr.finish()
		return
	}
	t0 := time.Now()
	r.note("docker stop", node)
	var apiDown, ksDown, agentStale time.Time
	check := func() (apiReady, ksReady, agentOK bool) {
		if n, err := r.o.CS.CoreV1().Nodes().Get(ctx, node, metav1.GetOptions{}); err == nil {
			apiReady = nodeReady(n)
		}
		if n, ok := r.ksNode(ctx, node); ok {
			ksReady = n.Ready
		}
		st, found := r.ksAgent(ctx, node)
		agentOK = found && !st
		return
	}
	for time.Since(t0) < r.o.StopFor {
		a, k, ag := check()
		if !a && apiDown.IsZero() {
			apiDown = time.Now()
			r.note("API server: node NotReady", fmt.Sprintf("+%.0fs after the stop", since(t0, apiDown)))
		}
		if !k && ksDown.IsZero() {
			ksDown = time.Now()
			r.note("kubesentry: node NotReady", fmt.Sprintf("+%.0fs after the stop", since(t0, ksDown)))
		}
		if !ag && agentStale.IsZero() {
			agentStale = time.Now()
			r.note("kubesentry: agent stale", fmt.Sprintf("+%.0fs after the stop", since(t0, agentStale)))
		}
		time.Sleep(3 * time.Second)
	}
	if b, err := exec.CommandContext(ctx, "docker", "start", node).CombinedOutput(); err != nil {
		r.fail("docker start %s: %v %s", node, err, b)
	}
	t1 := time.Now()
	r.note("docker start", fmt.Sprintf("%s after %.0fs down", node, t1.Sub(t0).Seconds()))
	var apiUp, ksUp, agentUp time.Time
	for time.Since(t1) < 6*time.Minute {
		a, k, ag := check()
		if a && apiUp.IsZero() {
			apiUp = time.Now()
			r.note("API server: node Ready", fmt.Sprintf("+%.0fs after the start", since(t1, apiUp)))
		}
		if k && ksUp.IsZero() {
			ksUp = time.Now()
			r.note("kubesentry: node Ready", fmt.Sprintf("+%.0fs after the start", since(t1, ksUp)))
		}
		if ag && agentUp.IsZero() && !apiUp.IsZero() {
			agentUp = time.Now()
			r.note("kubesentry: agent fresh", fmt.Sprintf("+%.0fs after the start", since(t1, agentUp)))
		}
		if !apiUp.IsZero() && !ksUp.IsZero() && !agentUp.IsZero() {
			break
		}
		time.Sleep(3 * time.Second)
	}
	s := pr.finish()
	r.judge(s, 1.0)
	n := r.scenario.Numbers
	n["node"], n["downSeconds"] = node, math.Round(t1.Sub(t0).Seconds())
	n["apiNotReadyAfter"], n["kubesentryNotReadyAfter"], n["agentStaleAfter"] = since(t0, apiDown), since(t0, ksDown), since(t0, agentStale)
	n["apiReadyAfterStart"], n["kubesentryReadyAfterStart"], n["agentFreshAfterStart"] = since(t1, apiUp), since(t1, ksUp), since(t1, agentUp)
	switch {
	case apiDown.IsZero():
		r.fail("the API server never showed %s NotReady within %s", node, r.o.StopFor)
	case ksDown.IsZero():
		r.fail("kubesentry never showed %s NotReady", node)
	case ksDown.Sub(apiDown) > 30*time.Second:
		r.fail("kubesentry showed NotReady %.0fs after the API server (want ≤ 30s)", ksDown.Sub(apiDown).Seconds())
	}
	if agentStale.IsZero() {
		r.fail("kubesentry never marked %s's agent stale while the node was down", node)
	}
	switch {
	case apiUp.IsZero():
		r.fail("%s not Ready again within 6 minutes", node)
	case ksUp.IsZero():
		r.fail("kubesentry did not show %s Ready again", node)
	case ksUp.Sub(apiUp) > 30*time.Second:
		r.fail("kubesentry showed Ready %.0fs after the API server (want ≤ 30s)", ksUp.Sub(apiUp).Seconds())
	}
	if agentUp.IsZero() {
		r.fail("%s's agent not fresh within 6 minutes of the start", node)
	}
	r.scenario.Summary = fmt.Sprintf("%s down %.0fs: NotReady in API +%.0fs, kubesentry +%.0fs; Ready again API +%.0fs, kubesentry +%.0fs after start; agent stale +%.0fs, fresh +%.0fs after start; probes %d/%d, snapshot age p99 %.1fs",
		node, t1.Sub(t0).Seconds(), since(t0, apiDown), since(t0, ksDown), since(t1, apiUp), since(t1, ksUp), since(t0, agentStale), since(t1, agentUp), s.OK, s.Probes, s.AgeP99)
}

// ---- cordon and drain -------------------------------------------------------

// compareNS reports pods where kubesentry and the API server disagree in one
// namespace: live (not terminating) pods missing from kubesentry or on
// another node, and pods kubesentry shows that the API server no longer has.
func (r *runner) compareNS(ctx context.Context, ns string) (int, []string, error) {
	api, err := r.o.CS.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return 0, nil, err
	}
	kp, err := r.ksPodsIn(ctx, ns)
	if err != nil {
		return 0, nil, err
	}
	var diffs []string
	live := map[string]bool{}
	for _, p := range api.Items {
		live[p.Name] = true
		if p.DeletionTimestamp != nil || p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		k, ok := kp[p.Name]
		switch {
		case !ok:
			diffs = append(diffs, "missing "+p.Name)
		case k.Node != p.Spec.NodeName:
			diffs = append(diffs, fmt.Sprintf("%s on %q, API %q", p.Name, k.Node, p.Spec.NodeName))
		}
	}
	for name := range kp {
		if !live[name] {
			diffs = append(diffs, "gone "+name)
		}
	}
	sort.Strings(diffs)
	return len(diffs), diffs, nil
}

func (r *runner) converge(ctx context.Context, nss []string, limit time.Duration) (time.Duration, []string) {
	t0 := time.Now()
	var last []string
	for time.Since(t0) < limit {
		last = nil
		for _, ns := range nss {
			_, d, err := r.compareNS(ctx, ns)
			if err != nil {
				d = []string{err.Error()}
			}
			last = append(last, d...)
		}
		if len(last) == 0 {
			return time.Since(t0), nil
		}
		time.Sleep(3 * time.Second)
	}
	return -1, last
}

// drain cordons and drains a real worker (except the pods DrainSelector
// excludes, e.g. KWOK's controller), then uncordons it.
func (r *runner) drain(ctx context.Context) {
	node := r.o.DrainNode
	pods, err := r.o.CS.CoreV1().Pods("").List(ctx, metav1.ListOptions{FieldSelector: "spec.nodeName=" + node})
	if err != nil {
		r.fail("list pods on %s: %v", node, err)
		return
	}
	nsSet := map[string]bool{}
	evict := 0
	for _, p := range pods.Items {
		ds := false
		for _, o := range p.OwnerReferences {
			ds = ds || o.Kind == "DaemonSet"
		}
		if ds || p.Annotations["kubernetes.io/config.mirror"] != "" || p.Labels["app"] == "kwok-controller" {
			continue
		}
		evict++
		nsSet[p.Namespace] = true
	}
	var nss []string
	for ns := range nsSet {
		nss = append(nss, ns)
	}
	sort.Strings(nss)
	r.note("before", fmt.Sprintf("%d pods to evict from %s in %v", evict, node, nss))
	if d, left := r.converge(ctx, nss, time.Minute); d < 0 {
		r.note("views differ before the drain", strings.Join(first10(left), "; "))
	}
	pr := r.startProbe(ctx, 3*time.Second)
	t0 := time.Now()
	type res struct {
		out string
		err error
	}
	done := make(chan res, 1)
	go func() {
		o, err := r.kubectl(ctx, "drain", node, "--ignore-daemonsets", "--delete-emptydir-data", "--force", "--grace-period=10",
			"--pod-selector", r.o.DrainSelector, "--timeout=6m")
		done <- res{o, err}
	}()
	var ksCordon time.Time
	var dr res
wait:
	for {
		select {
		case dr = <-done:
			break wait
		case <-time.After(3 * time.Second):
		}
		if ksCordon.IsZero() {
			if n, ok := r.ksNode(ctx, node); ok && n.Unschedulable {
				ksCordon = time.Now()
				r.note("kubesentry: node unschedulable", fmt.Sprintf("+%.0fs", since(t0, ksCordon)))
			}
		}
	}
	drained := time.Now()
	r.note("drain finished", fmt.Sprintf("after %.0fs, err %v: %s", drained.Sub(t0).Seconds(), dr.err, lastLines(dr.out, 2)))
	if dr.err != nil {
		r.fail("kubectl drain: %v", dr.err)
	}
	if ksCordon.IsZero() {
		if n, ok := r.ksNode(ctx, node); ok && n.Unschedulable {
			ksCordon = time.Now()
		}
	}
	// Replacement pods land on the other workers; kubesentry must agree.
	time.Sleep(10 * time.Second)
	conv1, left1 := r.converge(ctx, nss, 3*time.Minute)
	r.note("views agree after the drain", fmt.Sprintf("%.0fs (+10s settle); left %v", conv1.Seconds(), first10(left1)))
	if _, err := r.kubectl(ctx, "uncordon", node); err != nil {
		r.fail("uncordon: %v", err)
	}
	t2 := time.Now()
	var ksUncordon time.Time
	for time.Since(t2) < time.Minute {
		if n, ok := r.ksNode(ctx, node); ok && !n.Unschedulable {
			ksUncordon = time.Now()
			break
		}
		time.Sleep(2 * time.Second)
	}
	r.note("uncordoned", fmt.Sprintf("kubesentry schedulable again +%.0fs", since(t2, ksUncordon)))
	// Pending pods bound to node-local volumes go back to the node.
	time.Sleep(30 * time.Second)
	conv2, left2 := r.converge(ctx, nss, 3*time.Minute)
	r.note("views agree after the uncordon", fmt.Sprintf("%.0fs (+30s settle); left %v", conv2.Seconds(), first10(left2)))
	s := pr.finish()
	r.judge(s, 1.0)
	n := r.scenario.Numbers
	n["node"], n["evicted"], n["namespaces"] = node, evict, nss
	n["drainSeconds"], n["kubesentryUnschedulableAfter"], n["kubesentrySchedulableAfterUncordon"] = math.Round(drained.Sub(t0).Seconds()), since(t0, ksCordon), since(t2, ksUncordon)
	n["agreeAfterDrainSeconds"], n["agreeAfterUncordonSeconds"] = conv1.Seconds(), conv2.Seconds()
	if ksCordon.IsZero() || ksCordon.Sub(t0) > 30*time.Second {
		r.fail("kubesentry did not show the node unschedulable within 30s")
	}
	if conv1 < 0 || conv1 > 30*time.Second {
		r.fail("after the drain kubesentry and the API server disagree beyond 30s (+10s settle): %v", first10(left1))
	}
	if conv2 < 0 || conv2 > 30*time.Second {
		r.fail("after the uncordon kubesentry and the API server disagree beyond 30s (+30s settle): %v", first10(left2))
	}
	r.scenario.Summary = fmt.Sprintf("%d pods drained from %s in %.0fs; unschedulable shown +%.0fs; views agree %.0fs after the drain and %.0fs after the uncordon (plus settle time); probes %d/%d",
		evict, node, drained.Sub(t0).Seconds(), since(t0, ksCordon), conv1.Seconds(), conv2.Seconds(), s.OK, s.Probes)
}

func first10(s []string) []string {
	if len(s) > 10 {
		return append(s[:10:10], fmt.Sprintf("… %d more", len(s)-10))
	}
	return s
}

func lastLines(s string, n int) string {
	l := strings.Split(strings.TrimSpace(s), "\n")
	if len(l) > n {
		l = l[len(l)-n:]
	}
	return strings.Join(l, " / ")
}

// ---- RBAC storm -------------------------------------------------------------

// rbacStorm creates, modifies and deletes StormN RoleBindings for subjects
// that are not personas (so every persona's truth stays the same and any
// item outside it is a leak), while a probe identity is granted and revoked
// view in one namespace to time how long kubesentry takes to follow.
func (r *runner) rbacStorm(ctx context.Context) {
	nss := r.o.TeamNamespaces
	if len(nss) == 0 {
		r.fail("no team namespaces")
		return
	}
	pr := r.startProbe(ctx, 3*time.Second)
	// Leak watch: page every sampled persona's pods while the storm runs.
	stopWatch := make(chan struct{})
	var leaks, checks atomic.Int64
	var leakSamples sync.Map
	var watchWG sync.WaitGroup
	watchWG.Add(1)
	go func() {
		defer watchWG.Done()
		for {
			for _, p := range r.o.StormPersonas {
				select {
				case <-stopWatch:
					return
				default:
				}
				code, body := r.curl(ctx, "GET", "http://"+r.webIP+":4180/api/v1/pods?limit=1000", map[string]string{"Authorization": "Bearer " + p.Token}, nil)
				if code != 200 {
					continue
				}
				var pods ks.PodsResponse
				_ = json.Unmarshal([]byte(body), &pods)
				checks.Add(1)
				for _, it := range pods.Items {
					if !p.Allowed[it.Namespace] {
						leaks.Add(1)
						leakSamples.Store(p.Email+" sees "+it.Namespace+"/"+it.Name, true)
					}
				}
			}
			select {
			case <-stopWatch:
				return
			case <-time.After(2 * time.Second):
			}
		}
	}()

	rbs := r.o.CS.RbacV1()
	name := func(i int) string { return fmt.Sprintf("storm-%04d", i) }
	nsOf := func(i int) string { return nss[i%len(nss)] }
	labels := map[string]string{stressLabel: "true", "kubesentry.io/stress-storm": "true"}
	paced := func(what string, f func(i int) error) (time.Duration, int) {
		t := time.Now()
		var errs atomic.Int64
		jobs := make(chan int)
		var wg sync.WaitGroup
		for w := 0; w < 8; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range jobs {
					if err := f(i); err != nil && !apierrors.IsNotFound(err) {
						if errs.Add(1) <= 3 {
							r.note(what+" error", err.Error())
						}
					}
				}
			}()
		}
		tick := time.NewTicker(time.Duration(float64(time.Second) / r.o.StormRate))
		for i := 0; i < r.o.StormN; i++ {
			<-tick.C
			jobs <- i
		}
		tick.Stop()
		close(jobs)
		wg.Wait()
		d := time.Since(t)
		r.note(what, fmt.Sprintf("%d in %.0fs (%.0f/s), %d errors", r.o.StormN, d.Seconds(), float64(r.o.StormN)/d.Seconds(), errs.Load()))
		return d, int(errs.Load())
	}

	// The probe user: asks first (denied, cached), is granted view in one
	// namespace, later revoked.
	probeNS := nss[len(nss)/2]
	probeTok := r.o.Mint("storm-probe@corp.example", nil)
	visible := func() (bool, int) {
		code, body := r.curl(ctx, "GET", "http://"+r.webIP+":4180/api/v1/pods?limit=5&namespace="+probeNS, map[string]string{"Authorization": "Bearer " + probeTok}, nil)
		var pods ks.PodsResponse
		_ = json.Unmarshal([]byte(body), &pods)
		return code == 200 && len(pods.Items) > 0, code
	}
	probeRB := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "storm-probe", Namespace: probeNS, Labels: labels},
		Subjects:   []rbacv1.Subject{{Kind: "User", Name: "storm-probe@corp.example", APIGroup: "rbac.authorization.k8s.io"}},
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "view", APIGroup: "rbac.authorization.k8s.io"},
	}
	waitFor := func(want bool, limit time.Duration) float64 {
		t := time.Now()
		for time.Since(t) < limit {
			if v, _ := visible(); v == want {
				return math.Round(time.Since(t).Seconds()*10) / 10
			}
			time.Sleep(2 * time.Second)
		}
		return -1
	}
	if v, code := visible(); v {
		r.fail("the probe user sees %s before any grant (HTTP %d)", probeNS, code)
	} else {
		r.note("probe user before the grant", fmt.Sprintf("HTTP %d, nothing visible in %s", code, probeNS))
	}
	if _, err := rbs.RoleBindings(probeNS).Create(ctx, probeRB, metav1.CreateOptions{}); err != nil {
		r.fail("create the probe grant: %v", err)
	}
	grantDone := make(chan float64, 1)
	go func() { grantDone <- waitFor(true, 3*time.Minute) }()

	createD, createErrs := paced("created", func(i int) error {
		_, err := rbs.RoleBindings(nsOf(i)).Create(ctx, &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: name(i), Namespace: nsOf(i), Labels: labels},
			Subjects: []rbacv1.Subject{
				{Kind: "User", Name: fmt.Sprintf("storm-u-%d@corp.example", i), APIGroup: "rbac.authorization.k8s.io"},
				{Kind: "Group", Name: fmt.Sprintf("storm:g-%d", i%50), APIGroup: "rbac.authorization.k8s.io"},
			},
			RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: []string{"view", "edit", "admin"}[i%3], APIGroup: "rbac.authorization.k8s.io"},
		}, metav1.CreateOptions{})
		return err
	})
	grant := <-grantDone
	r.note("probe grant visible", fmt.Sprintf("after %.0fs (deny TTL 1m)", grant))
	// Revoke while the storm goes on.
	if err := rbs.RoleBindings(probeNS).Delete(ctx, "storm-probe", metav1.DeleteOptions{}); err != nil {
		r.fail("delete the probe grant: %v", err)
	}
	revokeDone := make(chan float64, 1)
	go func() { revokeDone <- waitFor(false, 7*time.Minute) }()
	modifyD, modifyErrs := paced("modified", func(i int) error {
		patch := fmt.Sprintf(`{"subjects":[{"kind":"User","name":"storm-u-%d-v2@corp.example","apiGroup":"rbac.authorization.k8s.io"},{"kind":"Group","name":"storm:g-%d","apiGroup":"rbac.authorization.k8s.io"}]}`, i, (i+1)%50)
		_, err := rbs.RoleBindings(nsOf(i)).Patch(ctx, name(i), types.MergePatchType, []byte(patch), metav1.PatchOptions{})
		return err
	})
	deleteD, deleteErrs := paced("deleted", func(i int) error {
		return rbs.RoleBindings(nsOf(i)).Delete(ctx, name(i), metav1.DeleteOptions{})
	})
	revoke := <-revokeDone
	r.note("probe revocation visible", fmt.Sprintf("after %.0fs (allow TTL 5m)", revoke))
	// The recheck path: grant, see it, revoke, ask for a recheck.
	recheck := -1.0
	if _, err := rbs.RoleBindings(probeNS).Create(ctx, probeRB, metav1.CreateOptions{}); err == nil {
		if g := waitFor(true, 3*time.Minute); g >= 0 {
			_ = rbs.RoleBindings(probeNS).Delete(ctx, "storm-probe", metav1.DeleteOptions{})
			time.Sleep(time.Second)
			code, body := r.curl(ctx, "POST", "http://"+r.webIP+":4180/api/v1/auth/recheck", map[string]string{"Authorization": "Bearer " + probeTok}, nil)
			r.note("POST /api/v1/auth/recheck", fmt.Sprintf("HTTP %d %s", code, firstN(strings.TrimSpace(body), 120)))
			recheck = waitFor(false, 6*time.Minute)
			r.note("revocation visible after the recheck", fmt.Sprintf("%.0fs", recheck))
		}
	}
	_ = rbs.RoleBindings(probeNS).Delete(ctx, "storm-probe", metav1.DeleteOptions{})
	close(stopWatch)
	watchWG.Wait()
	s := pr.finish()
	r.judge(s, 0.99)
	var samples []string
	leakSamples.Range(func(k, _ any) bool {
		if len(samples) < 5 {
			samples = append(samples, k.(string))
		}
		return true
	})
	n := r.scenario.Numbers
	n["roleBindings"], n["createSeconds"], n["modifySeconds"], n["deleteSeconds"] = r.o.StormN, math.Round(createD.Seconds()), math.Round(modifyD.Seconds()), math.Round(deleteD.Seconds())
	n["apiErrors"] = createErrs + modifyErrs + deleteErrs
	n["personaChecks"], n["leaks"] = checks.Load(), leaks.Load()
	n["grantVisibleSeconds"], n["revokeVisibleSeconds"], n["revokeAfterRecheckSeconds"] = grant, revoke, recheck
	if leaks.Load() > 0 {
		r.fail("%d leaked pods during the storm, e.g. %v", leaks.Load(), samples)
	}
	if grant < 0 || grant > 90 {
		r.fail("the grant took %.0fs to show (want ≤ 90s: deny TTL 1m)", grant)
	}
	if revoke < 0 || revoke > 330 {
		r.fail("the revocation took %.0fs to show (want ≤ 330s: allow TTL 5m)", revoke)
	}
	if recheck < 0 || recheck > 15 {
		r.fail("after POST /auth/recheck the revocation took %.0fs to show (want ≤ 15s)", recheck)
	}
	r.scenario.Summary = fmt.Sprintf("%d RoleBindings created in %.0fs, modified in %.0fs, deleted in %.0fs; %d persona page checks, %d leaks; probe grant visible after %.0fs, revocation after %.0fs (TTL), %.0fs with a recheck; probes %d/%d",
		r.o.StormN, createD.Seconds(), modifyD.Seconds(), deleteD.Seconds(), checks.Load(), leaks.Load(), grant, revoke, recheck, s.OK, s.Probes)
}

// ---- helpers for fake-node pods ----------------------------------------------

func boolp(b bool) *bool    { return &b }
func int64p(i int64) *int64 { return &i }

func fakePodSpec() corev1.PodSpec {
	return corev1.PodSpec{
		NodeSelector:                  map[string]string{"type": "kwok"},
		Tolerations:                   []corev1.Toleration{{Key: "kwok.x-k8s.io/node", Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule}},
		TerminationGracePeriodSeconds: int64p(0),
		Containers: []corev1.Container{{
			Name: "app", Image: "123456789012.dkr.ecr.us-east-1.amazonaws.com/chaos/app:1.0",
			Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{}},
			SecurityContext: &corev1.SecurityContext{
				RunAsNonRoot: boolp(true), AllowPrivilegeEscalation: boolp(false), ReadOnlyRootFilesystem: boolp(true),
				Capabilities:   &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
		}},
	}
}

func (r *runner) ensureNS(ctx context.Context, ns string) error {
	_, err := r.o.CS.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns, Labels: map[string]string{stressLabel: "true"}}}, metav1.CreateOptions{})
	if apierrors.IsAlreadyExists(err) {
		return nil
	}
	return err
}

func (r *runner) deleteNSAndWait(ctx context.Context, ns string, limit time.Duration) time.Duration {
	t := time.Now()
	_ = r.o.CS.CoreV1().Namespaces().Delete(ctx, ns, metav1.DeleteOptions{})
	for time.Since(t) < limit {
		if _, err := r.o.CS.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{}); apierrors.IsNotFound(err) {
			return time.Since(t)
		}
		time.Sleep(2 * time.Second)
	}
	return -1
}

// ksCount is kubesentry's pod count in a namespace (-1 on error).
func (r *runner) ksCount(ctx context.Context, ns string) int {
	m, err := r.ksPodsIn(ctx, ns)
	if err != nil {
		return -1
	}
	return len(m)
}

func (r *runner) apiCount(ctx context.Context, ns string, live bool) int {
	l, err := r.o.CS.CoreV1().Pods(ns).List(ctx, metav1.ListOptions{ResourceVersion: "0"})
	if err != nil {
		return -1
	}
	if !live {
		return len(l.Items)
	}
	n := 0
	for _, p := range l.Items {
		if p.DeletionTimestamp == nil {
			n++
		}
	}
	return n
}

func (r *runner) fakeNodes(ctx context.Context) []string {
	l, err := r.o.CS.CoreV1().Nodes().List(ctx, metav1.ListOptions{LabelSelector: "type=kwok"})
	if err != nil {
		return nil
	}
	var out []string
	for _, n := range l.Items {
		if nodeReady(&n) && len(n.Spec.Taints) <= 1 && n.Labels["eks.amazonaws.com/compute-type"] != "fargate" && n.Labels["kubernetes.io/os"] != "windows" {
			out = append(out, n.Name)
		}
	}
	sort.Strings(out)
	return out
}

// ---- pod churn -------------------------------------------------------------

// churn creates ChurnRate pods per second on fake nodes, each living
// ChurnLife, for ChurnFor, behind one Service, then deletes the rest.
func (r *runner) churn(ctx context.Context) {
	const ns = "stress-churn"
	if err := r.ensureNS(ctx, ns); err != nil {
		r.fail("namespace: %v", err)
		return
	}
	defer r.deleteNSAndWait(ctx, ns, 3*time.Minute)
	_, _ = r.o.CS.CoreV1().Services(ns).Create(ctx, &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "churn", Labels: map[string]string{stressLabel: "true"}},
		Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "churn"}, Ports: []corev1.ServicePort{{Port: 80, TargetPort: intstr.FromInt(8080)}}},
	}, metav1.CreateOptions{})
	nodes := r.fakeNodes(ctx)
	if len(nodes) == 0 {
		r.fail("no fake nodes")
		return
	}
	pr := r.startProbe(ctx, 3*time.Second)
	pods := r.o.CS.CoreV1().Pods(ns)
	type item struct {
		name string
		at   time.Time
	}
	var created, deleted, createErrs, deleteErrs atomic.Int64
	createQ := make(chan int, 1000)
	deleteQ := make(chan item, 100000)
	var wg sync.WaitGroup
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range createQ {
				spec := fakePodSpec()
				spec.NodeName = nodes[i%len(nodes)]
				p := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("churn-%05d", i), Labels: map[string]string{stressLabel: "true", "app": "churn"}}, Spec: spec}
				if _, err := pods.Create(ctx, p, metav1.CreateOptions{}); err != nil {
					createErrs.Add(1)
					continue
				}
				created.Add(1)
				deleteQ <- item{p.Name, time.Now()}
			}
		}()
	}
	stopDel := make(chan struct{})
	var dwg sync.WaitGroup
	for w := 0; w < 16; w++ {
		dwg.Add(1)
		go func() {
			defer dwg.Done()
			for {
				var it item
				select {
				case it = <-deleteQ:
				case <-stopDel:
					return
				}
				if d := time.Until(it.at.Add(r.o.ChurnLife)); d > 0 {
					select {
					case <-time.After(d):
					case <-stopDel:
						return
					}
				}
				if err := pods.Delete(ctx, it.name, metav1.DeleteOptions{GracePeriodSeconds: int64p(0)}); err != nil && !apierrors.IsNotFound(err) {
					deleteErrs.Add(1)
					continue
				}
				deleted.Add(1)
			}
		}()
	}
	// Watch kubesentry's count against the API server's while it runs.
	stopMon := make(chan struct{})
	diffs := hist.New()
	var maxLive, maxDiff atomic.Int64
	var mwg sync.WaitGroup
	mwg.Add(1)
	go func() {
		defer mwg.Done()
		for {
			select {
			case <-stopMon:
				return
			case <-time.After(5 * time.Second):
			}
			a := r.apiCount(ctx, ns, true)
			k := r.ksCount(ctx, ns)
			if a < 0 || k < 0 {
				continue
			}
			if int64(a) > maxLive.Load() {
				maxLive.Store(int64(a))
			}
			d := int64(math.Abs(float64(a - k)))
			diffs.Add(float64(d))
			if d > maxDiff.Load() {
				maxDiff.Store(d)
			}
		}
	}()
	t0 := time.Now()
	tick := time.NewTicker(time.Duration(float64(time.Second) / r.o.ChurnRate))
	i := 0
	for time.Since(t0) < r.o.ChurnFor {
		<-tick.C
		select {
		case createQ <- i:
			i++
		default: // creators are behind; the achieved rate shows it
		}
	}
	tick.Stop()
	close(createQ)
	wg.Wait()
	churnSecs := time.Since(t0).Seconds()
	r.note("churn finished", fmt.Sprintf("%d created (%.1f/s), %d deleted, %d create errors, %d delete errors", created.Load(), float64(created.Load())/churnSecs, deleted.Load(), createErrs.Load(), deleteErrs.Load()))
	close(stopDel)
	dwg.Wait()
	close(stopMon)
	mwg.Wait()
	// Delete what is left and time kubesentry's view reaching zero.
	_ = pods.DeleteCollection(ctx, metav1.DeleteOptions{GracePeriodSeconds: int64p(0)}, metav1.ListOptions{LabelSelector: "app=churn"})
	tDel := time.Now()
	var apiZero, ksZero time.Time
	for time.Since(tDel) < 5*time.Minute {
		if apiZero.IsZero() && r.apiCount(ctx, ns, false) == 0 {
			apiZero = time.Now()
		}
		if !apiZero.IsZero() && r.ksCount(ctx, ns) == 0 {
			ksZero = time.Now()
			break
		}
		time.Sleep(2 * time.Second)
	}
	s := pr.finish()
	r.judge(s, 0.99)
	rate := float64(created.Load()) / churnSecs
	lag := -1.0
	if !ksZero.IsZero() {
		lag = math.Round(ksZero.Sub(apiZero).Seconds()*10) / 10
	}
	n := r.scenario.Numbers
	n["targetRate"], n["achievedRate"], n["created"], n["deleted"], n["createErrors"], n["deleteErrors"] = r.o.ChurnRate, math.Round(rate*10)/10, created.Load(), deleted.Load(), createErrs.Load(), deleteErrs.Load()
	n["maxLivePods"], n["countDiffP50"], n["countDiffP95"], n["countDiffMax"] = maxLive.Load(), diffs.Quantile(0.5), diffs.Quantile(0.95), maxDiff.Load()
	n["apiEmptyAfterDeleteSeconds"], n["kubesentryEmptyAfterAPISeconds"] = since(tDel, apiZero), lag
	if rate < 0.9*r.o.ChurnRate {
		r.fail("achieved %.1f pods/s (target %.0f)", rate, r.o.ChurnRate)
	}
	if lag < 0 || lag > 30 {
		r.fail("kubesentry still showed churn pods %.0fs after the API server had none (want ≤ 30s)", lag)
	}
	r.scenario.Summary = fmt.Sprintf("%d pods created and %d deleted in %.0fs (%.1f/s, up to %d live); kubesentry's count within %.0f (p95) / %d (max) of the API server's while churning, empty %.0fs after the API server; probes %d/%d, snapshot age p99 %.1fs",
		created.Load(), deleted.Load(), churnSecs, rate, maxLive.Load(), diffs.Quantile(0.95), maxDiff.Load(), lag, s.OK, s.Probes, s.AgeP99)
}

// ---- rolling update of a big Deployment ------------------------------------------

func fakeDeployment(name string, replicas int32) *appsv1.Deployment {
	maxS, maxU := intstr.FromString("25%"), intstr.FromString("25%")
	spec := fakePodSpec()
	spec.TerminationGracePeriodSeconds = int64p(0)
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{stressLabel: "true"}},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": name}},
			Strategy: appsv1.DeploymentStrategy{Type: appsv1.RollingUpdateDeploymentStrategyType, RollingUpdate: &appsv1.RollingUpdateDeployment{MaxSurge: &maxS, MaxUnavailable: &maxU}},
			Template: corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": name, stressLabel: "true"}}, Spec: spec},
		},
	}
}

func (r *runner) waitAvailable(ctx context.Context, ns, name string, want int32, limit time.Duration) time.Duration {
	t := time.Now()
	for time.Since(t) < limit {
		d, err := r.o.CS.AppsV1().Deployments(ns).Get(ctx, name, metav1.GetOptions{})
		if err == nil && d.Status.ObservedGeneration >= d.Generation && d.Status.UpdatedReplicas == want && d.Status.AvailableReplicas == want && d.Status.Replicas == want {
			return time.Since(t)
		}
		time.Sleep(3 * time.Second)
	}
	return -1
}

func (r *runner) ksWorkloadPods(ctx context.Context, ns, name string) int {
	code, body := r.api(ctx, r.o.AdminToken, "/api/v1/workloads?limit=1000&namespace="+ns)
	if code != 200 {
		return -1
	}
	var w ks.WorkloadsResponse
	_ = json.Unmarshal([]byte(body), &w)
	for _, it := range w.Items {
		if it.Name == name && it.Kind == "Deployment" {
			return it.Pods
		}
	}
	return 0
}

// rollout creates a RolloutReplicas Deployment on fake nodes, rolls it, and
// checks kubesentry follows; then deletes it.
func (r *runner) rollout(ctx context.Context) {
	const ns, name = "stress-roll", "big"
	if err := r.ensureNS(ctx, ns); err != nil {
		r.fail("namespace: %v", err)
		return
	}
	defer r.deleteNSAndWait(ctx, ns, 5*time.Minute)
	n := int32(r.o.RolloutReplicas)
	if _, err := r.o.CS.AppsV1().Deployments(ns).Create(ctx, fakeDeployment(name, n), metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		r.fail("create: %v", err)
		return
	}
	up := r.waitAvailable(ctx, ns, name, n, 10*time.Minute)
	r.note("Deployment available", fmt.Sprintf("%d replicas after %.0fs", n, up.Seconds()))
	if up < 0 {
		r.fail("%d replicas not available within 10 minutes", n)
		return
	}
	t := time.Now()
	for r.ksWorkloadPods(ctx, ns, name) != int(n) && time.Since(t) < 2*time.Minute {
		time.Sleep(3 * time.Second)
	}
	r.note("kubesentry shows the Deployment", fmt.Sprintf("%d pods, %.0fs after it was available", r.ksWorkloadPods(ctx, ns, name), time.Since(t).Seconds()))
	pr := r.startProbe(ctx, 3*time.Second)
	t0 := time.Now()
	patch := fmt.Sprintf(`{"spec":{"template":{"metadata":{"annotations":{"kubesentry.io/stress-rev":"%d"}}}}}`, t0.Unix())
	if _, err := r.o.CS.AppsV1().Deployments(ns).Patch(ctx, name, types.MergePatchType, []byte(patch), metav1.PatchOptions{}); err != nil {
		r.fail("patch: %v", err)
	}
	// Watch kubesentry's pod count for the Deployment during the roll.
	stop := make(chan struct{})
	var maxKS atomic.Int64
	var mwg sync.WaitGroup
	mwg.Add(1)
	go func() {
		defer mwg.Done()
		for {
			select {
			case <-stop:
				return
			case <-time.After(5 * time.Second):
			}
			if c := r.ksWorkloadPods(ctx, ns, name); int64(c) > maxKS.Load() {
				maxKS.Store(int64(c))
			}
		}
	}()
	rolled := r.waitAvailable(ctx, ns, name, n, 15*time.Minute)
	tDone := time.Now()
	r.note("rollout complete (API)", fmt.Sprintf("%.0fs", rolled.Seconds()))
	close(stop)
	mwg.Wait()
	conv, left := r.converge(ctx, []string{ns}, 3*time.Minute)
	r.note("kubesentry agrees", fmt.Sprintf("%.0fs after the rollout completed; left %v", conv.Seconds(), first10(left)))
	wp := r.ksWorkloadPods(ctx, ns, name)
	// Then delete the namespace and time kubesentry's view emptying.
	_ = r.o.CS.CoreV1().Namespaces().Delete(ctx, ns, metav1.DeleteOptions{})
	tDel := time.Now()
	var apiZero, ksZero time.Time
	for time.Since(tDel) < 5*time.Minute {
		if apiZero.IsZero() && r.apiCount(ctx, ns, false) == 0 {
			apiZero = time.Now()
		}
		if !apiZero.IsZero() && r.ksCount(ctx, ns) == 0 {
			ksZero = time.Now()
			break
		}
		time.Sleep(2 * time.Second)
	}
	s := pr.finish()
	r.judge(s, 0.99)
	nm := r.scenario.Numbers
	nm["replicas"], nm["availableSeconds"], nm["rolloutSeconds"], nm["kubesentryAgreeAfterRolloutSeconds"] = n, math.Round(up.Seconds()), math.Round(rolled.Seconds()), conv.Seconds()
	nm["kubesentryWorkloadPodsAfter"], nm["kubesentryWorkloadPodsMaxDuring"] = wp, maxKS.Load()
	nm["apiEmptyAfterDeleteSeconds"], nm["kubesentryEmptyAfterAPISeconds"] = since(tDel, apiZero), since(apiZero, ksZero)
	if rolled < 0 {
		r.fail("rollout not complete within 15 minutes")
	}
	if conv < 0 || conv > 30*time.Second {
		r.fail("kubesentry disagreed with the API server %v after the rollout (want ≤ 30s): %v", conv, first10(left))
	}
	if wp != int(n) {
		r.fail("kubesentry counts %d pods for the Deployment after the rollout, want %d", wp, n)
	}
	if ksZero.IsZero() || ksZero.Sub(apiZero) > 30*time.Second {
		r.fail("kubesentry still showed pods %.0fs after the namespace was empty", since(apiZero, ksZero))
	}
	r.scenario.Summary = fmt.Sprintf("%d replicas available in %.0fs, rolled in %.0fs (25%% surge/unavailable); kubesentry agreed %.0fs after the rollout (max %d pods counted during it), and was empty %.0fs after the API server once deleted; probes %d/%d, snapshot age p99 %.1fs",
		n, up.Seconds(), rolled.Seconds(), conv.Seconds(), maxKS.Load(), since(apiZero, ksZero), s.OK, s.Probes, s.AgeP99)
	_ = tDone
}

// ---- deleting a namespace of 2,000 pods ----------------------------------------

func (r *runner) nsDelete(ctx context.Context) {
	const ns = "stress-nsdel"
	if err := r.ensureNS(ctx, ns); err != nil {
		r.fail("namespace: %v", err)
		return
	}
	per := int32(r.o.NSDeletePods / 4)
	for i := 0; i < 4; i++ {
		name := fmt.Sprintf("svc-%d", i)
		if _, err := r.o.CS.AppsV1().Deployments(ns).Create(ctx, fakeDeployment(name, per), metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
			r.fail("create %s: %v", name, err)
		}
		_, _ = r.o.CS.CoreV1().Services(ns).Create(ctx, &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{stressLabel: "true"}},
			Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": name}, Ports: []corev1.ServicePort{{Port: 80, TargetPort: intstr.FromInt(8080)}}},
		}, metav1.CreateOptions{})
	}
	for i := 0; i < 4; i++ {
		if d := r.waitAvailable(ctx, ns, fmt.Sprintf("svc-%d", i), per, 10*time.Minute); d < 0 {
			r.fail("svc-%d not available within 10 minutes", i)
		}
	}
	total := int(per) * 4
	t := time.Now()
	for r.ksCount(ctx, ns) < total && time.Since(t) < 2*time.Minute {
		time.Sleep(3 * time.Second)
	}
	r.note("ready", fmt.Sprintf("API %d pods, kubesentry %d", r.apiCount(ctx, ns, false), r.ksCount(ctx, ns)))
	pr := r.startProbe(ctx, 3*time.Second)
	t0 := time.Now()
	if err := r.o.CS.CoreV1().Namespaces().Delete(ctx, ns, metav1.DeleteOptions{}); err != nil {
		r.fail("delete namespace: %v", err)
	}
	var apiZero, apiGone, ksZero, ksMap404 time.Time
	for time.Since(t0) < 8*time.Minute {
		if apiZero.IsZero() && r.apiCount(ctx, ns, false) == 0 {
			apiZero = time.Now()
			r.note("API server: no pods", fmt.Sprintf("+%.0fs", since(t0, apiZero)))
		}
		if apiGone.IsZero() {
			if _, err := r.o.CS.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{}); apierrors.IsNotFound(err) {
				apiGone = time.Now()
				r.note("API server: namespace gone", fmt.Sprintf("+%.0fs", since(t0, apiGone)))
			}
		}
		if ksZero.IsZero() && r.ksCount(ctx, ns) == 0 {
			ksZero = time.Now()
			r.note("kubesentry: no pods", fmt.Sprintf("+%.0fs", since(t0, ksZero)))
		}
		if ksMap404.IsZero() && !apiGone.IsZero() {
			if code, _ := r.api(ctx, r.o.AdminToken, "/api/v1/map?namespace="+ns); code == 404 {
				ksMap404 = time.Now()
				r.note("kubesentry: map of the namespace 404", fmt.Sprintf("+%.0fs", since(t0, ksMap404)))
			}
		}
		if !apiGone.IsZero() && !ksZero.IsZero() && !ksMap404.IsZero() {
			break
		}
		time.Sleep(2 * time.Second)
	}
	s := pr.finish()
	r.judge(s, 0.99)
	nm := r.scenario.Numbers
	nm["pods"], nm["apiNoPodsAfter"], nm["apiNamespaceGoneAfter"], nm["kubesentryNoPodsAfter"], nm["kubesentryMap404After"] = total, since(t0, apiZero), since(t0, apiGone), since(t0, ksZero), since(t0, ksMap404)
	switch {
	case apiGone.IsZero():
		r.fail("namespace not gone within 8 minutes")
	case ksZero.IsZero():
		r.fail("kubesentry still shows pods of the deleted namespace")
	case ksZero.Sub(apiZero) > 30*time.Second:
		r.fail("kubesentry showed pods %.0fs after the API server had none (want ≤ 30s)", ksZero.Sub(apiZero).Seconds())
	}
	if !apiGone.IsZero() && (ksMap404.IsZero() || ksMap404.Sub(apiGone) > 30*time.Second) {
		r.fail("kubesentry's map still served the namespace %.0fs after it was gone", since(apiGone, ksMap404))
	}
	r.scenario.Summary = fmt.Sprintf("namespace with %d pods deleted: API server empty +%.0fs, namespace gone +%.0fs; kubesentry empty +%.0fs, map 404 +%.0fs; probes %d/%d, snapshot age p99 %.1fs",
		total, since(t0, apiZero), since(t0, apiGone), since(t0, ksZero), since(t0, ksMap404), s.OK, s.Probes, s.AgeP99)
}

// ---- cold restart under load -------------------------------------------------------

// coldRestart deletes both replicas at once while hack/stress-run.sh runs the
// users at 500. It times the replacements becoming Ready and serving, then
// reads the users' 10s buckets (UsersFile) for the errors around it.
func (r *runner) coldRestart(ctx context.Context) {
	old := r.serverPods(ctx)
	oldSet := map[string]bool{}
	for _, p := range old {
		oldSet[p.name] = true
	}
	// Serving check every second through oauth2-proxy.
	type obs struct {
		t  time.Time
		ok bool
	}
	var mu sync.Mutex
	var series []obs
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			case <-time.After(time.Second):
			}
			code, _ := r.api(ctx, r.o.AdminToken, "/api/v1/pods?limit=5")
			mu.Lock()
			series = append(series, obs{time.Now(), code == 200})
			mu.Unlock()
		}
	}()
	time.Sleep(10 * time.Second)
	t0 := time.Now()
	if out, err := r.kubectl(ctx, "-n", r.o.Namespace, "delete", "pod", "-l", "app.kubernetes.io/component=server", "--wait=false"); err != nil {
		r.fail("delete pods: %v %s", err, out)
	} else {
		r.note("deleted both replicas", out)
	}
	var firstReady, bothReady time.Time
	ready := map[string]bool{}
	for time.Since(t0) < 6*time.Minute {
		l, err := r.o.CS.CoreV1().Pods(r.o.Namespace).List(ctx, metav1.ListOptions{LabelSelector: "app.kubernetes.io/component=server"})
		if err == nil {
			for _, p := range l.Items {
				if oldSet[p.Name] || p.DeletionTimestamp != nil {
					continue
				}
				for _, c := range p.Status.Conditions {
					if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue && !ready[p.Name] {
						ready[p.Name] = true
						r.note("replacement Ready", fmt.Sprintf("%s +%.0fs", p.Name, time.Since(t0).Seconds()))
						if firstReady.IsZero() {
							firstReady = time.Now()
						}
					}
				}
			}
		}
		if len(ready) >= 2 {
			bothReady = time.Now()
			break
		}
		time.Sleep(time.Second)
	}
	time.Sleep(60 * time.Second)
	close(stop)
	wg.Wait()
	// Outage seen by the serving check: first failure after t0 to the first
	// success after the last failure.
	var outStart, outEnd time.Time
	fails := 0
	for _, o := range series {
		if o.t.Before(t0) {
			continue
		}
		if !o.ok {
			fails++
			if outStart.IsZero() {
				outStart = o.t
			}
			outEnd = time.Time{}
		} else if !outStart.IsZero() && outEnd.IsZero() {
			outEnd = o.t
		}
	}
	outage := 0.0
	if !outStart.IsZero() && !outEnd.IsZero() {
		outage = outEnd.Sub(outStart).Seconds()
	}
	r.note("serving check", fmt.Sprintf("%d failures; outage %.0fs (from +%.0fs)", fails, outage, since(t0, outStart)))
	// Restarts of the replacements so far.
	restarts := 0
	var reasons []string
	if l, err := r.o.CS.CoreV1().Pods(r.o.Namespace).List(ctx, metav1.ListOptions{LabelSelector: "app.kubernetes.io/component=server"}); err == nil {
		for _, p := range l.Items {
			for _, c := range p.Status.ContainerStatuses {
				restarts += int(c.RestartCount)
				if c.LastTerminationState.Terminated != nil {
					reasons = append(reasons, c.LastTerminationState.Terminated.Reason)
				}
			}
		}
	}
	nm := r.scenario.Numbers
	nm["firstReadySeconds"], nm["bothReadySeconds"], nm["servingOutageSeconds"], nm["servingFailures"], nm["replacementRestarts"] = since(t0, firstReady), since(t0, bothReady), math.Round(outage), fails, restarts
	if bothReady.IsZero() || bothReady.Sub(t0) > 120*time.Second {
		r.fail("both replacements Ready after %.0fs (want ≤ 120s)", since(t0, bothReady))
	}
	if outage > 120 {
		r.fail("not serving for %.0fs (want ≤ 120s)", outage)
	}
	if restarts > 0 {
		r.fail("replacements restarted %d times (%v)", restarts, reasons)
	}
	// The users' view: wait for the users result.
	usersErr, afterErr := -1.0, -1.0
	if r.o.UsersFile != "" {
		r.note("waiting for the users result", r.o.UsersFile)
		var u users.Result
		deadline := time.Now().Add(25 * time.Minute)
		for time.Now().Before(deadline) {
			var cand users.Result
			if b, err := os.ReadFile(r.o.UsersFile); err == nil && json.Unmarshal(b, &cand) == nil && cand.Started.Before(t0) && cand.Finished.After(t0) {
				u = cand
				break
			}
			time.Sleep(10 * time.Second)
		}
		if u.Finished.IsZero() {
			r.fail("no users result in %s", r.o.UsersFile)
		} else {
			var reqB, errB, reqDur, errDur, reqA, errA int64
			recovered := bothReady
			if recovered.IsZero() {
				recovered = t0.Add(2 * time.Minute)
			}
			for _, b := range u.Series {
				switch {
				case b.T.Before(t0.Add(-5*time.Minute)) || b.T.After(recovered.Add(5*time.Minute)):
				case b.T.Before(t0.Add(-10 * time.Second)):
					reqB, errB = reqB+b.Requests, errB+b.Errors
				case b.T.Before(recovered.Add(30 * time.Second)):
					reqDur, errDur = reqDur+b.Requests, errDur+b.Errors
				default:
					reqA, errA = reqA+b.Requests, errA+b.Errors
				}
			}
			rate := func(e, n int64) float64 {
				if n == 0 {
					return 0
				}
				return math.Round(10000*float64(e)/float64(n)) / 100
			}
			usersErr, afterErr = rate(errDur, reqDur), rate(errA, reqA)
			nm["usersErrorPctBefore"], nm["usersErrorsDuring"], nm["usersRequestsDuring"], nm["usersErrorPctDuring"], nm["usersErrorPctAfter"] = rate(errB, reqB), errDur, reqDur, usersErr, afterErr
			r.note("users", fmt.Sprintf("errors before %.2f%%; from the restart to 30s after both Ready: %d of %d (%.1f%%); next 5 min %.2f%%", rate(errB, reqB), errDur, reqDur, usersErr, afterErr))
			if afterErr >= 1 {
				r.fail("users' error rate %.2f%% in the 5 minutes after recovery (want < 1%%)", afterErr)
			}
		}
	}
	r.scenario.Summary = fmt.Sprintf("both replicas deleted under 500 users: first replacement Ready +%.0fs, both +%.0fs; serving outage %.0fs; users' errors %.1f%% during, %.2f%% in the 5 minutes after; %d restarts",
		since(t0, firstReady), since(t0, bothReady), outage, usersErr, afterErr, restarts)
}
