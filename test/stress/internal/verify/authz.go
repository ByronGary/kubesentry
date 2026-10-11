package verify

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/ByronGary/kubesentry/test/stress/internal/ks"
	"github.com/ByronGary/kubesentry/test/stress/internal/out"
	"github.com/ByronGary/kubesentry/test/stress/internal/personas"
)

// capability mirrors kubesentry's auth capabilities (internal/auth/auth.go).
type capability struct {
	name       string
	verb       string
	group      string
	resource   string
	namespaced bool
}

var (
	capPods        = capability{"pods", "list", "", "pods", true}
	capProcesses   = capability{"processes", "get", "kubesentry.io", "processes", true}
	capAudit       = capability{"audit", "list", "kubesentry.io", "auditevents", true}
	capRBAC        = capability{"rbac", "list", "rbac.authorization.k8s.io", "rolebindings", true}
	clusterCaps    = []capability{{"nodes", "list", "", "nodes", false}, {"pvs", "list", "", "persistentvolumes", false}, {"storageClasses", "list", "storage.k8s.io", "storageclasses", false}, {"clusterRBAC", "list", "rbac.authorization.k8s.io", "clusterrolebindings", false}, {"clusterIssuers", "list", "cert-manager.io", "clusterissuers", false}, {"agents", "list", "kubesentry.io", "agents", false}, {"clusterAudit", "list", "kubesentry.io", "auditevents", false}}
	namespacedCaps = []capability{capPods, capProcesses, capAudit, capRBAC}
)

// Scope is the namespaces one capability covers.
type Scope struct {
	All bool            `json:"all"`
	NS  map[string]bool `json:"-"`
	N   int             `json:"namespaces"`
}

func (s Scope) has(ns string) bool { return s.All || s.NS[ns] }

// PersonaTruth is what RBAC lets a persona see, from SubjectAccessReviews.
type PersonaTruth struct {
	Scopes  map[string]Scope `json:"scopes"`
	Cluster map[string]bool  `json:"cluster"`
	SARs    int              `json:"subjectAccessReviews"`
}

// RouteCheck is one route as one persona.
type RouteCheck struct {
	Route    string   `json:"route"`
	Status   int      `json:"status"`
	Want     string   `json:"want,omitempty"` // expected status or shape
	Items    int      `json:"items"`
	Leaks    int      `json:"leaks"`
	Samples  []string `json:"leakSamples,omitempty"`
	Problems []string `json:"problems,omitempty"` // not leaks: wrong status, missing degradation
	Ms       float64  `json:"ms"`
}

// PersonaResult is every route checked as one persona.
type PersonaResult struct {
	Persona      personas.Persona `json:"persona"`
	Truth        PersonaTruth     `json:"truth"`
	Capabilities map[string]bool  `json:"capabilities"` // as /info reported
	Routes       []RouteCheck     `json:"routes"`
	Leaks        int              `json:"leaks"`
	Problems     int              `json:"problems"`
}

// AuthzResult is authz.json.
type AuthzResult struct {
	Started  time.Time         `json:"started"`
	Seconds  float64           `json:"seconds"`
	Personas []PersonaResult   `json:"personas"`
	Leaks    int               `json:"leaks"`
	Problems int               `json:"problems"`
	ByKind   map[string][2]int `json:"byKind"` // persona kind → [leaks, problems]
}

// AuthzOptions configure verify authz.
type AuthzOptions struct {
	Client  *ks.Client
	Mint    func(email string, groups []string) (ks.Identity, error)
	Sample  []personas.Persona
	Timeout time.Duration
}

type sarClient struct {
	cs kubernetes.Interface
	mu sync.Mutex
	n  int
}

func (c *sarClient) allowed(ctx context.Context, p personas.Persona, cp capability, ns string) (bool, error) {
	groups := append(append([]string{}, p.Groups...), "system:authenticated")
	sar := &authorizationv1.SubjectAccessReview{Spec: authorizationv1.SubjectAccessReviewSpec{
		User: p.Email, Groups: groups,
		ResourceAttributes: &authorizationv1.ResourceAttributes{Verb: cp.verb, Group: cp.group, Resource: cp.resource, Namespace: ns},
	}}
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
	r, err := c.cs.AuthorizationV1().SubjectAccessReviews().Create(ctx, sar, metav1.CreateOptions{})
	if err != nil {
		return false, err
	}
	return r.Status.Allowed, nil
}

func personaTruth(ctx context.Context, sc *sarClient, p personas.Persona, namespaces []string) (PersonaTruth, error) {
	t := PersonaTruth{Scopes: map[string]Scope{}, Cluster: map[string]bool{}}
	start := sc.n
	for _, cp := range clusterCaps {
		ok, err := sc.allowed(ctx, p, cp, "")
		if err != nil {
			return t, err
		}
		t.Cluster[cp.name] = ok
	}
	for _, cp := range namespacedCaps {
		all, err := sc.allowed(ctx, p, cp, "")
		if err != nil {
			return t, err
		}
		s := Scope{All: all, NS: map[string]bool{}}
		if !all {
			var mu sync.Mutex
			var wg sync.WaitGroup
			sem := make(chan struct{}, 16)
			var firstErr error
			for _, ns := range namespaces {
				wg.Add(1)
				sem <- struct{}{}
				go func() {
					defer wg.Done()
					defer func() { <-sem }()
					ok, err := sc.allowed(ctx, p, cp, ns)
					mu.Lock()
					defer mu.Unlock()
					if err != nil && firstErr == nil {
						firstErr = err
					}
					if ok {
						s.NS[ns] = true
					}
				}()
			}
			wg.Wait()
			if firstErr != nil {
				return t, firstErr
			}
		}
		s.N = len(s.NS)
		if s.All {
			s.N = len(namespaces)
		}
		t.Scopes[cp.name] = s
	}
	t.SARs = sc.n - start
	return t, nil
}

// Response shapes read only here.
type storagePage struct {
	Claims []struct {
		Namespace    string `json:"namespace"`
		Name         string `json:"name"`
		StorageClass string `json:"storageClass"`
	} `json:"claims"`
	Volumes []struct {
		Name   string `json:"name"`
		Claim  string `json:"claim"`
		Status string `json:"status"`
	} `json:"volumes"`
	Classes []struct {
		Name string `json:"name"`
	} `json:"classes"`
	Unused []struct {
		Namespace string `json:"namespace"`
	} `json:"unused"`
	Continue string `json:"continue,omitempty"`
}

func (p *storagePage) Next() string { return p.Continue }

type auditPage struct {
	Items []struct {
		AuditID   string `json:"auditID"`
		Namespace string `json:"namespace"`
		Resource  string `json:"resource"`
	} `json:"items"`
	Continue string `json:"continue,omitempty"`
}

func (p *auditPage) Next() string { return p.Continue }

type certsResp struct {
	Certificates []struct {
		Namespace  string `json:"namespace"`
		Name       string `json:"name"`
		IssuerKind string `json:"issuerKind"`
		IssuerName string `json:"issuerName"`
	} `json:"certificates"`
	Issuers []struct {
		Kind      string `json:"kind"`
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
	} `json:"issuers"`
	Requests []struct {
		Namespace string `json:"namespace"`
	} `json:"requests"`
}

type unusedResp struct {
	Items []struct {
		Namespace string `json:"namespace"`
	} `json:"items"`
}

type summaryResp struct {
	TotalEvents int            `json:"totalEvents"`
	ByTag       map[string]int `json:"byTag"`
	Users       []any          `json:"users"`
}

type oomResp struct {
	Events []struct {
		Namespace string `json:"namespace"`
	} `json:"events"`
	Leaks []struct {
		Namespace string `json:"namespace"`
	} `json:"leaks"`
}

// Authz runs verify authz: RBAC truth by SubjectAccessReview for each sampled
// persona, then every list route as that persona; any item from outside the
// persona's scope is a leak.
func Authz(ctx context.Context, cs kubernetes.Interface, o AuthzOptions) (*AuthzResult, error) {
	res := &AuthzResult{Started: time.Now().UTC(), ByKind: map[string][2]int{}}
	start := time.Now()
	nsl, err := cs.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	var namespaces []string
	for _, n := range nsl.Items {
		namespaces = append(namespaces, n.Name)
	}
	sort.Strings(namespaces)
	// Pods per node and per namespace, for the node view's degradation rules.
	// Like kubesentry's node view, finished pods count while they are recent
	// (-recent-pod, 24h).
	podsByNode := map[string]map[string]bool{} // node → namespaces of its pods
	opts := metav1.ListOptions{Limit: 2000}
	for {
		l, err := cs.CoreV1().Pods("").List(ctx, opts)
		if err != nil {
			return nil, err
		}
		for _, p := range l.Items {
			finished := p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed
			if p.Spec.NodeName == "" || finished && time.Since(p.CreationTimestamp.Time) > 24*time.Hour {
				continue
			}
			if podsByNode[p.Spec.NodeName] == nil {
				podsByNode[p.Spec.NodeName] = map[string]bool{}
			}
			podsByNode[p.Spec.NodeName][p.Namespace] = true
		}
		if l.Continue == "" {
			break
		}
		opts.Continue = l.Continue
	}
	sc := &sarClient{cs: cs}
	for _, p := range o.Sample {
		pr := PersonaResult{Persona: p}
		pr.Truth, err = personaTruth(ctx, sc, p, namespaces)
		if err != nil {
			return nil, fmt.Errorf("truth for %s: %w", p.Email, err)
		}
		id, err := o.Mint(p.Email, p.Groups)
		if err != nil {
			return nil, err
		}
		pr.Routes, pr.Capabilities = checkRoutes(ctx, o, id, pr.Truth, namespaces, podsByNode)
		for _, r := range pr.Routes {
			pr.Leaks += r.Leaks
			pr.Problems += len(r.Problems)
		}
		res.Leaks += pr.Leaks
		res.Problems += pr.Problems
		bk := res.ByKind[p.Kind]
		bk[0] += pr.Leaks
		bk[1] += pr.Problems
		res.ByKind[p.Kind] = bk
		out.Logf("authz: %-11s %-34s pods-ns %3d audit-ns %3d: %d leaks, %d problems (%d SARs)", p.Kind, p.Email,
			pr.Truth.Scopes["pods"].N, pr.Truth.Scopes["audit"].N, pr.Leaks, pr.Problems, pr.Truth.SARs)
		res.Personas = append(res.Personas, pr)
	}
	res.Seconds = time.Since(start).Seconds()
	return res, nil
}

func checkRoutes(ctx context.Context, o AuthzOptions, id ks.Identity, t PersonaTruth, namespaces []string, podsByNode map[string]map[string]bool) ([]RouteCheck, map[string]bool) {
	pods, audit, rbac := t.Scopes["pods"], t.Scopes["audit"], t.Scopes["rbac"]
	var out []RouteCheck
	cctx := func() (context.Context, context.CancelFunc) { return context.WithTimeout(ctx, o.Timeout) }
	leak := func(rc *RouteCheck, what string) {
		rc.Leaks++
		if len(rc.Samples) < 5 {
			rc.Samples = append(rc.Samples, what)
		}
	}
	nsCheck := func(rc *RouteCheck, s Scope, ns, what string) {
		rc.Items++
		if !s.has(ns) {
			leak(rc, what)
		}
	}
	get := func(route string, v any) RouteCheck {
		c, cancel := cctx()
		defer cancel()
		r, err := o.Client.GetJSON(c, id, route, v)
		rc := RouteCheck{Route: route, Status: r.Status, Ms: out2ms(r.Elapsed)}
		if err != nil && r.Status == http.StatusOK {
			rc.Problems = append(rc.Problems, err.Error())
		}
		if r.Err != nil {
			rc.Problems = append(rc.Problems, r.Err.Error())
		}
		return rc
	}
	anyNS := pods.All || len(pods.NS) > 0

	// /info capabilities against the truth.
	var info ks.InfoFull
	rc := get("/api/v1/info", &info)
	for k, want := range t.Cluster {
		if info.Capabilities[k] != want {
			if info.Capabilities[k] {
				leak(&rc, fmt.Sprintf("capability %s=true, RBAC says false", k))
			} else {
				rc.Problems = append(rc.Problems, fmt.Sprintf("capability %s=false, RBAC says true", k))
			}
		}
	}
	for k, s := range map[string]Scope{"audit": audit, "processes": t.Scopes["processes"]} {
		want := s.All || len(s.NS) > 0
		if info.Capabilities[k] != want {
			if info.Capabilities[k] {
				leak(&rc, fmt.Sprintf("capability %s=true, RBAC says false", k))
			} else {
				rc.Problems = append(rc.Problems, fmt.Sprintf("capability %s=false, RBAC says true", k))
			}
		}
	}
	if info.Namespaces != nil && !pods.All && *info.Namespaces != len(pods.NS) {
		rc.Problems = append(rc.Problems, fmt.Sprintf("info.namespaces %d, RBAC allows %d", *info.Namespaces, len(pods.NS)))
	}
	out = append(out, rc)

	// Paged namespaced lists.
	pagedRoute := func(route string, run func(context.Context, *RouteCheck) (int, error)) {
		c, cancel := cctx()
		defer cancel()
		t0 := time.Now()
		rc := RouteCheck{Route: route, Status: 200}
		if _, err := run(c, &rc); err != nil {
			rc.Status = 0
			rc.Problems = append(rc.Problems, err.Error())
		}
		rc.Ms = out2ms(time.Since(t0))
		out = append(out, rc)
	}
	pagedRoute("/api/v1/pods", func(c context.Context, rc *RouteCheck) (int, error) {
		n, _, _, err := ks.GetAll(c, o.Client, id, "/api/v1/pods", 1000, func(p *ks.PodsResponse) {
			for _, it := range p.Items {
				nsCheck(rc, pods, it.Namespace, "Pod "+it.Namespace+"/"+it.Name)
			}
		})
		return n, err
	})
	pagedRoute("/api/v1/workloads", func(c context.Context, rc *RouteCheck) (int, error) {
		n, _, _, err := ks.GetAll(c, o.Client, id, "/api/v1/workloads", 1000, func(p *ks.WorkloadsResponse) {
			for _, it := range p.Items {
				nsCheck(rc, pods, it.Namespace, it.Kind+" "+it.Namespace+"/"+it.Name)
			}
		})
		return n, err
	})
	pagedRoute("/api/v1/storage", func(c context.Context, rc *RouteCheck) (int, error) {
		visibleClasses := map[string]bool{}
		n, _, _, err := ks.GetAll(c, o.Client, id, "/api/v1/storage", 1000, func(p *storagePage) {
			for _, it := range p.Claims {
				nsCheck(rc, pods, it.Namespace, "PVC "+it.Namespace+"/"+it.Name)
				visibleClasses[it.StorageClass] = true
			}
			for _, it := range p.Unused {
				nsCheck(rc, pods, it.Namespace, "unused PVC in "+it.Namespace)
			}
			if !t.Cluster["pvs"] {
				for _, v := range p.Volumes {
					rc.Items++
					ns, _, _ := strings.Cut(v.Claim, "/")
					if v.Claim == "" || !pods.has(ns) {
						leak(rc, "PV "+v.Name+" (claim "+v.Claim+") without the pvs capability")
					}
				}
			}
			if !t.Cluster["storageClasses"] {
				for _, cl := range p.Classes {
					rc.Items++
					if !visibleClasses[cl.Name] {
						leak(rc, "StorageClass "+cl.Name+" unused by visible claims, without the storageClasses capability")
					}
				}
			}
		})
		return n, err
	})
	secCheck := func(rc *RouteCheck, f ks.SecurityFinding) {
		rc.Items++
		switch {
		case f.Namespace == "" && f.Category == "rbac":
			if !t.Cluster["clusterRBAC"] {
				leak(rc, "cluster RBAC finding "+f.ID)
			}
		case f.Namespace == "" && f.Category == "namespace":
			if !pods.has(f.Subject) {
				leak(rc, "namespace finding "+f.ID)
			}
		case f.Namespace == "":
			if !pods.All {
				leak(rc, "cluster-scoped finding "+f.ID)
			}
		case f.Category == "rbac":
			if !rbac.has(f.Namespace) {
				leak(rc, "RBAC finding without list rolebindings in "+f.Namespace+": "+f.ID)
			}
		default:
			if !pods.has(f.Namespace) {
				leak(rc, "finding "+f.ID)
			}
		}
	}
	pagedRoute("/api/v1/security", func(c context.Context, rc *RouteCheck) (int, error) {
		n, _, _, err := ks.GetAll(c, o.Client, id, "/api/v1/security", 1000, func(p *ks.SecurityResponse) {
			for _, f := range p.Findings {
				secCheck(rc, f)
			}
			for _, nsp := range p.Namespaces {
				nsCheck(rc, pods, nsp.Name, "namespace posture "+nsp.Name)
			}
		})
		return n, err
	})
	{
		var s ks.SecurityResponse
		rc := get("/api/v1/security?view=summary", &s)
		total := 0
		for _, f := range s.Findings {
			secCheck(&rc, f)
		}
		for _, v := range s.Counts {
			total += v
		}
		if !anyNS && total > 0 && !t.Cluster["clusterRBAC"] {
			leak(&rc, fmt.Sprintf("summary counts %v for a user who sees nothing", s.Counts))
		}
		out = append(out, rc)
	}
	// Map: the default, the persona's namespaces, and one it may not see.
	{
		var m ks.MapResponse
		rc := get("/api/v1/map", &m)
		if anyNS && rc.Status != 200 {
			rc.Problems = append(rc.Problems, fmt.Sprintf("HTTP %d", rc.Status))
		}
		if !anyNS && rc.Status != 404 && rc.Status != 200 {
			rc.Problems = append(rc.Problems, fmt.Sprintf("no namespaces: HTTP %d", rc.Status))
		}
		checkMap(&rc, &m, pods, leak, nsCheck)
		out = append(out, rc)
		var hidden string
		for _, ns := range namespaces {
			if !pods.has(ns) && strings.Contains(ns, "-0") {
				hidden = ns
				break
			}
		}
		if hidden != "" {
			var hm ks.MapResponse
			hrc := get("/api/v1/map?namespace="+url.QueryEscape(hidden), &hm)
			hrc.Want = "404"
			if hrc.Status == 200 {
				leak(&hrc, "map of hidden namespace "+hidden+" answered 200")
			}
			checkMap(&hrc, &hm, pods, leak, nsCheck)
			out = append(out, hrc)
		}
		n := 0
		for ns := range pods.NS {
			if n >= 2 {
				break
			}
			n++
			var vm ks.MapResponse
			vrc := get("/api/v1/map?namespace="+url.QueryEscape(ns), &vm)
			checkMap(&vrc, &vm, pods, leak, nsCheck)
			out = append(out, vrc)
		}
	}
	{
		var c certsResp
		rc := get("/api/v1/certificates", &c)
		used := map[string]bool{}
		for _, it := range c.Certificates {
			nsCheck(&rc, pods, it.Namespace, "Certificate "+it.Namespace+"/"+it.Name)
			used[it.IssuerKind+"/"+it.IssuerName] = true
		}
		for _, is := range c.Issuers {
			rc.Items++
			switch {
			case is.Kind == "ClusterIssuer" && !t.Cluster["clusterIssuers"] && !used["ClusterIssuer/"+is.Name]:
				leak(&rc, "ClusterIssuer "+is.Name+" unused by visible certificates")
			case is.Kind == "Issuer" && !pods.has(is.Namespace):
				leak(&rc, "Issuer "+is.Namespace+"/"+is.Name)
			}
		}
		for _, r := range c.Requests {
			nsCheck(&rc, pods, r.Namespace, "CertificateRequest in "+r.Namespace)
		}
		out = append(out, rc)
	}
	{
		var u unusedResp
		rc := get("/api/v1/pvcs/unused", &u)
		for _, it := range u.Items {
			nsCheck(&rc, pods, it.Namespace, "unused PVC in "+it.Namespace)
		}
		out = append(out, rc)
	}
	auditRoute := func(route string) {
		pagedRoute(route, func(c context.Context, rc *RouteCheck) (int, error) {
			n, _, _, err := ks.GetAll(c, o.Client, id, route, 1000, func(p *auditPage) {
				for _, e := range p.Items {
					rc.Items++
					if e.Namespace == "" {
						if !t.Cluster["clusterAudit"] {
							leak(rc, "cluster-scoped audit event "+e.AuditID+" ("+e.Resource+")")
						}
					} else if !audit.has(e.Namespace) {
						leak(rc, "audit event "+e.AuditID+" in "+e.Namespace)
					}
				}
				if rc.Items > 5000 {
					p.Continue = "" // enough to judge; stop paging
				}
			})
			return n, err
		})
	}
	auditRoute("/api/v1/audit/events?since=24h")
	auditRoute("/api/v1/audit/events?since=24h&includeReads=true&actors=user,serviceaccount,system")
	{
		var s summaryResp
		rc := get("/api/v1/audit/summary?since=24h", &s)
		if !audit.All && len(audit.NS) == 0 && !t.Cluster["clusterAudit"] {
			rc.Want = "empty"
			if s.TotalEvents > 0 || len(s.Users) > 0 {
				leak(&rc, fmt.Sprintf("audit summary with %d events for a user with no audit grant", s.TotalEvents))
			}
		}
		out = append(out, rc)
	}
	checkNodes := func(route string) {
		var n ks.NodesResponse
		rc := get(route, &n)
		for _, node := range n.Items {
			rc.Items++
			if !t.Cluster["nodes"] {
				visible := false
				for ns := range podsByNode[node.Name] {
					if pods.has(ns) {
						visible = true
						break
					}
				}
				if !visible {
					leak(&rc, "node "+node.Name+" runs none of the caller's pods, without the nodes capability")
				}
			}
			for _, p := range node.Pods {
				nsCheck(&rc, pods, p.Namespace, "pod "+p.Namespace+"/"+p.Name+" on "+node.Name)
			}
		}
		out = append(out, rc)
	}
	checkNodes("/api/v1/nodes")
	checkNodes("/api/v1/nodes?summary=true")
	{
		var oo oomResp
		rc := get("/api/v1/oom?window=24h", &oo)
		for _, e := range oo.Events {
			nsCheck(&rc, pods, e.Namespace, "OOM event in "+e.Namespace)
		}
		for _, l := range oo.Leaks {
			nsCheck(&rc, pods, l.Namespace, "leak in "+l.Namespace)
		}
		out = append(out, rc)
	}
	{
		var a []map[string]any
		rc := get("/api/v1/agents", &a)
		rc.Items = len(a)
		if t.Cluster["agents"] {
			rc.Want = "200"
			if rc.Status != 200 {
				rc.Problems = append(rc.Problems, fmt.Sprintf("HTTP %d with the agents capability", rc.Status))
			}
		} else {
			rc.Want = "403"
			if rc.Status == 200 {
				leak(&rc, fmt.Sprintf("agents list (%d) without the agents capability", len(a)))
			}
		}
		out = append(out, rc)
	}
	return out, info.Capabilities
}

func checkMap(rc *RouteCheck, m *ks.MapResponse, pods Scope, leak func(*RouteCheck, string), nsCheck func(*RouteCheck, Scope, string, string)) {
	for _, ns := range m.Namespaces {
		nsCheck(rc, pods, ns, "map namespace list: "+ns)
	}
	for _, st := range m.NamespaceStats {
		nsCheck(rc, pods, st.Name, "map namespaceStats: "+st.Name)
	}
	for _, n := range m.Graph.Nodes {
		if n.Namespace == "" {
			continue
		}
		nsCheck(rc, pods, n.Namespace, "map node "+n.ID)
	}
}

func out2ms(d time.Duration) float64 { return out.Ms(d) }

// Markdown renders authz.md.
func (r *AuthzResult) Markdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Authorization leaks (verify authz)\n\n%d personas checked in %.0fs: **%d leaks**, %d other problems.\n\n", len(r.Personas), r.Seconds, r.Leaks, r.Problems)
	fmt.Fprintf(&b, "Truth comes from SubjectAccessReviews as each persona (list pods per namespace for namespaced data; kubesentry.io auditevents/processes; list rolebindings for RBAC findings; cluster-wide nodes, persistentvolumes, storageclasses, clusterrolebindings, clusterissuers, agents, auditevents). Every list route is then paged through as that persona; any item outside its scope is a leak. \"Problems\" are not leaks (e.g. less shown than RBAC allows, or an unexpected status).\n\n")
	fmt.Fprintf(&b, "| Persona | Kind | pods ns | audit ns | rbac ns | cluster caps | leaks | problems |\n|---|---|---:|---:|---:|---|---:|---:|\n")
	for _, p := range r.Personas {
		var caps []string
		for k, v := range p.Truth.Cluster {
			if v {
				caps = append(caps, k)
			}
		}
		sort.Strings(caps)
		sc := func(n string) string {
			s := p.Truth.Scopes[n]
			if s.All {
				return "all"
			}
			return fmt.Sprint(s.N)
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %d | %d |\n", p.Persona.Email, p.Persona.Kind, sc("pods"), sc("audit"), sc("rbac"), strings.Join(caps, ","), p.Leaks, p.Problems)
	}
	fmt.Fprintf(&b, "\n## Routes with leaks or problems\n\n")
	any := false
	for _, p := range r.Personas {
		for _, rc := range p.Routes {
			if rc.Leaks == 0 && len(rc.Problems) == 0 {
				continue
			}
			any = true
			fmt.Fprintf(&b, "- %s (%s) %s: HTTP %d, %d items, %d leaks %v %v\n", p.Persona.Email, p.Persona.Kind, rc.Route, rc.Status, rc.Items, rc.Leaks, rc.Samples, rc.Problems)
		}
	}
	if !any {
		b.WriteString("None.\n")
	}
	fmt.Fprintf(&b, "\n## Items checked per route (all personas)\n\n| Route | items | leaks | median ms |\n|---|---:|---:|---:|\n")
	type agg struct {
		items, leaks int
		ms           []float64
	}
	m := map[string]*agg{}
	var keys []string
	for _, p := range r.Personas {
		for _, rc := range p.Routes {
			k := rc.Route
			if strings.HasPrefix(k, "/api/v1/map?namespace=") {
				k = "/api/v1/map?namespace=…"
			}
			if m[k] == nil {
				m[k] = &agg{}
				keys = append(keys, k)
			}
			m[k].items += rc.Items
			m[k].leaks += rc.Leaks
			m[k].ms = append(m[k].ms, rc.Ms)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		a := m[k]
		sort.Float64s(a.ms)
		fmt.Fprintf(&b, "| %s | %d | %d | %.0f |\n", k, a.items, a.leaks, a.ms[len(a.ms)/2])
	}
	return b.String()
}
