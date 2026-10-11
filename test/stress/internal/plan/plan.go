package plan

import (
	"fmt"
	"math/rand/v2"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// Plan is everything gen creates for one level.
type Plan struct {
	Level      Level
	Nodes      []NodeSpec
	Cluster    []runtime.Object // cluster-scoped objects, in creation order
	Namespaces []*Namespace
	Stats      Stats
}

// Namespace is one namespace and its objects, in creation order.
type Namespace struct {
	Index   int // -1 for EKS add-on namespaces
	Object  *corev1.Namespace
	Objects []runtime.Object
	// Certs are cert-manager objects (Issuers, Certificates), created through
	// the dynamic client after the rest.
	Certs []*unstructured.Unstructured
	Pods  int // pods the namespace's workloads should run (incl. completed Job pods)
}

// Stats counts what the plan creates.
type Stats struct {
	Nodes               int            `json:"nodes"`
	NodesByPool         map[string]int `json:"nodesByPool"`
	ArmNodes            int            `json:"armNodes"`
	TeamNamespaces      int            `json:"teamNamespaces"`
	AddonNamespaces     int            `json:"addonNamespaces"`
	Deployments         int            `json:"deployments"`
	StatefulSets        int            `json:"statefulSets"`
	DaemonSets          int            `json:"daemonSets"`
	Jobs                int            `json:"jobs"`
	CronJobs            int            `json:"cronJobs"`
	BarePods            int            `json:"barePods"`
	Services            map[string]int `json:"services"`
	EndpointSlices      int            `json:"endpointSlices"`
	Ingresses           map[string]int `json:"ingresses"`
	PVCs                int            `json:"pvcs"`
	PVs                 int            `json:"pvs"`
	Roles               int            `json:"roles"`
	RoleBindings        int            `json:"roleBindings"`
	ClusterRoles        int            `json:"clusterRoles"`
	ClusterRoleBindings int            `json:"clusterRoleBindings"`
	Certificates        int            `json:"certificates"`
	Issuers             int            `json:"issuers"`
	// Pods the generated workloads run, plus the estimated DaemonSet and
	// tricky-case pods, i.e. the expected cluster-wide pod count.
	GeneratedPods     int `json:"generatedPods"`
	DaemonSetFakePods int `json:"daemonSetFakePods"`
	ExpectedPods      int `json:"expectedPods"`
}

// Teams name the team namespaces: namespace i is Teams[i%30] + "-" + (i/30+1).
var Teams = []string{
	"payments", "checkout", "search", "identity", "ledger", "catalog", "shipping", "pricing",
	"inventory", "fraud", "notify", "analytics", "billing", "reviews", "recommend", "media",
	"auth", "gateway", "orders", "loyalty", "support", "reporting", "risk", "onboarding",
	"messaging", "content", "partners", "tax", "returns", "warehouse",
}

var apps = []string{"api", "web", "worker", "consumer", "scheduler", "cache", "gateway", "sync", "indexer", "exporter", "frontend", "backend", "auth", "events"}

// AddonNamespaces are the EKS add-on namespaces the generator fills.
var AddonNamespaces = []string{"amazon-cloudwatch", "aws-observability", "karpenter", "amazon-guardduty"}

// NamespaceName is the name of team namespace i.
func NamespaceName(i int) string { return fmt.Sprintf("%s-%02d", Teams[i%len(Teams)], i/len(Teams)+1) }

// Build computes the plan for a level.
func Build(l Level) *Plan {
	p := &Plan{Level: l, Nodes: Nodes(l.Nodes)}
	p.Stats.Services = map[string]int{}
	p.Stats.Ingresses = map[string]int{}
	p.Stats.NodesByPool = map[string]int{}
	p.Stats.Nodes = len(p.Nodes)
	linux, windows := 0, 0
	for _, n := range p.Nodes {
		p.Stats.NodesByPool[n.Pool.Name]++
		if n.Instance.Arch == "arm64" {
			p.Stats.ArmNodes++
		}
		if n.Pool.OS == "windows" {
			windows++
		} else {
			linux++
		}
	}
	systemNodes := p.Stats.NodesByPool[PoolSystem]
	p.Stats.DaemonSetFakePods = DaemonSetsOnEveryNode*linux + windows

	p.Cluster = clusterObjects(l, &p.Stats)
	for _, name := range AddonNamespaces {
		ns := addonNamespace(name, systemNodes, &p.Stats)
		p.Namespaces = append(p.Namespaces, ns)
		p.Stats.GeneratedPods += ns.Pods
	}
	p.Stats.AddonNamespaces = len(AddonNamespaces)

	budget := l.Pods - p.Stats.DaemonSetFakePods - TrickyPodsEstimate - p.Stats.GeneratedPods
	for i := 0; ; i++ {
		ns := teamNamespace(i, systemNodes)
		if i > 0 && p.Stats.GeneratedPods+ns.Pods > budget+p.addonPods() {
			break
		}
		p.Namespaces = append(p.Namespaces, ns)
		p.Stats.GeneratedPods += ns.Pods
		p.Stats.TeamNamespaces++
		count(&p.Stats, ns)
		p.Cluster = append(p.Cluster, teamPVs(i)...)
	}
	for _, o := range p.Cluster {
		if _, ok := o.(*corev1.PersistentVolume); ok {
			p.Stats.PVs++
		}
	}
	p.Stats.ExpectedPods = p.Stats.GeneratedPods + p.Stats.DaemonSetFakePods + TrickyPodsEstimate
	return p
}

func (p *Plan) addonPods() int {
	n := 0
	for _, ns := range p.Namespaces {
		if ns.Index < 0 {
			n += ns.Pods
		}
	}
	return n
}

func count(s *Stats, ns *Namespace) {
	for _, o := range ns.Objects {
		switch v := o.(type) {
		case *appsv1.Deployment:
			s.Deployments++
		case *appsv1.StatefulSet:
			s.StatefulSets++
		case *appsv1.DaemonSet:
			s.DaemonSets++
		case *batchv1.Job:
			s.Jobs++
		case *batchv1.CronJob:
			s.CronJobs++
		case *corev1.Pod:
			s.BarePods++
		case *corev1.Service:
			s.Services[serviceKind(v)]++
		case *discoveryv1.EndpointSlice:
			s.EndpointSlices++
		case *networkingv1.Ingress:
			s.Ingresses[v.Annotations["kubesentry.io/stress-kind"]]++
		case *corev1.PersistentVolumeClaim:
			s.PVCs++
		case *rbacv1.Role:
			s.Roles++
		case *rbacv1.RoleBinding:
			s.RoleBindings++
		}
	}
	for _, c := range ns.Certs {
		switch c.GetKind() {
		case "Certificate":
			s.Certificates++
		case "Issuer":
			s.Issuers++
		}
	}
}

func serviceKind(s *corev1.Service) string {
	switch {
	case s.Spec.Type == corev1.ServiceTypeExternalName:
		return "ExternalName"
	case s.Spec.ClusterIP == corev1.ClusterIPNone:
		return "Headless"
	case s.Spec.Type == corev1.ServiceTypeLoadBalancer:
		return "LoadBalancer"
	case s.Spec.Type == corev1.ServiceTypeNodePort:
		return "NodePort"
	case len(s.Spec.Selector) == 0:
		return "SelectorLess"
	case s.Labels["kubesentry.io/stress-kind"] == "multi-workload":
		return "MultiWorkload"
	}
	return "ClusterIP"
}

func meta(ns, name string, kv ...string) metav1.ObjectMeta {
	m := map[string]string{"kubesentry.io/stress": "true"}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return metav1.ObjectMeta{Namespace: ns, Name: name, Labels: m}
}

func ptr[T any](v T) *T { return &v }

// podOpts shape a fake pod template.
type podOpts struct {
	team, app    string
	pool         string // nodegroup to pin to ("" for any general node)
	fargate      bool
	system       bool // tolerate CriticalAddonsOnly (ng-system)
	claim        string
	restartNever bool
	psa          string // the namespace's enforced Pod Security level
}

func fakeTemplate(r *rand.Rand, o podOpts, labels map[string]string) corev1.PodTemplateSpec {
	labels["kubesentry.io/stress"] = "true"
	sel := map[string]string{"type": "kwok"}
	tol := []corev1.Toleration{{Key: KwokTaint.Key, Operator: corev1.TolerationOpExists, Effect: corev1.TaintEffectNoSchedule}}
	if o.pool != "" {
		sel["eks.amazonaws.com/nodegroup"] = o.pool
	}
	if o.system {
		tol = append(tol, corev1.Toleration{Key: "CriticalAddonsOnly", Operator: corev1.TolerationOpExists})
	}
	if o.fargate {
		sel["eks.amazonaws.com/compute-type"] = "fargate"
		tol = append(tol, corev1.Toleration{Key: "eks.amazonaws.com/compute-type", Operator: corev1.TolerationOpEqual, Value: "fargate", Effect: corev1.TaintEffectNoSchedule})
	}
	cpu := []string{"25m", "50m", "100m", "250m"}[r.IntN(4)]
	mem := []string{"64Mi", "128Mi", "256Mi", "512Mi"}[r.IntN(4)]
	c := corev1.Container{
		Name:  o.app,
		Image: fmt.Sprintf("123456789012.dkr.ecr.us-east-1.amazonaws.com/%s/%s:1.%d.%d", o.team, o.app, r.IntN(20), r.IntN(10)),
		Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: 8080}},
		Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{
			corev1.ResourceCPU: resource.MustParse(cpu), corev1.ResourceMemory: resource.MustParse(mem),
		}},
	}
	if r.Float64() < 0.7 {
		q := resource.MustParse(mem)
		q.Add(q) // limit = 2x request
		c.Resources.Limits = corev1.ResourceList{corev1.ResourceMemory: q}
	}
	sc := &corev1.SecurityContext{}
	switch x := r.IntN(40); {
	case x == 0:
		sc.Privileged = ptr(true)
	case x == 1:
		sc.Capabilities = &corev1.Capabilities{Add: []corev1.Capability{"NET_ADMIN"}}
	case x < 15:
		sc.RunAsNonRoot = ptr(true)
		sc.RunAsUser = ptr(int64(10001))
		sc.AllowPrivilegeEscalation = ptr(false)
	case x < 25:
		sc.RunAsNonRoot = ptr(true)
	}
	switch o.psa {
	case "restricted":
		sc = restrictedSC()
	case "baseline":
		sc.Privileged, sc.Capabilities = nil, nil
	}
	c.SecurityContext = sc
	spec := corev1.PodSpec{
		NodeSelector: sel, Tolerations: tol,
		Containers:                    []corev1.Container{c},
		TerminationGracePeriodSeconds: ptr(int64(5)),
	}
	if r.Float64() < 0.25 {
		spec.Containers = append(spec.Containers, corev1.Container{
			Name: "envoy", Image: "public.ecr.aws/appmesh/aws-appmesh-envoy:v1.29.12.0-prod",
			Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{
				corev1.ResourceCPU: resource.MustParse("10m"), corev1.ResourceMemory: resource.MustParse("32Mi"),
			}},
		})
	}
	if r.Float64() < 0.4 {
		spec.AutomountServiceAccountToken = ptr(false)
	}
	if r.IntN(60) == 0 && o.psa == "" {
		spec.HostNetwork = true
	}
	if o.psa == "restricted" {
		for k := range spec.Containers {
			spec.Containers[k].SecurityContext = restrictedSC()
		}
	}
	if o.claim != "" {
		spec.Volumes = []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{
			PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: o.claim}}}}
		spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: "data", MountPath: "/data"}}
	}
	if o.restartNever {
		spec.RestartPolicy = corev1.RestartPolicyNever
	}
	return corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: labels}, Spec: spec}
}

func restrictedSC() *corev1.SecurityContext {
	return &corev1.SecurityContext{
		RunAsNonRoot: ptr(true), RunAsUser: ptr(int64(10001)), AllowPrivilegeEscalation: ptr(false),
		Capabilities:   &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
	}
}

var replicaChoices = []int32{1, 2, 2, 3, 3, 4, 4, 5, 6, 8, 10, 12}

func deployment(ns, name string, replicas int32, tpl corev1.PodTemplateSpec, kv ...string) *appsv1.Deployment {
	sel := map[string]string{"app": name}
	tpl.Labels["app"] = name
	return &appsv1.Deployment{
		TypeMeta:   metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"},
		ObjectMeta: meta(ns, name, append([]string{"app", name}, kv...)...),
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr(replicas), Selector: &metav1.LabelSelector{MatchLabels: sel}, Template: tpl,
			RevisionHistoryLimit: ptr(int32(2)),
		},
	}
}

// teamNamespace is namespace i: the same at every level.
func teamNamespace(i, systemNodes int) *Namespace {
	r := rand.New(rand.NewPCG(Seed, uint64(i)))
	name := NamespaceName(i)
	team := Teams[i%len(Teams)]
	nsLabels := []string{"kubesentry.io/team", team}
	switch i % 4 {
	case 0:
		nsLabels = append(nsLabels, "pod-security.kubernetes.io/enforce", "restricted")
	case 1:
		nsLabels = append(nsLabels, "pod-security.kubernetes.io/enforce", "baseline", "pod-security.kubernetes.io/warn", "restricted")
	case 2:
		nsLabels = append(nsLabels, "pod-security.kubernetes.io/enforce", "privileged")
	}
	ns := &Namespace{Index: i, Object: &corev1.Namespace{ObjectMeta: meta("", name, nsLabels...)}}
	add := func(o runtime.Object) { ns.Objects = append(ns.Objects, o) }
	psa := []string{"restricted", "baseline", "", ""}[i%4]
	mkTpl := func(o podOpts, labels map[string]string) corev1.PodTemplateSpec {
		o.psa = psa
		return fakeTemplate(r, o, labels)
	}

	add(&corev1.ServiceAccount{ObjectMeta: meta(name, "app")})
	add(&corev1.ServiceAccount{ObjectMeta: meta(name, "ci-deployer")})
	teamRBAC(i, name, team, r, add)

	// Deployments. Pod Security admission checks fake pods like real ones, so
	// templates in "restricted" and "baseline" namespaces comply (see fakeTemplate).
	nDeploy := 6 + r.IntN(5)
	var deploys []string
	var clusterIP []string
	for k := 0; k < nDeploy; k++ {
		app := apps[k%len(apps)]
		if k >= len(apps) {
			app = fmt.Sprintf("%s-%d", app, k/len(apps))
		}
		labels := map[string]string{"team": team}
		if i%4 == 1 && k < 2 {
			labels["tier"] = "backend"
		}
		tpl := mkTpl(podOpts{team: team, app: app}, labels)
		reps := replicaChoices[r.IntN(len(replicaChoices))]
		add(deployment(name, app, reps, tpl, "team", team))
		ns.Pods += int(reps)
		deploys = append(deploys, app)
		if r.Float64() < 0.6 {
			add(service(name, app, corev1.ServiceTypeClusterIP, map[string]string{"app": app}))
			clusterIP = append(clusterIP, app)
		}
	}
	if len(clusterIP) == 0 {
		add(service(name, deploys[0], corev1.ServiceTypeClusterIP, map[string]string{"app": deploys[0]}))
		clusterIP = append(clusterIP, deploys[0])
	}

	// StatefulSets with a headless Service each.
	for k := 0; k < 1+r.IntN(2); k++ {
		app := []string{"postgres", "redis", "kafka", "zookeeper"}[(i+k)%4]
		tpl := mkTpl(podOpts{team: team, app: app}, map[string]string{"app": app})
		add(&appsv1.StatefulSet{
			ObjectMeta: meta(name, app, "app", app),
			Spec: appsv1.StatefulSetSpec{
				Replicas: ptr(int32(3)), ServiceName: app + "-headless",
				Selector:            &metav1.LabelSelector{MatchLabels: map[string]string{"app": app}},
				Template:            tpl,
				PodManagementPolicy: appsv1.ParallelPodManagement,
			},
		})
		ns.Pods += 3
		h := service(name, app+"-headless", corev1.ServiceTypeClusterIP, map[string]string{"app": app})
		h.Spec.ClusterIP = corev1.ClusterIPNone
		add(h)
	}

	// Jobs (KWOK completes them) and a CronJob.
	for k := 0; k < 1+r.IntN(2); k++ {
		n := int32(1 + r.IntN(3))
		jname := fmt.Sprintf("migrate-%d", k)
		tpl := mkTpl(podOpts{team: team, app: "migrate", restartNever: true}, map[string]string{"job": jname})
		add(&batchv1.Job{
			ObjectMeta: meta(name, jname),
			Spec:       batchv1.JobSpec{Completions: ptr(n), Parallelism: ptr(n), BackoffLimit: ptr(int32(0)), Template: tpl},
		})
		ns.Pods += int(n)
	}
	{
		tpl := mkTpl(podOpts{team: team, app: "report", restartNever: true}, map[string]string{"cronjob": "nightly-report"})
		suspend := i%2 == 0
		add(&batchv1.CronJob{
			ObjectMeta: meta(name, "nightly-report"),
			Spec: batchv1.CronJobSpec{
				Schedule: "*/15 * * * *", Suspend: ptr(suspend), StartingDeadlineSeconds: ptr(int64(300)),
				SuccessfulJobsHistoryLimit: ptr(int32(1)), FailedJobsHistoryLimit: ptr(int32(1)),
				JobTemplate: batchv1.JobTemplateSpec{Spec: batchv1.JobSpec{BackoffLimit: ptr(int32(0)), Template: tpl}},
			},
		})
		if !suspend {
			ns.Pods++
		}
	}

	// A DaemonSet restricted to the system nodegroup in every 25th namespace.
	if i%25 == 3 {
		tpl := mkTpl(podOpts{team: team, app: "node-agent", pool: PoolSystem, system: true}, map[string]string{"app": "node-agent"})
		add(&appsv1.DaemonSet{
			ObjectMeta: meta(name, "node-agent", "app", "node-agent"),
			Spec:       appsv1.DaemonSetSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "node-agent"}}, Template: tpl},
		})
		ns.Pods += systemNodes
	}
	// Bare pods, as kubectl run leaves them.
	if i%3 == 0 {
		tpl := mkTpl(podOpts{team: team, app: "debug"}, map[string]string{"run": "debug-" + team})
		add(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: name, Name: "debug-" + team, Labels: tpl.Labels}, Spec: tpl.Spec})
		ns.Pods++
	}
	// Fargate profile workloads.
	if i%10 == 7 {
		tpl := mkTpl(podOpts{team: team, app: "fargate-batch", fargate: true}, map[string]string{})
		add(deployment(name, "fargate-batch", 2, tpl, "team", team))
		ns.Pods += 2
	}

	// Volumes: statically bound PVC/PV pairs, half mounted by a 1-replica db Deployment.
	for k, pv := range pvcPlan(i) {
		add(&corev1.PersistentVolumeClaim{
			ObjectMeta: meta(name, pv.claim, "kubesentry.io/stress-case", pv.kind),
			Spec: corev1.PersistentVolumeClaimSpec{
				AccessModes:      []corev1.PersistentVolumeAccessMode{pv.mode},
				StorageClassName: ptr(pv.class), VolumeName: pv.pvName,
				Resources: corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: resource.MustParse(pv.size)}},
			},
		})
		if pv.used {
			app := fmt.Sprintf("db-%d", k)
			tpl := mkTpl(podOpts{team: team, app: app, claim: pv.claim}, map[string]string{})
			if pv.zone != "" {
				tpl.Spec.NodeSelector["topology.kubernetes.io/zone"] = pv.zone
			}
			d := deployment(name, app, 1, tpl, "team", team)
			d.Spec.Strategy = appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType}
			add(d)
			ns.Pods++
		}
	}

	// Services of the remaining types.
	if i%4 == 0 {
		add(service(name, deploys[0]+"-np", corev1.ServiceTypeNodePort, map[string]string{"app": deploys[0]}))
	}
	if i%3 == 0 {
		lb := service(name, deploys[min(1, len(deploys)-1)]+"-lb", corev1.ServiceTypeLoadBalancer, map[string]string{"app": deploys[min(1, len(deploys)-1)]})
		// A loadBalancerClass keeps any in-cluster LB controller (such as
		// cloud-provider-kind) away, as the AWS Load Balancer Controller would.
		lb.Spec.LoadBalancerClass = ptr("service.k8s.aws/nlb")
		scheme := "internal"
		if i%2 == 1 {
			scheme = "internet-facing"
		}
		lb.Annotations = map[string]string{
			"service.beta.kubernetes.io/aws-load-balancer-scheme":          scheme,
			"service.beta.kubernetes.io/aws-load-balancer-type":            "external",
			"service.beta.kubernetes.io/aws-load-balancer-nlb-target-type": "ip",
		}
		add(lb)
	}
	if i%5 == 0 {
		en := &corev1.Service{ObjectMeta: meta(name, "rds-primary"), Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeExternalName, ExternalName: team + ".cluster-c0ffee.us-east-1.rds.amazonaws.com"}}
		add(en)
	}
	if i%5 == 1 {
		sl := &corev1.Service{ObjectMeta: meta(name, "legacy-db"), Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{{Name: "pg", Port: 5432, TargetPort: intstr.FromInt32(5432)}}}}
		add(sl)
		add(&discoveryv1.EndpointSlice{
			ObjectMeta: meta(name, "legacy-db-manual", "kubernetes.io/service-name", "legacy-db",
				"endpointslice.kubernetes.io/managed-by", "stress.kubesentry.io"),
			AddressType: discoveryv1.AddressTypeIPv4,
			Endpoints: []discoveryv1.Endpoint{
				{Addresses: []string{fmt.Sprintf("10.20.%d.10", i%250)}, Conditions: discoveryv1.EndpointConditions{Ready: ptr(true)}},
				{Addresses: []string{fmt.Sprintf("10.20.%d.11", i%250)}, Conditions: discoveryv1.EndpointConditions{Ready: ptr(true)}},
			},
			Ports: []discoveryv1.EndpointPort{{Name: ptr("pg"), Port: ptr(int32(5432)), Protocol: ptr(corev1.ProtocolTCP)}},
		})
	}
	if i%4 == 1 {
		mw := service(name, "backend", corev1.ServiceTypeClusterIP, map[string]string{"tier": "backend"})
		mw.Labels["kubesentry.io/stress-kind"] = "multi-workload"
		add(mw)
	}

	// Ingresses: ALB with an ACM certificate, internal ALB without TLS, nginx with spec.tls, none.
	nIng := 1
	if i%3 == 0 {
		nIng++
	}
	if i%5 == 0 {
		nIng++
	}
	for j := 0; j < nIng; j++ {
		backend := clusterIP[(i+j)%len(clusterIP)]
		if (i*7+j)%20 == 0 {
			backend = "missing-svc"
		}
		add(ingress(name, team, fmt.Sprintf("ing-%d", j), backend, (i+j)%4))
	}

	// cert-manager: a Certificate per namespace from the demo CA, a few local
	// Issuers, and some Certificates pointing at an issuer that does not exist.
	issuerKind, issuerName := "ClusterIssuer", "demo-ca"
	if i%10 == 5 {
		ns.Certs = append(ns.Certs, issuer(name, "selfsigned-local"))
		issuerKind, issuerName = "Issuer", "selfsigned-local"
	}
	nCert := 1
	if i%3 == 0 {
		nCert++
	}
	for j := 0; j < nCert; j++ {
		ik, in := issuerKind, issuerName
		if i%20 == 9 && j == 0 {
			ik, in = "Issuer", "missing-issuer"
		}
		dur := []string{"2160h", "720h", "240h", "48h", "2h"}[(i+j)%5]
		ns.Certs = append(ns.Certs, certificate(name, fmt.Sprintf("%s-tls-%d", clusterIP[j%len(clusterIP)], j), dur, ik, in))
	}
	return ns
}

func service(ns, name string, t corev1.ServiceType, sel map[string]string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: meta(ns, name),
		Spec: corev1.ServiceSpec{
			Type: t, Selector: sel,
			Ports: []corev1.ServicePort{{Name: "http", Port: 80, TargetPort: intstr.FromString("http")}},
		},
	}
}

var ingressKinds = []string{"alb-tls", "alb-internal", "nginx-tls", "none"}

func ingress(ns, team, name, backend string, kind int) *networkingv1.Ingress {
	host := fmt.Sprintf("%s.%s.%s.example.com", name, backend, team)
	ing := &networkingv1.Ingress{
		ObjectMeta: meta(ns, name),
		Spec: networkingv1.IngressSpec{Rules: []networkingv1.IngressRule{{
			Host: host,
			IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{Paths: []networkingv1.HTTPIngressPath{{
				Path: "/", PathType: ptr(networkingv1.PathTypePrefix),
				Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: backend, Port: networkingv1.ServiceBackendPort{Number: 80}}},
			}}}},
		}}},
	}
	ing.Annotations = map[string]string{"kubesentry.io/stress-kind": ingressKinds[kind]}
	switch ingressKinds[kind] {
	case "alb-tls":
		ing.Spec.IngressClassName = ptr("alb")
		ing.Annotations["alb.ingress.kubernetes.io/scheme"] = "internet-facing"
		ing.Annotations["alb.ingress.kubernetes.io/listen-ports"] = `[{"HTTPS":443}]`
		ing.Annotations["alb.ingress.kubernetes.io/certificate-arn"] = "arn:aws:acm:us-east-1:123456789012:certificate/" + hexOf(uint64(len(host))*31+uint64(kind), 8) + "-1111-2222-3333-" + hexOf(uint64(len(ns)), 12)
	case "alb-internal":
		ing.Spec.IngressClassName = ptr("alb")
		ing.Annotations["alb.ingress.kubernetes.io/scheme"] = "internal"
	case "nginx-tls":
		ing.Spec.IngressClassName = ptr("nginx")
		ing.Spec.TLS = []networkingv1.IngressTLS{{Hosts: []string{host}, SecretName: name + "-tls"}}
	}
	return ing
}

func issuer(ns, name string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "cert-manager.io/v1", "kind": "Issuer",
		"metadata": map[string]any{"namespace": ns, "name": name, "labels": map[string]any{"kubesentry.io/stress": "true"}},
		"spec":     map[string]any{"selfSigned": map[string]any{}},
	}}
	return u
}

func certificate(ns, name, duration, issuerKind, issuerName string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "cert-manager.io/v1", "kind": "Certificate",
		"metadata": map[string]any{"namespace": ns, "name": name, "labels": map[string]any{"kubesentry.io/stress": "true"}},
		"spec": map[string]any{
			"secretName": name,
			"dnsNames":   []any{name + "." + ns + ".example.test"},
			"duration":   duration,
			"privateKey": map[string]any{"algorithm": "ECDSA", "size": int64(256)},
			"issuerRef":  map[string]any{"kind": issuerKind, "name": issuerName},
		},
	}}
}

// teamRBAC adds about 10 Roles and 20 RoleBindings.
func teamRBAC(i int, ns, team string, r *rand.Rand, add func(runtime.Object)) {
	roles := []*rbacv1.Role{
		{ObjectMeta: meta(ns, "developer"), Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{"", "apps"}, Resources: []string{"pods", "pods/log", "deployments", "services", "configmaps"}, Verbs: []string{"get", "list", "watch"}}}},
		{ObjectMeta: meta(ns, "deployer"), Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{"apps", ""}, Resources: []string{"deployments", "services", "configmaps"}, Verbs: []string{"create", "update", "patch", "delete"}}}},
	}
	if i%3 == 0 {
		roles = append(roles, &rbacv1.Role{ObjectMeta: meta(ns, "secret-reader"), Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get", "list"}}}})
	}
	if i%7 == 0 {
		roles = append(roles, &rbacv1.Role{ObjectMeta: meta(ns, "ns-admin-wild"), Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}}})
	}
	resources := []string{"pods", "services", "configmaps", "jobs", "cronjobs", "ingresses", "events", "endpoints", "persistentvolumeclaims", "statefulsets"}
	verbs := [][]string{{"get"}, {"get", "list"}, {"get", "list", "watch"}, {"create", "delete"}, {"patch", "update"}}
	for k := len(roles); k < 10; k++ {
		roles = append(roles, &rbacv1.Role{ObjectMeta: meta(ns, fmt.Sprintf("role-%d", k)), Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{"", "apps", "batch", "networking.k8s.io"}, Resources: []string{resources[r.IntN(len(resources))], resources[r.IntN(len(resources))]}, Verbs: verbs[r.IntN(len(verbs))]}}})
	}
	for k, role := range roles {
		add(role)
		subjects := [][]rbacv1.Subject{
			{{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: team + ":developers"}},
			{{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: fmt.Sprintf("%s.%d@corp.example", team, (i+k)%17)}},
			{{Kind: rbacv1.ServiceAccountKind, Name: "ci-deployer", Namespace: ns}},
			{{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: "oidc:" + team + "-oncall"}, {Kind: rbacv1.ServiceAccountKind, Name: "app", Namespace: ns}},
		}
		for b := 0; b < 2; b++ {
			add(&rbacv1.RoleBinding{
				ObjectMeta: meta(ns, fmt.Sprintf("%s-%d", role.Name, b)),
				RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: role.Name},
				Subjects:   subjects[(k+b)%len(subjects)],
			})
		}
	}
}

// pvcSpec is one statically bound claim and its volume.
type pvcSpec struct {
	claim, pvName, class, size, kind, zone string
	mode                                   corev1.PersistentVolumeAccessMode
	used                                   bool
}

func pvcPlan(i int) []pvcSpec {
	r := rand.New(rand.NewPCG(Seed^0xd15c, uint64(i)))
	ns := NamespaceName(i)
	n := 5 + r.IntN(4)
	out := make([]pvcSpec, 0, n)
	for k := 0; k < n; k++ {
		s := pvcSpec{claim: fmt.Sprintf("data-%d", k), pvName: fmt.Sprintf("pv-%s-%d", ns, k), mode: corev1.ReadWriteOnce}
		switch x := r.Float64(); {
		case x < 0.5:
			s.class = "gp3"
		case x < 0.65:
			s.class = "io2"
		case x < 0.85:
			s.class, s.mode = "efs", corev1.ReadWriteMany
		default:
			s.class = "gp2"
		}
		if s.class == "efs" {
			s.size = "5Gi"
		} else {
			s.size = fmt.Sprintf("%dGi", []int{10, 20, 50, 100, 200, 500}[r.IntN(6)])
			s.zone = Zones[(i+k)%len(Zones)]
		}
		s.used = r.Float64() < 0.5
		s.kind = "unused"
		if s.used {
			s.kind = "used"
		}
		if s.class == "efs" {
			s.kind = "efs-" + s.kind
		}
		out = append(out, s)
	}
	return out
}

// teamPVs are the PersistentVolumes behind namespace i's claims, plus a
// Released volume (its claim is gone) in every other namespace.
func teamPVs(i int) []runtime.Object {
	ns := NamespaceName(i)
	var out []runtime.Object
	for _, s := range pvcPlan(i) {
		pv := &corev1.PersistentVolume{
			ObjectMeta: meta("", s.pvName, "kubesentry.io/stress-case", s.kind),
			Spec: corev1.PersistentVolumeSpec{
				Capacity:                      corev1.ResourceList{corev1.ResourceStorage: resource.MustParse(s.size)},
				AccessModes:                   []corev1.PersistentVolumeAccessMode{s.mode},
				PersistentVolumeReclaimPolicy: corev1.PersistentVolumeReclaimDelete,
				StorageClassName:              s.class,
				ClaimRef:                      &corev1.ObjectReference{Kind: "PersistentVolumeClaim", APIVersion: "v1", Namespace: ns, Name: s.claim},
				PersistentVolumeSource:        csiSource(s.class, s.pvName),
			},
		}
		if s.class == "io2" || s.class == "gp2" {
			pv.Spec.PersistentVolumeReclaimPolicy = corev1.PersistentVolumeReclaimRetain
		}
		if s.zone != "" {
			pv.Spec.NodeAffinity = zoneAffinity(s.zone)
		}
		out = append(out, pv)
	}
	if i%2 == 0 {
		name := "pv-" + ns + "-released"
		out = append(out, &corev1.PersistentVolume{
			ObjectMeta: meta("", name, "kubesentry.io/stress-case", "released"),
			Spec: corev1.PersistentVolumeSpec{
				Capacity:                      corev1.ResourceList{corev1.ResourceStorage: resource.MustParse("100Gi")},
				AccessModes:                   []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
				PersistentVolumeReclaimPolicy: corev1.PersistentVolumeReclaimRetain,
				StorageClassName:              "gp3",
				// A claimRef with a UID whose claim does not exist: the PV
				// controller marks the volume Released.
				ClaimRef: &corev1.ObjectReference{Kind: "PersistentVolumeClaim", APIVersion: "v1", Namespace: ns, Name: "old-data",
					UID: types.UID("00000000-0000-4000-8000-" + hexOf(uint64(i)+77, 12))},
				PersistentVolumeSource: csiSource("gp3", name),
				NodeAffinity:           zoneAffinity(Zones[i%len(Zones)]),
			},
		})
	}
	return out
}

func csiSource(class, name string) corev1.PersistentVolumeSource {
	if class == "efs" {
		return corev1.PersistentVolumeSource{CSI: &corev1.CSIPersistentVolumeSource{
			Driver: "efs.csi.aws.com", VolumeHandle: "fs-" + hexOf(uint64(len(name)), 8) + "::fsap-" + hexOf(hash(name), 17)}}
	}
	return corev1.PersistentVolumeSource{CSI: &corev1.CSIPersistentVolumeSource{
		Driver: "ebs.csi.aws.com", VolumeHandle: "vol-0" + hexOf(hash(name), 16), FSType: "ext4"}}
}

func zoneAffinity(zone string) *corev1.VolumeNodeAffinity {
	return &corev1.VolumeNodeAffinity{Required: &corev1.NodeSelector{NodeSelectorTerms: []corev1.NodeSelectorTerm{{
		MatchExpressions: []corev1.NodeSelectorRequirement{{Key: "topology.kubernetes.io/zone", Operator: corev1.NodeSelectorOpIn, Values: []string{zone}}},
	}}}}
}

func hash(s string) uint64 {
	var h uint64 = 1469598103934665603
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}

// addonNamespace fills an EKS add-on namespace. Its DaemonSets are pinned to
// the system nodegroup so they do not multiply with the node count.
func addonNamespace(name string, systemNodes int, s *Stats) *Namespace {
	r := rand.New(rand.NewPCG(Seed, hash(name)))
	ns := &Namespace{Index: -1, Object: &corev1.Namespace{ObjectMeta: meta("", name, "kubesentry.io/addon", "true")}}
	add := func(o runtime.Object) { ns.Objects = append(ns.Objects, o) }
	ds := func(app string) {
		tpl := fakeTemplate(r, podOpts{team: "eks", app: app, pool: PoolSystem, system: true}, map[string]string{"app": app})
		tpl.Spec.HostNetwork = app == "cloudwatch-agent"
		add(&appsv1.DaemonSet{ObjectMeta: meta(name, app, "app", app),
			Spec: appsv1.DaemonSetSpec{Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": app}}, Template: tpl}})
		ns.Pods += systemNodes
		s.DaemonSets++
	}
	dep := func(app string, reps int32) {
		tpl := fakeTemplate(r, podOpts{team: "eks", app: app, pool: PoolSystem, system: true}, map[string]string{})
		add(deployment(name, app, reps, tpl))
		add(service(name, app, corev1.ServiceTypeClusterIP, map[string]string{"app": app}))
		ns.Pods += int(reps)
		s.Deployments++
		s.Services["ClusterIP"]++
	}
	add(&corev1.ServiceAccount{ObjectMeta: meta(name, name)})
	switch name {
	case "amazon-cloudwatch":
		ds("cloudwatch-agent")
		ds("fluent-bit")
		dep("amazon-cloudwatch-observability-controller-manager", 1)
	case "aws-observability":
		add(&corev1.ConfigMap{ObjectMeta: meta(name, "aws-logging"), Data: map[string]string{
			"output.conf": "[OUTPUT]\n    Name cloudwatch_logs\n    region us-east-1\n"}})
		dep("adot-collector", 1)
	case "karpenter":
		dep("karpenter", 2)
	case "amazon-guardduty":
		ds("aws-guardduty-agent")
	}
	return ns
}

// clusterObjects are the cluster-scoped objects: storage classes, CSI drivers,
// ingress classes, cluster RBAC (including eks: look-alikes) and aws-auth.
func clusterObjects(l Level, s *Stats) []runtime.Object {
	var out []runtime.Object
	add := func(o runtime.Object) { out = append(out, o) }
	wffc := storagev1.VolumeBindingWaitForFirstConsumer
	imm := storagev1.VolumeBindingImmediate
	del := corev1.PersistentVolumeReclaimDelete
	add(&storagev1.StorageClass{ObjectMeta: meta("", "gp3"), Provisioner: "ebs.csi.aws.com", ReclaimPolicy: &del, VolumeBindingMode: &wffc,
		AllowVolumeExpansion: ptr(true), Parameters: map[string]string{"type": "gp3", "encrypted": "true"}})
	add(&storagev1.StorageClass{ObjectMeta: meta("", "io2"), Provisioner: "ebs.csi.aws.com", ReclaimPolicy: &del, VolumeBindingMode: &wffc,
		Parameters: map[string]string{"type": "io2", "iopsPerGB": "50"}})
	add(&storagev1.StorageClass{ObjectMeta: meta("", "gp2"), Provisioner: "kubernetes.io/aws-ebs", ReclaimPolicy: &del, VolumeBindingMode: &wffc,
		Parameters: map[string]string{"type": "gp2", "fsType": "ext4"}})
	add(&storagev1.StorageClass{ObjectMeta: meta("", "efs"), Provisioner: "efs.csi.aws.com", ReclaimPolicy: &del, VolumeBindingMode: &imm,
		Parameters: map[string]string{"provisioningMode": "efs-ap", "fileSystemId": "fs-0123456789abcdef0", "directoryPerms": "700"}})
	for _, d := range []string{"ebs.csi.aws.com", "efs.csi.aws.com"} {
		// attachRequired=false stops the attach/detach controller from creating
		// VolumeAttachments that no attacher would ever complete.
		add(&storagev1.CSIDriver{ObjectMeta: meta("", d), Spec: storagev1.CSIDriverSpec{AttachRequired: ptr(false)}})
	}
	for _, c := range []struct{ name, ctrl string }{{"alb", "ingress.k8s.aws/alb"}, {"nginx", "k8s.io/ingress-nginx"}} {
		add(&networkingv1.IngressClass{ObjectMeta: meta("", c.name), Spec: networkingv1.IngressClassSpec{Controller: c.ctrl}})
	}

	nCR := 10 * (l.Index + 1)
	if l.Index == 0 {
		nCR = 5
	}
	readers := []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"nodes", "namespaces", "pods"}, Verbs: []string{"get", "list", "watch"}}}
	for k := 0; k < nCR; k++ {
		rules := readers
		name := fmt.Sprintf("stress-reader-%d", k)
		switch k % 7 {
		case 0:
			name = fmt.Sprintf("stress-wild-%d", k)
			rules = []rbacv1.PolicyRule{{APIGroups: []string{"apps", "batch"}, Resources: []string{"*"}, Verbs: []string{"*"}}}
		case 1:
			name = fmt.Sprintf("stress-secrets-%d", k)
			rules = []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get", "list", "watch"}}}
		}
		add(&rbacv1.ClusterRole{ObjectMeta: meta("", name), Rules: rules})
		s.ClusterRoles++
		for b := 0; b < 2; b++ {
			var sub rbacv1.Subject
			switch (k + b) % 3 {
			case 0:
				sub = rbacv1.Subject{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: fmt.Sprintf("platform:group-%d", k)}
			case 1:
				sub = rbacv1.Subject{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: fmt.Sprintf("sre%d@corp.example", k)}
			default:
				sub = rbacv1.Subject{Kind: rbacv1.ServiceAccountKind, Name: "app", Namespace: NamespaceName(k % 30)}
			}
			add(&rbacv1.ClusterRoleBinding{ObjectMeta: meta("", fmt.Sprintf("%s-%d", name, b)),
				RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: name}, Subjects: []rbacv1.Subject{sub}})
			s.ClusterRoleBindings++
		}
	}
	crb := func(name, role string, subs ...rbacv1.Subject) {
		add(&rbacv1.ClusterRoleBinding{ObjectMeta: meta("", name), RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: role}, Subjects: subs})
		s.ClusterRoleBindings++
	}
	cr := func(name string, rules ...rbacv1.PolicyRule) {
		add(&rbacv1.ClusterRole{ObjectMeta: meta("", name), Rules: rules})
		s.ClusterRoles++
	}
	user := func(n string) rbacv1.Subject {
		return rbacv1.Subject{Kind: rbacv1.UserKind, APIGroup: rbacv1.GroupName, Name: n}
	}
	group := func(n string) rbacv1.Subject {
		return rbacv1.Subject{Kind: rbacv1.GroupKind, APIGroup: rbacv1.GroupName, Name: n}
	}
	// Real people with cluster-admin.
	crb("platform-admins", "cluster-admin", group("platform:admins"))
	crb("breakglass-alice", "cluster-admin", user("alice@corp.example"))
	// EKS-managed bindings: built in on every EKS cluster, not findings.
	crb("eks:addon-cluster-admin", "cluster-admin", user("eks:addon-manager"))
	cr("eks:node-bootstrapper", rbacv1.PolicyRule{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"certificatesigningrequests/selfnodeclient"}, Verbs: []string{"create"}})
	crb("eks:node-bootstrapper", "eks:node-bootstrapper", group("system:bootstrappers"), group("system:nodes"))
	cr("eks:k8s-metrics", rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"nodes", "pods"}, Verbs: []string{"get", "list", "watch"}})
	crb("eks:k8s-metrics", "eks:k8s-metrics", user("eks:k8s-metrics"))
	cr("eks:fargate-manager", rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"pods", "nodes"}, Verbs: []string{"*"}})
	crb("eks:fargate-manager", "eks:fargate-manager", user("eks:fargate-manager"))
	cr("eks:cloud-controller-manager", rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"*"}, Verbs: []string{"get", "list", "watch", "update", "patch"}})
	crb("eks:cloud-controller-manager", "eks:cloud-controller-manager", user("eks:cloud-controller-manager"))
	cr("eks:certificate-controller", rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get", "list", "watch"}})
	crb("eks:certificate-controller", "eks:certificate-controller", user("eks:certificate-controller"))
	cr("eks:authenticator", rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get", "list", "watch"}})
	crb("eks:authenticator", "eks:authenticator", user("eks:authenticator"))
	crb("eks:kube-proxy-windows", "system:node-proxier", group("eks:kube-proxy-windows"))
	// An anonymous binding.
	cr("stress-health-reader", rbacv1.PolicyRule{NonResourceURLs: []string{"/healthz", "/version"}, Verbs: []string{"get"}})
	crb("stress-anonymous-health", "stress-health-reader", group("system:unauthenticated"))

	add(&corev1.ConfigMap{
		ObjectMeta: meta("kube-system", "aws-auth"),
		Data: map[string]string{
			"mapRoles": `- rolearn: arn:aws:iam::123456789012:role/eks-node-role
  username: system:node:{{EC2PrivateDNSName}}
  groups:
    - system:bootstrappers
    - system:nodes
- rolearn: arn:aws:iam::123456789012:role/platform-admin
  username: platform-admin:{{SessionName}}
  groups:
    - system:masters
- rolearn: arn:aws:iam::123456789012:role/developers
  username: dev:{{SessionName}}
  groups:
    - payments:developers
    - checkout:developers
`,
			"mapUsers": `- userarn: arn:aws:iam::123456789012:user/alice
  username: alice@corp.example
  groups:
    - system:masters
`,
		},
	})
	return out
}

// Objects flattens a namespace's objects for counting in tests.
func (n *Namespace) Names() []string {
	out := []string{"Namespace/" + n.Object.Name}
	for _, o := range n.Objects {
		m, err := metaOf(o)
		if err == nil {
			out = append(out, fmt.Sprintf("%T/%s/%s", o, m.GetNamespace(), m.GetName()))
		}
	}
	for _, c := range n.Certs {
		out = append(out, c.GetKind()+"/"+c.GetNamespace()+"/"+c.GetName())
	}
	return out
}

func metaOf(o runtime.Object) (metav1.Object, error) {
	if m, ok := o.(metav1.Object); ok {
		return m, nil
	}
	return nil, fmt.Errorf("%T has no metadata", o)
}
