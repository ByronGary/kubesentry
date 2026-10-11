package detectors

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/ByronGary/kubesentry/internal/model"
)

// SecurityInput is everything AuditSecurity looks at. Pure data, so it is
// testable without a cluster.
type SecurityInput struct {
	Pods        []model.Pod
	Workloads   []model.Workload
	ReplicaSets []model.ReplicaSet // optional: resolves pods to Deployments
	Namespaces  []model.Namespace
	RBAC        model.RBAC
	Services    []model.Service
	Ingresses   []model.Ingress
	AWSAuth     *model.AWSAuth // nil when not read
}

// CheckAWSAuthMasters is crit: the EKS aws-auth ConfigMap maps an IAM role or
// user to system:masters, which bypasses RBAC and cannot be revoked by
// editing bindings.
const CheckAWSAuthMasters = "aws-auth-masters"

const (
	sevCrit = "crit"
	sevWarn = "warn"
	sevInfo = "info"
)

// reservedPrefix names Kubernetes' own bootstrap RBAC. Its bindings (for
// example the public-info grant to system:unauthenticated) are by design, so
// they are not judged at all; other built-in prefixes keep their findings,
// marked System.
const reservedPrefix = "system:"

// AuditSecurity runs the security checks with the default policy.
func AuditSecurity(in SecurityInput) ([]SecurityFinding, []NamespacePosture) {
	p := compatPolicy()
	inv := listInventory(model.Inventory{
		Pods: in.Pods, Workloads: in.Workloads, ReplicaSets: in.ReplicaSets, Namespaces: in.Namespaces,
		RBAC: in.RBAC, Services: in.Services, Ingresses: in.Ingresses, AWSAuth: in.AWSAuth,
	})
	return AuditSecurityWith(Associate(inv, p), p)
}

// AuditSecurityWith checks pod specs, RBAC (and the EKS aws-auth mappings),
// Pod Security labels and network exposure in a's inventory. Findings come
// most severe first, non-system before system, then by category and subject.
// Every namespace gets a posture row, sorted by name.
func AuditSecurityWith(a *Assoc, p Policy) ([]SecurityFinding, []NamespacePosture) {
	inv := a.Inventory()
	out := []SecurityFinding{}
	out = append(out, podFindings(a)...)
	out = append(out, rbacFindings(inv.RBAC, p, a.IsSystem)...)
	out = append(out, awsAuthFindings(inv.AWSAuth)...)
	nsFindings, posture := namespaceFindings(inv.Namespaces, a.IsSystem)
	out = append(out, nsFindings...)
	out = append(out, exposureFindings(inv.Services, inv.Ingresses, a.IsSystem)...)

	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		switch {
		case severityRank(a.Severity) != severityRank(b.Severity):
			return severityRank(a.Severity) < severityRank(b.Severity)
		case a.System != b.System:
			return !a.System
		case a.Category != b.Category:
			return a.Category < b.Category
		case a.Subject != b.Subject:
			return a.Subject < b.Subject
		}
		return a.ID < b.ID
	})
	return out, posture
}

func severityRank(s string) int {
	switch s {
	case sevCrit:
		return 0
	case sevWarn:
		return 1
	}
	return 2
}

func finding(category, check, sev, title, subjectKind, subject, ns, detail string, system bool) SecurityFinding {
	return SecurityFinding{
		ID: check + "/" + subjectKind + "/" + subject, Category: category, Check: check, Severity: sev, Title: title,
		Subject: subject, SubjectKind: subjectKind, Namespace: ns, Detail: detail, System: system,
	}
}

// podGroup is the pods of one workload, or a single pod nothing owns.
type podGroup struct {
	kind, ns, name string
	pods           []*model.Pod
}

// podFindings reports risky pod specs once per owner rather than per pod.
// Jobs that a CronJob created are reported under the CronJob; static and bare
// pods on their own.
func podFindings(a *Assoc) []SecurityFinding {
	pods := a.Inventory().Pods
	groups := map[refKey]*podGroup{}
	var order []refKey
	for i := range pods {
		p := &pods[i]
		kind, name := a.rootOf(p)
		key := refKey{kind, p.Namespace, name}
		g := groups[key]
		if g == nil {
			g = &podGroup{kind: kind, ns: p.Namespace, name: name}
			groups[key] = g
			order = append(order, key)
		}
		g.pods = append(g.pods, p)
	}

	var out []SecurityFinding
	for _, k := range order {
		g := groups[k]
		out = append(out, groupFindings(g, a.IsSystem(g.ns))...)
	}
	return out
}

func groupFindings(g *podGroup, system bool) []SecurityFinding {
	var privileged, rootish, escalation, noLimit, hostNS, hostPaths, accounts []string
	var capsCrit, capsWarn []string
	for _, p := range g.pods {
		if p.HostPID {
			hostNS = appendNew(hostNS, "hostPID")
		}
		if p.HostNetwork {
			hostNS = appendNew(hostNS, "hostNetwork")
		}
		if p.HostIPC {
			hostNS = appendNew(hostNS, "hostIPC")
		}
		for _, hp := range p.HostPaths {
			hostPaths = appendNew(hostPaths, hp)
		}
		if p.AutomountToken {
			sa := p.ServiceAccount
			if sa == "" {
				sa = "default"
			}
			accounts = appendNew(accounts, sa)
		}
		for _, c := range p.Specs {
			name := c.Name
			if c.Init {
				name += " (init)"
			}
			if c.Privileged {
				privileged = appendNew(privileged, name)
			}
			if !c.RunAsNonRoot && (c.RunAsUser == nil || *c.RunAsUser == 0) {
				rootish = appendNew(rootish, name)
			}
			if c.AllowPrivilegeEscalation == nil || *c.AllowPrivilegeEscalation {
				escalation = appendNew(escalation, name)
			}
			if c.MemoryLimitBytes == 0 {
				noLimit = appendNew(noLimit, name)
			}
			var dangerous, other []string
			for _, cp := range c.CapabilitiesAdd {
				cp = strings.TrimPrefix(strings.ToUpper(cp), "CAP_")
				switch cp {
				case "SYS_ADMIN", "ALL":
					dangerous = appendNew(dangerous, cp)
				case "NET_BIND_SERVICE":
				default:
					other = appendNew(other, cp)
				}
			}
			if len(dangerous)+len(other) > 0 {
				entry := name + " (" + list(slices.Concat(dangerous, other)) + ")"
				if len(dangerous) > 0 {
					capsCrit = appendNew(capsCrit, entry)
				} else {
					capsWarn = appendNew(capsWarn, entry)
				}
			}
		}
	}

	subject := g.ns + "/" + g.name
	var out []SecurityFinding
	add := func(check, sev, title, detail string) {
		out = append(out, finding("pod", check, sev, title, g.kind, subject, g.ns, detail, system))
	}
	if len(privileged) > 0 {
		add(CheckPrivileged, sevCrit, "Privileged container", "Runs privileged, with full access to the node: "+list(privileged)+".")
	}
	if len(hostNS) > 0 {
		add(CheckHostNamespaces, sevWarn, "Host namespaces", "Shares the node's namespaces: "+list(hostNS)+".")
	}
	if len(hostPaths) > 0 {
		add(CheckHostPath, sevWarn, "Host path volume", "Mounts directories from the node: "+list(hostPaths)+".")
	}
	if caps := slices.Concat(capsCrit, capsWarn); len(caps) > 0 {
		sev := sevWarn
		if len(capsCrit) > 0 {
			sev = sevCrit
		}
		add(CheckCapabilities, sev, "Added capabilities", "Adds Linux capabilities: "+list(caps)+".")
	}
	if len(rootish) > 0 {
		add(CheckRunAsRoot, sevWarn, "May run as root", "Nothing stops these containers running as root (runAsNonRoot unset, runAsUser unset or 0): "+list(rootish)+".")
	}
	if len(escalation) > 0 {
		add(CheckPrivilegeEscalation, sevInfo, "Privilege escalation allowed", "allowPrivilegeEscalation is not set to false: "+list(escalation)+".")
	}
	if len(noLimit) > 0 {
		add(CheckNoMemoryLimit, sevInfo, "No memory limit", "No memory limit, so one leak can starve the node: "+list(noLimit)+".")
	}
	if len(accounts) > 0 {
		add(CheckTokenAutomount, sevInfo, "API token mounted", "Mounts an API token for service account "+list(accounts)+"; most apps never call the Kubernetes API.")
	}
	return out
}

func appendNew(s []string, v string) []string {
	if slices.Contains(s, v) {
		return s
	}
	return append(s, v)
}

func list(s []string) string { return strings.Join(s, ", ") }

// systemSubject reports whether a binding subject is cluster plumbing: a user
// or group with a system principal prefix (system:, eks:), or a service
// account in a system namespace. The groups that stand for everyone, or every
// service account, are never plumbing.
func systemSubject(s model.Subject, p Policy, isSystem func(string) bool) bool {
	if s.Kind == "ServiceAccount" {
		return isSystem(s.Namespace)
	}
	if everyone[s.Name] {
		return false
	}
	if rest, ok := strings.CutPrefix(s.Name, "system:serviceaccount:"); ok {
		ns, _, _ := strings.Cut(rest, ":")
		return isSystem(ns)
	}
	if ns, ok := strings.CutPrefix(s.Name, "system:serviceaccounts:"); ok {
		return isSystem(ns)
	}
	return p.IsSystemPrincipal(s.Name)
}

func subjectLabel(s model.Subject) string {
	if s.Kind == "ServiceAccount" {
		return "ServiceAccount " + s.Namespace + "/" + s.Name
	}
	return s.Kind + " " + s.Name
}

func scopedName(ns, name string) string {
	if ns == "" {
		return name
	}
	return ns + "/" + name
}

func roleKey(kind, ns, name string) string { return kind + "/" + ns + "/" + name }

// rbacFindings flags cluster-admin and anonymous bindings, wildcard roles and
// who can read secrets. Bindings and roles named "system:..." are Kubernetes'
// own bootstrap policy and are not judged; those with another built-in prefix
// (eks:, kubeadm:) are judged but marked System.
func rbacFindings(r model.RBAC, pol Policy, isSystem func(string) bool) []SecurityFinding {
	roles := make(map[string]*model.Role, len(r.Roles))
	for i := range r.Roles {
		ro := &r.Roles[i]
		roles[roleKey(ro.Kind, ro.Namespace, ro.Name)] = ro
	}
	boundTo := map[string][]string{} // role key -> non-system subjects bound to it
	secrets := map[string]bool{}     // role key -> it can read secrets

	var out []SecurityFinding
	for _, b := range r.Bindings {
		subject := scopedName(b.Namespace, b.Name)
		reserved := strings.HasPrefix(b.Name, reservedPrefix)
		// Platform bindings such as kubeadm:cluster-admins (the admin
		// kubeconfig) or eks:... are real but expected: kept, marked plumbing.
		builtin := pol.IsBuiltinRBAC(b.Name)
		var people []string
		humans := false // a non-system User or Group, as opposed to only service accounts
		for _, s := range b.Subjects {
			if !systemSubject(s, pol, isSystem) {
				people = appendNew(people, subjectLabel(s))
				humans = humans || s.Kind != "ServiceAccount"
			}
		}
		scope := "cluster-wide"
		if b.Kind == "RoleBinding" {
			scope = "in namespace " + b.Namespace
		}

		admin := b.RoleKind == "ClusterRole" && b.RoleName == "cluster-admin" && len(people) > 0
		if admin {
			// Within one namespace it is that namespace's admin, which is serious but bounded.
			sev := sevCrit
			if b.Kind == "RoleBinding" {
				sev = sevWarn
			}
			out = append(out, finding("rbac", CheckClusterAdmin, sev, "cluster-admin granted", b.Kind, subject, b.Namespace,
				"Grants cluster-admin "+scope+" to "+list(people)+".", builtin))
		}

		if !reserved {
			var anon []string
			for _, s := range b.Subjects {
				if (s.Kind == "User" && s.Name == "system:anonymous") || (s.Kind == "Group" && s.Name == "system:unauthenticated") {
					anon = appendNew(anon, s.Name)
				}
			}
			if len(anon) > 0 {
				// kubeadm's own cluster-info binding lives in kube-public; such
				// bindings are plumbing, kept but hidden by default.
				system := builtin || isSystem(b.Namespace)
				out = append(out, finding("rbac", CheckAnonymous, sevCrit, "Anonymous access", b.Kind, subject, b.Namespace,
					fmt.Sprintf("Grants %s %s %s to %s, which includes requests with no credentials at all.", b.RoleKind, b.RoleName, scope, list(anon)), system))
			}
		}

		key := roleKey(b.RoleKind, "", b.RoleName)
		if b.RoleKind == "Role" {
			key = roleKey("Role", b.Namespace, b.RoleName)
		}
		role, found := roles[key]
		if !found || len(people) == 0 {
			continue
		}
		for _, p := range people {
			boundTo[key] = appendNew(boundTo[key], p)
		}
		reads, known := secrets[key]
		if !known {
			reads = readsSecrets(role.Rules)
			secrets[key] = reads
		}
		if !admin && !reserved && reads {
			// Controllers such as cert-manager or an operator need secrets to do
			// their job; people and groups reading them is the bigger risk.
			sev := sevInfo
			if humans {
				sev = sevWarn
			}
			out = append(out, finding("rbac", CheckSecretReaders, sev, "Can read secrets", b.Kind, subject, b.Namespace,
				fmt.Sprintf("%s can read secrets %s through %s %s.", list(people), scope, b.RoleKind, b.RoleName), builtin))
		}
	}

	for _, ro := range r.Roles {
		if strings.HasPrefix(ro.Name, reservedPrefix) || (ro.Kind == "ClusterRole" && (ro.Name == "cluster-admin" || ro.Name == "admin" || ro.Name == "edit")) {
			continue
		}
		people := boundTo[roleKey(ro.Kind, ro.Namespace, ro.Name)]
		if len(people) == 0 {
			continue
		}
		where := wildcards(ro.Rules)
		if where == "" {
			continue
		}
		out = append(out, finding("rbac", CheckWildcard, sevWarn, "Wildcard permissions", ro.Kind, scopedName(ro.Namespace, ro.Name), ro.Namespace,
			fmt.Sprintf("Uses \"*\" in %s, so it also grants anything added later; bound to %s.", where, list(people)), pol.IsBuiltinRBAC(ro.Name)))
	}
	return out
}

// awsAuthFindings flags aws-auth mappings into system:masters. Membership of
// that group bypasses RBAC, so no binding shows it.
func awsAuthFindings(aa *model.AWSAuth) []SecurityFinding {
	if aa == nil {
		return nil
	}
	var out []SecurityFinding
	add := func(kind, what string, m model.AWSAuthMapping) {
		if !slices.Contains(m.Groups, "system:masters") {
			return
		}
		user := m.Username
		if user == "" {
			user = "(none)"
		}
		out = append(out, finding("rbac", CheckAWSAuthMasters, sevCrit, "aws-auth maps to system:masters", kind, m.ARN, "",
			fmt.Sprintf("kube-system/aws-auth maps %s %s (username %s) to system:masters, which bypasses RBAC entirely; prefer an access entry or a bound ClusterRole.", what, m.ARN, user), false))
	}
	for _, m := range aa.MapRoles {
		add("IAMRole", "IAM role", m)
	}
	for _, m := range aa.MapUsers {
		add("IAMUser", "IAM user", m)
	}
	return out
}

// wildcards names the rule fields that contain "*", or "" when none do.
func wildcards(rules []model.PolicyRule) string {
	var verbs, resources bool
	for _, r := range rules {
		verbs = verbs || slices.Contains(r.Verbs, "*")
		resources = resources || slices.Contains(r.Resources, "*")
	}
	switch {
	case verbs && resources:
		return "verbs and resources"
	case verbs:
		return "verbs"
	case resources:
		return "resources"
	}
	return ""
}

// readsSecrets reports whether any rule allows get, list or watch on core secrets.
func readsSecrets(rules []model.PolicyRule) bool {
	for _, r := range rules {
		group := slices.Contains(r.APIGroups, "") || slices.Contains(r.APIGroups, "*")
		res := slices.Contains(r.Resources, "secrets") || slices.Contains(r.Resources, "*")
		verb := slices.ContainsFunc(r.Verbs, func(v string) bool { return v == "get" || v == "list" || v == "watch" || v == "*" })
		if group && res && verb {
			return true
		}
	}
	return false
}

const psaPrefix = "pod-security.kubernetes.io/"

// namespaceFindings reads each namespace's Pod Security Admission labels.
func namespaceFindings(nss []model.Namespace, isSystem func(string) bool) ([]SecurityFinding, []NamespacePosture) {
	var out []SecurityFinding
	posture := make([]NamespacePosture, 0, len(nss))
	for _, ns := range nss {
		p := NamespacePosture{
			Name: ns.Name, Enforce: ns.Labels[psaPrefix+"enforce"], Audit: ns.Labels[psaPrefix+"audit"],
			Warn: ns.Labels[psaPrefix+"warn"], System: isSystem(ns.Name), Status: StatusWarn,
		}
		switch p.Enforce {
		case "baseline", "restricted":
			p.Status = StatusOK
		case "":
			out = append(out, finding("namespace", CheckPSAMissing, sevWarn, "No Pod Security enforcement", "Namespace", ns.Name, ns.Name,
				"No pod-security.kubernetes.io/enforce label, so pods with any spec are admitted.", p.System))
		case "privileged":
			out = append(out, finding("namespace", CheckPSAPrivileged, sevWarn, "Pod Security set to privileged", "Namespace", ns.Name, ns.Name,
				"Enforces the privileged level, which admits pods with any spec.", p.System))
		}
		posture = append(posture, p)
	}
	sort.Slice(posture, func(i, j int) bool { return posture[i].Name < posture[j].Name })
	return out, posture
}

// AWS load balancer annotations kubesentry reads.
const (
	annLBScheme   = "service.beta.kubernetes.io/aws-load-balancer-scheme"
	annLBInternal = "service.beta.kubernetes.io/aws-load-balancer-internal"
	annLBType     = "service.beta.kubernetes.io/aws-load-balancer-type"
	annALBScheme  = "alb.ingress.kubernetes.io/scheme"
	annALBCert    = "alb.ingress.kubernetes.io/certificate-arn"
	annALBPorts   = "alb.ingress.kubernetes.io/listen-ports"
	annIngClass   = "kubernetes.io/ingress.class"
	albAnnPrefix  = "alb.ingress.kubernetes.io/"
	lbcNLBClass   = "service.k8s.aws/nlb"
)

// internalLB reports whether a LoadBalancer Service gets an internal load
// balancer. known is false when nothing says, and the in-tree default
// (internet-facing) applies.
func internalLB(s model.Service) (internal, known bool) {
	ann := s.Annotations
	if v := strings.TrimSpace(ann[annLBScheme]); v != "" {
		return strings.EqualFold(v, "internal"), true
	}
	if v, ok := ann[annLBInternal]; ok {
		// The legacy annotation made an internal ELB with any value but
		// "false"; old manifests often say "0.0.0.0/0".
		v = strings.TrimSpace(v)
		return v != "" && !strings.EqualFold(v, "false"), true
	}
	// The AWS Load Balancer Controller provisions internal NLBs unless the
	// scheme says otherwise.
	if s.LoadBalancerClass == lbcNLBClass {
		return true, true
	}
	switch strings.ToLower(ann[annLBType]) {
	case "external", "nlb-ip":
		return true, true
	}
	return false, false
}

// ingressTLS reports whether an Ingress terminates TLS: spec.tls, or an ALB
// certificate (certificate-arn, or an HTTPS listener).
func ingressTLS(ing model.Ingress) bool {
	return len(ing.TLS) > 0 ||
		strings.TrimSpace(ing.Annotations[annALBCert]) != "" ||
		strings.Contains(strings.ToUpper(ing.Annotations[annALBPorts]), "HTTPS")
}

// isALB reports whether the AWS Load Balancer Controller serves an Ingress.
func isALB(ing model.Ingress) bool {
	if ing.Class == "alb" || ing.Annotations[annIngClass] == "alb" {
		return true
	}
	for k := range ing.Annotations {
		if strings.HasPrefix(k, albAnnPrefix) {
			return true
		}
	}
	return false
}

// exposureFindings lists services and ingresses reachable from outside the
// cluster. Internal AWS load balancers and internal ALBs are reported as info.
func exposureFindings(svcs []model.Service, ings []model.Ingress, isSystem func(string) bool) []SecurityFinding {
	var out []SecurityFinding
	for _, s := range svcs {
		subject := s.Namespace + "/" + s.Name
		system := isSystem(s.Namespace)
		add := func(check, sev, title, detail string) {
			out = append(out, finding("exposure", check, sev, title, "Service", subject, s.Namespace, detail, system))
		}
		switch s.Type {
		case "NodePort":
			var ports []string
			for _, p := range s.Ports {
				if p.NodePort != 0 {
					ports = append(ports, fmt.Sprintf("%d/%s", p.NodePort, protocol(p.Protocol)))
				}
			}
			detail := "Opens a port on every node."
			if len(ports) > 0 {
				detail = "Opens " + plural(len(ports), "port ", "ports ") + list(ports) + " on every node."
			}
			add(CheckNodePort, sevWarn, "NodePort service", detail)
		case "LoadBalancer":
			internal, known := internalLB(s)
			at := "no address is assigned yet"
			if len(s.LoadBalancerIngress) > 0 {
				at = "at " + list(s.LoadBalancerIngress)
			}
			ranges := ""
			if len(s.SourceRanges) > 0 {
				ranges = " Source ranges: " + list(s.SourceRanges) + "."
			}
			switch {
			case internal:
				add(CheckLoadBalancer, sevInfo, "Internal load balancer", "Internal load balancer "+at+", reachable from inside the VPC only."+ranges)
			case known:
				add(CheckLoadBalancer, sevWarn, "Load balancer", "Internet-facing load balancer "+at+"."+ranges)
			case len(s.LoadBalancerIngress) > 0:
				add(CheckLoadBalancer, sevWarn, "Load balancer", "Reachable through a load balancer at "+list(s.LoadBalancerIngress)+"."+ranges)
			default:
				add(CheckLoadBalancer, sevWarn, "Load balancer", "Asks for an external load balancer; no address is assigned yet."+ranges)
			}
		}
		if len(s.ExternalIPs) > 0 {
			add(CheckExternalIP, sevWarn, "External IPs", "Accepts traffic sent to "+list(s.ExternalIPs)+" on any node.")
		}
	}
	for _, ing := range ings {
		if len(ing.Rules) == 0 || ingressTLS(ing) {
			continue
		}
		var hosts []string
		for _, r := range ing.Rules {
			h := r.Host
			if h == "" {
				h = "*"
			}
			hosts = appendNew(hosts, h)
		}
		subject := ing.Namespace + "/" + ing.Name
		system := isSystem(ing.Namespace)
		if !isALB(ing) {
			out = append(out, finding("exposure", CheckIngressNoTLS, sevWarn, "Ingress without TLS", "Ingress", subject, ing.Namespace,
				"Serves "+list(hosts)+" over plain HTTP.", system))
			continue
		}
		// The AWS Load Balancer Controller makes internal ALBs unless told otherwise.
		if strings.EqualFold(strings.TrimSpace(ing.Annotations[annALBScheme]), "internet-facing") {
			out = append(out, finding("exposure", CheckIngressNoTLS, sevWarn, "Ingress without TLS", "Ingress", subject, ing.Namespace,
				"Serves "+list(hosts)+" over plain HTTP from an internet-facing ALB.", system))
			continue
		}
		out = append(out, finding("exposure", CheckIngressNoTLS, sevInfo, "Internal ingress without TLS", "Ingress", subject, ing.Namespace,
			"Serves "+list(hosts)+" over plain HTTP from an internal ALB, reachable from inside the VPC only.", system))
	}
	return out
}

func protocol(p string) string {
	if p == "" {
		return "TCP"
	}
	return p
}
