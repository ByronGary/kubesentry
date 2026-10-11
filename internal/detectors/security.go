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
	Pods       []model.Pod
	Workloads  []model.Workload
	Namespaces []model.Namespace
	RBAC       model.RBAC
	Services   []model.Service
	Ingresses  []model.Ingress
}

const (
	sevCrit = "crit"
	sevWarn = "warn"
	sevInfo = "info"
)

// AuditSecurity checks pod specs, RBAC, Pod Security labels and network
// exposure. Findings come most severe first, non-system before system, then by
// category and subject. Every namespace gets a posture row, sorted by name.
func AuditSecurity(in SecurityInput) ([]SecurityFinding, []NamespacePosture) {
	out := []SecurityFinding{}
	out = append(out, podFindings(in.Pods, in.Workloads)...)
	out = append(out, rbacFindings(in.RBAC)...)
	nsFindings, posture := namespaceFindings(in.Namespaces)
	out = append(out, nsFindings...)
	out = append(out, exposureFindings(in.Services, in.Ingresses)...)

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
	pods           []model.Pod
}

// podFindings reports risky pod specs once per workload rather than per pod.
// Jobs that a CronJob created are reported under the CronJob.
func podFindings(pods []model.Pod, ws []model.Workload) []SecurityFinding {
	groups := map[string]*podGroup{}
	for _, p := range pods {
		kind, name, ok := OwnerOf(p, ws)
		switch {
		case !ok:
			kind, name = "Pod", p.Name
		case kind == "Job":
			if cj, ok := cronJobOf(p.Namespace, name, ws); ok {
				kind, name = "CronJob", cj
			}
		}
		key := kind + "/" + p.Namespace + "/" + name
		if groups[key] == nil {
			groups[key] = &podGroup{kind: kind, ns: p.Namespace, name: name}
		}
		groups[key].pods = append(groups[key].pods, p)
	}

	var out []SecurityFinding
	for _, g := range groups {
		out = append(out, groupFindings(g)...)
	}
	return out
}

func groupFindings(g *podGroup) []SecurityFinding {
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
	system := SystemNamespaces[g.ns]
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

// systemSubject reports whether a binding subject is cluster plumbing: a
// "system:" user or group, or a service account in a system namespace. The
// groups that stand for everyone, or every service account, are never plumbing.
func systemSubject(s model.Subject) bool {
	if s.Kind == "ServiceAccount" {
		return SystemNamespaces[s.Namespace]
	}
	switch s.Name {
	case "system:anonymous", "system:unauthenticated", "system:authenticated", "system:serviceaccounts":
		return false
	}
	if rest, ok := strings.CutPrefix(s.Name, "system:serviceaccount:"); ok {
		ns, _, _ := strings.Cut(rest, ":")
		return SystemNamespaces[ns]
	}
	if ns, ok := strings.CutPrefix(s.Name, "system:serviceaccounts:"); ok {
		return SystemNamespaces[ns]
	}
	return strings.HasPrefix(s.Name, "system:")
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
// who can read secrets. Bindings named "system:..." are Kubernetes' own.
func rbacFindings(r model.RBAC) []SecurityFinding {
	roles := map[string]model.Role{}
	for _, ro := range r.Roles {
		roles[roleKey(ro.Kind, ro.Namespace, ro.Name)] = ro
	}
	boundTo := map[string][]string{} // role key -> non-system subjects bound to it

	var out []SecurityFinding
	for _, b := range r.Bindings {
		subject := scopedName(b.Namespace, b.Name)
		builtin := strings.HasPrefix(b.Name, "system:")
		// kubeadm creates its own bindings, such as kubeadm:cluster-admins for
		// the admin kubeconfig. Their findings are kept but marked as plumbing.
		kubeadm := strings.HasPrefix(b.Name, "kubeadm:")
		var people []string
		humans := false // a non-system User or Group, as opposed to only service accounts
		for _, s := range b.Subjects {
			if !systemSubject(s) {
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
				"Grants cluster-admin "+scope+" to "+list(people)+".", kubeadm))
		}

		if !builtin {
			var anon []string
			for _, s := range b.Subjects {
				if (s.Kind == "User" && s.Name == "system:anonymous") || (s.Kind == "Group" && s.Name == "system:unauthenticated") {
					anon = appendNew(anon, s.Name)
				}
			}
			if len(anon) > 0 {
				// kubeadm's own cluster-info binding lives in kube-public; such
				// bindings are plumbing, kept but hidden by default.
				system := kubeadm || SystemNamespaces[b.Namespace]
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
		if !admin && !builtin && readsSecrets(role.Rules) {
			// Controllers such as cert-manager or an operator need secrets to do
			// their job; people and groups reading them is the bigger risk.
			sev := sevInfo
			if humans {
				sev = sevWarn
			}
			out = append(out, finding("rbac", CheckSecretReaders, sev, "Can read secrets", b.Kind, subject, b.Namespace,
				fmt.Sprintf("%s can read secrets %s through %s %s.", list(people), scope, b.RoleKind, b.RoleName), kubeadm))
		}
	}

	for _, ro := range r.Roles {
		if strings.HasPrefix(ro.Name, "system:") || (ro.Kind == "ClusterRole" && (ro.Name == "cluster-admin" || ro.Name == "admin" || ro.Name == "edit")) {
			continue
		}
		people := boundTo[roleKey(ro.Kind, ro.Namespace, ro.Name)]
		where := wildcards(ro.Rules)
		if len(people) == 0 || where == "" {
			continue
		}
		out = append(out, finding("rbac", CheckWildcard, sevWarn, "Wildcard permissions", ro.Kind, scopedName(ro.Namespace, ro.Name), ro.Namespace,
			fmt.Sprintf("Uses \"*\" in %s, so it also grants anything added later; bound to %s.", where, list(people)), false))
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
func namespaceFindings(nss []model.Namespace) ([]SecurityFinding, []NamespacePosture) {
	var out []SecurityFinding
	posture := make([]NamespacePosture, 0, len(nss))
	for _, ns := range nss {
		p := NamespacePosture{
			Name: ns.Name, Enforce: ns.Labels[psaPrefix+"enforce"], Audit: ns.Labels[psaPrefix+"audit"],
			Warn: ns.Labels[psaPrefix+"warn"], System: SystemNamespaces[ns.Name], Status: StatusWarn,
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

// exposureFindings lists services and ingresses reachable from outside the cluster.
func exposureFindings(svcs []model.Service, ings []model.Ingress) []SecurityFinding {
	var out []SecurityFinding
	for _, s := range svcs {
		subject := s.Namespace + "/" + s.Name
		system := SystemNamespaces[s.Namespace]
		add := func(check, title, detail string) {
			out = append(out, finding("exposure", check, sevWarn, title, "Service", subject, s.Namespace, detail, system))
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
			add(CheckNodePort, "NodePort service", detail)
		case "LoadBalancer":
			detail := "Asks for an external load balancer; no address is assigned yet."
			if len(s.LoadBalancerIngress) > 0 {
				detail = "Reachable through a load balancer at " + list(s.LoadBalancerIngress) + "."
			}
			add(CheckLoadBalancer, "Load balancer", detail)
		}
		if len(s.ExternalIPs) > 0 {
			add(CheckExternalIP, "External IPs", "Accepts traffic sent to "+list(s.ExternalIPs)+" on any node.")
		}
	}
	for _, ing := range ings {
		if len(ing.Rules) == 0 || len(ing.TLS) > 0 {
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
		out = append(out, finding("exposure", CheckIngressNoTLS, sevWarn, "Ingress without TLS", "Ingress", ing.Namespace+"/"+ing.Name, ing.Namespace,
			"Serves "+list(hosts)+" over plain HTTP.", SystemNamespaces[ing.Namespace]))
	}
	return out
}

func protocol(p string) string {
	if p == "" {
		return "TCP"
	}
	return p
}
