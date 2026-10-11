package detectors

import (
	"strings"
	"testing"

	"github.com/ByronGary/kubesentry/internal/model"
)

func TestExposureAWSAnnotations(t *testing.T) {
	lb := func(name string, ann map[string]string) model.Service {
		return model.Service{Namespace: "prod", Name: name, Type: "LoadBalancer", Annotations: ann, LoadBalancerIngress: []string{name + ".elb.amazonaws.com"}}
	}
	ranged := lb("ranged", map[string]string{"service.beta.kubernetes.io/aws-load-balancer-scheme": "internet-facing"})
	ranged.SourceRanges = []string{"203.0.113.0/24", "198.51.100.7/32"}
	lbc := lb("lbc-nlb", nil)
	lbc.LoadBalancerClass = "service.k8s.aws/nlb"
	alb := func(name string, ann map[string]string) model.Ingress {
		return model.Ingress{Namespace: "prod", Name: name, Class: "alb", Annotations: ann, Rules: []model.IngressRule{{Host: name + ".example.com", Service: "web"}}}
	}
	in := SecurityInput{
		Services: []model.Service{
			lb("scheme-internal", map[string]string{"service.beta.kubernetes.io/aws-load-balancer-scheme": "internal"}),
			lb("legacy-true", map[string]string{"service.beta.kubernetes.io/aws-load-balancer-internal": "true"}),
			lb("legacy-cidr", map[string]string{"service.beta.kubernetes.io/aws-load-balancer-internal": "0.0.0.0/0"}),
			lb("legacy-false", map[string]string{"service.beta.kubernetes.io/aws-load-balancer-internal": "false"}),
			lb("lbc-external", map[string]string{"service.beta.kubernetes.io/aws-load-balancer-type": "external"}),
			lbc,
			ranged,
			lb("plain", nil),
		},
		Ingresses: []model.Ingress{
			alb("cert-arn", map[string]string{"alb.ingress.kubernetes.io/scheme": "internet-facing", "alb.ingress.kubernetes.io/certificate-arn": "arn:aws:acm:us-east-1:111122223333:certificate/abc"}),
			alb("https-port", map[string]string{"alb.ingress.kubernetes.io/scheme": "internet-facing", "alb.ingress.kubernetes.io/listen-ports": `[{"HTTP": 80}, {"HTTPS": 443}]`}),
			alb("public-plain", map[string]string{"alb.ingress.kubernetes.io/scheme": "internet-facing"}),
			alb("internal-default", nil),
			{Namespace: "prod", Name: "by-annotation", Annotations: map[string]string{"kubernetes.io/ingress.class": "alb"}, Rules: []model.IngressRule{{Host: "x.example.com", Service: "web"}}},
			{Namespace: "prod", Name: "nginx", Class: "nginx", Rules: []model.IngressRule{{Host: "n.example.com", Service: "web"}}},
		},
	}
	fs, _ := AuditSecurity(in)
	m := findingsByID(fs)
	want := map[string]string{
		"loadbalancer/Service/prod/scheme-internal":    "info Internal load balancer",
		"loadbalancer/Service/prod/legacy-true":        "info Internal load balancer",
		"loadbalancer/Service/prod/legacy-cidr":        "info Internal load balancer",
		"loadbalancer/Service/prod/legacy-false":       "warn Load balancer",
		"loadbalancer/Service/prod/lbc-external":       "info Internal load balancer",
		"loadbalancer/Service/prod/lbc-nlb":            "info Internal load balancer",
		"loadbalancer/Service/prod/ranged":             "warn Load balancer",
		"loadbalancer/Service/prod/plain":              "warn Load balancer",
		"ingress-no-tls/Ingress/prod/public-plain":     "warn Ingress without TLS",
		"ingress-no-tls/Ingress/prod/internal-default": "info Internal ingress without TLS",
		"ingress-no-tls/Ingress/prod/by-annotation":    "info Internal ingress without TLS",
		"ingress-no-tls/Ingress/prod/nginx":            "warn Ingress without TLS",
	}
	for id, w := range want {
		f, ok := m[id]
		if !ok {
			t.Errorf("missing %s", id)
			continue
		}
		if got := f.Severity + " " + f.Title; got != w {
			t.Errorf("%s = %q, want %q", id, got, w)
		}
	}
	if len(fs) != len(want) {
		t.Errorf("got %d findings, want %d: %+v", len(fs), len(want), fs)
	}
	if d := m["loadbalancer/Service/prod/ranged"].Detail; !strings.Contains(d, "Internet-facing") || !strings.Contains(d, "Source ranges: 203.0.113.0/24, 198.51.100.7/32.") {
		t.Errorf("ranged detail = %q", d)
	}
	if d := m["ingress-no-tls/Ingress/prod/public-plain"].Detail; !strings.Contains(d, "internet-facing ALB") {
		t.Errorf("public ALB detail = %q", d)
	}
}

func TestEKSPrincipalsAndAWSAuth(t *testing.T) {
	all := model.PolicyRule{Verbs: []string{"*"}, APIGroups: []string{"*"}, Resources: []string{"*"}}
	readSecrets := model.PolicyRule{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"secrets"}}
	in := SecurityInput{
		RBAC: model.RBAC{
			Roles: []model.Role{
				{Kind: "ClusterRole", Name: "cluster-admin", Rules: []model.PolicyRule{all}},
				{Kind: "ClusterRole", Name: "eks:addon-manager", Rules: []model.PolicyRule{all, readSecrets}},
			},
			Bindings: []model.RoleBinding{
				// EKS's own plumbing: an eks: user bound to cluster-admin is not a person.
				{Kind: "ClusterRoleBinding", Name: "eks:addon-cluster-admin", RoleKind: "ClusterRole", RoleName: "cluster-admin",
					Subjects: []model.Subject{{Kind: "User", Name: "eks:addon-manager"}}},
				// An eks: binding that does grant a person something is kept, but marked System.
				{Kind: "ClusterRoleBinding", Name: "eks:addon-manager", RoleKind: "ClusterRole", RoleName: "eks:addon-manager",
					Subjects: []model.Subject{{Kind: "Group", Name: "platform-team"}}},
			},
		},
		Namespaces: []model.Namespace{
			{Name: "kube-system", Labels: map[string]string{"kubesentry.io/system": "false"}},
			{Name: "platform", Labels: map[string]string{"kubesentry.io/system": "true"}},
		},
		AWSAuth: &model.AWSAuth{
			MapRoles: []model.AWSAuthMapping{
				{ARN: "arn:aws:iam::111122223333:role/eks-node", Username: "system:node:{{EC2PrivateDNSName}}", Groups: []string{"system:bootstrappers", "system:nodes"}},
				{ARN: "arn:aws:iam::111122223333:role/Admin", Username: "admin", Groups: []string{"system:masters"}},
			},
			MapUsers: []model.AWSAuthMapping{{ARN: "arn:aws:iam::111122223333:user/ci", Groups: []string{"system:masters"}}},
		},
	}
	fs, posture := AuditSecurity(in)
	m := findingsByID(fs)

	if _, ok := m["cluster-admin/ClusterRoleBinding/eks:addon-cluster-admin"]; ok {
		t.Error("an eks: principal bound to cluster-admin is plumbing, not a finding")
	}
	if f, ok := m["secret-readers/ClusterRoleBinding/eks:addon-manager"]; !ok || !f.System {
		t.Errorf("eks: binding finding = %+v %v, want kept and System", f, ok)
	}
	if f, ok := m["wildcard-rbac/ClusterRole/eks:addon-manager"]; !ok || !f.System {
		t.Errorf("eks: role finding = %+v %v, want kept and System", f, ok)
	}
	role := m["aws-auth-masters/IAMRole/arn:aws:iam::111122223333:role/Admin"]
	if role.Severity != "crit" || role.Category != "rbac" || role.System || role.Namespace != "" || !strings.Contains(role.Detail, "username admin") {
		t.Errorf("aws-auth role finding = %+v", role)
	}
	if user := m["aws-auth-masters/IAMUser/arn:aws:iam::111122223333:user/ci"]; user.Severity != "crit" || !strings.Contains(user.Detail, "IAM user") {
		t.Errorf("aws-auth user finding = %+v", user)
	}
	if _, ok := m["aws-auth-masters/IAMRole/arn:aws:iam::111122223333:role/eks-node"]; ok {
		t.Error("node role mappings are not masters")
	}

	sys := map[string]bool{}
	for _, p := range posture {
		sys[p.Name] = p.System
	}
	if sys["kube-system"] || !sys["platform"] {
		t.Errorf("label override not applied: %v", sys)
	}
}
