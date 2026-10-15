package incidents

import (
	"sort"
	"strings"

	"github.com/ByronGary/kubesentry/internal/model"
	"github.com/ByronGary/kubesentry/internal/snapshot"
)

// Annotations the related-resource index reads. internal/kube must keep
// them (its annotation allowlists).
const (
	AnnotationALBGroup          = "alb.ingress.kubernetes.io/group.name"
	AnnotationALBName           = "alb.ingress.kubernetes.io/load-balancer-name"
	AnnotationALBSecurityGroups = "alb.ingress.kubernetes.io/security-groups"
	AnnotationNLBName           = "service.beta.kubernetes.io/aws-load-balancer-name"
	AnnotationNLBSecurityGroups = "service.beta.kubernetes.io/aws-load-balancer-security-groups"
	AnnotationNLBExtraSGs       = "service.beta.kubernetes.io/aws-load-balancer-extra-security-groups"
)

// What an identifier in the related-resource index is.
const (
	RelatedInstance      = "instance"
	RelatedTargetGroup   = "target-group"
	RelatedLoadBalancer  = "load-balancer"
	RelatedRole          = "irsa-role"
	RelatedSecurityGroup = "security-group"
	RelatedCluster       = "cluster"
)

// RelatedIndex maps AWS identifiers to the subjects they concern, so a
// CloudTrail change can be attached to the incidents it may explain:
//
//   - EC2 instance IDs (Node.ProviderID) to the node and the roots of the
//     pods it runs;
//   - target group ARNs (TargetGroupBindings) to the roots behind the bound
//     Service;
//   - load balancer names (Ingress group.name and load-balancer-name, the
//     Service load-balancer-name annotation) to the roots behind the
//     Services they route to;
//   - IRSA role ARNs and role/<name> (ServiceAccounts) to the roots of the pods
//     running as the account;
//   - security group IDs (ALB and NLB annotations) to the roots behind the
//     Ingress or Service;
//   - the EKS cluster name, for cluster, node group and add-on changes:
//     cluster-wide context.
//
// It is built once per view (View.Memo).
type RelatedIndex struct {
	cluster string
	ids     map[string]*related
}

type related struct {
	what     string
	subjects []Subject
}

// RelatedIndexOf returns the view's index; cluster names the EKS cluster
// (the view's ClusterInfo.Name when empty).
func RelatedIndexOf(v *snapshot.View, cluster string) *RelatedIndex {
	if cluster == "" {
		cluster = v.Inv.Cluster.Name
	}
	return v.Memo("incidents/related\x00"+cluster, func() any { return buildRelated(v, cluster) }).(*RelatedIndex)
}

func buildRelated(v *snapshot.View, cluster string) *RelatedIndex {
	x := &RelatedIndex{cluster: cluster, ids: map[string]*related{}}
	a := v.Assoc()
	inv := &v.Inv
	add := func(id, what string, subjects ...Subject) {
		id = strings.TrimSpace(id)
		if id == "" || len(subjects) == 0 {
			return
		}
		r := x.ids[id]
		if r == nil {
			r = &related{what: what}
			x.ids[id] = r
		}
		for _, s := range subjects {
			if !containsSubject(r.subjects, s) {
				r.subjects = append(r.subjects, s)
			}
		}
	}
	for i := range inv.Nodes {
		n := &inv.Nodes[i]
		id := instanceID(n.ProviderID)
		if id == "" {
			continue
		}
		subjects := []Subject{{Kind: KindNode, Name: n.Name}}
		for _, p := range a.PodsOnNode(n.Name) {
			if livePod(p) {
				subjects = append(subjects, subjectOfPod(a, p))
			}
		}
		add(id, RelatedInstance, subjects...)
	}
	for _, tgb := range inv.TargetGroupBindings {
		subjects := SubjectsOfService(v, tgb.Namespace, tgb.ServiceName)
		add(tgb.TargetGroupARN, RelatedTargetGroup, subjects...)
		if i := strings.Index(tgb.TargetGroupARN, ":targetgroup/"); i >= 0 {
			add(tgb.TargetGroupARN[i+1:], RelatedTargetGroup, subjects...)
		}
	}
	for i := range inv.Ingresses {
		ing := &inv.Ingresses[i]
		var subjects []Subject
		seen := map[string]bool{}
		for _, svc := range append([]string{ing.DefaultBackend}, ruleServices(ing.Rules)...) {
			if svc != "" && !seen[svc] {
				seen[svc] = true
				subjects = append(subjects, SubjectsOfService(v, ing.Namespace, svc)...)
			}
		}
		add(ing.Annotations[AnnotationALBName], RelatedLoadBalancer, subjects...)
		add(ing.Annotations[AnnotationALBGroup], RelatedLoadBalancer, subjects...)
		for _, sg := range splitList(ing.Annotations[AnnotationALBSecurityGroups]) {
			add(sg, RelatedSecurityGroup, subjects...)
		}
	}
	for i := range inv.Services {
		svc := &inv.Services[i]
		if len(svc.Annotations) == 0 {
			continue
		}
		subjects := SubjectsOfService(v, svc.Namespace, svc.Name)
		add(svc.Annotations[AnnotationNLBName], RelatedLoadBalancer, subjects...)
		for _, k := range []string{AnnotationNLBSecurityGroups, AnnotationNLBExtraSGs} {
			for _, sg := range splitList(svc.Annotations[k]) {
				add(sg, RelatedSecurityGroup, subjects...)
			}
		}
	}
	for _, sa := range inv.ServiceAccounts {
		if sa.RoleARN == "" {
			continue
		}
		var subjects []Subject
		for _, p := range a.PodsIn(sa.Namespace) {
			if livePod(p) && p.ServiceAccount == sa.Name {
				subjects = append(subjects, subjectOfPod(a, p))
			}
		}
		add(sa.RoleARN, RelatedRole, subjects...)
		if i := strings.LastIndexByte(sa.RoleARN, '/'); i >= 0 {
			add("role/"+sa.RoleARN[i+1:], RelatedRole, subjects...) // the short form CloudTrail sources give
		}
	}
	for _, r := range x.ids {
		sortSubjects(r.subjects)
	}
	return x
}

func ruleServices(rules []model.IngressRule) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.Service)
	}
	return out
}

func containsSubject(l []Subject, s Subject) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func splitList(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// instanceID extracts the EC2 instance ID from a provider ID
// (aws:///us-east-1a/i-0abc...).
func instanceID(providerID string) string {
	if !strings.HasPrefix(providerID, "aws://") {
		return ""
	}
	i := strings.LastIndexByte(providerID, '/')
	id := providerID[i+1:]
	if !strings.HasPrefix(id, "i-") {
		return ""
	}
	return id
}

// Match returns the subjects a CloudTrail event concerns, with the
// identifiers that matched ("instance:i-0abc"). cluster is true for a
// change to the EKS cluster itself, its node groups or add-ons.
//
// Resources come as full ARNs, bare instance and security group IDs,
// targetgroup/<name>/<id>, role/<roleName>, and for EKS cluster/<name>,
// nodegroup/<cluster>/<name> and addon/<cluster>/<name>.
func (x *RelatedIndex) Match(e *CloudTrailEvent) (subjects []Subject, matched []string, cluster bool) {
	seenID := map[string]bool{}
	for _, r := range e.Resources {
		for _, id := range candidates(r) {
			if seenID[id] {
				continue
			}
			seenID[id] = true
			if rel := x.ids[id]; rel != nil {
				matched = append(matched, rel.what+":"+id)
				for _, s := range rel.subjects {
					if !containsSubject(subjects, s) {
						subjects = append(subjects, s)
					}
				}
			}
		}
		if x.cluster != "" && e.Source == "eks.amazonaws.com" && eksCluster(r) == x.cluster {
			cluster = true
		}
	}
	if cluster {
		matched = append(matched, RelatedCluster+":"+x.cluster)
	}
	sortSubjects(subjects)
	sort.Strings(matched)
	return subjects, matched, cluster
}

// resourcePart is an ARN's resource (after the fifth colon), or r itself.
func resourcePart(r string) string {
	if !strings.HasPrefix(r, "arn:") {
		return r
	}
	parts := strings.SplitN(r, ":", 6)
	if len(parts) < 6 {
		return r
	}
	return parts[5]
}

// candidates are the index keys one resource string may stand for: itself,
// an ARN's resource part, and the IDs and names within it
// (instance/<id>, security-group/<id>, loadbalancer/app/<name>/<id>,
// role/<path>/<name> as role/<name>).
func candidates(r string) []string {
	r = strings.TrimSpace(r)
	if r == "" {
		return nil
	}
	out := []string{r}
	res := resourcePart(r)
	if res != r {
		out = append(out, res)
	}
	segs := strings.Split(res, "/")
	switch segs[0] {
	case "loadbalancer":
		if len(segs) >= 3 {
			out = append(out, segs[2]) // loadbalancer/app/<name>/<id>
		}
	case "instance", "security-group":
		if len(segs) >= 2 {
			out = append(out, segs[len(segs)-1])
		}
	case "role":
		if len(segs) >= 2 {
			out = append(out, "role/"+segs[len(segs)-1])
		}
	}
	return out
}

// eksCluster is the cluster an EKS resource names: cluster/<name>,
// nodegroup/<cluster>/..., addon/<cluster>/... (bare or in an ARN), or a
// bare name.
func eksCluster(r string) string {
	r = strings.TrimSpace(r)
	res := resourcePart(r)
	segs := strings.Split(res, "/")
	if len(segs) >= 2 {
		switch segs[0] {
		case "cluster", "nodegroup", "addon", "fargateprofile", "identityproviderconfig", "podidentityassociation", "access-entry":
			return segs[1]
		}
		return ""
	}
	if res != r {
		return ""
	}
	return r
}
