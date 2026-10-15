package kube

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/ByronGary/kubesentry/internal/model"
)

// TargetGroupBindings belong to the AWS Load Balancer Controller: each ties
// an AWS target group to a Service, which is how CloudTrail changes to a
// target group find the workloads behind it.
const (
	targetGroupBindingGroup    = "elbv2.k8s.aws"
	targetGroupBindingResource = "targetgroupbindings"
)

// targetGroupBindingAPI is elbv2.k8s.aws/v1beta1, watched while it is served.
var targetGroupBindingAPI = &crdAPI{
	name: "AWS Load Balancer Controller", group: targetGroupBindingGroup, version: "v1beta1",
	resources: []string{targetGroupBindingResource},
	reset:     func(m *memos) { m.targetgroupbindings.reset() },
}

// isTargetGroupBinding tells a TargetGroupBinding from the other custom
// resources the transform sees.
func isTargetGroupBinding(u *unstructured.Unstructured) bool {
	return u.GetKind() == "TargetGroupBinding" && strings.HasPrefix(u.GetAPIVersion(), targetGroupBindingGroup+"/")
}

// transformTargetGroupBinding keeps the identity, the target group and the
// Service reference; networking rules, node selectors, labels, annotations
// and status are dropped.
func transformTargetGroupBinding(u *unstructured.Unstructured) {
	out := map[string]any{}
	for _, k := range []string{"apiVersion", "kind"} {
		if v, ok := u.Object[k]; ok {
			out[k] = v
		}
	}
	md := map[string]any{}
	if m, ok := u.Object["metadata"].(map[string]any); ok {
		for _, k := range []string{"namespace", "name", "uid", "resourceVersion"} {
			if v, ok := m[k]; ok {
				md[k] = v
			}
		}
	}
	out["metadata"] = md
	if spec, ok := u.Object["spec"].(map[string]any); ok {
		kept := map[string]any{}
		if v, ok := spec["targetGroupARN"]; ok {
			kept["targetGroupARN"] = v
		}
		if ref, ok := spec["serviceRef"].(map[string]any); ok {
			r := map[string]any{}
			for _, k := range []string{"name", "port"} {
				if v, ok := ref[k]; ok {
					r[k] = v
				}
			}
			kept["serviceRef"] = r
		}
		out["spec"] = kept
	}
	u.Object = out
}

func convertTargetGroupBinding(u *unstructured.Unstructured) model.TargetGroupBinding {
	b := model.TargetGroupBinding{
		Namespace: u.GetNamespace(), Name: u.GetName(),
		TargetGroupARN: str(u, "spec", "targetGroupARN"),
		ServiceName:    str(u, "spec", "serviceRef", "name"),
	}
	// serviceRef.port is an IntOrString: a port number or a port name.
	port, _, _ := unstructured.NestedFieldNoCopy(u.Object, "spec", "serviceRef", "port")
	switch p := port.(type) {
	case string:
		b.ServicePort = p
	case int64:
		b.ServicePort = strconv.FormatInt(p, 10)
	case int32:
		b.ServicePort = strconv.FormatInt(int64(p), 10)
	case int:
		b.ServicePort = strconv.Itoa(p)
	case float64:
		b.ServicePort = strconv.FormatFloat(p, 'f', -1, 64)
	}
	return b
}

// targetGroupBindings lists TargetGroupBindings for the per-request Source:
// nil, without an error, while the elbv2.k8s.aws API is not served; a
// forbidden list is recorded in unavailable.
func (s *Source) targetGroupBindings(ctx context.Context, unavailable map[string]string) ([]model.TargetGroupBinding, error) {
	a := targetGroupBindingAPI
	if s.dyn == nil {
		return nil, nil
	}
	if _, err := s.cs.Discovery().ServerResourcesForGroupVersion(a.groupVersion()); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("discover %s: %w", a.groupVersion(), err)
	}
	var out []model.TargetGroupBinding
	err := s.listDynamic(ctx, a.gvr(targetGroupBindingResource), func(u *unstructured.Unstructured) {
		out = append(out, convertTargetGroupBinding(u))
	})
	if err != nil && apierrors.IsForbidden(err) {
		unavailable[targetGroupBindingResource] = forbiddenReason(err)
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}
