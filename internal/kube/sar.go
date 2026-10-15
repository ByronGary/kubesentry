package kube

import (
	"context"
	"fmt"

	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	authorizationclient "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"k8s.io/client-go/rest"
)

// Reviewer asks the API server whether a user may do something, with
// SubjectAccessReviews. It satisfies auth.Reviewer. Reviews run on their own
// client with their own rate limit, so a burst of sign-ins cannot starve the
// informers (and the reverse).
type Reviewer struct {
	client authorizationclient.SubjectAccessReviewInterface
}

// NewReviewer builds a Reviewer from c. With a rest.Config it copies the
// config and applies qps and burst (zero or less keeps the config's values);
// without one (fakes in tests) it uses c.CS.
func NewReviewer(c *Clients, qps float32, burst int) (*Reviewer, error) {
	if c.Config == nil {
		return &Reviewer{client: c.CS.AuthorizationV1().SubjectAccessReviews()}, nil
	}
	cfg := rest.CopyConfig(c.Config)
	if qps > 0 {
		cfg.QPS = qps
	}
	if burst > 0 {
		cfg.Burst = burst
	}
	cfg.RateLimiter = nil // let client-go build a limiter from QPS and Burst
	ac, err := authorizationclient.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create authorization client: %w", err)
	}
	return &Reviewer{client: ac.SubjectAccessReviews()}, nil
}

// Review creates one authorization.k8s.io/v1 SubjectAccessReview. verb,
// group, resource, subresource and namespace are ResourceAttributes (""
// subresource means the resource itself, "" namespace all namespaces). It
// fails closed: only an explicit Allowed is true.
func (r *Reviewer) Review(ctx context.Context, user string, groups []string, verb, group, resource, subresource, namespace string) (bool, error) {
	sar := &authorizationv1.SubjectAccessReview{Spec: authorizationv1.SubjectAccessReviewSpec{
		User:   user,
		Groups: groups,
		ResourceAttributes: &authorizationv1.ResourceAttributes{
			Namespace: namespace, Verb: verb, Group: group, Resource: resource, Subresource: subresource,
		},
	}}
	out, err := r.client.Create(ctx, sar, metav1.CreateOptions{})
	if err != nil {
		return false, fmt.Errorf("subjectaccessreview: %w", err)
	}
	return out.Status.Allowed && !out.Status.Denied, nil
}
