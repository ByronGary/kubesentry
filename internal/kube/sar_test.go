package kube

import (
	"context"
	"errors"
	"reflect"
	"testing"

	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"
)

func TestReviewer(t *testing.T) {
	cs := fake.NewClientset()
	var seen []authorizationv1.SubjectAccessReviewSpec
	cs.PrependReactor("create", "subjectaccessreviews", func(a k8stesting.Action) (bool, runtime.Object, error) {
		r := a.(k8stesting.CreateAction).GetObject().(*authorizationv1.SubjectAccessReview).DeepCopy()
		seen = append(seen, r.Spec)
		if r.Spec.User == "boom" {
			return true, nil, errors.New("apiserver unavailable")
		}
		ra := r.Spec.ResourceAttributes
		r.Status.Allowed = r.Spec.User == "erin" && ra.Verb == "list" && ra.Resource == "pods" && ra.Namespace == "app"
		r.Status.Denied = r.Spec.User == "mallory"
		if r.Spec.User == "mallory" {
			r.Status.Allowed = true // a conflicting answer still fails closed
		}
		return true, r, nil
	})
	rv, err := NewReviewer(&Clients{CS: cs}, 10, 20)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	ok, err := rv.Review(ctx, "erin", []string{"devs", "system:authenticated"}, "list", "", "pods", "app")
	if err != nil || !ok {
		t.Fatalf("erin in app: %v, %v", ok, err)
	}
	want := authorizationv1.SubjectAccessReviewSpec{User: "erin", Groups: []string{"devs", "system:authenticated"},
		ResourceAttributes: &authorizationv1.ResourceAttributes{Verb: "list", Resource: "pods", Namespace: "app"}}
	if !reflect.DeepEqual(seen[0], want) {
		t.Errorf("review spec: %+v", seen[0])
	}
	if ok, err := rv.Review(ctx, "erin", nil, "list", "", "pods", "other"); err != nil || ok {
		t.Errorf("erin in other: %v, %v", ok, err)
	}
	if ok, err := rv.Review(ctx, "mallory", nil, "list", "", "pods", "app"); err != nil || ok {
		t.Errorf("denied: %v, %v", ok, err)
	}
	if ok, err := rv.Review(ctx, "boom", nil, "get", "kubesentry.io", "processes", "app"); err == nil || ok {
		t.Errorf("failed review: %v, %v", ok, err)
	}
	if got := seen[len(seen)-1].ResourceAttributes; got.Group != "kubesentry.io" || got.Resource != "processes" || got.Verb != "get" {
		t.Errorf("virtual resource attributes: %+v", got)
	}

	// With a rest.Config the Reviewer gets its own client and rate limit,
	// leaving the shared config untouched.
	cfg := &rest.Config{Host: "https://example.invalid", QPS: 50, Burst: 100}
	r2, err := NewReviewer(&Clients{CS: cs, Config: cfg}, 200, 400)
	if err != nil || r2.client == nil {
		t.Fatalf("reviewer from config: %v", err)
	}
	if cfg.QPS != 50 || cfg.Burst != 100 {
		t.Errorf("shared config changed: %+v", cfg)
	}
}
