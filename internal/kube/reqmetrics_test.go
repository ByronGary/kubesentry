package kube

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequestKind(t *testing.T) {
	cases := []struct{ method, url, verb, resource string }{
		{"GET", "/api/v1/pods?limit=500", "list", "pods"},
		{"GET", "/api/v1/pods?watch=true&resourceVersion=1", "watch", "pods"},
		{"GET", "/api/v1/namespaces/kube-system/configmaps/aws-auth", "get", "configmaps"},
		{"GET", "/api/v1/namespaces/a/pods", "list", "pods"},
		{"GET", "/api/v1/namespaces", "list", "namespaces"},
		{"GET", "/api/v1/namespaces/a", "get", "namespaces"},
		{"GET", "/apis/apps/v1/namespaces/a/deployments/web/scale", "get", "deployments/scale"},
		{"POST", "/apis/authorization.k8s.io/v1/subjectaccessreviews", "create", "subjectaccessreviews"},
		{"DELETE", "/api/v1/namespaces/a/pods", "deletecollection", "pods"},
		{"GET", "/version", "get", "discovery"},
		{"GET", "/apis", "get", "discovery"},
	}
	for _, c := range cases {
		verb, resource := requestKind(httptest.NewRequest(c.method, c.url, nil))
		if verb != c.verb || resource != c.resource {
			t.Errorf("%s %s = %s %s, want %s %s", c.method, c.url, verb, resource, c.verb, c.resource)
		}
	}
}

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestObservingTransport(t *testing.T) {
	var got []string
	obs := func(verb, resource, code string) { got = append(got, verb+" "+resource+" "+code) }
	ok := observingTransport{next: rtFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 403, Body: http.NoBody}, nil
	}), observe: obs}
	fail := observingTransport{next: rtFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("dial")
	}), observe: obs}
	_, _ = ok.RoundTrip(httptest.NewRequest("GET", "/api/v1/nodes", nil))
	_, _ = fail.RoundTrip(httptest.NewRequest("GET", "/api/v1/nodes?watch=1", nil))
	if len(got) != 2 || got[0] != "list nodes 403" || got[1] != "watch nodes error" {
		t.Errorf("observed %v", got)
	}
}
