package kube

import (
	"net/http"
	"strconv"
	"strings"
)

// RequestObserver is told about every request a client built by ConnectWith
// (and NewReviewer) sends to the API server: the Kubernetes verb (get, list,
// watch, create, ...), the resource ("discovery" for non-resource paths) and
// the HTTP status code, or "error" when no response came back. Label values
// stay bounded: no names or namespaces.
type RequestObserver func(verb, resource, code string)

// observingTransport reports each round trip to an observer.
type observingTransport struct {
	next    http.RoundTripper
	observe RequestObserver
}

func (t observingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := t.next.RoundTrip(r)
	code := "error"
	if err == nil {
		code = strconv.Itoa(resp.StatusCode)
	}
	verb, resource := requestKind(r)
	t.observe(verb, resource, code)
	return resp, err
}

// requestKind derives the Kubernetes verb and resource from an API request:
// /api/v1/[namespaces/<ns>/]<resource>[/<name>[/<subresource>]] and the same
// under /apis/<group>/<version>.
func requestKind(r *http.Request) (verb, resource string) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	var rest []string
	switch {
	case len(parts) >= 3 && parts[0] == "api":
		rest = parts[2:]
	case len(parts) >= 4 && parts[0] == "apis":
		rest = parts[3:]
	default:
		return strings.ToLower(r.Method), "discovery"
	}
	if len(rest) >= 3 && rest[0] == "namespaces" {
		rest = rest[2:]
	}
	resource = rest[0]
	named := len(rest) > 1
	if len(rest) > 2 {
		resource += "/" + rest[2]
	}
	switch r.Method {
	case http.MethodGet:
		switch {
		case r.URL.Query().Get("watch") == "true" || r.URL.Query().Get("watch") == "1":
			verb = "watch"
		case named:
			verb = "get"
		default:
			verb = "list"
		}
	case http.MethodPost:
		verb = "create"
	case http.MethodPut:
		verb = "update"
	case http.MethodPatch:
		verb = "patch"
	case http.MethodDelete:
		verb = "delete"
		if !named {
			verb = "deletecollection"
		}
	default:
		verb = strings.ToLower(r.Method)
	}
	return verb, resource
}
