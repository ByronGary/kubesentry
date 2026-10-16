// Package uilink builds the hash routes of the pages that explain a
// finding, with the query parameters those pages read (web/src/pages):
// Workloads namespace and q, Security check and q, Certificates q, Nodes
// node, the Overview owner, an incident. The Overview's attention list and
// the alerts' kubesentry_url share them. Stdlib only.
package uilink

import "net/url"

// Workload is the Workloads page filtered to one workload.
func Workload(ns, name string) string {
	return "#/workloads?" + url.Values{"namespace": {ns}, "q": {name}}.Encode()
}

// Pod is a pod's diagnostic page.
func Pod(ns, pod string) string {
	return "#/pods/" + url.PathEscape(ns) + "/" + url.PathEscape(pod)
}

// Security is the Security page filtered to one check and subject.
func Security(check, subject string) string {
	return "#/security?" + url.Values{"check": {check}, "q": {subject}}.Encode()
}

// Certificate is the Certificates page filtered to one certificate.
func Certificate(ns, name string) string {
	return "#/certificates?" + url.Values{"q": {ns + "/" + name}}.Encode()
}

// Node is the Nodes page with one node open.
func Node(name string) string {
	return "#/nodes?" + url.Values{"node": {name}}.Encode()
}

// Incident is one incident's page.
func Incident(id string) string {
	return "#/incidents/" + url.PathEscape(id)
}

// Activity is the Activity page (the audit log) filtered to one tag and one
// user; either may be "".
func Activity(tag, user string) string {
	q := url.Values{}
	if tag != "" {
		q.Set("tag", tag)
	}
	if user != "" {
		q.Set("user", user)
	}
	if len(q) == 0 {
		return "#/activity"
	}
	return "#/activity?" + q.Encode()
}

// Agents is the node agents page.
func Agents() string { return "#/agents" }

// Owner is the Overview filtered to one owner's namespaces.
func Owner(owner string) string {
	return "#/?" + url.Values{"owner": {owner}}.Encode()
}

// Absolute joins an external base URL (e.g. https://kubesentry.example.com)
// and a hash route; "" when base is empty.
func Absolute(base, route string) string {
	if base == "" {
		return ""
	}
	for len(base) > 0 && base[len(base)-1] == '/' {
		base = base[:len(base)-1]
	}
	return base + "/" + route
}
