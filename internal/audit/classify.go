package audit

// Tags attached by Classify. They mark the events worth a human's attention.
const (
	TagExec         = "exec"            // pods/exec or pods/attach
	TagPortForward  = "portforward"     // pods/portforward
	TagDebug        = "debug-container" // pods/ephemeralcontainers (kubectl debug)
	TagSecretAccess = "secret-access"   // read of a Secret
	TagSecretChange = "secret-change"   // write to a Secret
	TagRBACChange   = "rbac-change"     // write to roles, bindings, clusterroles, clusterrolebindings
	TagDelete       = "delete"
	TagImpersonate  = "impersonate"
	TagTokenRequest = "token-request" // minting a ServiceAccount token
	TagDenied       = "denied"        // 401/403 or authorizer forbid
	TagAnonymous    = "anonymous"
)

func isRead(verb string) bool {
	return verb == "get" || verb == "list" || verb == "watch"
}

func isWrite(verb string) bool {
	switch verb {
	case "create", "update", "patch", "delete", "deletecollection":
		return true
	}
	return false
}

// Classify returns the security-relevant tags for an event, in a fixed order.
func Classify(e Event) []string {
	var tags []string
	add := func(t string) { tags = append(tags, t) }

	if e.Resource == "pods" {
		switch e.Subresource {
		case "exec", "attach":
			add(TagExec)
		case "portforward":
			add(TagPortForward)
		case "ephemeralcontainers":
			if isWrite(e.Verb) {
				add(TagDebug)
			}
		}
	}
	if e.Resource == "secrets" && e.APIGroup == "" {
		switch {
		case isRead(e.Verb):
			add(TagSecretAccess)
		case isWrite(e.Verb):
			add(TagSecretChange)
		}
	}
	if e.APIGroup == "rbac.authorization.k8s.io" && isWrite(e.Verb) {
		switch e.Resource {
		case "roles", "rolebindings", "clusterroles", "clusterrolebindings":
			add(TagRBACChange)
		}
	}
	if e.Verb == "delete" || e.Verb == "deletecollection" {
		add(TagDelete)
	}
	if e.ImpersonatedUser != "" || e.Verb == "impersonate" {
		add(TagImpersonate)
	}
	if e.Resource == "serviceaccounts" && e.Subresource == "token" && e.Verb == "create" {
		add(TagTokenRequest)
	}
	if e.StatusCode == 401 || e.StatusCode == 403 || e.Decision == "forbid" {
		add(TagDenied)
	}
	if e.Username == "system:anonymous" || hasGroup(e.Groups, "system:unauthenticated") {
		add(TagAnonymous)
	}
	return tags
}

func hasGroup(groups []string, g string) bool {
	for _, x := range groups {
		if x == g {
			return true
		}
	}
	return false
}
