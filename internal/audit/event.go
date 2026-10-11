// Package audit ingests Kubernetes API server audit events, normalizes them,
// tags the security-relevant ones, and serves them from a bounded store.
//
// It depends only on the standard library. Request and response bodies (which
// appear at the Request/RequestResponse audit levels and can contain secrets)
// are never decoded or kept.
package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// Event is a normalized audit.k8s.io/v1 event.
type Event struct {
	AuditID          string    `json:"auditID"`
	Time             time.Time `json:"time"`
	Stage            string    `json:"stage"`
	Verb             string    `json:"verb"`
	Username         string    `json:"username"`
	ActorKind        string    `json:"actorKind"` // "user", "serviceaccount" or "system"
	Groups           []string  `json:"groups,omitempty"`
	ARN              string    `json:"arn,omitempty"`         // from user.extra, set by AWS IAM authentication
	SessionName      string    `json:"sessionName,omitempty"` // from user.extra, set by AWS IAM authentication
	ImpersonatedUser string    `json:"impersonatedUser,omitempty"`
	SourceIPs        []string  `json:"sourceIPs,omitempty"`
	UserAgent        string    `json:"userAgent,omitempty"`
	APIGroup         string    `json:"apiGroup,omitempty"`
	Resource         string    `json:"resource,omitempty"`
	Subresource      string    `json:"subresource,omitempty"`
	Namespace        string    `json:"namespace,omitempty"`
	Name             string    `json:"name,omitempty"`
	RequestURI       string    `json:"requestURI,omitempty"` // for exec this includes the command
	StatusCode       int       `json:"statusCode"`
	Decision         string    `json:"decision,omitempty"` // "allow" or "forbid" from the authorizer annotation
	Tags             []string  `json:"tags,omitempty"`
}

// wireEvent mirrors the parts of audit.k8s.io/v1 Event we read. Bodies
// (requestObject, responseObject) are deliberately absent so they are skipped.
type wireEvent struct {
	Kind       string      `json:"kind"`
	Items      []wireEvent `json:"items"`
	AuditID    string      `json:"auditID"`
	Stage      string      `json:"stage"`
	RequestURI string      `json:"requestURI"`
	Verb       string      `json:"verb"`
	User       struct {
		Username string              `json:"username"`
		Groups   []string            `json:"groups"`
		Extra    map[string][]string `json:"extra"`
	} `json:"user"`
	ImpersonatedUser *struct {
		Username string `json:"username"`
	} `json:"impersonatedUser"`
	SourceIPs []string `json:"sourceIPs"`
	UserAgent string   `json:"userAgent"`
	ObjectRef *struct {
		Resource    string `json:"resource"`
		Namespace   string `json:"namespace"`
		Name        string `json:"name"`
		APIGroup    string `json:"apiGroup"`
		Subresource string `json:"subresource"`
	} `json:"objectRef"`
	ResponseStatus *struct {
		Code int `json:"code"`
	} `json:"responseStatus"`
	RequestReceivedTimestamp time.Time         `json:"requestReceivedTimestamp"`
	StageTimestamp           time.Time         `json:"stageTimestamp"`
	Annotations              map[string]string `json:"annotations"`
}

// Parse decodes audit events from r. It accepts an audit.k8s.io EventList (what
// the webhook backend sends), a single Event, or a stream of newline-delimited
// Events (what the log backend writes, and what CloudWatch exports produce
// after extracting each message). RequestReceived-stage events are dropped.
// On error nothing is returned, so callers can treat a payload atomically.
func Parse(r io.Reader) ([]Event, error) {
	dec := json.NewDecoder(r)
	var out []Event
	for {
		var w wireEvent
		err := dec.Decode(&w)
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("decode audit event: %w", err)
		}
		if w.Kind == "EventList" || w.Items != nil {
			for _, it := range w.Items {
				if e, ok := normalize(it); ok {
					out = append(out, e)
				}
			}
			continue
		}
		if e, ok := normalize(w); ok {
			out = append(out, e)
		}
	}
}

func normalize(w wireEvent) (Event, bool) {
	// RequestReceived duplicates every request; junk without a verb is not an event.
	if w.Stage == "RequestReceived" || w.Verb == "" {
		return Event{}, false
	}
	t := w.RequestReceivedTimestamp
	if t.IsZero() {
		t = w.StageTimestamp
	}
	e := Event{
		AuditID:    w.AuditID,
		Time:       t.UTC(),
		Stage:      w.Stage,
		Verb:       w.Verb,
		Username:   w.User.Username,
		Groups:     w.User.Groups,
		SourceIPs:  w.SourceIPs,
		UserAgent:  w.UserAgent,
		RequestURI: w.RequestURI,
		Decision:   w.Annotations["authorization.k8s.io/decision"],
	}
	e.ActorKind = actorKind(e.Username)
	// Key names vary with the authenticator; these are what aws-iam-authenticator
	// and EKS set. Best effort: absent keys simply leave the fields empty.
	if v := w.User.Extra["arn"]; len(v) > 0 {
		e.ARN = v[0]
	}
	if v := w.User.Extra["sessionName"]; len(v) > 0 {
		e.SessionName = v[0]
	}
	if w.ImpersonatedUser != nil {
		e.ImpersonatedUser = w.ImpersonatedUser.Username
	}
	if o := w.ObjectRef; o != nil {
		e.APIGroup, e.Resource, e.Subresource, e.Namespace, e.Name = o.APIGroup, o.Resource, o.Subresource, o.Namespace, o.Name
	}
	if w.ResponseStatus != nil {
		e.StatusCode = w.ResponseStatus.Code
	}
	e.Tags = Classify(e)
	return e, true
}

// actorKind classifies with the default prefixes; Ingester.Prepare applies
// configured ones.
func actorKind(username string) string {
	return ClassifyActor(username, DefaultSystemPrefixes)
}
