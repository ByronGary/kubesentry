package model

import "time"

// KubeEvent is a core/v1 or events.k8s.io Event, trimmed to what incidents
// use. Events are watched separately from the inventory (they churn) and are
// never part of Inventory.
type KubeEvent struct {
	UID       string
	Namespace string
	Type      string // "Warning" or "Normal"
	Reason    string
	Message   string // truncated
	Count     int32  // series count, at least 1
	FirstSeen time.Time
	LastSeen  time.Time
	// Regarding is the involved object.
	Regarding ObjectRef
	// Source is the reporting component, e.g. "kubelet" or "default-scheduler".
	Source string
}

// ObjectRef names a Kubernetes object.
type ObjectRef struct {
	Kind      string
	Namespace string
	Name      string
	UID       string
}

// ServiceAccount is kept only for its IRSA role, which links CloudTrail
// activity to the workloads that run as it.
type ServiceAccount struct {
	Namespace string
	Name      string
	RoleARN   string // eks.amazonaws.com/role-arn
}

// TargetGroupBinding is an elbv2.k8s.aws TargetGroupBinding: it ties an AWS
// target group to a Service.
type TargetGroupBinding struct {
	Namespace      string
	Name           string
	TargetGroupARN string
	ServiceName    string
	ServicePort    string
}

// RateSample is a request rate for one subject at one instant: a pod or a
// Service, from one request source (an ingress, the app's own metrics, an ALB).
type RateSample struct {
	Source    string // profile name, e.g. "nginx", "app", "alb"
	Namespace string
	Pod       string // set for pod-level sources
	Service   string // set for service-level sources
	PerSecond float64
	// ErrorRatio is the share of requests that failed (5xx), when the source
	// reports status; -1 when unknown.
	ErrorRatio float64
}

// MemorySample is a container's working set at one instant.
type MemorySample struct {
	Namespace string
	Pod       string
	Container string
	Bytes     float64
}
