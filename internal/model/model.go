// Package model holds the plain data types shared by the Kubernetes adapter,
// the Prometheus adapter, the detectors and the HTTP API. Keeping them free of
// client-go types means the detectors can be unit tested with the standard
// library alone.
package model

import (
	"errors"
	"time"
)

// ErrNotFound is returned by single-object lookups when the object does not exist.
var ErrNotFound = errors.New("not found")

// PVC is the subset of a PersistentVolumeClaim the detectors care about.
type PVC struct {
	Namespace     string    `json:"namespace"`
	Name          string    `json:"name"`
	StorageClass  string    `json:"storageClass"`
	Phase         string    `json:"phase"`
	CapacityBytes int64     `json:"capacityBytes"`
	VolumeName    string    `json:"volumeName,omitempty"`
	Created       time.Time `json:"created"`
}

// Pod is the subset of a Pod the detectors care about.
type Pod struct {
	UID        string // metadata.uid; links a pod to the processes a node agent sees
	Namespace  string
	Name       string
	Phase      string
	Claims     []string // PVC names mounted by this pod (same namespace)
	Containers []ContainerStatus

	NodeName       string
	Labels         map[string]string
	ServiceAccount string
	Created        time.Time
	HostPID        bool
	HostNetwork    bool
	HostIPC        bool
	HostPaths      []string // paths of hostPath volumes
	// AutomountToken is the effective automountServiceAccountToken. Unset on the
	// pod counts as true, because the service account default is not looked up.
	AutomountToken bool
	Specs          []ContainerSpec // containers, then init containers, from the pod spec

	// Owners are the pod's ownerReferences; the controller one has Controller set.
	Owners []OwnerRef
	// Ready is the pod's Ready condition; ReadyChanged is when it last flipped.
	Ready        bool
	ReadyChanged time.Time
	// Unschedulable carries the scheduler's message while PodScheduled is False.
	Unschedulable string
	DeletedAt     time.Time // deletionTimestamp; zero unless the pod is terminating
	PodIP         string
	QOSClass      string // Guaranteed, Burstable or BestEffort
}

// ContainerSpec is the security- and resource-relevant part of one container's
// spec, with the pod-level securityContext already applied as defaults.
type ContainerSpec struct {
	Name                     string
	Image                    string
	Init                     bool // init container, including native sidecars
	Privileged               bool
	AllowPrivilegeEscalation *bool // nil when not set
	RunAsNonRoot             bool  // effective runAsNonRoot is true
	RunAsUser                *int64
	ReadOnlyRootFilesystem   bool
	CapabilitiesAdd          []string
	CapabilitiesDropAll      bool
	CPURequestMilli          int64 // 0 when unset
	CPULimitMilli            int64
	MemoryRequestBytes       int64
	MemoryLimitBytes         int64
}

// ContainerStatus is the current state and most recent termination info for
// one container.
type ContainerStatus struct {
	Name                 string
	ContainerID          string // runtime ID without the "containerd://" style prefix
	RestartCount         int32
	LastTerminatedReason string // e.g. "OOMKilled", "Error", "Completed"
	LastTerminatedAt     time.Time
	LastExitCode         int32

	Init    bool // an init container or native sidecar
	Ready   bool
	Started bool
	// State is "running", "waiting" or "terminated"; Reason and Message explain
	// waiting and terminated states (CrashLoopBackOff, ImagePullBackOff, ...).
	State   string
	Reason  string
	Message string
	// MemoryLimitBytes is the limit the kubelet applied (status.resources), which
	// follows in-place resizes; 0 when unknown.
	MemoryLimitBytes int64
}

// OwnerRef is one ownerReference.
type OwnerRef struct {
	Kind       string
	Name       string
	UID        string
	Controller bool
}

// ContainerKey identifies one container of one pod.
type ContainerKey struct {
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Container string `json:"container"`
}

// Sample is one timestamped metric value.
type Sample struct {
	T time.Time
	V float64
}

// ContainerSeries is a time series for one container.
type ContainerSeries struct {
	Key     ContainerKey
	Samples []Sample
}
