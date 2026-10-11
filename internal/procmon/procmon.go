// Package procmon reads per-process information from /proc, attributes each
// process to a Kubernetes pod through its cgroup path, and holds the latest
// snapshot from each node. It depends only on the standard library.
//
// What it collects: pid, parent pid, command name, redacted command line,
// resident memory, thread count and CPU. What it never collects: environment
// variables, open files, memory contents or anything from processes that are
// not inside a pod.
package procmon

import "time"

// Process is one process that belongs to a pod.
type Process struct {
	PID         int     `json:"pid"`
	PPID        int     `json:"ppid"`
	Name        string  `json:"name"`
	Cmdline     string  `json:"cmdline"` // redacted and truncated
	PodUID      string  `json:"podUID"`
	ContainerID string  `json:"containerID"` // runtime container ID, 64 hex characters
	RSSBytes    int64   `json:"rssBytes"`
	Threads     int     `json:"threads"`
	CPUMillis   float64 `json:"cpuMillicores"` // 1000 = one full core; 0 on the first sample
	CPUTicks    uint64  `json:"-"`
	startTicks  uint64
}

// Report is what an agent sends: one node's pod processes at one moment.
type Report struct {
	Node      string    `json:"node"`
	Time      time.Time `json:"time"`
	Processes []Process `json:"processes"`
	// Bytes is the size of the report as received, set by DecodeReport (the
	// compressed size when gzipped). It is not part of the wire format.
	Bytes int64 `json:"-"`
}
