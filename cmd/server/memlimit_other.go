//go:build !linux

package main

// cgroupLimitFiles is empty outside Linux (macOS, Windows): there is no
// cgroup memory limit to follow, so setMemoryLimit leaves GOMEMLIMIT alone.
var cgroupLimitFiles []string
