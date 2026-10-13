package main

import (
	"os"
	"runtime/debug"
	"strconv"
	"strings"
)

// cgroupLimitFiles (memlimit_linux.go) are where the container's memory
// limit is read from. Elsewhere there are none, and setMemoryLimit does
// nothing.

// memLimitFraction leaves room for memory the Go runtime does not manage
// (stacks, cgo, the kernel's page cache charged to the cgroup).
const memLimitFraction = 0.9

// setMemoryLimit sets the Go soft memory limit to 90% of the container's
// memory limit, so the GC works harder before the kernel OOM-kills the
// process. A GOMEMLIMIT in the environment wins (the Go runtime has already
// applied it). It returns the limit set, or 0.
func setMemoryLimit() int64 {
	if os.Getenv("GOMEMLIMIT") != "" {
		return 0
	}
	limit := cgroupMemoryLimit(cgroupLimitFiles)
	if limit <= 0 {
		return 0
	}
	soft := int64(float64(limit) * memLimitFraction)
	debug.SetMemoryLimit(soft)
	return soft
}

// cgroupMemoryLimit returns the first limit found in files, or 0 when there
// is none ("max", unreadable, or v1's "unlimited" sentinel).
func cgroupMemoryLimit(files []string) int64 {
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		s := strings.TrimSpace(string(b))
		if s == "max" {
			return 0
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n <= 0 {
			continue
		}
		// cgroup v1 reports "no limit" as a huge page-rounded number.
		if n >= 1<<60 {
			return 0
		}
		return n
	}
	return 0
}
