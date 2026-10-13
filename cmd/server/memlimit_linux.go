package main

// cgroupLimitFiles are where the container's memory limit is read from:
// cgroup v2, then v1.
var cgroupLimitFiles = []string{
	"/sys/fs/cgroup/memory.max",
	"/sys/fs/cgroup/memory/memory.limit_in_bytes",
}
