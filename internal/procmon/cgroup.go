package procmon

import (
	"regexp"
	"strings"
)

var (
	// Pod UIDs appear as pod<uid> (cgroupfs) or pod<uid with underscores> (systemd driver).
	podRe       = regexp.MustCompile(`pod([0-9a-f]{8}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{12})`)
	containerRe = regexp.MustCompile(`(?:^|[/-])([0-9a-f]{64})(?:\.scope)?(?:/|$)`)
)

// ParseCgroup extracts the pod UID and container ID from the contents of
// /proc/<pid>/cgroup. ok is false for processes outside any pod. Handles
// cgroup v1 and v2, the systemd and cgroupfs drivers, and containerd, CRI-O
// and Docker path styles.
func ParseCgroup(content string) (podUID, containerID string, ok bool) {
	for _, line := range strings.Split(content, "\n") {
		// "hierarchy-ID:controllers:path"; the path may itself contain colons rarely.
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		path := parts[2]
		m := podRe.FindStringSubmatch(path)
		if m == nil {
			continue
		}
		uid := strings.ReplaceAll(m[1], "_", "-")
		var cid string
		if cm := containerRe.FindAllStringSubmatch(path, -1); len(cm) > 0 {
			cid = cm[len(cm)-1][1]
		}
		return uid, cid, true
	}
	return "", "", false
}
