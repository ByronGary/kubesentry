package procmon

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	uidA = "6f1c2d3e-1111-4a5b-8c9d-0123456789ab"
	ctrA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	ctrB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func TestParseCgroup(t *testing.T) {
	under := strings.ReplaceAll(uidA, "-", "_")
	tests := []struct {
		name, in, uid, cid string
		ok                 bool
	}{
		{"systemd containerd v2", "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod" + under + ".slice/cri-containerd-" + ctrA + ".scope\n", uidA, ctrA, true},
		{"systemd crio guaranteed", "0::/kubepods.slice/kubepods-pod" + under + ".slice/crio-" + ctrB + ".scope\n", uidA, ctrB, true},
		{"cgroupfs v1", "12:memory:/kubepods/besteffort/pod" + uidA + "/" + ctrA + "\n1:name=systemd:/x\n", uidA, ctrA, true},
		{"docker systemd", "0::/kubepods.slice/kubepods-pod" + under + ".slice/docker-" + ctrA + ".scope", uidA, ctrA, true},
		{"pod sandbox only", "0::/kubepods.slice/kubepods-pod" + under + ".slice\n", uidA, "", true},
		{"relative to a private cgroup namespace", "0::/../../kubepods-burstable.slice/kubepods-burstable-pod" + under + ".slice/cri-containerd-" + ctrA + ".scope\n", uidA, ctrA, true},
		{"host process", "0::/system.slice/sshd.service\n", "", "", false},
		{"empty", "", "", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			uid, cid, ok := ParseCgroup(tc.in)
			if uid != tc.uid || cid != tc.cid || ok != tc.ok {
				t.Fatalf("got (%q, %q, %v), want (%q, %q, %v)", uid, cid, ok, tc.uid, tc.cid, tc.ok)
			}
		})
	}
}

func TestRedact(t *testing.T) {
	tests := []struct {
		in   []string
		want string
	}{
		{[]string{"app", "--port=8080"}, "app --port=8080"},
		{[]string{"db", "--password=hunter2"}, "db --password=***"},
		{[]string{"db", "--password", "hunter2", "--verbose"}, "db --password *** --verbose"},
		{[]string{"x", "API_KEY=abc123"}, "x API_KEY=***"},
		{[]string{"curl", "https://bob:s3cret@example.com/x"}, "curl https://bob:***@example.com/x"},
		{[]string{"x", "--auth-token:abc"}, "x --auth-token:***"},
	}
	for _, tc := range tests {
		if got := Redact(tc.in); got != tc.want {
			t.Errorf("Redact(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	long := Redact([]string{strings.Repeat("a", 2000)})
	if len([]rune(long)) > maxCmdline+1 {
		t.Errorf("not truncated: %d", len(long))
	}
}

func TestParseStatHandlesAwkwardNames(t *testing.T) {
	// comm contains spaces and a closing parenthesis.
	line := "42 (my (odd) app) S 7 42 42 0 -1 4194560 100 0 0 0 150 50 0 0 20 0 3 0 9999 1000 200 18446744073709551615"
	p, ok := parseStat(line)
	if !ok {
		t.Fatal("parse failed")
	}
	if p.Name != "my (odd) app" || p.PPID != 7 || p.CPUTicks != 200 || p.Threads != 3 || p.startTicks != 9999 {
		t.Fatalf("unexpected: %+v", p)
	}
	if _, ok := parseStat("garbage"); ok {
		t.Fatal("garbage parsed")
	}
}

func writeProc(t *testing.T, root string, pid int, cgroup, comm string, ticks int, rssPages int, cmd []string) {
	t.Helper()
	d := filepath.Join(root, itoa(pid))
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	stat := itoa(pid) + " (" + comm + ") S 1 1 1 0 -1 0 0 0 0 0 " + itoa(ticks) + " 0 0 0 20 0 2 0 500 0 0 0"
	files := map[string]string{
		"cgroup":  cgroup,
		"stat":    stat,
		"statm":   "1000 " + itoa(rssPages) + " 0 0 0 0 0",
		"cmdline": strings.Join(cmd, "\x00") + "\x00",
	}
	for n, c := range files {
		if err := os.WriteFile(filepath.Join(d, n), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

func TestScanOnlyReturnsPodProcessesAndNeverEnv(t *testing.T) {
	root := t.TempDir()
	podCg := "0::/kubepods.slice/kubepods-pod" + strings.ReplaceAll(uidA, "-", "_") + ".slice/cri-containerd-" + ctrA + ".scope\n"
	writeProc(t, root, 100, podCg, "java", 300, 25000, []string{"java", "-jar", "app.jar", "--db.password=x"})
	writeProc(t, root, 200, "0::/system.slice/sshd.service\n", "sshd", 10, 100, []string{"sshd"})
	// A secret-bearing environ file must never be opened or returned.
	if err := os.WriteFile(filepath.Join(root, "100", "environ"), []byte("TOKEN=abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "self"), nil, 0o644); err != nil { // non-dir entries are ignored
		t.Fatal(err)
	}

	got, err := Scan(ScanOptions{Root: root, PageSize: 4096})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 pod process, got %d: %+v", len(got), got)
	}
	p := got[0]
	if p.PID != 100 || p.PodUID != uidA || p.ContainerID != ctrA || p.Name != "java" {
		t.Fatalf("unexpected process: %+v", p)
	}
	if p.RSSBytes != 25000*4096 || p.Threads != 2 {
		t.Fatalf("memory/threads wrong: %+v", p)
	}
	if strings.Contains(p.Cmdline, "x") && !strings.Contains(p.Cmdline, "***") || strings.Contains(p.Cmdline, "password=x") {
		t.Fatalf("cmdline not redacted: %q", p.Cmdline)
	}
}

func TestScanMaxProcesses(t *testing.T) {
	root := t.TempDir()
	cg := "0::/kubepods.slice/kubepods-pod" + strings.ReplaceAll(uidA, "-", "_") + ".slice/cri-containerd-" + ctrA + ".scope\n"
	for pid := 1; pid <= 5; pid++ {
		writeProc(t, root, pid, cg, "p", 1, 1, []string{"p"})
	}
	got, _ := Scan(ScanOptions{Root: root, MaxProcesses: 3})
	if len(got) != 3 {
		t.Fatalf("got %d", len(got))
	}
}

func TestSamplerComputesMillicores(t *testing.T) {
	root := t.TempDir()
	cg := "0::/kubepods.slice/kubepods-pod" + strings.ReplaceAll(uidA, "-", "_") + ".slice/cri-containerd-" + ctrA + ".scope\n"
	writeProc(t, root, 7, cg, "busy", 1000, 10, []string{"busy"})
	now := time.Unix(1000, 0)
	s := &Sampler{Opts: ScanOptions{Root: root}, Now: func() time.Time { return now }}
	first, _ := s.Sample()
	if first[0].CPUMillis != 0 {
		t.Fatalf("first sample should have no CPU, got %v", first[0].CPUMillis)
	}
	// 50 ticks in 10 s = 0.5 CPU-seconds / 10 s = 50 millicores.
	writeProc(t, root, 7, cg, "busy", 1050, 10, []string{"busy"})
	now = now.Add(10 * time.Second)
	second, _ := s.Sample()
	if got := second[0].CPUMillis; got < 49.9 || got > 50.1 {
		t.Fatalf("want ~50 millicores, got %v", got)
	}
}

func TestStore(t *testing.T) {
	st := NewStore()
	at := time.Unix(5000, 0)
	st.Now = func() time.Time { return at }
	st.Update(Report{Node: "n1", Time: time.Unix(1, 0), Processes: []Process{
		{PID: 1, PodUID: uidA, RSSBytes: 10}, {PID: 2, PodUID: uidA, RSSBytes: 99}, {PID: 3, PodUID: "other"},
	}})
	v, ok := st.ForPod(uidA)
	if !ok || v.Node != "n1" || len(v.Processes) != 2 || v.Processes[0].PID != 2 {
		t.Fatalf("unexpected view: %+v ok=%v", v, ok)
	}
	if !v.ObservedAt.Equal(at) {
		t.Fatal("receive time should replace the agent's clock")
	}
	if _, ok := st.ForPod("missing"); ok {
		t.Fatal("unexpected hit")
	}
	st.Update(Report{Node: "n1"}) // a node's newer report replaces the old one
	if _, ok := st.ForPod(uidA); ok {
		t.Fatal("old report should be replaced")
	}
	if st.Nodes() != 1 {
		t.Fatal("node count")
	}
}
