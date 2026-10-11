package procmon

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const clockTicksPerSec = 100 // USER_HZ is 100 on every Linux platform Kubernetes supports

// ScanOptions configures Scan.
type ScanOptions struct {
	Root         string // procfs mount, default /proc
	PageSize     int    // default os.Getpagesize()
	MaxProcesses int    // default 5000; extra processes are dropped
}

func (o *ScanOptions) defaults() {
	if o.Root == "" {
		o.Root = "/proc"
	}
	if o.PageSize == 0 {
		o.PageSize = os.Getpagesize()
	}
	if o.MaxProcesses == 0 {
		o.MaxProcesses = 5000
	}
}

// Scan lists the processes that belong to pods. Processes that exit while
// being read, or that cannot be read, are skipped.
func Scan(opts ScanOptions) ([]Process, error) {
	opts.defaults()
	entries, err := os.ReadDir(opts.Root)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", opts.Root, err)
	}
	out := []Process{}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || !e.IsDir() {
			continue
		}
		p, ok := readProcess(filepath.Join(opts.Root, e.Name()), pid, opts.PageSize)
		if !ok {
			continue
		}
		out = append(out, p)
		if len(out) >= opts.MaxProcesses {
			break
		}
	}
	return out, nil
}

func readProcess(dir string, pid, pageSize int) (Process, bool) {
	cg, err := os.ReadFile(filepath.Join(dir, "cgroup"))
	if err != nil {
		return Process{}, false
	}
	uid, cid, ok := ParseCgroup(string(cg))
	if !ok {
		return Process{}, false // not in a pod: never collected
	}
	stat, err := os.ReadFile(filepath.Join(dir, "stat"))
	if err != nil {
		return Process{}, false
	}
	p, ok := parseStat(string(stat))
	if !ok {
		return Process{}, false
	}
	p.PID, p.PodUID, p.ContainerID = pid, uid, cid
	if statm, err := os.ReadFile(filepath.Join(dir, "statm")); err == nil {
		f := strings.Fields(string(statm))
		if len(f) >= 2 {
			if pages, err := strconv.ParseInt(f[1], 10, 64); err == nil {
				p.RSSBytes = pages * int64(pageSize)
			}
		}
	}
	if cmd, err := os.ReadFile(filepath.Join(dir, "cmdline")); err == nil && len(cmd) > 0 {
		args := strings.Split(strings.TrimRight(string(cmd), "\x00"), "\x00")
		p.Cmdline = Redact(args)
	}
	return p, true
}

// parseStat reads /proc/<pid>/stat. The command name sits in parentheses and
// may itself contain spaces and parentheses, so fields are counted after the
// last ')'.
func parseStat(s string) (Process, bool) {
	open, closeIdx := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
	if open < 0 || closeIdx < open {
		return Process{}, false
	}
	f := strings.Fields(s[closeIdx+1:])
	// Field n of proc(5) is f[n-3]: ppid=4, utime=14, stime=15, num_threads=20, starttime=22.
	if len(f) < 20 {
		return Process{}, false
	}
	num := func(i int) uint64 { v, _ := strconv.ParseUint(f[i], 10, 64); return v }
	ppid, _ := strconv.Atoi(f[1])
	return Process{
		PPID:       ppid,
		Name:       s[open+1 : closeIdx],
		CPUTicks:   num(11) + num(12),
		Threads:    int(num(17)),
		startTicks: num(19),
	}, true
}

// Sampler turns cumulative CPU ticks into millicores by comparing scans.
type Sampler struct {
	Opts ScanOptions
	Now  func() time.Time
	prev map[[2]uint64]sample
}

type sample struct {
	ticks uint64
	at    time.Time
}

// Sample scans and fills CPUMillis from the previous call. The first call has no
// baseline, so CPUMillis is 0 everywhere.
func (s *Sampler) Sample() ([]Process, error) {
	procs, err := Scan(s.Opts)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if s.Now != nil {
		now = s.Now()
	}
	next := make(map[[2]uint64]sample, len(procs))
	for i := range procs {
		p := &procs[i]
		// pid + start time identifies a process even after pid reuse.
		key := [2]uint64{uint64(p.PID), p.startTicks}
		if old, ok := s.prev[key]; ok && p.CPUTicks >= old.ticks {
			if dt := now.Sub(old.at).Seconds(); dt > 0 {
				p.CPUMillis = float64(p.CPUTicks-old.ticks) / clockTicksPerSec / dt * 1000
			}
		}
		next[key] = sample{ticks: p.CPUTicks, at: now}
	}
	s.prev = next
	return procs, nil
}
