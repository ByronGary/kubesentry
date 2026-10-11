package demo

import (
	"context"
	"math"
	"time"

	"github.com/ByronGary/kubesentry/internal/procmon"
)

const mebibyte = int64(1) << 20

// proc describes one synthetic process in a container.
type proc struct {
	name, cmd string
	rssMiB    int64
	cpu       float64 // millicores
	threads   int
	child     bool // child of the container's first process
}

// processesByContainer is the demo script. Pods and containers not listed get
// a single plausible process named after the container.
var processesByContainer = map[string][]proc{
	"prod/checkout-api-7d9f8b6c4-x2k9p/api": {
		{"node", "node /app/server.js --port=8080", 120, 180, 11, false},
		{"node", "node /app/worker.js --queue=thumbnails", 70, 40, 8, true},
		{"image-resize", "image-resize --watch /tmp/uploads", 78, 15, 2, true}, // the one that keeps growing
	},
	"prod/checkout-api-7d9f8b6c4-x2k9p/envoy": {
		{"envoy", "envoy -c /etc/envoy/envoy.yaml --service-cluster checkout", 380, 90, 24, false},
	},
	"prod/payments-worker-5c6d7f9b8-q8wzn/worker": {
		{"java", "java -Xmx900m -jar /opt/worker.jar --db.password=hunter2 --queue=payments", 740, 260, 41, false},
	},
	"prod/postgres-0/postgres": {
		{"postgres", "postgres -D /var/lib/postgresql/data", 410, 70, 1, false},
		{"postgres", "postgres: checkpointer", 35, 4, 1, true},
		{"postgres", "postgres: autovacuum launcher", 12, 1, 1, true},
	},
}

// Processes builds one synthetic report per node from the demo cluster, as
// the agents on those nodes would. The values move a little on each call so
// the page looks alive.
func Processes(c *Cluster, now time.Time) []procmon.Report {
	wobble := math.Sin(float64(now.Unix()) / 20)
	reports := map[string]*procmon.Report{}
	var order []string
	pids := map[string]int{}
	for _, p := range c.pods {
		if p.Phase != "Running" || p.NodeName == "" {
			continue
		}
		rep := reports[p.NodeName]
		if rep == nil {
			rep = &procmon.Report{Node: p.NodeName, Time: now, Processes: []procmon.Process{}}
			reports[p.NodeName] = rep
			order = append(order, p.NodeName)
			pids[p.NodeName] = 100
		}
		pid := pids[p.NodeName] + 1
		rep.Processes = append(rep.Processes, procmon.Process{
			PID: pid, PPID: 1, Name: "pause", Cmdline: "/pause", PodUID: p.UID, RSSBytes: 1 * mebibyte, Threads: 1,
		})
		for _, ctr := range p.Containers {
			script, ok := processesByContainer[p.Namespace+"/"+p.Name+"/"+ctr.Name]
			if !ok {
				script = []proc{{ctr.Name, ctr.Name, 90, 25, 6, false}}
			}
			var parent int
			for i, sp := range script {
				pid++
				if i == 0 {
					parent = pid
				}
				ppid := 1
				if sp.child {
					ppid = parent
				}
				rep.Processes = append(rep.Processes, procmon.Process{
					PID: pid, PPID: ppid, Name: sp.name, Cmdline: procmon.Redact(splitArgs(sp.cmd)), PodUID: p.UID,
					ContainerID: ctr.ContainerID, RSSBytes: (sp.rssMiB + int64(wobble*3)) * mebibyte,
					Threads: sp.threads, CPUMillis: math.Max(0, sp.cpu*(1+0.15*wobble)),
				})
			}
		}
		pids[p.NodeName] = pid
	}
	out := make([]procmon.Report, 0, len(order))
	for _, n := range order {
		out = append(out, *reports[n])
	}
	return out
}

func splitArgs(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ' ' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

// KeepFresh refreshes the synthetic report until ctx ends, as a real agent would.
func KeepFresh(ctx context.Context, st *procmon.Store, c *Cluster, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			for _, r := range Processes(c, now) {
				st.Update(r)
			}
		}
	}
}
