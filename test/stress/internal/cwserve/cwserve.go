// Package cwserve hosts kubesentry's CloudWatch Logs fake (cwfake) in the
// cluster and checks, against Postgres, that every event it serves was stored
// exactly once.
package cwserve

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/ByronGary/kubesentry/internal/cloudwatch/cwfake"
	"github.com/ByronGary/kubesentry/test/stress/internal/out"
)

// Options describe the fake log group. The same options give the same events.
type Options struct {
	Listen     string
	LogGroup   string
	Events     int64
	Rate       float64
	Start      time.Time
	Duplicates float64
	Late       float64
	Seed       int64
}

// FakeOptions converts to cwfake's options.
func (o Options) FakeOptions() cwfake.Options {
	return cwfake.Options{Seed: o.Seed, LogGroup: o.LogGroup, Start: o.Start, Rate: o.Rate, Events: o.Events,
		DuplicateFraction: o.Duplicates, LateFraction: o.Late}
}

// Serve runs the fake and a /truth endpoint describing it.
func Serve(ctx context.Context, o Options) error {
	f := cwfake.New(o.FakeOptions())
	mux := http.NewServeMux()
	mux.Handle("/", f)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ok") })
	mux.HandleFunc("/truth", func(w http.ResponseWriter, _ *http.Request) {
		end := f.Time(o.Events - 1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"options": o, "first": f.Time(0), "last": end, "requests": f.Requests(), "served": f.Served(), "throttled": f.Throttled(),
		})
	})
	srv := &http.Server{Addr: o.Listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { <-ctx.Done(); _ = srv.Close() }()
	out.Logf("cwfake: %d events at %.0f/s from %s, group %s, on %s", o.Events, o.Rate, o.Start.Format(time.RFC3339), o.LogGroup, o.Listen)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// Result is cloudwatch.json.
type Result struct {
	Checked      time.Time `json:"checked"`
	Expected     int64     `json:"expectedEvents"` // events whose time has passed (visible by now)
	Found        int64     `json:"found"`
	Missing      int64     `json:"missing"`
	Duplicated   int64     `json:"duplicated"` // audit IDs stored more than once
	MissingIDs   []string  `json:"missingSample,omitempty"`
	DupIDs       []string  `json:"duplicatedSample,omitempty"`
	NewestStored time.Time `json:"newestStored"`
	LagSeconds   float64   `json:"lagSeconds"` // now - the newest cwfake event stored (the live tail's lag)
	Complete     bool      `json:"complete"`   // every event of the group has its time in the past
}

// Verify compares the events cwfake has made visible with the rows in
// Postgres, read through kubectl exec into the Postgres pod (host side).
//
// window, if positive, checks only the events of the last window (an endless
// tail grows without bound: every expected ID is held in memory).
func Verify(ctx context.Context, o Options, kubeContext, pgNamespace, pgPod, schema string, grace, window time.Duration) (*Result, error) {
	f := cwfake.New(o.FakeOptions())
	now := time.Now()
	res := &Result{Checked: now.UTC()}
	// Events become visible a little after their time; leave a grace period.
	cut := now.Add(-grace)
	_, hi := f.Range(f.Time(0), cut)
	lo := int64(0)
	if window > 0 {
		lo, _ = f.Range(now.Add(-window), cut)
	}
	res.Expected = hi - lo
	res.Complete = o.Events > 0 && hi >= o.Events
	first, last := f.Time(lo), f.Time(max(lo, hi-1))
	q := fmt.Sprintf(`COPY (SELECT audit_id, count(*), max(time) FROM %s.audit_events WHERE time >= '%s' AND time <= '%s' GROUP BY audit_id) TO STDOUT`,
		schema, first.Format(time.RFC3339Nano), last.Add(time.Second).Format(time.RFC3339Nano))
	cmd := exec.CommandContext(ctx, "kubectl", "--context", kubeContext, "-n", pgNamespace, "exec", pgPod, "--",
		"psql", "-U", "kubesentry", "-d", "kubesentry", "-At", "-c", q)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	type row struct {
		n int
		t time.Time
	}
	stored := make(map[string]row, hi)
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		parts := strings.Split(sc.Text(), "\t")
		if len(parts) < 3 {
			continue
		}
		n, _ := strconv.Atoi(parts[1])
		t, _ := time.Parse("2006-01-02 15:04:05.999999-07", parts[2])
		stored[parts[0]] = row{n, t}
	}
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("psql: %v: %s", err, stderr.String())
	}
	for i := lo; i < hi; i++ {
		id := f.AuditID(i)
		r, ok := stored[id]
		switch {
		case !ok:
			res.Missing++
			if len(res.MissingIDs) < 10 {
				res.MissingIDs = append(res.MissingIDs, fmt.Sprintf("%d:%s@%s", i, id, f.Time(i).Format(time.RFC3339)))
			}
		default:
			res.Found++
			if r.n > 1 {
				res.Duplicated++
				if len(res.DupIDs) < 10 {
					res.DupIDs = append(res.DupIDs, id)
				}
			}
			if r.t.After(res.NewestStored) {
				res.NewestStored = r.t
			}
		}
	}
	// The live tail: the newest cwfake event stored at all (also inside the
	// grace period) gives the reader's lag behind real time.
	_, hiNow := f.Range(f.Time(0), now)
	if hiNow > hi {
		q2 := fmt.Sprintf(`COPY (SELECT DISTINCT audit_id FROM %s.audit_events WHERE time > '%s' AND time <= '%s') TO STDOUT`,
			schema, f.Time(hi).Add(-time.Second).Format(time.RFC3339Nano), now.Add(time.Second).Format(time.RFC3339Nano))
		out, err := exec.CommandContext(ctx, "kubectl", "--context", kubeContext, "-n", pgNamespace, "exec", pgPod, "--",
			"psql", "-U", "kubesentry", "-d", "kubesentry", "-At", "-c", q2).Output()
		if err == nil {
			recent := map[string]bool{}
			for _, l := range strings.Split(string(out), "\n") {
				recent[strings.TrimSpace(l)] = true
			}
			for i := hiNow - 1; i >= hi; i-- {
				if recent[f.AuditID(i)] {
					if t := f.Time(i); t.After(res.NewestStored) {
						res.NewestStored = t
					}
					break
				}
			}
		}
	}
	if !res.NewestStored.IsZero() {
		res.LagSeconds = now.Sub(res.NewestStored).Seconds()
	}
	return res, nil
}
