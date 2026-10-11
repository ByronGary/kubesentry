package firehose

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ByronGary/kubesentry/test/stress/internal/hist"
	"github.com/ByronGary/kubesentry/test/stress/internal/ks"
	"github.com/ByronGary/kubesentry/test/stress/internal/out"
)

// Options configure a firehose run.
type Options struct {
	Client     *ks.Client
	Ingest     *ks.Client  // where /audit/webhook is (default Client)
	AuditID    ks.Identity // webhook token
	APIID      ks.Identity // API token for queries
	Total      int
	Rate       float64 // events per second
	BatchSize  int
	Workers    int
	Namespaces int
	QueryReps  int
	QueryConc  int
	Seed       uint64
	Timeout    time.Duration
	MaxRun     time.Duration // stop sending after this long
	// IDsFile, if set, receives every distinct auditID that was accepted, one
	// per line, for checking the store afterwards (no loss, no duplicates).
	IDsFile    string
	MaxRetries int  // retries of a batch answered 503/429 with Retry-After (default 30)
	NoQueries  bool // only ingest: no Findings query during, no query phase after
}

// Result is audit.json.
type Result struct {
	Started        time.Time          `json:"started"`
	Seconds        float64            `json:"seconds"`
	TargetEvents   int                `json:"targetEvents"`
	TargetRate     float64            `json:"targetRate"`
	BatchSize      int                `json:"batchSize"`
	SentEvents     int64              `json:"sentEvents"`
	AcceptedEvents int64              `json:"acceptedEvents"`
	FailedBatches  int64              `json:"failedBatches"`
	AchievedRate   float64            `json:"achievedRate"` // accepted events per second
	PayloadBytes   int64              `json:"payloadBytes"`
	EventMix       map[string]int64   `json:"eventMix"`
	Ingest         []hist.RouteReport `json:"ingest"`
	DuringIngest   []hist.RouteReport `json:"queriesDuringIngest"`
	Queries        []hist.RouteReport `json:"queriesAfter"`
	StoreView      map[string]int     `json:"storeView"` // counts returned by the queries after ingest
	Stopped        string             `json:"stopped,omitempty"`
	Backpressure   int64              `json:"backpressureResponses"` // 503 or 429 with Retry-After, retried
	Retried        int64              `json:"retriedBatches"`
	GaveUp         int64              `json:"gaveUpBatches"`
	DistinctIDs    int                `json:"distinctAcceptedIDs,omitempty"`
}

// Queries run after the ingest, with a route name each.
var Queries = []struct{ Route, Path string }{
	{"events default (Findings)", "/api/v1/audit/events?since=24h&limit=500"},
	{"events Activity", "/api/v1/audit/events?since=24h&limit=200"},
	{"events tag=exec", "/api/v1/audit/events?since=24h&tag=exec&limit=200"},
	{"events tag=denied", "/api/v1/audit/events?since=24h&tag=denied&limit=200"},
	{"events user", "/api/v1/audit/events?since=24h&user=checkout.1%40corp.example&limit=200"},
	{"events namespace", "/api/v1/audit/events?since=24h&namespace=checkout-01&limit=200"},
	{"events all reads", "/api/v1/audit/events?since=24h&includeReads=true&actors=user,serviceaccount,system&limit=1000"},
	{"events 1h", "/api/v1/audit/events?since=1h&limit=200"},
	{"summary 24h", "/api/v1/audit/summary?since=24h"},
	{"summary 1h", "/api/v1/audit/summary?since=1h"},
}

// Run sends the events, then queries the store.
func Run(ctx context.Context, o Options) *Result {
	res := &Result{Started: time.Now().UTC(), TargetEvents: o.Total, TargetRate: o.Rate, BatchSize: o.BatchSize}
	gen := NewGen(o.Seed, o.Namespaces)
	ingest, during := hist.NewRecorder(), hist.NewRecorder()
	type batch struct {
		body []byte
		n    int
		ids  []string
	}
	if o.Ingest == nil {
		o.Ingest = o.Client
	}
	if o.MaxRetries == 0 {
		o.MaxRetries = 30
	}
	var idsMu sync.Mutex
	acceptedIDs := map[string]struct{}{}
	var backpressure, retried, gaveUp atomic.Int64
	batches := make(chan batch, 8)
	sendCtx, stopSend := context.WithCancel(ctx)
	defer stopSend()
	if o.MaxRun > 0 {
		var cancel context.CancelFunc
		sendCtx, cancel = context.WithTimeout(sendCtx, o.MaxRun)
		defer cancel()
	}

	// Producer, paced to the target rate.
	go func() {
		defer close(batches)
		start := time.Now()
		sent := 0
		for sent < o.Total {
			n := min(o.BatchSize, o.Total-sent)
			body, ids, err := gen.BatchIDs(n, time.Now())
			if err != nil {
				out.Logf("audit: marshal: %v", err)
				return
			}
			due := start.Add(time.Duration(float64(sent) / o.Rate * float64(time.Second)))
			if d := time.Until(due); d > 0 {
				select {
				case <-time.After(d):
				case <-sendCtx.Done():
					return
				}
			}
			select {
			case batches <- batch{body, n, ids}:
			case <-sendCtx.Done():
				return
			}
			sent += n
		}
	}()

	var sentEv, accepted, failed, bytes atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < o.Workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for b := range batches {
				var r ks.Response
				for attempt := 0; ; attempt++ {
					rctx, cancel := context.WithTimeout(ctx, o.Timeout)
					r = o.Ingest.Do(rctx, o.AuditID, http.MethodPost, "/audit/webhook", b.body, "application/json", true)
					cancel()
					oc := hist.Classify(r.Err, ctx.Err())
					ingest.Record("POST /audit/webhook", r.Status, int64(len(b.body)), r.Elapsed, oc, r.Err)
					bytes.Add(int64(len(b.body)))
					// Backpressure: the store's queue is full (e.g. Postgres is
					// down). Wait as told and send the same batch again.
					if r.Err == nil && (r.Status == http.StatusServiceUnavailable || r.Status == http.StatusTooManyRequests) && r.Header.Get("Retry-After") != "" {
						backpressure.Add(1)
						if attempt >= o.MaxRetries || ctx.Err() != nil {
							gaveUp.Add(1)
							break
						}
						if attempt == 0 {
							retried.Add(1)
						}
						wait, _ := strconv.Atoi(r.Header.Get("Retry-After"))
						select {
						case <-time.After(time.Duration(max(1, wait)) * time.Second):
						case <-ctx.Done():
						}
						continue
					}
					break
				}
				sentEv.Add(int64(b.n))
				var acc struct {
					Accepted int `json:"accepted"`
				}
				if r.Err == nil && r.Status == http.StatusOK && json.Unmarshal(r.Body, &acc) == nil {
					accepted.Add(int64(acc.Accepted))
					if o.IDsFile != "" {
						idsMu.Lock()
						for _, id := range b.ids {
							acceptedIDs[id] = struct{}{}
						}
						idsMu.Unlock()
					}
				} else {
					failed.Add(1)
				}
			}
		}()
	}

	// A dashboard user watching Findings while the firehose runs.
	duringDone := make(chan struct{})
	go func() {
		defer close(duringDone)
		if o.NoQueries {
			<-sendCtx.Done()
			return
		}
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-sendCtx.Done():
				return
			case <-t.C:
			}
			q := Queries[0]
			rctx, cancel := context.WithTimeout(sendCtx, o.Timeout)
			r := o.Client.Do(rctx, o.APIID, http.MethodGet, q.Path, nil, "", false)
			cancel()
			during.Record(q.Route, r.Status, r.Bytes, r.Elapsed, hist.Classify(r.Err, sendCtx.Err()), r.Err)
		}
	}()

	progress := time.NewTicker(10 * time.Second)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	start := time.Now()
loop:
	for {
		select {
		case <-done:
			break loop
		case <-progress.C:
			el := time.Since(start).Seconds()
			out.Logf("audit: %d sent, %d accepted (%.0f/s), %d failed batches", sentEv.Load(), accepted.Load(), float64(accepted.Load())/el, failed.Load())
		}
	}
	progress.Stop()
	if sendCtx.Err() != nil && ctx.Err() == nil && sentEv.Load() < int64(o.Total) {
		res.Stopped = "max run time reached"
	}
	stopSend()
	<-duringDone
	res.Seconds = time.Since(start).Seconds()
	res.SentEvents, res.AcceptedEvents, res.FailedBatches, res.PayloadBytes = sentEv.Load(), accepted.Load(), failed.Load(), bytes.Load()
	res.AchievedRate = float64(res.AcceptedEvents) / res.Seconds
	res.Backpressure, res.Retried, res.GaveUp = backpressure.Load(), retried.Load(), gaveUp.Load()
	if o.IDsFile != "" {
		var sb strings.Builder
		for id := range acceptedIDs {
			sb.WriteString(id)
			sb.WriteByte('\n')
		}
		res.DistinctIDs = len(acceptedIDs)
		if err := os.WriteFile(o.IDsFile, []byte(sb.String()), 0o644); err != nil {
			out.Logf("audit: write ids: %v", err)
		}
	}
	res.EventMix = gen.Counts
	res.Ingest, res.DuringIngest = ingest.Report(), during.Report()
	out.Logf("audit: done: %d accepted of %d sent in %.0fs (%.0f/s)", res.AcceptedEvents, res.SentEvents, res.Seconds, res.AchievedRate)

	if o.NoQueries {
		return res
	}
	// Query latency with the store full.
	qrec := hist.NewRecorder()
	res.StoreView = map[string]int{}
	var viewMu sync.Mutex
	for _, q := range Queries {
		var qwg sync.WaitGroup
		var next atomic.Int64
		for c := 0; c < max(1, o.QueryConc); c++ {
			qwg.Add(1)
			go func() {
				defer qwg.Done()
				for next.Add(1) <= int64(o.QueryReps) {
					rctx, cancel := context.WithTimeout(ctx, o.Timeout)
					r := o.Client.Do(rctx, o.APIID, http.MethodGet, q.Path, nil, "", true)
					cancel()
					qrec.Record(q.Route, r.Status, r.Bytes, r.Elapsed, hist.Classify(r.Err, ctx.Err()), r.Err)
					var body struct {
						Count int   `json:"count"`
						Users []any `json:"users"`
					}
					if r.Err == nil && json.Unmarshal(r.Body, &body) == nil {
						n := body.Count
						if n == 0 {
							n = len(body.Users)
						}
						viewMu.Lock()
						res.StoreView[q.Route] = n
						viewMu.Unlock()
					}
				}
			}()
		}
		qwg.Wait()
	}
	res.Queries = qrec.Report()
	for _, q := range res.Queries {
		out.Logf("audit query %-28s n=%d p50=%.0fms p95=%.0fms p99=%.0fms bytes=%d", q.Route, q.Requests, q.Completed.P50, q.Completed.P95, q.Completed.P99, q.MeanBytes)
	}
	return res
}
