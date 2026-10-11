package audit

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"time"
)

// ErrLeadershipLost is wrapped by writers that only commit while holding a
// lease (pgstore's Leader) once the lease is gone. Pollers such as the
// CloudWatch reader stop on it instead of retrying, so another replica takes
// over.
var ErrLeadershipLost = errors.New("audit: leadership lost")

// Ingester parses incoming audit payloads, stores them and, if configured,
// journals them. It is the single entry point for the webhook and file tailer.
type Ingester struct {
	Store   *MemoryStore
	Journal *Journal // optional

	// Backend, when set, receives the events instead of Store, and Query reads
	// from it. Use it for the Postgres store (or MemoryStore.AsStore()). Its
	// ErrBackpressure is returned by IngestReader unchanged, so the webhook can
	// answer 503 with Retry-After.
	Backend Store
	// SystemPrefixes classify usernames as actor kind "system" at ingest
	// (e.g. "system:", "eks:"). Empty means DefaultSystemPrefixes.
	SystemPrefixes []string
	// RedactExecArgs strips exec command arguments from request URIs before
	// they are stored (see RedactExecArgs).
	RedactExecArgs bool
	// BackpressureWait bounds how long IngestLine keeps retrying a line the
	// Backend refuses with ErrBackpressure before dropping it. Default 2m.
	BackpressureWait time.Duration
}

// Active returns the Store that ingestion writes to and queries read from:
// Backend when set, otherwise Store through MemoryStore.AsStore. Nil when
// neither is set.
func (in *Ingester) Active() Store {
	if in.Backend != nil {
		return in.Backend
	}
	if in.Store != nil {
		return in.Store.AsStore()
	}
	return nil
}

// Prepare applies the ingest-time policy to parsed events in place: actor
// kinds from SystemPrefixes and, when enabled, exec argument redaction. The
// CloudWatch reader calls it so every source stores events alike.
func (in *Ingester) Prepare(events []Event) {
	prefixes := in.SystemPrefixes
	if len(prefixes) == 0 {
		prefixes = DefaultSystemPrefixes
	}
	for i := range events {
		e := &events[i]
		e.ActorKind = ClassifyActor(e.Username, prefixes)
		if in.RedactExecArgs && e.Subresource == "exec" {
			e.RequestURI = RedactExecArgs(e.RequestURI)
		}
	}
}

// IngestReader ingests one payload (EventList, Event or NDJSON) and returns the
// number of events accepted. Nothing is stored if the payload is malformed.
func (in *Ingester) IngestReader(r io.Reader) (int, error) {
	return in.Ingest(context.Background(), r)
}

// Ingest is IngestReader with a context for the Backend write. With a Backend
// it returns ErrBackpressure (unwrapped) when the store's queue is full.
func (in *Ingester) Ingest(ctx context.Context, r io.Reader) (int, error) {
	events, err := Parse(r)
	if err != nil {
		return 0, err
	}
	if len(events) == 0 {
		return 0, nil
	}
	in.Prepare(events)
	if in.Backend != nil {
		if err := in.Backend.Add(ctx, events); err != nil {
			return 0, err
		}
	} else {
		in.Store.Add(events...)
	}
	if in.Journal != nil {
		if err := in.Journal.Append(events); err != nil {
			// The event is already queryable; losing durability is worth a log, not a failed request.
			slog.Error("audit journal write failed", "err", err)
		}
	}
	return len(events), nil
}

// IngestLine ingests one line from a tailed log file. Bad lines are logged and
// skipped so one corrupt entry cannot stall the tailer. When the Backend is
// busy the line is retried with backoff (the file is the buffer) for up to
// BackpressureWait, then dropped with an error log.
func (in *Ingester) IngestLine(line []byte) {
	wait := in.BackpressureWait
	if wait <= 0 {
		wait = 2 * time.Minute
	}
	deadline := time.Now().Add(wait)
	backoff := 50 * time.Millisecond
	for {
		_, err := in.IngestReader(bytes.NewReader(line))
		if err == nil {
			return
		}
		if !errors.Is(err, ErrBackpressure) {
			slog.Warn("skipping audit line", "err", err)
			return
		}
		if time.Now().After(deadline) {
			slog.Error("dropping audit line: store stayed busy", "waited", wait)
			return
		}
		time.Sleep(backoff)
		if backoff < 2*time.Second {
			backoff *= 2
		}
	}
}

// Query lets the Ingester satisfy the API's backend interface. With a Backend,
// errors are logged and yield no events.
func (in *Ingester) Query(q Query) []Event {
	if in.Backend != nil {
		events, err := in.Backend.Query(context.Background(), q)
		if err != nil {
			slog.Error("audit query failed", "err", err)
			return []Event{}
		}
		return events
	}
	return in.Store.Query(q)
}
