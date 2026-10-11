package audit

import (
	"bytes"
	"io"
	"log/slog"
)

// Ingester parses incoming audit payloads, stores them and, if configured,
// journals them. It is the single entry point for the webhook and file tailer.
type Ingester struct {
	Store   *MemoryStore
	Journal *Journal // optional
}

// IngestReader ingests one payload (EventList, Event or NDJSON) and returns the
// number of events accepted. Nothing is stored if the payload is malformed.
func (in *Ingester) IngestReader(r io.Reader) (int, error) {
	events, err := Parse(r)
	if err != nil {
		return 0, err
	}
	if len(events) == 0 {
		return 0, nil
	}
	in.Store.Add(events...)
	if in.Journal != nil {
		if err := in.Journal.Append(events); err != nil {
			// The event is already queryable; losing durability is worth a log, not a failed request.
			slog.Error("audit journal write failed", "err", err)
		}
	}
	return len(events), nil
}

// IngestLine ingests one line from a tailed log file. Bad lines are logged and
// skipped so one corrupt entry cannot stall the tailer.
func (in *Ingester) IngestLine(line []byte) {
	if _, err := in.IngestReader(bytes.NewReader(line)); err != nil {
		slog.Warn("skipping unparseable audit line", "err", err)
	}
}

// Query lets the Ingester satisfy the API's backend interface.
func (in *Ingester) Query(q Query) []Event { return in.Store.Query(q) }
