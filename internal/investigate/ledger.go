package investigate

import (
	"strings"
	"sync"
	"time"
)

// Evidence kinds, the prefix of each ref (web/src/types.ts EvidenceRef):
// signal:<id>, event:<uid>, log:<n>, logtpl:<n>, audit:<id>,
// cloudtrail:<id>, metric:<metric>:<label>.
const (
	KindSignal     = "signal"
	KindEvent      = "event"
	KindLog        = "log"
	KindLogTpl     = "logtpl"
	KindAudit      = "audit"
	KindCloudTrail = "cloudtrail"
	KindMetric     = "metric"
)

// Ledger records every ref shown to the model during a run, with what it
// pointed at: the digest's records first, then each tool result's. The
// report may cite only these; the stored evidence index is built from it.
// It is safe for concurrent use (parallel tool calls add to it).
type Ledger struct {
	mu      sync.Mutex
	entries map[string]int
	list    []Evidence
	// nextLog numbers the log lines tools return (log:<n>).
	nextLog int
}

// maxLedger bounds a run's ledger; refs past it are not recorded (and so
// cannot be cited as verified). A run shows far fewer: 24 tool calls of at
// most 200 records, plus the digest.
const maxLedger = 20000

// NewLedger returns an empty ledger.
func NewLedger() *Ledger { return &Ledger{entries: map[string]int{}} }

// Add records e (its snippet cut to 300 bytes); a ref seen before keeps its
// first entry.
func (l *Ledger) Add(e Evidence) {
	if e.Ref == "" {
		return
	}
	e.Snippet = cutText(e.Snippet, 300)
	e.Object = cutText(e.Object, 300)
	if !e.Time.IsZero() {
		e.Time = e.Time.UTC().Truncate(time.Second)
	}
	if e.Kind == "" {
		e.Kind, _, _ = strings.Cut(e.Ref, ":")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.entries[e.Ref]; ok || len(l.list) >= maxLedger {
		return
	}
	l.entries[e.Ref] = len(l.list)
	l.list = append(l.list, e)
}

// Has reports whether ref was shown.
func (l *Ledger) Has(ref string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.entries[ref]
	return ok
}

// Get returns ref's entry.
func (l *Ledger) Get(ref string) (Evidence, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	i, ok := l.entries[ref]
	if !ok {
		return Evidence{}, false
	}
	return l.list[i], true
}

// Len is the number of refs recorded.
func (l *Ledger) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.list)
}

// All returns the entries in the order they were first shown.
func (l *Ledger) All() []Evidence {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Evidence(nil), l.list...)
}

// logRefs reserves n log refs and returns the first number.
func (l *Ledger) logRefs(n int) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	first := l.nextLog + 1
	l.nextLog += n
	return first
}
