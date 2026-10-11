package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"
)

const maxJournalLine = 16 << 20

// Journal appends normalized events to a JSONL file so history survives a
// restart. This matters in webhook mode, where the API server sends each event
// once. It is not rotated: point it at a volume you manage.
type Journal struct {
	mu  sync.Mutex
	f   *os.File
	enc *json.Encoder
}

func OpenJournal(path string) (*Journal, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit journal: %w", err)
	}
	return &Journal{f: f, enc: json.NewEncoder(f)}, nil
}

func (j *Journal) Append(events []Event) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, e := range events {
		if err := j.enc.Encode(e); err != nil {
			return fmt.Errorf("write audit journal: %w", err)
		}
	}
	return nil
}

func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.f.Close()
}

// LoadJournal replays a journal into store and returns the number of events
// read. A missing file is not an error. Malformed lines are skipped, since a
// crash can leave a truncated final line.
func LoadJournal(path string, store *MemoryStore) (int, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("open audit journal: %w", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), maxJournalLine)
	n := 0
	for sc.Scan() {
		var e Event
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue
		}
		store.Add(e)
		n++
	}
	return n, sc.Err()
}
