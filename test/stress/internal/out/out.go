// Package out writes harness results: JSON documents and markdown next to each
// other in one results directory per run.
package out

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

// WriteJSON writes v as indented JSON to dir/name, creating dir.
func WriteJSON(dir, name string, v any) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name), append(b, '\n'), 0o644)
}

// WriteText writes s to dir/name, creating dir.
func WriteText(dir, name, s string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name), []byte(s), 0o644)
}

// ReadJSON decodes dir/name into v.
func ReadJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// Logf logs with a timestamp prefix; harness jobs stream these lines.
func Logf(format string, args ...any) {
	log.Printf(format, args...)
}

// Must exits on error.
func Must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// Stamp is a sortable UTC timestamp for file names.
func Stamp(t time.Time) string { return t.UTC().Format("20060102T150405Z") }

// Ms converts a duration to float milliseconds.
func Ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
