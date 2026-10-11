package audit

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"time"
)

const maxLine = 16 << 20

// TailFile follows an audit log file (kube-apiserver --audit-log-path), calling
// handle for every complete line. It starts at the end of the file unless
// fromStart is set, waits for the file to appear, and reopens it from the start
// after rotation or truncation. handle must finish with the slice before it
// returns, because the buffer is reused. It returns when ctx is cancelled.
func TailFile(ctx context.Context, path string, fromStart bool, poll time.Duration, handle func(line []byte)) error {
	var (
		f       *os.File
		r       *bufio.Reader
		offset  int64
		pending []byte
		first   = true
	)
	defer func() {
		if f != nil {
			f.Close()
		}
	}()

	open := func(seekEnd bool) error {
		nf, err := os.Open(path)
		if err != nil {
			return err
		}
		offset = 0
		if seekEnd {
			if offset, err = nf.Seek(0, io.SeekEnd); err != nil {
				nf.Close()
				return err
			}
		}
		f = nf
		r = bufio.NewReaderSize(f, 1<<20)
		pending = pending[:0]
		return nil
	}

	for {
		if f == nil {
			if err := open(first && !fromStart); err != nil {
				if !sleep(ctx, poll) {
					return ctx.Err()
				}
				continue
			}
			first = false
		}

		line, err := r.ReadBytes('\n')
		offset += int64(len(line))
		pending = append(pending, line...)
		if len(pending) > maxLine {
			slog.Warn("dropping oversized audit log line", "bytes", len(pending))
			pending = pending[:0]
		}
		if err == nil {
			if trimmed := bytes.TrimSpace(pending); len(trimmed) > 0 {
				handle(trimmed)
			}
			pending = pending[:0]
			continue
		}
		if !errors.Is(err, io.EOF) {
			return err
		}

		// Caught up. Wait, then check for rotation or truncation.
		if !sleep(ctx, poll) {
			return ctx.Err()
		}
		cur, serr := os.Stat(path)
		if serr != nil {
			continue // briefly missing mid-rotation
		}
		mine, ferr := f.Stat()
		if ferr != nil || !os.SameFile(cur, mine) || cur.Size() < offset {
			f.Close()
			f = nil // the loop reopens the new file from its start
		}
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
