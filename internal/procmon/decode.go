package procmon

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Errors from DecodeReport, for choosing the HTTP status.
var (
	ErrTooLarge            = errors.New("report too large")             // 413
	ErrUnsupportedEncoding = errors.New("unsupported content encoding") // 415
	ErrInvalidReport       = errors.New("invalid report")               // 400
)

// DefaultMaxProcesses is the most processes DecodeReport accepts in one
// report: the store's default per-node cap.
const DefaultMaxProcesses = 20000

// DecodeReport reads an agent's report from the request body, plain JSON or
// gzip (Content-Encoding: gzip). maxBytes caps both the bytes read off the
// wire and the decompressed JSON, so a small compressed body cannot expand
// without bound. A report with more than DefaultMaxProcesses processes is
// ErrTooLarge. The returned report's Bytes is the size received.
func DecodeReport(r *http.Request, maxBytes int64) (Report, error) {
	return DecodeReportMax(r, maxBytes, DefaultMaxProcesses)
}

// DecodeReportMax is DecodeReport with a process limit. The process list is
// decoded one element at a time and decoding stops with ErrTooLarge at the
// first process beyond maxProcesses, so a body of millions of tiny entries
// ("[{},{},...]") never becomes millions of structs.
func DecodeReportMax(r *http.Request, maxBytes int64, maxProcesses int) (Report, error) {
	wire := &capReader{r: r.Body, left: maxBytes}
	var body io.Reader = wire
	switch enc := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding"))); enc {
	case "", "identity":
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(wire)
		if err != nil {
			return Report{}, classify(err)
		}
		defer zr.Close()
		body = &capReader{r: zr, left: maxBytes}
	default:
		return Report{}, fmt.Errorf("%w: %q", ErrUnsupportedEncoding, enc)
	}

	if maxProcesses <= 0 {
		maxProcesses = DefaultMaxProcesses
	}
	dec := json.NewDecoder(body)
	rep, err := decodeReport(dec, maxProcesses)
	if err != nil {
		return Report{}, classify(err)
	}
	// Drain the rest so gzip's checksum is verified and trailing junk is refused.
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			err = errors.New("data after the report")
		}
		return Report{}, classify(err)
	}
	rep.Bytes = wire.read
	return rep, nil
}

// decodeReport reads one report object. The processes array is streamed
// with a limit; every other member is decoded as encoding/json would
// (case-insensitive names, the last duplicate wins, unknown ones ignored).
func decodeReport(dec *json.Decoder, maxProcesses int) (Report, error) {
	if err := expectDelim(dec, '{'); err != nil {
		return Report{}, err
	}
	var rep Report
	rest := map[string]json.RawMessage{}
	seen := false
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return Report{}, err
		}
		key, _ := tok.(string)
		if strings.EqualFold(key, "processes") {
			if seen {
				return Report{}, errors.New("processes given twice")
			}
			seen = true
			if rep.Processes, err = decodeProcesses(dec, maxProcesses); err != nil {
				return Report{}, err
			}
			continue
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return Report{}, err
		}
		rest[key] = raw
	}
	if err := expectDelim(dec, '}'); err != nil {
		return Report{}, err
	}
	if len(rest) > 0 {
		// Only the fields besides the processes, so no other spelling of
		// "processes" can bypass the limit.
		var head struct {
			Node string    `json:"node"`
			Time time.Time `json:"time"`
		}
		b, err := json.Marshal(rest)
		if err != nil {
			return Report{}, err
		}
		if err := json.Unmarshal(b, &head); err != nil {
			return Report{}, err
		}
		rep.Node, rep.Time = head.Node, head.Time
	}
	return rep, nil
}

// decodeProcesses reads a JSON array (or null) of processes, failing with
// ErrTooLarge before decoding the element after the max-th.
func decodeProcesses(dec *json.Decoder, max int) ([]Process, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if tok == nil {
		return nil, nil
	}
	if d, ok := tok.(json.Delim); !ok || d != '[' {
		return nil, errors.New("processes is not an array")
	}
	procs := make([]Process, 0, min(max, 256))
	for dec.More() {
		if len(procs) >= max {
			return nil, fmt.Errorf("%w: more than %d processes", ErrTooLarge, max)
		}
		var p Process
		if err := dec.Decode(&p); err != nil {
			return nil, err
		}
		procs = append(procs, p)
	}
	return procs, expectDelim(dec, ']')
}

func expectDelim(dec *json.Decoder, want json.Delim) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != want {
		return fmt.Errorf("expected %q, got %v", want, tok)
	}
	return nil
}

func classify(err error) error {
	var tooBig *http.MaxBytesError
	if errors.Is(err, ErrTooLarge) || errors.As(err, &tooBig) {
		return ErrTooLarge
	}
	return fmt.Errorf("%w: %v", ErrInvalidReport, err)
}

// capReader fails with ErrTooLarge once more than left bytes are read, and
// counts what it read.
type capReader struct {
	r    io.Reader
	left int64
	read int64
}

func (c *capReader) Read(p []byte) (int, error) {
	if c.left < 0 {
		return 0, ErrTooLarge
	}
	if int64(len(p)) > c.left+1 {
		p = p[:c.left+1]
	}
	n, err := c.r.Read(p)
	c.read += int64(n)
	c.left -= int64(n)
	if c.left < 0 {
		return n, ErrTooLarge
	}
	return n, err
}
