package procmon

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Errors from DecodeReport, for choosing the HTTP status.
var (
	ErrTooLarge            = errors.New("report too large")             // 413
	ErrUnsupportedEncoding = errors.New("unsupported content encoding") // 415
	ErrInvalidReport       = errors.New("invalid report")               // 400
)

// DecodeReport reads an agent's report from the request body, plain JSON or
// gzip (Content-Encoding: gzip). maxBytes caps both the bytes read off the
// wire and the decompressed JSON, so a small compressed body cannot expand
// without bound. The returned report's Bytes is the size received.
func DecodeReport(r *http.Request, maxBytes int64) (Report, error) {
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

	var rep Report
	dec := json.NewDecoder(body)
	if err := dec.Decode(&rep); err != nil {
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
