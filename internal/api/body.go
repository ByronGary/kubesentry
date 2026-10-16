package api

// JSON request bodies of the /api/ write routes (docs/contracts.md, "Write
// routes: cross-origin and body rules"): application/json only, small, and
// strict about fields, so a typo in a field name is an error rather than an
// action taken with a default.

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
)

// maxJSONBody bounds a write route's JSON body.
const maxJSONBody = 16 << 10

// decodeJSON reads r's body, a single JSON value, into v. It answers 415
// unless the Content-Type is application/json, 413 when the body is longer
// than max bytes, and 400 when it is not valid JSON, names a field v does
// not have, or has anything after the value; it then reports false.
func decodeJSON(w http.ResponseWriter, r *http.Request, max int64, v any) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "the body must be JSON (Content-Type: application/json)")
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, max))
	dec.DisallowUnknownFields()
	err = dec.Decode(v)
	if err == nil {
		if _, err = dec.Token(); err == io.EOF {
			return true
		} else if err == nil {
			err = errors.New("more than one JSON value")
		}
	}
	var tooBig *http.MaxBytesError
	switch {
	case errors.As(err, &tooBig):
		writeError(w, http.StatusRequestEntityTooLarge, "the body is too large")
	case errors.Is(err, io.EOF):
		writeError(w, http.StatusBadRequest, "the body is empty")
	default:
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
	}
	return false
}
