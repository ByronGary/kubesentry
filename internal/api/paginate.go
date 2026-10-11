package api

// Keyset pagination for list routes: ?limit= (default 200, at most 1000; more
// is clamped) and an opaque ?continue= token. A token carries the sort key of
// the last item served, so the next page starts right after it even if the
// view was rebuilt in between (an item whose sort key changed meanwhile may
// then show on two pages or none, as with any keyset paging). Tokens are not
// signed: one edited by hand only moves the start position, and every row is
// still filtered by the caller's scope.

import (
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
)

const (
	defaultPageLimit = 200
	maxPageLimit     = 1000
)

var errBadToken = errors.New("invalid continue token")

// limitParam reads ?limit=: def when absent, an error for anything but a
// positive integer, and maxPageLimit at most.
func limitParam(r *http.Request, def int) (int, error) {
	raw := r.URL.Query().Get("limit")
	if raw == "" {
		return def, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("limit must be a positive integer (at most %d)", maxPageLimit)
	}
	return min(n, maxPageLimit), nil
}

// page is a parsed ?limit= and ?continue=.
type page struct {
	limit int
	after string // sort key of the last item already served; "" for the first page
}

// pageParams parses the paging parameters of one route; it answers 400 and
// returns false when they are invalid.
func pageParams(w http.ResponseWriter, r *http.Request, route string) (page, bool) {
	limit, err := limitParam(r, defaultPageLimit)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return page{}, false
	}
	after, err := decodeToken(route, r.URL.Query().Get("continue"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return page{}, false
	}
	return page{limit: limit, after: after}, true
}

const tokenVersion = "k1"

// encodeToken makes the continue token for a route after the item with sort
// key key; "" when there is no next page.
func encodeToken(route, key string) string {
	if key == "" {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString([]byte(tokenVersion + "\x00" + route + "\x00" + key))
}

// decodeToken returns the sort key a token carries. The empty token is the
// first page; a token for another route, or not made by encodeToken, is an
// error.
func decodeToken(route, token string) (string, error) {
	if token == "" {
		return "", nil
	}
	if len(token) > 4096 {
		return "", errBadToken
	}
	b, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", errBadToken
	}
	ver, rest, ok := strings.Cut(string(b), "\x00")
	if !ok || ver != tokenVersion {
		return "", errBadToken
	}
	rt, key, ok := strings.Cut(rest, "\x00")
	if !ok || rt != route || key == "" {
		return "", errBadToken
	}
	return key, nil
}

// Sort key parts. Keys compare as strings, so numbers are fixed width and
// fields are joined with NUL, which sorts before every character a
// Kubernetes name can hold.

func keyJoin(parts ...string) string { return strings.Join(parts, "\x00") }

// keyDesc encodes n so that larger values sort first.
func keyDesc(n int64) string { return fmt.Sprintf("%019d", math.MaxInt64-max(n, 0)) }

// keyRank encodes a small rank so that smaller values sort first.
func keyRank(n int) string { return strconv.Itoa(min(max(n, 0), 9)) }
