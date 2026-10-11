package audit

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// DefaultSystemPrefixes are the username prefixes classified as actor kind
// "system" when an Ingester sets no SystemPrefixes. "system:serviceaccount:"
// is always "serviceaccount", whatever the prefixes say.
var DefaultSystemPrefixes = []string{"system:"}

// ClassifyActor returns the actor kind of a username: "serviceaccount" for
// system:serviceaccount:*, "system" when the name starts with one of
// systemPrefixes (EKS adds "eks:"), otherwise "user".
func ClassifyActor(username string, systemPrefixes []string) string {
	if strings.HasPrefix(username, "system:serviceaccount:") {
		return "serviceaccount"
	}
	for _, p := range systemPrefixes {
		if p != "" && strings.HasPrefix(username, p) {
			return "system"
		}
	}
	return "user"
}

// RedactExecArgs removes the arguments of an exec request's command from a
// request URI, keeping the executable: the API server puts the whole argv in
// repeated "command" query parameters, and arguments can carry secrets
// (passwords on a psql or mysql command line, tokens in curl headers). Only
// the first command parameter survives, cut at its first space. URIs that are
// not exec requests are returned unchanged.
func RedactExecArgs(uri string) string {
	path, query, ok := strings.Cut(uri, "?")
	if !ok || !strings.HasSuffix(path, "/exec") {
		return uri
	}
	parts := strings.Split(query, "&")
	out := parts[:0]
	seen := false
	for _, p := range parts {
		key, val, _ := strings.Cut(p, "=")
		if k, err := url.QueryUnescape(key); err == nil {
			key = k
		}
		if key != "command" {
			out = append(out, p)
			continue
		}
		if seen {
			continue
		}
		seen = true
		v, err := url.QueryUnescape(val)
		if err != nil {
			v = ""
		}
		if i := strings.IndexFunc(v, func(r rune) bool { return r == ' ' || r == '\t' || r == '\n' }); i >= 0 {
			v = v[:i]
		}
		out = append(out, "command="+url.QueryEscape(v))
	}
	return path + "?" + strings.Join(out, "&")
}

// NormalizeForStore puts an event in the canonical form every Store keeps, so
// MemoryStore and the Postgres store return identical data: time in UTC at
// microsecond precision (what audit logs and Postgres carry), strings valid
// UTF-8 without NUL bytes, empty slices as nil, and a deterministic AuditID
// derived from the content when the event has none (so a replayed duplicate
// collapses instead of piling up).
func NormalizeForStore(e Event) Event {
	e.Time = e.Time.UTC().Truncate(time.Microsecond)
	for _, p := range []*string{&e.AuditID, &e.Stage, &e.Verb, &e.Username, &e.ActorKind, &e.ARN, &e.SessionName,
		&e.ImpersonatedUser, &e.UserAgent, &e.APIGroup, &e.Resource, &e.Subresource, &e.Namespace, &e.Name,
		&e.RequestURI, &e.Decision} {
		*p = cleanString(*p)
	}
	e.Groups = cleanStrings(e.Groups)
	e.SourceIPs = cleanStrings(e.SourceIPs)
	e.Tags = cleanStrings(e.Tags)
	if e.AuditID == "" {
		b, _ := json.Marshal(e)
		sum := sha256.Sum256(b)
		e.AuditID = "gen-" + hex.EncodeToString(sum[:16])
	}
	return e
}

func cleanString(s string) string {
	if utf8.ValidString(s) && strings.IndexByte(s, 0) < 0 {
		return s
	}
	return strings.ReplaceAll(strings.ToValidUTF8(s, "�"), "\x00", "�")
}

func cleanStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	var out []string
	for i, s := range in {
		c := cleanString(s)
		if c != s && out == nil {
			out = append([]string(nil), in...)
		}
		if out != nil {
			out[i] = c
		}
	}
	if out != nil {
		return out
	}
	return in
}

// Canonical returns the query as every Store evaluates it: times in UTC and
// rounded to microseconds without changing which events match (stored times
// are whole microseconds), and a negative Limit treated as 0.
func (q Query) Canonical() Query {
	if !q.Since.IsZero() {
		q.Since = ceilMicro(q.Since.UTC())
	}
	if !q.Before.Time.IsZero() {
		t := q.Before.Time.UTC()
		if c := ceilMicro(t); !c.Equal(t) {
			// No stored event sits between the two microseconds, so "strictly
			// older than t" is "strictly older than the next whole microsecond".
			q.Before = Cursor{Time: c}
		} else {
			q.Before.Time = t
		}
	}
	if q.Limit < 0 {
		q.Limit = 0
	}
	return q
}

func ceilMicro(t time.Time) time.Time {
	tt := t.Truncate(time.Microsecond)
	if tt.Before(t) {
		tt = tt.Add(time.Microsecond)
	}
	return tt
}

// DefaultView reports whether q is the default "interesting" view: system
// actors hidden unless tagged, reads hidden unless tagged. Stores index it.
func (q Query) DefaultView() bool {
	return q.Actors == nil && !q.IncludeReads && q.Verb == ""
}

// InDefaultView reports whether e shows in the default view.
func InDefaultView(e *Event) bool {
	tagged := len(e.Tags) > 0
	return (e.ActorKind != "system" || tagged) && (!isRead(e.Verb) || tagged)
}

// IsRead reports whether verb is a read (get, list, watch).
func IsRead(verb string) bool { return isRead(verb) }

// IsWrite reports whether verb changes state (create, update, patch, delete,
// deletecollection).
func IsWrite(verb string) bool { return isWrite(verb) }

// StageRank orders the stages of one request; a store never replaces a record
// with one of a lower rank.
func StageRank(stage string) int { return stageRank(stage) }

// CursorOf returns the cursor that pages past e: the next page holds events
// strictly older than e in newest-first order.
func CursorOf(e Event) Cursor { return Cursor{Time: e.Time, AuditID: e.AuditID} }

// IsZero reports whether c is the zero cursor (start from the newest event).
func (c Cursor) IsZero() bool { return c.Time.IsZero() }

// Encode returns c as an opaque, URL-safe continue token.
func (c Cursor) Encode() string {
	if c.IsZero() {
		return ""
	}
	raw := "v1:" + strconv.FormatInt(c.Time.UnixNano(), 10) + ":" + c.AuditID
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

// ErrBadCursor is returned by DecodeCursor for a token it did not produce.
var ErrBadCursor = errors.New("invalid continue token")

// DecodeCursor parses a token made by Cursor.Encode. The empty token is the
// zero cursor.
func DecodeCursor(token string) (Cursor, error) {
	if token == "" {
		return Cursor{}, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return Cursor{}, ErrBadCursor
	}
	ver, rest, ok := strings.Cut(string(b), ":")
	if !ok || ver != "v1" {
		return Cursor{}, ErrBadCursor
	}
	ns, id, ok := strings.Cut(rest, ":")
	if !ok {
		return Cursor{}, ErrBadCursor
	}
	n, err := strconv.ParseInt(ns, 10, 64)
	if err != nil || n == 0 {
		return Cursor{}, ErrBadCursor
	}
	return Cursor{Time: time.Unix(0, n).UTC(), AuditID: id}, nil
}
