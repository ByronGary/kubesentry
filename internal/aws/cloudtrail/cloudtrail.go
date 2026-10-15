// Package cloudtrail reads AWS write events for incidents, in two modes:
//
//   - lookup: the account's event history through LookupEvents (90 days, no
//     trail needed), called as a SigV4-signed AWS JSON 1.1 request so no
//     CloudTrail SDK module is needed, and paced (the API allows two calls
//     per second per account and region);
//   - logs: a trail delivered to CloudWatch Logs, read with the filter
//     pattern { $.readOnly IS FALSE } through cloudwatch.RawReader.
//
// Both implement incidents.CloudTrailSource. CloudTrail delivers events up to
// about 15 minutes late, so each poll re-reads an overlap and drops the
// event IDs its checkpoint remembers from the last one.
package cloudtrail

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ByronGary/kubesentry/internal/incidents"
)

// Modes (-cloudtrail).
const (
	ModeLookup = "lookup"
	ModeLogs   = "logs"
)

// Defaults and limits.
const (
	// DefaultOverlap is re-read before each poll's start, for late delivery.
	DefaultOverlap = 15 * time.Minute
	// DefaultStart is how far back the first poll reads (-cloudtrail-start).
	DefaultStart = time.Hour
	// MaxLookback bounds how far back a poll reads after a long pause.
	MaxLookback = 24 * time.Hour
	// MaxRaw caps CloudTrailEvent.Raw.
	MaxRaw = 8 << 10
	// maxSeen bounds the event IDs a checkpoint keeps.
	maxSeen = 20000
	// maxResources bounds CloudTrailEvent.Resources.
	maxResources = 64
)

// Results reported to OnResult hooks, for
// kubesentry_cloudtrail_events_total{result}.
const (
	ResultFetched   = "fetched"   // new write events returned
	ResultDuplicate = "duplicate" // re-read in the overlap and dropped
	ResultUnparsed  = "unparsed"  // records that were not CloudTrail events
	ResultTruncated = "truncated" // a poll stopped at its cap
	ResultThrottled = "throttled" // the API asked to slow down
)

// checkpoint is what a source persists between polls.
type checkpoint struct {
	V int `json:"v"`
	// Last is the end of the window read (lookup), or of what was read
	// (logs).
	Last time.Time `json:"last"`
	// Partial: the poll stopped early at Last, so the next one resumes there
	// without the overlap.
	Partial bool `json:"partial,omitempty"`
	// Seen holds the IDs (with Unix seconds) of events at or after
	// Last − overlap, which the next poll will read again.
	Seen map[string]int64 `json:"seen,omitempty"`
}

func decodeCheckpoint(b []byte) checkpoint {
	var cp checkpoint
	if len(b) > 0 && json.Unmarshal(b, &cp) == nil && cp.V == 1 {
		return cp
	}
	return checkpoint{}
}

func (cp checkpoint) encode() []byte {
	cp.V = 1
	b, _ := json.Marshal(cp)
	return b
}

// from is where a poll starts: after the checkpoint (less the overlap
// unless the last poll stopped early), never before since, at most
// MaxLookback ago, and start ago when there is neither.
func from(now, since time.Time, cp checkpoint, overlap, start time.Duration) time.Time {
	f := since
	if !cp.Last.IsZero() {
		resume := cp.Last.Add(-overlap)
		if cp.Partial {
			resume = cp.Last
		}
		if resume.After(f) {
			f = resume
		}
	}
	if f.IsZero() {
		f = now.Add(-start)
	}
	if oldest := now.Add(-MaxLookback); f.Before(oldest) {
		f = oldest
	}
	return f
}

// remember returns the IDs the next poll may read again: those of seen and
// got at or after cut, newest kept when there are too many.
func remember(seen, got map[string]int64, cut time.Time) map[string]int64 {
	type idt struct {
		id string
		t  int64
	}
	var all []idt
	c := cut.Unix()
	for _, m := range []map[string]int64{seen, got} {
		for id, t := range m {
			if t >= c {
				all = append(all, idt{id, t})
			}
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].t != all[j].t {
			return all[i].t > all[j].t
		}
		return all[i].id < all[j].id
	})
	out := make(map[string]int64, min(len(all), maxSeen))
	for _, e := range all {
		if len(out) >= maxSeen {
			break
		}
		out[e.id] = e.t
	}
	return out
}

// record is the part of a CloudTrail record kubesentry reads.
type record struct {
	EventID      string `json:"eventID"`
	EventTime    string `json:"eventTime"`
	EventName    string `json:"eventName"`
	EventSource  string `json:"eventSource"`
	AWSRegion    string `json:"awsRegion"`
	ReadOnly     *bool  `json:"readOnly"`
	ErrorCode    string `json:"errorCode"`
	UserIdentity struct {
		Type           string `json:"type"`
		ARN            string `json:"arn"`
		UserName       string `json:"userName"`
		PrincipalID    string `json:"principalId"`
		InvokedBy      string `json:"invokedBy"`
		SessionContext struct {
			SessionIssuer struct {
				ARN string `json:"arn"`
			} `json:"sessionIssuer"`
		} `json:"sessionContext"`
	} `json:"userIdentity"`
	Resources []struct {
		ARN  string `json:"ARN"`
		Type string `json:"type"`
	} `json:"resources"`
	RequestParameters json.RawMessage `json:"requestParameters"`
}

// ParseRecord reads one CloudTrail record (the CloudTrailEvent string of
// LookupEvents, or a trail's log message). Resources are the identifiers it
// touches: resources[].ARN, then string values of requestParameters that
// are ARNs, instance IDs (i-…), security group IDs (sg-…), target group
// paths (targetgroup/…) or role paths (role/…, and role/<roleName>); for EKS
// events also cluster/<name>, nodegroup/<cluster>/<name> and
// addon/<cluster>/<name>, the resource parts of EKS ARNs. Raw is the
// compacted record, at most MaxRaw bytes (responseElements is dropped first,
// then the text is cut); it is not redacted.
func ParseRecord(raw []byte) (incidents.CloudTrailEvent, error) {
	var r record
	if err := json.Unmarshal(raw, &r); err != nil {
		return incidents.CloudTrailEvent{}, err
	}
	if r.EventName == "" && r.EventSource == "" && r.EventID == "" {
		return incidents.CloudTrailEvent{}, errors.New("not a CloudTrail record")
	}
	ev := incidents.CloudTrailEvent{
		ID: r.EventID, Name: r.EventName, Source: r.EventSource, Region: r.AWSRegion, ErrorCode: r.ErrorCode,
		Actor: actor(r), Raw: capRaw(raw),
	}
	if r.ReadOnly != nil {
		ev.ReadOnly = *r.ReadOnly
	}
	if t, err := time.Parse(time.RFC3339Nano, r.EventTime); err == nil {
		ev.Time = t.UTC()
	}
	res := newResourceSet()
	for _, x := range r.Resources {
		res.add(x.ARN)
	}
	var params any
	if len(r.RequestParameters) > 0 && json.Unmarshal(r.RequestParameters, &params) == nil {
		budget := 4000
		walk(params, "", 0, res, &budget)
		if r.EventSource == "eks.amazonaws.com" {
			eksResources(params, res)
		}
	}
	ev.Resources = res.list
	return ev, nil
}

func actor(r record) string {
	id := r.UserIdentity
	for _, a := range []string{id.ARN, id.SessionContext.SessionIssuer.ARN, id.UserName, id.InvokedBy, id.PrincipalID} {
		if a != "" {
			return a
		}
	}
	return ""
}

var (
	instanceID  = regexp.MustCompile(`^i-[0-9a-f]{8}([0-9a-f]{9})?$`)
	sgID        = regexp.MustCompile(`^sg-[0-9a-f]{8}([0-9a-f]{9})?$`)
	tgPath      = regexp.MustCompile(`^targetgroup/[A-Za-z0-9-]{1,32}/[0-9a-f]{16}$`)
	rolePath    = regexp.MustCompile(`^role/[\w+=,.@/-]{1,512}$`)
	iamName     = regexp.MustCompile(`^[\w+=,.@-]{1,128}$`)
	eksName     = regexp.MustCompile(`^[0-9A-Za-z][A-Za-z0-9_-]{0,99}$`)
	arnIdentity = regexp.MustCompile(`^arn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:[a-z0-9-]*:\S+$`)
)

type resourceSet struct {
	seen map[string]bool
	list []string
}

func newResourceSet() *resourceSet { return &resourceSet{seen: map[string]bool{}, list: []string{}} }

func (s *resourceSet) add(id string) {
	if id == "" || len(id) > 2048 || s.seen[id] || len(s.list) >= maxResources {
		return
	}
	s.seen[id] = true
	s.list = append(s.list, id)
}

// walk visits requestParameters, in key order, collecting identifiers.
func walk(v any, key string, depth int, res *resourceSet, budget *int) {
	if depth > 8 || *budget <= 0 {
		return
	}
	*budget--
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			walk(t[k], k, depth+1, res, budget)
		}
	case []any:
		for _, x := range t {
			walk(x, key, depth+1, res, budget)
		}
	case string:
		switch {
		case arnIdentity.MatchString(t), instanceID.MatchString(t), sgID.MatchString(t), tgPath.MatchString(t), rolePath.MatchString(t):
			res.add(t)
		case key == "roleName" && iamName.MatchString(t):
			res.add("role/" + t)
		}
	}
}

// eksResources names the cluster, node group and add-on of an EKS call.
func eksResources(params any, res *resourceSet) {
	m, ok := params.(map[string]any)
	if !ok {
		return
	}
	str := func(k string) string {
		s, _ := m[k].(string)
		if eksName.MatchString(s) {
			return s
		}
		return ""
	}
	cluster := str("name")
	if cluster == "" {
		cluster = str("clusterName")
	}
	if cluster == "" {
		return
	}
	res.add("cluster/" + cluster)
	if ng := str("nodegroupName"); ng != "" {
		res.add("nodegroup/" + cluster + "/" + ng)
	}
	if a := str("addonName"); a != "" {
		res.add("addon/" + cluster + "/" + a)
	}
}

// capRaw compacts the record and keeps it under MaxRaw bytes.
func capRaw(raw []byte) string {
	var buf bytes.Buffer
	if json.Compact(&buf, raw) != nil {
		buf.Reset()
		buf.Write(raw)
	}
	if buf.Len() <= MaxRaw {
		return buf.String()
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(buf.Bytes(), &m) == nil {
		if _, ok := m["responseElements"]; ok {
			delete(m, "responseElements")
			var out bytes.Buffer
			enc := json.NewEncoder(&out)
			enc.SetEscapeHTML(false)
			if enc.Encode(m) == nil && out.Len()-1 <= MaxRaw {
				return strings.TrimSuffix(out.String(), "\n")
			}
		}
	}
	return cutUTF8(buf.String(), MaxRaw)
}

func cutUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

func sortEvents(evs []incidents.CloudTrailEvent) {
	sort.SliceStable(evs, func(i, j int) bool {
		if !evs[i].Time.Equal(evs[j].Time) {
			return evs[i].Time.Before(evs[j].Time)
		}
		return evs[i].ID < evs[j].ID
	})
}
