package cloudtrail

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/ByronGary/kubesentry/internal/aws/awsjson"
	"github.com/ByronGary/kubesentry/internal/awsauth"
	"github.com/ByronGary/kubesentry/internal/incidents"
)

// Protocol constants of CloudTrail's AWS JSON 1.1 API.
const (
	SigningName  = "cloudtrail"
	TargetPrefix = "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101"
)

// Lookup defaults.
const (
	// DefaultQPS leaves half of the account's two LookupEvents calls per
	// second to other tools (-cloudtrail-qps).
	DefaultQPS = 1.0
	// DefaultMaxPages bounds one poll at 40 pages of 50 events.
	DefaultMaxPages = 40
	pageSize        = 50 // the API's maximum
)

// LookupOptions configures NewLookup.
type LookupOptions struct {
	// Region whose event history is read (-cloudtrail-region, else
	// -aws-region); empty uses the SDK's default configuration.
	Region  string
	Profile string
	// Endpoint overrides the CloudTrail endpoint (a VPC endpoint, tests).
	Endpoint string
	// Credentials replaces the SDK's default chain (tests).
	Credentials aws.CredentialsProvider
	// Base sends the signed requests (tests); default http.DefaultTransport.
	Base http.RoundTripper
	// QPS spaces calls, retries included; default DefaultQPS.
	QPS float64
	// MaxPages bounds one poll; default DefaultMaxPages. A poll that stops
	// there reports ResultTruncated: LookupEvents answers newest first, so
	// the oldest events of its window are skipped.
	MaxPages int
	Overlap  time.Duration // default DefaultOverlap
	Start    time.Duration // first poll's look-back; default DefaultStart
	// Now and Sleep are the clock (tests); Sleep waits for the pacing and
	// the retry backoff.
	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) bool
	// OnResult, if set, counts events and polls by result (Result*).
	OnResult func(result string, n int)
}

// LookupSource reads the event history with LookupEvents. It implements
// incidents.CloudTrailSource.
type LookupSource struct {
	api      *awsjson.Client
	maxPages int
	overlap  time.Duration
	start    time.Duration
	now      func() time.Time
	onResult func(string, int)
}

var _ incidents.CloudTrailSource = (*LookupSource)(nil)

// NewLookup returns a lookup source. Like awsauth.New it only reads local
// configuration; credentials are fetched by the first call.
func NewLookup(ctx context.Context, o LookupOptions) (*LookupSource, error) {
	t, err := awsauth.New(ctx, o.Endpoint, awsauth.Options{
		Region: o.Region, Profile: o.Profile, Service: SigningName, Base: o.Base, Credentials: o.Credentials, Now: o.Now,
	})
	if err != nil {
		return nil, fmt.Errorf("cloudtrail: %w", err)
	}
	endpoint := o.Endpoint
	if endpoint == "" {
		endpoint = awsjson.Endpoint(SigningName, t.Region())
	}
	qps := o.QPS
	if qps <= 0 {
		qps = DefaultQPS
	}
	lim := awsjson.NewLimiter(qps)
	if o.Now != nil {
		lim.Now = o.Now
	}
	if o.Sleep != nil {
		lim.Sleep = o.Sleep
	}
	s := &LookupSource{
		maxPages: o.MaxPages, overlap: o.Overlap, start: o.Start, now: o.Now, onResult: o.OnResult,
	}
	s.api = &awsjson.Client{
		Endpoint: endpoint, Target: TargetPrefix, ContentType: awsjson.JSON11,
		HTTP:    &http.Client{Transport: t, Timeout: 30 * time.Second},
		Limiter: lim, Sleep: o.Sleep,
		OnThrottle: func() { s.result(ResultThrottled, 1) },
	}
	if s.maxPages <= 0 {
		s.maxPages = DefaultMaxPages
	}
	if s.overlap <= 0 {
		s.overlap = DefaultOverlap
	}
	if s.start <= 0 {
		s.start = DefaultStart
	}
	if s.now == nil {
		s.now = time.Now
	}
	return s, nil
}

// Name is ModeLookup.
func (s *LookupSource) Name() string { return ModeLookup }

func (s *LookupSource) result(r string, n int) {
	if s.onResult != nil && n > 0 {
		s.onResult(r, n)
	}
}

type lookupAttribute struct {
	AttributeKey   string `json:"AttributeKey"`
	AttributeValue string `json:"AttributeValue"`
}

type lookupEventsInput struct {
	StartTime        awsjson.Seconds   `json:"StartTime"`
	EndTime          awsjson.Seconds   `json:"EndTime"`
	LookupAttributes []lookupAttribute `json:"LookupAttributes"`
	MaxResults       int               `json:"MaxResults"`
	NextToken        string            `json:"NextToken,omitempty"`
}

type lookupEvent struct {
	EventID         string          `json:"EventId"`
	EventName       string          `json:"EventName"`
	EventSource     string          `json:"EventSource"`
	EventTime       awsjson.Seconds `json:"EventTime"`
	ReadOnly        string          `json:"ReadOnly"`
	Username        string          `json:"Username"`
	AccessKeyID     string          `json:"AccessKeyId"`
	CloudTrailEvent string          `json:"CloudTrailEvent"`
	Resources       []struct {
		ResourceType string `json:"ResourceType"`
		ResourceName string `json:"ResourceName"`
	} `json:"Resources"`
}

type lookupEventsOutput struct {
	Events    []lookupEvent `json:"Events"`
	NextToken string        `json:"NextToken"`
}

// writesOnly is the lookup attribute for write events.
var writesOnly = []lookupAttribute{{AttributeKey: "ReadOnly", AttributeValue: "false"}}

// Changes returns the write events since the checkpoint (re-reading the
// overlap and dropping events it already returned), oldest first, and the
// checkpoint to store. On error the checkpoint is returned unchanged and
// nothing is lost: the next poll reads the window again.
func (s *LookupSource) Changes(ctx context.Context, since time.Time, cpb []byte) ([]incidents.CloudTrailEvent, []byte, error) {
	cp := decodeCheckpoint(cpb)
	now := s.now().UTC().Truncate(time.Second)
	start := from(now, since, cp, s.overlap, s.start)
	if !now.After(start) {
		return nil, cpb, nil
	}
	in := lookupEventsInput{
		StartTime: awsjson.At(start), EndTime: awsjson.At(now),
		LookupAttributes: writesOnly, MaxResults: pageSize,
	}
	var out []incidents.CloudTrailEvent
	got := map[string]int64{}
	dups, unparsed := 0, 0
	for page := 0; ; page++ {
		if page >= s.maxPages {
			s.result(ResultTruncated, 1)
			break
		}
		var resp lookupEventsOutput
		if err := s.api.Do(ctx, "LookupEvents", in, &resp); err != nil {
			return nil, cpb, fmt.Errorf("cloudtrail LookupEvents: %w", err)
		}
		for _, e := range resp.Events {
			ev, ok := fromLookup(e)
			if !ok {
				unparsed++
			}
			if ev.ID == "" {
				continue
			}
			if _, dup := got[ev.ID]; dup {
				continue
			}
			got[ev.ID] = ev.Time.Unix()
			if _, dup := cp.Seen[ev.ID]; dup {
				dups++
				continue
			}
			if ev.ReadOnly {
				continue
			}
			out = append(out, ev)
		}
		if resp.NextToken == "" {
			break
		}
		in.NextToken = resp.NextToken
	}
	sortEvents(out)
	s.result(ResultFetched, len(out))
	s.result(ResultDuplicate, dups)
	s.result(ResultUnparsed, unparsed)
	next := checkpoint{Last: now, Seen: remember(cp.Seen, got, now.Add(-s.overlap))}
	return out, next.encode(), nil
}

// fromLookup builds an event from a LookupEvents entry and its embedded
// record; ok is false when the record could not be parsed (the entry's own
// fields are used).
func fromLookup(e lookupEvent) (incidents.CloudTrailEvent, bool) {
	ev, err := ParseRecord([]byte(e.CloudTrailEvent))
	ok := err == nil
	if !ok {
		ev = incidents.CloudTrailEvent{Raw: cutUTF8(e.CloudTrailEvent, MaxRaw), Resources: []string{}}
	}
	if e.EventID != "" {
		ev.ID = e.EventID
	}
	if e.EventTime > 0 {
		ev.Time = e.EventTime.Time()
	}
	if ev.Name == "" {
		ev.Name = e.EventName
	}
	if ev.Source == "" {
		ev.Source = e.EventSource
	}
	if ev.Actor == "" {
		ev.Actor = e.Username
	}
	if e.ReadOnly != "" {
		ev.ReadOnly = e.ReadOnly == "true"
	}
	res := newResourceSet()
	for _, r := range ev.Resources {
		res.add(r)
	}
	for _, r := range e.Resources {
		name := r.ResourceName
		if r.ResourceType == "AWS::IAM::Role" && iamName.MatchString(name) {
			name = "role/" + name
		}
		res.add(name)
	}
	ev.Resources = res.list
	return ev, ok
}

// Probe reports ProbeOK when LookupEvents answers, or "error: …".
func (s *LookupSource) Probe(ctx context.Context) string {
	now := s.now().UTC().Truncate(time.Second)
	in := lookupEventsInput{
		StartTime: awsjson.At(now.Add(-time.Hour)), EndTime: awsjson.At(now),
		LookupAttributes: writesOnly, MaxResults: 1,
	}
	if err := s.api.Do(ctx, "LookupEvents", in, nil); err != nil {
		if awsjson.IsAccessDenied(err) {
			return "error: access denied (cloudtrail:LookupEvents): " + err.Error()
		}
		return "error: " + err.Error()
	}
	return "ok"
}
