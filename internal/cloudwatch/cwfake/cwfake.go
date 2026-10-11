// Package cwfake is a stand-in for the CloudWatch Logs FilterLogEvents API
// (AWS JSON 1.1, X-Amz-Target Logs_20140328.FilterLogEvents) serving EKS
// kube-apiserver audit events. Events are a pure function of a seed and their
// index, so a million of them cost no memory, and a test can ask which events
// exist in any window. It can play a live tail, late and duplicated delivery,
// and throttling. It uses only the standard library, so tests and the stress
// harness need no AWS SDK or account.
package cwfake

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Options shapes the generated log group. Zero values take the defaults shown.
type Options struct {
	Seed     int64
	LogGroup string    // "/aws/eks/fake/cluster"; any other group is ResourceNotFoundException
	Start    time.Time // timestamp of event 0; default 2026-10-10T00:00:00Z
	Rate     float64   // audit events per second, evenly spaced; default 100
	// Events is the total number of audit events; 0 generates them without end
	// (a live tail) up to the current time.
	Events int64
	// Streams is the number of kube-apiserver-audit-* streams (default 2). The
	// group also holds an "authenticator-*" stream of plain-text lines, which a
	// correct logStreamNamePrefix filters out.
	Streams int
	// IngestDelay is how long after its timestamp an event becomes visible
	// (default 2s). LateFraction of events instead show up LateBy late (3m).
	IngestDelay  time.Duration
	LateFraction float64
	LateBy       time.Duration
	// DuplicateFraction of events are logged twice, the copy in another
	// stream and 20s later (same audit event, different eventId).
	DuplicateFraction float64
	// ThrottleEvery makes every Nth request fail with ThrottlingException.
	ThrottleEvery int
	// PageSize caps events per response (default 10,000, the service limit);
	// a request's own limit can lower it. ScanBudget caps how many event
	// indexes one request examines before it returns (possibly empty) with a
	// nextToken, as the real service does on sparse matches (default 100,000).
	PageSize   int
	ScanBudget int
	Now        func() time.Time
}

// Fake serves the API. Create it with New.
type Fake struct {
	o         Options
	startNS   int64
	requests  atomic.Int64
	throttled atomic.Int64
	served    atomic.Int64
}

// New returns a Fake for o.
func New(o Options) *Fake {
	if o.LogGroup == "" {
		o.LogGroup = "/aws/eks/fake/cluster"
	}
	if o.Start.IsZero() {
		o.Start = time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	}
	if o.Rate <= 0 {
		o.Rate = 100
	}
	if o.Streams <= 0 {
		o.Streams = 2
	}
	if o.IngestDelay == 0 {
		o.IngestDelay = 2 * time.Second
	}
	if o.LateBy == 0 {
		o.LateBy = 3 * time.Minute
	}
	if o.PageSize <= 0 {
		o.PageSize = 10_000
	}
	if o.ScanBudget <= 0 {
		o.ScanBudget = 100_000
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Fake{o: o, startNS: o.Start.UnixNano()}
}

// Handler returns an http.Handler serving o, for hosting in another server.
func Handler(o Options) http.Handler { return New(o) }

// NewServer starts an httptest.Server serving f; its URL is the endpoint.
func NewServer(o Options) (*httptest.Server, *Fake) {
	f := New(o)
	return httptest.NewServer(f), f
}

// Requests, Throttled and Served count API calls, injected throttles and log
// events returned.
func (f *Fake) Requests() int64  { return f.requests.Load() }
func (f *Fake) Throttled() int64 { return f.throttled.Load() }
func (f *Fake) Served() int64    { return f.served.Load() }

// Options returns the effective options.
func (f *Fake) Options() Options { return f.o }

// Time returns the timestamp of event i (whole microseconds, as audit logs).
func (f *Fake) Time(i int64) time.Time {
	return time.Unix(0, f.timeNS(i)).UTC()
}

func (f *Fake) timeNS(i int64) int64 {
	ns := f.startNS + int64(float64(i)*1e9/f.o.Rate)
	return ns - ns%1000
}

// firstAtOrAfter returns the smallest index whose timestamp is >= ns.
func (f *Fake) firstAtOrAfter(ns int64) int64 {
	if ns <= f.startNS {
		return 0
	}
	i := int64(float64(ns-f.startNS) * f.o.Rate / 1e9)
	for i > 0 && f.timeNS(i-1) >= ns {
		i--
	}
	for f.timeNS(i) < ns {
		i++
	}
	return i
}

// Range returns the half-open index range [lo, hi) of audit events with
// timestamps in [from, to], bounded by Events.
func (f *Fake) Range(from, to time.Time) (lo, hi int64) {
	lo = f.firstAtOrAfter(from.UnixNano())
	hi = f.firstAtOrAfter(to.UnixNano() + 1)
	if f.o.Events > 0 {
		lo, hi = min(lo, f.o.Events), min(hi, f.o.Events)
	}
	return lo, max(lo, hi)
}

// AuditID returns the auditID of event i.
func (f *Fake) AuditID(i int64) string {
	a, b := f.rnd(i, 1), f.rnd(i, 2)
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", uint32(a), uint16(a>>32), uint16(a>>48)&0x0fff|0x4000, uint16(b)&0x3fff|0x8000, b>>16&0xffffffffffff)
}

// Late reports whether event i is delivered late; Duplicated whether it is
// logged twice.
func (f *Fake) Late(i int64) bool       { return f.frac(i, 3) < f.o.LateFraction }
func (f *Fake) Duplicated(i int64) bool { return f.frac(i, 4) < f.o.DuplicateFraction }

// visibleAt is when event i (or its duplicate copy) can be read.
func (f *Fake) visibleAt(i int64, dup bool) int64 {
	d := f.o.IngestDelay
	if f.Late(i) {
		d = f.o.LateBy
	}
	if dup {
		d += 20 * time.Second
	}
	return f.timeNS(i) + int64(d)
}

func (f *Fake) streamName(i int64, dup bool) string {
	s := i % int64(f.o.Streams)
	if dup {
		s = (s + 1) % int64(f.o.Streams)
	}
	return fmt.Sprintf("kube-apiserver-audit-%016x", uint64(f.rnd(s, 99)))
}

func (f *Fake) authStream() string {
	return fmt.Sprintf("authenticator-%016x", uint64(f.rnd(0, 98)))
}

// splitmix64 over (seed, i, salt).
func (f *Fake) rnd(i int64, salt uint64) uint64 {
	z := uint64(f.o.Seed)*0x9e3779b97f4a7c15 ^ uint64(i)*0xbf58476d1ce4e5b9 ^ salt*0x94d049bb133111eb
	z += 0x9e3779b97f4a7c15
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

func (f *Fake) frac(i int64, salt uint64) float64 {
	return float64(f.rnd(i, salt)>>11) / (1 << 53)
}

func (f *Fake) pick(i int64, salt uint64, n int) int { return int(f.rnd(i, salt) % uint64(n)) }

// wire is the audit.k8s.io/v1 Event as EKS writes it to CloudWatch.
type wire struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"apiVersion"`
	Level      string `json:"level"`
	AuditID    string `json:"auditID"`
	Stage      string `json:"stage"`
	RequestURI string `json:"requestURI"`
	Verb       string `json:"verb"`
	User       struct {
		Username string              `json:"username"`
		UID      string              `json:"uid,omitempty"`
		Groups   []string            `json:"groups"`
		Extra    map[string][]string `json:"extra,omitempty"`
	} `json:"user"`
	ImpersonatedUser *struct {
		Username string `json:"username"`
	} `json:"impersonatedUser,omitempty"`
	SourceIPs []string `json:"sourceIPs"`
	UserAgent string   `json:"userAgent"`
	ObjectRef *struct {
		Resource    string `json:"resource"`
		Namespace   string `json:"namespace,omitempty"`
		Name        string `json:"name,omitempty"`
		APIGroup    string `json:"apiGroup,omitempty"`
		APIVersion  string `json:"apiVersion"`
		Subresource string `json:"subresource,omitempty"`
	} `json:"objectRef,omitempty"`
	ResponseStatus struct {
		Metadata struct{} `json:"metadata"`
		Code     int      `json:"code"`
	} `json:"responseStatus"`
	RequestReceivedTimestamp string            `json:"requestReceivedTimestamp"`
	StageTimestamp           string            `json:"stageTimestamp"`
	Annotations              map[string]string `json:"annotations"`
}

var (
	people     = []string{"alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi"}
	namespaces = []string{"prod", "staging", "payments", "search", "data", "monitoring", "kube-system", "karpenter"}
	resources  = []struct{ group, version, resource, sub string }{
		{"", "v1", "pods", ""}, {"", "v1", "pods", ""}, {"", "v1", "configmaps", ""}, {"apps", "v1", "deployments", ""},
		{"", "v1", "secrets", ""}, {"", "v1", "pods", "exec"}, {"", "v1", "pods", "log"}, {"coordination.k8s.io", "v1", "leases", ""},
		{"rbac.authorization.k8s.io", "v1", "rolebindings", ""}, {"", "v1", "serviceaccounts", "token"}, {"", "v1", "nodes", ""},
		{"", "v1", "events", ""}, {"apps", "v1", "replicasets", ""},
	}
	agents = []string{"kubectl/v1.36.0 (darwin/arm64) kubernetes/9f1a2b3", "kube-controller-manager/v1.36.4 (linux/amd64) kubernetes/9f1a2b3/leader-election",
		"kubelet/v1.36.4 (linux/arm64) kubernetes/9f1a2b3", "karpenter/1.8.0", "argocd-application-controller/v2.13.1"}
)

// Message returns the audit event JSON of event i: one audit.k8s.io/v1 Event
// per log event, as EKS writes them.
func (f *Fake) Message(i int64) []byte {
	var w wire
	w.Kind, w.APIVersion, w.Level, w.Stage = "Event", "audit.k8s.io/v1", "Metadata", "ResponseComplete"
	w.AuditID = f.AuditID(i)
	r := resources[f.pick(i, 10, len(resources))]
	ns := namespaces[f.pick(i, 11, len(namespaces))]
	name := fmt.Sprintf("%s-%d", strings.TrimSuffix(r.resource, "s"), f.pick(i, 12, 40))
	switch who := f.pick(i, 13, 100); {
	case who < 35:
		w.User.Username = fmt.Sprintf("system:node:ip-10-0-%d-%d.ec2.internal", f.pick(i, 14, 4), f.pick(i, 15, 250))
		w.User.Groups = []string{"system:nodes", "system:authenticated"}
	case who < 60:
		w.User.Username = fmt.Sprintf("system:serviceaccount:%s:%s", ns, []string{"default", "app", "argocd", "karpenter"}[f.pick(i, 16, 4)])
		w.User.Groups = []string{"system:serviceaccounts", "system:serviceaccounts:" + ns, "system:authenticated"}
	case who < 75:
		w.User.Username = []string{"system:kube-controller-manager", "system:kube-scheduler", "system:apiserver"}[f.pick(i, 17, 3)]
		w.User.Groups = []string{"system:authenticated"}
	case who < 82:
		w.User.Username = []string{"eks:node-manager", "eks:addon-manager", "eks:certificate-controller", "eks:pod-identity-mutating-webhook"}[f.pick(i, 18, 4)]
		w.User.Groups = []string{"system:authenticated"}
	default:
		p := people[f.pick(i, 19, len(people))]
		w.User.Username = "arn:aws:sts::111122223333:assumed-role/Developer/" + p
		w.User.Groups = []string{"system:authenticated", "developers"}
		w.User.Extra = map[string][]string{
			"arn":          {"arn:aws:sts::111122223333:assumed-role/Developer/" + p},
			"canonicalArn": {"arn:aws:iam::111122223333:role/Developer"},
			"sessionName":  {p},
			"principalId":  {fmt.Sprintf("AROAEXAMPLE%06d", f.pick(i, 20, 999999))},
		}
		if f.pick(i, 21, 20) == 0 {
			w.ImpersonatedUser = &struct {
				Username string `json:"username"`
			}{"system:serviceaccount:" + ns + ":app"}
		}
	}
	verbs := []string{"get", "list", "watch", "get", "update", "patch", "create", "delete"}
	w.Verb = verbs[f.pick(i, 22, len(verbs))]
	code := []int{200, 200, 200, 200, 200, 201, 404, 403, 409}[f.pick(i, 23, 9)]
	switch r.sub {
	case "exec":
		w.Verb, code = "create", 101
	case "token":
		w.Verb, code = "create", 201
	}
	if w.Verb == "create" && code == 200 {
		code = 201
	}
	ref := &struct {
		Resource    string `json:"resource"`
		Namespace   string `json:"namespace,omitempty"`
		Name        string `json:"name,omitempty"`
		APIGroup    string `json:"apiGroup,omitempty"`
		APIVersion  string `json:"apiVersion"`
		Subresource string `json:"subresource,omitempty"`
	}{Resource: r.resource, APIGroup: r.group, APIVersion: r.version, Subresource: r.sub}
	if r.resource != "nodes" {
		ref.Namespace = ns
	}
	if w.Verb != "list" && w.Verb != "watch" && !(w.Verb == "create" && r.sub == "") {
		ref.Name = name
	}
	w.ObjectRef = ref
	prefix := "/api/" + r.version
	if r.group != "" {
		prefix = "/apis/" + r.group + "/" + r.version
	}
	uri := prefix
	if ref.Namespace != "" {
		uri += "/namespaces/" + ref.Namespace
	}
	uri += "/" + r.resource
	if ref.Name != "" {
		uri += "/" + ref.Name
	}
	if r.sub != "" {
		uri += "/" + r.sub
	}
	if r.sub == "exec" {
		uri += "?command=sh&command=-c&command=env&container=app&stdin=true&stdout=true&tty=true"
	} else if w.Verb == "watch" {
		uri += "?watch=true&resourceVersion=" + strconv.FormatInt(int64(f.pick(i, 24, 1_000_000)), 10)
	}
	w.RequestURI = uri
	w.SourceIPs = []string{fmt.Sprintf("10.0.%d.%d", f.pick(i, 25, 4), f.pick(i, 26, 250))}
	w.UserAgent = agents[f.pick(i, 27, len(agents))]
	w.ResponseStatus.Code = code
	t := f.Time(i)
	w.RequestReceivedTimestamp = t.Format("2006-01-02T15:04:05.000000Z")
	w.StageTimestamp = t.Add(time.Duration(1+f.pick(i, 28, 40)) * time.Millisecond).Format("2006-01-02T15:04:05.000000Z")
	decision := "allow"
	if code == 403 {
		decision = "forbid"
	}
	w.Annotations = map[string]string{"authorization.k8s.io/decision": decision, "authorization.k8s.io/reason": ""}
	b, _ := json.Marshal(w)
	return b
}

type request struct {
	LogGroupName        string   `json:"logGroupName"`
	LogGroupIdentifier  string   `json:"logGroupIdentifier"`
	LogStreamNamePrefix string   `json:"logStreamNamePrefix"`
	LogStreamNames      []string `json:"logStreamNames"`
	StartTime           *int64   `json:"startTime"`
	EndTime             *int64   `json:"endTime"`
	FilterPattern       string   `json:"filterPattern"`
	NextToken           string   `json:"nextToken"`
	Limit               int      `json:"limit"`
}

type logEvent struct {
	LogStreamName string `json:"logStreamName"`
	Timestamp     int64  `json:"timestamp"`
	Message       string `json:"message"`
	IngestionTime int64  `json:"ingestionTime"`
	EventID       string `json:"eventId"`
}

type response struct {
	Events             []logEvent `json:"events"`
	SearchedLogStreams []struct {
		LogStreamName      string `json:"logStreamName"`
		SearchedCompletely bool   `json:"searchedCompletely"`
	} `json:"searchedLogStreams"`
	NextToken string `json:"nextToken,omitempty"`
}

// token is the opaque nextToken: where to resume, bound to the query.
type token struct {
	Next int64  `json:"n"`
	Sub  int    `json:"s"` // 0 original, 1 duplicate, 2 authenticator line
	Q    string `json:"q"`
}

func apiError(w http.ResponseWriter, status int, typ, msg string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.Header().Set("X-Amzn-ErrorType", typ)
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"__type": typ, "message": msg})
}

func (f *Fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	n := f.requests.Add(1)
	if r.Method != http.MethodPost {
		apiError(w, http.StatusMethodNotAllowed, "InvalidAction", "POST only")
		return
	}
	if target := r.Header.Get("X-Amz-Target"); target != "Logs_20140328.FilterLogEvents" {
		apiError(w, http.StatusBadRequest, "UnknownOperationException", "unsupported operation "+target)
		return
	}
	if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
		apiError(w, http.StatusBadRequest, "MissingAuthenticationTokenException", "request is not signed")
		return
	}
	if f.o.ThrottleEvery > 0 && n%int64(f.o.ThrottleEvery) == 0 {
		f.throttled.Add(1)
		apiError(w, http.StatusBadRequest, "ThrottlingException", "Rate exceeded")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		apiError(w, http.StatusBadRequest, "SerializationException", err.Error())
		return
	}
	var req request
	if err := json.Unmarshal(body, &req); err != nil {
		apiError(w, http.StatusBadRequest, "SerializationException", err.Error())
		return
	}
	group := req.LogGroupName
	if group == "" {
		group = req.LogGroupIdentifier
	}
	if group != f.o.LogGroup {
		apiError(w, http.StatusBadRequest, "ResourceNotFoundException", "The specified log group does not exist.")
		return
	}
	if req.FilterPattern != "" {
		apiError(w, http.StatusBadRequest, "InvalidParameterException", "cwfake does not support filterPattern")
		return
	}
	resp, err := f.page(req)
	if err != nil {
		apiError(w, http.StatusBadRequest, "InvalidParameterException", err.Error())
		return
	}
	f.served.Add(int64(len(resp.Events)))
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.Header().Set("X-Amzn-RequestId", fmt.Sprintf("cwfake-%d", n))
	json.NewEncoder(w).Encode(resp)
}

func (f *Fake) streamWanted(req *request, name string) bool {
	if len(req.LogStreamNames) > 0 {
		for _, s := range req.LogStreamNames {
			if s == name {
				return true
			}
		}
		return false
	}
	return strings.HasPrefix(name, req.LogStreamNamePrefix)
}

func (f *Fake) page(req request) (*response, error) {
	nowNS := f.o.Now().UnixNano()
	fromMS, toMS := int64(0), nowNS/1e6
	if req.StartTime != nil {
		fromMS = *req.StartTime
	}
	if req.EndTime != nil {
		toMS = *req.EndTime
	}
	qkey := fmt.Sprintf("%d:%d:%s:%s", fromMS, toMS, req.LogStreamNamePrefix, strings.Join(req.LogStreamNames, ","))
	lo, hi := f.Range(time.UnixMilli(fromMS), time.UnixMilli(toMS).Add(999*time.Microsecond))
	if f.o.Events == 0 {
		// Live: nothing exists past now.
		_, nowHi := f.Range(time.Unix(0, 0), time.Unix(0, nowNS))
		hi = min(hi, nowHi)
	}
	sub := 0
	if req.NextToken != "" {
		raw, err := base64.RawURLEncoding.DecodeString(req.NextToken)
		var t token
		if err != nil || json.Unmarshal(raw, &t) != nil || t.Q != qkey {
			return nil, fmt.Errorf("the nextToken is invalid for this query")
		}
		lo, sub = t.Next, t.Sub
	}
	limit := f.o.PageSize
	if req.Limit > 0 && req.Limit < limit {
		limit = req.Limit
	}
	resp := &response{Events: []logEvent{}}
	auth := f.authStream()
	scanned := 0
	i := lo
	for ; i < hi; i, sub = i+1, 0 {
		if scanned >= f.o.ScanBudget || len(resp.Events) >= limit {
			break
		}
		scanned++
		ts := f.timeNS(i)
		for ; sub < 3; sub++ {
			if len(resp.Events) >= limit {
				break
			}
			var ev logEvent
			switch sub {
			case 0, 1:
				dup := sub == 1
				if dup && !f.Duplicated(i) {
					continue
				}
				vis := f.visibleAt(i, dup)
				if vis > nowNS {
					continue
				}
				name := f.streamName(i, dup)
				if !f.streamWanted(&req, name) {
					continue
				}
				ev = logEvent{LogStreamName: name, Message: string(f.Message(i)), IngestionTime: vis / 1e6,
					EventID: fmt.Sprintf("%020d%016x%d", ts/1e6, f.rnd(i, 5), sub)}
			case 2:
				if i%7 != 0 || !f.streamWanted(&req, auth) {
					continue
				}
				ev = logEvent{LogStreamName: auth, IngestionTime: ts/1e6 + 1,
					Message: fmt.Sprintf(`time="%s" level=info msg="access granted" arn="arn:aws:iam::111122223333:role/Node" path=/authenticate`, time.Unix(0, ts).UTC().Format(time.RFC3339)),
					EventID: fmt.Sprintf("%020d%016x2", ts/1e6, f.rnd(i, 6))}
			}
			ev.Timestamp = ts / 1e6
			resp.Events = append(resp.Events, ev)
		}
		if sub < 3 { // page filled mid-index
			break
		}
	}
	if i < hi {
		b, _ := json.Marshal(token{Next: i, Sub: sub, Q: qkey})
		resp.NextToken = base64.RawURLEncoding.EncodeToString(b)
	}
	return resp, nil
}
