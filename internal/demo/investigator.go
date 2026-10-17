package demo

// The demo's AI investigator: the real investigate.Service with its memory
// store, digest, tools, egress filter, budgets and report validation, driven
// by a scripted model (provider "demo", model "demo-scripted") instead of
// Claude. Nothing leaves the process.
//
// For each demo incident the script makes two or three real tool calls over
// the demo's incidents runner (logs, metric series, Kubernetes events, audit
// events), reads the refs the digest and the tool results showed it, and
// submits a report that cites those refs, with a root cause that matches the
// story in incidents.go. Each report suggests read-only checks and one
// command that is not read-only, so the "command removed" path shows; the
// catalog-api report also cites a ref it was never shown, so the
// "not verified" path shows. The script is stateless: it reads everything it
// needs from the conversation, so runs of different incidents can overlap.

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/ByronGary/kubesentry/internal/incidents"
	"github.com/ByronGary/kubesentry/internal/investigate"
	"github.com/ByronGary/kubesentry/internal/investigate/viewstate"
	"github.com/ByronGary/kubesentry/internal/snapshot"
)

// The demo investigator's provider and model (/info.investigator).
const (
	DemoProvider = "demo"
	DemoModel    = "demo-scripted"
	// DefaultInvestigatorDelay is how long each scripted model turn takes,
	// so the running state and its steps show in the UI.
	DefaultInvestigatorDelay = 1200 * time.Millisecond
	// unverifiedDemoRef is the ref the catalog-api report cites without
	// having been shown it.
	unverifiedDemoRef = "metric:requests:inventory-svc"
)

// demoSource is what the demo's investigator reads: the incident from the
// demo's runner, and the current workload state from the demo's views.
type demoSource struct {
	*incidents.Runner
	current func() *snapshot.View
}

func (s demoSource) WorkloadState(_ context.Context, in *incidents.Incident) (*investigate.WorkloadState, error) {
	return viewstate.Of(s.current(), in)
}

// NewInvestigator returns the demo's investigator over the demo's incidents
// runner (as NewIncidents returns it) and views, with each scripted turn
// taking delay.
func NewInvestigator(inc any, current func() *snapshot.View, delay time.Duration) (*investigate.Service, error) {
	d, ok := inc.(demoIncidents)
	if !ok {
		return nil, fmt.Errorf("demo investigator: want the demo's incidents runner, got %T", inc)
	}
	return investigate.NewService(investigate.Config{
		LLM:     scriptedModel{delay: delay},
		Source:  demoSource{Runner: d.Runner, current: current},
		Store:   investigate.NewMemoryStore(0),
		Options: investigate.Options{Model: DemoModel, Effort: "high"},
		Cluster: demoClusterName,
	})
}

// scriptedModel is the demo's stand-in for Claude.
type scriptedModel struct{ delay time.Duration }

func (scriptedModel) Provider() string { return DemoProvider }

func (m scriptedModel) Send(ctx context.Context, req *investigate.Request) (*investigate.Response, error) {
	if m.delay > 0 {
		t := time.NewTimer(m.delay)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-t.C:
		}
	}
	c := readConversation(req)
	sc := scripts[c.workload]
	if sc == nil {
		sc = &script{report: genericReport}
	}
	usage := usageOf(req)
	if req.ToolChoiceNone {
		// The final turn without tools: the report as JSON text.
		b, err := json.Marshal(sc.report(c))
		if err != nil {
			return nil, err
		}
		usage.Output = 2100
		return &investigate.Response{Content: []investigate.Block{{Type: investigate.BlockText, Text: string(b)}},
			StopReason: investigate.StopEndTurn, Usage: usage, RequestID: "req_demo"}, nil
	}
	var calls []call
	if c.turn < len(sc.calls) {
		calls = sc.calls[c.turn](c)
		usage.Output = 240 + 140*int64(len(calls))
	} else {
		calls = []call{{investigate.ToolSubmitReport, sc.report(c)}}
		usage.Output = 2300
	}
	resp := &investigate.Response{StopReason: investigate.StopToolUse, Usage: usage, RequestID: "req_demo"}
	for i, cl := range calls {
		in, err := json.Marshal(cl.input)
		if err != nil {
			return nil, err
		}
		resp.Content = append(resp.Content, investigate.Block{Type: investigate.BlockToolUse,
			ID: fmt.Sprintf("toolu_demo_%d_%d", c.turn, i), Name: cl.name, Input: in})
	}
	return resp, nil
}

// usageOf is a plausible token count for a request, about four characters
// a token: the first turn writes the prompt to the cache, later turns read
// the conversation so far from it and write the newest message.
func usageOf(req *investigate.Request) investigate.Usage {
	tokens := func(n int) int64 { return int64(n/4 + 1) }
	prefix := len(req.System)
	for _, t := range req.Tools {
		prefix += len(t.Name) + len(t.Description) + len(t.InputSchema)
	}
	last := 0
	for i, msg := range req.Messages {
		n := 0
		for _, b := range msg.Content {
			n += len(b.Text) + len(b.Content) + len(b.Input) + len(b.Raw)
		}
		if i == len(req.Messages)-1 {
			last = n
		} else {
			prefix += n
		}
	}
	if len(req.Messages) <= 1 {
		return investigate.Usage{Input: 3, CacheWrite: tokens(prefix + last)}
	}
	return investigate.Usage{Input: 3, CacheRead: tokens(prefix), CacheWrite: tokens(last)}
}

// call is one scripted tool call.
type call struct {
	name  string
	input any
}

// script is what the model does for one demo incident: the tool calls of
// each turn, then the report built from what it was shown.
type script struct {
	calls  []func(c *conversation) []call
	report func(c *conversation) map[string]any
}

// record is one record the conversation showed: a digest entry or a tool
// result's, with its ref.
type record struct {
	ref    string
	source string // "digest" or the tool's name
	m      map[string]any
}

func (r record) str(key string) string {
	switch v := r.m[key].(type) {
	case string:
		return v
	case float64:
		return fmt.Sprint(v)
	}
	return ""
}

// conversation is what the scripted model reads from a request.
type conversation struct {
	turn     int
	workload string
	window   struct{ from, to time.Time }
	pods     []string
	records  []record
}

var (
	digestRe    = regexp.MustCompile(`(?s)<incident_digest>\s*(.*?)\s*</incident_digest>`)
	untrustedRe = regexp.MustCompile(`(?s)<untrusted source="([^"]+)">(.*?)</untrusted>`)
)

func readConversation(req *investigate.Request) *conversation {
	c := &conversation{}
	for i, msg := range req.Messages {
		if msg.Role == investigate.RoleAssistant {
			c.turn++
			continue
		}
		for _, b := range msg.Content {
			if i == 0 && b.Type == investigate.BlockText {
				if m := digestRe.FindStringSubmatch(b.Text); m != nil {
					c.readDigest([]byte(m[1]))
				}
			}
			if b.Type == investigate.BlockToolResult && !b.IsError {
				for _, m := range untrustedRe.FindAllStringSubmatch(b.Content, -1) {
					var v any
					if json.Unmarshal([]byte(m[2]), &v) == nil {
						c.collect(m[1], v)
					}
				}
			}
		}
	}
	return c
}

func (c *conversation) readDigest(raw []byte) {
	var d struct {
		Window struct {
			From, To time.Time
		} `json:"window"`
		Incident struct {
			Subject string   `json:"subject"`
			Pods    []string `json:"pods"`
		} `json:"incident"`
	}
	if json.Unmarshal(raw, &d) == nil {
		c.workload = d.Incident.Subject[strings.LastIndex(d.Incident.Subject, "/")+1:]
		c.window.from, c.window.to = d.Window.From, d.Window.To
		c.pods = d.Incident.Pods
	}
	var v any
	if json.Unmarshal(raw, &v) == nil {
		c.collect("digest", v)
	}
}

// collect walks v for objects that carry a ref.
func (c *conversation) collect(source string, v any) {
	switch x := v.(type) {
	case map[string]any:
		if ref, ok := x["ref"].(string); ok && ref != "" {
			c.records = append(c.records, record{ref: ref, source: source, m: x})
		}
		for _, e := range x {
			c.collect(source, e)
		}
	case []any:
		for _, e := range x {
			c.collect(source, e)
		}
	}
}

// find returns the first record the predicate accepts, in the order shown.
func (c *conversation) find(pred func(r record) bool) (record, bool) {
	for _, r := range c.records {
		if pred(r) {
			return r, true
		}
	}
	return record{}, false
}

// ref is the first matching record's ref, or "" (which refs drops).
func (c *conversation) ref(pred func(r record) bool) string {
	r, _ := c.find(pred)
	return r.ref
}

// at is the first matching record's time (the field named), or "".
func (c *conversation) at(field string, pred func(r record) bool) string {
	r, ok := c.find(pred)
	if !ok {
		return ""
	}
	return r.str(field)
}

func refKind(prefix string) func(r record) bool {
	return func(r record) bool { return strings.HasPrefix(r.ref, prefix+":") }
}

func and(preds ...func(r record) bool) func(r record) bool {
	return func(r record) bool {
		for _, p := range preds {
			if !p(r) {
				return false
			}
		}
		return true
	}
}

func field(key, want string) func(r record) bool {
	return func(r record) bool { return r.str(key) == want }
}

func fieldHas(key, part string) func(r record) bool {
	return func(r record) bool { return strings.Contains(r.str(key), part) }
}

func from(source string) func(r record) bool {
	return func(r record) bool { return r.source == source }
}

// refs drops the empty ones (evidence the run did not see).
func refs(rs ...string) []string {
	out := []string{}
	for _, r := range rs {
		if r != "" {
			out = append(out, r)
		}
	}
	return out
}

// timeline keeps the entries whose time the run saw, oldest first.
func timeline(entries ...map[string]any) []any {
	type timed struct {
		at time.Time
		e  map[string]any
	}
	var keep []timed
	for _, e := range entries {
		s, _ := e["time"].(string)
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			keep = append(keep, timed{t, e})
		}
	}
	sort.SliceStable(keep, func(i, j int) bool { return keep[i].at.Before(keep[j].at) })
	out := []any{}
	for _, k := range keep {
		out = append(out, k.e)
	}
	return out
}

func entry(t, event string, evidence ...string) map[string]any {
	return map[string]any{"time": t, "event": event, "evidence": refs(evidence...)}
}

func report(summary, status, statement, confidence string, evidence []string) map[string]any {
	return map[string]any{
		"summary": summary, "status": status,
		"root_cause":           map[string]any{"statement": statement, "confidence": confidence, "evidence": evidence},
		"contributing_factors": []any{}, "timeline": []any{}, "impact": "",
		"suggested_checks": []any{}, "remediation_ideas": []any{}, "open_questions": []any{}, "data_gaps": []any{},
	}
}

func check(description, command string) map[string]any {
	return map[string]any{"description": description, "command": command}
}

func remedy(description, risk string) map[string]any {
	return map[string]any{"description": description, "risk": risk}
}

func factor(statement string, evidence ...string) map[string]any {
	return map[string]any{"statement": statement, "evidence": refs(evidence...)}
}

// The scripts, by the incident subject's name.
var scripts = map[string]*script{
	"checkout-web":    {calls: []func(*conversation) []call{webTurn1, webTurn2}, report: webReport},
	"recommendations": {calls: []func(*conversation) []call{recsTurn1, recsTurn2}, report: recsReport},
	"catalog-api":     {calls: []func(*conversation) []call{catalogTurn1, catalogTurn2}, report: catalogReport},
}

// ---- checkout-web: a request spike on a pod near its memory limit ----

func webTurn1(c *conversation) []call {
	return []call{
		{investigate.ToolGetMetricSeries, map[string]any{"metric": "memory", "max_points": 40}},
		{investigate.ToolGetLogs, map[string]any{"pods": []string{webPod}, "level": "error", "limit": 40}},
	}
}

func webTurn2(c *conversation) []call {
	return []call{{investigate.ToolGetK8sEvents, map[string]any{"object_kind": "Pod", "object_name": webPod}}}
}

func webReport(c *conversation) map[string]any {
	sig := func(typ string) func(record) bool { return and(refKind("signal"), field("type", typ)) }
	deploy, spike, mem := c.ref(sig("deploy")), c.ref(sig("request-spike")), c.ref(sig("memory-spike"))
	unhealthy := c.ref(and(refKind("event"), field("reason", "Unhealthy"), fieldHas("object", webPod)))
	rescale := c.ref(and(refKind("event"), field("reason", "SuccessfulRescale")))
	memSeries := c.ref(and(refKind("metric"), from(investigate.ToolGetMetricSeries), field("label", webPod+"/web")))
	reqSeries := c.ref(and(refKind("metric"), field("metric", "requests")))
	timeout := c.ref(and(refKind("log"), fieldHas("text", "upstream timed out")))
	gc := c.ref(and(refKind("logtpl"), fieldHas("template", "GC pause")))
	patch := c.ref(and(refKind("audit"), field("resource", "configmaps")))
	if patch == "" {
		patch = c.ref(sig("audit-change"))
	}
	trail := c.ref(refKind("cloudtrail"))

	r := report(
		"checkout-web's requests rose to almost five times their baseline while one pod, "+webPod+", sat at 93% of its memory limit. "+
			"That pod answered slowly: its readiness probe timed out, its calls to the checkout upstream timed out, and error logs "+
			"kept coming after the spike ended. Release 2.8.1, 20 minutes before the spike, and a ConfigMap patch 12 minutes before it "+
			"are the changes in the window; neither is shown to cause it.",
		investigate.LikelyCause,
		"The traffic spike pushed "+webPod+" close to its 256 MiB memory limit; under that pressure it spent long stretches in "+
			"garbage collection and answered too slowly, so its readiness probe and its requests to the upstream timed out.",
		"medium", refs(spike, mem, memSeries, timeout))
	r["contributing_factors"] = []any{
		factor("Release 2.8.1 (revision 14) rolled out 20 minutes before the spike; a release that needs more memory per request would explain why one pod ran out of headroom.", deploy),
		factor("dave patched the checkout-web-config ConfigMap 12 minutes before the spike; what changed is not in the audit record.", patch),
		factor("The HorizontalPodAutoscaler scaled out to 3 replicas, but the pod already near its limit kept receiving traffic.", rescale),
	}
	r["timeline"] = timeline(
		entry(c.at("start", func(r record) bool { return r.ref == deploy }), "Deployment checkout-web rolled out revision 14 (2.8.1).", deploy),
		entry(c.at("start", func(r record) bool { return r.ref == patch })+c.at("time", func(r record) bool { return r.ref == patch }),
			"dave patched ConfigMap checkout-web-config.", patch),
		entry(c.at("start", func(r record) bool { return r.ref == spike }), "Requests rose to 552/s, 4.7 times the baseline.", spike, reqSeries),
		entry(c.at("start", func(r record) bool { return r.ref == mem }), webPod+" reached 93% of its memory limit.", mem, memSeries),
		entry(c.at("first", func(r record) bool { return r.ref == unhealthy }), "Readiness probes on "+webPod+" began to time out.", unhealthy),
		entry(c.at("time", func(r record) bool { return r.ref == timeout }), "checkout-web logged timeouts from its upstream on POST /api/checkout, and long GC pauses.", timeout, gc),
	)
	r["impact"] = "Checkout requests slowed down and part of them failed with upstream timeouts for about half an hour; errors continue at a lower rate."
	r["suggested_checks"] = []any{
		check("See the pod's memory use now, per container.", "kubectl top pod "+webPod+" -n prod --containers"),
		check("See what revision 14 changed.", "kubectl rollout history deployment/checkout-web -n prod --revision 14"),
		check("Read the ConfigMap as it is now.", "kubectl get configmap checkout-web-config -n prod -o yaml"),
		check("Roll back to revision 13.", "kubectl rollout undo deployment/checkout-web -n prod --to-revision 13"),
	}
	r["remediation_ideas"] = []any{
		remedy("Raise checkout-web's memory limit (for example to 384 MiB) and its request to match.", "More memory per pod on the nodes; hides a leak if 2.8.1 has one."),
		remedy("Roll back to 2.8.0 (revision 13) if memory per request is higher in 2.8.1.", "Drops whatever 2.8.1 fixed or added."),
	}
	r["open_questions"] = []any{
		"What did dave's ConfigMap patch change?",
		"Why did the second pod stay below 90% while " + webPod + " did not: uneven load balancing or different state?",
	}
	gaps := []any{"The audit record does not include the ConfigMap's contents before and after the patch."}
	if trail != "" {
		gaps = append(gaps, "A security group on the load balancer was opened to 0.0.0.0/0 during the incident ("+trail+"); it does not explain the symptoms, but deserves its own review.")
	}
	r["data_gaps"] = gaps
	return r
}

// ---- recommendations: release 4.0.0 cannot start ----

func recsTurn1(c *conversation) []call {
	return []call{
		{investigate.ToolGetLogs, map[string]any{"pods": []string{recsPod}, "level": "warn", "limit": 60}},
		{investigate.ToolGetK8sEvents, map[string]any{"object_kind": "Node", "reason": "OOMKilling"}},
	}
}

func recsTurn2(c *conversation) []call {
	return []call{{investigate.ToolGetMetricSeries, map[string]any{"metric": "memory", "label": recsPod + "/api", "max_points": 60}}}
}

func recsReport(c *conversation) map[string]any {
	sig := func(typ string) func(record) bool { return and(refKind("signal"), field("type", typ)) }
	deploy, oom, loop := c.ref(sig("deploy")), c.ref(sig("oom-kill")), c.ref(sig("crash-loop"))
	nodeOOM := c.ref(and(refKind("event"), field("reason", "OOMKilling")))
	backoff := c.ref(and(refKind("event"), field("reason", "BackOff")))
	oomLog := c.ref(and(refKind("log"), fieldHas("text", "out of memory")))
	envLog := c.ref(and(refKind("log"), fieldHas("text", "RECS_MODEL_URL")))
	panicLog := c.ref(and(refKind("log"), fieldHas("text", "connection refused")))
	memSeries := c.ref(and(refKind("metric"), from(investigate.ToolGetMetricSeries), field("label", recsPod+"/api")))

	r := report(
		"Release 4.0.0 of recommendations cannot start. Its first start was OOM killed while loading a 1.9 GiB model; every start "+
			"since logs that RECS_MODEL_URL is not set, falls back to the v3 feature store and panics when that refuses the "+
			"connection, so the pod has crash-looped for about 45 minutes.",
		investigate.RootCauseIdentified,
		"Release 4.0.0 (revision 7) is broken in this environment: it was OOM killed loading its model on the first start, and "+
			"every later start panics because RECS_MODEL_URL is not set and the feature store it falls back to refuses connections.",
		"high", refs(deploy, oom, nodeOOM, envLog, panicLog, loop))
	r["contributing_factors"] = []any{
		factor("Memory climbed steadily from the rollout to the limit while the model loaded, then dropped to nothing at the kill.", memSeries, oomLog),
		factor("The back-off between restarts is now 5 minutes, so the service has been down most of the time.", backoff),
	}
	r["timeline"] = timeline(
		entry(c.at("start", func(r record) bool { return r.ref == deploy }), "Deployment recommendations rolled out revision 7 (4.0.0).", deploy),
		entry(c.at("start", func(r record) bool { return r.ref == oom }), "The api container was OOM killed on its first start.", oom, nodeOOM, oomLog),
		entry(c.at("time", func(r record) bool { return r.ref == envLog }), "After the restart it logged that RECS_MODEL_URL is not set.", envLog),
		entry(c.at("time", func(r record) bool { return r.ref == panicLog }), "It panicked: the v3 feature store refused the connection.", panicLog),
		entry(c.at("start", func(r record) bool { return r.ref == loop }), "Kubernetes reported the container as crash-looping.", loop, backoff),
	)
	r["impact"] = "Recommendations have been unavailable since the rollout: about a third of its requests fail and the rest are served without it."
	r["suggested_checks"] = []any{
		check("Read the previous container's log.", "kubectl logs "+recsPod+" -n prod -c api --previous"),
		check("See what changed in revision 7.", "kubectl rollout history deployment/recommendations -n prod --revision 7"),
		check("Check the container's memory limit and environment.", "kubectl describe deployment recommendations -n prod"),
		check("Find the panic in the previous log.", "kubectl logs "+recsPod+" -n prod -c api --previous | grep panic"),
	}
	r["remediation_ideas"] = []any{
		remedy("Roll back to 3.9.2 (revision 6) until 4.0.0 is fixed.", "Loses whatever 4.0.0 added; check its release notes for a data migration first."),
		remedy("Set RECS_MODEL_URL for 4.0.0 and raise the memory limit to fit the 1.9 GiB model.", "Several times more memory per pod; the nodes may not fit as many replicas."),
	}
	r["open_questions"] = []any{"Is the v3 feature store at 10.100.14.62:6379 meant to be gone, or is it down too?"}
	r["data_gaps"] = []any{"The container's memory limit was not read; that the model does not fit comes from the log and the OOM kill."}
	return r
}

// ---- catalog-api: errors from a failing dependency, resolved ----

func catalogTurn1(c *conversation) []call {
	return []call{
		{investigate.ToolGetLogs, map[string]any{"pods": []string{catalogPod}, "level": "warn", "limit": 60}},
		{investigate.ToolGetMetricSeries, map[string]any{"metric": "errors", "max_points": 40}},
	}
}

func catalogTurn2(c *conversation) []call {
	return []call{{investigate.ToolGetK8sEvents, map[string]any{"reason": "Unhealthy", "type": "Warning"}}}
}

func catalogReport(c *conversation) map[string]any {
	sig := func(typ string) func(record) bool { return and(refKind("signal"), field("type", typ)) }
	errRate := c.ref(sig("error-rate"))
	logBurst := c.ref(sig("log-errors"))
	upstream := c.ref(and(refKind("log"), fieldHas("text", "inventory-svc returned 503")))
	breaker := c.ref(and(refKind("log"), fieldHas("text", "circuit breaker open")))
	errSeries := c.ref(and(refKind("metric"), from(investigate.ToolGetMetricSeries), field("metric", "errors")))
	unhealthy := c.ref(and(refKind("event"), field("reason", "Unhealthy")))

	r := report(
		"For twelve minutes about 8% of catalog-api's requests failed. Its logs blame its dependency inventory-svc, which answered "+
			"503; catalog-api opened its circuit breaker and served cached stock, and its readiness probe failed while the breaker was "+
			"open. The incident ended on its own; error logs ran on for eight more minutes.",
		investigate.LikelyCause,
		"inventory-svc returned 503 Service Unavailable to catalog-api's stock lookups, and catalog-api passed the failures on to its callers.",
		"medium", refs(upstream, errRate, errSeries))
	r["contributing_factors"] = []any{
		factor("catalog-api's readiness probe returns 503 while its circuit breaker is open, which took the pod out of the Service for part of the time.", unhealthy, breaker),
		factor("inventory-svc's own request rate and errors are not part of this incident.", unverifiedDemoRef),
	}
	r["timeline"] = timeline(
		entry(c.at("start", func(r record) bool { return r.ref == errRate }), "8% of catalog-api's requests started to fail.", errRate, errSeries),
		entry(c.at("time", func(r record) bool { return r.ref == upstream }), "catalog-api logged 503s from inventory-svc.", upstream, logBurst),
		entry(c.at("time", func(r record) bool { return r.ref == breaker }), "catalog-api opened its circuit breaker for inventory-svc and served cached stock.", breaker),
		entry(c.at("first", func(r record) bool { return r.ref == unhealthy }), "catalog-api's readiness probe failed with 503.", unhealthy),
		entry(c.at("end", func(r record) bool { return r.ref == errRate }), "The error rate returned to normal.", errRate),
	)
	r["impact"] = "About 8% of catalog requests failed for 12 minutes; most others were answered from cached stock levels."
	r["suggested_checks"] = []any{
		check("Look for restarts of inventory-svc's pods.", "kubectl get pods -n prod -l app=inventory-svc"),
		check("Read inventory-svc's recent events.", "kubectl events -n prod --for deployment/inventory-svc"),
	}
	r["remediation_ideas"] = []any{
		remedy("Keep the readiness probe independent of the circuit breaker, so a failing dependency does not take catalog-api out of service.", "The pod stays in the Service while it can only serve cached data."),
	}
	r["open_questions"] = []any{"Why did inventory-svc answer 503 for twelve minutes?"}
	r["data_gaps"] = []any{"inventory-svc is outside this incident: its metrics, events and logs were not read."}
	return r
}

// genericReport answers an incident the script does not know.
func genericReport(c *conversation) map[string]any {
	trig := c.ref(and(refKind("signal"), from("digest")))
	r := report("The demo investigator only knows the demo's three incidents; this report lists the first trigger it was shown.",
		investigate.Inconclusive, "No cause was looked for.", "low", refs(trig))
	r["impact"] = "Unknown."
	r["data_gaps"] = []any{"The demo investigator follows a script for the demo's incidents only."}
	return r
}
