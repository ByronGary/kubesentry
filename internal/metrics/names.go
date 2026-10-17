package metrics

// The metrics kubesentry exposes (docs/contracts.md), registered on Default.
// Use these variables rather than registering names elsewhere, and keep label
// values bounded: route patterns, not paths; result enums, not errors.
var (
	// HTTPRequests counts API responses. Labels: route (the route name given
	// to api.WithMetrics), code (HTTP status, e.g. "200").
	HTTPRequests = NewCounterVec("kubesentry_http_requests_total", "HTTP requests by route and status code.", "route", "code")
	// HTTPDuration observes request latency. Label: route.
	HTTPDuration = NewHistogramVec("kubesentry_http_request_duration_seconds", "HTTP request latency by route.", DefBuckets, "route")
	// Inflight is the number of requests being served.
	Inflight = NewGauge("kubesentry_http_inflight", "HTTP requests currently being served.")
	// HTTPCache counts response-cache lookups. Label: result ("hit", "miss", "coalesced", "skip").
	HTTPCache = NewCounterVec("kubesentry_http_cache_total", "Response cache lookups by result.", "result")

	// SnapshotBuild observes how long a view rebuild takes.
	SnapshotBuild = NewHistogram("kubesentry_snapshot_build_seconds", "Time to build a snapshot view.",
		[]float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60})
	// SnapshotAge is the age of the view being served; set it with SetFunc.
	SnapshotAge = NewGauge("kubesentry_snapshot_age_seconds", "Age of the snapshot view being served.")
	// SnapshotVersion is the version of the view being served.
	SnapshotVersion = NewGauge("kubesentry_snapshot_version", "Version of the snapshot view being served.")
	// InformerObjects counts cached objects. Label: resource (e.g. "pods").
	InformerObjects = NewGaugeVec("kubesentry_informer_objects", "Objects held by the informer cache by resource.", "resource")
	// KubeRequests counts requests to the Kubernetes API. Labels: verb, resource, code.
	KubeRequests = NewCounterVec("kubesentry_kube_requests_total", "Kubernetes API requests by verb, resource and status code.", "verb", "resource", "code")

	// AuthzReviews counts SubjectAccessReviews. Label: result ("allowed", "denied", "error").
	AuthzReviews = NewCounterVec("kubesentry_authz_reviews_total", "SubjectAccessReviews by result.", "result")
	// AuthzCache counts authorization cache lookups. Label: result ("hit", "miss", "coalesced").
	AuthzCache = NewCounterVec("kubesentry_authz_cache_total", "Authorization cache lookups by result.", "result")

	// PromQuery observes Prometheus query latency. Label: kind (e.g. "range", "instant").
	PromQuery = NewHistogramVec("kubesentry_prometheus_query_seconds", "Prometheus query latency by kind.", DefBuckets, "kind")
	// PromCache counts Prometheus result-cache lookups. Label: result.
	PromCache = NewCounterVec("kubesentry_prometheus_cache_total", "Prometheus result cache lookups by result.", "result")

	// AuditIngested counts stored audit events. Label: source ("webhook", "file", "cloudwatch", ...).
	AuditIngested = NewCounterVec("kubesentry_audit_ingested_total", "Audit events ingested by source.", "source")
	// AuditQueueDepth is the number of audit events waiting to be written.
	AuditQueueDepth = NewGauge("kubesentry_audit_queue_depth", "Audit events queued for the store.")
	// AuditStoreErrors counts failed audit store writes.
	AuditStoreErrors = NewCounter("kubesentry_audit_store_errors_total", "Failed audit store operations.")
	// CloudWatchLag is how far the CloudWatch reader is behind.
	CloudWatchLag = NewGauge("kubesentry_cloudwatch_lag_seconds", "Delay between the newest CloudWatch audit event read and now.")

	// AgentReports counts process agent reports. Label: code (HTTP status).
	AgentReports = NewCounterVec("kubesentry_agent_reports_total", "Process agent reports by status code.", "code")
	// AgentNodesReporting is the number of nodes with a fresh agent report.
	AgentNodesReporting = NewGauge("kubesentry_agent_nodes_reporting", "Nodes whose process agent reported recently.")

	// HTTPRejected counts /api/ requests turned away before a route is
	// known. Label: reason ("rate_limit", "max_inflight", "unauthenticated",
	// "cross_origin").
	HTTPRejected = NewCounterVec("kubesentry_http_rejected_total", "API requests rejected before routing, by reason.", "reason")
	// DependencyUp is 1 while a configured dependency works, from the logic
	// behind /readyz. Label: dependency ("snapshot", "prometheus",
	// "postgres", "cloudwatch", "alertmanager"); only configured ones appear.
	DependencyUp = NewGaugeVec("kubesentry_dependency_up", "Whether a configured dependency works (1) or not (0).", "dependency")
	// LeakScanRuns counts background leak scans. Label: result ("ok",
	// "partial": some queries failed, "failed": no fresh findings).
	LeakScanRuns = NewCounterVec("kubesentry_leak_scan_runs_total", "Background leak scans by result.", "result")
	// SnapshotLastChange is when the informers last reported a cluster
	// change (Unix seconds; every poll without informers). Newer than the
	// served view's build time means a change is waiting for a rebuild; a
	// quiet cluster has an old view and an old change.
	SnapshotLastChange = NewGauge("kubesentry_snapshot_last_change_timestamp_seconds", "When the cluster last changed, as the informers saw it.")

	// Findings counts open alert findings (not resolved) on the replica that
	// evaluates them; others report 0. Labels: check, severity
	// ("warning", "critical"). No object names, so it stays small.
	Findings = NewGaugeVec("kubesentry_findings", "Open alert findings by check and severity (on the evaluating replica).", "check", "severity")
	// AlertsSent counts alerts handed to Alertmanager, per URL. Label:
	// result ("sent", "failed", "dropped").
	AlertsSent = NewCounterVec("kubesentry_alerts_sent_total", "Alerts posted to Alertmanager by result, per URL.", "result")
	// AlertsQueueDepth is the alerts waiting to be posted (all URLs).
	AlertsQueueDepth = NewGauge("kubesentry_alerts_queue_depth", "Alerts queued for Alertmanager.")
	// AlertsEvaluation observes how long one alert evaluation takes.
	AlertsEvaluation = NewHistogram("kubesentry_alerts_evaluation_seconds", "Time to evaluate the alert findings of one view.",
		[]float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10})
	// AlertsLeader is 1 on the replica that evaluates and notifies.
	AlertsLeader = NewGauge("kubesentry_alerts_leader", "1 on the replica that evaluates alerts and notifies.")
	// AlertsDigested counts new findings storm protection put in their
	// owner's digest instead of alerting on them alone. Label: reason
	// ("max_new": more than -alerts-max-new at once; "owner_budget": the
	// owner's -alerts-owner-max-new per -alerts-owner-window was spent).
	AlertsDigested = NewCounterVec("kubesentry_alerts_digested_total", "New alert findings sent in a per-owner digest instead of alone, by reason.", "reason")
	// AlertsStandingDigests counts the standing-state digests sent (one per
	// owner and kind at each scheduled time). Label: kind ("rbac-posture",
	// "unused-volumes", "certificates").
	AlertsStandingDigests = NewCounterVec("kubesentry_alerts_standing_digests_total", "Standing-state digest alerts sent, one per owner, by kind.", "kind")
	// AlertActions counts acknowledgements and silences, per finding.
	// Labels: action ("ack", "unack", "silence", "unsilence"), result ("ok",
	// "forbidden", "not_found", "invalid", "resolved").
	AlertActions = NewCounterVec("kubesentry_alert_actions_total", "Actions taken on alert findings by action and result.", "action", "result")

	// Incidents counts open incidents on the replica that runs the
	// incidents engine; the others report 0. Label: severity ("warning",
	// "critical"; the current severity).
	Incidents = NewGaugeVec("kubesentry_incidents", "Open incidents by severity (on the replica running the engine).", "severity")
	// IncidentSignals counts signals handed to the incidents engine. Label:
	// type (the signal type, e.g. "request-spike", "deploy").
	IncidentSignals = NewCounterVec("kubesentry_incident_signals_total", "Signals handed to the incidents engine by type.", "type")
	// KubeEvents counts Kubernetes events the incidents engine kept. Label:
	// result ("stored", "error").
	KubeEvents = NewCounterVec("kubesentry_k8s_events_total", "Kubernetes events stored for incidents by result.", "result")
	// CloudTrailEvents counts CloudTrail events read for incidents. Label:
	// result: "fetched", "duplicate", "unparsed", "truncated" and "throttled"
	// from the source; "kept" (matched to a related resource) and "error"
	// (a failed poll) from the engine.
	CloudTrailEvents = NewCounterVec("kubesentry_cloudtrail_events_total", "CloudTrail events and polls for incidents by result.", "result")
	// IncidentLogFetches counts container log reads for incidents. Labels:
	// source ("kubernetes", "cloudwatch"), result ("ok", "truncated", "error").
	IncidentLogFetches = NewCounterVec("kubesentry_incident_log_fetches_total", "Container log reads for incidents by source and result.", "source", "result")
	// IncidentSourceUp is 1 while an incidents source works and 0 while it
	// fails, as /info's incidents.sources reports it; a source that is
	// absent (not configured, or without data) has no sample. Label: source
	// (the keys of incidents.sources: "events", "memory", "logs:kubernetes",
	// "requests:nginx", ...). Set it with SetOptionalFunc.
	IncidentSourceUp = NewGaugeVec("kubesentry_incident_source_up", "Whether an incidents source works (1) or fails (0); absent sources have no sample.", "source")
	// IncidentsLeader is 1 on the replica that runs the incidents engine.
	IncidentsLeader = NewGauge("kubesentry_incidents_leader", "1 on the replica that runs the incidents engine.")

	// Investigations counts AI investigations by how they ended or why they
	// did not start. Labels: provider ("anthropic", "bedrock", "demo"),
	// result ("completed", "refused", "failed", "timeout", "budget",
	// "cancelled", "cached", "quota", "busy"). investigate.Hooks.OnResult.
	Investigations = NewCounterVec("kubesentry_investigations_total", "AI investigations by provider and result.", "provider", "result")
	// InvestigationsRunning is the investigations running on this replica.
	// investigate.Hooks.OnRunning.
	InvestigationsRunning = NewGauge("kubesentry_investigations_running", "AI investigations running on this replica.")
	// InvestigationDuration observes how long finished investigations ran.
	// investigate.Hooks.OnDuration.
	InvestigationDuration = NewHistogram("kubesentry_investigation_duration_seconds", "How long AI investigations ran.",
		[]float64{10, 30, 60, 120, 240, 420, 600, 900})
	// InvestigationTokens counts model tokens. Labels: provider, model, kind
	// ("input", "output", "cache_read", "cache_write").
	// investigate.Hooks.OnTokens.
	InvestigationTokens = NewCounterVec("kubesentry_investigation_tokens_total", "Model tokens used by AI investigations by kind.", "provider", "model", "kind")
	// InvestigationToolCalls counts the investigator's tool calls. Labels:
	// tool (the tool name, "unknown" for a made-up one), result ("ok",
	// "error", "denied", "invalid"). investigate.Hooks.OnToolCall.
	InvestigationToolCalls = NewCounterVec("kubesentry_investigation_tool_calls_total", "AI investigator tool calls by tool and result.", "tool", "result")
	// LLMRequests counts requests to the model provider, retries included.
	// Labels: provider, code (HTTP status, or "error" without one). Counted
	// by internal/llm.
	LLMRequests = NewCounterVec("kubesentry_llm_requests_total", "Requests to the model provider by status code.", "provider", "code")
)

func init() { Default.RegisterRuntime() }

// AuthzObserver feeds AuthzReviews and AuthzCache. It satisfies
// auth.Observer, for auth.SARAuthorizer.Metrics.
var AuthzObserver authzObserver

type authzObserver struct{}

// ObserveReview counts one SubjectAccessReview.
func (authzObserver) ObserveReview(result string) { AuthzReviews.With(result).Inc() }

// ObserveCache counts one authorization cache lookup.
func (authzObserver) ObserveCache(result string) { AuthzCache.With(result).Inc() }
