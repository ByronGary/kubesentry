// Shapes of the kubesentry JSON API. Keep in sync with internal/api.

export type Status = 'ok' | 'warn' | 'crit' | 'unknown'

export interface Info {
  demo: boolean
  metrics: boolean
  audit: boolean
  processes: boolean
  /** Map, Workloads, Storage and Security routes exist. */
  inventory: boolean
  /** The certificates route exists; cert-manager itself may still be absent. */
  certs: boolean
  /** Who is calling, when the server knows (proxy or token mode). */
  identity?: { user: string; groups: string[]; source: 'proxy' | 'token' | 'none' }
  /** kubesentry build version (main.version), shown in the sidebar footer. */
  version?: string
  /** Proxy mode: where "Sign out" goes (the oauth2-proxy sign-out path), from -auth-sign-out-url. */
  signOutURL?: string
  /** What this caller may see beyond namespaced data; absent means everything. */
  capabilities?: Partial<Record<Capability, boolean>>
  cluster?: { name?: string; version: string; platform: string; provider?: string; region?: string }
  /** The precomputed view the inventory pages are served from. */
  snapshot?: { version: number; builtAt: string; ageSeconds: number; stale: boolean; error?: string }
  auditStore?: { backend: 'memory' | 'postgres'; oldest?: string; newest?: string; events: number; retentionHours?: number; maxEvents?: number }
  prometheus?: { source: 'flag' | 'discovered' | 'amp' | 'none'; url?: string; retentionHours?: number; flavor?: string; version?: string }
  /** How many namespaces the caller can see (0 means RBAC grants none). */
  namespaces?: number
  /** Sources that could not be read, with the reason (e.g. RBAC forbidden). */
  unavailable?: Record<string, string>
  /** Alerting (-alerts); absent from servers older than alerting. The delivery fields are this replica's: only the leader sends. */
  alerts?: {
    enabled: boolean
    sink: 'alertmanager' | 'none'
    /** This replica holds the alerts lock and notifies. */
    leader?: boolean
    lastSentAt?: string
    /** Why the latest delivery failed, while it still fails ("alertmanager 1 of 2: HTTP 503 ..."). */
    lastError?: string
    /** Standing-state digests (-alerts-digest-at): when the last one was sent and the next is due. */
    lastDigestAt?: string
    nextDigestAt?: string
    /** The longest silence an action may ask for (-alerts-max-silence), in seconds; absent on older servers (then 7 days). */
    maxSilenceSeconds?: number
  }
  /** The Settings page (/api/v1/settings/investigator); absent on older servers. */
  settings?: {
    investigator: boolean
    /** ui: admins change the settings live; locked: Helm is the only source. */
    mode: 'ui' | 'locked'
  }
  /** AI investigator (-investigator); absent when off or on older servers. */
  investigator?: {
    enabled: boolean
    /** Where the redacted incident data is sent. "demo" is the scripted, offline investigator of cmd/demo. */
    provider: 'anthropic' | 'bedrock' | 'demo'
    /** e.g. "claude-opus-5-5" or "anthropic.claude-opus-5-5". */
    model: string
    effort: 'low' | 'medium' | 'high' | 'xhigh' | 'max'
    /** Runs one caller may start per hour (cache hits are free). */
    perHour: number
  }
  /** Incidents (-incidents); absent when off or on older servers. */
  incidents?: {
    enabled: boolean
    /** This replica holds the incidents lease. */
    leader?: boolean
    /** Signal sources and their state: "ok", "absent" or "error: …" (e.g. requests:nginx, requests:alb, logs:cloudwatch, cloudtrail). */
    sources: Record<string, string>
    maxRangeHours: number
    logLeadSeconds: number
    logLagSeconds: number
  }
}

export type Capability = 'nodes' | 'pvs' | 'storageClasses' | 'clusterRBAC' | 'clusterIssuers' | 'processes' | 'audit' | 'clusterAudit' | 'agents' | 'podLogs' | 'cloudtrail'
  /** `update alerts.kubesentry.io` somewhere: may ack and silence the alerts it can see there. */
  | 'alertsUpdate'
  /** `create investigations.kubesentry.io` somewhere: may start AI investigations of incidents there. */
  | 'investigate'
  /** `update settings.kubesentry.io` cluster-wide: may read and change the Settings page. */
  | 'settings'

/** Optional paging on list responses: pass `continue` back to get the next page. */
export interface Paged {
  continue?: string
}

export interface UnusedPVC {
  namespace: string
  name: string
  storageClass: string
  phase: string
  capacityBytes: number
  created: string
  ageHours: number
  /** 0 when costKnown is false. */
  estMonthlyCostUSD: number
  costKnown?: boolean
  priceSource?: PriceSource
}

export interface UnusedPVCResponse {
  count: number
  totalEstMonthlyCostUSD: number
  items: UnusedPVC[]
}

export interface OOMEvent {
  namespace: string
  pod: string
  container: string
  restartCount: number
  lastOOMAt: string
  exitCode: number
}

export interface LeakFinding {
  namespace: string
  pod: string
  container: string
  segments: number
  leakySegments: number
  slopeBytesPerHour: number
  r2: number
  currentBytes: number
  limitBytes?: number
  timeToLimitHours?: number
  confidence: 'high' | 'medium'
  oomKilled: boolean
  lastOOMAt?: string
}

export interface OOMResponse {
  window: string
  metricsAvailable: boolean
  events: OOMEvent[]
  leaks: LeakFinding[]
  warnings?: string[]
}

export interface PodSummary {
  namespace: string
  name: string
  phase: string
  containers: number
  restarts: number
  oomKilled: boolean
  ready?: boolean
  /** Worst container waiting reason, e.g. CrashLoopBackOff. */
  reason?: string
  node?: string
  /** "Kind/name" of the owner. */
  workload?: string
}

export interface PodsResponse extends Paged {
  count: number
  items: PodSummary[]
}

export interface Check {
  id: string
  title: string
  status: Status
  detail: string
}

export interface VolumeState {
  claim: string
  found: boolean
  phase?: string
  storageClass?: string
  capacityBytes?: number
}

export interface ContainerDiag {
  name: string
  restartCount: number
  lastTerminatedReason?: string
  lastTerminatedAt?: string
  lastExitCode?: number
  limitBytes?: number
  currentBytes?: number
  /** [unix ms, bytes] */
  series: [number, number][]
  leak?: LeakFinding
}

export interface AuditEvent {
  auditID: string
  time: string
  stage: string
  verb: string
  username: string
  actorKind: 'user' | 'serviceaccount' | 'system'
  arn?: string
  sessionName?: string
  impersonatedUser?: string
  sourceIPs?: string[]
  userAgent?: string
  apiGroup?: string
  resource?: string
  subresource?: string
  namespace?: string
  name?: string
  requestURI?: string
  statusCode: number
  decision?: string
  tags?: string[]
}

export interface AuditEventsResponse extends Paged {
  count: number
  items: AuditEvent[]
}

export interface UserSummary {
  username: string
  actorKind: string
  total: number
  writes: number
  execs: number
  secretAccess: number
  denied: number
  lastSeen: string
}

export interface AuditSummary {
  window: string
  totalEvents: number
  byTag: Record<string, number>
  users: UserSummary[]
}

export interface PodDiagnostics {
  namespace: string
  name: string
  phase: string
  window: string
  metricsAvailable: boolean
  auditAvailable: boolean
  checks: Check[]
  containers: ContainerDiag[]
  volumes: VolumeState[]
  activity: AuditEvent[]
  /** Incidents (open, or resolved within 24h) whose subject owns this pod. */
  incidents?: IncidentRef[]
  /** Go duration of the activity lookback (e.g. "168h0m0s"). */
  activityWindow?: string
  warnings?: string[]
}

export interface ProcessItem {
  pid: number
  ppid: number
  name: string
  cmdline: string
  container: string
  rssBytes: number
  threads: number
  cpuMillicores: number
}

export interface ProcessesResponse {
  available: boolean
  node?: string
  observedAt?: string
  stale: boolean
  processes: ProcessItem[]
}

// Inventory pages. Mirrors internal/detectors/inventory.go and internal/api/inventory.go.

export interface WorkloadSummary {
  kind: 'Deployment' | 'StatefulSet' | 'DaemonSet' | 'Job' | 'CronJob'
  namespace: string
  name: string
  status: Status
  detail: string
  desired: number
  ready: number
  updated: number
  available: number
  /** Live pods the selector matches. */
  pods: number
  restarts: number
  oomKilled: boolean
  notReady?: number
  /** Pods by worst waiting reason, e.g. { CrashLoopBackOff: 2 }. */
  waiting?: Record<string, number>
  images: string[]
  created: string
  schedule?: string
  suspended?: boolean
  lastScheduleTime?: string
  lastSuccessTime?: string
}

export interface WorkloadsResponse extends Paged {
  count: number
  items: WorkloadSummary[]
}

export interface ClaimSummary {
  namespace: string
  name: string
  phase: string
  storageClass: string
  volumeName?: string
  capacityBytes: number
  /** Live pods mounting it. */
  usedBy: string[]
  status: Status
  detail: string
  created: string
  estMonthlyCostUSD?: number
  /** False when no price applies; priceSource says why (e.g. usage-billed for EFS). */
  costKnown?: boolean
  priceSource?: PriceSource
}

export type PriceSource = 'annotation' | 'class-price' | 'ebs-table' | 'default' | 'usage-billed' | 'unknown'

export interface VolumeSummary {
  name: string
  phase: string
  storageClass: string
  reclaimPolicy: string
  source: string
  driver?: string
  volumeHandle?: string
  /** "namespace/name" */
  claim?: string
  capacityBytes: number
  status: Status
  detail: string
  created: string
}

export interface ClassSummary {
  name: string
  provisioner: string
  reclaimPolicy: string
  bindingMode: string
  allowExpansion: boolean
  default: boolean
  claims: number
  capacityBytes: number
  pricePerGiBMonth?: number
  priceSource?: PriceSource
  parameters?: Record<string, string>
}

export interface StorageResponse extends Paged {
  claims: ClaimSummary[]
  volumes: VolumeSummary[]
  classes: ClassSummary[]
  unused: UnusedPVC[]
  unusedMonthlyCostUSD: number
}

export type SecuritySeverity = 'crit' | 'warn' | 'info'
export type SecurityCategory = 'pod' | 'rbac' | 'namespace' | 'exposure'

export interface SecurityFinding {
  id: string
  category: SecurityCategory
  /** e.g. privileged, host-namespaces, cluster-admin, psa-missing, ingress-no-tls */
  check: string
  severity: SecuritySeverity
  title: string
  /** "namespace/name" or the name of a cluster-scoped object */
  subject: string
  subjectKind: string
  namespace?: string
  detail: string
  /** Cluster plumbing (system namespaces, built-in system: RBAC); hidden by default. */
  system: boolean
}

export interface NamespacePosture {
  name: string
  enforce: string
  audit: string
  warn: string
  system: boolean
  status: Status
}

export interface SecurityResponse extends Paged {
  /** By severity, excluding system findings. */
  counts: Partial<Record<SecuritySeverity, number>>
  findings: SecurityFinding[]
  namespaces: NamespacePosture[]
  warnings?: string[]
}

export interface CertSummary {
  namespace: string
  name: string
  secretName: string
  dnsNames: string[]
  issuerKind: string
  issuerName: string
  /** Ready condition: "True", "False", "Unknown", or "" before the first one */
  ready: string
  reason?: string
  message?: string
  notAfter?: string
  renewalTime?: string
  /** Negative once expired. */
  expiresInHours?: number
  status: Status
  detail: string
}

export interface IssuerSummary {
  kind: string
  namespace?: string
  name: string
  /** acme, ca, vault, selfSigned, venafi or unknown */
  type: string
  server?: string
  ready: string
  reason?: string
  message?: string
  certificates: number
  status: Status
  detail: string
}

export interface RequestSummary {
  namespace: string
  name: string
  certificate: string
  issuerKind: string
  issuerName: string
  ready: string
  reason?: string
  message?: string
  approved: boolean
  denied: boolean
  created: string
  status: Status
}

export interface CertificatesResponse {
  installed: boolean
  certificates: CertSummary[]
  issuers: IssuerSummary[]
  requests: RequestSummary[]
}

export type GraphKind = 'Ingress' | 'Service' | 'Deployment' | 'StatefulSet' | 'DaemonSet' | 'Job' | 'CronJob' | 'ReplicaSet' | 'Controller' | 'Pod' | 'PVC' | 'Node'

export interface GraphNode {
  /** "<Kind>/<namespace>/<name>", or "Node/<name>" */
  id: string
  kind: GraphKind
  name: string
  namespace?: string
  status: Status
  detail: string
  /** The real kind behind a Controller node, e.g. Rollout. */
  ownerKind?: string
}

/** From the routing or owning object to what it routes to, runs or uses. */
export interface GraphEdge {
  from: string
  to: string
  /** How the link was found: ownerReferences, EndpointSlices, or labels (fallback). */
  how?: 'owner' | 'endpoints' | 'selector'
  /** Endpoint counts on Service links. */
  ready?: number
  notReady?: number
  terminating?: number
}

export interface MapResponse {
  namespace: string
  namespaces: string[]
  graph: { nodes: GraphNode[]; edges: GraphEdge[] }
  /** Live pods per namespace the caller can see, for choosing a default namespace. */
  namespaceStats?: { name: string; pods: number; system: boolean }[]
}

export interface NodePod {
  namespace: string
  name: string
  phase: string
  status: Status
  /** "Kind/name" of the owning workload */
  workload?: string
  /** Absent when the pod has not reported a Ready condition. */
  ready?: boolean
  reason?: string
}

export interface Placement {
  zone?: string
  region?: string
  instanceType?: string
  arch?: string
  os?: string
  /** Node group or Karpenter node pool name. */
  pool?: string
  poolKind?: 'nodegroup' | 'karpenter' | 'fargate' | ''
  capacityType?: 'on-demand' | 'spot' | ''
  providerID?: string
}

export interface NodeSummary {
  name: string
  roles: string[]
  ready: boolean
  unschedulable: boolean
  status: Status
  detail: string
  kubeletVersion: string
  osImage: string
  containerRuntime: string
  pressure: string[]
  taints: string[]
  cpuAllocatableMilli: number
  cpuRequestedMilli: number
  memoryAllocatableBytes: number
  memoryRequestedBytes: number
  podsAllocatable: number
  /** Omitted with ?summary=true; podCount stays. */
  pods?: NodePod[]
  podCount?: number
  placement?: Placement
}

/** POST /api/v1/auth/recheck: the caller's capabilities after their cached access decisions were dropped. */
export interface RecheckResponse {
  capabilities: Partial<Record<Capability, boolean>>
}

export interface AgentStatus {
  node: string
  lastReport: string
  processes: number
  /** Size of the last report as received (compressed when the agent gzips). */
  bytes: number
  stale: boolean
  /** Processes cut by the server's per-node cap in the last report. */
  dropped?: number
}

export interface NodesResponse {
  count: number
  items: NodeSummary[]
}

// ---- Overview dashboard (GET /api/v1/overview?namespace=&owner=) ----
// Scoped to the caller like every other route; cluster-scoped parts are null
// when the caller lacks the capability. See docs/proposals/overview-dashboard.md.

export type AttentionSeverity = 'crit' | 'warn'

export interface OverviewResponse {
  /** Snapshot view version the answer was built from. */
  version: number
  builtAt: string
  ageSeconds: number
  /** The filter applied, and how many namespaces it covers for this caller. */
  scope: { namespace?: string; owner?: string; namespaces: number }
  /** Namespaces the caller can see (before the filter), sorted, for the namespace picker. */
  namespaces?: string[]
  health: {
    prometheus: 'ok' | 'unavailable' | 'none'
    auditStore: 'ok' | 'degraded' | 'none'
    cloudwatchLagSeconds?: number
    /** Present with the `agents` capability. */
    agents?: { reporting: number; stale: number }
  }
  /** Null without the `nodes` capability. */
  nodes: null | {
    total: number
    ready: number
    notReady: number
    cordoned: number
    pools: OverviewPool[]
    zones: { name: string; nodes: number }[]
  }
  pods: { total: number; running: number; pending: number; failing: number; byReason: Record<string, number> }
  workloads: { total: number; unhealthy: number }
  /** Null when cert-manager is not installed. */
  certificates: null | { total: number; expiringSoon: number; notReady: number; issuerMissing: number }
  security: { crit: number; warn: number; newSince24h?: number }
  /** Top 10 problems, worst first, folded per workload. */
  attention: AttentionItem[]
  /** Null without the `audit` capability. Counts over windowHours (24 by default). */
  activity: null | {
    windowHours: number
    exec: number
    execProduction: number
    secretReads: number
    rbacChanges: number
    denied: number
    latest: AuditEvent[]
    /** Visible namespaces carrying the production label, so the UI can mark production events. */
    productionNamespaces?: string[]
  }
  waste: { unusedPVCs: number; monthlyUSD: number; usageBilled: number }
  /** Owners (namespace annotation kubesentry.io/owner) of the caller's visible namespaces, for the filter. */
  owners: string[]
  /** Sidebar badges, keyed by nav item; absent when zero. */
  badges: Partial<Record<'workloads' | 'pods' | 'findings' | 'memory' | 'security' | 'certificates' | 'incidents' | 'alerts', { count: number; severity: AttentionSeverity }>>
  history: OverviewHistory
  /** Alert findings not resolved, in the caller's scope and filter (cluster-scoped ones only without a filter). Absent when alerting is off. */
  alerts?: { open: number; acknowledged: number; silenced: number; byOwner: Record<string, number> }
  /** Open incidents in scope; absent when incidents are off. */
  incidents?: { open: { critical: number; warning: number } }
}

export interface OverviewPool {
  name: string
  kind: 'nodegroup' | 'karpenter' | 'fargate' | 'other'
  nodes: number
  /** Requested / allocatable, percent; absent for Fargate (not metered). */
  cpuRequestedPct?: number
  memRequestedPct?: number
}

export interface AttentionItem {
  severity: AttentionSeverity
  /** Check that raised it, e.g. "crashloop", "cert-expiring", "leak", "exposure". */
  kind: string
  namespace?: string
  name: string
  title: string
  owner?: string
  /** When the problem started, if known. */
  since?: string
  /** Hash route of the page that explains it, already filtered (e.g. "#/workloads?status=crit&namespace=shop"). */
  href: string
}

/** In-process history (24h, fixed buckets) for sparklines; lost on restart, per replica. */
export interface OverviewHistory {
  stepSeconds: number
  /** Time of the first bucket; values are oldest first. */
  start: string
  series: Partial<Record<'unhealthyWorkloads' | 'failingPods' | 'securityCrit' | 'securityWarn' | 'certsExpiringSoon', number[]>>
}


// ---- Alerts (GET /api/v1/alerts?namespace=&owner=&state=&limit=&continue=) ----
// The findings kubesentry alerts on, scoped like every route: namespaced ones
// need the namespace (RBAC ones also `list rolebindings` there), cluster-scoped
// ones the clusterRBAC capability. Open, acknowledged and silenced findings,
// and those resolved in the last 24 hours, most troubled first.
// See docs/alerts.md.

export type AlertState = 'open' | 'acknowledged' | 'silenced' | 'resolved'
export type AlertSeverity = 'warning' | 'critical'

export interface AlertFinding {
  /** Stable dedupe key: check/kind/namespace/name. */
  key: string
  /** The alertname, e.g. "KubesentryWorkloadUnhealthy". */
  alert: string
  /** e.g. "workload-unhealthy", "cert-expiring", "cluster-admin". */
  check: string
  /** The object's kind: Deployment, Certificate, ClusterRoleBinding, ... (a bare pod: Pod). */
  kind: string
  namespace?: string
  name: string
  severity: AlertSeverity
  title: string
  owner: string
  production: boolean
  /** The label set last sent to Alertmanager. */
  labels: Record<string, string>
  /** summary, description, runbook_url, kubesentry_url (with -external-url), dedupe_key, and per alert e.g. pods, reasons, predicted_oom. */
  annotations: Record<string, string>
  state: AlertState
  silencedUntil?: string
  /** Announced in a per-owner digest (storm protection) rather than on its own. */
  digest?: boolean
  firstSeen: string
  lastSeen: string
  lastNotified?: string
  resolvedAt?: string
  /** Who acknowledged this episode, and when (state "acknowledged"). Cleared when a new episode starts or it turns critical. */
  ackBy?: string
  ackAt?: string
  /** Who silenced the finding, when, and why (state "silenced", until silencedUntil). */
  silencedBy?: string
  silencedAt?: string
  silenceReason?: string
  /** UI route of the object, e.g. "#/workloads?namespace=shop&q=checkout". */
  link?: string
  /** The incident this finding's episode joined, when there is one. */
  incidentId?: string
  /** Reported only in the standing digest for now (a certificate far from expiry); never notified on its own. */
  quiet?: boolean
  /** The caller may ack or silence it (alertsUpdate in its namespace, or cluster-wide for cluster-scoped findings). */
  actionable?: boolean
}

export interface AlertsResponse extends Paged {
  /** Items on this page. */
  count: number
  items: AlertFinding[]
  /** Everything the caller can see by state, before the namespace, owner and state filters. */
  counts: Record<AlertState, number>
  /** When the findings were last evaluated (the leader) or read from the store; absent before the first evaluation. */
  updatedAt?: string
}

// ---- Alert actions (POST/GET /api/v1/alerts/actions) ----
// Ack is per episode (the finding's firstSeen); silence is per key and lasts
// until it expires or is lifted. Neither writes to Alertmanager's silences.

export type AlertActionKind = 'ack' | 'unack' | 'silence' | 'unsilence'

export interface AlertActionRequest {
  /** At most 100 dedupe keys. */
  keys: string[]
  action: AlertActionKind
  /** Silence only: a Go duration from 5m to the server's maximum (default 7d), e.g. "4h". */
  for?: string
  /** Silence only: 3 to 500 characters. */
  reason?: string
}

export interface AlertActionResult {
  key: string
  ok: boolean
  /** A key the caller cannot see answers "not found", like an unknown one. */
  error?: 'not found' | 'forbidden' | 'resolved' | 'invalid'
  /** The finding after the action. */
  finding?: AlertFinding
}

export interface AlertActionResponse {
  results: AlertActionResult[]
}

export interface AlertAction {
  id: number
  key: string
  /** The namespace of the finding acted on (from its key); absent for cluster-scoped findings. */
  namespace?: string
  /** The episode acted on. */
  firstSeen: string
  action: AlertActionKind
  actor: string
  reason?: string
  /** Silence only. */
  until?: string
  /** The finding's severity when the action was taken. */
  severity: AlertSeverity
  at: string
}

/** GET /api/v1/alerts/actions?key=&limit= : newest first, at most 200, only for findings the caller can see. */
export interface AlertActionsResponse {
  items: AlertAction[]
}

// ---- Incidents (GET /api/v1/incidents…) ----
// One incident per workload root; triggers open it and set severity, context
// signals (what changed, logs) attach. See docs/contracts.md "Incidents".

export type IncidentSeverity = 'critical' | 'warning'

export type IncidentSignalType =
  | 'request-spike' | 'error-rate' | 'memory-spike' | 'oom-kill' | 'restart' | 'crashloop' | 'eviction'
  | 'k8s-event' | 'alert' | 'deploy' | 'scale' | 'audit-change' | 'cloudtrail-change' | 'log-errors'

export interface IncidentSubject { kind: string; namespace?: string; name: string }

export interface ObjectRef { kind: string; namespace?: string; name: string; uid?: string }

export interface IncidentRef { id: string; severity: IncidentSeverity; state: 'open' | 'resolved'; title: string; start: string }

export interface Incident {
  id: string
  subject: IncidentSubject
  title: string
  severity: IncidentSeverity
  peakSeverity: IncidentSeverity
  state: 'open' | 'resolved'
  start: string
  lastSignal: string
  end?: string
  capped?: boolean
  previous?: string
  owner?: string
  production?: boolean
  tags?: Record<string, string>
  services?: string[]
  pods?: string[]
  nodes?: string[]
  types: IncidentSignalType[]
  counts: Partial<Record<IncidentSignalType, number>>
}

export interface IncidentSignal {
  id: string
  type: IncidentSignalType
  source: 'view' | 'metrics' | 'events' | 'alerts' | 'audit' | 'cloudtrail' | 'logs'
  role: 'trigger' | 'context'
  severity?: IncidentSeverity
  start: string
  end?: string
  subject: IncidentSubject
  object: ObjectRef
  title: string
  value?: number
  baseline?: number
  threshold?: number
  count?: number
  tags?: Record<string, string>
  attrs?: Record<string, string>
}

export interface IncidentsResponse extends Paged {
  /** Counts in range before the severity/type/state filters. */
  counts: { open: number; resolved: number; critical: number; warning: number; byType: Partial<Record<IncidentSignalType, number>> }
  items: Incident[]
}

/** A metric series on the incident's shared time axis: [unixMs, value][]. */
export interface IncidentSeries {
  metric: 'memory' | 'requests' | 'errors'
  /** e.g. pod/container, service, or "others" for the folded remainder. */
  label: string
  unit: 'bytes' | 'rps' | 'ratio'
  source?: string
  points: [number, number][]
}

export interface IncidentKubeEvent {
  uid: string
  namespace?: string
  type: 'Warning' | 'Normal'
  reason: string
  message: string
  count: number
  firstSeen: string
  lastSeen: string
  regarding: ObjectRef
  source?: string
  /** The workload root the event resolved to, when known. */
  subject?: IncidentSubject
}

export interface IncidentDetail {
  incident: Incident
  /** The padded window logs and events are read in. */
  window: { from: string; to: string }
  signals: IncidentSignal[]
  events: IncidentKubeEvent[]
  /** Audit events in the window (with the audit capability). */
  audit?: AuditEvent[]
  series: IncidentSeries[]
  thresholds?: { metric: IncidentSeries['metric']; label: string; value: number }[]
  /** Other incidents sharing app/service tags whose windows overlap. */
  related: IncidentRef[]
  /** State of each source for this incident ("ok", "absent", "error: …", "forbidden"). */
  sources: Record<string, string>
  warnings?: string[]
}

export interface IncidentLogLine {
  time: string
  pod: string
  container: string
  /** "error", "warn", "info", "debug" or "" when unknown. */
  level: string
  text: string
  source: 'kubernetes' | 'cloudwatch'
}

export interface IncidentLogsResponse {
  from: string
  to: string
  /** "" when no log source is configured (the response then carries a warning). */
  source: 'kubernetes' | 'cloudwatch' | ''
  lines: IncidentLogLine[]
  truncated: boolean
  warnings?: string[]
}

/** First record of /incidents/{id}/bundle?format=ndjson, and the top of the JSON form. */
export interface IncidentBundleHeader {
  schema: 'kubesentry.io/incident-bundle/v1'
  generatedAt: string
  cluster?: string
  incident: Incident
  window: { from: string; to: string }
  complete: boolean
  /** Sections left out, with the reason (e.g. {"cloudtrail": "forbidden"}). */
  omitted?: Record<string, string>
  truncated?: Record<string, boolean>
}

// ---- AI investigator (/api/v1/incidents/{id}/investigations…) ----
// An agent reads a redacted digest of the incident, pulls more evidence through
// read-only tools limited to the starting user's permissions, and submits a
// report. Runs are asynchronous: POST answers 202, then poll the run.
// See docs/contracts.md "AI investigator".

export type InvestigationStatus = 'running' | 'completed' | 'refused' | 'failed' | 'cancelled'

/** Sections the run could read for its starter (frozen at start). Reading the run needs the same. */
export interface InvestigationAccess { logs: boolean; audit: boolean; cloudtrail: boolean; nodes: boolean }

export interface InvestigationStep {
  at: string
  /**
   * "turn" (a model reply: "turn 2: 1 tool call (11377 tokens)"), "tool" (a tool call), or "note"
   * (budget, retry, cancel, cache). When a refusal fallback answered a turn, a note reads
   * "turn <n>: <model> declined; the fallback model <model> answered".
   */
  kind: 'turn' | 'tool' | 'note'
  /** Tool name for kind "tool": list_signals, get_logs, get_metric_series, get_k8s_events, get_audit_events, get_cloudtrail_events, get_workload_state, submit_report. */
  tool?: string
  /** One line for people, e.g. "get_logs checkout-7d9 error 12:01–12:20: 48 lines" (times in UTC). Never raw tool input. */
  text: string
  /** Tool steps, and a turn whose model request failed ("error"). */
  result?: 'ok' | 'error' | 'denied' | 'invalid'
}

/**
 * A reference to evidence: signal:<id>, event:<uid>, log:<n> (numbered per run), logtpl:<n> (the digest's log
 * templates), audit:<auditID>, cloudtrail:<eventID>, metric:<metric>:<label> (metric is memory, requests or errors;
 * the label may hold colons).
 */
export type EvidenceRef = string

export interface InvestigationEvidence {
  ref: EvidenceRef
  kind: 'signal' | 'event' | 'log' | 'logtpl' | 'audit' | 'cloudtrail' | 'metric'
  /** When it happened (a metric's peak, an event group's latest event, a template's first line). */
  time?: string
  /** The object or series: "Pod/<name>", "<pod>/<container>" for a log line, "<pod>, <pod>" for a template, a series label. */
  object?: string
  /** Redacted, at most 300 characters: a title, a log line or template, "max 2.517e+08 bytes at <time>". */
  snippet?: string
}

export interface InvestigationReport {
  summary: string
  status: 'root_cause_identified' | 'likely_cause' | 'inconclusive'
  root_cause: { statement: string; confidence: 'high' | 'medium' | 'low'; evidence: EvidenceRef[] }
  contributing_factors: { statement: string; evidence: EvidenceRef[] }[]
  timeline: { time: string; event: string; evidence: EvidenceRef[] }[]
  impact: string
  /**
   * Read-only checks; kubesentry never runs them. A command that was not read-only is removed: `command` is
   * then "" and the description ends with "(command removed: not read-only)".
   */
  suggested_checks: { description: string; command: string }[]
  remediation_ideas: { description: string; risk: string }[]
  open_questions: string[]
  data_gaps: string[]
  /** Refs the model cited that the run never showed it (set by the server, not the model). */
  unverified?: EvidenceRef[]
}

export interface InvestigationUsage { input: number; output: number; cacheRead: number; cacheWrite: number }

export interface InvestigationSummary {
  id: string
  incidentId: string
  status: InvestigationStatus
  requestedBy: string
  createdAt: string
  finishedAt?: string
  provider: 'anthropic' | 'bedrock' | 'demo'
  model: string
  effort: string
  /** The report's status and root-cause confidence, once completed. */
  outcome?: InvestigationReport['status']
  confidence?: InvestigationReport['root_cause']['confidence']
  /**
   * Served from an earlier run with the same input (no new model call): that run's ID, which starts with its
   * creation time (20261016T120102Z-<hex>). The copy carries its report, evidence and steps, zero usage.
   */
  cachedFrom?: string
}

export interface Investigation extends InvestigationSummary {
  access: InvestigationAccess
  /**
   * Sections left out, with the reason: what the starter could not see ("forbidden"; keys logs, audit,
   * cloudtrail, nodes) and sections the bundle could not read.
   */
  omitted?: Record<string, string>
  steps: InvestigationStep[]
  report?: InvestigationReport
  /** The ledger entries of the verified refs the report cites, in citation order. */
  evidence?: InvestigationEvidence[]
  /** status "refused": the model's refusal category and explanation. */
  refusal?: { category: string; explanation: string }
  /**
   * status "failed": a short reason without provider response bodies: "timeout", "interrupted",
   * "budget: turns|tool calls|tokens", "no valid report", "max_tokens: …", "context window exceeded",
   * "model request failed", "HTTP <status> <type>" ("HTTP 529 overloaded", "HTTP 403 permission").
   */
  error?: string
  /** Tokens over the run; all zero for a cached copy. */
  usage: InvestigationUsage
  turns: number
  toolCalls: number
}

/** POST /api/v1/incidents/{id}/investigations: 202 with the new run, or 200 with cached: true. */
export interface InvestigationStartResponse {
  investigation: Investigation
  cached?: boolean
}

/** POST /api/v1/incidents/{id}/investigations answers 409 with this while a run of the incident is running. */
export interface InvestigationConflict {
  error: string
  runningId: string
}

/** GET /api/v1/incidents/{id}/investigations: newest first. */
export interface InvestigationsResponse {
  items: InvestigationSummary[]
  /** Runs on this incident that used sections the caller cannot see. */
  hidden: number
}

// ---- Settings (/api/v1/settings/investigator) ----
// Mirrors internal/settings (Investigator, State, Environment, Credentials,
// Guide, TestResult) and internal/api/settings.go. docs/contracts.md
// "Settings (M7b)".

export type InvestigatorProvider = 'anthropic' | 'bedrock'
export type BedrockAPI = 'mantle' | 'runtime'
export type Effort = 'low' | 'medium' | 'high' | 'xhigh' | 'max'

export interface InvestigatorValues {
  enabled: boolean
  provider: InvestigatorProvider
  /** Empty: the provider's default model. */
  model: string
  effort: Effort
  /** Empty: -aws-region, then AWS_REGION. */
  region: string
  bedrockAPI: BedrockAPI | ''
  endpoint: string
  /** auto, off or a model ID. */
  fallback: string
  limits: {
    perHour: number
    perHourTotal: number
    concurrency: number
    maxTurns: number
    maxToolCalls: number
    maxTokens: number
    /** A duration: "10m", "1h30m". */
    timeout: string
  }
}

export interface SettingSource {
  source: 'helm' | 'ui'
  by?: string
  at?: string
}

export interface SettingChange {
  field: string
  old: string
  new: string
}

export interface SettingsAuditEntry {
  id: number
  at: string
  actor: string
  action: 'save' | 'reset'
  version: number
  changes: SettingChange[]
  egressAcknowledged: boolean
  egressAckByPlatform?: boolean
}

export interface SettingsEnvironment {
  kind: 'eks' | 'kubernetes' | 'remote'
  label: string
  cluster?: string
  region?: string
  platform?: string
  namespace?: string
  serviceAccount?: string
  kubeContext?: string
  oidcIssuer?: string
}

export interface SettingsCredentials {
  kind: 'bedrock-api-key' | 'profile' | 'env-keys' | 'irsa' | 'pod-identity' | 'container' | 'instance-role' | 'none'
  label: string
  roleArn?: string
  profile?: string
  sso?: boolean
  note?: string
  anthropicKey: boolean
  accountId?: string
}

export interface SetupStep {
  title: string
  text: string
  code?: string
  lang?: 'json' | 'yaml' | 'shell'
}

export interface SetupTab {
  id: 'irsa' | 'pod-identity' | 'outside-eks' | 'anthropic'
  title: string
  summary: string
  steps: SetupStep[]
}

export interface InvestigatorSettings {
  values: InvestigatorValues
  helm: InvestigatorValues
  /** Keyed by field: "enabled", "model", "limits.timeout", … */
  sources: Record<string, SettingSource>
  mode: 'ui' | 'locked'
  locked: boolean
  version: number
  updatedAt?: string
  updatedBy?: string
  /** What this replica runs with. */
  applied: { enabled: boolean; at?: string; error?: string }
  audit: SettingsAuditEntry[]
  egressAckByPlatform: boolean
  /** -incidents is on (the investigator needs it). */
  incidents: boolean
  anthropicKey: boolean
  defaultRegion?: string
  environment: SettingsEnvironment
  credentials: SettingsCredentials
  setup: { recommended: SetupTab['id']; tabs: SetupTab[] }
  options: { providers: InvestigatorProvider[]; bedrockAPIs: BedrockAPI[]; efforts: Effort[]; fields: string[] }
}

/** PUT /api/v1/settings/investigator */
export interface InvestigatorSettingsSave {
  version: number
  values?: InvestigatorValues
  reset?: boolean
  egressAcknowledged?: boolean
}

/** POST /api/v1/settings/investigator/test */
export interface ConnectionTestResult {
  ok: boolean
  provider: string
  region?: string
  endpoint: string
  model: string
  identityArn?: string
  account?: string
  credentialSource?: string
  latencyMs: number
  at: string
  error?: {
    kind: 'no_credentials' | 'access_denied' | 'model_access' | 'model_unavailable' | 'network' | 'auth' | 'throttled' | 'config' | 'other'
    message: string
    hint?: string
    action?: string
    status?: number
  }
}
