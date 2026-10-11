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
}

export interface UnusedPVC {
  namespace: string
  name: string
  storageClass: string
  phase: string
  capacityBytes: number
  created: string
  ageHours: number
  estMonthlyCostUSD: number
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
}

export interface PodsResponse {
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

export interface AuditEventsResponse {
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
  images: string[]
  created: string
  schedule?: string
  suspended?: boolean
  lastScheduleTime?: string
  lastSuccessTime?: string
}

export interface WorkloadsResponse {
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
}

export interface VolumeSummary {
  name: string
  phase: string
  storageClass: string
  reclaimPolicy: string
  source: string
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
}

export interface StorageResponse {
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

export interface SecurityResponse {
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

export type GraphKind = 'Ingress' | 'Service' | 'Deployment' | 'StatefulSet' | 'DaemonSet' | 'Job' | 'CronJob' | 'Pod' | 'PVC' | 'Node'

export interface GraphNode {
  /** "<Kind>/<namespace>/<name>", or "Node/<name>" */
  id: string
  kind: GraphKind
  name: string
  namespace?: string
  status: Status
  detail: string
}

/** From the routing or owning object to what it routes to, runs or uses. */
export interface GraphEdge {
  from: string
  to: string
}

export interface MapResponse {
  namespace: string
  namespaces: string[]
  graph: { nodes: GraphNode[]; edges: GraphEdge[] }
}

export interface NodePod {
  namespace: string
  name: string
  phase: string
  status: Status
  /** "Kind/name" of the owning workload */
  workload?: string
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
  pods: NodePod[]
}

export interface NodesResponse {
  count: number
  items: NodeSummary[]
}
