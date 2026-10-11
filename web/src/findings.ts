import { ago, formatBytes, formatExpiry, formatHours, formatUSD, listSome, plural } from './format'
import type { AuditEvent, CertificatesResponse, OOMResponse, SecurityFinding, SecurityResponse, UnusedPVCResponse } from './types'

export type Severity = 'crit' | 'warn' | 'info'
export type Category = 'Memory' | 'OOMKilled' | 'Security' | 'Certificates' | 'Volumes' | 'Activity'

/** One line on the Findings page: something worth a person's attention. */
export interface Finding {
  id: string
  severity: Severity
  category: Category
  /** What it is about: a pod, or a short label for cluster-wide findings. */
  subject: string
  /** Whether `subject` is an identifier (shown in monospace). */
  subjectIsId: boolean
  sentence: string
  /** Small right-aligned context, e.g. "high confidence". */
  meta: string
  href: string
  /** Lower sorts first within a severity. */
  order: number
}

const SEVERITY_RANK: Record<Severity, number> = { crit: 0, warn: 1, info: 2 }
// Within a severity, group by category; `order` is only comparable inside one category.
const CATEGORY_RANK: Record<Category, number> = { OOMKilled: 0, Memory: 1, Security: 2, Certificates: 3, Volumes: 4, Activity: 5 }

export function podHref(ns: string, pod: string): string {
  return `#/pods/${encodeURIComponent(ns)}/${encodeURIComponent(pod)}`
}

/** The Workloads page filtered to one namespace and name. */
export function workloadHref(ns: string, name: string): string {
  const p = new URLSearchParams()
  if (ns) p.set('namespace', ns)
  if (name) p.set('q', name)
  const q = p.toString()
  return `#/workloads${q ? `?${q}` : ''}`
}

export function memoryFindings(oom: OOMResponse | undefined): Finding[] {
  const out: Finding[] = []
  for (const l of oom?.leaks ?? []) {
    const rate = `${formatBytes(l.slopeBytesPerHour)}/h`
    const ttl = l.timeToLimitHours
    let sentence: string
    let severity: Severity
    if (ttl !== undefined && l.limitBytes) {
      severity = ttl < 6 ? 'crit' : 'warn'
      sentence = `${l.container} grows ${rate} and reaches its ${formatBytes(l.limitBytes)} limit in about ${formatHours(ttl)}.`
    } else {
      severity = 'warn'
      sentence = `${l.container} grows ${rate} and has no memory limit, so nothing stops it growing.`
    }
    out.push({
      id: `leak:${l.namespace}/${l.pod}/${l.container}`,
      severity,
      category: 'Memory',
      subject: `${l.namespace}/${l.pod}`,
      subjectIsId: true,
      sentence,
      meta: `${l.confidence} confidence`,
      href: podHref(l.namespace, l.pod),
      order: ttl ?? Number.MAX_SAFE_INTEGER,
    })
  }
  return out
}

export function oomFindings(oom: OOMResponse | undefined, now: number = Date.now()): Finding[] {
  return (oom?.events ?? []).map((e) => ({
    id: `oom:${e.namespace}/${e.pod}/${e.container}`,
    severity: 'crit' as const,
    category: 'OOMKilled' as const,
    subject: `${e.namespace}/${e.pod}`,
    subjectIsId: true,
    sentence: `${e.container} was OOMKilled ${ago(e.lastOOMAt, now)}, after ${e.restartCount} ${plural(e.restartCount, 'restart', 'restarts')}.`,
    meta: `exit code ${e.exitCode}`,
    href: podHref(e.namespace, e.pod),
    order: new Date(e.lastOOMAt).getTime() * -1,
  }))
}

export function volumeFindings(pvcs: UnusedPVCResponse | undefined): Finding[] {
  if (!pvcs || pvcs.count === 0) return []
  const total = formatUSD(pvcs.totalEstMonthlyCostUSD)
  return [
    {
      id: 'volumes:unused',
      severity: 'warn',
      category: 'Volumes',
      subject: 'Unused volumes',
      subjectIsId: false,
      sentence: `${pvcs.count} ${plural(pvcs.count, 'volume claim is', 'volume claims are')} not mounted by any pod, costing about ${total} a month.`,
      meta: 'estimate',
      href: '#/storage',
      order: -pvcs.totalEstMonthlyCostUSD,
    },
  ]
}

/** How each security check reads as a sentence, given how many objects it hit. */
const SECURITY_PHRASE: Record<string, (n: number) => string> = {
  privileged: (n) => `${n} ${plural(n, 'workload runs', 'workloads run')} privileged containers`,
  'host-namespaces': (n) => `${n} ${plural(n, "workload shares the node's", "workloads share the node's")} network, PID or IPC namespace`,
  'host-path': (n) => `${n} ${plural(n, 'workload mounts', 'workloads mount')} paths from the node`,
  capabilities: (n) => `${n} ${plural(n, 'workload adds', 'workloads add')} Linux capabilities`,
  'run-as-root': (n) => `${n} ${plural(n, 'workload may run', 'workloads may run')} as root`,
  'privilege-escalation': (n) => `${n} ${plural(n, 'workload allows', 'workloads allow')} privilege escalation`,
  'no-memory-limit': (n) => `${n} ${plural(n, 'workload has', 'workloads have')} no memory limit`,
  'token-automount': (n) => `${n} ${plural(n, 'workload mounts', 'workloads mount')} a service account token`,
  'cluster-admin': (n) => `${n} ${plural(n, 'subject is', 'subjects are')} bound to cluster-admin`,
  'anonymous-binding': (n) => `${n} ${plural(n, 'binding grants', 'bindings grant')} access to anonymous users`,
  'wildcard-rbac': (n) => `${n} ${plural(n, 'role uses', 'roles use')} wildcard verbs or resources`,
  'secret-readers': (n) => `${n} ${plural(n, 'subject can', 'subjects can')} read secrets`,
  'psa-missing': (n) => `${n} ${plural(n, 'namespace has', 'namespaces have')} no Pod Security enforce label`,
  'psa-privileged': (n) => `${n} ${plural(n, 'namespace enforces', 'namespaces enforce')} the privileged Pod Security level`,
  nodeport: (n) => `${n} ${plural(n, 'service is', 'services are')} exposed on node ports`,
  loadbalancer: (n) => `${n} ${plural(n, 'service is', 'services are')} exposed through a load balancer`,
  'external-ip': (n) => `${n} ${plural(n, 'service has', 'services have')} external IPs`,
  'ingress-no-tls': (n) => `${n} ${plural(n, 'ingress serves', 'ingresses serve')} plain HTTP without TLS`,
}

const SECURITY_CATEGORY_LABEL: Record<string, string> = { pod: 'Pods', rbac: 'RBAC', namespace: 'Namespaces', exposure: 'Exposure' }

/**
 * One line per security check with critical or warning hits outside system
 * components, e.g. "2 workloads run privileged containers: data/ml-trainer, shop/cache."
 */
export function securityFindings(resp: SecurityResponse | undefined, partial = false): Finding[] {
  const byCheck = new Map<string, SecurityFinding[]>()
  for (const f of resp?.findings ?? []) {
    if (f.system || (f.severity !== 'crit' && f.severity !== 'warn')) continue
    byCheck.set(f.check, [...(byCheck.get(f.check) ?? []), f])
  }
  const out: Finding[] = []
  for (const [check, fs] of byCheck) {
    const severity: Severity = fs.some((f) => f.severity === 'crit') ? 'crit' : 'warn'
    const ordered = [...fs].sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] || a.subject.localeCompare(b.subject))
    const subjects = [...new Set(ordered.map((f) => f.subject))]
    const n = subjects.length
    const phrase = SECURITY_PHRASE[check]?.(n) ?? `${fs[0].title}: ${n} ${plural(n, 'object', 'objects')}`
    out.push({
      id: `security:${check}`,
      severity,
      category: 'Security',
      subject: fs[0].title,
      subjectIsId: false,
      // A summary holds only the most severe findings, so the count is a lower bound.
      sentence: `${partial ? `At least ${phrase}` : phrase}: ${listSome(subjects)}.`,
      meta: SECURITY_CATEGORY_LABEL[fs[0].category] ?? fs[0].category,
      href: `#/security?check=${encodeURIComponent(check)}`,
      order: -n,
    })
  }
  return out
}

/** Make a server detail string read as a sentence. */
function asSentence(s: string): string {
  const t = s.trim()
  if (!t) return t
  const first = t[0].toUpperCase() + t.slice(1)
  return /[.!?…]$/.test(first) ? first : `${first}.`
}

function clip(s: string, max: number): string {
  return s.length > max ? `${s.slice(0, max - 1).trimEnd()}…` : s
}

/** Certificates and issuers that are failing or close to expiry. */
export function certFindings(resp: CertificatesResponse | undefined): Finding[] {
  if (!resp?.installed) return []
  const out: Finding[] = []
  for (const c of resp.certificates ?? []) {
    if (c.status !== 'crit' && c.status !== 'warn') continue
    const h = c.expiresInHours
    const fallback = h !== undefined && h < 0 ? `Expired ${formatHours(-h)} ago` : c.ready === 'False' ? `Not ready${c.reason ? `: ${c.reason}` : ''}` : 'Needs attention'
    out.push({
      id: `cert:${c.namespace}/${c.name}`,
      severity: c.status,
      category: 'Certificates',
      subject: `${c.namespace}/${c.name}`,
      subjectIsId: true,
      sentence: asSentence(c.detail || fallback),
      meta: h !== undefined ? (h < 0 ? 'expired' : `expires ${formatExpiry(h)}`) : `${c.issuerKind} ${c.issuerName}`,
      href: `#/certificates?q=${encodeURIComponent(`${c.namespace}/${c.name}`)}`,
      order: h ?? Number.MAX_SAFE_INTEGER,
    })
  }
  for (const i of resp.issuers ?? []) {
    if (i.status !== 'crit' && i.status !== 'warn') continue
    const name = i.namespace ? `${i.namespace}/${i.name}` : i.name
    // Add the condition message unless the detail already says it.
    const detail = i.detail.replace(/[.\s]+$/, '')
    const message = (i.message ?? '').replace(/[.\s]+$/, '')
    const why = [detail, message && !detail.includes(message) ? clip(message, 160) : ''].filter(Boolean).join(': ')
    out.push({
      id: `issuer:${i.kind}/${name}`,
      severity: i.status,
      category: 'Certificates',
      subject: `${i.kind} ${name}`,
      subjectIsId: true,
      sentence: asSentence(why || `${i.kind} is not ready`),
      meta: `${i.certificates} ${plural(i.certificates, 'certificate', 'certificates')}`,
      href: '#/certificates',
      // Issuers before the certificates they break.
      order: -1e9 - i.certificates,
    })
  }
  return out
}

interface TagRule {
  severity: Severity
  /** Builds the sentence from the matching events. */
  sentence: (events: AuditEvent[]) => string
}

function who(events: AuditEvent[]): string {
  const counts = new Map<string, number>()
  for (const e of events) counts.set(e.username, (counts.get(e.username) ?? 0) + 1)
  const names = [...counts.entries()].sort((a, b) => b[1] - a[1]).map(([u]) => u)
  return names.length > 3 ? `${names.slice(0, 3).join(', ')} and ${names.length - 3} more` : names.join(', ')
}

const n = (events: AuditEvent[], one: string, many: string) => `${events.length} ${plural(events.length, one, many)}`

// Only tags worth interrupting someone for. delete and portforward stay on the Activity page.
const TAG_RULES: Record<string, TagRule> = {
  anonymous: { severity: 'crit', sentence: (e) => `${n(e, 'request', 'requests')} came from unauthenticated users.` },
  'rbac-change': { severity: 'warn', sentence: (e) => `${n(e, 'RBAC change was', 'RBAC changes were')} made by ${who(e)}.` },
  impersonate: { severity: 'warn', sentence: (e) => `${who(e)} acted as another identity ${e.length} ${plural(e.length, 'time', 'times')}.` },
  denied: { severity: 'warn', sentence: (e) => `${n(e, 'request was', 'requests were')} denied, from ${who(e)}.` },
  exec: { severity: 'info', sentence: (e) => `${who(e)} opened ${n(e, 'shell or exec session', 'shell or exec sessions')} in pods.` },
  'secret-access': { severity: 'info', sentence: (e) => `${who(e)} read ${n(e, 'secret', 'secrets')}.` },
  'secret-change': { severity: 'info', sentence: (e) => `${who(e)} changed ${n(e, 'secret', 'secrets')}.` },
  'debug-container': { severity: 'info', sentence: (e) => `${who(e)} attached ${n(e, 'debug container', 'debug containers')}.` },
  'token-request': { severity: 'info', sentence: (e) => `${who(e)} created ${n(e, 'service account token', 'service account tokens')}.` },
}

const TAG_LABEL: Record<string, string> = {
  anonymous: 'Unauthenticated access',
  'rbac-change': 'RBAC changes',
  impersonate: 'Impersonation',
  denied: 'Denied requests',
  exec: 'Exec sessions',
  'secret-access': 'Secret reads',
  'secret-change': 'Secret changes',
  'debug-container': 'Debug containers',
  'token-request': 'Token requests',
}

export function activityFindings(events: AuditEvent[] | undefined): Finding[] {
  const byTag = new Map<string, AuditEvent[]>()
  for (const e of events ?? []) {
    for (const t of e.tags ?? []) {
      if (!TAG_RULES[t]) continue
      byTag.set(t, [...(byTag.get(t) ?? []), e])
    }
  }
  const out: Finding[] = []
  for (const [tag, evs] of byTag) {
    const rule = TAG_RULES[tag]
    out.push({
      id: `activity:${tag}`,
      severity: rule.severity,
      category: 'Activity',
      subject: TAG_LABEL[tag],
      subjectIsId: false,
      sentence: rule.sentence(evs),
      meta: ago(evs[0].time),
      href: `#/activity?tag=${encodeURIComponent(tag)}`,
      order: 0,
    })
  }
  return out
}

/** Most urgent first: severity, then category, then the lowest `order` within a category. */
export function rank(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    if (a.severity !== b.severity) return SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]
    if (a.category !== b.category) return CATEGORY_RANK[a.category] - CATEGORY_RANK[b.category]
    if (a.order !== b.order) return a.order - b.order
    return a.id.localeCompare(b.id)
  })
}

/** What the empty Findings page checked: only sources that answered are named. */
export interface Checked {
  /** Prometheus answered, so leaks were looked for. */
  leaks: boolean
  security: boolean
  certs: boolean
  /** The audit log answered. */
  activity: boolean
}

/** "No OOM kills, leaking containers or unused volumes in the last 24 hours." */
export function nothingFoundText(c: Checked, lookback: string): string {
  const parts = ['OOM kills', c.leaks && 'leaking containers', c.security && 'security risks', c.certs && 'failing certificates', 'unused volumes', c.activity && 'notable activity'].filter(
    (p): p is string => typeof p === 'string',
  )
  return `No ${parts.slice(0, -1).join(', ')} or ${parts[parts.length - 1]} ${lookback}.`
}
