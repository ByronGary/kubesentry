// Pure helpers for the Workloads, Storage and Security pages, kept free of React so they are testable.

import { podHref, workloadHref } from './findings'
import { ago } from './format'
import { isWorkloadKind } from './mapLayout'
import type { PodSummary, SecurityFinding, SecurityResponse, SecuritySeverity, WorkloadSummary } from './types'

/** Case-insensitive substring match of a search box against any of the fields. */
export function matches(q: string, ...fields: (string | undefined)[]): boolean {
  const needle = q.trim().toLowerCase()
  if (!needle) return true
  return fields.some((f) => f !== undefined && f.toLowerCase().includes(needle))
}

export interface WorkloadFilter {
  q: string
  namespace: string
  kind: string
  status: string
}

export function filterWorkloads(items: WorkloadSummary[], f: WorkloadFilter): WorkloadSummary[] {
  return items.filter(
    (w) =>
      (!f.namespace || w.namespace === f.namespace) &&
      (!f.kind || w.kind === f.kind) &&
      (!f.status || w.status === f.status) &&
      matches(f.q, `${w.namespace}/${w.name}`, ...(w.images ?? [])),
  )
}

/** The Ready column: "2/3", or for a CronJob its schedule and last run. */
export function readiness(w: WorkloadSummary, now: number = Date.now()): { main: string; sub?: string } {
  if (w.kind === 'CronJob') {
    const last = w.lastScheduleTime ? `last run ${ago(w.lastScheduleTime, now)}` : 'never run'
    return { main: w.schedule || '-', sub: w.suspended ? `suspended, ${last}` : last }
  }
  return { main: `${w.ready}/${w.desired}` }
}

/** Pods matching a search over name, namespace, node, workload, phase and reason. */
export function filterPods(items: PodSummary[], q: string): PodSummary[] {
  if (!q.trim()) return items
  return items.filter((p) => matches(q, `${p.namespace}/${p.name}`, p.node, p.workload, p.reason, p.phase))
}

/** Waiting reasons that mean the pod is broken rather than starting. */
const BAD_REASON = /BackOff|Err|Invalid|Failed|OOMKilled|Error|CreateContainer/i

/** How serious a pod's reason is: crit for crash loops and image errors, warn otherwise. */
export function reasonStatus(reason: string | undefined): 'crit' | 'warn' | undefined {
  if (!reason) return undefined
  return BAD_REASON.test(reason) ? 'crit' : 'warn'
}

/** Pods stuck waiting, by reason, most pods first: ["CrashLoopBackOff ×3", "ImagePullBackOff ×1"]. */
export function waitingReasons(waiting: Record<string, number> | undefined): string[] {
  return Object.entries(waiting ?? {})
    .filter(([, n]) => n > 0)
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([r, n]) => `${r} ×${n}`)
}

/** "Deployment/web" into its parts; undefined when it is not "Kind/name". */
export function splitWorkload(ref: string | undefined): { kind: string; name: string } | undefined {
  if (!ref) return undefined
  const i = ref.indexOf('/')
  if (i <= 0 || i === ref.length - 1) return undefined
  return { kind: ref.slice(0, i), name: ref.slice(i + 1) }
}

/** First image and how many more there are. */
export function imageSummary(images: string[] | null | undefined): { first: string; more: number } {
  const list = images ?? []
  return { first: list[0] ?? '-', more: Math.max(0, list.length - 1) }
}

/**
 * An image reference short enough for a table cell: the registry host is
 * replaced by "…/" and a digest is cut to 12 hex digits. The full reference
 * belongs in a tooltip.
 */
export function shortImage(ref: string): string {
  let s = ref.replace(/@sha256:([0-9a-f]{12})[0-9a-f]+/, '@sha256:$1…')
  const i = s.indexOf('/')
  if (i > 0) {
    const first = s.slice(0, i)
    // Docker's rule: the first part is a registry host if it has a dot or port, or is localhost.
    if (first.includes('.') || first.includes(':') || first === 'localhost') s = `…/${s.slice(i + 1)}`
  }
  return s
}

/** Split "namespace/name" into its parts; cluster-scoped names have no namespace. */
export function splitSubject(subject: string, namespace?: string): { namespace: string; name: string } {
  const i = subject.indexOf('/')
  if (i === -1) return { namespace: namespace ?? '', name: subject }
  return { namespace: namespace ?? subject.slice(0, i), name: subject.slice(i + 1) }
}

/** Where a security finding's subject links: the pod page, the workloads page, or nowhere. */
export function securitySubjectHref(f: SecurityFinding): string | undefined {
  const { namespace, name } = splitSubject(f.subject, f.namespace)
  if (f.subjectKind === 'Pod' && namespace) return podHref(namespace, name)
  if (isWorkloadKind(f.subjectKind)) return workloadHref(namespace, name)
  return undefined
}

export interface SecurityFilter {
  category: string
  severity: string
  q: string
  /** Include cluster plumbing. */
  system: boolean
  /** Only this check, when set. */
  check: string
}

export interface SecurityGroup {
  check: string
  title: string
  /** The worst severity in the group. */
  severity: SecuritySeverity
  findings: SecurityFinding[]
}

const SEV_RANK: Record<SecuritySeverity, number> = { crit: 0, warn: 1, info: 2 }

/**
 * Whether a security response holds only part of the findings: the server says
 * there is more, or its counts (which leave out system findings) exceed the
 * non-system findings that came back. A server without summaries sends
 * everything, so this is false for it.
 */
export function securityPartial(resp: Pick<SecurityResponse, 'continue' | 'counts' | 'findings'>): boolean {
  if (resp.continue) return true
  const total = Object.values(resp.counts ?? {}).reduce((s: number, n) => s + (n ?? 0), 0)
  let shown = 0
  for (const f of resp.findings ?? []) if (!f.system) shown++
  return total > shown
}

/**
 * Severity filter: "" (the default) shows critical and warnings, plus info when
 * a single check is picked; "all" shows everything; otherwise one severity.
 * Info findings are numerous hardening hints that would bury the real risks.
 */
function severityShown(f: SecurityFilter, s: SecuritySeverity): boolean {
  if (f.severity === 'all') return true
  if (f.severity) return s === f.severity
  return s !== 'info' || f.check !== ''
}

/** Filter, then group by check: worst severity first, then the biggest groups. */
export function groupSecurity(findings: SecurityFinding[], f: SecurityFilter): SecurityGroup[] {
  const groups = new Map<string, SecurityGroup>()
  for (const x of findings) {
    if (!f.system && x.system) continue
    if (f.category && x.category !== f.category) continue
    if (!severityShown(f, x.severity)) continue
    if (f.check && x.check !== f.check) continue
    if (!matches(f.q, x.subject, x.subjectKind, x.title, x.detail, x.check)) continue
    const g = groups.get(x.check)
    if (!g) groups.set(x.check, { check: x.check, title: x.title, severity: x.severity, findings: [x] })
    else {
      g.findings.push(x)
      if (SEV_RANK[x.severity] < SEV_RANK[g.severity]) g.severity = x.severity
    }
  }
  const out = [...groups.values()]
  for (const g of out) g.findings.sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity] || a.subject.localeCompare(b.subject))
  return out.sort(
    (a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity] || b.findings.length - a.findings.length || a.title.localeCompare(b.title),
  )
}
