// The Overview dashboard, from GET /api/v1/overview: what each tile shows,
// where every number links (already filtered), the health strip, and which
// parts a restricted caller does not get. Kept free of React so it is testable.

import { auditTarget } from './components/ActivityTable'
import { ago, formatUSD, plural } from './format'
import { formatAgeSeconds, STALE_AFTER_SECONDS } from './retention'
import type { AttentionItem, AttentionSeverity, AuditEvent, OverviewHistory, OverviewPool, OverviewResponse, Status } from './types'

// ---- Filters ----

export interface OverviewFilter {
  namespace: string
  owner: string
}

export function readFilter(q: URLSearchParams): OverviewFilter {
  return { namespace: q.get('namespace')?.trim() ?? '', owner: q.get('owner')?.trim() ?? '' }
}

export function isFiltered(f: OverviewFilter): boolean {
  return f.namespace !== '' || f.owner !== ''
}

/** The API path for a filter: `/api/v1/overview?namespace=&owner=`, without empty parameters. */
export function overviewPath(f: OverviewFilter): string {
  const p = new URLSearchParams()
  if (f.namespace) p.set('namespace', f.namespace)
  if (f.owner) p.set('owner', f.owner)
  const s = p.toString()
  return `/api/v1/overview${s ? `?${s}` : ''}`
}

/** "All 48 namespaces you can see", "Namespace shop", "team-payments: 4 namespaces". */
export function scopeText(scope: OverviewResponse['scope']): string {
  const n = scope.namespaces
  const count = `${n.toLocaleString('en-US')} ${plural(n, 'namespace', 'namespaces')}`
  if (scope.namespace && scope.owner) return `Namespace ${scope.namespace}, owned by ${scope.owner}`
  if (scope.namespace) return `Namespace ${scope.namespace}`
  if (scope.owner) return `${scope.owner}: ${count}`
  return n === 1 ? 'The 1 namespace you can see' : `All ${count} you can see`
}

/**
 * Namespaces for the scope picker, sorted: the server's list when it sends one
 * (not in the contract yet), else the Map's, plus any named in Needs attention
 * and the one chosen now.
 */
export function namespaceOptions(lists: (readonly string[] | undefined)[], attention: readonly AttentionItem[], current: string): string[] {
  const s = new Set<string>()
  for (const l of lists) for (const n of l ?? []) if (n) s.add(n)
  for (const a of attention) if (a.namespace) s.add(a.namespace)
  if (current) s.add(current)
  return [...s].sort((a, b) => a.localeCompare(b))
}

// ---- Links ----

/**
 * Only in-app hash routes from the server are followed ("#/workloads?..."); a
 * missing or foreign href (another scheme, another site) is dropped, so a
 * row never links anywhere unexpected.
 */
export function safeHref(h: string | undefined): string | undefined {
  if (!h) return undefined
  return /^#\/[^\s]*$/.test(h) ? h : undefined
}

function link(path: string, params: Record<string, string | undefined> = {}): string {
  const p = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) if (v) p.set(k, v)
  const s = p.toString()
  return `#/${path}${s ? `?${s}` : ''}`
}

// ---- Health strip ----

export interface HealthItem {
  key: 'data' | 'prometheus' | 'audit' | 'cloudwatch' | 'agents'
  status: Status
  text: string
  href?: string
}

/** CloudWatch delivers audit events late; past these, the lag is worth a look. */
export const CLOUDWATCH_WARN_SECONDS = 300
export const CLOUDWATCH_CRIT_SECONDS = 1800

export function healthItems(o: Pick<OverviewResponse, 'ageSeconds' | 'health'>): HealthItem[] {
  const out: HealthItem[] = []
  const age = Number.isFinite(o.ageSeconds) ? Math.max(0, o.ageSeconds) : 0
  out.push({ key: 'data', status: age > STALE_AFTER_SECONDS ? 'warn' : 'ok', text: `Data ${formatAgeSeconds(age)} old` })
  const h = o.health
  if (h.prometheus === 'ok') out.push({ key: 'prometheus', status: 'ok', text: 'Prometheus', href: '#/memory' })
  else if (h.prometheus === 'unavailable') out.push({ key: 'prometheus', status: 'warn', text: 'Prometheus unavailable', href: '#/memory' })
  else out.push({ key: 'prometheus', status: 'unknown', text: 'No Prometheus' })
  if (h.auditStore === 'ok') out.push({ key: 'audit', status: 'ok', text: 'Audit store' })
  else if (h.auditStore === 'degraded') out.push({ key: 'audit', status: 'warn', text: 'Audit store degraded' })
  else out.push({ key: 'audit', status: 'unknown', text: 'No audit log' })
  if (h.cloudwatchLagSeconds !== undefined && Number.isFinite(h.cloudwatchLagSeconds)) {
    const lag = Math.max(0, h.cloudwatchLagSeconds)
    const status: Status = lag >= CLOUDWATCH_CRIT_SECONDS ? 'crit' : lag >= CLOUDWATCH_WARN_SECONDS ? 'warn' : 'ok'
    out.push({ key: 'cloudwatch', status, text: `CloudWatch lag ${formatAgeSeconds(lag)}` })
  }
  if (h.agents) {
    const { reporting, stale } = h.agents
    out.push({
      key: 'agents',
      status: stale > 0 ? 'warn' : reporting > 0 ? 'ok' : 'unknown',
      text: `Agents ${reporting.toLocaleString('en-US')} reporting${stale > 0 ? `, ${stale.toLocaleString('en-US')} stale` : ''}`,
      href: '#/agents',
    })
  }
  return out
}

// ---- Tiles ----

export interface TileLine {
  key: string
  count: number
  text: string
  /** Shape and word for a count that needs attention; undefined for a neutral or zero count. */
  status?: Status
  href?: string
}

export interface TileSpark {
  values: number[]
  /** What the line counts, e.g. "unhealthy workloads". */
  label: string
  /** "24h", "40 min". */
  span: string
}

export type TileKey = 'nodes' | 'pods' | 'workloads' | 'certificates' | 'security'

export interface Tile {
  key: TileKey
  title: string
  /** Set when the caller may not see this part of the cluster: the tile says so instead of numbers. */
  restricted?: boolean
  total?: number
  totalHref?: string
  status: Status
  lines: TileLine[]
  /** Small extra facts, e.g. pod reasons or "3 pools · 3 zones". */
  extras: TileLine[]
  foot?: string
  spark?: TileSpark
}

/** The time a history covers: "24h", "6h", "40 min". */
export function historySpan(h: OverviewHistory | undefined, points: number): string {
  if (!h || !(h.stepSeconds > 0) || points < 2) return ''
  const seconds = h.stepSeconds * points
  if (seconds >= 3600) return `${Math.round(seconds / 3600)}h`
  return `${Math.max(1, Math.round(seconds / 60))} min`
}

function spark(h: OverviewHistory | undefined, key: keyof OverviewHistory['series'], label: string): TileSpark | undefined {
  const values = h?.series?.[key]
  if (!values || values.length < 2) return undefined
  return { values, label, span: historySpan(h, values.length) }
}

function worst(lines: TileLine[]): Status {
  if (lines.some((l) => l.status === 'crit')) return 'crit'
  if (lines.some((l) => l.status === 'warn')) return 'warn'
  return 'ok'
}

/** "needs attention" shape for a count: none at zero. */
const flag = (n: number, s: AttentionSeverity): AttentionSeverity | undefined => (n > 0 ? s : undefined)

/**
 * The tiles, in the wireframe's order. A null `nodes` (no access) keeps its
 * tile, saying "not visible to you"; a null `certificates` (no cert-manager)
 * drops the tile. Every number links to the page that explains it, with the
 * namespace filter carried over where that page understands it.
 */
export function tiles(o: OverviewResponse, f: OverviewFilter = { namespace: '', owner: '' }): Tile[] {
  const ns = f.namespace || undefined
  const out: Tile[] = []

  if (o.nodes === null) {
    out.push({ key: 'nodes', title: 'Nodes', restricted: true, status: 'unknown', lines: [], extras: [] })
  } else {
    const n = o.nodes
    const lines: TileLine[] = [
      { key: 'ready', count: n.ready, text: 'ready', href: link('nodes') },
      { key: 'notReady', count: n.notReady, text: 'not ready', status: flag(n.notReady, 'crit'), href: link('nodes') },
    ]
    if (n.cordoned > 0) lines.push({ key: 'cordoned', count: n.cordoned, text: 'cordoned', status: 'warn', href: link('nodes') })
    const pools = n.pools?.length ?? 0
    const zones = n.zones?.length ?? 0
    out.push({
      key: 'nodes',
      title: 'Nodes',
      total: n.total,
      totalHref: link('nodes'),
      status: worst(lines),
      lines,
      extras: [],
      foot: `${pools} ${plural(pools, 'pool', 'pools')} · ${zones} ${plural(zones, 'zone', 'zones')}`,
    })
  }

  const p = o.pods
  const podLines: TileLine[] = [
    { key: 'running', count: p.running, text: 'running', href: link('pods', { namespace: ns }) },
    { key: 'pending', count: p.pending, text: 'pending', status: flag(p.pending, 'warn'), href: link('pods', { namespace: ns, status: 'pending' }) },
    { key: 'failing', count: p.failing, text: 'failing', status: flag(p.failing, 'crit'), href: link('pods', { namespace: ns, status: 'failing' }) },
  ]
  out.push({
    key: 'pods',
    title: 'Pods',
    total: p.total,
    totalHref: link('pods', { namespace: ns }),
    status: worst(podLines),
    lines: podLines,
    extras: podReasons(p.byReason).map(([reason, count]) => ({ key: reason, count, text: reason, href: link('pods', { namespace: ns, q: reason }) })),
    spark: spark(o.history, 'failingPods', 'failing pods'),
  })

  const w = o.workloads
  const wSev = o.badges?.workloads?.severity ?? 'warn'
  const wLines: TileLine[] = [
    { key: 'unhealthy', count: w.unhealthy, text: 'unhealthy', status: flag(w.unhealthy, wSev), href: link('workloads', { namespace: ns, status: 'unhealthy' }) },
  ]
  out.push({
    key: 'workloads',
    title: 'Workloads',
    total: w.total,
    totalHref: link('workloads', { namespace: ns }),
    status: worst(wLines),
    lines: wLines,
    extras: [],
    spark: spark(o.history, 'unhealthyWorkloads', 'unhealthy workloads'),
  })

  if (o.certificates) {
    const c = o.certificates
    const href = link('certificates', { status: 'unhealthy' })
    const cLines: TileLine[] = [
      { key: 'expiringSoon', count: c.expiringSoon, text: 'expire within 14 days', status: flag(c.expiringSoon, 'warn'), href },
      { key: 'notReady', count: c.notReady, text: 'not ready', status: flag(c.notReady, 'crit'), href },
    ]
    if (c.issuerMissing > 0) cLines.push({ key: 'issuerMissing', count: c.issuerMissing, text: 'issuer missing', status: 'crit', href })
    out.push({
      key: 'certificates',
      title: 'Certificates',
      total: c.total,
      totalHref: link('certificates'),
      status: worst(cLines),
      lines: cLines,
      extras: [],
      spark: spark(o.history, 'certsExpiringSoon', 'certificates expiring soon'),
    })
  }

  const s = o.security
  const sLines: TileLine[] = [
    { key: 'crit', count: s.crit, text: 'critical', status: flag(s.crit, 'crit'), href: link('security', { severity: 'crit' }) },
    { key: 'warn', count: s.warn, text: plural(s.warn, 'warning', 'warnings'), status: flag(s.warn, 'warn'), href: link('security', { severity: 'warn' }) },
  ]
  out.push({
    key: 'security',
    title: 'Security',
    total: s.crit + s.warn,
    totalHref: link('security'),
    status: worst(sLines),
    lines: sLines,
    extras: [],
    foot: s.newSince24h !== undefined ? `${s.newSince24h > 0 ? '+' : ''}${s.newSince24h.toLocaleString('en-US')} new since 24h` : undefined,
    spark: spark(o.history, 'securityCrit', 'critical security findings'),
  })
  return out
}

/** Pod reasons, most pods first, at most `max`: [["CrashLoopBackOff", 2], ...]. */
export function podReasons(byReason: Record<string, number> | undefined, max = 3): [string, number][] {
  return Object.entries(byReason ?? {})
    .filter(([, n]) => n > 0)
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, max)
}

// ---- Needs attention ----

const KIND_LABEL: Record<string, string> = {
  crashloop: 'Crash loop',
  'image-pull': 'Image pull',
  oom: 'OOMKilled',
  leak: 'Memory leak',
  pending: 'Pending',
  'cert-expiring': 'Certificate',
  'cert-not-ready': 'Certificate',
  exposure: 'Exposure',
  node: 'Node',
  'unused-pvc': 'Unused volume',
}

/** A label for the check that raised an item: known ones by name, others from their id ("pod-security" → "Pod security"). */
export function kindLabel(kind: string): string {
  if (KIND_LABEL[kind]) return KIND_LABEL[kind]
  const t = kind.replace(/[-_]+/g, ' ').trim()
  return t ? t[0].toUpperCase() + t.slice(1) : 'Finding'
}

export interface AttentionRow {
  key: string
  severity: AttentionSeverity
  kind: string
  subject: string
  title: string
  owner?: string
  /** "14 minutes ago", when the server knows when it started. */
  age?: string
  href?: string
}

/** The top items as rows, worst first (the server's order), at most `max`. */
export function attentionRows(items: readonly AttentionItem[] | undefined, now: number = Date.now(), max = 10): AttentionRow[] {
  return (items ?? []).slice(0, max).map((a, i) => {
    const age = a.since ? ago(a.since, now) : undefined
    return {
      key: `${i}:${a.kind}:${a.namespace ?? ''}/${a.name}`,
      severity: a.severity === 'crit' ? 'crit' : 'warn',
      kind: kindLabel(a.kind),
      subject: a.namespace ? `${a.namespace}/${a.name}` : a.name,
      title: a.title,
      owner: a.owner || undefined,
      age: age && age !== '-' ? age : undefined,
      href: safeHref(a.href),
    }
  })
}

// ---- Capacity ----

export interface PoolRow {
  name: string
  kind: string
  nodes: number
  /** False for Fargate, which has no node capacity to measure. */
  metered: boolean
  cpu?: number
  mem?: number
  href: string
}

const POOL_KIND: Record<OverviewPool['kind'], string> = { nodegroup: 'Node group', karpenter: 'Karpenter', fargate: 'Fargate', other: 'Other' }

const pct = (n: number | undefined) => (n !== undefined && Number.isFinite(n) ? Math.round(n) : undefined)

export function poolRows(pools: readonly OverviewPool[] | undefined): PoolRow[] {
  return (pools ?? []).map((p) => {
    const cpu = pct(p.cpuRequestedPct)
    const mem = pct(p.memRequestedPct)
    return {
      name: p.name,
      kind: POOL_KIND[p.kind] ?? p.kind,
      nodes: p.nodes,
      metered: p.kind !== 'fargate' && (cpu !== undefined || mem !== undefined),
      cpu,
      mem,
      href: link('nodes', { q: p.name }),
    }
  })
}

/** Requested share past which a pool is running out of room. */
export const POOL_HIGH_PCT = 90

// ---- Sensitive activity ----

export interface ActivityCount {
  key: string
  label: string
  count: number
  href: string
  /** Exec into production: called out with a shape and words, not colour alone. */
  highlight?: boolean
}

/** Activity page periods; the window is passed on when it is one of them and not the default. */
const ACTIVITY_SINCE = new Set([1, 168, 720])

export function activityCounts(a: NonNullable<OverviewResponse['activity']>): ActivityCount[] {
  const since = ACTIVITY_SINCE.has(a.windowHours) ? `${a.windowHours}h` : undefined
  const to = (tag: string) => link('activity', { since, tag })
  return [
    { key: 'execProduction', label: 'exec into production', count: a.execProduction, href: to('exec'), highlight: a.execProduction > 0 },
    { key: 'exec', label: plural(a.exec, 'exec session', 'exec sessions'), count: a.exec, href: to('exec') },
    { key: 'secretReads', label: plural(a.secretReads, 'secret read', 'secret reads'), count: a.secretReads, href: to('secret-access') },
    { key: 'rbacChanges', label: plural(a.rbacChanges, 'RBAC change', 'RBAC changes'), count: a.rbacChanges, href: to('rbac-change') },
    { key: 'denied', label: plural(a.denied, 'denied request', 'denied requests'), count: a.denied, href: to('denied') },
  ]
}

/** The tags the latest-events list links by, most telling first. */
const NOTABLE = ['exec', 'rbac-change', 'secret-access', 'secret-change', 'denied', 'impersonate', 'anonymous']

export interface EventRow {
  key: string
  who: string
  what: string
  target: string
  age: string
  tag?: string
  href: string
}

export function latestRows(events: readonly AuditEvent[] | undefined, now: number = Date.now(), max = 5): EventRow[] {
  return (events ?? []).slice(0, max).map((e, i) => {
    const tag = NOTABLE.find((t) => e.tags?.includes(t)) ?? e.tags?.[0]
    const who = e.arn ? e.sessionName || e.arn : e.username
    return {
      key: `${e.auditID}:${e.stage}:${i}`,
      who,
      what: e.subresource === 'exec' ? 'exec' : e.verb,
      target: auditTarget(e),
      age: ago(e.time, now),
      tag,
      href: link('activity', { user: e.username, tag }),
    }
  })
}

// ---- Cost and waste ----

export interface WasteLine {
  key: string
  text: string
  href: string
}

export function wasteLines(w: OverviewResponse['waste']): WasteLine[] {
  const out: WasteLine[] = []
  if (w.unusedPVCs > 0) {
    const cost = w.monthlyUSD > 0 ? `, about ${formatUSD(w.monthlyUSD)} a month` : ''
    out.push({ key: 'unused', text: `${w.unusedPVCs.toLocaleString('en-US')} unused volume ${plural(w.unusedPVCs, 'claim', 'claims')}${cost}`, href: link('storage') })
  }
  if (w.usageBilled > 0) {
    out.push({ key: 'usage', text: `${w.usageBilled.toLocaleString('en-US')} ${plural(w.usageBilled, 'claim', 'claims')} on EFS or FSx, billed by usage and not estimated`, href: link('storage') })
  }
  return out
}
