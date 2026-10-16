// Incidents: the list filters and their addresses, severity glyphs, what each
// signal type looks like and which lane it goes in, the merged timeline, the
// 24-hour cap, and log levels. Kept free of React so it is testable.

import { auditTarget } from './components/ActivityTable'
import { bucketCounts, brushRange, type MarkerIn, type Range } from './chartMath'
import { plural } from './format'
import { formatSpan, type WindowChoice, type WindowOption } from './retention'
import type { Capability, Incident, IncidentDetail, IncidentSeries, IncidentSeverity, IncidentSignal, IncidentSignalType, Info, Status } from './types'

// ---- Severity ----

/** One mapping from the wire's words to the UI's glyphs: critical → crit, warning ("caution") → warn. */
export function severityGlyph(s: string | undefined): Status {
  if (s === 'critical') return 'crit'
  if (s === 'warning') return 'warn'
  return 'unknown'
}

export const SEVERITY_WORD: Record<IncidentSeverity, string> = { critical: 'Critical', warning: 'Warning' }

// ---- Signal types ----

/** Where a signal is drawn in the event lanes. */
export type Lane = 'spikes' | 'pods' | 'events' | 'changes' | 'alerts' | 'audit' | 'cloudtrail'

/** Chart markers: ✕ OOM, ↻ restart, ◆ deploy, ▲ event. */
export type MarkKind = 'oom' | 'restart' | 'deploy' | 'event'

/** The shape drawn for a signal; the same shape in the lanes, the charts and the lists. */
export type Shape = 'peak' | 'x' | 'cycle' | 'diamond' | 'diamond-open' | 'triangle' | 'square' | 'circle' | 'square-open'

export interface SignalMeta {
  label: string
  /** A text stand-in for the shape, for tooltips. */
  glyph: string
  shape: Shape
  lane: Lane
  /** Triggers open an incident and set its severity; context only attaches. k8s events can be either. */
  role: 'trigger' | 'context' | 'either'
  /** The marker it puts on the charts. */
  mark?: MarkKind
  /** The chart its spike is shaded on. */
  chart?: IncidentSeries['metric']
}

export const SIGNAL_META: Record<IncidentSignalType, SignalMeta> = {
  'request-spike': { label: 'Request spike', glyph: '⌃', shape: 'peak', lane: 'spikes', role: 'trigger', chart: 'requests' },
  'error-rate': { label: 'Error rate', glyph: '⌃', shape: 'peak', lane: 'spikes', role: 'trigger', chart: 'errors' },
  'memory-spike': { label: 'Memory spike', glyph: '⌃', shape: 'peak', lane: 'spikes', role: 'trigger', chart: 'memory' },
  'oom-kill': { label: 'OOM kill', glyph: '✕', shape: 'x', lane: 'pods', role: 'trigger', mark: 'oom' },
  restart: { label: 'Restart', glyph: '↻', shape: 'cycle', lane: 'pods', role: 'trigger', mark: 'restart' },
  crashloop: { label: 'Crash loop', glyph: '↻', shape: 'cycle', lane: 'pods', role: 'trigger', mark: 'restart' },
  eviction: { label: 'Eviction', glyph: '▲', shape: 'triangle', lane: 'pods', role: 'trigger', mark: 'event' },
  'k8s-event': { label: 'Kubernetes event', glyph: '▲', shape: 'triangle', lane: 'events', role: 'either', mark: 'event' },
  alert: { label: 'Alert', glyph: '■', shape: 'square', lane: 'alerts', role: 'trigger' },
  deploy: { label: 'Deploy', glyph: '◆', shape: 'diamond', lane: 'changes', role: 'context', mark: 'deploy' },
  scale: { label: 'Scale', glyph: '◇', shape: 'diamond-open', lane: 'changes', role: 'context', mark: 'deploy' },
  'audit-change': { label: 'Audit change', glyph: '●', shape: 'circle', lane: 'audit', role: 'context' },
  'cloudtrail-change': { label: 'CloudTrail change', glyph: '□', shape: 'square-open', lane: 'cloudtrail', role: 'context' },
  'log-errors': { label: 'Error logs', glyph: '⌃', shape: 'peak', lane: 'spikes', role: 'context' },
}

/** Metadata for a type, including ones a newer server sends that this UI does not know. */
export function signalMeta(type: string): SignalMeta {
  return SIGNAL_META[type as IncidentSignalType] ?? { label: humanize(type), glyph: '●', shape: 'circle', lane: 'events', role: 'context' }
}

/** Every known type, triggers first, in the order the filter shows them. */
export const SIGNAL_TYPES: IncidentSignalType[] = (Object.keys(SIGNAL_META) as IncidentSignalType[]).sort(
  (a, b) => roleRank(SIGNAL_META[a].role) - roleRank(SIGNAL_META[b].role),
)

function roleRank(r: SignalMeta['role']): number {
  return r === 'trigger' ? 0 : r === 'either' ? 1 : 2
}

/** Types that last until they end (a spike, a crash loop, an alert episode); the rest are points in time. */
const CONDITION_TYPES = new Set<string>(['request-spike', 'error-rate', 'memory-spike', 'crashloop', 'alert', 'log-errors'])

export interface LaneDef {
  key: Lane
  label: string
  /** The capability the lane's data needs; without it the lane says why it is empty. */
  cap?: Capability
}

export const LANES: LaneDef[] = [
  { key: 'spikes', label: 'Metric spikes and error logs' },
  { key: 'pods', label: 'Restarts, OOM kills and evictions' },
  { key: 'events', label: 'Kubernetes events' },
  { key: 'changes', label: 'Deploys and scaling' },
  { key: 'alerts', label: 'Alerts' },
  { key: 'audit', label: 'Changes by people (audit log)', cap: 'audit' },
  { key: 'cloudtrail', label: 'AWS changes (CloudTrail)', cap: 'cloudtrail' },
]

/** A type's chip on the list: shape, label and how many signals. Triggers first. */
export interface TypeChip {
  type: IncidentSignalType
  label: string
  shape: Shape
  count: number
  trigger: boolean
}

export function typeChips(inc: Pick<Incident, 'types' | 'counts'>): TypeChip[] {
  const types = [...new Set(inc.types ?? [])]
  return types
    .map((t) => {
      const m = signalMeta(t)
      return { type: t, label: m.label, shape: m.shape, count: inc.counts?.[t] ?? 0, trigger: m.role === 'trigger' }
    })
    .sort((a, b) => Number(b.trigger) - Number(a.trigger) || roleRank(signalMeta(a.type).role) - roleRank(signalMeta(b.type).role) || a.label.localeCompare(b.label))
}

// ---- Tags ----

export const TAG_APP = 'kubesentry.io/app'
export const TAG_SERVICE = 'service'
export const TAG_INGRESS = 'ingress'

export interface TagChip {
  key: string
  /** "app", "service", "ingress" or the label key. */
  name: string
  value: string
  /** The list filter that finds incidents with this tag, when there is one. */
  filter?: Partial<IncidentFilter>
}

/** The incident's tags for display: app first, then each service and ingress, then the label keys. */
export function tagChips(tags: Record<string, string> | undefined): TagChip[] {
  if (!tags) return []
  const out: TagChip[] = []
  const app = tags[TAG_APP]
  if (app) out.push({ key: `app=${app}`, name: 'app', value: app, filter: { app } })
  for (const s of splitList(tags[TAG_SERVICE])) out.push({ key: `service=${s}`, name: 'service', value: s, filter: { service: s } })
  for (const s of splitList(tags[TAG_INGRESS])) out.push({ key: `ingress=${s}`, name: 'ingress', value: s })
  for (const k of Object.keys(tags).sort()) {
    if (k === TAG_APP || k === TAG_SERVICE || k === TAG_INGRESS || !tags[k]) continue
    // The app label usually repeats the app tag; say it once.
    if (tags[k] === app && (k === 'app' || k === 'app.kubernetes.io/name')) continue
    out.push({ key: `${k}=${tags[k]}`, name: k, value: tags[k] })
  }
  return out
}

function splitList(s: string | undefined): string[] {
  return (s ?? '')
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean)
}

/** "Deployment shop/api", or "Node ip-10-0-1-5" for a cluster-scoped subject. */
export function subjectText(s: Incident['subject']): string {
  return `${s.kind} ${s.namespace ? `${s.namespace}/` : ''}${s.name}`
}

// ---- The window: 1 to 24 hours, never more than the server allows ----

export const MAX_RANGE_HOURS = 24

export const WINDOWS: WindowOption[] = [
  { value: '1h', label: 'Last hour', hours: 1 },
  { value: '3h', label: 'Last 3 hours', hours: 3 },
  { value: '6h', label: 'Last 6 hours', hours: 6 },
  { value: '12h', label: 'Last 12 hours', hours: 12 },
  { value: '24h', label: 'Last 24 hours', hours: 24 },
]

/** The longest range the server answers for: its maxRangeHours, never above 24 and at least 1. */
export function maxRangeHours(info: Pick<Info, 'incidents'> | undefined): number {
  const h = info?.incidents?.maxRangeHours
  if (typeof h !== 'number' || !Number.isFinite(h) || h <= 0) return MAX_RANGE_HOURS
  return Math.min(MAX_RANGE_HOURS, Math.max(1, h))
}

/** The window choices, with those past the server's cap disabled and the reason. */
export function windowChoicesFor(maxHours: number): WindowChoice[] {
  return WINDOWS.map((w) =>
    w.hours > maxHours * 1.0001
      ? { ...w, disabled: true, reason: `This server answers for at most ${formatSpan(maxHours)} at a time.` }
      : { ...w, disabled: false },
  )
}

/**
 * A window from the address, clamped to the cap: one of WINDOWS, the largest
 * that fits when it asks for more (or is not one of them), the default when
 * it is missing or unreadable.
 */
export function clampWindow(value: string | null | undefined, maxHours = MAX_RANGE_HOURS, fallback = '24h'): string {
  const allowed = WINDOWS.filter((w) => w.hours <= maxHours * 1.0001)
  if (allowed.length === 0) return WINDOWS[0].value
  const want = parseHours(value) ?? parseHours(fallback) ?? MAX_RANGE_HOURS
  const fit = allowed.filter((w) => w.hours <= want)
  return (fit.length ? fit[fit.length - 1] : allowed[0]).value
}

function parseHours(v: string | null | undefined): number | undefined {
  const m = /^\s*(\d+(?:\.\d+)?)\s*(h|m)?\s*$/.exec(v ?? '')
  if (!m) return undefined
  const n = Number(m[1]) / (m[2] === 'm' ? 60 : 1)
  return n > 0 ? n : undefined
}

// ---- List filters, kept in the address ----

export interface IncidentFilter {
  window: string
  severity: '' | IncidentSeverity
  state: '' | 'open' | 'resolved'
  types: string[]
  namespace: string
  owner: string
  app: string
  service: string
}

const TYPE_RE = /^[a-z0-9][a-z0-9-]{0,62}$/

/** The filter in an address. `type` is a comma-separated list (repeated keys are read too). */
export function readIncidentFilter(q: URLSearchParams, maxHours = MAX_RANGE_HOURS): IncidentFilter {
  const sev = q.get('severity')
  const state = q.get('state')
  const types = [...new Set(q.getAll('type').flatMap((t) => t.split(',')).map((t) => t.trim()).filter((t) => TYPE_RE.test(t)))]
  return {
    window: clampWindow(q.get('window'), maxHours),
    severity: sev === 'critical' || sev === 'warning' ? sev : '',
    state: state === 'open' || state === 'resolved' ? state : '',
    types,
    namespace: (q.get('namespace') ?? '').trim(),
    owner: (q.get('owner') ?? '').trim(),
    app: (q.get('app') ?? '').trim(),
    service: (q.get('service') ?? '').trim(),
  }
}

/** The whole query for setQuery('/incidents', …): every key, empty ones left for setQuery to drop. */
export function filterQuery(f: IncidentFilter): Record<string, string | undefined> {
  return {
    window: f.window,
    severity: f.severity || undefined,
    state: f.state || undefined,
    type: f.types.length ? f.types.join(',') : undefined,
    namespace: f.namespace || undefined,
    owner: f.owner || undefined,
    app: f.app || undefined,
    service: f.service || undefined,
  }
}

/** The filter with some keys changed, as the whole query for setQuery. */
export function patchFilter(f: IncidentFilter, patch: Partial<IncidentFilter>): Record<string, string | undefined> {
  return filterQuery({ ...f, ...patch })
}

/** The type list with `t` added or removed. */
export function toggleType(types: readonly string[], t: string): string[] {
  return types.includes(t) ? types.filter((x) => x !== t) : [...types, t]
}

/** Any filter beyond the window. */
export function isNarrowed(f: IncidentFilter): boolean {
  return !!(f.severity || f.state || f.types.length || f.namespace || f.owner || f.app || f.service)
}

/** The list route for a filter; `type` repeats, as the server reads it. */
export function incidentsPath(f: IncidentFilter): string {
  const p = new URLSearchParams()
  p.set('window', f.window)
  if (f.severity) p.set('severity', f.severity)
  for (const t of f.types) p.append('type', t)
  if (f.state) p.set('state', f.state)
  if (f.namespace) p.set('namespace', f.namespace)
  if (f.owner) p.set('owner', f.owner)
  if (f.app) p.set('app', f.app)
  if (f.service) p.set('service', f.service)
  return `/api/v1/incidents?${p.toString()}`
}

/** The address of an incident's page; the id is encoded so it can never break out of the hash route. */
export function incidentHref(id: string): string {
  return `#/incidents/${encodeURIComponent(id)}`
}

export function incidentPath(id: string): string {
  return `/api/v1/incidents/${encodeURIComponent(id)}`
}

export function bundlePath(id: string): string {
  return `${incidentPath(id)}/bundle?format=ndjson`
}

// ---- The selected range on the detail page (the brush), kept in the address ----

/** RFC 3339 to the second, as the server reads `from` and `to`. */
export function isoSeconds(ms: number): string {
  return new Date(Math.round(ms / 1000) * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z')
}

function parseTime(s: string | null): number | undefined {
  if (!s) return undefined
  if (/^\d{10,}$/.test(s)) return Number(s)
  const t = Date.parse(s)
  return Number.isNaN(t) ? undefined : t
}

/**
 * The brushed range in an address (`from`, `to`; RFC 3339 or unix ms),
 * clamped to the incident's window and at most 24 hours. Null when absent,
 * unreadable or outside the window.
 */
export function readRange(q: URLSearchParams, window: Range | undefined): Range | null {
  const from = parseTime(q.get('from'))
  const to = parseTime(q.get('to'))
  if (from === undefined || to === undefined || !window) return null
  const r = brushRange(from, to, window)
  if (!r || r[1] <= window[0] || r[0] >= window[1]) return null
  return clampSpan(r)
}

/** At most 24 hours, keeping the end. */
export function clampSpan(r: Range, maxHours = MAX_RANGE_HOURS): Range {
  const max = maxHours * 3_600_000
  return r[1] - r[0] > max ? [r[1] - max, r[1]] : r
}

/** The whole query for setQuery on the detail page. */
export function rangeQuery(r: Range | null): Record<string, string | undefined> {
  return r ? { from: isoSeconds(r[0]), to: isoSeconds(r[1]) } : { from: undefined, to: undefined }
}

/** The incident's padded window as times; undefined when the server sent something unreadable. */
export function windowRange(w: IncidentDetail['window'] | undefined): Range | undefined {
  if (!w) return undefined
  const a = Date.parse(w.from)
  const b = Date.parse(w.to)
  return Number.isNaN(a) || Number.isNaN(b) || b <= a ? undefined : [a, b]
}

/**
 * The time axis an incident's charts, lanes and logs share: its padded
 * window, reaching back to the earliest thing attached to it (a deploy or a
 * change caught by the lookbehind starts before the window), with a minute of
 * margin. It reaches back at most 24 hours before the window.
 */
export function incidentDomain(window: Range | undefined, items: readonly Pick<TimelineItem, 't'>[], margin = 60_000): Range | undefined {
  if (!window) return undefined
  let lo = window[0]
  for (const i of items) if (Number.isFinite(i.t) && i.t - margin < lo) lo = i.t - margin
  return [Math.max(lo, window[0] - MAX_RANGE_HOURS * 3_600_000), window[1]]
}

/** "5 min", "1 h", "1 h 30 min", "45 s". */
export function shortSpan(ms: number): string {
  if (!Number.isFinite(ms) || ms <= 0) return '0 min'
  const s = Math.round(ms / 1000)
  if (s < 60) return `${s} s`
  const m = Math.round(s / 60)
  if (m < 60) return `${m} min`
  const h = Math.floor(m / 60)
  const rest = m % 60
  if (h < 48) return rest ? `${h} h ${rest} min` : `${h} h`
  return `${Math.round(h / 24)} days`
}

/**
 * How far logs and events reach past the incident: "Logs and events include
 * 5 min before it started and 10 min after its last signal." The server's
 * padding when /info says, else what the window shows.
 */
export function paddingText(
  inc: Pick<Incident, 'start' | 'lastSignal' | 'end' | 'state'>,
  window: Range | undefined,
  pad?: { logLeadSeconds?: number; logLagSeconds?: number },
): string | undefined {
  const start = Date.parse(inc.start)
  const last = Date.parse(inc.end ?? inc.lastSignal)
  let lead = pad?.logLeadSeconds !== undefined ? pad.logLeadSeconds * 1000 : window && !Number.isNaN(start) ? start - window[0] : undefined
  let lag = pad?.logLagSeconds !== undefined ? pad.logLagSeconds * 1000 : window && !Number.isNaN(last) ? window[1] - last : undefined
  if (lead !== undefined && !(lead > 0)) lead = undefined
  if (lag !== undefined && !(lag > 0)) lag = undefined
  if (lead === undefined && lag === undefined) return undefined
  const before = lead !== undefined ? `${shortSpan(lead)} before it started` : ''
  const after = lag !== undefined ? (inc.state === 'open' ? `${shortSpan(lag)} past its latest signal, up to now` : `${shortSpan(lag)} after it ended`) : ''
  return `Logs and events include ${[before, after].filter(Boolean).join(' and ')}, to catch lines written after the fact.`
}

/** "38 min", "2 h 5 min"; open incidents run to `now`. */
export function incidentDuration(inc: Pick<Incident, 'start' | 'end' | 'lastSignal' | 'state'>, now = Date.now()): string {
  const a = Date.parse(inc.start)
  const b = inc.end ? Date.parse(inc.end) : inc.state === 'open' ? now : Date.parse(inc.lastSignal)
  if (Number.isNaN(a) || Number.isNaN(b)) return '-'
  return shortSpan(Math.max(0, b - a))
}

// ---- Sources ----

export interface SourceRow {
  key: string
  label: string
  status: Status
  /** "ok", "not configured", "hidden from you", or the error. */
  text: string
}

const SOURCE_LABEL: Record<string, string> = {
  'requests:nginx': 'Requests (ingress-nginx)',
  'requests:app': 'Requests (app metrics)',
  'requests:alb': 'Requests (ALB)',
  'logs:cloudwatch': 'Logs (CloudWatch)',
  'logs:kubernetes': 'Logs (Kubernetes)',
  cloudtrail: 'CloudTrail',
  'logs:demo': 'Logs (demo)',
  logs: 'Logs',
  memory: 'Memory (Prometheus)',
  series: 'Chart series',
  prometheus: 'Prometheus',
  events: 'Kubernetes events',
  audit: 'Audit log',
  alerts: 'Alerts',
}

function sourceLabel(key: string): string {
  if (SOURCE_LABEL[key]) return SOURCE_LABEL[key]
  const [head, ...rest] = key.split(':')
  return rest.length ? `${humanize(head)} (${rest.join(':')})` : humanize(head)
}

/** The state of each source, ok first, then by name. The shape tells the state, not colour. */
export function sourceRows(sources: Record<string, string> | undefined): SourceRow[] {
  return Object.entries(sources ?? {})
    .map(([key, raw]) => {
      const v = (raw ?? '').trim()
      let status: Status = 'unknown'
      let text = v
      if (v === 'ok') {
        status = 'ok'
        text = 'ok'
      } else if (v === 'absent') text = 'not configured'
      else if (v === 'forbidden') text = 'hidden from you'
      else if (v.startsWith('error')) {
        status = 'warn'
        text = v.replace(/^error:?\s*/, '') || 'error'
      }
      return { key, label: sourceLabel(key), status, text }
    })
    .sort((a, b) => Number(b.status === 'ok') - Number(a.status === 'ok') || a.label.localeCompare(b.label))
}

export type Access = 'ok' | 'forbidden' | 'absent'

/**
 * Whether this caller sees a section of this incident. The incident's own
 * sources decide first: `audit`, `cloudtrail` and `logs:*` read "forbidden"
 * where the caller may not see them here (the capabilities only say "in some
 * namespace"); then the capability; then whether the source exists at all.
 */
export function sectionAccess(sources: Record<string, string> | undefined, caps: { audit: boolean; cloudtrail: boolean; podLogs: boolean }): Record<'audit' | 'cloudtrail' | 'logs', Access> {
  const s = sources ?? {}
  const one = (key: string, allowed: boolean): Access => {
    if (s[key] === 'forbidden' || !allowed) return 'forbidden'
    return s[key] === 'absent' ? 'absent' : 'ok'
  }
  const logKeys = Object.keys(s).filter((k) => k === 'logs' || k.startsWith('logs:'))
  let logs: Access = 'ok'
  if (!caps.podLogs || logKeys.some((k) => s[k] === 'forbidden')) logs = 'forbidden'
  else if (logKeys.length > 0 && logKeys.every((k) => s[k] === 'absent')) logs = 'absent'
  return { audit: one('audit', caps.audit), cloudtrail: one('cloudtrail', caps.cloudtrail), logs }
}

/** The log sources the switch can ask for by name: those the incident lists as working. */
export function logSources(sources: Record<string, string> | undefined): { kubernetes: boolean; cloudwatch: boolean } {
  const s = sources ?? {}
  const up = (k: string) => s[k] !== undefined && s[k] !== 'absent' && s[k] !== 'forbidden'
  return { kubernetes: up('logs:kubernetes'), cloudwatch: up('logs:cloudwatch') }
}

/** Whether any source of a kind ("requests", "logs") answers; false when all are absent or failing, undefined when none is listed. */
export function sourceUp(sources: Record<string, string> | undefined, prefix: string): boolean | undefined {
  const keys = Object.keys(sources ?? {}).filter((k) => k === prefix || k.startsWith(`${prefix}:`))
  if (keys.length === 0) return undefined
  return keys.some((k) => sources![k] === 'ok')
}

// ---- The timeline: signals, Kubernetes events and audit events, merged ----

export interface TimelineItem {
  key: string
  lane: Lane
  shape: Shape
  /** Start, unix ms. */
  t: number
  /** When it ended, for things that last. */
  end?: number
  /** Lasts and has not ended. */
  ongoing?: boolean
  severity?: Status
  role?: 'trigger' | 'context'
  type?: string
  title: string
  detail?: string
  mark?: MarkKind
}

function ms(s: string | undefined): number | undefined {
  if (!s) return undefined
  const t = Date.parse(s)
  return Number.isNaN(t) ? undefined : t
}

/** What a signal's attributes add to its title: the image change, the replica change, how often. Nothing the title already says. */
export function signalDetail(s: Pick<IncidentSignal, 'type' | 'attrs' | 'count' | 'role'> & { title?: string }): string | undefined {
  const a = s.attrs ?? {}
  const parts: string[] = []
  if (s.type === 'deploy') {
    if (a.images) parts.push(a.images)
    if (a.rollback === 'true') parts.push('rollback')
  }
  if (s.type === 'scale' && a.from !== undefined && a.to !== undefined) parts.push(`${a.from} → ${a.to} replicas`)
  if (s.type === 'cloudtrail-change' && a.region) parts.push(a.region)
  const title = (s.title ?? '').toLowerCase()
  // "212 error log lines" already says how often.
  if (s.count && s.count > 1 && !new RegExp(`(^|\\D)${s.count}(\\D|$)`).test(title)) parts.push(`${s.count} times`)
  const fresh = parts.filter((p) => !title.includes(p.toLowerCase()))
  return fresh.length ? fresh.join(' · ') : undefined
}

/**
 * Everything on the incident's time axis, oldest first: each signal, each
 * Kubernetes event and each audit event. A k8s-event or audit-change signal
 * and the raw event it came from (matched by uid or audit ID) show once, as
 * the event carrying the signal's role and severity.
 */
export function mergeTimeline(d: Pick<IncidentDetail, 'signals' | 'events' | 'audit'>): TimelineItem[] {
  const out: TimelineItem[] = []
  const eventSignal = new Map<string, IncidentSignal>()
  const auditSignal = new Map<string, IncidentSignal>()
  for (const s of d.signals ?? []) {
    if (s.type === 'k8s-event' && s.id.startsWith('events:')) eventSignal.set(s.id.slice(7).replace(/#\d+$/, ''), s)
    if (s.type === 'audit-change' && s.id.startsWith('audit:')) auditSignal.set(s.id.slice(6), s)
  }
  const seenEvents = new Set<string>()
  for (const e of d.events ?? []) {
    const t = ms(e.firstSeen) ?? ms(e.lastSeen)
    if (t === undefined) continue
    seenEvents.add(e.uid)
    const sig = eventSignal.get(e.uid)
    const last = ms(e.lastSeen)
    const regarding = `${e.regarding.kind}/${e.regarding.name}`
    out.push({
      key: `event:${e.uid}`,
      lane: 'events',
      shape: 'triangle',
      t,
      end: last !== undefined && last > t ? last : undefined,
      severity: sig?.severity ? severityGlyph(sig.severity) : undefined,
      role: sig?.role,
      type: 'k8s-event',
      title: `${e.reason}: ${e.message}`,
      detail: [e.type === 'Warning' ? 'Warning' : 'Normal', regarding, e.count > 1 ? `${e.count} times` : ''].filter(Boolean).join(' · '),
      mark: e.type === 'Warning' || sig?.role === 'trigger' ? 'event' : undefined,
    })
  }
  const seenAudit = new Set<string>()
  for (const a of d.audit ?? []) {
    const t = ms(a.time)
    if (t === undefined || seenAudit.has(a.auditID)) continue
    seenAudit.add(a.auditID)
    const who = a.arn ? a.sessionName || a.arn : a.username
    out.push({
      key: `audit:${a.auditID}`,
      lane: 'audit',
      shape: 'circle',
      t,
      role: auditSignal.get(a.auditID)?.role ?? 'context',
      type: 'audit-change',
      title: `${who} ${a.verb} ${auditTarget(a)}`,
      detail: a.statusCode ? `HTTP ${a.statusCode}` : undefined,
    })
  }
  for (const s of d.signals ?? []) {
    if (s.type === 'k8s-event' && s.id.startsWith('events:') && seenEvents.has(s.id.slice(7).replace(/#\d+$/, ''))) continue
    if (s.type === 'audit-change' && s.id.startsWith('audit:') && seenAudit.has(s.id.slice(6))) continue
    const t = ms(s.start)
    if (t === undefined) continue
    const m = signalMeta(s.type)
    const end = ms(s.end)
    out.push({
      key: `signal:${s.id}`,
      lane: m.lane,
      shape: m.shape,
      t,
      end: end !== undefined && end > t ? end : undefined,
      ongoing: CONDITION_TYPES.has(s.type) && end === undefined ? true : undefined,
      severity: s.severity ? severityGlyph(s.severity) : undefined,
      role: s.role,
      type: s.type,
      title: s.title || m.label,
      detail: signalDetail({ ...s, title: s.title || m.label }),
      mark: m.mark,
    })
  }
  const lane = (l: Lane) => LANES.findIndex((x) => x.key === l)
  return out.sort((a, b) => a.t - b.t || lane(a.lane) - lane(b.lane) || a.key.localeCompare(b.key))
}

/** The items in one lane. */
export function laneItems(items: readonly TimelineItem[], lane: Lane): TimelineItem[] {
  return items.filter((i) => i.lane === lane)
}

/** Whether an item touches a range (a point inside it, or a span overlapping it). */
export function inRange(i: Pick<TimelineItem, 't' | 'end' | 'ongoing'>, r: Range | null | undefined): boolean {
  if (!r) return true
  const end = i.ongoing ? Infinity : (i.end ?? i.t)
  return i.t <= r[1] && end >= r[0]
}

/** The chart markers: ✕ OOM, ↻ restart, ◆ deploy, ▲ event. */
export function chartMarks(items: readonly TimelineItem[]): MarkerIn<MarkKind>[] {
  return items.filter((i) => i.mark).map((i) => ({ t: i.t, kind: i.mark!, label: i.title }))
}

export interface SpikeSpan {
  from: number
  to: number
  label: string
  severity: Status
}

/** The spikes to shade on one metric's chart; one still going runs to the end of the domain. */
export function spikeSpans(signals: readonly IncidentSignal[] | undefined, metric: IncidentSeries['metric'], domainEnd: number): SpikeSpan[] {
  const out: SpikeSpan[] = []
  for (const s of signals ?? []) {
    if (signalMeta(s.type).chart !== metric) continue
    const from = ms(s.start)
    if (from === undefined) continue
    const to = ms(s.end) ?? domainEnd
    out.push({ from, to: Math.max(from, to), label: s.title || signalMeta(s.type).label, severity: severityGlyph(s.severity) })
  }
  return out
}

// ---- Chart series ----

/** The label the server gives the folded remainder of a metric's series. */
export const OTHERS = 'others'

export interface ChartLine {
  key: string
  label: string
  points: [number, number][]
  /** 1–3: a coloured, dashed, end-labelled line; 0: a thin grey context line. */
  slot: 0 | 1 | 2 | 3
}

/**
 * One metric's series as chart lines: the three with the highest peak get a
 * hue, a dash pattern and an end label (colour never alone); the rest, and
 * the server's folded "others", are thin grey context lines.
 */
export function chartLines(series: readonly IncidentSeries[] | undefined, metric: IncidentSeries['metric']): ChartLine[] {
  const peak = (s: IncidentSeries) => s.points.reduce((m, p) => (Number.isFinite(p[1]) && p[1] > m ? p[1] : m), -Infinity)
  const mine = (series ?? []).filter((s) => s.metric === metric && s.points.length > 0)
  const named = mine.filter((s) => s.label !== OTHERS).sort((a, b) => peak(b) - peak(a) || a.label.localeCompare(b.label))
  const rest = mine.filter((s) => s.label === OTHERS)
  return [...named, ...rest].map((s, i) => ({
    key: `${s.metric}:${s.label}:${i}`,
    label: s.label,
    points: s.points,
    slot: s.label !== OTHERS && i < 3 ? ((i + 1) as 1 | 2 | 3) : 0,
  }))
}

/** The distinct thresholds for one metric (one per value), at most `max`. */
export function chartThresholds(t: IncidentDetail['thresholds'], metric: IncidentSeries['metric'], max = 3): { label: string; value: number }[] {
  const seen = new Set<number>()
  const out: { label: string; value: number }[] = []
  for (const x of t ?? []) {
    if (x.metric !== metric || !Number.isFinite(x.value) || seen.has(x.value)) continue
    seen.add(x.value)
    out.push({ label: x.label, value: x.value })
  }
  return out.sort((a, b) => b.value - a.value).slice(0, max)
}

// ---- Logs ----

export type LogLevel = '' | 'info' | 'warn' | 'error'
export type LogSource = 'auto' | 'kubernetes' | 'cloudwatch'

/** The level control: a minimum severity, as the server reads `level`. */
export const LEVELS: { value: LogLevel; label: string }[] = [
  { value: '', label: 'All' },
  { value: 'info', label: 'Info and up' },
  { value: 'warn', label: 'Warnings and up' },
  { value: 'error', label: 'Errors' },
]

/** A line's level in the UI's four words; "" when unknown. */
export function normalLevel(level: string | undefined): '' | 'debug' | 'info' | 'warn' | 'error' {
  const l = (level ?? '').trim().toLowerCase()
  if (/^(err|error|fatal|crit|critical|panic|alert|emerg|emergency|severe|e)$/.test(l)) return 'error'
  if (/^(warn|warning|w)$/.test(l)) return 'warn'
  if (/^(info|information|notice|i)$/.test(l)) return 'info'
  if (/^(debug|trace|dbg|d|verbose)$/.test(l)) return 'debug'
  return ''
}

const LEVEL_RANK = { '': -1, debug: 0, info: 1, warn: 2, error: 3 } as const

/** Whether a line's level reaches a minimum; lines of unknown level pass only "All". */
export function atLeast(level: string, min: LogLevel): boolean {
  if (!min) return true
  return LEVEL_RANK[normalLevel(level)] >= LEVEL_RANK[min]
}

/** The glyph for a level, so errors and warnings stand out by shape; undefined for the rest. */
export function levelGlyph(level: string): Status | undefined {
  const l = normalLevel(level)
  return l === 'error' ? 'crit' : l === 'warn' ? 'warn' : undefined
}

export interface LogQuery {
  from?: number
  to?: number
  pod?: string
  container?: string
  level?: LogLevel
  q?: string
  source?: LogSource
  limit?: number
}

export function logsPath(id: string, q: LogQuery): string {
  const p = new URLSearchParams()
  if (q.from !== undefined) p.set('from', isoSeconds(q.from))
  if (q.to !== undefined) p.set('to', isoSeconds(q.to))
  if (q.pod) p.set('pod', q.pod)
  if (q.container) p.set('container', q.container)
  if (q.level) p.set('level', q.level)
  if (q.q) p.set('q', q.q)
  if (q.source && q.source !== 'auto') p.set('source', q.source)
  if (q.limit) p.set('limit', String(q.limit))
  const s = p.toString()
  return `${incidentPath(id)}/logs${s ? `?${s}` : ''}`
}

export interface LogVolume {
  all: number[]
  errors: number[]
  max: number
}

/** Lines per slice of the domain, and how many of them are errors, for the volume strip. */
export function logVolume(lines: readonly { time: string; level: string }[], domain: Range, buckets: number): LogVolume {
  const times: number[] = []
  const errs: number[] = []
  for (const l of lines) {
    const t = Date.parse(l.time)
    if (Number.isNaN(t)) continue
    times.push(t)
    if (normalLevel(l.level) === 'error') errs.push(t)
  }
  const all = bucketCounts(times, domain, buckets)
  return { all, errors: bucketCounts(errs, domain, buckets), max: Math.max(0, ...all) }
}

/** "3 pods", "api-7d9f-a" */
export function countText(n: number, one: string, many: string): string {
  return `${n.toLocaleString('en-US')} ${plural(n, one, many)}`
}

function humanize(s: string): string {
  const t = s.replace(/[-_]+/g, ' ').trim()
  return t ? t[0].toUpperCase() + t.slice(1) : s
}
