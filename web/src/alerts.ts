// The Alerts page's logic, kept free of React so it is testable: the filters
// in the address, the state tabs, what each row may do, bulk selection, the
// silence dialog's duration and reason, what an action's results say, and
// the Overview's alerts widget.

import { ago, formatDateTime, plural } from './format'
import type {
  AlertAction,
  AlertActionKind,
  AlertActionResult,
  AlertFinding,
  AlertSeverity,
  AlertState,
  Info,
  OverviewResponse,
  Status,
} from './types'

// ---- Filters ----

/** A state tab: one lifecycle state, or every state. */
export type StateTab = AlertState | 'all'

export const STATE_TABS: { value: StateTab; label: string }[] = [
  { value: 'open', label: 'Open' },
  { value: 'acknowledged', label: 'Acknowledged' },
  { value: 'silenced', label: 'Silenced' },
  { value: 'resolved', label: 'Resolved' },
  { value: 'all', label: 'All' },
]

const TABS = new Set<string>(STATE_TABS.map((t) => t.value))

export interface AlertFilter {
  state: StateTab
  namespace: string
  owner: string
  severity: '' | AlertSeverity
  check: string
  /** Free text, matched against title, object, check, owner and key. */
  q: string
  /** One finding to highlight and open (?key=). */
  key: string
}

/** Longest search text kept from the address. */
export const MAX_QUERY = 200

/** The tab a filter starts on: Open, or every state when the address names one finding (it may be in any state). */
export function defaultState(key: string): StateTab {
  return key ? 'all' : 'open'
}

/** The filter in the address: #/alerts?state=&namespace=&owner=&severity=&check=&q=&key=. Unknown values fall back to the defaults. */
export function readAlertFilter(q: URLSearchParams): AlertFilter {
  const get = (k: string) => (q.get(k) ?? '').trim()
  const key = get('key')
  const st = get('state')
  const sev = get('severity')
  return {
    state: TABS.has(st) ? (st as StateTab) : defaultState(key),
    namespace: get('namespace'),
    owner: get('owner'),
    severity: sev === 'critical' || sev === 'warning' ? sev : '',
    check: get('check'),
    q: (q.get('q') ?? '').slice(0, MAX_QUERY),
    key,
  }
}

/** The address's query for a filter, leaving out defaults. */
export function alertQuery(f: AlertFilter): Record<string, string | undefined> {
  return {
    key: f.key || undefined,
    state: f.state === defaultState(f.key) ? undefined : f.state,
    namespace: f.namespace || undefined,
    owner: f.owner || undefined,
    severity: f.severity || undefined,
    check: f.check || undefined,
    q: f.q || undefined,
  }
}

export function patchAlertFilter(f: AlertFilter, patch: Partial<AlertFilter>): Record<string, string | undefined> {
  return alertQuery({ ...f, ...patch })
}

/** Filters beyond the state tab are set (the key only highlights). */
export function isNarrowed(f: AlertFilter): boolean {
  return !!(f.namespace || f.owner || f.severity || f.check || f.q.trim())
}

/**
 * The list route. Namespace and owner narrow on the server; every state is
 * asked for, so the tabs can count what the other filters leave.
 */
export function alertsPath(f: Pick<AlertFilter, 'namespace' | 'owner'>): string {
  const p = new URLSearchParams()
  if (f.namespace) p.set('namespace', f.namespace)
  if (f.owner) p.set('owner', f.owner)
  const s = p.toString()
  return `/api/v1/alerts${s ? `?${s}` : ''}`
}

/** Hash route of the Alerts page, filtered. */
export function alertsHref(p: { key?: string; state?: StateTab; namespace?: string; owner?: string; severity?: AlertSeverity }): string {
  const q = new URLSearchParams()
  for (const k of ['key', 'state', 'namespace', 'owner', 'severity'] as const) {
    const v = p[k]
    if (v) q.set(k, v)
  }
  const s = q.toString()
  return `#/alerts${s ? `?${s}` : ''}`
}

/** One finding on the Alerts page, opened. */
export function alertHref(key: string): string {
  return alertsHref({ key })
}

function haystack(a: AlertFinding): string {
  return [a.title, a.kind, a.namespace, a.name, a.check, a.alert, a.owner, a.key, a.annotations?.summary].filter(Boolean).join('\n').toLowerCase()
}

/** Whether a finding passes the filter; `withState` false ignores the state tab (for the tab counts). */
export function matches(a: AlertFinding, f: AlertFilter, withState = true): boolean {
  if (withState && f.state !== 'all' && a.state !== f.state) return false
  if (f.namespace && (a.namespace ?? '') !== f.namespace) return false
  if (f.owner && a.owner !== f.owner) return false
  if (f.severity && a.severity !== f.severity) return false
  if (f.check && a.check !== f.check) return false
  const words = f.q.trim().toLowerCase().split(/\s+/).filter(Boolean)
  if (words.length > 0) {
    const h = haystack(a)
    if (!words.every((w) => h.includes(w))) return false
  }
  return true
}

export function filterAlerts(rows: readonly AlertFinding[], f: AlertFilter): AlertFinding[] {
  return rows.filter((a) => matches(a, f))
}

/**
 * Counts for the tabs. Without filters they are the server's (everything the
 * caller can see, even past the rows loaded); with filters they count the
 * loaded rows the filters leave, so each tab says what clicking it shows.
 */
export function tabCounts(rows: readonly AlertFinding[], f: AlertFilter, server?: Partial<Record<AlertState, number>>): Record<StateTab, number> {
  const out: Record<StateTab, number> = { open: 0, acknowledged: 0, silenced: 0, resolved: 0, all: 0 }
  if (server && !isNarrowed(f)) {
    for (const s of ['open', 'acknowledged', 'silenced', 'resolved'] as const) out[s] = server[s] ?? 0
  } else {
    for (const a of rows) if (matches(a, f, false) && a.state in out) out[a.state]++
  }
  out.all = out.open + out.acknowledged + out.silenced + out.resolved
  return out
}

/** Distinct non-empty values, sorted, keeping the current one even when no row has it. */
export function optionsOf(values: readonly (string | undefined)[], current: string): string[] {
  return [...new Set([...values.filter((v): v is string => !!v), ...(current ? [current] : [])])].sort()
}

// ---- Words ----

export const STATE_WORD: Record<AlertState, string> = { open: 'Open', acknowledged: 'Acknowledged', silenced: 'Silenced', resolved: 'Resolved' }
export const SEVERITY_WORD: Record<AlertSeverity, string> = { critical: 'Critical', warning: 'Warning' }

/** The status glyph for a severity: a diamond for critical, a triangle for warning. */
export function severityStatus(s: string): Status {
  return s === 'critical' ? 'crit' : s === 'warning' ? 'warn' : 'unknown'
}

const CHECK_WORD: Record<string, string> = {
  'workload-unhealthy': 'Workload unhealthy',
  'pod-evicted': 'Pods evicted',
  'pod-stuck-terminating': 'Pods stuck terminating',
  'memory-leak': 'Memory leak',
  'cert-expiring': 'Certificate expiring',
  'cert-not-ready': 'Certificate not ready',
  'cluster-admin': 'cluster-admin binding',
  'anonymous-binding': 'Anonymous binding',
  'wildcard-rbac': 'Wildcard role',
  'aws-auth-masters': 'aws-auth system:masters',
  loadbalancer: 'Internet-facing load balancer',
  nodeport: 'NodePort service',
  'external-ip': 'External IP',
  'ingress-no-tls': 'Ingress without TLS',
  privileged: 'Privileged container',
  'host-namespaces': 'Host namespaces',
  'audit-exec': 'Exec into pods',
  'audit-secret-read': 'Secret reads',
  'audit-rbac-change': 'RBAC changes',
  'audit-impersonation': 'Impersonation',
  'audit-denied-burst': 'Denied requests',
  'audit-anonymous': 'Anonymous requests',
  'agent-missing': 'Agent not reporting',
}

/** A check's name for people: "Workload unhealthy" for workload-unhealthy. */
export function checkLabel(check: string): string {
  if (CHECK_WORD[check]) return CHECK_WORD[check]
  const s = check.replace(/[-_]+/g, ' ').trim()
  return s ? s[0].toUpperCase() + s.slice(1) : check
}

/** What the finding is about: "Deployment prod/web", "ClusterRoleBinding erin-admin"; an audit finding's actor: "User alice in prod". */
export function objectText(a: Pick<AlertFinding, 'kind' | 'namespace' | 'name'>): string {
  if (a.kind === 'User') return `User ${a.name}${a.namespace ? ` in ${a.namespace}` : ''}`
  return `${a.kind} ${a.namespace ? `${a.namespace}/` : ''}${a.name}`
}

/** The page a finding's link opens, for the link's text; undefined for anything but a hash route. */
export function linkLabel(link: string | undefined): string | undefined {
  if (!link || !link.startsWith('#/')) return undefined
  const page = link.slice(2).split(/[/?]/)[0]
  const names: Record<string, string> = {
    workloads: 'Workloads',
    pods: 'the pod page',
    security: 'Security',
    certificates: 'Certificates',
    activity: 'Activity',
    agents: 'Agents',
    nodes: 'Nodes',
    storage: 'Storage',
    memory: 'Memory',
    incidents: 'Incidents',
    '': 'Overview',
  }
  return `Open in ${names[page] ?? page}`
}

/** "Acknowledged by dave 38 minutes ago." */
export function ackText(a: Pick<AlertFinding, 'ackBy' | 'ackAt'>, now = Date.now()): string | undefined {
  if (!a.ackBy) return undefined
  return `Acknowledged by ${a.ackBy}${a.ackAt ? ` ${ago(a.ackAt, now)}` : ''}`
}

/** "Silenced by erin until Oct 19, 14:00 (in 2 days)". */
export function silenceText(a: Pick<AlertFinding, 'silencedBy' | 'silencedUntil'>, now = Date.now()): string | undefined {
  if (!a.silencedBy) return undefined
  if (!a.silencedUntil) return `Silenced by ${a.silencedBy}`
  const left = Date.parse(a.silencedUntil) - now
  return `Silenced by ${a.silencedBy} until ${formatDateTime(a.silencedUntil)}${Number.isFinite(left) && left > 0 ? ` (${durationText(left, 2)} left)` : ''}`
}

// ---- Actions on one row ----

export interface RowActions {
  ack: boolean
  unack: boolean
  silence: boolean
  unsilence: boolean
}

const NONE: RowActions = { ack: false, unack: false, silence: false, unsilence: false }

/**
 * What the caller may do to a finding, as the server judges it: nothing
 * without `actionable`; on a resolved finding only lifting a silence that
 * still lasts (it would apply when the finding reopens); otherwise ack or
 * unack by whether this episode is acknowledged, silence while it is not
 * silenced, unsilence while it is.
 */
export function rowActions(a: Pick<AlertFinding, 'actionable' | 'state' | 'ackBy' | 'silencedBy'>): RowActions {
  if (!a.actionable) return NONE
  if (a.state === 'resolved') return { ...NONE, unsilence: !!a.silencedBy }
  return { ack: !a.ackBy, unack: !!a.ackBy, silence: a.state !== 'silenced', unsilence: !!a.silencedBy }
}

/** A row gets a checkbox when some action applies to it. */
export function canSelect(a: Pick<AlertFinding, 'actionable' | 'state' | 'ackBy' | 'silencedBy'>): boolean {
  const r = rowActions(a)
  return r.ack || r.unack || r.silence || r.unsilence
}

// ---- Bulk selection ----

export interface Selection {
  /** Selected keys among the rows shown. */
  keys: string[]
  /** Keys of the rows shown that may be selected. */
  selectable: string[]
  /** Every selectable row shown is selected. */
  all: boolean
  /** Some, not all. */
  some: boolean
}

/** The selection as it applies to the rows shown: a key selected on another tab or filter does not count. */
export function selectionOf(rows: readonly AlertFinding[], selected: ReadonlySet<string>): Selection {
  const selectable = rows.filter(canSelect).map((a) => a.key)
  const keys = selectable.filter((k) => selected.has(k))
  const all = selectable.length > 0 && keys.length === selectable.length
  return { keys, selectable, all, some: keys.length > 0 && !all }
}

export function toggleKey(selected: ReadonlySet<string>, key: string): Set<string> {
  const out = new Set(selected)
  if (out.has(key)) out.delete(key)
  else out.add(key)
  return out
}

/** "Select all": selects every selectable row shown, or clears them when all already are. */
export function toggleAll(rows: readonly AlertFinding[], selected: ReadonlySet<string>): Set<string> {
  const sel = selectionOf(rows, selected)
  const out = new Set(selected)
  for (const k of sel.selectable) {
    if (sel.all) out.delete(k)
    else out.add(k)
  }
  return out
}

export type BulkPlan = Record<AlertActionKind, string[]>

/** For each action, the selected keys it applies to. */
export function bulkPlan(rows: readonly AlertFinding[], keys: readonly string[]): BulkPlan {
  const want = new Set(keys)
  const out: BulkPlan = { ack: [], unack: [], silence: [], unsilence: [] }
  for (const a of rows) {
    if (!want.has(a.key)) continue
    const r = rowActions(a)
    for (const k of ['ack', 'unack', 'silence', 'unsilence'] as const) if (r[k]) out[k].push(a.key)
  }
  return out
}

/** Keys per request: the server takes at most 100. */
export const MAX_KEYS = 100

export function chunks<T>(xs: readonly T[], n = MAX_KEYS): T[][] {
  const out: T[][] = []
  for (let i = 0; i < xs.length; i += n) out.push(xs.slice(i, i + n))
  return out
}

// ---- Silence: duration and reason ----

const MINUTE = 60_000
const HOUR = 60 * MINUTE
const DAY = 24 * HOUR

export const MIN_SILENCE_MS = 5 * MINUTE
export const DEFAULT_MAX_SILENCE_MS = 7 * DAY
/** The server never allows longer (alerts.MaxSilenceCap). */
export const MAX_SILENCE_CAP_MS = 30 * DAY

export const SILENCE_PRESETS: { value: string; label: string; ms: number }[] = [
  { value: '1h', label: '1 hour', ms: HOUR },
  { value: '4h', label: '4 hours', ms: 4 * HOUR },
  { value: '24h', label: '24 hours', ms: DAY },
  { value: '7d', label: '7 days', ms: 7 * DAY },
]

/** The longest silence this server allows: /info's, else the default 7 days; never above 30 days. */
export function maxSilenceMs(info: Pick<Info, 'alerts'> | undefined): number {
  const s = info?.alerts?.maxSilenceSeconds
  if (!s || !(s > 0)) return DEFAULT_MAX_SILENCE_MS
  return Math.min(s * 1000, MAX_SILENCE_CAP_MS)
}

const UNIT_MS: Record<string, number> = {
  d: DAY, day: DAY, days: DAY,
  h: HOUR, hr: HOUR, hrs: HOUR, hour: HOUR, hours: HOUR,
  m: MINUTE, min: MINUTE, mins: MINUTE, minute: MINUTE, minutes: MINUTE,
}

/**
 * A duration typed by a person: "90m", "6h", "2d", "1d12h", "1.5 hours",
 * "2 days 6 hours". Milliseconds, rounded to whole minutes; undefined when it
 * is not one (a bare number has no unit).
 */
export function parseDuration(text: string): number | undefined {
  const s = text.trim().toLowerCase()
  if (!s) return undefined
  const re = /(\d+(?:\.\d+)?|\.\d+)\s*([a-z]+)\s*/gy
  let total = 0
  let at = 0
  let m: RegExpExecArray | null
  while ((m = re.exec(s)) !== null) {
    const unit = UNIT_MS[m[2]]
    if (unit === undefined) return undefined
    total += parseFloat(m[1]) * unit
    at = re.lastIndex
  }
  if (at !== s.length) return undefined
  const ms = Math.round(total / MINUTE) * MINUTE
  return ms > 0 ? ms : undefined
}

/** A duration as the server parses it (Go's, plus days): "7d", "1d12h", "90m" → "1h30m". */
export function goDuration(ms: number): string {
  let min = Math.max(0, Math.round(ms / MINUTE))
  const d = Math.floor(min / 1440)
  min -= d * 1440
  const h = Math.floor(min / 60)
  const m = min - h * 60
  const out = `${d ? `${d}d` : ''}${h ? `${h}h` : ''}${m ? `${m}m` : ''}`
  return out || '0m'
}

/** "1 day 12 hours", "4 hours", "45 minutes"; `parts` keeps only the largest units. */
export function durationText(ms: number, parts = 3): string {
  let min = Math.max(0, Math.round(ms / MINUTE))
  const d = Math.floor(min / 1440)
  min -= d * 1440
  const h = Math.floor(min / 60)
  const m = min - h * 60
  const out: string[] = []
  if (d) out.push(`${d} ${plural(d, 'day', 'days')}`)
  if (h) out.push(`${h} ${plural(h, 'hour', 'hours')}`)
  if (m) out.push(`${m} ${plural(m, 'minute', 'minutes')}`)
  return out.length ? out.slice(0, parts).join(' ') : 'less than a minute'
}

/** A preset the server's maximum allows. */
export function presetAllowed(value: string, maxMs: number): boolean {
  const p = SILENCE_PRESETS.find((x) => x.value === value)
  return !!p && p.ms <= maxMs
}

export type DurationCheck = { ok: true; ms: number; go: string; text: string } | { ok: false; error: string }

/** The silence's length from the chosen preset, or the custom text when `choice` is "custom". */
export function checkDuration(choice: string, custom: string, maxMs: number): DurationCheck {
  let ms: number | undefined
  if (choice === 'custom') {
    if (!custom.trim()) return { ok: false, error: 'Enter how long, for example 90m, 6h or 2d.' }
    ms = parseDuration(custom)
    if (ms === undefined) return { ok: false, error: 'Use minutes, hours or days, for example 90m, 6h or 2d.' }
  } else {
    ms = SILENCE_PRESETS.find((p) => p.value === choice)?.ms
    if (ms === undefined) return { ok: false, error: 'Choose how long.' }
  }
  if (ms < MIN_SILENCE_MS) return { ok: false, error: 'A silence lasts at least 5 minutes.' }
  if (ms > maxMs) return { ok: false, error: `This server allows at most ${durationText(maxMs)}.` }
  return { ok: true, ms, go: goDuration(ms), text: durationText(ms) }
}

export const MIN_REASON = 3
export const MAX_REASON = 500

/** Characters as the server counts them (code points), after trimming. */
export function reasonLength(reason: string): number {
  return [...reason.trim()].length
}

export function checkReason(reason: string): { ok: boolean; error?: string; length: number } {
  const n = reasonLength(reason)
  if (n < MIN_REASON) return { ok: false, length: n, error: n === 0 ? 'Say why, so whoever is on call next knows.' : `At least ${MIN_REASON} characters.` }
  if (n > MAX_REASON) return { ok: false, length: n, error: `At most ${MAX_REASON} characters (now ${n}).` }
  return { ok: true, length: n }
}

// ---- What an action did ----

export interface Outcome {
  tone: 'ok' | 'warn' | 'crit'
  text: string
  /** Each finding the action was not taken on, and why. */
  details: string[]
}

const DONE: Record<AlertActionKind, string> = {
  ack: 'Acknowledged',
  unack: 'Removed the acknowledgement from',
  silence: 'Silenced',
  unsilence: 'Lifted the silence on',
}

const INVALID: Record<AlertActionKind, string> = {
  ack: 'it cannot be acknowledged as it is now',
  unack: 'it is not acknowledged',
  silence: 'the silence would end in the past',
  unsilence: 'it is not silenced',
}

/**
 * What the per-key results of one action say: how many it was taken on,
 * and for the rest why not. `titles` names the findings; `skipped` counts
 * selected rows the action did not apply to (left out of the request).
 */
export function outcomeOf(
  action: AlertActionKind,
  results: readonly AlertActionResult[],
  titles: ReadonlyMap<string, string>,
  opts: { forText?: string; skipped?: number } = {},
): Outcome {
  const ok = results.filter((r) => r.ok).length
  const skipped = opts.skipped ?? 0
  const what = (n: number) => `${n} ${plural(n, 'alert', 'alerts')}`
  let text = ok > 0 ? `${DONE[action]} ${what(ok)}${action === 'silence' && opts.forText ? ` for ${opts.forText}` : ''}.` : 'No alert was changed.'
  const why: Record<string, string> = {
    'not found': 'not found: it may have left the list, or you can no longer see it',
    forbidden: 'not allowed: acting on it needs the alerts responder role in its namespace',
    resolved: 'already resolved',
    invalid: INVALID[action],
  }
  const groups = new Map<string, number>()
  const details: string[] = []
  for (const r of results) {
    if (r.ok) continue
    const e = r.error ?? 'invalid'
    groups.set(e, (groups.get(e) ?? 0) + 1)
    details.push(`${titles.get(r.key) ?? r.key}: ${why[e] ?? e}`)
  }
  const failed = [...groups.entries()].map(([e, n]) => `${n} ${e === 'invalid' ? 'skipped' : e}`)
  if (failed.length) text += ` ${failed.join(', ')}.`
  if (skipped > 0) text += ` ${what(skipped)} selected did not apply and ${plural(skipped, 'was', 'were')} left out.`
  const tone = ok === results.length && skipped === 0 && ok > 0 ? 'ok' : ok > 0 ? 'warn' : 'crit'
  return { tone, text, details }
}

/** Why the request as a whole failed, from its status and the server's message. */
export function requestErrorText(status: number, message: string): string {
  switch (status) {
    case 403:
      return 'You may not acknowledge or silence alerts: that needs the kubesentry alerts responder role.'
    case 400:
    case 413:
    case 415:
      return `The server refused the request: ${message}.`
    case 503:
      return `The action could not be recorded (${message}). Try again in a moment.`
    case 404:
      return 'This server does not take alert actions.'
    default:
      return message || 'The request failed.'
  }
}

// ---- Details and history ----

export interface AnnotationRow {
  key: string
  label: string
  value: string
  /** For a URL that is safe to open (http or https). */
  href?: string
}

/** Annotations shown elsewhere (summary as the title, the key) or links the page makes itself. */
const SKIP_ANNOTATIONS = new Set(['summary', 'description', 'dedupe_key', 'kubesentry_url', 'incident_url'])

const ANNOTATION_WORD: Record<string, string> = {
  runbook_url: 'Runbook',
  predicted_oom: 'Predicted OOM kill',
  growth_bytes_per_hour: 'Growth (bytes per hour)',
  expires_at: 'Expires',
  first_at: 'First event',
  last_at: 'Latest event',
  actor_kind: 'Actor kind',
}

export function safeURL(u: string | undefined): string | undefined {
  return u && /^https?:\/\//i.test(u) ? u : undefined
}

/** The annotations worth showing in a row's details, the runbook first. */
export function annotationRows(annotations: Record<string, string> | undefined): AnnotationRow[] {
  const rows: AnnotationRow[] = []
  for (const [key, value] of Object.entries(annotations ?? {})) {
    if (SKIP_ANNOTATIONS.has(key) || !value) continue
    const label = ANNOTATION_WORD[key] ?? (key.replace(/_/g, ' ').replace(/^./, (c) => c.toUpperCase()))
    rows.push({ key, label, value, href: key.endsWith('_url') ? safeURL(value) : undefined })
  }
  return rows.sort((a, b) => (a.key === 'runbook_url' ? -1 : b.key === 'runbook_url' ? 1 : a.key.localeCompare(b.key)))
}

export interface HistoryRow {
  id: number
  actor: string
  what: string
  at: string
  reason?: string
  /** Taken on an earlier episode of the finding (an ack there no longer applies). */
  earlier: boolean
}

/** The action log of one finding, newest first, in words. */
export function historyRows(items: readonly AlertAction[], firstSeen?: string): HistoryRow[] {
  const first = firstSeen ? Date.parse(firstSeen) : NaN
  return items.map((x) => {
    let what: string
    switch (x.action) {
      case 'ack':
        what = 'acknowledged'
        break
      case 'unack':
        what = 'removed the acknowledgement'
        break
      case 'silence': {
        const span = x.until ? Date.parse(x.until) - Date.parse(x.at) : NaN
        what = Number.isFinite(span) && span > 0 ? `silenced for ${durationText(span, 2)}, until ${formatDateTime(x.until!)}` : 'silenced'
        break
      }
      case 'unsilence':
        what = 'lifted the silence'
        break
      default:
        what = x.action
    }
    const t = Date.parse(x.firstSeen)
    return {
      id: x.id,
      actor: x.actor || 'someone',
      what,
      at: x.at,
      reason: x.reason || undefined,
      earlier: Number.isFinite(first) && Number.isFinite(t) && t !== first,
    }
  })
}

/** The address names a finding that is not in the list (once the list is whole). */
export function keyMissing(f: Pick<AlertFilter, 'key'>, rows: readonly AlertFinding[], complete: boolean): boolean {
  return !!f.key && complete && !rows.some((a) => a.key === f.key)
}

/** A DOM id for a finding's row, from its key. */
export function rowId(key: string): string {
  let h = 0
  for (let i = 0; i < key.length; i++) h = (Math.imul(h, 31) + key.charCodeAt(i)) | 0
  return `alert-${(h >>> 0).toString(36)}`
}

// ---- The Overview's widget ----

export interface AlertsWidget {
  states: { key: AlertState; label: string; count: number; href: string }[]
  owners: { owner: string; label: string; count: number; href?: string }[]
  total: number
  href: string
}

/** The Overview's alerts panel: not-resolved findings by state and by owner, each linking to the Alerts page under the same namespace and owner. */
export function alertsWidget(a: NonNullable<OverviewResponse['alerts']>, filter: { namespace?: string; owner?: string } = {}): AlertsWidget {
  const base = { namespace: filter.namespace || undefined, owner: filter.owner || undefined }
  const states = (['open', 'acknowledged', 'silenced'] as const).map((s) => ({
    key: s,
    label: STATE_WORD[s].toLowerCase(),
    count: a[s] ?? 0,
    href: alertsHref({ ...base, state: s }),
  }))
  const owners = Object.entries(a.byOwner ?? {})
    .filter(([, n]) => n > 0)
    .sort((x, y) => y[1] - x[1] || x[0].localeCompare(y[0]))
    .map(([owner, count]) => ({
      owner,
      label: owner || 'no owner',
      count,
      href: owner ? alertsHref({ namespace: base.namespace, owner }) : undefined,
    }))
  return { states, owners, total: states.reduce((n, s) => n + s.count, 0), href: alertsHref(base) }
}
