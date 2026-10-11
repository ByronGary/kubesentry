// How much history the server really holds, so the UI never claims a window it
// has no data for. Kept free of React so it is testable.

import { formatDateTime, plural } from './format'
import type { Info } from './types'

type AuditStore = NonNullable<Info['auditStore']>
type Snapshot = NonNullable<Info['snapshot']>

/** "6 hours", "24 hours", "30 days", "45 minutes". */
export function formatSpan(hours: number): string {
  if (!Number.isFinite(hours) || hours <= 0) return '0 minutes'
  if (hours < 1) {
    const m = Math.max(1, Math.round(hours * 60))
    return `${m} ${plural(m, 'minute', 'minutes')}`
  }
  if (hours < 47.5) {
    const h = Math.round(hours)
    return `${h} ${plural(h, 'hour', 'hours')}`
  }
  const d = Math.round(hours / 24)
  return `${d} ${plural(d, 'day', 'days')}`
}

/** Hours in a Go duration string such as "168h0m0s", "6h", "90m". Undefined when unreadable. */
export function durationHours(s: string | undefined): number | undefined {
  if (!s) return undefined
  const re = /(\d+(?:\.\d+)?)(h|ms|m|s)/g
  let total = 0
  let any = false
  let m: RegExpExecArray | null
  while ((m = re.exec(s))) {
    any = true
    const v = Number(m[1])
    total += m[2] === 'h' ? v : m[2] === 'm' ? v / 60 : m[2] === 's' ? v / 3600 : v / 3_600_000
  }
  return any ? total : undefined
}

/**
 * Hours of audit history the store can answer for: the smaller of its
 * retention and the age of its oldest event. Undefined when the server does not
 * say, which includes the moment at startup before the store answers /info:
 * callers then enable every window and word their text neutrally. `events` is
 * an estimate above 100,000 with Postgres, but 0 is always exact.
 */
export function auditHistoryHours(store: AuditStore | undefined, now: number = Date.now()): number | undefined {
  if (!store) return undefined
  let h: number | undefined = store.retentionHours && store.retentionHours > 0 ? store.retentionHours : undefined
  if (store.events === 0) return 0
  if (store.oldest) {
    const t = Date.parse(store.oldest)
    if (!Number.isNaN(t)) {
      const age = Math.max(0, (now - t) / 3_600_000)
      h = h === undefined ? age : Math.min(h, age)
    }
  }
  return h
}

/** Hours of metrics Prometheus keeps, when the server knows. */
export function metricsHistoryHours(p: Info['prometheus'] | undefined): number | undefined {
  return p?.retentionHours && p.retentionHours > 0 ? p.retentionHours : undefined
}

export interface WindowOption<V extends string = string> {
  value: V
  label: string
  hours: number
}

export interface WindowChoice<V extends string = string> extends WindowOption<V> {
  disabled: boolean
  /** Why it is disabled, for a tooltip. */
  reason?: string
}

/**
 * Disable windows with no data behind them. A window stays enabled when the
 * history covers it, and so does the smallest window that reaches past the
 * history, so the user can always see everything there is.
 */
export function windowChoices<V extends string>(options: WindowOption<V>[], historyHours: number | undefined, why: (history: number) => string): WindowChoice<V>[] {
  if (historyHours === undefined) return options.map((o) => ({ ...o, disabled: false }))
  // A little slack both ways: 6 h 59 min of history still makes "7 hours" fully backed.
  const have = historyHours * 1.02
  const backed = options.filter((o) => o.hours <= have)
  const coversAll = backed.some((o) => o.hours >= historyHours * 0.98)
  const covering = coversAll ? undefined : options.filter((o) => o.hours > have).sort((a, b) => a.hours - b.hours)[0]
  return options.map((o) => {
    const disabled = o.hours > have && o !== covering
    return disabled ? { ...o, disabled, reason: why(historyHours) } : { ...o, disabled }
  })
}

/** Tooltip for a disabled audit window. */
export function auditWhy(store: AuditStore | undefined): (history: number) => string {
  return (h) => {
    if (store?.events === 0) return 'No audit events are stored yet.'
    const since = store?.oldest ? ` (since ${formatDateTime(store.oldest)})` : ''
    if (store?.retentionHours && h >= store.retentionHours * 0.98) return `Audit events are kept for ${formatSpan(store.retentionHours)}.`
    return `The audit log holds only ${formatSpan(h)} of events${since}.`
  }
}

/** Tooltip for a disabled metrics window. */
export function metricsWhy(h: number): string {
  return `Prometheus keeps only ${formatSpan(h)} of history.`
}

/**
 * "in the last 24 hours", or, when the source holds less, "in the last 6 hours
 * (all the history Prometheus keeps)". Never claims more than there is.
 */
export function lookbackText(wantedHours: number, historyHours: number | undefined, source: string): string {
  if (historyHours !== undefined && historyHours < wantedHours * 0.98) {
    if (historyHours <= 0) return `yet (${source} has no history)`
    return `in the last ${formatSpan(historyHours)} (all the history ${source} has)`
  }
  return `in the last ${formatSpan(wantedHours)}`
}

/**
 * The lookback the empty Findings page may claim for its `wantedHours` of
 * queries: no more than Prometheus (`metricsHours`, when leaks were checked)
 * or the audit log holds. An audit log that is part of the claim but has not
 * said how far back it goes (a missing `auditStore` means "not known yet", not
 * "empty") makes the claim neutral: "recently".
 */
export function findingsLookback(
  wantedHours: number,
  metricsHours: number | undefined,
  audit: { included: boolean; store?: AuditStore },
  now: number = Date.now(),
): string {
  if (audit.included && !audit.store) return 'recently'
  const events = audit.included ? auditHistoryHours(audit.store, now) : undefined
  if (events !== undefined && (metricsHours === undefined || events < metricsHours)) return lookbackText(wantedHours, events, 'the audit log')
  return lookbackText(wantedHours, metricsHours, 'Prometheus')
}

/**
 * The empty state for a pod's recent activity. `window` is the server's
 * lookback (a Go duration) when it says. Without it, or while the audit store
 * has not said how far back it goes (/info leaves `auditStore` out for a
 * moment at startup), the text makes no claim about how far back it looked.
 */
export function activityEmptyText(window: string | undefined, store: AuditStore | undefined, now: number = Date.now()): string {
  const wanted = durationHours(window)
  const history = auditHistoryHours(store, now)
  if (wanted === undefined || history === undefined) {
    if (history !== undefined && store?.oldest) return `Nobody has acted on this pod since the audit log begins (${formatDateTime(store.oldest)}).`
    return 'Nobody has acted on this pod recently.'
  }
  if (history < wanted * 0.98 && store?.oldest) {
    return `Nobody has acted on this pod since the audit log begins (${formatDateTime(store.oldest)}).`
  }
  return `Nobody has acted on this pod in the last ${formatSpan(wanted)}.`
}

/** Seconds as "45 s", "3 minutes", "2 hours". */
export function formatAgeSeconds(s: number): string {
  if (s < 120) return `${Math.max(0, Math.round(s))} s`
  return formatSpan(s / 3600)
}

/** Data older than this gets a banner even when the server does not call it stale. */
export const STALE_AFTER_SECONDS = 60

/** The staleness banner text, or undefined when the data is fresh or the server does not say. */
export function stalenessText(snap: Snapshot | undefined): string | undefined {
  if (!snap) return undefined
  const age = Number.isFinite(snap.ageSeconds) ? snap.ageSeconds : 0
  if (!snap.stale && age <= STALE_AFTER_SECONDS) return undefined
  return `Data is ${formatAgeSeconds(age)} old; the API server may be unreachable.`
}

/** "prod-use1 · Kubernetes 1.31.2 · AWS us-east-1". */
export function clusterFacts(c: Info['cluster'] | undefined): { name?: string; facts: string[] } {
  if (!c) return { facts: [] }
  const facts: string[] = []
  if (c.version) facts.push(`Kubernetes ${c.version.replace(/^v/, '')}`)
  const provider = PROVIDER[c.provider ?? ''] ?? c.provider
  const where = [provider, c.region].filter(Boolean).join(' ')
  if (where) facts.push(where)
  if (c.platform && !where) facts.push(c.platform)
  return { name: c.name || undefined, facts }
}

const PROVIDER: Record<string, string> = { aws: 'AWS', gce: 'Google Cloud', azure: 'Azure', kind: 'kind', openstack: 'OpenStack', vsphere: 'vSphere' }
