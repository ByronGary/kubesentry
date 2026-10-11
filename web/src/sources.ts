// Whether the sources behind the pages answer: Prometheus and the audit store,
// from /info `unavailable` and from the warnings a response carries. Kept free
// of React so it is testable.

import type { Info } from './types'

/**
 * Why Prometheus cannot be queried, from /info `unavailable`; undefined while
 * it answers or when none is configured. The reason stays the same while the
 * failure does, so it doubles as the dismissal key.
 */
export function prometheusOutage(info: Pick<Info, 'unavailable'> | undefined): string | undefined {
  const reason = info?.unavailable?.prometheus
  if (reason === undefined) return undefined
  return reason.trim() || 'it cannot be queried'
}

export interface UnavailableBanner {
  /** Every unreadable source, so dismissing the banner on one page hides it on the others. */
  sig: string
  /** The sources to list on this page, by name. */
  shown: [string, string][]
}

/** The generic "Some sources could not be read" banner, leaving out the sources this page explains itself. */
export function unavailableBanner(unavailable: Info['unavailable'], explained: readonly string[] = []): UnavailableBanner {
  const all = Object.entries(unavailable ?? {}).sort(([a], [b]) => a.localeCompare(b))
  return {
    sig: all.map(([k, v]) => `${k}=${v}`).join('\n'),
    shown: all.filter(([k]) => !explained.includes(k)),
  }
}

// The server's words when a source fails part of a response (internal/api pods.go, oom.go).
const PROMETHEUS_FAILED = /could not query Prometheus/i
const AUDIT_FAILED = /could not query the audit store/i
const AUDIT_HIDDEN = /^Activity is hidden/i

/** Response warnings, without those the page already explains in its own notice. */
export function unexplainedWarnings(warnings: string[] | undefined, explained: { prometheus?: boolean; audit?: boolean }): string[] {
  return (warnings ?? []).filter((w) => !(explained.prometheus && PROMETHEUS_FAILED.test(w)) && !(explained.audit && AUDIT_FAILED.test(w)))
}

/**
 * The pod page's activity section: `shown` when the audit store answered,
 * `unavailable` when it was asked and did not answer (busy or down, so it is
 * worth asking again), `hidden` when the caller may not read audit events in
 * the namespace, `off` when the server has no audit log.
 */
export type PodActivity = 'shown' | 'unavailable' | 'hidden' | 'off'

export function podActivity(d: { auditAvailable: boolean; warnings?: string[] }): PodActivity {
  if (d.auditAvailable) return 'shown'
  const w = d.warnings ?? []
  if (w.some((x) => AUDIT_FAILED.test(x))) return 'unavailable'
  if (w.some((x) => AUDIT_HIDDEN.test(x))) return 'hidden'
  return 'off'
}
