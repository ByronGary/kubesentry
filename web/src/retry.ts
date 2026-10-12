// When to try again after a busy audit store, kept free of React so it is testable.
//
// The audit routes answer 503 with Retry-After when every read slot of the
// store stayed busy. The pages then wait that long and ask again, doubling the
// wait while the store stays busy, up to a minute.

/** The wait when a 503 carries no usable Retry-After. */
export const BUSY_DEFAULT_MS = 5_000

/** The longest wait between attempts, whatever the server says. */
export const BUSY_MAX_MS = 60_000

/** The shortest wait, so "Retry-After: 0" cannot spin. */
export const BUSY_MIN_MS = 1_000

/** Up to this fraction is added to each wait, so many tabs refused at once do not return at once. */
export const BUSY_JITTER = 0.2

/** A scheduled retry. */
export interface Retry {
  /** When the next attempt starts (epoch ms). */
  at: number
  /** How many busy answers in a row led here (1 for the first). */
  attempt: number
}

/** The parts of an ApiError the decision reads. */
export interface Failure {
  status?: number
  retryAfterMs?: number
}

/** A busy store: 503, with or without Retry-After. */
export function isBusy(e: unknown): e is Failure {
  return typeof e === 'object' && e !== null && (e as Failure).status === 503
}

/**
 * Milliseconds to wait after the `attempt`-th busy answer in a row: Retry-After
 * (or 5 s) the first time, doubling after each further one, never above
 * `maxMs` (60 s, or less to keep a page's own refresh rhythm). `random` in
 * [0, 1) adds up to 20% so tabs refused together spread out.
 */
export function busyDelayMs(retryAfterMs: number | undefined, attempt: number, random = 0, maxMs = BUSY_MAX_MS): number {
  const cap = Math.max(BUSY_MIN_MS, Math.min(BUSY_MAX_MS, maxMs))
  const first = retryAfterMs !== undefined && Number.isFinite(retryAfterMs) ? retryAfterMs : BUSY_DEFAULT_MS
  const base = Math.min(cap, Math.max(BUSY_MIN_MS, first))
  const n = Math.max(1, Math.floor(attempt))
  const wait = base * 2 ** Math.min(n - 1, 16)
  const r = Math.min(1, Math.max(0, random))
  return Math.round(Math.min(cap, wait * (1 + BUSY_JITTER * r)))
}

/** The retry after the `attempt`-th busy answer in a row. */
export function nextRetry(attempt: number, retryAfterMs: number | undefined, now: number, o: { maxMs?: number; random?: number } = {}): Retry {
  return { at: now + busyDelayMs(retryAfterMs, attempt, o.random ?? Math.random(), o.maxMs), attempt }
}

/** Whole seconds until the retry, never negative. */
export function secondsLeft(retry: Retry, now: number): number {
  return Math.max(0, Math.ceil((retry.at - now) / 1000))
}

/**
 * Polling pauses while the tab is hidden. On coming back, ask at once when the
 * last answer is at least one interval old; otherwise the regular rhythm will.
 * Nothing loaded yet means the first request is still on its way.
 */
export function refreshDue(loadedAt: number | undefined, now: number, intervalMs: number): boolean {
  if (loadedAt === undefined) return false
  return now - loadedAt >= intervalMs
}

/** "retrying in 5 s…", then "retrying now…" while the attempt is under way. */
export function retryText(retry: Retry, now: number): string {
  const s = secondsLeft(retry, now)
  return s > 0 ? `retrying in ${s} s…` : 'retrying now…'
}
