// Sign-in helpers kept free of React and of the network so they are testable:
// the reload-loop guard for single sign-on, the recheck cool-down, and safe
// browser storage.

import type { Info } from './types'

/** The subset of Storage the helpers use, so tests can pass a plain object. */
export interface KV {
  getItem(key: string): string | null
  setItem(key: string, value: string): void
  removeItem(key: string): void
}

/** sessionStorage, or undefined where it is blocked (private mode, sandboxed frames, tests). */
export function sessionStore(): KV | undefined {
  try {
    return typeof window === 'undefined' ? undefined : window.sessionStorage
  } catch {
    return undefined
  }
}

/** localStorage, or undefined where it is blocked. */
export function localStore(): KV | undefined {
  try {
    return typeof window === 'undefined' ? undefined : window.localStorage
  } catch {
    return undefined
  }
}

export function readString(store: KV | undefined, key: string): string | undefined {
  try {
    return store?.getItem(key) ?? undefined
  } catch {
    return undefined
  }
}

export function writeString(store: KV | undefined, key: string, value: string | undefined): void {
  try {
    if (value === undefined || value === '') store?.removeItem(key)
    else store?.setItem(key, value)
  } catch {
    /* storage full or blocked: the value lasts until reload */
  }
}

export function readNumber(store: KV | undefined, key: string): number | undefined {
  const s = readString(store, key)
  if (s === undefined) return undefined
  const n = Number(s)
  return Number.isFinite(n) ? n : undefined
}

export function writeNumber(store: KV | undefined, key: string, n: number): void {
  writeString(store, key, String(n))
}

export type AuthSource = NonNullable<Info['identity']>['source']

/** Where the last /info said the identity came from; kept per tab so a 401 before /info answers is still handled. */
export const AUTH_SOURCE_KEY = 'kubesentry.authSource'

/** When the page last reloaded itself to renew a single sign-on session. */
export const REAUTH_KEY = 'kubesentry.reauthAt'

/** A second expiry within this long of a reload means renewing does not work: stop and say so. */
export const REAUTH_GAP_MS = 2 * 60_000

/**
 * What to do about a 401 in proxy mode. The oauth2-proxy session expired, and a
 * top-level navigation signs the user in again, so reload, unless the page did
 * that moments ago: then reloading again would loop.
 */
export function reauthDecision(lastReloadAt: number | undefined, now: number, gapMs = REAUTH_GAP_MS): 'reload' | 'stuck' {
  if (lastReloadAt === undefined) return 'reload'
  const since = now - lastReloadAt
  // A timestamp in the future (clock change) does not block forever.
  return since >= 0 && since < gapMs ? 'stuck' : 'reload'
}

/** How long a user waits between access rechecks (the server allows one a minute). */
export const RECHECK_COOLDOWN_MS = 60_000
export const RECHECK_KEY = 'kubesentry.recheckAt'

/** Milliseconds until the recheck button works again; 0 when it does. */
export function cooldownLeft(until: number | undefined, now: number): number {
  if (until === undefined) return 0
  return Math.max(0, until - now)
}

/**
 * A Retry-After header in milliseconds: either delay-seconds or an HTTP date.
 * Undefined when missing or unreadable.
 */
export function retryAfterMs(header: string | null | undefined, now: number): number | undefined {
  if (!header) return undefined
  const s = header.trim()
  if (/^\d+$/.test(s)) return Number(s) * 1000
  const t = Date.parse(s)
  return Number.isNaN(t) ? undefined : Math.max(0, t - now)
}

/** How the identity was established, in words. */
export function sourceText(source: AuthSource | undefined): string {
  switch (source) {
    case 'proxy':
      return 'Signed in through single sign-on'
    case 'token':
      return 'Using the shared API token'
    case 'none':
      return 'This server does not ask who you are'
    default:
      return ''
  }
}

/** Groups worth showing first: the ones that grant access, before the catch-alls every user has. */
export function sortGroups(groups: string[] | undefined): string[] {
  const generic = (g: string) => (g === 'system:authenticated' || g === 'system:unauthenticated' ? 1 : 0)
  return [...(groups ?? [])].sort((a, b) => generic(a) - generic(b) || a.localeCompare(b))
}
