import { useCallback, useEffect, useRef, useState } from 'react'
import { apiGet, ApiError } from './api'
import { isBusy, nextRetry, refreshDue, type Retry } from './retry'

export interface ApiState<T> {
  data: T | undefined
  error: ApiError | Error | undefined
  /** True while a request is in flight; `data` may still hold the previous result. */
  loading: boolean
  reload: () => void
  /**
   * Set while a busy store is being waited out: when the next attempt starts.
   * With `error` it is a 503; without, an answer that `busyIn` flagged.
   */
  retry?: Retry
}

export interface ApiOptions<T> {
  /** Retry a 503 (a busy audit store) after its Retry-After, backing off while it stays busy. Other errors show as usual. */
  retryBusy?: boolean
  /** An answer with a part its store could not serve: keep it, and ask again the same way. */
  busyIn?: (data: T) => boolean
}

let authVersion = 0
const listeners = new Set<() => void>()

/**
 * Refetch everything: a token was entered, or the user's access was
 * rechecked. Every useApi and usePaged hook loads again.
 */
export function bumpAuth(): void {
  authVersion++
  listeners.forEach((l) => l())
}

/** Changes whenever bumpAuth runs, so effects that depend on it refetch. */
export function useAuthVersion(): number {
  const [v, setV] = useState(authVersion)
  useEffect(() => {
    const on = () => setV(authVersion)
    listeners.add(on)
    return () => void listeners.delete(on)
  }, [])
  return v
}

/**
 * GET `path` (null to skip). Keeps the previous result while refetching so the
 * screen does not collapse, and refetches when the token changes. With
 * `retryBusy`, a 503 schedules another attempt (see retry.ts) and pauses the
 * periodic refresh meanwhile; leaving the page or changing `path` cancels it.
 */
export function useApi<T>(path: string | null, refreshMs?: number, options?: ApiOptions<T>): ApiState<T> {
  const [data, setData] = useState<T>()
  const [error, setError] = useState<ApiError | Error>()
  const [loading, setLoading] = useState(path !== null)
  const [retry, setRetry] = useState<Retry>()
  const [tick, setTick] = useState(0)
  const auth = useAuthVersion()
  const lastPath = useRef<string | null>(null)
  const opts = useRef({ options, refreshMs })
  opts.current = { options, refreshMs }
  // Busy answers in a row, for the backoff.
  const busy = useRef(0)

  useEffect(() => {
    if (!path) {
      setLoading(false)
      setRetry(undefined)
      busy.current = 0
      return
    }
    // A different resource: drop stale data. Same resource: keep it while refetching.
    if (lastPath.current !== path) {
      setData(undefined)
      setError(undefined)
      setRetry(undefined)
      busy.current = 0
    }
    lastPath.current = path
    const ctl = new AbortController()
    let timer: ReturnType<typeof setTimeout> | undefined
    const again = (retryAfterMs: number | undefined) => {
      busy.current++
      const now = Date.now()
      const r = nextRetry(busy.current, retryAfterMs, now, { maxMs: opts.current.refreshMs })
      setRetry(r)
      timer = setTimeout(() => setTick((t) => t + 1), r.at - now)
    }
    const settled = () => {
      busy.current = 0
      setRetry(undefined)
    }
    setLoading(true)
    apiGet<T>(path, ctl.signal)
      .then((d) => {
        if (ctl.signal.aborted) return
        setData(d)
        setError(undefined)
        if (opts.current.options?.busyIn?.(d)) again(undefined)
        else settled()
      })
      .catch((e: unknown) => {
        if (ctl.signal.aborted) return
        const err = e instanceof Error ? e : new Error(String(e))
        setError(err)
        if (opts.current.options?.retryBusy && isBusy(err)) again((err as ApiError).retryAfterMs)
        else settled()
      })
      .finally(() => {
        if (!ctl.signal.aborted) setLoading(false)
      })
    return () => {
      ctl.abort()
      clearTimeout(timer)
    }
  }, [path, tick, auth])

  // The scheduled retry stands in for the periodic refresh while a store is busy.
  const waiting = retry !== undefined
  useEffect(() => {
    if (!refreshMs || !path || waiting) return
    const id = setInterval(() => setTick((t) => t + 1), refreshMs)
    return () => clearInterval(id)
  }, [refreshMs, path, waiting])

  const reload = useCallback(() => setTick((t) => t + 1), [])
  return { data, error, loading, reload, retry }
}

/** Whether the tab is visible; false while it is in the background. */
export function usePageVisible(): boolean {
  const [visible, setVisible] = useState(() => typeof document === 'undefined' || document.visibilityState !== 'hidden')
  useEffect(() => {
    const on = () => setVisible(document.visibilityState !== 'hidden')
    document.addEventListener('visibilitychange', on)
    return () => document.removeEventListener('visibilitychange', on)
  }, [])
  return visible
}

/**
 * useApi, refreshed every `ms` while the tab is visible. A hidden tab stops
 * asking; coming back asks once at once when the last answer is an interval
 * old (retry.ts `refreshDue`). Busy answers are retried as useApi does.
 */
export function usePolled<T>(path: string | null, ms: number, options?: ApiOptions<T>): ApiState<T> {
  const visible = usePageVisible()
  const state = useApi<T>(path, visible ? ms : undefined, options)
  const loadedAt = useRef<number | undefined>(undefined)
  useEffect(() => {
    if (state.data !== undefined) loadedAt.current = Date.now()
  }, [state.data])
  const { reload } = state
  const wasVisible = useRef(visible)
  useEffect(() => {
    const back = visible && !wasVisible.current
    wasVisible.current = visible
    if (back && path && refreshDue(loadedAt.current, Date.now(), ms)) reload()
  }, [visible, path, ms, reload])
  return state
}

/** `value`, once it has stopped changing for `ms`. Keeps typing responsive on big lists. */
export function useDebounced<T>(value: T, ms = 200): T {
  const [v, setV] = useState(value)
  useEffect(() => {
    if (Object.is(v, value)) return
    const id = setTimeout(() => setV(value), ms)
    return () => clearTimeout(id)
  }, [value, ms, v])
  return v
}

/** A clock that ticks every `ms`, for "3 s ago" text and cool-downs. */
export function useNow(ms = 1000, active = true): number {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    if (!active) return
    setNow(Date.now())
    const id = setInterval(() => setNow(Date.now()), ms)
    return () => clearInterval(id)
  }, [ms, active])
  return now
}
