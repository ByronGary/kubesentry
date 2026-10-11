import { useCallback, useEffect, useRef, useState } from 'react'
import { apiGet, ApiError } from './api'

export interface ApiState<T> {
  data: T | undefined
  error: ApiError | Error | undefined
  /** True while a request is in flight; `data` may still hold the previous result. */
  loading: boolean
  reload: () => void
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
 * screen does not collapse, and refetches when the token changes.
 */
export function useApi<T>(path: string | null, refreshMs?: number): ApiState<T> {
  const [data, setData] = useState<T>()
  const [error, setError] = useState<ApiError | Error>()
  const [loading, setLoading] = useState(path !== null)
  const [tick, setTick] = useState(0)
  const auth = useAuthVersion()
  const lastPath = useRef<string | null>(null)

  useEffect(() => {
    if (!path) {
      setLoading(false)
      return
    }
    // A different resource: drop stale data. Same resource: keep it while refetching.
    if (lastPath.current !== path) {
      setData(undefined)
      setError(undefined)
    }
    lastPath.current = path
    const ctl = new AbortController()
    setLoading(true)
    apiGet<T>(path, ctl.signal)
      .then((d) => {
        setData(d)
        setError(undefined)
      })
      .catch((e: unknown) => {
        if (ctl.signal.aborted) return
        setError(e instanceof Error ? e : new Error(String(e)))
      })
      .finally(() => {
        if (!ctl.signal.aborted) setLoading(false)
      })
    return () => ctl.abort()
  }, [path, tick, auth])

  useEffect(() => {
    if (!refreshMs || !path) return
    const id = setInterval(() => setTick((t) => t + 1), refreshMs)
    return () => clearInterval(id)
  }, [refreshMs, path])

  const reload = useCallback(() => setTick((t) => t + 1), [])
  return { data, error, loading, reload }
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
