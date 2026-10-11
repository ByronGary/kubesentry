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
export function bumpAuth(): void {
  authVersion++
  listeners.forEach((l) => l())
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
  const [auth, setAuth] = useState(authVersion)
  const lastPath = useRef<string | null>(null)

  useEffect(() => {
    const on = () => setAuth(authVersion)
    listeners.add(on)
    return () => void listeners.delete(on)
  }, [])

  useEffect(() => {
    if (!path) {
      setLoading(false)
      return
    }
    // A different resource: drop stale data. Same resource: keep it while refetching.
    if (lastPath.current !== path) setData(undefined)
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
