import { useCallback, useEffect, useRef, useState } from 'react'
import { apiGet } from './api'
import { followPages, isAbort, PAGE_LIMIT, pageURL, ROW_CAP, type PageFetcher } from './paging'
import type { Paged } from './types'
import { useAuthVersion, type ApiState } from './useApi'

export interface PagedOptions<R, T> {
  /** The rows in one response. */
  items: (r: R) => T[] | undefined
  /** The first response, with every row loaded so far in place of its own. */
  merge: (first: R, items: T[]) => R
  limit?: number
  cap?: number
  /** Refetch this often, but only while everything fits in one page. */
  refreshMs?: number
  /** `auto` follows `continue` in the background; `manual` waits for loadMore(). */
  mode?: 'auto' | 'manual'
}

export interface PagedState<R> extends ApiState<R> {
  /** Rows loaded so far. */
  loaded: number
  pages: number
  /** Auto mode: more pages are on their way. */
  following: boolean
  /** Auto mode: stopped at the row cap with more on the server. */
  truncated: boolean
  /** The user stopped loading. */
  stopped: boolean
  /** Manual mode: the server has another page. */
  hasMore: boolean
  loadingMore: boolean
  loadMore: () => void
  stop: () => void
  /** Every row there is has been loaded. */
  complete: boolean
}

/**
 * GET a list route page by page. In auto mode the rows appear as the first page
 * arrives and grow as the rest follow; leaving the page aborts the loop. A
 * server that does not page answers the first request with everything and no
 * `continue`, which ends the loop at once.
 */
export function usePaged<R extends Paged, T>(path: string | null, o: PagedOptions<R, T>): PagedState<R> {
  const [data, setDataState] = useState<R>()
  const [error, setError] = useState<Error>()
  const [loading, setLoading] = useState(path !== null)
  const [loaded, setLoaded] = useState(0)
  const [pages, setPages] = useState(0)
  const [following, setFollowing] = useState(false)
  const [truncated, setTruncated] = useState(false)
  const [stopped, setStopped] = useState(false)
  const [next, setNext] = useState<string>()
  const [loadingMore, setLoadingMore] = useState(false)
  const [tick, setTick] = useState(0)
  const auth = useAuthVersion()

  const opts = useRef(o)
  opts.current = o
  const lastPath = useRef<string | null>(null)
  const hasData = useRef(false)
  const ctlRef = useRef<AbortController | undefined>(undefined)
  const moreCtl = useRef<AbortController | undefined>(undefined)
  const stoppedRef = useRef(false)
  const setData = (d: R | undefined) => {
    hasData.current = d !== undefined
    setDataState(d)
  }

  useEffect(() => {
    if (!path) {
      setLoading(false)
      return
    }
    const fresh = lastPath.current !== path
    if (fresh) {
      setData(undefined)
      setError(undefined)
      setLoaded(0)
      setPages(0)
      setTruncated(false)
      setNext(undefined)
    }
    lastPath.current = path
    moreCtl.current?.abort()
    const ctl = new AbortController()
    ctlRef.current = ctl
    stoppedRef.current = false
    setStopped(false)
    setLoadingMore(false)
    setLoading(true)

    const { items, merge, limit = PAGE_LIMIT, cap = ROW_CAP, mode = 'auto' } = opts.current
    let first: R | undefined
    const fetchPage: PageFetcher<T> = async (cont, signal) => {
      const r = await apiGet<R>(pageURL(path, limit, cont), signal)
      if (!first) first = r
      return { items: items(r) ?? [], next: r.continue }
    }
    // A first load shows rows as they arrive. A refresh keeps the old rows until the new set is whole.
    const progressive = !hasData.current

    const fail = (e: unknown) => {
      if (ctl.signal.aborted || isAbort(e)) return
      setError(e instanceof Error ? e : new Error(String(e)))
    }

    if (mode === 'manual') {
      fetchPage(undefined, ctl.signal)
        .then((p) => {
          setData(opts.current.merge(first!, p.items))
          setNext(p.next)
          setLoaded(p.items.length)
          setPages(1)
          setError(undefined)
        })
        .catch(fail)
        .finally(() => {
          if (!ctl.signal.aborted) setLoading(false)
        })
    } else {
      setFollowing(true)
      followPages(fetchPage, {
        signal: ctl.signal,
        cap,
        onPage: (all, n, more) => {
          if (progressive || !more) setData(merge(first!, all))
          setLoaded(all.length)
          setPages(n)
          setFollowing(more)
          if (progressive) setLoading(false)
        },
      })
        .then((res) => {
          setTruncated(res.truncated)
          setNext(res.next)
          setError(undefined)
        })
        .catch(fail)
        .finally(() => {
          if (ctl.signal.aborted) return
          setFollowing(false)
          setLoading(false)
        })
    }
    return () => ctl.abort()
  }, [path, tick, auth])

  // Abort a "load older" request when leaving the page.
  useEffect(() => () => moreCtl.current?.abort(), [])

  const { refreshMs } = o
  useEffect(() => {
    if (!refreshMs || !path || pages !== 1 || following || stopped) return
    const id = setInterval(() => setTick((t) => t + 1), refreshMs)
    return () => clearInterval(id)
  }, [refreshMs, path, pages, following, stopped])

  const reload = useCallback(() => setTick((t) => t + 1), [])

  const stop = useCallback(() => {
    if (!ctlRef.current || ctlRef.current.signal.aborted) return
    stoppedRef.current = true
    ctlRef.current.abort()
    setStopped(true)
    setFollowing(false)
    setLoading(false)
  }, [])

  const loadMore = useCallback(() => {
    if (!next || !path || loadingMore) return
    const { items, merge, limit = PAGE_LIMIT } = opts.current
    moreCtl.current?.abort()
    const ctl = new AbortController()
    moreCtl.current = ctl
    setLoadingMore(true)
    apiGet<R>(pageURL(path, limit, next), ctl.signal)
      .then((r) => {
        const add = items(r) ?? []
        setDataState((prev) => {
          const d = prev ? merge(prev, [...(items(prev) ?? []), ...add]) : merge(r, add)
          hasData.current = true
          return d
        })
        setNext(r.continue && r.continue !== next ? r.continue : undefined)
        setLoaded((n) => n + add.length)
        setPages((p) => p + 1)
      })
      .catch((e: unknown) => {
        if (ctl.signal.aborted || isAbort(e)) return
        setError(e instanceof Error ? e : new Error(String(e)))
      })
      .finally(() => {
        if (!ctl.signal.aborted) setLoadingMore(false)
      })
  }, [next, path, loadingMore])

  const mode = o.mode ?? 'auto'
  const complete = data !== undefined && !following && !truncated && !stopped && (mode === 'auto' || !next)
  return {
    data,
    error,
    loading,
    reload,
    loaded,
    pages,
    following,
    truncated,
    stopped,
    hasMore: mode === 'manual' && !!next,
    loadingMore,
    loadMore,
    stop,
    complete,
  }
}
