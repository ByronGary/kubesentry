import { useCallback, useEffect, useRef, useState } from 'react'
import { apiGet, type ApiError } from './api'
import { followPages, isAbort, PAGE_LIMIT, pageURL, ROW_CAP, type PageFetcher } from './paging'
import { isBusy, nextRetry, type Retry } from './retry'
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
  /** Retry a 503 (a busy audit store) after its Retry-After, backing off while it stays busy. */
  retryBusy?: boolean
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
  /** With `retryBusy`: loadMore() met a busy store and tries again at this time. */
  moreRetry?: Retry
}

type Timer = ReturnType<typeof setTimeout> | undefined

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
  const [retry, setRetry] = useState<Retry>()
  const [moreRetry, setMoreRetry] = useState<Retry>()
  const [tick, setTick] = useState(0)
  const auth = useAuthVersion()

  const opts = useRef(o)
  opts.current = o
  const lastPath = useRef<string | null>(null)
  const hasData = useRef(false)
  const ctlRef = useRef<AbortController | undefined>(undefined)
  const moreCtl = useRef<AbortController | undefined>(undefined)
  const stoppedRef = useRef(false)
  // Busy answers in a row, for the backoff; loadMore() keeps its own count and timer.
  const busy = useRef(0)
  const moreBusy = useRef(0)
  const moreTimer = useRef<Timer>(undefined)
  const loadMoreRef = useRef<() => void>(() => {})
  const setData = (d: R | undefined) => {
    hasData.current = d !== undefined
    setDataState(d)
  }
  const cancelMoreRetry = () => {
    clearTimeout(moreTimer.current)
    moreTimer.current = undefined
    moreBusy.current = 0
    setMoreRetry(undefined)
  }

  useEffect(() => {
    if (!path) {
      setLoading(false)
      setRetry(undefined)
      busy.current = 0
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
      setRetry(undefined)
      busy.current = 0
    }
    lastPath.current = path
    moreCtl.current?.abort()
    cancelMoreRetry()
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

    let timer: Timer
    const settled = () => {
      busy.current = 0
      setRetry(undefined)
    }
    const fail = (e: unknown) => {
      if (ctl.signal.aborted || isAbort(e)) return
      const err = e instanceof Error ? e : new Error(String(e))
      setError(err)
      if (!opts.current.retryBusy || !isBusy(err)) {
        settled()
        return
      }
      busy.current++
      const now = Date.now()
      const r = nextRetry(busy.current, (err as ApiError).retryAfterMs, now, { maxMs: opts.current.refreshMs })
      setRetry(r)
      timer = setTimeout(() => setTick((t) => t + 1), r.at - now)
    }

    if (mode === 'manual') {
      fetchPage(undefined, ctl.signal)
        .then((p) => {
          if (ctl.signal.aborted) return
          setData(opts.current.merge(first!, p.items))
          setNext(p.next)
          setLoaded(p.items.length)
          setPages(1)
          setError(undefined)
          settled()
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
          settled()
        })
        .catch(fail)
        .finally(() => {
          if (ctl.signal.aborted) return
          setFollowing(false)
          setLoading(false)
        })
    }
    return () => {
      ctl.abort()
      clearTimeout(timer)
    }
  }, [path, tick, auth])

  // Abort a "load older" request, or its pending retry, when leaving the page.
  useEffect(
    () => () => {
      moreCtl.current?.abort()
      clearTimeout(moreTimer.current)
    },
    [],
  )

  const { refreshMs } = o
  // A scheduled retry stands in for the periodic refresh while a store is busy.
  const waiting = retry !== undefined || moreRetry !== undefined
  useEffect(() => {
    if (!refreshMs || !path || pages !== 1 || following || stopped || waiting) return
    const id = setInterval(() => setTick((t) => t + 1), refreshMs)
    return () => clearInterval(id)
  }, [refreshMs, path, pages, following, stopped, waiting])

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
    clearTimeout(moreTimer.current)
    const ctl = new AbortController()
    moreCtl.current = ctl
    setLoadingMore(true)
    apiGet<R>(pageURL(path, limit, next), ctl.signal)
      .then((r) => {
        if (ctl.signal.aborted) return
        const add = items(r) ?? []
        setDataState((prev) => {
          const d = prev ? merge(prev, [...(items(prev) ?? []), ...add]) : merge(r, add)
          hasData.current = true
          return d
        })
        setNext(r.continue && r.continue !== next ? r.continue : undefined)
        setLoaded((n) => n + add.length)
        setPages((p) => p + 1)
        moreBusy.current = 0
        setMoreRetry(undefined)
      })
      .catch((e: unknown) => {
        if (ctl.signal.aborted || isAbort(e)) return
        const err = e instanceof Error ? e : new Error(String(e))
        if (opts.current.retryBusy && isBusy(err)) {
          moreBusy.current++
          const now = Date.now()
          const r = nextRetry(moreBusy.current, (err as ApiError).retryAfterMs, now)
          setMoreRetry(r)
          // The latest loadMore, which sees loadingMore back at false.
          moreTimer.current = setTimeout(() => loadMoreRef.current(), r.at - now)
          return
        }
        moreBusy.current = 0
        setMoreRetry(undefined)
        setError(err)
      })
      .finally(() => {
        if (!ctl.signal.aborted) setLoadingMore(false)
      })
  }, [next, path, loadingMore])
  loadMoreRef.current = loadMore

  const mode = o.mode ?? 'auto'
  const complete = data !== undefined && !following && !truncated && !stopped && (mode === 'auto' || !next)
  return {
    data,
    error,
    loading,
    reload,
    retry,
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
    moreRetry,
  }
}
