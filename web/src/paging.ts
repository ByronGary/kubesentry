// Following `continue` tokens across pages, kept free of React so it is testable.
//
// List routes take `limit` (at most 1000) and an opaque `continue`, and answer
// with `continue` while there is more. A server that does not page simply
// leaves `continue` out, so one request gets everything, as before.

/** Rows asked for per request; the server's maximum. */
export const PAGE_LIMIT = 1000

/** Stop following pages after this many rows; past it the browser, not the server, is the bottleneck. */
export const ROW_CAP = 20_000

export interface Page<T> {
  items: T[]
  /** The token for the next page, when there is one. */
  next?: string
}

export type PageFetcher<T> = (cont: string | undefined, signal?: AbortSignal) => Promise<Page<T>>

export interface FollowOptions<T> {
  signal?: AbortSignal
  /** Stop requesting once this many rows are loaded (the page that crosses it is kept whole). */
  cap?: number
  /** Called after every page with all rows so far, and whether more pages follow. */
  onPage?: (items: T[], pages: number, more: boolean) => void
}

export interface FollowResult<T> {
  items: T[]
  pages: number
  /** The server had more, but the cap stopped the loop. */
  truncated: boolean
  /** Where the next page would start, when truncated. */
  next?: string
}

export function abortError(): Error {
  try {
    return new DOMException('The operation was aborted.', 'AbortError')
  } catch {
    const e = new Error('The operation was aborted.')
    e.name = 'AbortError'
    return e
  }
}

export function isAbort(e: unknown): boolean {
  return e instanceof Error && e.name === 'AbortError'
}

function check(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw abortError()
}

/**
 * Fetch the first page, then follow `next` until the server stops sending it,
 * the cap is reached, or the signal aborts (which rejects with an AbortError).
 * A token the server already sent ends the loop, so a buggy server cannot spin it.
 */
export async function followPages<T>(fetchPage: PageFetcher<T>, o: FollowOptions<T> = {}): Promise<FollowResult<T>> {
  const cap = o.cap ?? Infinity
  const seen = new Set<string>()
  let items: T[] = []
  let next: string | undefined
  let pages = 0
  for (;;) {
    check(o.signal)
    const page = await fetchPage(next, o.signal)
    check(o.signal)
    pages++
    items = items.concat(page.items ?? [])
    next = page.next || undefined
    if (next !== undefined) {
      if (seen.has(next)) next = undefined
      else seen.add(next)
    }
    const capped = next !== undefined && items.length >= cap
    o.onPage?.(items, pages, next !== undefined && !capped)
    if (next === undefined) return { items, pages, truncated: false }
    if (capped) return { items, pages, truncated: true, next }
  }
}

/** Add `limit` and `continue` to a path that may already carry a query string. */
export function pageURL(path: string, limit: number | undefined, cont: string | undefined): string {
  const i = path.indexOf('?')
  const base = i === -1 ? path : path.slice(0, i)
  const p = new URLSearchParams(i === -1 ? '' : path.slice(i + 1))
  if (limit !== undefined) p.set('limit', String(limit))
  if (cont) p.set('continue', cont)
  else p.delete('continue')
  const s = p.toString()
  return s ? `${base}?${s}` : base
}

/** "Loaded 3,000…" style progress for the status line. */
export function loadedText(n: number, noun: [string, string], state: { following: boolean; truncated: boolean; complete: boolean }): string {
  const count = n.toLocaleString('en-US')
  const word = n === 1 ? noun[0] : noun[1]
  if (state.following) return `Loaded ${count} ${word}…`
  if (state.truncated) return `Showing the first ${count} ${word}; the rest were not loaded`
  if (!state.complete) return `Loaded ${count} ${word}; stopped before the end`
  return `${count} ${word}`
}
