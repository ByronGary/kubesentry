import { describe, expect, it } from 'vitest'
import { followPages, isAbort, loadedText, pageURL, type Page, type PageFetcher } from './paging'

/** A fake paged server: `total` rows, `size` per page, tokens "p1", "p2", ... */
function server(total: number, size: number) {
  const calls: (string | undefined)[] = []
  const fetch: PageFetcher<number> = async (cont) => {
    calls.push(cont)
    const start = cont ? Number(cont.slice(1)) * size : 0
    const items = Array.from({ length: Math.max(0, Math.min(size, total - start)) }, (_, i) => start + i)
    const next = start + size < total ? `p${start / size + 1}` : undefined
    return { items, next }
  }
  return { fetch, calls }
}

describe('followPages', () => {
  it('follows continue until the server stops sending it', async () => {
    const s = server(2500, 1000)
    const progress: [number, number, boolean][] = []
    const r = await followPages(s.fetch, { onPage: (items, pages, more) => progress.push([items.length, pages, more]) })
    expect(r.items).toHaveLength(2500)
    expect(r.items[2499]).toBe(2499)
    expect(r.pages).toBe(3)
    expect(r.truncated).toBe(false)
    expect(s.calls).toEqual([undefined, 'p1', 'p2'])
    expect(progress).toEqual([
      [1000, 1, true],
      [2000, 2, true],
      [2500, 3, false],
    ])
  })

  it('works against a server that does not page (one response, no continue)', async () => {
    const s = server(12_000, 100_000)
    const r = await followPages(s.fetch)
    expect(r).toMatchObject({ pages: 1, truncated: false })
    expect(r.items).toHaveLength(12_000)
    expect(s.calls).toEqual([undefined])
  })

  it('stops at the cap and says where to resume', async () => {
    const s = server(50_000, 1000)
    const progress: boolean[] = []
    const r = await followPages(s.fetch, { cap: 20_000, onPage: (_, __, more) => progress.push(more) })
    expect(r.items).toHaveLength(20_000)
    expect(r.truncated).toBe(true)
    expect(r.next).toBe('p20')
    expect(s.calls).toHaveLength(20)
    // The last page reports no more, so the UI stops showing "Loaded N…".
    expect(progress.at(-1)).toBe(false)
  })

  it('does not call a cap reached on the very last page truncated', async () => {
    const r = await followPages(server(2000, 1000).fetch, { cap: 2000 })
    expect(r.truncated).toBe(false)
  })

  it('ends when the server repeats a token instead of looping forever', async () => {
    let n = 0
    const r = await followPages<number>(async () => ({ items: [n++], next: 'same' }))
    expect(r.items).toEqual([0, 1])
    expect(r.pages).toBe(2)
  })

  it('tolerates a page without items', async () => {
    const r = await followPages<number>(async (c) => (c ? { items: [1] } : ({ next: 'a' } as unknown as Page<number>)))
    expect(r.items).toEqual([1])
  })

  it('rejects with an AbortError when aborted between pages', async () => {
    const ctl = new AbortController()
    const s = server(5000, 1000)
    const p = followPages(s.fetch, {
      signal: ctl.signal,
      onPage: (_, pages) => {
        if (pages === 2) ctl.abort()
      },
    })
    await expect(p).rejects.toSatisfy(isAbort)
    expect(s.calls).toEqual([undefined, 'p1'])
  })

  it('rejects at once when the signal is already aborted', async () => {
    const ctl = new AbortController()
    ctl.abort()
    const s = server(10, 5)
    await expect(followPages(s.fetch, { signal: ctl.signal })).rejects.toSatisfy(isAbort)
    expect(s.calls).toEqual([])
  })

  it('discards a page that arrives after the abort', async () => {
    const ctl = new AbortController()
    const seen: number[] = []
    const p = followPages<number>(
      async () => {
        ctl.abort()
        return { items: [1], next: 'x' }
      },
      { signal: ctl.signal, onPage: (items) => seen.push(items.length) },
    )
    await expect(p).rejects.toSatisfy(isAbort)
    expect(seen).toEqual([])
  })
})

describe('pageURL', () => {
  it('adds limit and continue to a bare path', () => {
    expect(pageURL('/api/v1/pods', 1000, undefined)).toBe('/api/v1/pods?limit=1000')
    expect(pageURL('/api/v1/pods', 1000, 'abc/+=')).toBe('/api/v1/pods?limit=1000&continue=abc%2F%2B%3D')
  })
  it('keeps an existing query', () => {
    expect(pageURL('/api/v1/pods?namespace=shop', 500, 't')).toBe('/api/v1/pods?namespace=shop&limit=500&continue=t')
    expect(pageURL('/api/v1/audit/events?since=24h&continue=old', 200, undefined)).toBe('/api/v1/audit/events?since=24h&limit=200')
  })
})

describe('loadedText', () => {
  const noun: [string, string] = ['pod', 'pods']
  it('describes progress, truncation and the final count', () => {
    expect(loadedText(3000, noun, { following: true, truncated: false, complete: false })).toBe('Loaded 3,000 pods…')
    expect(loadedText(20000, noun, { following: false, truncated: true, complete: false })).toBe('Showing the first 20,000 pods; the rest were not loaded')
    expect(loadedText(1, noun, { following: false, truncated: false, complete: true })).toBe('1 pod')
    expect(loadedText(12345, noun, { following: false, truncated: false, complete: true })).toBe('12,345 pods')
  })
})
