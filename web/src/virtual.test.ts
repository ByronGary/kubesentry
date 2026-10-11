import { describe, expect, it } from 'vitest'
import { bodyHeight, compareNumber, compareStatus, compareText, nextSort, scrollToRow, sortRows, windowRange } from './virtual'

describe('windowRange', () => {
  const base = { viewport: 400, rowHeight: 40, count: 10_000, overscan: 5 }

  it('renders the visible rows plus overscan at the top', () => {
    const r = windowRange({ ...base, scrollTop: 0 })
    // 400 / 40 = 10 visible, +1 for a partly shown row, +5 below.
    expect(r).toEqual({ start: 0, end: 16, padTop: 0, padBottom: (10_000 - 16) * 40 })
  })

  it('keeps the spacers and rows summing to the full height anywhere in the list', () => {
    for (const scrollTop of [0, 1, 39, 40, 12_345, 200_000, 399_600]) {
      const r = windowRange({ ...base, scrollTop })
      expect(r.padTop + (r.end - r.start) * 40 + r.padBottom).toBe(bodyHeight(10_000, 40))
      // The first visible row is always rendered.
      const first = Math.floor(scrollTop / 40)
      expect(r.start).toBeLessThanOrEqual(first)
      expect(r.end).toBeGreaterThan(Math.min(first, 9_999))
    }
  })

  it('renders a bounded number of rows however long the list is', () => {
    const r = windowRange({ ...base, count: 1_000_000, scrollTop: 20_000_000 })
    expect(r.end - r.start).toBe(10 + 1 + 5 + 5)
  })

  it('accounts for the sticky header above the first row', () => {
    const r = windowRange({ ...base, scrollTop: 37 + 40 * 100, offset: 37, overscan: 0 })
    expect(r.start).toBe(100)
  })

  it('shows the last rows when scrolled past the end after the list shrank', () => {
    const r = windowRange({ ...base, count: 30, scrollTop: 300_000, overscan: 2 })
    expect(r.end).toBe(30)
    expect(r.start).toBe(30 - 11 - 2)
    expect(r.padBottom).toBe(0)
  })

  it('handles empty lists and bad input', () => {
    expect(windowRange({ ...base, count: 0, scrollTop: 0 })).toEqual({ start: 0, end: 0, padTop: 0, padBottom: 0 })
    expect(windowRange({ ...base, rowHeight: 0, scrollTop: 0 }).end).toBe(0)
    expect(windowRange({ ...base, count: 3, scrollTop: -50 })).toMatchObject({ start: 0, end: 3 })
  })
})

describe('scrollToRow', () => {
  const v = { scrollTop: 400, viewport: 200, rowHeight: 40 }
  it('scrolls up or down just enough, or not at all', () => {
    // In view: rows 10 to 14 (400 to 600 px).
    expect(scrollToRow(5, v)).toBe(200)
    expect(scrollToRow(15, v)).toBe(15 * 40 + 40 - 200)
    expect(scrollToRow(12, v)).toBeUndefined()
  })
})

describe('sorting', () => {
  const rows = [
    { n: 'pod-10', v: 3 },
    { n: 'pod-2', v: 1 },
    { n: 'Pod-1', v: 3 },
  ]
  it('sorts naturally and case-insensitively, keeping ties stable', () => {
    expect(sortRows(rows, (a, b) => compareText(a.n, b.n), 'asc').map((r) => r.n)).toEqual(['Pod-1', 'pod-2', 'pod-10'])
    expect(sortRows(rows, (a, b) => compareNumber(a.v, b.v), 'desc').map((r) => r.n)).toEqual(['pod-10', 'Pod-1', 'pod-2'])
  })
  it('returns the same array when unsorted and never mutates the input', () => {
    expect(sortRows(rows, undefined, 'asc')).toBe(rows)
    const copy = [...rows]
    sortRows(rows, (a, b) => compareText(a.n, b.n), 'asc')
    expect(rows).toEqual(copy)
  })
  it('orders statuses worst first and puts missing numbers last when ascending', () => {
    expect(['ok', 'crit', 'unknown', 'warn'].sort(compareStatus)).toEqual(['crit', 'warn', 'unknown', 'ok'])
    const vs = [{ v: 3 }, { v: undefined }, { v: 1 }]
    expect(vs.sort((a, b) => compareNumber(a.v, b.v)).map((x) => x.v)).toEqual([undefined, 1, 3])
  })
  it('cycles a header between directions', () => {
    expect(nextSort(undefined, 'name')).toEqual({ key: 'name', dir: 'asc' })
    expect(nextSort({ key: 'name', dir: 'asc' }, 'name')).toEqual({ key: 'name', dir: 'desc' })
    expect(nextSort({ key: 'name', dir: 'desc' }, 'restarts', 'desc')).toEqual({ key: 'restarts', dir: 'desc' })
  })
})
