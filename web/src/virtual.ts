// Window math and sorting for the virtualized table, kept free of React so it is testable.

export interface WindowInput {
  /** scrollTop of the scrolling container. */
  scrollTop: number
  /** clientHeight of the scrolling container. */
  viewport: number
  /** Every row is exactly this tall. */
  rowHeight: number
  count: number
  /** Extra rows rendered above and below the visible ones. */
  overscan?: number
  /** Space above the first row inside the container, e.g. the sticky header. */
  offset?: number
}

export interface WindowRange {
  /** First rendered row. */
  start: number
  /** One past the last rendered row. */
  end: number
  /** Height of the spacer above the rendered rows. */
  padTop: number
  /** Height of the spacer below them. */
  padBottom: number
}

export const DEFAULT_OVERSCAN = 8

/**
 * Which rows to render for a scroll position. A scrollTop past the end (the
 * rows just shrank and the browser has not clamped it yet) shows the last rows
 * instead of nothing.
 */
export function windowRange(i: WindowInput): WindowRange {
  const h = i.rowHeight
  const count = Math.max(0, Math.floor(i.count))
  if (count === 0 || !(h > 0)) return { start: 0, end: 0, padTop: 0, padBottom: 0 }
  const over = Math.max(0, i.overscan ?? DEFAULT_OVERSCAN)
  const visible = Math.max(1, Math.ceil(Math.max(0, i.viewport) / h) + 1)
  const top = Math.max(0, (i.scrollTop || 0) - (i.offset ?? 0))
  const first = Math.min(Math.floor(top / h), Math.max(0, count - visible))
  const start = Math.max(0, first - over)
  const end = Math.min(count, first + visible + over)
  return { start, end, padTop: start * h, padBottom: (count - end) * h }
}

/** Total scrollable height of the body. */
export function bodyHeight(count: number, rowHeight: number): number {
  return Math.max(0, count) * rowHeight
}

/** Scroll position that brings a row fully into view, or undefined when it already is. */
export function scrollToRow(row: number, i: Omit<WindowInput, 'count' | 'overscan'>): number | undefined {
  const off = i.offset ?? 0
  const top = off + row * i.rowHeight
  const bottom = top + i.rowHeight
  if (top - off < i.scrollTop) return Math.max(0, top - off)
  if (bottom > i.scrollTop + i.viewport) return bottom - i.viewport
  return undefined
}

export type SortDir = 'asc' | 'desc'

export interface SortState {
  key: string
  dir: SortDir
}

/** A new array sorted by `cmp` (stable, so equal rows keep the server's order); the same array when unsorted. */
export function sortRows<T>(rows: T[], cmp: ((a: T, b: T) => number) | undefined, dir: SortDir): T[] {
  if (!cmp) return rows
  const c = dir === 'asc' ? cmp : (a: T, b: T) => cmp(b, a)
  return [...rows].sort(c)
}

/** Clicking a header: a new column starts at its default direction, the same column flips. */
export function nextSort(current: SortState | undefined, key: string, firstDir: SortDir = 'asc'): SortState {
  if (!current || current.key !== key) return { key, dir: firstDir }
  return { key, dir: current.dir === 'asc' ? 'desc' : 'asc' }
}

const collator = new Intl.Collator('en', { numeric: true, sensitivity: 'base' })

/** Natural, case-insensitive text order: "pod-2" before "pod-10". */
export function compareText(a: string | undefined, b: string | undefined): number {
  return collator.compare(a ?? '', b ?? '')
}

export function compareNumber(a: number | undefined, b: number | undefined): number {
  const x = a ?? -Infinity
  const y = b ?? -Infinity
  return x === y ? 0 : x < y ? -1 : 1
}

const STATUS_RANK: Record<string, number> = { crit: 0, warn: 1, unknown: 2, info: 3, ok: 4 }

/** Worst first when ascending. */
export function compareStatus(a: string, b: string): number {
  return (STATUS_RANK[a] ?? 5) - (STATUS_RANK[b] ?? 5)
}
