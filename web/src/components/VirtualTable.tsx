import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { nextSort, sortRows, windowRange, type SortDir, type SortState } from '../virtual'

export interface Column<T> {
  key: string
  header: ReactNode
  /** Column width: pixels, or any CSS width such as '30%'. */
  width: number | string
  cell: (row: T) => ReactNode
  /** Makes the header a sort button. */
  sort?: (a: T, b: T) => number
  /** Direction of the first click; counts usually start high. */
  firstDir?: SortDir
  /** e.g. 'num' for right-aligned numbers. */
  className?: string
  /** Full text for a cell that may be cut short. */
  title?: (row: T) => string | undefined
}

export interface VirtualTableProps<T> {
  rows: T[]
  columns: Column<T>[]
  rowKey: (row: T) => string
  /** Accessible name of the table and its scroll region. */
  caption: string
  /** Every row is exactly this tall; cells clip their content to fit. */
  rowHeight?: number
  /** Wider than this, the table scrolls sideways inside its box (phones). */
  minWidth?: number
  initialSort?: SortState
  rowClass?: (row: T) => string | undefined
  /** Scrolls back to the top when it changes, e.g. the filter text. */
  resetKey?: string
}

const HEADER_GUESS = 37

/**
 * A table that renders only the rows in view, so ten thousand rows scroll as
 * smoothly as fifty. Rows have a fixed height; the header stays put; the box
 * scrolls with the wheel, touch and, once focused, the keyboard.
 */
export function VirtualTable<T>({ rows, columns, rowKey, caption, rowHeight = 40, minWidth = 720, initialSort, rowClass, resetKey }: VirtualTableProps<T>) {
  const box = useRef<HTMLDivElement>(null)
  const head = useRef<HTMLTableSectionElement>(null)
  const [scrollTop, setScrollTop] = useState(0)
  const [viewport, setViewport] = useState(600)
  const [headerH, setHeaderH] = useState(HEADER_GUESS)
  const [sort, setSort] = useState<SortState | undefined>(initialSort)
  const frame = useRef(0)

  const sorted = useMemo(() => {
    const col = sort ? columns.find((c) => c.key === sort.key) : undefined
    return sortRows(rows, col?.sort, sort?.dir ?? 'asc')
    // Columns are recreated on every render; only the rows and the sort key matter here.
  }, [rows, sort])

  useLayoutEffect(() => {
    const el = box.current
    if (!el) return
    const measure = () => {
      setViewport(el.clientHeight)
      if (head.current) setHeaderH(head.current.offsetHeight || HEADER_GUESS)
    }
    measure()
    if (typeof ResizeObserver === 'undefined') return
    const ro = new ResizeObserver(measure)
    ro.observe(el)
    return () => ro.disconnect()
  }, [])

  useEffect(() => () => cancelAnimationFrame(frame.current), [])

  useEffect(() => {
    if (box.current) box.current.scrollTop = 0
    setScrollTop(0)
  }, [resetKey])

  const onScroll = useCallback(() => {
    if (frame.current) return
    frame.current = requestAnimationFrame(() => {
      frame.current = 0
      if (box.current) setScrollTop(box.current.scrollTop)
    })
  }, [])

  const r = windowRange({ scrollTop, viewport, rowHeight, count: sorted.length, offset: headerH })
  const visible = sorted.slice(r.start, r.end)
  const height = headerH + sorted.length * rowHeight + 2

  return (
    <div
      className="vt"
      ref={box}
      onScroll={onScroll}
      tabIndex={0}
      role="region"
      aria-label={`${caption}, ${sorted.length.toLocaleString('en-US')} rows. Scroll to see more.`}
      style={{ height }}
    >
      <table className="vt-table" style={{ minWidth }} aria-rowcount={sorted.length + 1}>
        <caption className="sr-only">{caption}</caption>
        <colgroup>
          {columns.map((c) => (
            <col key={c.key} style={{ width: c.width }} />
          ))}
        </colgroup>
        <thead ref={head}>
          <tr aria-rowindex={1}>
            {columns.map((c) => {
              const on = sort?.key === c.key
              return (
                <th
                  key={c.key}
                  scope="col"
                  className={c.className}
                  aria-sort={on ? (sort!.dir === 'asc' ? 'ascending' : 'descending') : c.sort ? 'none' : undefined}
                >
                  {c.sort ? (
                    <button type="button" className="vt-sort" onClick={() => setSort((s) => nextSort(s, c.key, c.firstDir))}>
                      {c.header}
                      <span className="vt-arrow" aria-hidden="true">{on ? (sort!.dir === 'asc' ? '▲' : '▼') : '↕'}</span>
                    </button>
                  ) : (
                    c.header
                  )}
                </th>
              )
            })}
          </tr>
        </thead>
        <tbody>
          {r.padTop > 0 && (
            <tr className="vt-pad" aria-hidden="true">
              <td colSpan={columns.length} style={{ height: r.padTop }} />
            </tr>
          )}
          {visible.map((row, i) => {
            const cls = rowClass?.(row)
            return (
              <tr key={rowKey(row)} aria-rowindex={r.start + i + 2} className={cls} style={{ height: rowHeight }}>
                {columns.map((c) => (
                  <td key={c.key} className={c.className} title={c.title?.(row)} style={{ height: rowHeight }}>
                    {c.cell(row)}
                  </td>
                ))}
              </tr>
            )
          })}
          {r.padBottom > 0 && (
            <tr className="vt-pad" aria-hidden="true">
              <td colSpan={columns.length} style={{ height: r.padBottom }} />
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}

/** Two stacked lines in a fixed-height cell, each cut with an ellipsis. */
export function Lines({ main, sub }: { main: ReactNode; sub?: ReactNode }) {
  return (
    <>
      <div className="vt-line">{main}</div>
      {sub !== undefined && sub !== null && sub !== false && <div className="vt-line vt-sub">{sub}</div>}
    </>
  )
}
