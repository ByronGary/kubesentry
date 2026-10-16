import { useEffect, useId, useMemo, useRef, useState, type ReactNode } from 'react'
import { linePath, medianStep, plotGeometry, rateTicks, spreadLabels, stackMarkers, thin, valueAt, type Margin, type MarkerIn, type PlotGeometry, type Point, type Range } from '../chartMath'
import { formatClock, formatDateTime, truncateMiddle } from '../format'
import type { ChartLine, MarkKind, Shape, SpikeSpan } from '../incidents'
import { ShapePath } from './SignalMark'
import { TIME_KEYS_HINT, useTimeInteraction } from './useTimeInteraction'

/** Margins shared by every chart, lane and strip on the incident page, so a time sits at the same x in each. */
export function axisFor(width: number): Margin {
  return { top: 14, right: width < 520 ? 14 : 136, bottom: 26, left: 62 }
}

/** Measures a box's width, for charts that fill it. */
export function useWidth(initial = 640, min = 280) {
  const ref = useRef<HTMLDivElement>(null)
  const [w, setW] = useState(initial)
  useEffect(() => {
    const el = ref.current
    if (!el || typeof ResizeObserver === 'undefined') return
    const ro = new ResizeObserver(([e]) => setW(Math.max(min, Math.floor(e.contentRect.width))))
    ro.observe(el)
    return () => ro.disconnect()
  }, [min])
  return [ref, w] as const
}

/** The hover state, held by the chart unless the page lifts it to sync several. */
export function useHover(hoverT: number | null | undefined, onHover: ((t: number | null) => void) | undefined) {
  const [own, setOwn] = useState<number | null>(null)
  return onHover ? ([hoverT ?? null, onHover] as const) : ([own, setOwn] as const)
}

const DASH: Record<1 | 2 | 3, string | undefined> = { 1: undefined, 2: '7 4', 3: '2 3' }
const MARK_SHAPE: Record<MarkKind, Shape> = { oom: 'x', restart: 'cycle', deploy: 'diamond', event: 'triangle' }
const MARK_WORD: Record<MarkKind, [string, string]> = { oom: ['OOM kill', 'OOM kills'], restart: ['restart', 'restarts'], deploy: ['deploy or scale', 'deploys and scaling'], event: ['event', 'events'] }
const ROW_H = 13

export interface ChartScales extends PlotGeometry {
  margin: Margin
  width: number
  height: number
}

export interface TimeChartProps {
  title: string
  /** The text alternative: what the chart shows. */
  summary: string
  /** The x domain, shared with the other charts on the page. */
  domain: Range
  lines: ChartLine[]
  format: (v: number) => string
  ticks?: (max: number) => number[]
  thresholds?: { label: string; value: number; title?: string }[]
  markers?: MarkerIn<MarkKind>[]
  spans?: SpikeSpan[]
  /** Grey verticals with a tooltip, e.g. where memory dropped. */
  guides?: { t: number; label: string }[]
  /** Lifted hover time, so several charts share one crosshair. */
  hoverT?: number | null
  onHover?: (t: number | null) => void
  /** The committed brush; without onBrush there is no brushing. */
  brush?: Range | null
  onBrush?: (r: Range | null) => void
  height?: number
  margin?: Margin
  /** Fill under a single line (the memory chart). */
  area?: boolean
  /** A dot on the newest sample of each line. */
  endDot?: boolean
  /** More values the y scale must fit, e.g. where a projection ends. */
  fit?: number[]
  /** Extra SVG drawn above the lines, given the scales. */
  overlay?: (s: ChartScales) => ReactNode
  note?: ReactNode
  /** The column heading for a single line in the data table. */
  valueLabel?: string
  /** Break lines where samples are missing (more than twice the usual step apart). */
  breakGaps?: boolean
}

/**
 * A time chart drawn by hand in SVG: lines on an x domain shared with the
 * other charts on the page, thresholds, stacked event markers, spike bands,
 * a crosshair synced through `hoverT`, keyboard steps, a brush, and a data
 * table instead of the picture on request.
 */
export function TimeChart(p: TimeChartProps) {
  const [wrap, w] = useWidth()
  const [table, setTable] = useState(false)
  const [hoverT, setHover] = useHover(p.hoverT, p.onHover)
  const clip = `clip-${useId().replace(/[^a-zA-Z0-9_-]/g, '')}`
  const H = p.height ?? 200
  const base = p.margin ?? axisFor(w)
  const lines = useMemo(() => p.lines.filter((l) => l.points.length > 0), [p.lines])
  const multi = lines.length > 1
  const ticks = p.ticks ?? ((m: number) => rateTicks(m))

  const values = useMemo(() => {
    const v: number[] = []
    for (const l of lines) for (const pt of l.points) if (pt[0] >= p.domain[0] && pt[0] <= p.domain[1]) v.push(pt[1])
    for (const t of p.thresholds ?? []) v.push(t.value)
    for (const f of p.fit ?? []) v.push(f)
    return v
  }, [lines, p.thresholds, p.fit, p.domain])

  // Markers stack in rows above the plot; the top margin grows to hold them.
  const pre = plotGeometry({ width: w, height: H, margin: base, domain: p.domain, values, ticks })
  const stacks = stackMarkers(p.markers ?? [], pre.x, 13, 3)
  const rows = stacks.length ? Math.max(...stacks.map((s) => s.row)) + 1 : 0
  const m: Margin = { ...base, top: base.top + rows * ROW_H }
  const g = plotGeometry({ width: w, height: H + rows * ROW_H, margin: m, domain: p.domain, values, ticks })
  const height = H + rows * ROW_H
  const scales: ChartScales = { ...g, margin: m, width: w, height }
  const bottom = m.top + g.ih
  const right = w - m.right

  const keys = useMemo(() => {
    const longest = lines.reduce<Point[]>((a, l) => (l.points.length > a.length ? l.points : a), [])
    return longest.map((pt) => pt[0]).filter((t) => t >= p.domain[0] && t <= p.domain[1])
  }, [lines, p.domain])
  const step = useMemo(() => medianStep(lines[0]?.points ?? []) ?? (p.domain[1] - p.domain[0]) / 60, [lines, p.domain])

  const ia = useTimeInteraction({
    domain: p.domain,
    left: m.left,
    width: g.iw,
    svgWidth: w,
    keys,
    hoverT,
    onHover: setHover,
    brush: p.brush,
    onBrush: p.onBrush,
    snap: true,
  })

  const hintId = `${clip}-hint`
  const inDomain = (t: number | null | undefined): t is number => typeof t === 'number' && t >= p.domain[0] && t <= p.domain[1]
  const hovering = inDomain(hoverT)
  const tolerance = step * 0.75
  const at = hovering
    ? lines
        .map((l) => ({ l, v: valueAt(l.points, hoverT, tolerance) }))
        .filter((x): x is { l: ChartLine; v: number } => x.v !== undefined)
        .sort((a, b) => b.v - a.v)
    : []

  // End labels beside the coloured lines and the threshold labels share the right margin, kept apart;
  // on a phone the legend above names the lines.
  const labelled = multi ? lines.filter((l) => l.slot > 0) : []
  const thresholds = p.thresholds ?? []
  const marginYs = spreadLabels(
    [...thresholds.map((t) => g.y(t.value)), ...labelled.map((l) => g.y(l.points[l.points.length - 1][1]))],
    13,
    Math.max(6, m.top - 6),
    bottom,
  )
  const thresholdYs = marginYs.slice(0, thresholds.length)
  const endYs = marginYs.slice(thresholds.length)
  const showEndLabels = m.right >= 80
  const restCount = lines.filter((l) => l.slot === 0).length
  const brushShown = ia.pending ?? p.brush ?? null
  const breakAfter = p.breakGaps ? step * 2.5 : Infinity

  const legend = multi && (
    <ul className="chart-legend" aria-label="Lines">
      {labelled.map((l) => (
        <li key={l.key}>
          <svg width="22" height="8" aria-hidden="true">
            <line className={`s-line s${l.slot}`} x1="1" x2="21" y1="4" y2="4" strokeDasharray={DASH[l.slot as 1 | 2 | 3]} />
          </svg>
          <span className="id">{l.label}</span>
        </li>
      ))}
      {restCount > 0 && (
        <li>
          <svg width="22" height="8" aria-hidden="true">
            <line className="s-line s0" x1="1" x2="21" y1="4" y2="4" />
          </svg>
          <span>{restCount === 1 && lines.find((l) => l.slot === 0)?.label === 'others' ? 'others (summed)' : `${restCount} more, in grey`}</span>
        </li>
      )}
    </ul>
  )

  return (
    <div className="chart" ref={wrap}>
      <div className="chart-bar">
        <span className="chart-title">{p.title}</span>
        <button type="button" className="linklike" onClick={() => setTable((t) => !t)} aria-pressed={table}>
          {table ? 'Show chart' : 'Show data'}
        </button>
      </div>
      {legend}
      {table ? (
        <DataTable lines={lines} format={p.format} summary={p.summary} valueLabel={p.valueLabel} tolerance={tolerance} />
      ) : (
        <div className="chart-plot">
          <svg
            viewBox={`0 0 ${w} ${height}`}
            width={w}
            height={height}
            role="img"
            aria-label={p.summary}
            aria-describedby={hintId}
            tabIndex={0}
            className={p.onBrush ? 'brushable' : undefined}
            {...ia.handlers}
          >
            <defs>
              <clipPath id={clip}>
                <rect x={m.left} y={m.top - 2} width={g.iw} height={g.ih + 4} />
              </clipPath>
            </defs>
            {g.yTicks.map((v) => (
              <g key={v}>
                <line className="grid" x1={m.left} x2={right} y1={g.y(v)} y2={g.y(v)} />
                <text className="axis" x={m.left - 8} y={g.y(v)} textAnchor="end" dominantBaseline="middle">
                  {v === 0 ? '0' : p.format(v)}
                </text>
              </g>
            ))}
            {g.xTicks.map((t) => (
              <text key={t} className="axis" x={g.x(t)} y={height - 7} textAnchor="middle">
                {formatClock(t)}
              </text>
            ))}
            {(p.spans ?? []).map((s, i) => (
              <rect key={i} className={`spike-span sev-${s.severity}`} x={g.x(Math.max(s.from, p.domain[0]))} y={m.top} width={Math.max(2, g.x(Math.min(s.to, p.domain[1])) - g.x(Math.max(s.from, p.domain[0])))} height={g.ih}>
                <title>{s.label}</title>
              </rect>
            ))}
            {brushShown && (
              <g className={ia.pending ? 'brush pending' : 'brush'}>
                <rect x={g.x(brushShown[0])} y={m.top} width={Math.max(1, g.x(brushShown[1]) - g.x(brushShown[0]))} height={g.ih} />
                <line x1={g.x(brushShown[0])} x2={g.x(brushShown[0])} y1={m.top} y2={bottom} />
                <line x1={g.x(brushShown[1])} x2={g.x(brushShown[1])} y1={m.top} y2={bottom} />
              </g>
            )}
            {(p.guides ?? []).map((gd, i) => (
              <line key={i} className="restart" x1={g.x(gd.t)} x2={g.x(gd.t)} y1={m.top} y2={bottom}>
                <title>{gd.label}</title>
              </line>
            ))}
            {p.area && lines.length === 1 && lines[0].points.length > 1 && (
              <path
                className="area"
                clipPath={`url(#${clip})`}
                d={`${linePath(lines[0].points, g.x, g.y)}L${g.x(lines[0].points[lines[0].points.length - 1][0]).toFixed(1)},${g.y(0)}L${g.x(lines[0].points[0][0]).toFixed(1)},${g.y(0)}Z`}
              />
            )}
            {thresholds.map((t, i) => (
              <g key={`${t.label}:${t.value}`}>
                <line className="limit" x1={m.left} x2={right} y1={g.y(t.value)} y2={g.y(t.value)}>
                  <title>{t.title ?? `${p.format(t.value)} ${t.label}`}</title>
                </line>
                {showEndLabels ? (
                  <text className="limit-label" x={right + 6} y={thresholdYs[i]} dominantBaseline="middle">
                    {truncateMiddle(`${p.format(t.value)} ${t.label}`, 18)}
                  </text>
                ) : (
                  <text className="limit-label" x={right - 4} y={g.y(t.value) - 5} textAnchor="end">
                    {p.format(t.value)} {t.label}
                  </text>
                )}
              </g>
            ))}
            {/* Grey context lines first, so the named ones draw over them. */}
            {[...lines].sort((a, b) => Number(a.slot > 0) - Number(b.slot > 0)).map((l) => (
              <path
                key={l.key}
                clipPath={`url(#${clip})`}
                className={!multi ? 'trace' : `s-line s${l.slot}`}
                strokeDasharray={multi && l.slot > 0 ? DASH[l.slot as 1 | 2 | 3] : undefined}
                d={linePath(l.points, g.x, g.y, breakAfter)}
              >
                <title>{l.label}</title>
              </path>
            ))}
            {p.overlay?.(scales)}
            {p.endDot &&
              lines.map((l) => {
                const e = l.points[l.points.length - 1]
                return inDomain(e[0]) ? <circle key={l.key} className="end-dot" cx={g.x(e[0])} cy={g.y(e[1])} r="4" /> : null
              })}
            {multi &&
              showEndLabels &&
              labelled.map((l, i) => (
                <text key={l.key} className="end-label" x={right + 6} y={endYs[i]} dominantBaseline="middle">
                  <title>{l.label}</title>
                  {truncateMiddle(l.label, 17)}
                </text>
              ))}
            {stacks.map((s, i) => (
              <g key={i} className={`mk mk-${s.kind}`} transform={`translate(${s.px.toFixed(1)},${m.top - 8 - s.row * ROW_H})`}>
                <line className="mk-rule" x1="0" x2="0" y1={6} y2={g.ih + 8 + s.row * ROW_H} />
                <ShapePath shape={MARK_SHAPE[s.kind]} r={4.5} />
                {s.items.length > 1 && (
                  <text className="mk-count" x="7" y="3.5">
                    {s.items.length}
                  </text>
                )}
                <title>{markTitle(s.items)}</title>
              </g>
            ))}
            {hovering && (
              <g>
                <line className="cross" x1={g.x(hoverT)} x2={g.x(hoverT)} y1={m.top} y2={bottom} />
                {at.map(({ l, v }) => (
                  <circle key={l.key} className="end-dot" cx={g.x(hoverT)} cy={g.y(v)} r="3.5" />
                ))}
              </g>
            )}
          </svg>
          <span id={hintId} className="sr-only">
            {TIME_KEYS_HINT}
          </span>
          {hovering && (
            <div
              className="tip"
              style={{ left: Math.min(Math.max(g.x(hoverT), 80), w - 80), top: !multi && at.length === 1 ? Math.max(g.y(at[0].v) - 52, 0) : 0 }}
              role="status"
            >
              {at.length === 0 ? (
                <span>{formatDateTime(hoverT)}</span>
              ) : at.length === 1 && !multi ? (
                <>
                  <strong>{p.format(at[0].v)}</strong>
                  <span>{formatDateTime(hoverT)}</span>
                </>
              ) : (
                <>
                  <span>{formatDateTime(hoverT)}</span>
                  {at.slice(0, 5).map(({ l, v }) => (
                    <span key={l.key} className="tip-row">
                      <span className="id">{truncateMiddle(l.label, 22)}</span> <strong>{p.format(v)}</strong>
                    </span>
                  ))}
                  {at.length > 5 && <span>and {at.length - 5} more</span>}
                </>
              )}
            </div>
          )}
        </div>
      )}
      {p.note && <p className="chart-note">{p.note}</p>}
    </div>
  )
}

function markTitle(items: MarkerIn<MarkKind>[]): string {
  if (items.length === 1) return `${formatClock(items[0].t)} ${items[0].label}`
  const kinds = [...new Set(items.map((i) => i.kind))]
  const head = kinds.length === 1 ? `${items.length} ${MARK_WORD[kinds[0]][1]}` : `${items.length} events`
  const lines = items.slice(0, 6).map((i) => `${formatClock(i.t)} ${i.label}`)
  return [head, ...lines, items.length > 6 ? `and ${items.length - 6} more` : ''].filter(Boolean).join('\n')
}

function DataTable({ lines, format, summary, valueLabel, tolerance }: { lines: ChartLine[]; format: (v: number) => string; summary: string; valueLabel?: string; tolerance: number }) {
  const longest = lines.reduce<Point[]>((a, l) => (l.points.length > a.length ? l.points : a), [])
  const rows = thin(longest, 48)
  return (
    <div className="table-wrap chart-table" tabIndex={0}>
      <table>
        <caption className="sr-only">{summary}</caption>
        <thead>
          <tr>
            <th>Time</th>
            {lines.length === 1 ? (
              <th className="num">{valueLabel ?? lines[0].label}</th>
            ) : (
              lines.map((l) => (
                <th key={l.key} className="num id">
                  {l.label}
                </th>
              ))
            )}
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r[0]}>
              <td>{formatDateTime(r[0])}</td>
              {lines.map((l) => {
                const v = valueAt(l.points, r[0], tolerance)
                return (
                  <td key={l.key} className="num">
                    {v === undefined ? '-' : format(v)}
                  </td>
                )
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
