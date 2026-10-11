import { useEffect, useMemo, useRef, useState, type KeyboardEvent, type PointerEvent } from 'react'
import { byteTicks, findDrops, nearestIndex, projectToLimit, thin, timeTicks, type Point } from '../chartMath'
import { formatBytes, formatClock, formatDateTime } from '../format'
import type { ContainerDiag } from '../types'

const H = 224
const M = { top: 14, right: 84, bottom: 26, left: 62 }

export function MemoryChart({ container }: { container: ContainerDiag }) {
  const series = container.series as Point[]
  const wrap = useRef<HTMLDivElement>(null)
  const [w, setW] = useState(640)
  const [hover, setHover] = useState<number | null>(null)
  const [table, setTable] = useState(false)

  useEffect(() => {
    const el = wrap.current
    if (!el) return
    const ro = new ResizeObserver(([e]) => setW(Math.max(280, Math.floor(e.contentRect.width))))
    ro.observe(el)
    return () => ro.disconnect()
  }, [])

  const geo = useMemo(() => {
    if (series.length < 2) return null
    const t0 = series[0][0]
    const tLast = series[series.length - 1][0]
    const last = series[series.length - 1]
    const slope = container.leak?.slopeBytesPerHour ?? 0
    const proj = projectToLimit(last, slope, container.limitBytes, (tLast - t0) * 0.3)
    const t1 = proj ? proj.to[0] : tLast
    const maxSeries = Math.max(...series.map((p) => p[1]))
    const yMax = Math.max(maxSeries, container.limitBytes ?? 0, proj?.to[1] ?? 0) * 1.06
    const ticks = byteTicks(yMax, 4)
    const yTop = Math.max(yMax, ticks[ticks.length - 1])
    return { t0, t1, tLast, last, proj, yTop, yTicks: ticks, xTicks: timeTicks(t0, t1, Math.max(3, Math.floor(w / 110))), drops: findDrops(series) }
  }, [series, container.limitBytes, container.leak, w])

  if (!geo) {
    return <p className="muted">Not enough memory samples in this window to draw a trend.</p>
  }

  const iw = w - M.left - M.right
  const ih = H - M.top - M.bottom
  const x = (t: number) => M.left + ((t - geo.t0) / (geo.t1 - geo.t0)) * iw
  const y = (v: number) => M.top + ih - (v / geo.yTop) * ih
  const line = series.map((p, i) => `${i ? 'L' : 'M'}${x(p[0]).toFixed(1)},${y(p[1]).toFixed(1)}`).join('')
  const area = `${line}L${x(geo.tLast).toFixed(1)},${y(0)}L${x(geo.t0).toFixed(1)},${y(0)}Z`
  const end = series[series.length - 1]
  const hp = hover !== null ? series[hover] : null
  const limitY = container.limitBytes ? y(container.limitBytes) : null

  const at = (e: PointerEvent<SVGSVGElement>) => {
    const r = e.currentTarget.getBoundingClientRect()
    const px = ((e.clientX - r.left) / r.width) * w
    if (px < M.left || px > x(geo.tLast) + 4) return setHover(null)
    setHover(nearestIndex(series, geo.t0 + ((px - M.left) / iw) * (geo.t1 - geo.t0)))
  }
  const key = (e: KeyboardEvent) => {
    const cur = hover ?? series.length - 1
    if (e.key === 'ArrowLeft') setHover(Math.max(0, cur - 1))
    else if (e.key === 'ArrowRight') setHover(Math.min(series.length - 1, cur + 1))
    else if (e.key === 'Escape') setHover(null)
    else return
    e.preventDefault()
  }

  const summary = `Working-set memory for ${container.name}, now ${formatBytes(end[1])}${
    container.limitBytes ? ` of a ${formatBytes(container.limitBytes)} limit` : ', no limit set'
  }.`

  return (
    <div className="chart" ref={wrap}>
      <div className="chart-bar">
        <span className="chart-title">Working-set memory</span>
        <button type="button" className="linklike" onClick={() => setTable((t) => !t)} aria-pressed={table}>
          {table ? 'Show chart' : 'Show data'}
        </button>
      </div>
      {table ? (
        <div className="table-wrap chart-table" tabIndex={0}>
          <table>
            <caption className="sr-only">{summary}</caption>
            <thead>
              <tr><th>Time</th><th className="num">Memory</th></tr>
            </thead>
            <tbody>
              {thin(series, 48).map((p) => (
                <tr key={p[0]}><td>{formatDateTime(p[0])}</td><td className="num">{formatBytes(p[1])}</td></tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="chart-plot">
          <svg
            viewBox={`0 0 ${w} ${H}`}
            width={w}
            height={H}
            role="img"
            aria-label={summary}
            tabIndex={0}
            onPointerMove={at}
            onPointerLeave={() => setHover(null)}
            onKeyDown={key}
          >
            {geo.yTicks.map((v) => (
              <g key={v}>
                <line className="grid" x1={M.left} x2={w - M.right} y1={y(v)} y2={y(v)} />
                <text className="axis" x={M.left - 8} y={y(v)} textAnchor="end" dominantBaseline="middle">{v === 0 ? '0' : formatBytes(v)}</text>
              </g>
            ))}
            {geo.xTicks.map((t) => (
              <text key={t} className="axis" x={x(t)} y={H - 7} textAnchor="middle">{formatClock(t)}</text>
            ))}
            <path className="area" d={area} />
            {geo.drops.map((i) => (
              <line key={i} className="restart" x1={x(series[i][0])} x2={x(series[i][0])} y1={M.top} y2={y(0)}>
                <title>Memory dropped here, likely a restart</title>
              </line>
            ))}
            {limitY !== null && (
              <g>
                <line className="limit" x1={M.left} x2={w - M.right} y1={limitY} y2={limitY} />
                <text className="limit-label" x={w - M.right + 6} y={limitY} dominantBaseline="middle">
                  {formatBytes(container.limitBytes!)} limit
                </text>
              </g>
            )}
            <path className="trace" d={line} />
            {geo.proj && (
              <g>
                <line className="projection" x1={x(geo.proj.from[0])} y1={y(geo.proj.from[1])} x2={x(geo.proj.to[0])} y2={y(geo.proj.to[1])} />
                {!geo.proj.clipped && (
                  <g>
                    <circle className="proj-end" cx={x(geo.proj.to[0])} cy={y(geo.proj.to[1])} r="4" />
                    <text className="axis" x={x(geo.proj.to[0])} y={y(geo.proj.to[1]) + 16} textAnchor="end">
                      full about {formatClock(geo.proj.to[0])}
                    </text>
                  </g>
                )}
              </g>
            )}
            <circle className="end-dot" cx={x(end[0])} cy={y(end[1])} r="4" />
            {hp && (
              <g>
                <line className="cross" x1={x(hp[0])} x2={x(hp[0])} y1={M.top} y2={y(0)} />
                <circle className="end-dot" cx={x(hp[0])} cy={y(hp[1])} r="4" />
              </g>
            )}
          </svg>
          {hp && (
            <div
              className="tip"
              style={{ left: Math.min(Math.max(x(hp[0]), 70), w - 70), top: Math.max(y(hp[1]) - 52, 0) }}
              role="status"
            >
              <strong>{formatBytes(hp[1])}</strong>
              <span>{formatDateTime(hp[0])}</span>
            </div>
          )}
        </div>
      )}
      {container.leak && (
        <p className="chart-note">
          Growing {formatBytes(container.leak.slopeBytesPerHour)} an hour (fit R² {container.leak.r2.toFixed(2)}).
          {geo.proj ? ' The dashed line shows where that trend meets the limit.' : ''}
          {geo.drops.length > 0 ? ' Grey verticals mark drops, usually restarts.' : ''}
        </p>
      )}
    </div>
  )
}
