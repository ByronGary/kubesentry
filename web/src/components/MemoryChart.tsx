import { useMemo } from 'react'
import { byteTicks, findDrops, projectToLimit, type Point } from '../chartMath'
import { formatBytes, formatClock } from '../format'
import type { ChartLine } from '../incidents'
import type { ContainerDiag } from '../types'
import { TimeChart } from './TimeChart'

/** The pod page's geometry, unchanged since before TimeChart. */
const MARGIN = { top: 14, right: 84, bottom: 26, left: 62 }
const byteAxis = (m: number) => byteTicks(m, 4)

/**
 * One container's working-set memory on the pod page: the trend, its limit,
 * where memory dropped (usually a restart) and, for a leak, where the trend
 * meets the limit. A thin wrapper around TimeChart.
 */
export function MemoryChart({ container }: { container: ContainerDiag }) {
  const series = container.series as Point[]
  const geo = useMemo(() => {
    if (series.length < 2) return null
    const t0 = series[0][0]
    const tLast = series[series.length - 1][0]
    const last = series[series.length - 1]
    const slope = container.leak?.slopeBytesPerHour ?? 0
    const proj = projectToLimit(last, slope, container.limitBytes, (tLast - t0) * 0.3)
    const t1 = proj ? proj.to[0] : tLast
    return { domain: [t0, t1] as [number, number], proj, drops: findDrops(series) }
  }, [series, container.limitBytes, container.leak])
  const lines = useMemo<ChartLine[]>(() => [{ key: 'memory', label: container.name, points: series, slot: 1 }], [series, container.name])

  if (!geo) {
    return <p className="muted">Not enough memory samples in this window to draw a trend.</p>
  }
  const end = series[series.length - 1]
  const summary = `Working-set memory for ${container.name}, now ${formatBytes(end[1])}${
    container.limitBytes ? ` of a ${formatBytes(container.limitBytes)} limit` : ', no limit set'
  }.`
  const { proj } = geo

  return (
    <TimeChart
      title="Working-set memory"
      summary={summary}
      domain={geo.domain}
      lines={lines}
      format={formatBytes}
      ticks={byteAxis}
      height={224}
      margin={MARGIN}
      area
      endDot
      valueLabel="Memory"
      fit={proj ? [proj.to[1]] : undefined}
      thresholds={container.limitBytes ? [{ label: 'limit', value: container.limitBytes }] : undefined}
      guides={geo.drops.map((i) => ({ t: series[i][0], label: 'Memory dropped here, likely a restart' }))}
      overlay={
        proj
          ? (s) => (
              <g>
                <line className="projection" x1={s.x(proj.from[0])} y1={s.y(proj.from[1])} x2={s.x(proj.to[0])} y2={s.y(proj.to[1])} />
                {!proj.clipped && (
                  <g>
                    <circle className="proj-end" cx={s.x(proj.to[0])} cy={s.y(proj.to[1])} r="4" />
                    <text className="axis" x={s.x(proj.to[0])} y={s.y(proj.to[1]) + 16} textAnchor="end">
                      full about {formatClock(proj.to[0])}
                    </text>
                  </g>
                )}
              </g>
            )
          : undefined
      }
      note={
        container.leak && (
          <>
            Growing {formatBytes(container.leak.slopeBytesPerHour)} an hour (fit R² {container.leak.r2.toFixed(2)}).
            {proj ? ' The dashed line shows where that trend meets the limit.' : ''}
            {geo.drops.length > 0 ? ' Grey verticals mark drops, usually restarts.' : ''}
          </>
        )
      }
    />
  )
}
