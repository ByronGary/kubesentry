import { sparkline, sparkText } from '../chartMath'

/**
 * A small trend line, hand-drawn in SVG over chartMath.ts. Its text
 * alternative names the range and the newest value, e.g. "unhealthy
 * workloads, last 24h: min 0, max 4, now 2".
 */
export function Sparkline({ values, label, span, width = 120, height = 28 }: { values: number[]; label: string; span: string; width?: number; height?: number }) {
  const s = sparkline(values, width, height, 3)
  if (!s.line) return null
  const text = sparkText(label, values, span)
  return (
    <div className="spark">
      <svg viewBox={`0 0 ${width} ${height}`} width={width} height={height} role="img" aria-label={text}>
        <title>{text}</title>
        <path className="spark-area" d={s.area} />
        <path className="spark-line" d={s.line} />
        {s.end && <circle className="spark-end" cx={s.end[0]} cy={s.end[1]} r="2.5" />}
      </svg>
      {span && (
        <span className="spark-cap" aria-hidden="true">
          {span}
        </span>
      )}
    </div>
  )
}
