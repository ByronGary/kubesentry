import { useId, type ReactNode } from 'react'
import { xOf, type Range } from '../chartMath'
import { axisFor } from './TimeChart'
import { TIME_KEYS_HINT, useTimeInteraction } from './useTimeInteraction'

export interface StripScale {
  x: (t: number) => number
  left: number
  right: number
  height: number
}

/**
 * A short band on the shared time axis (an event lane, the log volume): same
 * margins as the charts so times line up, the same crosshair and the same
 * brush. `children` draws the content with the strip's x scale.
 */
export function TimeStrip({
  width,
  height = 24,
  domain,
  label,
  keys,
  hoverT,
  onHover,
  brush,
  onBrush,
  children,
}: {
  width: number
  height?: number
  domain: Range
  /** The text alternative. */
  label: string
  /** Times the arrow keys step through. */
  keys: readonly number[]
  hoverT: number | null
  onHover: (t: number | null) => void
  brush?: Range | null
  onBrush?: (r: Range | null) => void
  children: (s: StripScale) => ReactNode
}) {
  const m = axisFor(width)
  const iw = Math.max(1, width - m.left - m.right)
  const x = (t: number) => xOf(t, domain, m.left, iw)
  const ia = useTimeInteraction({ domain, left: m.left, width: iw, svgWidth: width, keys, hoverT, onHover, brush, onBrush })
  const shown = ia.pending ?? brush ?? null
  const hint = `strip-${useId().replace(/[^a-zA-Z0-9_-]/g, '')}`
  const hovering = hoverT !== null && hoverT >= domain[0] && hoverT <= domain[1]
  return (
    <div className="tstrip">
      <svg
        viewBox={`0 0 ${width} ${height}`}
        width={width}
        height={height}
        role="img"
        aria-label={label}
        aria-describedby={hint}
        tabIndex={0}
        className={onBrush ? 'brushable' : undefined}
        {...ia.handlers}
      >
        <line className="strip-axis" x1={m.left} x2={width - m.right} y1={height - 0.5} y2={height - 0.5} />
        {shown && (
          <g className={ia.pending ? 'brush pending' : 'brush'}>
            <rect x={x(shown[0])} y={0} width={Math.max(1, x(shown[1]) - x(shown[0]))} height={height} />
            <line x1={x(shown[0])} x2={x(shown[0])} y1={0} y2={height} />
            <line x1={x(shown[1])} x2={x(shown[1])} y1={0} y2={height} />
          </g>
        )}
        {children({ x, left: m.left, right: width - m.right, height })}
        {hovering && <line className="cross" x1={x(hoverT)} x2={x(hoverT)} y1={0} y2={height} />}
      </svg>
      <span id={hint} className="sr-only">
        {TIME_KEYS_HINT}
      </span>
    </div>
  )
}
