import type { Shape } from '../incidents'
import type { Status } from '../types'

/**
 * A signal's shape centred on (0, 0) with radius r, in currentColor: ✕ OOM,
 * ↻ restart, ◆ deploy, ▲ event and the rest. Drawn, not typed, so it looks
 * the same with any system font.
 */
export function ShapePath({ shape, r = 5 }: { shape: Shape; r?: number }) {
  const sw = Math.max(1.4, r * 0.38)
  switch (shape) {
    case 'x':
      return <path d={`M${-r * 0.8},${-r * 0.8}L${r * 0.8},${r * 0.8}M${r * 0.8},${-r * 0.8}L${-r * 0.8},${r * 0.8}`} fill="none" stroke="currentColor" strokeWidth={sw * 1.2} strokeLinecap="round" />
    case 'cycle': {
      const a = r * 0.82
      return (
        <g fill="none" stroke="currentColor" strokeWidth={sw} strokeLinecap="round" strokeLinejoin="round">
          <path d={`M${a},0A${a},${a} 0 1 1 ${a * 0.5},${-a * 0.87}`} />
          <path d={`M${a * 0.5 - r * 0.55},${-a * 0.87 - r * 0.25}L${a * 0.5},${-a * 0.87}L${a * 0.5 - r * 0.2},${-a * 0.87 + r * 0.55}`} />
        </g>
      )
    }
    case 'diamond':
      return <path d={`M0,${-r}L${r},0L0,${r}L${-r},0Z`} fill="currentColor" />
    case 'diamond-open':
      return <path d={`M0,${-r * 0.9}L${r * 0.9},0L0,${r * 0.9}L${-r * 0.9},0Z`} fill="var(--page)" stroke="currentColor" strokeWidth={sw} strokeLinejoin="round" />
    case 'triangle':
      return <path d={`M0,${-r}L${r},${r * 0.8}L${-r},${r * 0.8}Z`} fill="currentColor" strokeLinejoin="round" />
    case 'square':
      return <rect x={-r * 0.78} y={-r * 0.78} width={r * 1.56} height={r * 1.56} fill="currentColor" />
    case 'square-open':
      return <rect x={-r * 0.72} y={-r * 0.72} width={r * 1.44} height={r * 1.44} fill="var(--page)" stroke="currentColor" strokeWidth={sw} />
    case 'peak':
      return <path d={`M${-r * 0.9},${r * 0.55}L0,${-r * 0.6}L${r * 0.9},${r * 0.55}`} fill="none" stroke="currentColor" strokeWidth={sw * 1.2} strokeLinecap="round" strokeLinejoin="round" />
    default:
      return <circle r={r * 0.75} fill="currentColor" />
  }
}

/** The shape inline in text, tinted by severity when there is one. Decorative: the text beside it names the signal. */
export function SignalMark({ shape, severity, size = 12 }: { shape: Shape; severity?: Status; size?: number }) {
  return (
    <svg className={`sig-mark${severity ? ` sev-${severity}` : ''}`} viewBox="-7 -7 14 14" width={size} height={size} aria-hidden="true" focusable="false">
      <ShapePath shape={shape} r={5.5} />
    </svg>
  )
}
