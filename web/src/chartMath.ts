// Pure helpers for the memory chart, kept free of React so they are testable.

export type Point = [number, number] // [unix ms, bytes]

/** Round tick values for an axis from 0 to max. Always includes 0. */
export function niceTicks(max: number, target = 4): number[] {
  if (!(max > 0)) return [0]
  const rough = max / target
  const pow = Math.pow(10, Math.floor(Math.log10(rough)))
  const frac = rough / pow
  const step = (frac <= 1 ? 1 : frac <= 2 ? 2 : frac <= 5 ? 5 : 10) * pow
  const ticks: number[] = []
  for (let v = 0; v <= max + step * 1e-9; v += step) ticks.push(v)
  return ticks
}

/** Binary-power ticks (MiB/GiB boundaries) for byte axes: 128, 256, 512 MiB, 1 GiB... */
export function byteTicks(max: number, target = 4): number[] {
  if (!(max > 0)) return [0]
  const unit = max >= 1 << 30 ? 1 << 30 : max >= 1 << 20 ? 1 << 20 : 1 << 10
  return niceTicks(max / unit, target).map((t) => t * unit)
}

/** Evenly spaced time ticks snapped to "round" intervals. */
export function timeTicks(start: number, end: number, target = 5): number[] {
  const span = end - start
  if (!(span > 0)) return [start]
  const minute = 60_000
  const steps = [1, 2, 5, 10, 15, 30, 60, 120, 180, 360, 720, 1440, 2880].map((m) => m * minute)
  const step = steps.find((s) => span / s <= target) ?? steps[steps.length - 1]
  // Snap to local-time boundaries so ticks read as 12:00, 12:30...
  const offset = new Date(start).getTimezoneOffset() * minute
  const first = Math.ceil((start - offset) / step) * step + offset
  const out: number[] = []
  for (let t = first; t <= end; t += step) out.push(t)
  return out
}

/** Index of the sample closest in time to t. Samples must be sorted by time. */
export function nearestIndex(series: Point[], t: number): number {
  if (series.length === 0) return -1
  let lo = 0
  let hi = series.length - 1
  while (lo < hi) {
    const mid = (lo + hi) >> 1
    if (series[mid][0] < t) lo = mid + 1
    else hi = mid
  }
  if (lo > 0 && Math.abs(series[lo - 1][0] - t) <= Math.abs(series[lo][0] - t)) return lo - 1
  return lo
}

/** Indices where memory fell sharply versus the previous sample: usually a restart. */
export function findDrops(series: Point[], ratio = 0.7): number[] {
  const out: number[] = []
  for (let i = 1; i < series.length; i++) {
    if (series[i][1] < series[i - 1][1] * ratio) out.push(i)
  }
  return out
}

export interface Projection {
  /** Where the dashed line starts. */
  from: Point
  /** Where it ends: the limit, or the chart edge if the limit is further away. */
  to: Point
  /** True when the limit is not reached before the chart edge. */
  clipped: boolean
}

/**
 * Straight-line projection from the newest sample to the memory limit.
 * `maxFutureMs` caps how far past "now" the chart is willing to extend.
 * Returns null when there is nothing to project (no growth, no limit, already over).
 */
export function projectToLimit(
  last: Point,
  slopeBytesPerHour: number,
  limitBytes: number | undefined,
  maxFutureMs: number,
): Projection | null {
  if (!limitBytes || !(slopeBytesPerHour > 0) || last[1] >= limitBytes) return null
  const msToLimit = ((limitBytes - last[1]) / slopeBytesPerHour) * 3_600_000
  if (msToLimit <= maxFutureMs) {
    return { from: last, to: [last[0] + msToLimit, limitBytes], clipped: false }
  }
  const t = last[0] + maxFutureMs
  const v = last[1] + (slopeBytesPerHour * maxFutureMs) / 3_600_000
  return { from: last, to: [t, v], clipped: true }
}

// Sparklines: a small trend of counts, oldest first, drawn from a zero baseline.

export interface Spark {
  /** SVG path of the line; empty when there are fewer than two points to draw. */
  line: string
  /** The same line closed down to the baseline, for a light fill. */
  area: string
  /** Where the newest value sits, for an end dot. */
  end?: [number, number]
  min: number
  max: number
  /** The newest value. */
  last?: number
}

const r2 = (n: number) => Math.round(n * 100) / 100

/**
 * Lay out `values` (counts, oldest first) in a width x height box, inset by
 * `pad`. The scale starts at zero and reaches at least 1, so an all-zero
 * series lies flat on the baseline instead of in the middle. Missing values
 * (NaN, null) break the line.
 */
export function sparkline(values: readonly (number | null | undefined)[], width: number, height: number, pad = 2): Spark {
  const finite = values.filter((v): v is number => typeof v === 'number' && Number.isFinite(v))
  const min = finite.length ? Math.min(...finite) : 0
  const max = finite.length ? Math.max(...finite) : 0
  let last: number | undefined
  for (let i = values.length - 1; i >= 0; i--) {
    const v = values[i]
    if (typeof v === 'number' && Number.isFinite(v)) {
      last = v
      break
    }
  }
  if (finite.length < 2) return { line: '', area: '', min, max, last }
  const top = Math.max(1, max)
  const base = height - pad
  const step = (width - 2 * pad) / (values.length - 1)
  const x = (i: number) => r2(pad + i * step)
  const y = (v: number) => r2(base - (Math.max(0, v) / top) * (height - 2 * pad))
  const segments: [number, number][][] = []
  let cur: [number, number][] = []
  values.forEach((v, i) => {
    if (typeof v === 'number' && Number.isFinite(v)) cur.push([x(i), y(v)])
    else if (cur.length) {
      segments.push(cur)
      cur = []
    }
  })
  if (cur.length) segments.push(cur)
  const line = segments.map((s) => s.map(([px, py], i) => `${i === 0 ? 'M' : 'L'}${px},${py}`).join('')).join('')
  const area = segments
    .filter((s) => s.length > 1)
    .map((s) => `M${s[0][0]},${r2(base)}${s.map(([px, py]) => `L${px},${py}`).join('')}L${s[s.length - 1][0]},${r2(base)}Z`)
    .join('')
  const tail = segments[segments.length - 1]
  return { line, area, end: tail[tail.length - 1], min, max, last }
}

/** The text alternative: "unhealthy workloads, last 24h: min 0, max 4, now 2". */
export function sparkText(label: string, values: readonly (number | null | undefined)[], span: string): string {
  const s = sparkline(values, 1, 1, 0)
  const head = span ? `${label}, last ${span}` : label
  if (s.last === undefined) return `${head}: no data yet`
  return `${head}: min ${s.min.toLocaleString('en-US')}, max ${s.max.toLocaleString('en-US')}, now ${s.last.toLocaleString('en-US')}`
}

/** Thin a series to at most `max` points for a table view, always keeping the newest. */
export function thin(series: Point[], max: number): Point[] {
  if (series.length <= max) return series
  const out: Point[] = []
  const stride = (series.length - 1) / (max - 1)
  for (let i = 0; i < max; i++) out.push(series[Math.round(i * stride)])
  return out
}
