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

/** Thin a series to at most `max` points for a table view, always keeping the newest. */
export function thin(series: Point[], max: number): Point[] {
  if (series.length <= max) return series
  const out: Point[] = []
  const stride = (series.length - 1) / (max - 1)
  for (let i = 0; i < max; i++) out.push(series[Math.round(i * stride)])
  return out
}
