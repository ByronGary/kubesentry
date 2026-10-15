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

// ---- Time-aligned charts (incidents): one x domain shared by every chart, lane and strip on a page ----

/** A [from, to] time range in unix ms. */
export type Range = [number, number]

const finite = (n: unknown): n is number => typeof n === 'number' && Number.isFinite(n)

/** First and last sample time of a series; undefined when empty. */
export function extent(points: readonly Point[]): Range | undefined {
  let lo = Infinity
  let hi = -Infinity
  for (const p of points) {
    if (!finite(p[0])) continue
    if (p[0] < lo) lo = p[0]
    if (p[0] > hi) hi = p[0]
  }
  return lo <= hi ? [lo, hi] : undefined
}

/**
 * The x domain charts on one page share, so a time sits at the same x in each.
 * The window (the incident's padded window) wins when it is valid; otherwise
 * the union of the data extents. A span narrower than `minSpan` grows around
 * its middle, so a single sample still gets an axis. Undefined when there is
 * nothing to go on.
 */
export function sharedDomain(window: Range | undefined, extents: readonly (Range | undefined)[] = [], minSpan = 60_000): Range | undefined {
  let lo = Infinity
  let hi = -Infinity
  if (window && finite(window[0]) && finite(window[1])) {
    lo = Math.min(window[0], window[1])
    hi = Math.max(window[0], window[1])
  } else {
    for (const e of extents) {
      if (!e || !finite(e[0]) || !finite(e[1])) continue
      lo = Math.min(lo, e[0], e[1])
      hi = Math.max(hi, e[0], e[1])
    }
  }
  if (!(lo <= hi)) return undefined
  if (hi - lo < minSpan) {
    const mid = (lo + hi) / 2
    return [mid - minSpan / 2, mid + minSpan / 2]
  }
  return [lo, hi]
}

/** x pixel for time t on a domain drawn from `left` over `width` pixels. */
export function xOf(t: number, domain: Range, left: number, width: number): number {
  const span = domain[1] - domain[0]
  return left + (span > 0 ? ((t - domain[0]) / span) * width : 0)
}

/** The time under pixel `px`, clamped to the domain. */
export function timeAt(px: number, domain: Range, left: number, width: number): number {
  if (!(width > 0)) return domain[0]
  const f = Math.min(1, Math.max(0, (px - left) / width))
  return domain[0] + f * (domain[1] - domain[0])
}

/**
 * Round ticks from zero for a rate or ratio axis, reaching at least `max`.
 * Unlike niceTicks it never returns a lone 0 (an all-zero series still gets a
 * scale) and computes each tick by multiplication, so 0.1 steps do not drift
 * to 0.30000000000000004.
 */
export function rateTicks(max: number, target = 4): number[] {
  if (!(max > 0) || !Number.isFinite(max)) return [0, 1]
  const rough = max / target
  const pow = Math.pow(10, Math.floor(Math.log10(rough)))
  const frac = rough / pow
  const step = (frac <= 1 ? 1 : frac <= 2 ? 2 : frac <= 5 ? 5 : 10) * pow
  const n = Math.max(1, Math.ceil(max / step - 1e-9))
  const out: number[] = []
  for (let i = 0; i <= n; i++) out.push(Number((i * step).toPrecision(12)))
  return out
}

/**
 * The range a brush covers, from its two ends in either order: clamped to the
 * domain and at least `minSpan` wide (grown around its middle, kept inside the
 * domain). Null when the ends coincide or are not numbers: a click, not a drag.
 */
export function brushRange(a: number, b: number, domain: Range, minSpan = 60_000): Range | null {
  if (!finite(a) || !finite(b) || a === b) return null
  let from = Math.max(domain[0], Math.min(a, b))
  let to = Math.min(domain[1], Math.max(a, b))
  if (to < from) return null
  const span = Math.min(minSpan, domain[1] - domain[0])
  if (to - from < span) {
    const mid = (from + to) / 2
    from = mid - span / 2
    to = mid + span / 2
    if (from < domain[0]) {
      to += domain[0] - from
      from = domain[0]
    }
    if (to > domain[1]) {
      from -= to - domain[1]
      to = domain[1]
    }
  }
  return [Math.round(from), Math.round(to)]
}

/** How many of `times` fall in each of `buckets` equal slices of the domain; times outside it are left out. */
export function bucketCounts(times: readonly number[], domain: Range, buckets: number): number[] {
  const n = Math.max(0, Math.floor(buckets))
  const out = new Array<number>(n).fill(0)
  const span = domain[1] - domain[0]
  if (n === 0 || !(span > 0)) return out
  for (const t of times) {
    if (!finite(t) || t < domain[0] || t > domain[1]) continue
    out[Math.min(n - 1, Math.floor(((t - domain[0]) / span) * n))]++
  }
  return out
}

export interface MarkerIn<K extends string = string> {
  t: number
  kind: K
  label: string
}

export interface MarkerStack<K extends string = string> {
  /** Where the stack sits: its first marker's time and x. */
  t: number
  px: number
  /** 0 is the row nearest the axis. */
  row: number
  kind: K
  /** Every marker this one glyph stands for. */
  items: MarkerIn<K>[]
}

/**
 * Lays out event markers (OOM, restart, deploy, event) so their glyphs do not
 * overlap. Markers of one kind closer than `gap` pixels merge into one glyph
 * with a count; a different kind that would collide moves up a row; once
 * `maxRows` are used, it joins the latest stack on the top row instead.
 */
export function stackMarkers<K extends string>(markers: readonly MarkerIn<K>[], toPx: (t: number) => number, gap = 12, maxRows = 3): MarkerStack<K>[] {
  const sorted = markers.filter((m) => finite(m.t)).slice().sort((a, b) => a.t - b.t)
  // Same kind, close together: one glyph.
  const groups: MarkerStack<K>[] = []
  const lastOfKind = new Map<K, MarkerStack<K>>()
  for (const m of sorted) {
    const px = toPx(m.t)
    const g = lastOfKind.get(m.kind)
    if (g && px - g.px < gap) {
      g.items.push(m)
      continue
    }
    const ng: MarkerStack<K> = { t: m.t, px, row: 0, kind: m.kind, items: [m] }
    groups.push(ng)
    lastOfKind.set(m.kind, ng)
  }
  // Different kinds that collide: stack in rows.
  const rows = Math.max(1, Math.floor(maxRows))
  const rowEnd: number[] = []
  const rowLast: MarkerStack<K>[] = []
  const out: MarkerStack<K>[] = []
  for (const g of groups) {
    let r = rowEnd.findIndex((end) => g.px - end >= gap)
    if (r === -1 && rowEnd.length < rows) r = rowEnd.length
    if (r === -1) {
      rowLast[rows - 1].items.push(...g.items)
      continue
    }
    g.row = r
    rowEnd[r] = g.px
    rowLast[r] = g
    out.push(g)
  }
  return out
}

/**
 * Moves label centres apart so none are closer than `gap`, keeping their
 * order and staying within [top, bottom] where there is room. Returns the new
 * positions in the input order (end labels beside several lines).
 */
export function spreadLabels(ys: readonly number[], gap: number, top: number, bottom: number): number[] {
  const order = ys.map((y, i) => ({ y, i })).sort((a, b) => a.y - b.y || a.i - b.i)
  const pos = order.map((o) => Math.min(bottom, Math.max(top, o.y)))
  for (let k = 1; k < pos.length; k++) if (pos[k] - pos[k - 1] < gap) pos[k] = pos[k - 1] + gap
  // Pushed past the bottom: shift the run back up, but not above the top.
  if (pos.length && pos[pos.length - 1] > bottom) {
    for (let k = pos.length - 1; k >= 0; k--) {
      const limit = k === pos.length - 1 ? bottom : pos[k + 1] - gap
      pos[k] = Math.max(top, Math.min(pos[k], limit))
    }
  }
  const out = new Array<number>(ys.length)
  order.forEach((o, k) => (out[o.i] = Math.round(pos[k] * 10) / 10))
  return out
}

/**
 * SVG path through the points, broken at non-finite values and where two
 * samples are more than `breakAfter` ms apart (no samples there).
 */
export function linePath(points: readonly Point[], x: (t: number) => number, y: (v: number) => number, breakAfter = Infinity): string {
  let d = ''
  let prev: number | undefined
  for (const [t, v] of points) {
    if (!finite(t) || !finite(v)) {
      prev = undefined
      continue
    }
    const move = prev === undefined || t - prev > breakAfter
    d += `${move ? 'M' : 'L'}${x(t).toFixed(1)},${y(v).toFixed(1)}`
    prev = t
  }
  return d
}

/** The usual spacing of a series' samples (the median gap); undefined with fewer than two. */
export function medianStep(points: readonly Point[]): number | undefined {
  if (points.length < 2) return undefined
  const gaps: number[] = []
  for (let i = 1; i < points.length; i++) gaps.push(points[i][0] - points[i - 1][0])
  gaps.sort((a, b) => a - b)
  return gaps[Math.floor(gaps.length / 2)]
}

/** The value of a series at time t: the nearest sample within `tolerance` ms, else undefined. */
export function valueAt(points: readonly Point[], t: number, tolerance: number): number | undefined {
  if (!points.length) return undefined
  const i = nearestIndex(points as Point[], t)
  const p = points[i]
  return p && Math.abs(p[0] - t) <= tolerance ? p[1] : undefined
}
