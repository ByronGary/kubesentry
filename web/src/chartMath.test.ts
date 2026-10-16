import { describe, expect, it } from 'vitest'
import {
  brushRange,
  bucketCounts,
  byteTicks,
  extent,
  findDrops,
  linePath,
  medianStep,
  nearestIndex,
  niceTicks,
  plotGeometry,
  projectToLimit,
  rateTicks,
  sharedDomain,
  sparkline,
  sparkText,
  spreadLabels,
  stackMarkers,
  thin,
  timeAt,
  timeTicks,
  valueAt,
  xOf,
  type MarkerIn,
  type Point,
} from './chartMath'

describe('sparkline', () => {
  it('scales counts from a zero baseline across the box', () => {
    const s = sparkline([0, 2, 4], 100, 20, 0)
    expect(s.line).toBe('M0,20L50,10L100,0')
    expect(s.area).toBe('M0,20L0,20L50,10L100,0L100,20Z')
    expect(s.end).toEqual([100, 0])
    expect([s.min, s.max, s.last]).toEqual([0, 4, 4])
  })
  it('keeps an all-zero series flat on the baseline, inside the padding', () => {
    expect(sparkline([0, 0, 0], 40, 10, 2).line).toBe('M2,8L20,8L38,8')
  })
  it('draws nothing for fewer than two points, but still reports them', () => {
    expect(sparkline([3], 40, 10)).toMatchObject({ line: '', area: '', min: 3, max: 3, last: 3 })
    expect(sparkline([], 40, 10)).toMatchObject({ line: '', last: undefined })
  })
  it('breaks the line at missing values', () => {
    const s = sparkline([1, 1, null, 1, NaN], 40, 10, 0)
    expect(s.line).toBe('M0,0L10,0M30,0')
    expect(s.last).toBe(1)
    expect(s.end).toEqual([30, 0])
  })
  it('has a text alternative', () => {
    expect(sparkText('unhealthy workloads', [0, 4, 1, 2], '24h')).toBe('unhealthy workloads, last 24h: min 0, max 4, now 2')
    expect(sparkText('failing pods', [], '24h')).toBe('failing pods, last 24h: no data yet')
    expect(sparkText('certificates', [1200, 1300], '')).toBe('certificates: min 1,200, max 1,300, now 1,300')
  })
})

const MiB = 1 << 20

describe('niceTicks', () => {
  it('starts at zero with round steps', () => {
    expect(niceTicks(100, 4)).toEqual([0, 50, 100])
    expect(niceTicks(0)).toEqual([0])
  })
})

describe('byteTicks', () => {
  it('lands on MiB boundaries', () => {
    const t = byteTicks(480 * MiB, 4)
    expect(t[0]).toBe(0)
    expect(t.every((v) => v % MiB === 0)).toBe(true)
    expect(t[t.length - 1]).toBeGreaterThanOrEqual(400 * MiB)
  })
})

describe('timeTicks', () => {
  it('returns ascending ticks inside the range', () => {
    const start = Date.parse('2026-01-01T00:07:00Z')
    const end = start + 6 * 3_600_000
    const t = timeTicks(start, end, 6)
    expect(t.length).toBeGreaterThan(2)
    expect(t.every((v, i) => v >= start && v <= end && (i === 0 || v > t[i - 1]))).toBe(true)
  })
})

describe('nearestIndex', () => {
  const s: Point[] = [[0, 1], [10, 2], [20, 3]]
  it('finds the closest sample', () => {
    expect(nearestIndex(s, 4)).toBe(0)
    expect(nearestIndex(s, 6)).toBe(1)
    expect(nearestIndex(s, 99)).toBe(2)
    expect(nearestIndex([], 5)).toBe(-1)
  })
})

describe('findDrops', () => {
  it('flags only sharp falls', () => {
    const s: Point[] = [[0, 100], [1, 95], [2, 20], [3, 30]]
    expect(findDrops(s)).toEqual([2])
  })
})

describe('projectToLimit', () => {
  const hour = 3_600_000
  it('reaches the limit when it is near enough', () => {
    const p = projectToLimit([0, 400 * MiB], 50 * MiB, 500 * MiB, 6 * hour)
    expect(p?.clipped).toBe(false)
    expect(p?.to[0]).toBe(2 * hour)
    expect(p?.to[1]).toBe(500 * MiB)
  })
  it('clips at the chart edge when the limit is far', () => {
    const p = projectToLimit([0, 100 * MiB], 10 * MiB, 500 * MiB, hour)
    expect(p?.clipped).toBe(true)
    expect(p?.to[1]).toBe(110 * MiB)
  })
  it('returns null with nothing to project', () => {
    expect(projectToLimit([0, 1], 0, 10, hour)).toBeNull()
    expect(projectToLimit([0, 1], 5, undefined, hour)).toBeNull()
    expect(projectToLimit([0, 20], 5, 10, hour)).toBeNull()
  })
})

describe('thin', () => {
  it('caps length and keeps the newest', () => {
    const s: Point[] = Array.from({ length: 100 }, (_, i) => [i, i])
    const t = thin(s, 10)
    expect(t).toHaveLength(10)
    expect(t[9]).toEqual([99, 99])
    expect(thin(s.slice(0, 5), 10)).toHaveLength(5)
  })
})

const MIN = 60_000

describe('sharedDomain', () => {
  it('uses the window when there is one, so every chart shares it', () => {
    expect(sharedDomain([1000, 5000 + MIN], [[0, 99 * MIN]])).toEqual([1000, 5000 + MIN])
    // Reversed ends are put in order.
    expect(sharedDomain([10 * MIN, 0])).toEqual([0, 10 * MIN])
  })
  it('falls back to the union of the data extents', () => {
    expect(sharedDomain(undefined, [[2 * MIN, 5 * MIN], undefined, [0, 3 * MIN]])).toEqual([0, 5 * MIN])
    expect(sharedDomain([NaN, 1], [[0, 2 * MIN]])).toEqual([0, 2 * MIN])
  })
  it('grows a too-narrow span around its middle and gives up on nothing', () => {
    expect(sharedDomain(undefined, [[MIN, MIN]])).toEqual([MIN / 2, MIN * 1.5])
    expect(sharedDomain(undefined, [])).toBeUndefined()
  })
  it('reads extents from series', () => {
    expect(extent([[5, 1], [9, 2], [7, 3]])).toEqual([5, 9])
    expect(extent([])).toBeUndefined()
  })
})

describe('xOf and timeAt', () => {
  const d: [number, number] = [0, 100]
  it('map time to pixels and back', () => {
    expect(xOf(50, d, 10, 200)).toBe(110)
    expect(timeAt(110, d, 10, 200)).toBe(50)
  })
  it('clamp pixels outside the plot to the domain', () => {
    expect(timeAt(-40, d, 10, 200)).toBe(0)
    expect(timeAt(900, d, 10, 200)).toBe(100)
    expect(timeAt(50, d, 10, 0)).toBe(0)
  })
})

describe('rateTicks', () => {
  it('gives round steps that reach the maximum', () => {
    expect(rateTicks(37)).toEqual([0, 10, 20, 30, 40])
    expect(rateTicks(0.3)).toEqual([0, 0.1, 0.2, 0.3])
    expect(rateTicks(0.031)).toEqual([0, 0.01, 0.02, 0.03, 0.04])
  })
  it('never collapses to a lone zero', () => {
    expect(rateTicks(0)).toEqual([0, 1])
    expect(rateTicks(NaN)).toEqual([0, 1])
    expect(rateTicks(1e-9).length).toBeGreaterThan(1)
  })
})

describe('brushRange', () => {
  const d: [number, number] = [0, 60 * MIN]
  it('orders the ends and clamps them to the domain', () => {
    expect(brushRange(30 * MIN, 10 * MIN, d)).toEqual([10 * MIN, 30 * MIN])
    expect(brushRange(-5 * MIN, 70 * MIN, d)).toEqual([0, 60 * MIN])
  })
  it('treats a click as no brush', () => {
    expect(brushRange(5, 5, d)).toBeNull()
    expect(brushRange(NaN, 5, d)).toBeNull()
  })
  it('grows a tiny brush to the minimum span, inside the domain', () => {
    expect(brushRange(10 * MIN, 10 * MIN + 1000, d)).toEqual([10 * MIN + 500 - MIN / 2, 10 * MIN + 500 + MIN / 2])
    // At the left edge it grows rightwards.
    expect(brushRange(0, 1000, d)).toEqual([0, MIN])
    // At the right edge, leftwards.
    expect(brushRange(60 * MIN - 1000, 60 * MIN, d)).toEqual([59 * MIN, 60 * MIN])
    // A domain narrower than the minimum is used whole.
    expect(brushRange(0, 10, [0, 30_000])).toEqual([0, 30_000])
  })
})

describe('bucketCounts', () => {
  it('counts times per equal slice, keeping the end in the last one', () => {
    expect(bucketCounts([0, 1, 2, 5, 9, 10], [0, 10], 2)).toEqual([3, 3])
    expect(bucketCounts([0, 3, 3, 7], [0, 10], 5)).toEqual([1, 2, 0, 1, 0])
  })
  it('leaves out times outside the domain', () => {
    expect(bucketCounts([-1, 11, NaN, 5], [0, 10], 1)).toEqual([1])
    expect(bucketCounts([1], [0, 0], 3)).toEqual([0, 0, 0])
    expect(bucketCounts([1], [0, 10], 0)).toEqual([])
  })
})

describe('stackMarkers', () => {
  const px = (t: number) => t
  const m = (t: number, kind: string): MarkerIn => ({ t, kind, label: `${kind}@${t}` })
  it('merges close markers of one kind into one glyph', () => {
    const s = stackMarkers([m(0, 'restart'), m(5, 'restart'), m(40, 'restart')], px, 12)
    expect(s.map((x) => [x.px, x.row, x.items.length])).toEqual([[0, 0, 2], [40, 0, 1]])
  })
  it('stacks colliding kinds in rows, then folds into the top row', () => {
    const s = stackMarkers([m(0, 'oom'), m(2, 'restart'), m(4, 'deploy'), m(6, 'event')], px, 12, 3)
    expect(s.map((x) => [x.kind, x.row])).toEqual([['oom', 0], ['restart', 1], ['deploy', 2]])
    expect(s[2].items.map((i) => i.kind)).toEqual(['deploy', 'event'])
  })
  it('reuses the lowest free row and sorts by time', () => {
    const s = stackMarkers([m(30, 'event'), m(0, 'oom'), m(3, 'deploy')], px, 12)
    expect(s.map((x) => [x.kind, x.row])).toEqual([['oom', 0], ['deploy', 1], ['event', 0]])
  })
})

describe('spreadLabels', () => {
  it('keeps labels apart and in order', () => {
    expect(spreadLabels([50, 52, 100], 12, 0, 200)).toEqual([50, 62, 100])
    expect(spreadLabels([52, 50], 12, 0, 200)).toEqual([62, 50])
  })
  it('pushes a run back up from the bottom', () => {
    expect(spreadLabels([198, 199, 200], 10, 0, 200)).toEqual([180, 190, 200])
  })
})

describe('linePath and medianStep', () => {
  const id = (n: number) => n
  it('breaks the line at gaps and missing values', () => {
    expect(linePath([[0, 1], [10, 2], [40, 3], [50, NaN], [60, 4]], id, id, 15)).toBe('M0.0,1.0L10.0,2.0M40.0,3.0M60.0,4.0')
    expect(linePath([], id, id)).toBe('')
  })
  it('finds the usual sample spacing', () => {
    expect(medianStep([[0, 1], [10, 1], [20, 1], [90, 1]])).toBe(10)
    expect(medianStep([[0, 1]])).toBeUndefined()
  })
  it('lays out a plot: margins, a y scale with headroom to a round tick, the shared x', () => {
    const g = plotGeometry({ width: 400, height: 200, margin: { top: 10, right: 40, bottom: 30, left: 60 }, domain: [0, 100], values: [37, 12, NaN], ticks: (m) => rateTicks(m) })
    expect([g.iw, g.ih]).toEqual([300, 160])
    expect(g.yTicks).toEqual([0, 10, 20, 30, 40])
    expect(g.yTop).toBe(40)
    expect(g.y(0)).toBe(170)
    expect(g.y(40)).toBe(10)
    expect(g.x(0)).toBe(60)
    expect(g.x(100)).toBe(360)
    // Nothing to fit still gives a usable scale.
    const flat = plotGeometry({ width: 400, height: 200, margin: { top: 0, right: 0, bottom: 0, left: 0 }, domain: [0, 1], values: [], ticks: (m) => byteTicks(m) })
    expect(flat.yTop).toBe(1)
    expect(Number.isFinite(flat.y(0))).toBe(true)
  })
  it('reads a value near a time, within a tolerance', () => {
    const s: Point[] = [[0, 1], [10, 2]]
    expect(valueAt(s, 9, 2)).toBe(2)
    expect(valueAt(s, 5, 2)).toBeUndefined()
    expect(valueAt([], 5, 2)).toBeUndefined()
  })
})
