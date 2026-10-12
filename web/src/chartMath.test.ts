import { describe, expect, it } from 'vitest'
import { byteTicks, findDrops, nearestIndex, niceTicks, projectToLimit, sparkline, sparkText, thin, timeTicks, type Point } from './chartMath'

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
