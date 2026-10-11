import { describe, expect, it } from 'vitest'
import { byteTicks, findDrops, nearestIndex, niceTicks, projectToLimit, thin, timeTicks, type Point } from './chartMath'

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
