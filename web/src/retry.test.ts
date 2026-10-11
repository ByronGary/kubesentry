import { describe, expect, it } from 'vitest'
import { BUSY_MAX_MS, busyDelayMs, isBusy, nextRetry, retryText, secondsLeft } from './retry'

describe('isBusy', () => {
  it('is a 503, with or without Retry-After', () => {
    expect(isBusy({ status: 503, retryAfterMs: 5000 })).toBe(true)
    expect(isBusy({ status: 503 })).toBe(true)
    expect(isBusy({ status: 502 })).toBe(false)
    expect(isBusy({ status: 429, retryAfterMs: 1000 })).toBe(false)
    expect(isBusy(new Error('network'))).toBe(false)
    expect(isBusy(undefined)).toBe(false)
  })
})

describe('busyDelayMs', () => {
  it('waits Retry-After first, 5 s without one', () => {
    expect(busyDelayMs(5000, 1)).toBe(5000)
    expect(busyDelayMs(12_000, 1)).toBe(12_000)
    expect(busyDelayMs(undefined, 1)).toBe(5000)
    expect(busyDelayMs(NaN, 1)).toBe(5000)
  })
  it('doubles while the store stays busy, up to a minute', () => {
    expect([1, 2, 3, 4, 5, 6, 50].map((n) => busyDelayMs(5000, n))).toEqual([5000, 10_000, 20_000, 40_000, 60_000, 60_000, 60_000])
  })
  it('never spins and never waits past the cap', () => {
    expect(busyDelayMs(0, 1)).toBe(1000)
    expect(busyDelayMs(-5, 1)).toBe(1000)
    expect(busyDelayMs(0, 2)).toBe(2000)
    expect(busyDelayMs(3_600_000, 1)).toBe(BUSY_MAX_MS)
    expect(busyDelayMs(5000, 0)).toBe(5000)
  })
  it('keeps a shorter page refresh as the cap', () => {
    expect([1, 2, 3, 4].map((n) => busyDelayMs(5000, n, 0, 30_000))).toEqual([5000, 10_000, 20_000, 30_000])
  })
  it('spreads tabs out by up to a fifth, still under the cap', () => {
    expect(busyDelayMs(5000, 1, 0.5)).toBe(5500)
    expect(busyDelayMs(5000, 1, 0.999)).toBeLessThanOrEqual(6000)
    expect(busyDelayMs(5000, 5, 0.9)).toBe(BUSY_MAX_MS)
  })
})

describe('retry countdown', () => {
  const now = 1_000_000
  it('schedules from now and counts down in whole seconds', () => {
    const r = nextRetry(1, 5000, now, { random: 0 })
    expect(r).toEqual({ at: now + 5000, attempt: 1 })
    expect(secondsLeft(r, now)).toBe(5)
    expect(retryText(r, now)).toBe('retrying in 5 s…')
    expect(retryText(r, now + 4200)).toBe('retrying in 1 s…')
    expect(retryText(r, now + 5000)).toBe('retrying now…')
    expect(secondsLeft(r, now + 9000)).toBe(0)
  })
  it('backs off on the attempt it is given', () => {
    expect(nextRetry(3, undefined, now, { random: 0 }).at).toBe(now + 20_000)
    expect(nextRetry(9, undefined, now, { random: 0, maxMs: 60_000 }).at).toBe(now + 60_000)
  })
})
