import { describe, expect, it } from 'vitest'
import { axisFor } from './components/TimeChart'
import { stepTime, timeKey, type KeyState } from './components/useTimeInteraction'

const MIN = 60_000
const keys = [0, MIN, 2 * MIN, 3 * MIN, 4 * MIN]
const ctx = { keys, domain: [0, 4 * MIN] as [number, number], canBrush: true, hasBrush: false }
const idle: KeyState = { hoverT: null, pending: null, anchor: null }

describe('timeKey: the keyboard on the time axis', () => {
  it('shows the crosshair first, then steps through the samples', () => {
    const a = timeKey(idle, 'ArrowLeft', false, ctx)!
    expect(a.hoverT).toBe(4 * MIN)
    const b = timeKey(a, 'ArrowLeft', false, ctx)!
    expect(b.hoverT).toBe(3 * MIN)
    expect(timeKey(b, 'Home', false, ctx)!.hoverT).toBe(0)
    expect(timeKey(b, 'End', false, ctx)!.hoverT).toBe(4 * MIN)
    // It stops at the ends.
    expect(timeKey({ ...idle, hoverT: 0 }, 'ArrowLeft', false, ctx)!.hoverT).toBe(0)
  })
  it('brushes with Shift+Arrow from where it started, and Enter applies it', () => {
    let s: KeyState = { ...idle, hoverT: 2 * MIN }
    s = timeKey(s, 'ArrowRight', true, ctx)!
    expect([s.anchor, s.pending]).toEqual([2 * MIN, [2 * MIN, 3 * MIN]])
    s = timeKey(s, 'ArrowRight', true, ctx)!
    expect(s.pending).toEqual([2 * MIN, 4 * MIN])
    // Back past the start flips the range.
    s = timeKey(timeKey(timeKey(s, 'ArrowLeft', true, ctx)!, 'ArrowLeft', true, ctx)!, 'ArrowLeft', true, ctx)!
    expect(s.pending).toEqual([MIN, 2 * MIN])
    const done = timeKey(s, 'Enter', false, ctx)!
    expect(done.commit).toEqual([MIN, 2 * MIN])
    expect([done.pending, done.anchor]).toEqual([null, null])
  })
  it('clears with Escape: what is pending first, then the applied brush', () => {
    const pending: KeyState = { hoverT: MIN, pending: [0, MIN], anchor: 0 }
    expect(timeKey(pending, 'Escape', false, { ...ctx, hasBrush: true })).toEqual({ hoverT: null, pending: null, anchor: null, clear: false })
    expect(timeKey({ ...idle, hoverT: MIN }, 'Escape', false, { ...ctx, hasBrush: true })!.clear).toBe(true)
  })
  it('only moves the crosshair where there is no brush, and ignores other keys', () => {
    const r = timeKey({ ...idle, hoverT: MIN }, 'ArrowRight', true, { ...ctx, canBrush: false })!
    expect([r.hoverT, r.pending]).toEqual([2 * MIN, null])
    expect(timeKey(idle, 'Enter', false, ctx)).toBeUndefined()
    expect(timeKey(idle, 'a', false, ctx)).toBeUndefined()
  })
})

describe('stepTime', () => {
  it('steps by a sixtieth of the domain without samples, inside it', () => {
    expect(stepTime(0, 1, [], [0, 60 * MIN])).toBe(MIN)
    expect(stepTime(0, -1, [], [0, 60 * MIN])).toBe(0)
    expect(stepTime(5, 'end', [], [0, 60 * MIN])).toBe(60 * MIN)
  })
  it('snaps to the nearest sample before stepping', () => {
    expect(stepTime(1.4 * MIN, 1, keys, ctx.domain)).toBe(2 * MIN)
  })
})

describe('axisFor', () => {
  it('shares one left edge and makes room for end labels except on a phone', () => {
    expect(axisFor(1200)).toEqual({ top: 14, right: 112, bottom: 26, left: 62 })
    expect(axisFor(360).right).toBe(14)
    expect(axisFor(360).left).toBe(axisFor(1200).left)
  })
})
