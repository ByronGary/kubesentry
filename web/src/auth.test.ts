import { describe, expect, it } from 'vitest'
import { cooldownLeft, readNumber, readString, REAUTH_GAP_MS, reauthDecision, retryAfterMs, sortGroups, sourceText, writeNumber, writeString, type KV } from './auth'

function memoryStore(): KV & { data: Map<string, string> } {
  const data = new Map<string, string>()
  return {
    data,
    getItem: (k) => data.get(k) ?? null,
    setItem: (k, v) => void data.set(k, v),
    removeItem: (k) => void data.delete(k),
  }
}

const broken: KV = {
  getItem: () => {
    throw new Error('SecurityError')
  },
  setItem: () => {
    throw new Error('QuotaExceededError')
  },
  removeItem: () => {
    throw new Error('SecurityError')
  },
}

describe('reauthDecision (single sign-on reload-loop guard)', () => {
  const now = 1_000_000_000
  it('reloads on the first expiry', () => {
    expect(reauthDecision(undefined, now)).toBe('reload')
  })
  it('refuses to reload again right after a reload, which would loop', () => {
    expect(reauthDecision(now - 1000, now)).toBe('stuck')
    expect(reauthDecision(now - REAUTH_GAP_MS + 1, now)).toBe('stuck')
  })
  it('reloads again once the gap has passed: a later expiry is a new session ending', () => {
    expect(reauthDecision(now - REAUTH_GAP_MS, now)).toBe('reload')
    expect(reauthDecision(now - 3_600_000, now)).toBe('reload')
  })
  it('is not blocked forever by a timestamp from the future', () => {
    expect(reauthDecision(now + 60_000, now)).toBe('reload')
  })
  it('works through storage: reload, then stuck on the next 401, as the api layer uses it', () => {
    const s = memoryStore()
    const first = reauthDecision(readNumber(s, 'k'), now)
    expect(first).toBe('reload')
    writeNumber(s, 'k', now)
    // The page reloaded and the next request still gets a 401 a few seconds later.
    expect(reauthDecision(readNumber(s, 'k'), now + 5000)).toBe('stuck')
  })
})

describe('storage helpers', () => {
  it('round-trips and clears values', () => {
    const s = memoryStore()
    writeString(s, 'a', 'x')
    expect(readString(s, 'a')).toBe('x')
    writeString(s, 'a', undefined)
    expect(s.data.has('a')).toBe(false)
    writeNumber(s, 'n', 42)
    expect(readNumber(s, 'n')).toBe(42)
    s.setItem('n', 'garbage')
    expect(readNumber(s, 'n')).toBeUndefined()
  })
  it('never throws when storage is blocked or missing', () => {
    expect(readString(broken, 'a')).toBeUndefined()
    expect(() => writeString(broken, 'a', 'x')).not.toThrow()
    expect(() => writeString(broken, 'a', undefined)).not.toThrow()
    expect(readNumber(undefined, 'a')).toBeUndefined()
    expect(() => writeNumber(undefined, 'a', 1)).not.toThrow()
  })
})

describe('recheck cool-down', () => {
  it('counts down to zero', () => {
    expect(cooldownLeft(undefined, 10)).toBe(0)
    expect(cooldownLeft(70_000, 10_000)).toBe(60_000)
    expect(cooldownLeft(70_000, 80_000)).toBe(0)
  })
  it('reads Retry-After as seconds or an HTTP date', () => {
    const now = Date.parse('2026-10-11T12:00:00Z')
    expect(retryAfterMs('42', now)).toBe(42_000)
    expect(retryAfterMs('Sun, 11 Oct 2026 12:00:30 GMT', now)).toBe(30_000)
    expect(retryAfterMs('Sun, 11 Oct 2026 11:00:00 GMT', now)).toBe(0)
    expect(retryAfterMs('soon', now)).toBeUndefined()
    expect(retryAfterMs(null, now)).toBeUndefined()
  })
})

describe('identity text', () => {
  it('names the source', () => {
    expect(sourceText('proxy')).toMatch(/single sign-on/)
    expect(sourceText('token')).toMatch(/token/)
    expect(sourceText(undefined)).toBe('')
  })
  it('lists real groups before the ones everybody has', () => {
    expect(sortGroups(['system:authenticated', 'team-b', 'Team-a'])).toEqual(['Team-a', 'team-b', 'system:authenticated'])
    expect(sortGroups(undefined)).toEqual([])
  })
})
