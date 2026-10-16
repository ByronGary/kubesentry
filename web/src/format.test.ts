import { describe, expect, it } from 'vitest'
import { ago, formatAge, formatBytes, formatCPU, formatExpiry, formatHours, formatPercent, formatRate, formatUSD, hoursUntil, listSome, percent, plural, truncateMiddle } from './format'

describe('formatRate and formatPercent', () => {
  it('keeps request rates short', () => {
    expect([0, 0.354, 4.25, 4, 35.4, 1240, 14_400, NaN].map(formatRate)).toEqual(['0/s', '0.35/s', '4.3/s', '4/s', '35/s', '1.2k/s', '14k/s', '-'])
  })
  it('shows error ratios as percents', () => {
    expect([0, 0.005, 0.0512, 0.2, 1, NaN].map(formatPercent)).toEqual(['0%', '0.5%', '5.1%', '20%', '100%', '-'])
  })
})

describe('formatBytes', () => {
  it('uses binary units and drops needless decimals', () => {
    expect(formatBytes(512 * 1024 * 1024)).toBe('512 MiB')
    expect(formatBytes(1.5 * 1024 ** 3)).toBe('1.5 GiB')
    expect(formatBytes(0)).toBe('0 B')
    expect(formatBytes(NaN)).toBe('-')
  })
})

describe('formatHours', () => {
  it('picks a readable unit', () => {
    expect(formatHours(0.5)).toBe('30 minutes')
    expect(formatHours(1)).toBe('1 hour')
    expect(formatHours(5.4)).toBe('5 hours')
    expect(formatHours(72)).toBe('3 days')
  })
})

describe('ago', () => {
  const now = Date.parse('2026-01-01T12:00:00Z')
  it('describes relative time', () => {
    expect(ago('2026-01-01T11:59:40Z', now)).toBe('just now')
    expect(ago('2026-01-01T11:30:00Z', now)).toBe('30 minutes ago')
    expect(ago('2026-01-01T09:00:00Z', now)).toBe('3 hours ago')
    expect(ago('2025-12-28T12:00:00Z', now)).toBe('4 days ago')
    expect(ago('garbage', now)).toBe('-')
  })
})

describe('misc', () => {
  it('formats CPU', () => {
    expect(formatCPU(0)).toBe('0m')
    expect(formatCPU(45.4)).toBe('45m')
    expect(formatCPU(1300)).toBe('1.3 cores')
  })
  it('formats money and plurals', () => {
    expect(formatUSD(12.5)).toBe('$12.50')
    expect(formatUSD(1234)).toBe('$1,234')
    expect(plural(1, 'pod', 'pods')).toBe('pod')
    expect(plural(2, 'pod', 'pods')).toBe('pods')
  })
})

describe('formatExpiry', () => {
  it('reads forwards and backwards in time', () => {
    expect(formatExpiry(480)).toBe('in 20 days')
    expect(formatExpiry(5.2)).toBe('in 5 hours')
    expect(formatExpiry(0.5)).toBe('in 30 minutes')
    expect(formatExpiry(-72)).toBe('expired 3 days ago')
    expect(formatExpiry(-1)).toBe('expired 1 hour ago')
    expect(formatExpiry(undefined)).toBe('-')
  })
  it('pairs with hoursUntil', () => {
    const now = Date.parse('2026-01-01T00:00:00Z')
    expect(hoursUntil('2026-01-21T00:00:00Z', now)).toBe(480)
    expect(formatExpiry(hoursUntil('2025-12-29T00:00:00Z', now))).toBe('expired 3 days ago')
    expect(hoursUntil(undefined, now)).toBeUndefined()
    expect(hoursUntil('nope', now)).toBeUndefined()
  })
})

describe('formatAge', () => {
  const now = Date.parse('2026-01-10T12:00:00Z')
  it('is compact like kubectl', () => {
    expect(formatAge('2026-01-10T11:59:30Z', now)).toBe('30s')
    expect(formatAge('2026-01-10T11:48:00Z', now)).toBe('12m')
    expect(formatAge('2026-01-10T07:00:00Z', now)).toBe('5h')
    expect(formatAge('2026-01-07T12:00:00Z', now)).toBe('3d')
    expect(formatAge('2026-01-10T12:00:05Z', now)).toBe('0s')
    expect(formatAge('bad', now)).toBe('-')
  })
})

describe('percent', () => {
  it('rounds and clamps', () => {
    expect(percent(1, 4)).toBe(25)
    expect(percent(2, 3)).toBe(67)
    expect(percent(5, 4)).toBe(100)
    expect(percent(1, 0)).toBeUndefined()
  })
})

describe('truncateMiddle', () => {
  it('keeps both ends of long names', () => {
    expect(truncateMiddle('short', 10)).toBe('short')
    const t = truncateMiddle('checkout-7d9f8b6c5-x2k4p', 15)
    expect(t).toHaveLength(15)
    expect(t).toBe('checkou…5-x2k4p')
  })
})

describe('listSome', () => {
  it('names a few and counts the rest', () => {
    expect(listSome(['a', 'b'])).toBe('a, b')
    expect(listSome(['a', 'b', 'c', 'd', 'e'])).toBe('a, b, c and 2 more')
  })
})
