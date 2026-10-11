import { describe, expect, it } from 'vitest'
import {
  activityEmptyText,
  auditHistoryHours,
  auditWhy,
  clusterFacts,
  durationHours,
  findingsLookback,
  formatSpan,
  lookbackText,
  metricsHistoryHours,
  metricsWhy,
  stalenessText,
  windowChoices,
  type WindowOption,
} from './retention'

const now = Date.parse('2026-10-11T12:00:00Z')
const hoursAgo = (h: number) => new Date(now - h * 3_600_000).toISOString()

describe('formatSpan and durationHours', () => {
  it('formats spans the way people say them', () => {
    expect(formatSpan(0.5)).toBe('30 minutes')
    expect(formatSpan(6)).toBe('6 hours')
    expect(formatSpan(24)).toBe('24 hours')
    expect(formatSpan(168)).toBe('7 days')
    expect(formatSpan(720)).toBe('30 days')
    expect(formatSpan(0)).toBe('0 minutes')
  })
  it('reads Go durations', () => {
    expect(durationHours('168h0m0s')).toBe(168)
    expect(durationHours('6h')).toBe(6)
    expect(durationHours('90m')).toBe(1.5)
    expect(durationHours('1h30m0s')).toBe(1.5)
    expect(durationHours('')).toBeUndefined()
    expect(durationHours('soon')).toBeUndefined()
  })
})

describe('history', () => {
  it('is the smaller of audit retention and the age of the oldest event', () => {
    expect(auditHistoryHours(undefined, now)).toBeUndefined()
    expect(auditHistoryHours({ backend: 'postgres', events: 9, retentionHours: 720, oldest: hoursAgo(50) }, now)).toBeCloseTo(50)
    expect(auditHistoryHours({ backend: 'postgres', events: 9, retentionHours: 168, oldest: hoursAgo(500) }, now)).toBe(168)
    expect(auditHistoryHours({ backend: 'memory', events: 9, oldest: hoursAgo(3) }, now)).toBeCloseTo(3)
    expect(auditHistoryHours({ backend: 'memory', events: 0 }, now)).toBe(0)
  })
  it('reads Prometheus retention only when set', () => {
    expect(metricsHistoryHours({ source: 'discovered', retentionHours: 6 })).toBe(6)
    expect(metricsHistoryHours({ source: 'flag' })).toBeUndefined()
    expect(metricsHistoryHours(undefined)).toBeUndefined()
  })
})

describe('windowChoices', () => {
  const opts: WindowOption[] = [
    { value: '1h', label: 'Last hour', hours: 1 },
    { value: '24h', label: 'Last 24 hours', hours: 24 },
    { value: '168h', label: 'Last 7 days', hours: 168 },
    { value: '720h', label: 'Last 30 days', hours: 720 },
  ]
  const enabled = (h: number | undefined) => windowChoices(opts, h, (x) => `only ${x}h`).filter((c) => !c.disabled).map((c) => c.value)

  it('enables everything when the server does not say', () => {
    expect(enabled(undefined)).toEqual(['1h', '24h', '168h', '720h'])
  })
  it('disables windows past the history, keeping the smallest one that covers it', () => {
    expect(enabled(168)).toEqual(['1h', '24h', '168h'])
    expect(enabled(50)).toEqual(['1h', '24h', '168h'])
    expect(enabled(6)).toEqual(['1h', '24h'])
    expect(enabled(10_000)).toEqual(['1h', '24h', '168h', '720h'])
    expect(enabled(0)).toEqual(['1h'])
  })
  it('allows a little slack and says why a window is off', () => {
    expect(enabled(167)).toEqual(['1h', '24h', '168h'])
    const c = windowChoices(opts, 24, metricsWhy)
    expect(c.find((x) => x.value === '720h')).toMatchObject({ disabled: true, reason: 'Prometheus keeps only 24 hours of history.' })
  })
  it('explains audit limits by retention or by how far back events go', () => {
    expect(auditWhy({ backend: 'postgres', events: 5, retentionHours: 168 })(168)).toBe('Audit events are kept for 7 days.')
    expect(auditWhy({ backend: 'memory', events: 5 })(3)).toBe('The audit log holds only 3 hours of events.')
    expect(auditWhy({ backend: 'memory', events: 0 })(0)).toBe('No audit events are stored yet.')
  })
})

describe('retention-driven text', () => {
  it('never claims a window longer than the history', () => {
    expect(lookbackText(24, undefined, 'Prometheus')).toBe('in the last 24 hours')
    expect(lookbackText(24, 168, 'Prometheus')).toBe('in the last 24 hours')
    expect(lookbackText(24, 6, 'Prometheus')).toBe('in the last 6 hours (all the history Prometheus has)')
    expect(lookbackText(24, 0, 'the audit log')).toBe('yet (the audit log has no history)')
  })
  it('claims the Findings window only as far as the sources reach', () => {
    const pg = { backend: 'postgres' as const, events: 120_000, retentionHours: 720, oldest: hoursAgo(500) }
    expect(findingsLookback(24, undefined, { included: false }, now)).toBe('in the last 24 hours')
    expect(findingsLookback(24, 6, { included: false }, now)).toBe('in the last 6 hours (all the history Prometheus has)')
    expect(findingsLookback(24, 168, { included: true, store: pg }, now)).toBe('in the last 24 hours')
    expect(findingsLookback(24, 168, { included: true, store: { backend: 'memory', events: 3, oldest: hoursAgo(2) } }, now)).toBe(
      'in the last 2 hours (all the history the audit log has)',
    )
    expect(findingsLookback(24, undefined, { included: true, store: { backend: 'memory', events: 0 } }, now)).toBe('yet (the audit log has no history)')
  })
  it('stays neutral while the audit store has not answered /info', () => {
    // At startup the server waits at most 50 ms for audit coverage and leaves auditStore out.
    expect(findingsLookback(24, 168, { included: true, store: undefined }, now)).toBe('recently')
    expect(activityEmptyText('168h0m0s', undefined, now)).toBe('Nobody has acted on this pod recently.')
    expect(auditHistoryHours(undefined, now)).toBeUndefined()
    expect(windowChoices([{ value: '720h', label: '30 days', hours: 720 }], auditHistoryHours(undefined, now), auditWhy(undefined)).every((c) => !c.disabled)).toBe(true)
  })
  it('words the empty pod activity from the server window and the audit store', () => {
    expect(activityEmptyText('168h0m0s', { backend: 'postgres', events: 4, retentionHours: 720, oldest: hoursAgo(500) }, now)).toBe('Nobody has acted on this pod in the last 7 days.')
    expect(activityEmptyText(undefined, undefined, now)).toBe('Nobody has acted on this pod recently.')
    expect(activityEmptyText('168h0m0s', { backend: 'memory', events: 4, oldest: hoursAgo(5) }, now)).toMatch(/^Nobody has acted on this pod since the audit log begins \(/)
    expect(activityEmptyText('24h', { backend: 'postgres', events: 4, retentionHours: 720, oldest: hoursAgo(500) }, now)).toBe('Nobody has acted on this pod in the last 24 hours.')
  })
})

describe('stalenessText', () => {
  it('stays quiet for fresh data and servers that do not say', () => {
    expect(stalenessText(undefined)).toBeUndefined()
    expect(stalenessText({ version: 3, builtAt: '', ageSeconds: 4, stale: false })).toBeUndefined()
    expect(stalenessText({ version: 3, builtAt: '', ageSeconds: 60, stale: false })).toBeUndefined()
  })
  it('warns when stale or older than a minute', () => {
    expect(stalenessText({ version: 3, builtAt: '', ageSeconds: 95, stale: false })).toBe('Data is 95 s old; the API server may be unreachable.')
    expect(stalenessText({ version: 3, builtAt: '', ageSeconds: 30, stale: true })).toBe('Data is 30 s old; the API server may be unreachable.')
    expect(stalenessText({ version: 3, builtAt: '', ageSeconds: 900, stale: true })).toBe('Data is 15 minutes old; the API server may be unreachable.')
  })
})

describe('clusterFacts', () => {
  it('names the cluster, version and where it runs', () => {
    expect(clusterFacts({ name: 'prod-use1', version: 'v1.31.2-eks-1', platform: 'linux/amd64', provider: 'aws', region: 'us-east-1' })).toEqual({
      name: 'prod-use1',
      facts: ['Kubernetes 1.31.2-eks-1', 'AWS us-east-1'],
    })
    expect(clusterFacts({ version: 'v1.36.4', platform: 'linux/amd64' })).toEqual({ name: undefined, facts: ['Kubernetes 1.36.4', 'linux/amd64'] })
    expect(clusterFacts(undefined)).toEqual({ facts: [] })
  })
})
