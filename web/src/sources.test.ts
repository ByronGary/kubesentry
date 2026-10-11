import { describe, expect, it } from 'vitest'
import { podActivity, prometheusOutage, unavailableBanner, unexplainedWarnings } from './sources'

describe('prometheusOutage', () => {
  it('is the stable reason from /info, while there is one', () => {
    expect(prometheusOutage({ unavailable: { prometheus: 'queries fail: HTTP 503 Service Unavailable' } })).toBe('queries fail: HTTP 503 Service Unavailable')
    expect(prometheusOutage({ unavailable: { kubernetes: 'forbidden' } })).toBeUndefined()
    expect(prometheusOutage({})).toBeUndefined()
    expect(prometheusOutage(undefined)).toBeUndefined()
    expect(prometheusOutage({ unavailable: { prometheus: ' ' } })).toBe('it cannot be queried')
  })
})

describe('unavailableBanner', () => {
  const unavailable = { prometheus: 'queries fail: no answer in time', 'cert-manager': 'forbidden' }
  it('lists every source, sorted, where no page explains them', () => {
    const b = unavailableBanner(unavailable)
    expect(b.shown).toEqual([['cert-manager', 'forbidden'], ['prometheus', 'queries fail: no answer in time']])
    expect(b.sig).toBe('cert-manager=forbidden\nprometheus=queries fail: no answer in time')
  })
  it('leaves out what the page explains, but dismisses the whole set', () => {
    const b = unavailableBanner(unavailable, ['prometheus'])
    expect(b.shown).toEqual([['cert-manager', 'forbidden']])
    expect(b.sig).toBe(unavailableBanner(unavailable).sig)
    expect(unavailableBanner({ prometheus: 'x' }, ['prometheus']).shown).toEqual([])
    expect(unavailableBanner(undefined)).toEqual({ sig: '', shown: [] })
  })
})

describe('response warnings', () => {
  const memory = 'Memory history is unavailable: could not query Prometheus.'
  const leaks = 'leak detection unavailable: could not query Prometheus'
  const activity = 'Activity is unavailable: could not query the audit store.'
  const hidden = 'Activity is hidden: you may not read audit events in this namespace.'
  const other = 'leak scan: 3 containers skipped'

  it('drops only what the page explains itself', () => {
    expect(unexplainedWarnings([memory, leaks, activity, other], {})).toEqual([memory, leaks, activity, other])
    expect(unexplainedWarnings([memory, leaks, activity, other], { prometheus: true })).toEqual([activity, other])
    expect(unexplainedWarnings([memory, activity, hidden], { audit: true })).toEqual([memory, hidden])
    expect(unexplainedWarnings(undefined, { audit: true })).toEqual([])
  })
  it('tells a busy audit store from hidden or absent activity', () => {
    expect(podActivity({ auditAvailable: true, warnings: [activity] })).toBe('shown')
    expect(podActivity({ auditAvailable: false, warnings: [memory, activity] })).toBe('unavailable')
    expect(podActivity({ auditAvailable: false, warnings: [hidden] })).toBe('hidden')
    expect(podActivity({ auditAvailable: false })).toBe('off')
    expect(podActivity({ auditAvailable: false, warnings: [memory] })).toBe('off')
  })
})
