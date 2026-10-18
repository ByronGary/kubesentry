import { describe, expect, it } from 'vitest'
import {
  announceText,
  brushAround,
  cachedFromTime,
  cachedText,
  canCancel,
  cancelErrorText,
  checkView,
  chosenRun,
  egressNotice,
  failedText,
  fallbacks,
  hiddenRunsText,
  idTime,
  investigationPath,
  investigationsPath,
  investigatorOn,
  isTerminal,
  laneKeyOf,
  modelText,
  omittedRows,
  outcomeText,
  parseRef,
  pollMs,
  refAction,
  refLabel,
  startErrorText,
  stepView,
  templateSearch,
  timelineRange,
  usageText,
  utcSpan,
  waitText,
  type RefContext,
} from './investigation'
import type { Info, InvestigationEvidence } from './types'

const inv = { enabled: true, provider: 'bedrock' as const, model: 'anthropic.claude-opus-5-5', effort: 'high' as const, perHour: 10 }

describe('investigatorOn', () => {
  it('needs the investigator and the capability', () => {
    expect(investigatorOn(undefined)).toBe(false)
    expect(investigatorOn({} as Info)).toBe(false)
    expect(investigatorOn({ investigator: { ...inv, enabled: false } })).toBe(false)
    // No capabilities: an unrestricted server.
    expect(investigatorOn({ investigator: inv })).toBe(true)
    expect(investigatorOn({ investigator: inv, capabilities: { investigate: true } })).toBe(true)
    expect(investigatorOn({ investigator: inv, capabilities: { investigate: false } })).toBe(false)
    expect(investigatorOn({ investigator: inv, capabilities: { podLogs: true } })).toBe(false)
  })
})

describe('egressNotice', () => {
  it('names the provider and model, and says commands never run', () => {
    expect(egressNotice(inv)).toBe(
      'Sends a redacted digest of this incident, and the logs, events, audit and CloudTrail records you may see, to Amazon Bedrock (anthropic.claude-opus-5-5). Suggested commands are never run.',
    )
    expect(egressNotice({ ...inv, provider: 'anthropic', model: 'claude-opus-5-5' })).toContain('to Anthropic (claude-opus-5-5)')
    expect(egressNotice({ ...inv, provider: 'demo', model: 'demo-scripted' })).toContain('offline demo investigator (demo-scripted)')
    expect(egressNotice(undefined)).toBe('')
  })
})

describe('paths and polling', () => {
  it('escapes IDs', () => {
    expect(investigationsPath('a/b')).toBe('/api/v1/incidents/a%2Fb/investigations')
    expect(investigationPath('i', 'r 1')).toBe('/api/v1/incidents/i/investigations/r%201')
  })
  it('polls every 2s while running and stops on terminal states', () => {
    expect(pollMs({ status: 'running' })).toBe(2000)
    for (const s of ['completed', 'refused', 'failed', 'cancelled'] as const) {
      expect(pollMs({ status: s })).toBeUndefined()
      expect(isTerminal(s)).toBe(true)
    }
    expect(pollMs(undefined)).toBeUndefined()
    expect(isTerminal('running')).toBe(false)
  })
})

describe('parseRef', () => {
  it('splits metric refs at the metric, keeping colons in the label', () => {
    expect(parseRef('metric:memory:pod-a/web')).toEqual({ ref: 'metric:memory:pod-a/web', kind: 'metric', id: 'memory:pod-a/web', metric: 'memory', label: 'pod-a/web' })
    expect(parseRef('metric:requests:svc:8080:x')).toMatchObject({ metric: 'requests', label: 'svc:8080:x' })
    // An older form without the metric.
    expect(parseRef('metric:checkout')).toEqual({ ref: 'metric:checkout', kind: 'metric', id: 'checkout', label: 'checkout' })
  })
  it('keeps the whole id of other kinds', () => {
    expect(parseRef('signal:events:abc#7')).toMatchObject({ kind: 'signal', id: 'events:abc#7' })
    expect(parseRef('log:12')).toMatchObject({ kind: 'log', id: '12' })
    expect(parseRef('cloudtrail:5d2e')).toMatchObject({ kind: 'cloudtrail', id: '5d2e' })
  })
  it('marks unknown forms', () => {
    expect(parseRef('note:1').kind).toBe('unknown')
    expect(parseRef('signal:').kind).toBe('unknown')
    expect(parseRef('plain').kind).toBe('unknown')
  })
})

describe('laneKeyOf', () => {
  const keys = new Set(['event:u1', 'audit:a1', 'signal:cloudtrail:c1', 'signal:view:deploy:x@14', 'signal:events:u2#3'])
  it('maps event and audit signals to the records the page shows', () => {
    expect(laneKeyOf(parseRef('signal:events:u1#7'), keys)).toBe('event:u1')
    expect(laneKeyOf(parseRef('signal:audit:a1'), keys)).toBe('audit:a1')
    expect(laneKeyOf(parseRef('signal:view:deploy:x@14'), keys)).toBe('signal:view:deploy:x@14')
    expect(laneKeyOf(parseRef('cloudtrail:c1'), keys)).toBe('signal:cloudtrail:c1')
    expect(laneKeyOf(parseRef('event:u2'), keys)).toBe('signal:events:u2#3')
    expect(laneKeyOf(parseRef('event:nope'), keys)).toBeUndefined()
    expect(laneKeyOf(parseRef('log:1'), keys)).toBeUndefined()
  })
})

describe('refAction', () => {
  const t0 = Date.parse('2026-10-17T12:00:00Z')
  const domain: [number, number] = [t0, t0 + 3_600_000]
  const ev = (e: InvestigationEvidence): [string, InvestigationEvidence] => [e.ref, e]
  const ctx: RefContext = {
    evidence: new Map([
      ev({ ref: 'log:3', kind: 'log', time: '2026-10-17T12:30:00Z', object: 'web-1/web', snippet: 'boom' }),
      ev({ ref: 'logtpl:1', kind: 'logtpl', time: '2026-10-17T12:10:00Z', object: 'web-1', snippet: 'upstream timed out ({n}: Connection timed out) client: {ip}' }),
      ev({ ref: 'logtpl:2', kind: 'logtpl', object: 'web-1, web-2', snippet: '{n} {n}' }),
      ev({ ref: 'metric:memory:web-1/web', kind: 'metric', time: '2026-10-17T12:59:30Z', object: 'web-1/web' }),
      ev({ ref: 'audit:a1', kind: 'audit', time: '2026-10-17T12:05:00Z', snippet: 'dave patch configmaps cfg' }),
      ev({ ref: 'cloudtrail:c9', kind: 'cloudtrail', time: '2026-10-17T12:06:00Z', snippet: 'jordan called AuthorizeSecurityGroupIngress' }),
      ev({ ref: 'signal:gone', kind: 'signal', time: '2026-10-17T12:07:00Z', snippet: 'gone' }),
    ]),
    unverified: new Set(['metric:requests:other']),
    laneKeys: new Set(['event:u1', 'audit:a1', 'signal:s1']),
    domain,
  }
  it('highlights signals and events in the lanes', () => {
    expect(refAction('signal:s1', ctx)).toEqual({ kind: 'lane', key: 'signal:s1', t: undefined })
    expect(refAction('signal:events:u1#4', ctx)).toMatchObject({ kind: 'lane', key: 'event:u1' })
    expect(refAction('event:u1', ctx)).toMatchObject({ kind: 'lane', key: 'event:u1' })
    // Not on the page: the record from the evidence index.
    expect(refAction('signal:gone', ctx)).toMatchObject({ kind: 'record', evidence: { snippet: 'gone' } })
    expect(refAction('event:nope', ctx)).toEqual({ kind: 'text', reason: 'missing' })
  })
  it('narrows the logs around a line, or searches a template', () => {
    expect(refAction('log:3', ctx)).toEqual({
      kind: 'logs',
      focus: { pod: 'web-1', container: 'web' },
      range: [t0 + 28 * 60_000, t0 + 32 * 60_000],
      t: t0 + 30 * 60_000,
    })
    expect(refAction('logtpl:1', ctx)).toMatchObject({ kind: 'logs', focus: { pod: 'web-1', q: 'Connection timed out) client' }, range: null })
    expect(refAction('logtpl:2', ctx)).toMatchObject({ kind: 'logs', focus: { pod: undefined, q: undefined } })
    expect(refAction('log:99', ctx)).toEqual({ kind: 'text', reason: 'missing' })
  })
  it('brushes the charts around a metric peak, clamped to the domain', () => {
    expect(refAction('metric:memory:web-1/web', ctx)).toEqual({
      kind: 'charts',
      range: [domain[1] - 4 * 60_000, domain[1]],
      metric: 'memory',
      label: 'web-1/web',
    })
  })
  it('opens audit and CloudTrail records', () => {
    expect(refAction('audit:a1', ctx)).toMatchObject({ kind: 'record', key: 'audit:a1', evidence: { ref: 'audit:a1' } })
    expect(refAction('cloudtrail:c9', ctx)).toMatchObject({ kind: 'record', key: undefined })
  })
  it('leaves unverified and unknown refs as text', () => {
    expect(refAction('metric:requests:other', ctx)).toEqual({ kind: 'text', reason: 'unverified' })
    expect(refAction('whatever', ctx)).toEqual({ kind: 'text', reason: 'unverified' })
  })
})

describe('templateSearch', () => {
  it('takes the longest literal part', () => {
    expect(templateSearch('GC pause {n}ms, heap {n}MiB of {n}MiB')).toBe('GC pause')
    expect(templateSearch('token [REDACTED] for user {uuid} rejected by the gateway')).toBe('rejected by the gateway')
    expect(templateSearch('{n} ok')).toBeUndefined()
    expect(templateSearch(undefined)).toBeUndefined()
    expect(templateSearch('x'.repeat(300))?.length).toBe(120)
  })
})

describe('brushAround and timelineRange', () => {
  const d: [number, number] = [0, 3_600_000]
  it('keeps 4 minutes, moved inside the domain', () => {
    expect(brushAround(1_800_000, d)).toEqual([1_680_000, 1_920_000])
    expect(brushAround(10_000, d)).toEqual([0, 240_000])
    expect(brushAround(3_590_000, d)).toEqual([3_360_000, 3_600_000])
    // Outside the domain: the nearest edge.
    expect(brushAround(-5_000_000, d)).toEqual([0, 240_000])
    // A domain shorter than 4 minutes: the whole of it.
    expect(brushAround(60_000, [0, 100_000])).toEqual([0, 100_000])
    expect(brushAround(NaN, d)).toBeNull()
    expect(brushAround(5, [10, 10])).toBeNull()
  })
  it('reads RFC 3339 times', () => {
    const t = Date.parse('2026-10-17T12:00:00Z')
    expect(timelineRange('2026-10-17T12:00:00Z', [t - 3_600_000, t + 3_600_000])).toEqual([t - 120_000, t + 120_000])
    expect(timelineRange('not a time', [0, 1])).toBeNull()
  })
})

describe('steps', () => {
  it('marks the UTC span and gives each result a shape and a word', () => {
    expect(utcSpan('get_logs web error 12:01–12:20: 48 lines')).toBe('get_logs web error 12:01–12:20 UTC: 48 lines')
    expect(utcSpan('list_signals Oct 16 23:50–Oct 17 00:20: 2 signals')).toBe('list_signals Oct 16 23:50–Oct 17 00:20 UTC: 2 signals')
    expect(utcSpan('turn 1: 2 tool calls (100 tokens)')).toBe('turn 1: 2 tool calls (100 tokens)')
    const at = '2026-10-17T12:00:00Z'
    expect(stepView({ at, kind: 'tool', tool: 'get_logs', text: 'get_logs: no pods', result: 'ok' }, 0)).toMatchObject({ glyph: 'ok', loud: false })
    expect(stepView({ at, kind: 'tool', text: 'get_logs: not permitted', result: 'denied' }, 1)).toMatchObject({ glyph: 'warn', word: 'not permitted', loud: true })
    expect(stepView({ at, kind: 'tool', text: 'x', result: 'invalid' }, 1)).toMatchObject({ word: 'invalid input', loud: true })
    expect(stepView({ at, kind: 'turn', text: 'turn 2: model request failed', result: 'error' }, 2)).toMatchObject({ glyph: 'crit', word: 'failed' })
    expect(stepView({ at, kind: 'turn', text: 'turn 1: 1 tool call' }, 3)).toMatchObject({ glyph: 'info', loud: false })
    expect(stepView({ at, kind: 'note', text: 'cancelled' }, 4)).toMatchObject({ glyph: 'unknown', word: 'note' })
  })
})

describe('run texts', () => {
  it('explains failures', () => {
    expect(failedText('timeout')).toContain('ran out of time')
    expect(failedText('interrupted')).toContain('interrupted')
    expect(failedText('budget: tool calls')).toBe('Its budget of tool calls ran out before the model gave a valid report.')
    expect(failedText('HTTP 529 overloaded')).toBe('The model provider answered HTTP 529 overloaded.')
    expect(failedText('something odd')).toBe('Something odd.')
    expect(failedText(undefined)).toContain('without saying why')
  })
  it('reads the fallback notes', () => {
    const steps = [
      { at: '', kind: 'note' as const, text: 'turn 2: claude-opus-5-5 declined; the fallback model claude-opus-5 answered' },
      { at: '', kind: 'note' as const, text: 'turn 3: claude-opus-5-5 declined; the fallback model claude-opus-5 answered' },
      { at: '', kind: 'turn' as const, text: 'turn 3: 1 tool call' },
    ]
    expect(fallbacks(steps)).toEqual([
      { turn: 2, declined: 'claude-opus-5-5', model: 'claude-opus-5' },
      { turn: 3, declined: 'claude-opus-5-5', model: 'claude-opus-5' },
    ])
    expect(modelText({ provider: 'anthropic', model: 'claude-opus-5-5', effort: 'high', steps })).toBe(
      'claude-opus-5-5 on Anthropic, effort high; claude-opus-5 answered turns 2, 3 after claude-opus-5-5 declined',
    )
    expect(modelText({ provider: 'demo', model: 'demo-scripted', effort: 'high', steps: [] })).toBe('demo-scripted on the demo investigator, effort high')
  })
  it('counts usage, and says when a cached copy used none', () => {
    expect(usageText({ turns: 3, toolCalls: 4, usage: { input: 9, output: 3200, cacheRead: 17391, cacheWrite: 11015 } })).toBe(
      '3 turns, 4 tool calls, 31,615 tokens (17,391 read from the prompt cache)',
    )
    expect(usageText({ turns: 1, toolCalls: 1, usage: { input: 1, output: 0, cacheRead: 0, cacheWrite: 0 } })).toBe('1 turn, 1 tool call, 1 token')
    expect(usageText({ turns: 3, toolCalls: 4, cachedFrom: 'x', usage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 } })).toBe(
      '3 turns, 4 tool calls in the earlier run; no new tokens',
    )
  })
  it('dates a cached copy from the list or the ID', () => {
    expect(idTime('20261016T120102Z-ab12cd34')).toBe(Date.UTC(2026, 9, 16, 12, 1, 2))
    expect(idTime('nope')).toBeUndefined()
    const runs = [{ id: 'orig', createdAt: '2026-10-17T10:00:00Z' }] as never
    expect(cachedFromTime({ cachedFrom: 'orig' }, runs)).toBe(Date.parse('2026-10-17T10:00:00Z'))
    expect(cachedFromTime({ cachedFrom: '20261016T120102Z-ab12cd34' })).toBe(Date.UTC(2026, 9, 16, 12, 1, 2))
    expect(cachedFromTime({})).toBeUndefined()
    expect(cachedText({ cachedFrom: '20261016T120102Z-ab12cd34' })).toMatch(/^From an earlier run at .+, with the same input: no new model call/)
    expect(cachedText({})).toBeUndefined()
  })
  it('lists omitted sections', () => {
    expect(omittedRows({ logs: 'forbidden', cloudtrail: 'error: throttled' })).toEqual(['CloudTrail: error: throttled', 'Logs: not permitted for you'])
    expect(omittedRows(undefined)).toEqual([])
  })
  it('words outcomes and announcements', () => {
    expect(outcomeText({ outcome: 'likely_cause', confidence: 'medium' })).toBe('Likely cause, medium confidence')
    expect(outcomeText({})).toBeUndefined()
    expect(announceText({ status: 'completed', outcome: 'root_cause_identified', confidence: 'high' })).toBe(
      'Investigation completed: root cause identified, high confidence.',
    )
    expect(announceText({ status: 'completed', cachedFrom: 'x' })).toBe('Investigation answered from an earlier run.')
    expect(announceText({ status: 'refused', refusal: { category: 'cyber', explanation: '' } })).toBe('The model declined the investigation (cyber).')
    expect(announceText({ status: 'failed', error: 'timeout' })).toContain('Investigation failed: It ran out of time')
  })
  it('lets the starter cancel', () => {
    expect(canCancel({ status: 'running', requestedBy: 'alice' }, 'alice', false)).toBe(true)
    expect(canCancel({ status: 'running', requestedBy: 'alice' }, 'bob', false)).toBe(false)
    expect(canCancel({ status: 'running', requestedBy: 'alice' }, 'bob', true)).toBe(true)
    expect(canCancel({ status: 'running', requestedBy: 'kubesentry:anonymous' }, undefined, false)).toBe(true)
    expect(canCancel({ status: 'completed', requestedBy: 'alice' }, 'alice', true)).toBe(false)
  })
})

describe('errors', () => {
  it('words quota, busy and conflict answers with Retry-After', () => {
    expect(waitText(40_000)).toBe('40 seconds')
    expect(waitText(1000)).toBe('1 second')
    expect(waitText(12 * 60_000 - 500)).toBe('12 minutes')
    expect(waitText(3 * 3_600_000)).toBe('3 hours')
    expect(waitText(undefined)).toBeUndefined()
    expect(
      startErrorText({ status: 429, message: 'investigate: you have started 10 investigations in the last hour, the most allowed', retryAfterMs: 720_000 }),
    ).toBe('You have started 10 investigations in the last hour, the most allowed. Try again in 12 minutes.')
    expect(startErrorText({ status: 429, message: '' })).toBe('The hourly limit of investigations is reached. Try again later.')
    expect(startErrorText({ status: 503, message: 'investigate: busy', retryAfterMs: 30_000 })).toBe(
      'This server is running as many investigations as it may. Try again in 30 seconds.',
    )
    expect(startErrorText({ status: 409, message: 'an investigation of this incident is already running' })).toBe(
      'An investigation of this incident is already running.',
    )
    expect(startErrorText({ status: 403, message: 'investigating incidents needs create on investigations.kubesentry.io in this namespace' })).toBe(
      'You may not investigate this incident: investigating incidents needs create on investigations.kubesentry.io in this namespace.',
    )
    expect(startErrorText({ status: 404, message: 'incident not found' })).toContain('no longer stored')
    expect(startErrorText({ status: 415, message: 'want application/json' })).toBe('The server refused the request: Want application/json.')
    expect(startErrorText({ status: 502, message: 'the investigator: boom' })).toBe('The investigator: boom.')
    expect(startErrorText({ status: 0, message: '' })).toBe('The request failed.')
  })
  it('words cancel answers', () => {
    expect(cancelErrorText({ status: 403, message: '' })).toContain('Only the person who started')
    expect(cancelErrorText({ status: 409, message: '' })).toContain('already finished')
  })
})

describe('checks and runs', () => {
  it('separates removed commands', () => {
    expect(checkView({ description: 'Roll back. (command removed: not read-only)', command: '' })).toEqual({ description: 'Roll back.', removed: true })
    expect(checkView({ description: 'Pods.', command: ' kubectl get pods -n shop ' })).toEqual({ description: 'Pods.', command: 'kubectl get pods -n shop', removed: false })
    expect(checkView({ description: 'Just look.', command: '' })).toEqual({ description: 'Just look.', command: undefined, removed: false })
  })
  it('chooses the run to show', () => {
    const items = [{ id: 'b' }, { id: 'a' }] as never
    expect(chosenRun(items, undefined)).toBe('b')
    expect(chosenRun(items, 'a')).toBe('a')
    expect(chosenRun(items, 'new', 'new')).toBe('new')
    expect(chosenRun(items, 'gone')).toBe('b')
    expect(chosenRun([], undefined)).toBeUndefined()
  })
  it('notes hidden runs', () => {
    expect(hiddenRunsText(0)).toBeUndefined()
    expect(hiddenRunsText(1)).toContain('1 other investigation of this incident used data you may not see')
    expect(hiddenRunsText(2)).toContain('they are not listed')
  })
  it('labels refs from the evidence index', () => {
    expect(refLabel('metric:memory:web-1/web', { ref: '', kind: 'metric' })).toMatchObject({ kind: 'Metric', text: 'Memory web-1/web' })
    expect(refLabel('logtpl:2', { ref: 'logtpl:2', kind: 'logtpl', snippet: 'GC pause {n}ms' })).toMatchObject({ kind: 'Log pattern', text: 'GC pause {n}ms' })
    expect(refLabel('signal:x', undefined)).toMatchObject({ kind: 'Signal', text: 'x' })
    expect(refLabel('odd', undefined)).toMatchObject({ kind: 'Ref', text: 'odd' })
    expect(refLabel('signal:x', { ref: 'signal:x', kind: 'signal', snippet: 'y'.repeat(200) }).text.length).toBeLessThanOrEqual(90)
  })
})
