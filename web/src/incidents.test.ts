import { describe, expect, it } from 'vitest'
import {
  atLeast,
  bundlePath,
  chartMarks,
  clampSpan,
  clampWindow,
  filterQuery,
  incidentDuration,
  incidentHref,
  incidentsPath,
  inRange,
  isNarrowed,
  isoSeconds,
  laneItems,
  LANES,
  levelGlyph,
  logsPath,
  logVolume,
  maxRangeHours,
  mergeTimeline,
  normalLevel,
  paddingText,
  patchFilter,
  rangeQuery,
  readIncidentFilter,
  readRange,
  severityGlyph,
  shortSpan,
  SIGNAL_META,
  SIGNAL_TYPES,
  signalDetail,
  signalMeta,
  sourceRows,
  sourceUp,
  spikeSpans,
  subjectText,
  tagChips,
  toggleType,
  typeChips,
  windowChoicesFor,
  windowRange,
} from './incidents'
import { safeHref } from './overview'
import type { IncidentDetail, IncidentSignal, IncidentSignalType } from './types'

const T0 = Date.parse('2026-10-15T12:00:00Z')
const MIN = 60_000
const iso = (m: number) => new Date(T0 + m * MIN).toISOString()

function sig(p: Partial<IncidentSignal> & Pick<IncidentSignal, 'id' | 'type'>): IncidentSignal {
  return {
    source: 'view',
    role: SIGNAL_META[p.type as IncidentSignalType]?.role === 'trigger' ? 'trigger' : 'context',
    start: iso(0),
    subject: { kind: 'Deployment', namespace: 'shop', name: 'api' },
    object: { kind: 'Pod', namespace: 'shop', name: 'api-1' },
    title: p.type,
    ...p,
  }
}

describe('severityGlyph', () => {
  it('maps the wire words to the glyphs in one place', () => {
    expect(severityGlyph('critical')).toBe('crit')
    expect(severityGlyph('warning')).toBe('warn')
    expect(severityGlyph(undefined)).toBe('unknown')
    expect(severityGlyph('caution')).toBe('unknown')
  })
})

describe('signal metadata', () => {
  it('covers every type with a lane, a shape and a role', () => {
    for (const t of SIGNAL_TYPES) {
      const m = SIGNAL_META[t]
      expect(LANES.some((l) => l.key === m.lane)).toBe(true)
      expect(m.label).not.toBe('')
    }
    expect(SIGNAL_TYPES).toHaveLength(14)
  })
  it('lists triggers before context', () => {
    expect(SIGNAL_TYPES.slice(0, 3)).toEqual(['request-spike', 'error-rate', 'memory-spike'])
    expect(SIGNAL_TYPES.at(-1)).toBe('log-errors')
  })
  it('gives the chart markers their shapes: ✕ OOM, ↻ restart, ◆ deploy, ▲ event', () => {
    expect([SIGNAL_META['oom-kill'].mark, SIGNAL_META['oom-kill'].glyph]).toEqual(['oom', '✕'])
    expect([SIGNAL_META.restart.mark, SIGNAL_META.crashloop.mark]).toEqual(['restart', 'restart'])
    expect([SIGNAL_META.deploy.mark, SIGNAL_META.deploy.glyph]).toEqual(['deploy', '◆'])
    expect(SIGNAL_META['k8s-event'].mark).toBe('event')
  })
  it('copes with a type a newer server sends', () => {
    expect(signalMeta('disk-pressure')).toMatchObject({ label: 'Disk pressure', lane: 'events', role: 'context' })
  })
  it('orders type chips triggers first, with counts', () => {
    const chips = typeChips({ types: ['deploy', 'memory-spike', 'request-spike'], counts: { 'memory-spike': 2, 'request-spike': 1, deploy: 1 } })
    expect(chips.map((c) => [c.type, c.count, c.trigger])).toEqual([
      ['memory-spike', 2, true],
      ['request-spike', 1, true],
      ['deploy', 1, false],
    ])
  })
})

describe('tags', () => {
  it('shows the app first, each service, then the label keys without repeating the app', () => {
    const chips = tagChips({ 'kubesentry.io/app': 'shop', service: 'api,api-canary', ingress: 'shop', 'app.kubernetes.io/name': 'shop', 'app.kubernetes.io/part-of': 'store' })
    expect(chips.map((c) => `${c.name}=${c.value}`)).toEqual(['app=shop', 'service=api', 'service=api-canary', 'ingress=shop', 'app.kubernetes.io/part-of=store'])
    expect(chips[0].filter).toEqual({ app: 'shop' })
    expect(chips[1].filter).toEqual({ service: 'api' })
    expect(tagChips(undefined)).toEqual([])
  })
  it('names the subject', () => {
    expect(subjectText({ kind: 'Deployment', namespace: 'shop', name: 'api' })).toBe('Deployment shop/api')
    expect(subjectText({ kind: 'Node', name: 'ip-10-0-1-5' })).toBe('Node ip-10-0-1-5')
  })
})

describe('the window cap', () => {
  it('reads the server cap, never above 24 hours', () => {
    expect(maxRangeHours(undefined)).toBe(24)
    expect(maxRangeHours({ incidents: { enabled: true, sources: {}, maxRangeHours: 12, logLeadSeconds: 300, logLagSeconds: 600 } })).toBe(12)
    expect(maxRangeHours({ incidents: { enabled: true, sources: {}, maxRangeHours: 72, logLeadSeconds: 0, logLagSeconds: 0 } })).toBe(24)
    expect(maxRangeHours({ incidents: { enabled: true, sources: {}, maxRangeHours: 0, logLeadSeconds: 0, logLagSeconds: 0 } })).toBe(24)
  })
  it('disables windows past the cap, saying why', () => {
    const c = windowChoicesFor(6)
    expect(c.map((x) => x.disabled)).toEqual([false, false, false, true, true])
    expect(c[4].reason).toBe('This server answers for at most 6 hours at a time.')
  })
  it('clamps a window from the address', () => {
    expect(clampWindow('6h')).toBe('6h')
    expect(clampWindow('48h')).toBe('24h')
    expect(clampWindow('24h', 12)).toBe('12h')
    expect(clampWindow('2h')).toBe('1h')
    expect(clampWindow('90m')).toBe('1h')
    expect(clampWindow(null)).toBe('24h')
    expect(clampWindow('junk', 6)).toBe('6h')
    expect(clampWindow('5m')).toBe('1h')
  })
  it('caps a brushed span at 24 hours, keeping the end', () => {
    expect(clampSpan([0, 30 * 3_600_000])).toEqual([6 * 3_600_000, 30 * 3_600_000])
    expect(clampSpan([0, 10])).toEqual([0, 10])
  })
})

describe('list filters', () => {
  const q = (s: string) => new URLSearchParams(s)
  it('reads every filter from the address, ignoring junk', () => {
    expect(readIncidentFilter(q('window=6h&severity=critical&state=open&type=request-spike,memory-spike&namespace=shop&owner=team-a&app=shop&service=api'))).toEqual({
      window: '6h',
      severity: 'critical',
      state: 'open',
      types: ['request-spike', 'memory-spike'],
      namespace: 'shop',
      owner: 'team-a',
      app: 'shop',
      service: 'api',
    })
    const junk = readIncidentFilter(q('severity=caution&state=maybe&type=Bad Type,ok-type&type=ok-type'))
    expect([junk.severity, junk.state, junk.types]).toEqual(['', '', ['ok-type']])
  })
  it('builds the whole query for setQuery, so other keys are never kept by accident', () => {
    const f = readIncidentFilter(q('window=3h&type=deploy'))
    expect(filterQuery(f)).toEqual({ window: '3h', severity: undefined, state: undefined, type: 'deploy', namespace: undefined, owner: undefined, app: undefined, service: undefined })
    expect(patchFilter(f, { types: toggleType(f.types, 'oom-kill'), severity: 'warning' })).toMatchObject({ type: 'deploy,oom-kill', severity: 'warning', window: '3h' })
    expect(toggleType(['a', 'b'], 'a')).toEqual(['b'])
  })
  it('round-trips through the address', () => {
    const f = readIncidentFilter(q('window=12h&severity=warning&type=alert,deploy&app=shop'))
    const p = new URLSearchParams()
    for (const [k, v] of Object.entries(filterQuery(f))) if (v) p.set(k, v)
    expect(readIncidentFilter(p)).toEqual(f)
  })
  it('asks the server with repeated type keys', () => {
    const f = readIncidentFilter(q('window=6h&type=request-spike,memory-spike&state=open&namespace=shop'))
    expect(incidentsPath(f)).toBe('/api/v1/incidents?window=6h&type=request-spike&type=memory-spike&state=open&namespace=shop')
    expect(isNarrowed(f)).toBe(true)
    expect(isNarrowed(readIncidentFilter(q('window=6h')))).toBe(false)
  })
})

describe('addresses', () => {
  it('encodes ids and passes the Overview link check', () => {
    expect(incidentHref('20261015T120000Z-abcdef012345')).toBe('#/incidents/20261015T120000Z-abcdef012345')
    expect(incidentHref('a b/c')).toBe('#/incidents/a%20b%2Fc')
    expect(safeHref(incidentHref('20261015T120000Z-abcdef012345'))).toBe('#/incidents/20261015T120000Z-abcdef012345')
    expect(safeHref('#/incidents/20261015T120000Z-abcdef012345')).toBeDefined()
    expect(bundlePath('x/y')).toBe('/api/v1/incidents/x%2Fy/bundle?format=ndjson')
  })
  it('builds the logs route, leaving out defaults', () => {
    expect(logsPath('i1', { from: T0, to: T0 + 5 * MIN, level: 'warn', q: 'timeout', source: 'auto', pod: 'api-1' })).toBe(
      '/api/v1/incidents/i1/logs?from=2026-10-15T12%3A00%3A00Z&to=2026-10-15T12%3A05%3A00Z&pod=api-1&level=warn&q=timeout',
    )
    expect(logsPath('i1', { source: 'cloudwatch', container: 'app', limit: 500 })).toBe('/api/v1/incidents/i1/logs?container=app&source=cloudwatch&limit=500')
  })
})

describe('the brushed range in the address', () => {
  const win: [number, number] = [T0, T0 + 60 * MIN]
  it('writes RFC 3339 to the second and reads it back', () => {
    expect(isoSeconds(T0 + 1499)).toBe('2026-10-15T12:00:01Z')
    const qr = rangeQuery([T0 + 10 * MIN, T0 + 20 * MIN])
    expect(qr).toEqual({ from: '2026-10-15T12:10:00Z', to: '2026-10-15T12:20:00Z' })
    expect(readRange(new URLSearchParams(qr as Record<string, string>), win)).toEqual([T0 + 10 * MIN, T0 + 20 * MIN])
    expect(rangeQuery(null)).toEqual({ from: undefined, to: undefined })
  })
  it('clamps to the window and drops a range outside it', () => {
    expect(readRange(new URLSearchParams(`from=${T0 - 99 * MIN}&to=${T0 + 5 * MIN}`), win)).toEqual([T0, T0 + 5 * MIN])
    expect(readRange(new URLSearchParams(`from=${T0 + 90 * MIN}&to=${T0 + 95 * MIN}`), win)).toBeNull()
    expect(readRange(new URLSearchParams('from=junk&to=2'), win)).toBeNull()
    expect(readRange(new URLSearchParams(''), win)).toBeNull()
    expect(readRange(new URLSearchParams(`from=${T0}&to=${T0 + MIN}`), undefined)).toBeNull()
  })
  it('reads the padded window', () => {
    expect(windowRange({ from: iso(0), to: iso(10) })).toEqual([T0, T0 + 10 * MIN])
    expect(windowRange({ from: iso(10), to: iso(0) })).toBeUndefined()
    expect(windowRange(undefined)).toBeUndefined()
  })
})

describe('spans and padding', () => {
  it('says spans briefly', () => {
    expect(shortSpan(45_000)).toBe('45 s')
    expect(shortSpan(5 * MIN)).toBe('5 min')
    expect(shortSpan(90 * MIN)).toBe('1 h 30 min')
    expect(shortSpan(120 * MIN)).toBe('2 h')
    expect(shortSpan(0)).toBe('0 min')
  })
  it('says how far logs and events reach past the incident', () => {
    const resolved = { start: iso(10), lastSignal: iso(40), end: iso(50), state: 'resolved' as const }
    expect(paddingText(resolved, undefined, { logLeadSeconds: 300, logLagSeconds: 600 })).toBe(
      'Logs and events include 5 min before it started and 10 min after it ended, to catch lines written after the fact.',
    )
    // Without /info, from the window.
    expect(paddingText(resolved, [T0 + 5 * MIN, T0 + 60 * MIN])).toContain('5 min before it started and 10 min after it ended')
    const open = { start: iso(10), lastSignal: iso(40), state: 'open' as const }
    expect(paddingText(open, undefined, { logLeadSeconds: 300, logLagSeconds: 600 })).toContain('10 min past its latest signal, up to now')
    expect(paddingText(open, undefined, { logLeadSeconds: 0, logLagSeconds: 0 })).toBeUndefined()
  })
  it('measures an incident, open ones to now', () => {
    expect(incidentDuration({ start: iso(0), end: iso(38), lastSignal: iso(30), state: 'resolved' })).toBe('38 min')
    expect(incidentDuration({ start: iso(0), lastSignal: iso(30), state: 'open' }, T0 + 125 * MIN)).toBe('2 h 5 min')
    expect(incidentDuration({ start: 'bad', lastSignal: iso(30), state: 'open' })).toBe('-')
  })
})

describe('sources', () => {
  it('reads each state, ok first, never by colour alone', () => {
    const rows = sourceRows({ 'requests:nginx': 'absent', 'logs:cloudwatch': 'error: AccessDenied', 'requests:app': 'ok', cloudtrail: 'forbidden', 'x:y': 'ok' })
    expect(rows.map((r) => [r.label, r.status, r.text])).toEqual([
      ['Requests (app metrics)', 'ok', 'ok'],
      ['X (y)', 'ok', 'ok'],
      ['CloudTrail', 'unknown', 'hidden from you'],
      ['Logs (CloudWatch)', 'warn', 'AccessDenied'],
      ['Requests (ingress-nginx)', 'unknown', 'not configured'],
    ])
    expect(sourceRows(undefined)).toEqual([])
  })
  it('says whether a kind of source answers', () => {
    const s = { 'requests:nginx': 'absent', 'requests:app': 'ok', 'logs:cloudwatch': 'absent' }
    expect(sourceUp(s, 'requests')).toBe(true)
    expect(sourceUp(s, 'logs')).toBe(false)
    expect(sourceUp(s, 'cloudtrail')).toBeUndefined()
  })
})

describe('mergeTimeline', () => {
  const detail: Pick<IncidentDetail, 'signals' | 'events' | 'audit'> = {
    signals: [
      sig({ id: 'metrics:request-spike:shop/api@1', type: 'request-spike', source: 'metrics', severity: 'critical', start: iso(20), title: 'api requests at 80/s' }),
      sig({ id: 'metrics:memory-spike:shop/api-1/app@1', type: 'memory-spike', source: 'metrics', severity: 'warning', start: iso(22), end: iso(30) }),
      sig({ id: 'view:deploy:Deployment/shop/api@7', type: 'deploy', start: iso(0), attrs: { images: 'app: v1 → v2' } }),
      sig({ id: 'events:uid-1#3', type: 'k8s-event', source: 'events', role: 'trigger', severity: 'warning', start: iso(25) }),
      sig({ id: 'events:uid-9#1', type: 'k8s-event', source: 'events', start: iso(26), title: 'event not in the list' }),
      sig({ id: 'audit:a1', type: 'audit-change', source: 'audit', start: iso(5) }),
      sig({ id: 'view:oom-kill:shop/api-1/app#2', type: 'oom-kill', severity: 'critical', start: iso(31) }),
    ],
    events: [
      {
        uid: 'uid-1',
        namespace: 'shop',
        type: 'Warning',
        reason: 'BackOff',
        message: 'Back-off restarting failed container',
        count: 3,
        firstSeen: iso(24),
        lastSeen: iso(28),
        regarding: { kind: 'Pod', namespace: 'shop', name: 'api-1' },
      },
      { uid: 'uid-2', type: 'Normal', reason: 'Pulled', message: 'Pulled image', count: 1, firstSeen: iso(1), lastSeen: iso(1), regarding: { kind: 'Pod', name: 'api-2' } },
    ],
    audit: [
      { auditID: 'a1', time: iso(5), stage: 'ResponseComplete', verb: 'patch', username: 'alice', actorKind: 'user', resource: 'deployments', namespace: 'shop', name: 'api', statusCode: 200 },
    ],
  }
  const items = mergeTimeline(detail)

  it('puts everything on one time axis, oldest first', () => {
    expect(items.map((i) => i.key)).toEqual([
      'signal:view:deploy:Deployment/shop/api@7',
      'event:uid-2',
      'audit:a1',
      'signal:metrics:request-spike:shop/api@1',
      'signal:metrics:memory-spike:shop/api-1/app@1',
      'event:uid-1',
      'signal:events:uid-9#1',
      'signal:view:oom-kill:shop/api-1/app#2',
    ])
  })
  it('shows a signal and the event it came from once, carrying the signal role and severity', () => {
    const ev = items.find((i) => i.key === 'event:uid-1')!
    expect(ev).toMatchObject({ lane: 'events', role: 'trigger', severity: 'warn', mark: 'event', end: T0 + 28 * MIN, title: 'BackOff: Back-off restarting failed container' })
    expect(ev.detail).toBe('Warning · Pod/api-1 · 3 times')
    expect(items.find((i) => i.key === 'audit:a1')).toMatchObject({ lane: 'audit', title: 'alice patch shop: deployments/api', detail: 'HTTP 200' })
    // A Normal event is not a chart marker.
    expect(items.find((i) => i.key === 'event:uid-2')!.mark).toBeUndefined()
  })
  it('marks conditions still going, and ended ones with their end', () => {
    expect(items.find((i) => i.type === 'request-spike')).toMatchObject({ ongoing: true, severity: 'crit', lane: 'spikes' })
    expect(items.find((i) => i.type === 'memory-spike')).toMatchObject({ end: T0 + 30 * MIN, severity: 'warn' })
    expect(items.find((i) => i.type === 'oom-kill')!.ongoing).toBeUndefined()
  })
  it('feeds the lanes and the chart markers', () => {
    expect(laneItems(items, 'changes').map((i) => i.detail)).toEqual(['app: v1 → v2'])
    expect(chartMarks(items).map((m) => m.kind)).toEqual(['deploy', 'event', 'event', 'oom'])
  })
  it('tells whether an item touches the brushed range', () => {
    const r: [number, number] = [T0 + 26 * MIN, T0 + 27 * MIN]
    expect(inRange({ t: T0 + 24 * MIN, end: T0 + 28 * MIN }, r)).toBe(true)
    expect(inRange({ t: T0 + 20 * MIN, ongoing: true }, r)).toBe(true)
    expect(inRange({ t: T0 + 5 * MIN }, r)).toBe(false)
    expect(inRange({ t: T0 }, null)).toBe(true)
  })
  it('shades spikes on their own chart', () => {
    const spans = spikeSpans(detail.signals, 'requests', T0 + 60 * MIN)
    expect(spans).toEqual([{ from: T0 + 20 * MIN, to: T0 + 60 * MIN, label: 'api requests at 80/s', severity: 'crit' }])
    expect(spikeSpans(detail.signals, 'errors', 0)).toEqual([])
  })
  it('explains signals by their attributes', () => {
    expect(signalDetail({ type: 'deploy', role: 'context', attrs: { images: 'app: v2 → v1', rollback: 'true' } })).toBe('app: v2 → v1 · rollback')
    expect(signalDetail({ type: 'scale', role: 'context', attrs: { from: '2', to: '6' } })).toBe('2 → 6 replicas')
    expect(signalDetail({ type: 'restart', role: 'trigger', count: 4 })).toBe('4 times')
    expect(signalDetail({ type: 'alert', role: 'trigger' })).toBeUndefined()
  })
  it('copes with an empty detail', () => {
    expect(mergeTimeline({ signals: [], events: [] })).toEqual([])
  })
})

describe('log levels', () => {
  it('normalises the many spellings', () => {
    expect(['ERROR', 'fatal', 'E', 'Warning', 'w', 'INFO', 'notice', 'trace', '', 'what'].map(normalLevel)).toEqual([
      'error', 'error', 'error', 'warn', 'warn', 'info', 'info', 'debug', '', '',
    ])
  })
  it('filters by a minimum level', () => {
    expect(atLeast('error', 'warn')).toBe(true)
    expect(atLeast('info', 'warn')).toBe(false)
    expect(atLeast('', 'info')).toBe(false)
    expect(atLeast('', '')).toBe(true)
  })
  it('marks errors and warnings by shape', () => {
    expect([levelGlyph('err'), levelGlyph('WARN'), levelGlyph('info')]).toEqual(['crit', 'warn', undefined])
  })
  it('counts lines and errors for the volume strip', () => {
    const v = logVolume(
      [
        { time: iso(1), level: 'error' },
        { time: iso(2), level: 'info' },
        { time: iso(8), level: 'ERROR' },
        { time: 'bad', level: 'error' },
      ],
      [T0, T0 + 10 * MIN],
      2,
    )
    expect(v).toEqual({ all: [2, 1], errors: [1, 1], max: 2 })
  })
})
