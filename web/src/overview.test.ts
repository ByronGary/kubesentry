import { describe, expect, it } from 'vitest'
import {
  activityCounts,
  attentionRows,
  healthItems,
  historySpan,
  isFiltered,
  kindLabel,
  latestRows,
  namespaceOptions,
  overviewPath,
  podReasons,
  poolRows,
  readFilter,
  safeHref,
  scopeText,
  tiles,
  wasteLines,
} from './overview'
import type { AuditEvent, OverviewResponse } from './types'

const now = Date.parse('2026-10-12T12:00:00Z')
const ago = (min: number) => new Date(now - min * 60_000).toISOString()

function overview(patch: Partial<OverviewResponse> = {}): OverviewResponse {
  return {
    version: 7,
    builtAt: ago(0),
    ageSeconds: 2,
    scope: { namespaces: 48 },
    health: { prometheus: 'ok', auditStore: 'ok', cloudwatchLagSeconds: 34, agents: { reporting: 503, stale: 3 } },
    nodes: {
      total: 506,
      ready: 504,
      notReady: 2,
      cordoned: 1,
      pools: [
        { name: 'ng-general', kind: 'nodegroup', nodes: 320, cpuRequestedPct: 82.4, memRequestedPct: 61 },
        { name: 'fp-batch', kind: 'fargate', nodes: 4 },
      ],
      zones: [
        { name: 'a', nodes: 170 },
        { name: 'b', nodes: 336 },
      ],
    },
    pods: { total: 9547, running: 9542, pending: 2, failing: 3, byReason: { CrashLoopBackOff: 2, ImagePullBackOff: 1, Zero: 0 } },
    workloads: { total: 2494, unhealthy: 4 },
    certificates: { total: 117, expiringSoon: 14, notReady: 9, issuerMissing: 0 },
    security: { crit: 3, warn: 41, newSince24h: 1 },
    attention: [],
    activity: { windowHours: 24, exec: 9, execProduction: 2, secretReads: 14, rbacChanges: 6, denied: 1, latest: [] },
    waste: { unusedPVCs: 41, monthlyUSD: 312.4, usageBilled: 3 },
    owners: ['team-payments'],
    badges: { workloads: { count: 4, severity: 'warn' } },
    history: { stepSeconds: 300, start: ago(24 * 60), series: { unhealthyWorkloads: Array.from({ length: 288 }, (_, i) => (i > 280 ? 4 : 1)) } },
    ...patch,
  }
}

describe('filters', () => {
  it('reads the filter from the address and builds the API path', () => {
    const f = readFilter(new URLSearchParams('owner=team-payments&namespace=%20shop%20'))
    expect(f).toEqual({ namespace: 'shop', owner: 'team-payments' })
    expect(isFiltered(f)).toBe(true)
    expect(overviewPath(f)).toBe('/api/v1/overview?namespace=shop&owner=team-payments')
    expect(overviewPath({ namespace: '', owner: '' })).toBe('/api/v1/overview')
    expect(isFiltered(readFilter(new URLSearchParams('')))).toBe(false)
  })
  it('says what the numbers cover', () => {
    expect(scopeText({ namespaces: 48 })).toBe('All 48 namespaces you can see')
    expect(scopeText({ namespaces: 1 })).toBe('The 1 namespace you can see')
    expect(scopeText({ namespaces: 1, namespace: 'shop' })).toBe('Namespace shop')
    expect(scopeText({ namespaces: 4, owner: 'team-payments' })).toBe('team-payments: 4 namespaces')
    expect(scopeText({ namespaces: 1, owner: 'team-payments', namespace: 'pay' })).toBe('Namespace pay, owned by team-payments')
  })
  it('collects namespace choices from every source, sorted and unique', () => {
    expect(namespaceOptions([undefined, ['shop', 'data']], [{ severity: 'warn', kind: 'x', namespace: 'pay', name: 'a', title: '', href: '#/' }], 'zeta')).toEqual(['data', 'pay', 'shop', 'zeta'])
    expect(namespaceOptions([], [], '')).toEqual([])
  })
})

describe('safeHref', () => {
  it('follows in-app hash routes only', () => {
    expect(safeHref('#/workloads?status=crit&namespace=shop')).toBe('#/workloads?status=crit&namespace=shop')
    expect(safeHref('javascript:alert(1)')).toBeUndefined()
    expect(safeHref('https://evil.example/#/x')).toBeUndefined()
    expect(safeHref('//evil.example')).toBeUndefined()
    expect(safeHref('#/x y')).toBeUndefined()
    expect(safeHref('')).toBeUndefined()
    expect(safeHref(undefined)).toBeUndefined()
  })
})

describe('healthItems', () => {
  it('reads the strip: data age, Prometheus, audit store, CloudWatch lag, agents', () => {
    expect(healthItems(overview())).toEqual([
      { key: 'data', status: 'ok', text: 'Data 2 s old' },
      { key: 'prometheus', status: 'ok', text: 'Prometheus', href: '#/memory' },
      { key: 'audit', status: 'ok', text: 'Audit store' },
      { key: 'cloudwatch', status: 'ok', text: 'CloudWatch lag 34 s' },
      { key: 'agents', status: 'warn', text: 'Agents 503 reporting, 3 stale', href: '#/agents' },
    ])
  })
  it('flags stale data, missing sources and a long CloudWatch lag; leaves out what the server does not send', () => {
    const items = healthItems({ ageSeconds: 300, health: { prometheus: 'unavailable', auditStore: 'degraded', cloudwatchLagSeconds: 2400 } })
    expect(items.map((i) => [i.key, i.status, i.text])).toEqual([
      ['data', 'warn', 'Data 5 minutes old'],
      ['prometheus', 'warn', 'Prometheus unavailable'],
      ['audit', 'warn', 'Audit store degraded'],
      ['cloudwatch', 'crit', 'CloudWatch lag 40 minutes'],
    ])
    const none = healthItems({ ageSeconds: 1, health: { prometheus: 'none', auditStore: 'none' } })
    expect(none.map((i) => [i.key, i.status, i.text])).toEqual([
      ['data', 'ok', 'Data 1 s old'],
      ['prometheus', 'unknown', 'No Prometheus'],
      ['audit', 'unknown', 'No audit log'],
    ])
  })
})

describe('tiles', () => {
  it('shows every tile for a cluster admin, in the wireframe order', () => {
    const t = tiles(overview())
    expect(t.map((x) => x.key)).toEqual(['nodes', 'pods', 'workloads', 'certificates', 'security'])
    const nodes = t[0]
    expect(nodes).toMatchObject({ total: 506, totalHref: '#/nodes', status: 'crit', foot: '2 pools · 2 zones' })
    expect(nodes.lines.map((l) => [l.text, l.count, l.status])).toEqual([
      ['ready', 504, undefined],
      ['not ready', 2, 'crit'],
      ['cordoned', 1, 'warn'],
    ])
  })
  it('keeps the nodes tile as "not visible to you" when nodes is null, and drops certificates when cert-manager is absent', () => {
    const t = tiles(overview({ nodes: null, certificates: null }))
    expect(t.map((x) => x.key)).toEqual(['nodes', 'pods', 'workloads', 'security'])
    expect(t[0]).toMatchObject({ restricted: true, lines: [], status: 'unknown' })
    expect(t[0].total).toBeUndefined()
  })
  it('links every number to the page that explains it, carrying the namespace where the page understands it', () => {
    const t = tiles(overview(), { namespace: 'shop', owner: 'team-payments' })
    const pods = t.find((x) => x.key === 'pods')!
    expect(pods.totalHref).toBe('#/pods?namespace=shop')
    expect(pods.lines.map((l) => l.href)).toEqual(['#/pods?namespace=shop', '#/pods?namespace=shop&status=pending', '#/pods?namespace=shop&status=failing'])
    expect(pods.extras.map((e) => [e.text, e.count, e.href])).toEqual([
      ['CrashLoopBackOff', 2, '#/pods?namespace=shop&q=CrashLoopBackOff'],
      ['ImagePullBackOff', 1, '#/pods?namespace=shop&q=ImagePullBackOff'],
    ])
    const wl = t.find((x) => x.key === 'workloads')!
    expect(wl.lines[0]).toMatchObject({ count: 4, status: 'warn', href: '#/workloads?namespace=shop&status=unhealthy' })
    expect(t.find((x) => x.key === 'certificates')!.lines[0].href).toBe('#/certificates?status=unhealthy')
    const sec = t.find((x) => x.key === 'security')!
    expect(sec.lines.map((l) => l.href)).toEqual(['#/security?severity=crit', '#/security?severity=warn'])
    expect(sec.foot).toBe('+1 new since 24h')
    expect(sec.total).toBe(44)
  })
  it('marks only counts that need attention, with the badge severity for workloads', () => {
    const quiet = tiles(overview({ pods: { total: 5, running: 5, pending: 0, failing: 0, byReason: {} }, workloads: { total: 3, unhealthy: 0 }, badges: {} }))
    const pods = quiet.find((x) => x.key === 'pods')!
    expect(pods.status).toBe('ok')
    expect(pods.lines.every((l) => l.status === undefined)).toBe(true)
    const crit = tiles(overview({ badges: { workloads: { count: 4, severity: 'crit' } } }))
    expect(crit.find((x) => x.key === 'workloads')!.status).toBe('crit')
  })
  it('adds a sparkline only with at least two points of history, and says how long it covers', () => {
    const t = tiles(overview())
    expect(t.find((x) => x.key === 'workloads')!.spark).toMatchObject({ label: 'unhealthy workloads', span: '24h' })
    expect(t.find((x) => x.key === 'pods')!.spark).toBeUndefined()
    const fresh = tiles(overview({ history: { stepSeconds: 300, start: ago(5), series: { unhealthyWorkloads: [1] } } }))
    expect(fresh.find((x) => x.key === 'workloads')!.spark).toBeUndefined()
    expect(historySpan({ stepSeconds: 300, start: '', series: {} }, 8)).toBe('40 min')
    expect(historySpan(undefined, 8)).toBe('')
  })
  it('leaves "new since 24h" out when the server does not send it', () => {
    const t = tiles(overview({ security: { crit: 0, warn: 0 } }))
    const sec = t.find((x) => x.key === 'security')!
    expect(sec.foot).toBeUndefined()
    expect(sec.status).toBe('ok')
  })
  it('sorts pod reasons, most pods first, skipping zeros', () => {
    expect(podReasons({ B: 1, A: 1, C: 5, Z: 0 })).toEqual([['C', 5], ['A', 1], ['B', 1]])
    expect(podReasons(undefined)).toEqual([])
  })
})

describe('attentionRows', () => {
  it('shows severity, subject, owner, relative age and a safe link, top 10', () => {
    const items = Array.from({ length: 12 }, (_, i) => ({
      severity: (i === 0 ? 'crit' : 'warn') as 'crit' | 'warn',
      kind: i === 0 ? 'crashloop' : 'pod-security',
      namespace: i === 1 ? undefined : 'payments',
      name: `w${i}`,
      title: 'CrashLoopBackOff on 3 pods',
      owner: i === 0 ? 'team-payments' : '',
      since: i === 0 ? ago(14) : undefined,
      href: i === 2 ? 'javascript:alert(1)' : `#/workloads?q=w${i}`,
    }))
    const rows = attentionRows(items, now)
    expect(rows).toHaveLength(10)
    expect(rows[0]).toMatchObject({ severity: 'crit', kind: 'Crash loop', subject: 'payments/w0', owner: 'team-payments', age: '14 minutes ago', href: '#/workloads?q=w0' })
    expect(rows[1]).toMatchObject({ subject: 'w1', kind: 'Pod security', owner: undefined, age: undefined })
    expect(rows[2].href).toBeUndefined()
    expect(attentionRows(undefined)).toEqual([])
  })
  it('labels unknown kinds from their id', () => {
    expect(kindLabel('cert-expiring')).toBe('Certificate')
    expect(kindLabel('host_path')).toBe('Host path')
    expect(kindLabel('')).toBe('Finding')
  })
})

describe('poolRows', () => {
  it('rounds requested shares, links to the pool on the Nodes page, and marks Fargate as not metered', () => {
    expect(poolRows(overview().nodes!.pools)).toEqual([
      { name: 'ng-general', kind: 'Node group', nodes: 320, metered: true, cpu: 82, mem: 61, href: '#/nodes?q=ng-general' },
      { name: 'fp-batch', kind: 'Fargate', nodes: 4, metered: false, cpu: undefined, mem: undefined, href: '#/nodes?q=fp-batch' },
    ])
    expect(poolRows(undefined)).toEqual([])
  })
})

describe('sensitive activity', () => {
  it('counts by tag, links to Activity filtered by it, and calls out exec into production', () => {
    const c = activityCounts(overview().activity!)
    expect(c.map((x) => [x.label, x.count, x.href, x.highlight ?? false])).toEqual([
      ['exec into production', 2, '#/activity?tag=exec', true],
      ['exec sessions', 9, '#/activity?tag=exec', false],
      ['secret reads', 14, '#/activity?tag=secret-access', false],
      ['RBAC changes', 6, '#/activity?tag=rbac-change', false],
      ['denied request', 1, '#/activity?tag=denied', false],
    ])
    const week = activityCounts({ ...overview().activity!, windowHours: 168, execProduction: 0 })
    expect(week[0]).toMatchObject({ href: '#/activity?since=168h&tag=exec', highlight: false })
    // A window the Activity page has no period for keeps its default.
    expect(activityCounts({ ...overview().activity!, windowHours: 12 })[2].href).toBe('#/activity?tag=secret-access')
  })
  it('lists the latest events, linking to Activity for that user and tag', () => {
    const e: AuditEvent = {
      auditID: 'a1',
      time: ago(3),
      stage: 'ResponseComplete',
      verb: 'create',
      username: 'alice@corp.example',
      actorKind: 'user',
      resource: 'pods',
      subresource: 'exec',
      namespace: 'prod',
      name: 'api-7f',
      statusCode: 101,
      tags: ['exec'],
    }
    expect(latestRows([e, { ...e, auditID: 'a2', subresource: undefined, verb: 'get', resource: 'secrets', tags: ['denied', 'secret-access'], arn: 'arn:aws:sts::1:assumed-role/x/bob', sessionName: 'bob' }], now)).toEqual([
      { key: 'a1:ResponseComplete:0', who: 'alice@corp.example', what: 'exec', target: 'prod: pods/exec/api-7f', age: '3 minutes ago', tag: 'exec', href: '#/activity?user=alice%40corp.example&tag=exec' },
      { key: 'a2:ResponseComplete:1', who: 'bob', what: 'get', target: 'prod: secrets/api-7f', age: '3 minutes ago', tag: 'secret-access', href: '#/activity?user=alice%40corp.example&tag=secret-access' },
    ])
  })
})

describe('wasteLines', () => {
  it('sums only priced claims and names usage-billed ones separately', () => {
    expect(wasteLines({ unusedPVCs: 41, monthlyUSD: 312.4, usageBilled: 3 })).toEqual([
      { key: 'unused', text: '41 unused volume claims, about $312 a month', href: '#/storage' },
      { key: 'usage', text: '3 claims on EFS or FSx, billed by usage and not estimated', href: '#/storage' },
    ])
    expect(wasteLines({ unusedPVCs: 1, monthlyUSD: 0, usageBilled: 0 })).toEqual([{ key: 'unused', text: '1 unused volume claim', href: '#/storage' }])
    expect(wasteLines({ unusedPVCs: 0, monthlyUSD: 0, usageBilled: 0 })).toEqual([])
  })
})
