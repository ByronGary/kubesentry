import { describe, expect, it } from 'vitest'
import {
  filterPods,
  filterWorkloads,
  groupSecurity,
  imageSummary,
  matches,
  podStatusFilter,
  readiness,
  reasonStatus,
  securityPartial,
  securitySubjectHref,
  shortImage,
  splitSubject,
  splitWorkload,
  statusMatches,
  waitingReasons,
} from './inventory'
import type { PodSummary, SecurityFinding, WorkloadSummary } from './types'

const wl = (kind: WorkloadSummary['kind'], namespace: string, name: string, extra: Partial<WorkloadSummary> = {}): WorkloadSummary => ({
  kind, namespace, name, status: 'ok', detail: '', desired: 3, ready: 2, updated: 3, available: 2, pods: 3, restarts: 0,
  oomKilled: false, images: ['nginx:1.27'], created: '2026-01-01T00:00:00Z', ...extra,
})

describe('filterWorkloads', () => {
  const items = [
    wl('Deployment', 'shop', 'web', { status: 'warn' }),
    wl('StatefulSet', 'shop', 'db', { images: ['postgres:16'] }),
    wl('CronJob', 'ops', 'backup'),
  ]
  it('combines namespace, kind, status and search', () => {
    expect(filterWorkloads(items, { q: '', namespace: '', kind: '', status: '' })).toHaveLength(3)
    expect(filterWorkloads(items, { q: '', namespace: 'shop', kind: '', status: '' }).map((w) => w.name)).toEqual(['web', 'db'])
    expect(filterWorkloads(items, { q: '', namespace: '', kind: 'CronJob', status: '' }).map((w) => w.name)).toEqual(['backup'])
    expect(filterWorkloads(items, { q: '', namespace: '', kind: '', status: 'warn' }).map((w) => w.name)).toEqual(['web'])
    expect(filterWorkloads(items, { q: 'POSTGRES', namespace: '', kind: '', status: '' }).map((w) => w.name)).toEqual(['db'])
    expect(filterWorkloads(items, { q: 'shop/w', namespace: '', kind: '', status: '' }).map((w) => w.name)).toEqual(['web'])
  })
  it('reads "unhealthy" as critical or warning, as the Overview counts them', () => {
    const more = [...items, wl('Deployment', 'pay', 'api', { status: 'crit' }), wl('Job', 'pay', 'etl', { status: 'unknown' })]
    expect(filterWorkloads(more, { q: '', namespace: '', kind: '', status: 'unhealthy' }).map((w) => w.name)).toEqual(['web', 'api'])
    expect(statusMatches('', 'unknown')).toBe(true)
    expect(statusMatches('crit', 'warn')).toBe(false)
    expect(statusMatches('unhealthy', 'ok')).toBe(false)
  })
  it('tolerates a null image list', () => {
    expect(filterWorkloads([wl('Job', 'a', 'b', { images: null as never })], { q: 'x', namespace: '', kind: '', status: '' })).toEqual([])
  })
})

describe('readiness', () => {
  const now = Date.parse('2026-01-01T12:00:00Z')
  it('shows ready of desired', () => {
    expect(readiness(wl('Deployment', 'a', 'b'), now)).toEqual({ main: '2/3' })
  })
  it('shows schedule and last run for CronJobs', () => {
    expect(readiness(wl('CronJob', 'a', 'b', { schedule: '0 * * * *', lastScheduleTime: '2026-01-01T09:00:00Z' }), now)).toEqual({ main: '0 * * * *', sub: 'last run 3 hours ago' })
    expect(readiness(wl('CronJob', 'a', 'b', { schedule: '@daily', suspended: true }), now)).toEqual({ main: '@daily', sub: 'suspended, never run' })
  })
})

describe('shortImage', () => {
  it('drops the registry host and long digests', () => {
    expect(shortImage('postgres:16.4')).toBe('postgres:16.4')
    expect(shortImage('grafana/grafana:11.2.2')).toBe('grafana/grafana:11.2.2')
    expect(shortImage('602401143452.dkr.ecr.us-east-1.amazonaws.com/eks/coredns:v1.11.3')).toBe('…/eks/coredns:v1.11.3')
    expect(shortImage('localhost:5000/app:dev')).toBe('…/app:dev')
    expect(shortImage('localhost/app')).toBe('…/app')
    expect(shortImage('ghcr.io/acme/web@sha256:' + 'a'.repeat(64))).toBe('…/acme/web@sha256:aaaaaaaaaaaa…')
  })
})

describe('imageSummary', () => {
  it('returns the first image and a count of the rest', () => {
    expect(imageSummary(['a', 'b', 'c'])).toEqual({ first: 'a', more: 2 })
    expect(imageSummary([])).toEqual({ first: '-', more: 0 })
    expect(imageSummary(null)).toEqual({ first: '-', more: 0 })
  })
})

const sf = (check: string, subject: string, extra: Partial<SecurityFinding> = {}): SecurityFinding => ({
  id: `${check}/${subject}`, category: 'pod', check, severity: 'warn', title: check, subject, subjectKind: 'Deployment',
  detail: '', system: false, ...extra,
})

describe('security subjects', () => {
  it('splits namespaced and cluster-scoped names', () => {
    expect(splitSubject('shop/web')).toEqual({ namespace: 'shop', name: 'web' })
    expect(splitSubject('cluster-admin-binding')).toEqual({ namespace: '', name: 'cluster-admin-binding' })
    expect(splitSubject('web', 'shop')).toEqual({ namespace: 'shop', name: 'web' })
  })
  it('links pods and workloads only', () => {
    expect(securitySubjectHref(sf('privileged', 'shop/web-1', { subjectKind: 'Pod' }))).toBe('#/pods/shop/web-1')
    expect(securitySubjectHref(sf('privileged', 'shop/web', { subjectKind: 'StatefulSet', namespace: 'shop' }))).toBe('#/workloads?namespace=shop&q=web')
    expect(securitySubjectHref(sf('cluster-admin', 'alice', { subjectKind: 'User' }))).toBeUndefined()
    expect(securitySubjectHref(sf('nodeport', 'shop/web', { subjectKind: 'Service' }))).toBeUndefined()
  })
})

describe('groupSecurity', () => {
  const all = [
    sf('run-as-root', 'shop/b'),
    sf('run-as-root', 'shop/a'),
    sf('privileged', 'shop/z', { severity: 'crit' }),
    sf('privileged', 'kube-system/proxy', { severity: 'crit', system: true }),
    sf('cluster-admin', 'bob', { severity: 'crit', category: 'rbac', subjectKind: 'User' }),
    sf('no-memory-limit', 'shop/a', { severity: 'info' }),
  ]
  const none = { category: '', severity: '', q: '', system: false, check: '' }
  it('groups by check, worst and biggest first, hiding system and info findings by default', () => {
    const g = groupSecurity(all, none)
    expect(g.map((x) => [x.check, x.findings.length])).toEqual([['cluster-admin', 1], ['privileged', 1], ['run-as-root', 2]])
    expect(g[2].findings.map((f) => f.subject)).toEqual(['shop/a', 'shop/b'])
    expect(groupSecurity(all, { ...none, severity: 'all' }).map((x) => x.check)).toEqual(['cluster-admin', 'privileged', 'run-as-root', 'no-memory-limit'])
    // Picking a single check shows its info findings too.
    expect(groupSecurity(all, { ...none, check: 'no-memory-limit' }).map((x) => x.findings.length)).toEqual([1])
  })
  it('applies each filter', () => {
    expect(groupSecurity(all, { ...none, system: true }).find((x) => x.check === 'privileged')!.findings).toHaveLength(2)
    expect(groupSecurity(all, { ...none, category: 'rbac' }).map((x) => x.check)).toEqual(['cluster-admin'])
    expect(groupSecurity(all, { ...none, severity: 'info' }).map((x) => x.check)).toEqual(['no-memory-limit'])
    expect(groupSecurity(all, { ...none, check: 'run-as-root', q: 'shop/b' }).map((x) => x.findings.length)).toEqual([1])
  })
  it('matches search text case-insensitively', () => {
    expect(matches('WEB', 'shop/web')).toBe(true)
    expect(matches('  ', 'x')).toBe(true)
    expect(matches('nope', 'x', undefined)).toBe(false)
  })
})

describe('securityPartial', () => {
  const f = (system = false): SecurityFinding => ({ id: String(Math.random()), category: 'pod', check: 'x', severity: 'warn', title: 'x', subject: 's', subjectKind: 'Pod', detail: '', system })
  it('is false when every counted finding came back (servers without summaries)', () => {
    expect(securityPartial({ counts: { warn: 2 }, findings: [f(), f(), f(true)] })).toBe(false)
    expect(securityPartial({ counts: {}, findings: [] })).toBe(false)
  })
  it('is true when the server says there is more or counts exceed what came back', () => {
    expect(securityPartial({ counts: { warn: 2 }, findings: [f(), f()], continue: 'abc' })).toBe(true)
    expect(securityPartial({ counts: { crit: 150, warn: 5000 }, findings: Array.from({ length: 200 }, () => f()) })).toBe(true)
  })
})

describe('pods and workloads', () => {
  const pod = (name: string, extra: Partial<PodSummary> = {}): PodSummary => ({ namespace: 'shop', name, phase: 'Running', containers: 1, restarts: 0, oomKilled: false, ...extra })
  it('searches pods by name, node, owner and reason', () => {
    const items = [pod('web-1', { node: 'ip-10-0-1-1', workload: 'Deployment/web' }), pod('db-0', { reason: 'CrashLoopBackOff', workload: 'StatefulSet/db' })]
    expect(filterPods(items, 'crashloop').map((p) => p.name)).toEqual(['db-0'])
    expect(filterPods(items, 'ip-10-0-1').map((p) => p.name)).toEqual(['web-1'])
    expect(filterPods(items, 'statefulset/').map((p) => p.name)).toEqual(['db-0'])
    expect(filterPods(items, '')).toBe(items)
  })
  it('filters pods by status from the address: failing or pending', () => {
    const items = [
      pod('web-1'),
      pod('db-0', { reason: 'CrashLoopBackOff' }),
      pod('cache-0', { oomKilled: true }),
      pod('evicted', { phase: 'Failed', reason: 'Evicted' }),
      pod('new-0', { phase: 'Pending', reason: 'ContainerCreating' }),
    ]
    expect(filterPods(items, '', 'failing').map((p) => p.name)).toEqual(['db-0', 'cache-0', 'evicted'])
    expect(filterPods(items, '', 'pending').map((p) => p.name)).toEqual(['new-0'])
    expect(filterPods(items, 'db', 'failing').map((p) => p.name)).toEqual(['db-0'])
    expect(podStatusFilter('failing')).toBe('failing')
    expect(podStatusFilter('bogus')).toBe('')
    expect(podStatusFilter(null)).toBe('')
  })
  it('rates reasons: crash loops and image errors are critical, the rest are warnings', () => {
    expect(reasonStatus('CrashLoopBackOff')).toBe('crit')
    expect(reasonStatus('ImagePullBackOff')).toBe('crit')
    expect(reasonStatus('ErrImagePull')).toBe('crit')
    expect(reasonStatus('CreateContainerConfigError')).toBe('crit')
    expect(reasonStatus('ContainerCreating')).toBe('warn')
    expect(reasonStatus('Unschedulable')).toBe('warn')
    expect(reasonStatus(undefined)).toBeUndefined()
  })
  it('lists waiting reasons, most pods first', () => {
    expect(waitingReasons({ ImagePullBackOff: 1, CrashLoopBackOff: 3, Zero: 0 })).toEqual(['CrashLoopBackOff ×3', 'ImagePullBackOff ×1'])
    expect(waitingReasons(undefined)).toEqual([])
  })
  it('splits owner references', () => {
    expect(splitWorkload('Deployment/web')).toEqual({ kind: 'Deployment', name: 'web' })
    expect(splitWorkload('Rollout/a/b')).toEqual({ kind: 'Rollout', name: 'a/b' })
    expect(splitWorkload('web')).toBeUndefined()
    expect(splitWorkload('Deployment/')).toBeUndefined()
    expect(splitWorkload(undefined)).toBeUndefined()
  })
})
