import { describe, expect, it } from 'vitest'
import { activityFindings, certFindings, memoryFindings, nothingFoundText, oomFindings, rank, securityFindings, volumeFindings, workloadHref } from './findings'
import type { AuditEvent, CertificatesResponse, CertSummary, IssuerSummary, OOMResponse, SecurityFinding, SecurityResponse } from './types'

const MiB = 1 << 20
const leak = (pod: string, ttl?: number) => ({
  namespace: 'shop', pod, container: 'app', segments: 2, leakySegments: 2,
  slopeBytesPerHour: 20 * MiB, r2: 0.95, currentBytes: 300 * MiB,
  limitBytes: ttl === undefined ? undefined : 512 * MiB, timeToLimitHours: ttl,
  confidence: 'high' as const, oomKilled: false,
})
const oom = (leaks: ReturnType<typeof leak>[]): OOMResponse => ({ window: '24h', metricsAvailable: true, events: [], leaks })

describe('memoryFindings', () => {
  it('marks near-term exhaustion critical and unlimited growth a warning', () => {
    const f = memoryFindings(oom([leak('a', 2), leak('b', 30), leak('c')]))
    expect(f.map((x) => x.severity)).toEqual(['crit', 'warn', 'warn'])
    expect(f[2].sentence).toContain('no memory limit')
  })
})

describe('oomFindings', () => {
  it('is critical and links to the pod', () => {
    const f = oomFindings({
      window: '24h', metricsAvailable: true, leaks: [],
      events: [{ namespace: 'a b', pod: 'p', container: 'c', restartCount: 1, lastOOMAt: '2026-01-01T10:00:00Z', exitCode: 137 }],
    }, Date.parse('2026-01-01T12:00:00Z'))
    expect(f[0].severity).toBe('crit')
    expect(f[0].sentence).toContain('2 hours ago')
    expect(f[0].sentence).toContain('1 restart.')
    expect(f[0].href).toBe('#/pods/a%20b/p')
  })
})

describe('volumeFindings', () => {
  it('is empty when nothing is unused', () => {
    expect(volumeFindings({ count: 0, totalEstMonthlyCostUSD: 0, items: [] })).toEqual([])
    expect(volumeFindings(undefined)).toEqual([])
  })
  it('summarises cost', () => {
    const f = volumeFindings({ count: 4, totalEstMonthlyCostUSD: 42.5, items: [] })
    expect(f[0].sentence).toContain('4 volume claims are')
    expect(f[0].sentence).toContain('$42.50')
    expect(f[0].href).toBe('#/storage')
  })
})

describe('activityFindings', () => {
  const ev = (user: string, tags: string[]): AuditEvent => ({
    auditID: user + tags.join(), time: '2026-01-01T10:00:00Z', stage: 'ResponseComplete', verb: 'create',
    username: user, actorKind: 'user', statusCode: 200, tags,
  })
  it('only surfaces interesting tags and names who did it', () => {
    const f = activityFindings([ev('alice', ['exec']), ev('bob', ['exec']), ev('carol', ['delete'])])
    expect(f).toHaveLength(1)
    expect(f[0].sentence).toBe('alice, bob opened 2 shell or exec sessions in pods.')
  })
})

describe('rank', () => {
  it('orders by severity then urgency', () => {
    const f = rank([
      ...memoryFindings(oom([leak('slow', 30), leak('fast', 2)])),
      ...volumeFindings({ count: 1, totalEstMonthlyCostUSD: 5, items: [] }),
    ])
    expect(f.map((x) => x.id)).toEqual(['leak:shop/fast/app', 'leak:shop/slow/app', 'volumes:unused'])
  })
})

const sec = (check: string, subject: string, severity: SecurityFinding['severity'], extra: Partial<SecurityFinding> = {}): SecurityFinding => ({
  id: `${check}/${subject}`, category: 'pod', check, severity, title: check === 'privileged' ? 'Privileged container' : check,
  subject, subjectKind: 'Deployment', detail: '', system: false, ...extra,
})
const secResp = (findings: SecurityFinding[]): SecurityResponse => ({ counts: {}, findings, namespaces: [] })

describe('securityFindings', () => {
  it('folds each check into one line naming the subjects', () => {
    const f = securityFindings(secResp([
      sec('privileged', 'shop/cache', 'crit'),
      sec('privileged', 'data/ml-trainer', 'crit'),
      sec('privileged', 'kube-system/kube-proxy', 'crit', { system: true }),
      sec('no-memory-limit', 'shop/web', 'info'),
    ]))
    expect(f).toHaveLength(1)
    expect(f[0]).toMatchObject({
      id: 'security:privileged', severity: 'crit', category: 'Security', subject: 'Privileged container',
      sentence: '2 workloads run privileged containers: data/ml-trainer, shop/cache.',
      href: '#/security?check=privileged',
    })
  })
  it('uses the worst severity, singular wording and a fallback for unknown checks', () => {
    const f = securityFindings(secResp([
      sec('cluster-admin', 'alice', 'crit', { category: 'rbac', subjectKind: 'User' }),
      sec('mystery', 'shop/x', 'warn', { title: 'Odd thing' }),
    ]))
    expect(f.find((x) => x.id === 'security:cluster-admin')!.sentence).toBe('1 subject is bound to cluster-admin: alice.')
    expect(f.find((x) => x.id === 'security:cluster-admin')!.meta).toBe('RBAC')
    expect(f.find((x) => x.id === 'security:mystery')!.sentence).toBe('Odd thing: 1 object: shop/x.')
    expect(securityFindings(undefined)).toEqual([])
  })
  it('gives a lower bound when built from a partial summary', () => {
    const f = securityFindings(secResp([sec('privileged', 'shop/cache', 'crit')]), true)
    expect(f[0].sentence).toBe('At least 1 workload runs privileged containers: shop/cache.')
  })
})

const cert = (name: string, status: CertSummary['status'], extra: Partial<CertSummary> = {}): CertSummary => ({
  namespace: 'shop', name, secretName: name + '-tls', dnsNames: [], issuerKind: 'ClusterIssuer', issuerName: 'letsencrypt',
  ready: 'True', status, detail: '', ...extra,
})
const issuer = (name: string, status: IssuerSummary['status'], extra: Partial<IssuerSummary> = {}): IssuerSummary => ({
  kind: 'ClusterIssuer', name, type: 'acme', ready: 'True', certificates: 3, status, detail: '', ...extra,
})
const certs = (c: CertSummary[], i: IssuerSummary[] = []): CertificatesResponse => ({ installed: true, certificates: c, issuers: i, requests: [] })

describe('certFindings', () => {
  it('lists failing and expiring certificates and issuers', () => {
    const f = certFindings(certs(
      [cert('ok', 'ok'), cert('soon', 'warn', { expiresInHours: 100, detail: 'expires in 4 days' }), cert('gone', 'crit', { expiresInHours: -48 })],
      [issuer('vault', 'crit', { detail: 'Vault is sealed' }), issuer('fine', 'ok')],
    ))
    expect(f.map((x) => x.id).sort()).toEqual(['cert:shop/gone', 'cert:shop/soon', 'issuer:ClusterIssuer/vault'])
    expect(f.every((x) => x.category === 'Certificates')).toBe(true)
    const soon = f.find((x) => x.id === 'cert:shop/soon')!
    expect(soon.sentence).toBe('Expires in 4 days.')
    expect(soon.meta).toBe('expires in 4 days')
    expect(f.find((x) => x.id === 'cert:shop/gone')!.sentence).toBe('Expired 2 days ago.')
    expect(f.find((x) => x.id === 'issuer:ClusterIssuer/vault')!.sentence).toBe('Vault is sealed.')
  })
  it('adds the issuer condition message, shortened', () => {
    const f = certFindings(certs([], [issuer('vault', 'crit', { detail: 'Not ready', message: 'Failed to init Vault client: ' + 'x'.repeat(300) })]))
    expect(f[0].sentence.startsWith('Not ready: Failed to init Vault client: xxx')).toBe(true)
    expect(f[0].sentence.endsWith('…')).toBe(true)
    expect(f[0].sentence.length).toBeLessThan(200)
    const g = certFindings(certs([], [issuer('vault', 'crit', { detail: 'Not ready: Vault sealed.', message: 'Vault sealed' })]))
    expect(g[0].sentence).toBe('Not ready: Vault sealed.')
    expect(f.every((x) => x.href.startsWith('#/certificates'))).toBe(true)
  })
  it('is empty without cert-manager', () => {
    expect(certFindings({ installed: false, certificates: [], issuers: [], requests: [] })).toEqual([])
    expect(certFindings(undefined)).toEqual([])
  })
})

describe('rank across categories', () => {
  it('puts security and certificates between memory and volumes', () => {
    const f = rank([
      ...volumeFindings({ count: 1, totalEstMonthlyCostUSD: 5, items: [] }),
      ...certFindings(certs([cert('soon', 'warn', { expiresInHours: 100 })])),
      ...securityFindings(secResp([sec('host-path', 'shop/a', 'warn')])),
      ...memoryFindings(oom([leak('slow', 30)])),
    ])
    expect(f.map((x) => x.category)).toEqual(['Memory', 'Security', 'Certificates', 'Volumes'])
  })
})

describe('workloadHref', () => {
  it('filters the workloads page', () => {
    expect(workloadHref('data', 'ml trainer')).toBe('#/workloads?namespace=data&q=ml+trainer')
    expect(workloadHref('', '')).toBe('#/workloads')
  })
})

describe('nothingFoundText', () => {
  it('names only what was checked', () => {
    expect(nothingFoundText({ leaks: true, security: true, certs: true, activity: true }, 'in the last 24 hours')).toBe(
      'No OOM kills, leaking containers, security risks, failing certificates, unused volumes or notable activity in the last 24 hours.',
    )
    // Prometheus down and the audit store busy: neither leaks nor activity is claimed.
    expect(nothingFoundText({ leaks: false, security: false, certs: false, activity: false }, 'recently')).toBe('No OOM kills or unused volumes recently.')
    expect(nothingFoundText({ leaks: true, security: false, certs: true, activity: false }, 'in the last 6 hours (all the history Prometheus has)')).toBe(
      'No OOM kills, leaking containers, failing certificates or unused volumes in the last 6 hours (all the history Prometheus has).',
    )
  })
})
