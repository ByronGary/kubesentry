import { describe, expect, it } from 'vitest'
import { busiestNamespace, can, chooseMapNamespace, hiddenNote, isScoped, missingCapabilities, namesOnlyNote, seesNothing, visibleNav, type NavItem } from './access'
import type { Info } from './types'

const base: Info = { demo: false, metrics: true, audit: true, processes: true, inventory: true, certs: true }

describe('can', () => {
  it('allows everything when the server sends no capabilities (older or unscoped servers)', () => {
    expect(can(base, 'nodes')).toBe(true)
    expect(can(undefined, 'clusterAudit')).toBe(true)
    expect(isScoped(base)).toBe(false)
  })
  it('follows the capabilities when present; a missing key means no', () => {
    const info = { ...base, capabilities: { nodes: true, pvs: false } }
    expect(isScoped(info)).toBe(true)
    expect(can(info, 'nodes')).toBe(true)
    expect(can(info, 'pvs')).toBe(false)
    expect(can(info, 'agents')).toBe(false)
  })
})

describe('visibleNav', () => {
  const nav: NavItem[] = [
    { href: '/', label: 'Findings' },
    { href: '/map', label: 'Map', needs: 'inventory' },
    { href: '/certificates', label: 'Certificates', needs: 'certs' },
    { href: '/activity', label: 'Activity', cap: 'audit' },
    { href: '/agents', label: 'Agents', needs: 'processes', cap: 'agents', scopedOnly: true },
  ]
  const hrefs = (items: NavItem[]) => items.map((n) => n.href)

  it('shows everything a full server has, except routes only scoped servers offer', () => {
    expect(hrefs(visibleNav(nav, base))).toEqual(['/', '/map', '/certificates', '/activity'])
  })
  it('hides pages the server lacks', () => {
    expect(hrefs(visibleNav(nav, { ...base, inventory: false, certs: false }))).toEqual(['/', '/activity'])
  })
  it('hides pages the user lacks the capability for', () => {
    const info = { ...base, capabilities: { audit: false, agents: true } }
    expect(hrefs(visibleNav(nav, info))).toEqual(['/', '/map', '/certificates', '/agents'])
    expect(hrefs(visibleNav(nav, { ...info, processes: false }))).toEqual(['/', '/map', '/certificates'])
  })
  it('hides routes found missing at run time', () => {
    const info = { ...base, capabilities: { audit: true, agents: true } }
    expect(hrefs(visibleNav(nav, info, new Set(['/agents'])))).toEqual(['/', '/map', '/certificates', '/activity'])
  })
})

describe('notes', () => {
  it('explain degraded and hidden sources', () => {
    expect(namesOnlyNote('nodes')).toBe("You don't have cluster-wide access to nodes; showing names only.")
    expect(hiddenNote('pvs')).toMatch(/^Persistent volumes are hidden/)
    expect(hiddenNote('clusterAudit')).toMatch(/cluster-wide audit access/)
  })
  it('lists what a scoped user lacks', () => {
    expect(missingCapabilities(base)).toEqual([])
    const caps = { nodes: true, pvs: true, storageClasses: true, clusterRBAC: false, clusterIssuers: true, processes: true, audit: true, clusterAudit: false, agents: true }
    expect(missingCapabilities({ capabilities: caps })).toEqual(['clusterRBAC', 'clusterAudit'])
  })
})

describe('seesNothing', () => {
  const proxy: Info = { ...base, identity: { user: 'ann@example.com', groups: [], source: 'proxy' }, capabilities: {} }
  it('is true for a signed-in user whose complete list is empty', () => {
    expect(seesNothing(proxy, 0, true)).toBe(true)
  })
  it('waits for the list to finish and is false once anything shows', () => {
    expect(seesNothing(proxy, 0, false)).toBe(false)
    expect(seesNothing(proxy, 3, true)).toBe(false)
  })
  it('is false for unrestricted identities and older servers: empty just means empty', () => {
    expect(seesNothing({ ...proxy, identity: { user: 'token', groups: [], source: 'token' } }, 0, true)).toBe(false)
    expect(seesNothing(base, 0, true)).toBe(false)
    expect(seesNothing(undefined, 0, true)).toBe(false)
  })
})

describe('map default namespace', () => {
  const stats = [
    { name: 'kube-system', pods: 90, system: true },
    { name: 'shop', pods: 40 },
    { name: 'data', pods: 40 },
    { name: 'empty', pods: 0 },
  ]
  it('picks the busiest non-system namespace, ties by name', () => {
    expect(busiestNamespace(stats)).toBe('data')
    expect(busiestNamespace([{ name: 'kube-system', pods: 9, system: true }])).toBeUndefined()
    expect(busiestNamespace(undefined)).toBeUndefined()
  })
  it('prefers the address, then the remembered namespace while it is visible, then the busiest', () => {
    expect(chooseMapNamespace({ fromURL: 'shop', remembered: 'data', stats })).toBe('shop')
    expect(chooseMapNamespace({ fromURL: '', remembered: 'shop', stats })).toBe('shop')
    expect(chooseMapNamespace({ fromURL: '', remembered: 'gone', visible: ['shop', 'data'], stats })).toBe('data')
    expect(chooseMapNamespace({ fromURL: '', stats })).toBe('data')
    expect(chooseMapNamespace({ fromURL: '' })).toBe('')
  })
})
