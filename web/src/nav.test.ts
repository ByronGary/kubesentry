import { describe, expect, it } from 'vitest'
import {
  activeKey,
  arrowTarget,
  badgeFor,
  compactCount,
  defaultLayout,
  groupNav,
  layoutFor,
  NAV,
  navReducer,
  readNavPrefs,
  resolveRoute,
  trapTab,
  writeNavPrefs,
  type NavState,
} from './nav'
import type { Info } from './types'

const base: Info = { demo: false, metrics: true, audit: true, processes: true, inventory: true, certs: true }
const scoped: Info = {
  ...base,
  capabilities: { nodes: true, pvs: true, storageClasses: true, clusterRBAC: true, clusterIssuers: true, processes: true, audit: true, clusterAudit: true, agents: true },
}
const keys = (info: Info, opts = {}) => groupNav(info, opts).map((s) => [s.key, s.items.map((i) => i.key)])

describe('groupNav', () => {
  it('groups the pages into the decided sections, in order', () => {
    expect(keys(scoped)).toEqual([
      ['top', ['overview']],
      ['cluster', ['map', 'workloads', 'pods', 'nodes', 'agents']],
      ['health', ['findings', 'memory', 'storage']],
      ['security', ['security', 'certificates', 'activity']],
    ])
  })
  it('shows Alerts only when /info says alerting is enabled', () => {
    expect(NAV.some((n) => n.key === 'alerts')).toBe(true)
    // An older server leaves info.alerts out; one running without -alerts sends it switched off.
    expect(groupNav(scoped)[0].items.map((i) => i.key)).toEqual(['overview'])
    expect(groupNav({ ...scoped, alerts: { enabled: false, sink: 'none' } })[0].items.map((i) => i.key)).toEqual(['overview'])
    expect(groupNav({ ...scoped, alerts: { enabled: true, sink: 'none' } })[0].items.map((i) => i.key)).toEqual(['overview', 'alerts'])
    // Seeing alerts needs no capability: the server scopes the list itself.
    expect(groupNav({ ...scoped, capabilities: {}, alerts: { enabled: true, sink: 'alertmanager' } })[0].items.map((i) => i.key)).toEqual(['overview', 'alerts'])
  })
  it('badges Alerts with the open count, worst severity first', () => {
    const on: Info = { ...scoped, alerts: { enabled: true, sink: 'none' } }
    const top = groupNav(on, { badges: { alerts: { count: 6, severity: 'crit' } } })[0]
    const alerts = top.items.find((i) => i.key === 'alerts')!
    expect(alerts.badge).toEqual({ count: 6, severity: 'crit', href: '#/alerts?state=open', label: '6 open alerts, critical' })
    expect(top.worst).toBe('crit')
    expect(badgeFor('alerts', { alerts: { count: 1, severity: 'warn' } })?.label).toBe('1 open alert, warning')
  })
  it('gates items like the old tabs: server features, capabilities, scoped-only routes', () => {
    // An unscoped server: everything allowed, but no Agents (a newer, scoped-only route).
    expect(keys(base)[1]).toEqual(['cluster', ['map', 'workloads', 'pods', 'nodes']])
    // A team member: no nodes, no audit, no agents.
    const team: Info = { ...base, capabilities: { audit: false, nodes: false } }
    expect(keys(team)).toEqual([
      ['top', ['overview']],
      ['cluster', ['map', 'workloads', 'pods']],
      ['health', ['findings', 'memory', 'storage']],
      ['security', ['security', 'certificates']],
    ])
  })
  it('puts Settings at the bottom, for settings admins of a server that has the page', () => {
    const withPage: Info = { ...scoped, settings: { investigator: true, mode: 'ui' } }
    // An older server: no page.
    expect(keys(scoped).map(([k]) => k)).not.toContain('bottom')
    // The page, but not the capability.
    expect(keys(withPage).map(([k]) => k)).not.toContain('bottom')
    expect(keys({ ...withPage, capabilities: { ...scoped.capabilities, settings: true } }).at(-1)).toEqual(['bottom', ['settings']])
    // An unscoped server (the API token, the demo): everything allowed.
    expect(keys({ ...base, settings: { investigator: true, mode: 'locked' } }).at(-1)).toEqual(['bottom', ['settings']])
    expect(resolveRoute('/settings', new URLSearchParams(), { overview: true }).page).toBe('settings')
    // The bottom section never folds.
    const s0: NavState = { folded: [], drawerOpen: false }
    expect(navReducer(s0, { type: 'toggleSection', section: 'bottom' })).toBe(s0)
  })
  it('drops a section with nothing visible in it', () => {
    const bare: Info = { ...base, inventory: false, certs: false, capabilities: { audit: false } }
    expect(keys(bare).map(([k]) => k)).toEqual(['top', 'cluster', 'health'])
    // And the top section, when the server has no /overview.
    expect(keys(bare, { hidden: new Set(['/']) }).map(([k]) => k)).toEqual(['cluster', 'health'])
  })
  it('hides routes found missing at run time', () => {
    expect(keys(scoped, { hidden: new Set(['/agents']) })[1]).toEqual(['cluster', ['map', 'workloads', 'pods', 'nodes']])
  })
  it('attaches badges and marks the worst one per section', () => {
    const s = groupNav(scoped, {
      badges: { pods: { count: 3, severity: 'crit' }, workloads: { count: 4, severity: 'warn' }, memory: { count: 1, severity: 'warn' } },
    })
    const cluster = s.find((x) => x.key === 'cluster')!
    expect(cluster.items.find((i) => i.key === 'pods')!.badge).toMatchObject({ count: 3, severity: 'crit', href: '#/pods?status=failing' })
    expect(cluster.worst).toBe('crit')
    expect(cluster.flagged).toBe(2)
    const health = s.find((x) => x.key === 'health')!
    expect(health.worst).toBe('warn')
    expect(s.find((x) => x.key === 'security')!.worst).toBeUndefined()
  })
})

describe('badgeFor', () => {
  it('links to the page that explains the count, already filtered', () => {
    expect(badgeFor('workloads', { workloads: { count: 4, severity: 'warn' } })).toEqual({
      count: 4,
      severity: 'warn',
      href: '#/workloads?status=unhealthy',
      label: '4 unhealthy workloads, warning',
    })
    expect(badgeFor('security', { security: { count: 3, severity: 'crit' } })?.href).toBe('#/security?severity=crit')
    expect(badgeFor('certificates', { certificates: { count: 1, severity: 'crit' } })?.label).toBe('1 certificate needs attention, critical')
  })
  it('shows nothing without /overview, for zero, or for items without badges', () => {
    expect(badgeFor('pods', undefined)).toBeUndefined()
    expect(badgeFor('pods', { pods: { count: 0, severity: 'crit' } })).toBeUndefined()
    expect(badgeFor('map', { pods: { count: 2, severity: 'crit' } })).toBeUndefined()
    // A severity the UI does not know is not guessed at.
    expect(badgeFor('pods', { pods: { count: 2, severity: 'info' as never } })).toBeUndefined()
  })
})

describe('compactCount', () => {
  it('keeps badges short', () => {
    expect(compactCount(7)).toBe('7')
    expect(compactCount(999)).toBe('999')
    expect(compactCount(1000)).toBe('1k')
    expect(compactCount(1240)).toBe('1.2k')
    expect(compactCount(9960)).toBe('10k')
    expect(compactCount(14_400)).toBe('14k')
  })
})

describe('resolveRoute', () => {
  const r = (hash: string, overview = true) => {
    const [path, q = ''] = hash.split('?')
    return resolveRoute(path, new URLSearchParams(q), { overview })
  }
  it('makes Overview the home page and moves Findings to #/findings', () => {
    expect(r('/').page).toBe('overview')
    expect(r('/findings').page).toBe('findings')
    expect(r('/nodes').page).toBe('nodes')
  })
  it('falls back to Findings as home on a server without /overview', () => {
    expect(r('/', false).page).toBe('findings')
    expect(r('/findings', false).page).toBe('findings')
    expect(activeKey(r('/', false).page)).toBe('findings')
  })
  it('shows the home page for unknown paths', () => {
    expect(r('/nope').page).toBe('overview')
    expect(r('/nope', false).page).toBe('findings')
  })
  it('routes Alerts, keeping its filters, and marks it in the sidebar', () => {
    expect(r('/alerts?key=a/b/c/d&state=all')).toEqual({ page: 'alerts', parts: ['alerts'] })
    expect(r('/alerts', false).page).toBe('alerts')
    expect(activeKey('alerts')).toBe('alerts')
  })
  it('redirects the Map node view to the Nodes page, keeping the node', () => {
    expect(r('/map?view=nodes&node=ip-10-0-1-5&namespace=shop')).toEqual({ page: 'nodes', parts: ['nodes'], redirect: '#/nodes?node=ip-10-0-1-5' })
    expect(r('/map?view=nodes').redirect).toBe('#/nodes')
    expect(r('/map?namespace=shop')).toEqual({ page: 'map', parts: ['map'] })
  })
  it('redirects old aliases, keeping the rest of the address', () => {
    expect(r('/volumes?q=data')).toEqual({ page: 'storage', parts: ['storage'], redirect: '#/storage?q=data' })
  })
  it('opens the pod page under Pods', () => {
    const x = r('/pods/shop/web%2D0')
    expect(x.page).toBe('pod')
    expect(x.parts).toEqual(['pods', 'shop', 'web-0'])
    expect(activeKey(x.page)).toBe('pods')
    expect(r('/pods/shop').page).toBe('pods')
  })
  it('survives malformed escapes', () => {
    expect(r('/pods/shop/%E0%A4%A').parts).toEqual(['pods', 'shop', '%E0%A4%A'])
  })
  it('opens the incidents list and one incident under Incidents', () => {
    expect(r('/incidents?state=open').page).toBe('incidents')
    const x = r('/incidents/20261015T120000Z-abcdef012345?from=2026-10-15T12%3A10%3A00Z')
    expect(x).toEqual({ page: 'incident', parts: ['incidents', '20261015T120000Z-abcdef012345'] })
    expect(activeKey(x.page)).toBe('incidents')
    // An encoded slash stays inside the id.
    expect(r('/incidents/a%2Fb').parts).toEqual(['incidents', 'a/b'])
  })
})

describe('incidents in the sidebar', () => {
  const on: Info = { ...scoped, incidents: { enabled: true, sources: {}, maxRangeHours: 24, logLeadSeconds: 300, logLagSeconds: 600 } }
  it('shows Incidents first in Health when the server tracks them', () => {
    expect(keys(on).find(([k]) => k === 'health')).toEqual(['health', ['incidents', 'findings', 'memory', 'storage']])
  })
  it('hides it on older servers and when incidents are switched off', () => {
    expect(keys(scoped).find(([k]) => k === 'health')![1]).not.toContain('incidents')
    const off: Info = { ...scoped, incidents: { enabled: false, sources: {}, maxRangeHours: 24, logLeadSeconds: 0, logLagSeconds: 0 } }
    expect(keys(off).find(([k]) => k === 'health')![1]).not.toContain('incidents')
  })
  it('carries the open-incidents badge to the open list', () => {
    const health = groupNav(on, { badges: { incidents: { count: 2, severity: 'crit' } } }).find((s) => s.key === 'health')!
    expect(health.items[0].badge).toEqual({ count: 2, severity: 'crit', href: '#/incidents?state=open', label: '2 open incidents, critical' })
    expect(health.worst).toBe('crit')
  })
})

describe('layout', () => {
  it('defaults by width: expanded from 1280, rail from 768, drawer below', () => {
    expect(defaultLayout(1440)).toBe('expanded')
    expect(defaultLayout(1280)).toBe('expanded')
    expect(defaultLayout(1279)).toBe('rail')
    expect(defaultLayout(1024)).toBe('rail')
    expect(defaultLayout(768)).toBe('rail')
    expect(defaultLayout(767)).toBe('drawer')
    expect(defaultLayout(390)).toBe('drawer')
  })
  it('follows the remembered choice, except on a phone', () => {
    expect(layoutFor(1440, 'rail')).toBe('rail')
    expect(layoutFor(1024, 'expanded')).toBe('expanded')
    expect(layoutFor(390, 'expanded')).toBe('drawer')
    expect(layoutFor(1024, undefined)).toBe('rail')
  })
})

describe('navReducer', () => {
  const s0: NavState = { folded: [], drawerOpen: false }
  it('« / » flips between expanded and rail from whatever is showing', () => {
    expect(navReducer(s0, { type: 'toggleRail', layout: 'expanded' }).pref).toBe('rail')
    expect(navReducer(s0, { type: 'toggleRail', layout: 'rail' }).pref).toBe('expanded')
    expect(navReducer(s0, { type: 'toggleRail', layout: 'drawer' })).toBe(s0)
  })
  it('folds and unfolds sections, but never the top one', () => {
    const a = navReducer(s0, { type: 'toggleSection', section: 'health' })
    expect(a.folded).toEqual(['health'])
    expect(navReducer(a, { type: 'toggleSection', section: 'health' }).folded).toEqual([])
    expect(navReducer(s0, { type: 'toggleSection', section: 'top' })).toBe(s0)
  })
  it('opens and closes the drawer without needless updates', () => {
    const open = navReducer(s0, { type: 'openDrawer' })
    expect(open.drawerOpen).toBe(true)
    expect(navReducer(open, { type: 'openDrawer' })).toBe(open)
    expect(navReducer(open, { type: 'closeDrawer' }).drawerOpen).toBe(false)
    expect(navReducer(s0, { type: 'closeDrawer' })).toBe(s0)
  })
})

describe('remembered sidebar state', () => {
  it('round-trips the choice and the folded sections, never the drawer', () => {
    const s: NavState = { pref: 'rail', folded: ['health', 'security'], drawerOpen: true }
    const raw = writeNavPrefs(s)
    expect(raw).toBe('{"pref":"rail","folded":["health","security"]}')
    expect(readNavPrefs(raw)).toEqual({ pref: 'rail', folded: ['health', 'security'], drawerOpen: false })
    expect(writeNavPrefs({ folded: [], drawerOpen: true })).toBeUndefined()
  })
  it('ignores anything it does not recognise', () => {
    expect(readNavPrefs(undefined)).toEqual({ folded: [], drawerOpen: false })
    expect(readNavPrefs('not json')).toEqual({ folded: [], drawerOpen: false })
    expect(readNavPrefs('{"pref":"huge","folded":["top","health","health",3]}')).toEqual({ folded: ['health'], drawerOpen: false })
  })
})

describe('keyboard', () => {
  it('moves through the list with arrows, wrapping, plus Home and End', () => {
    expect(arrowTarget(0, 5, 'ArrowDown')).toBe(1)
    expect(arrowTarget(4, 5, 'ArrowDown')).toBe(0)
    expect(arrowTarget(0, 5, 'ArrowUp')).toBe(4)
    expect(arrowTarget(-1, 5, 'ArrowDown')).toBe(0)
    expect(arrowTarget(-1, 5, 'ArrowUp')).toBe(4)
    expect(arrowTarget(2, 5, 'Home')).toBe(0)
    expect(arrowTarget(2, 5, 'End')).toBe(4)
    expect(arrowTarget(2, 5, 'ArrowLeft')).toBeUndefined()
    expect(arrowTarget(0, 0, 'ArrowDown')).toBeUndefined()
  })
  it('traps Tab inside the open drawer', () => {
    expect(trapTab(4, 5, false)).toBe(0)
    expect(trapTab(0, 5, true)).toBe(4)
    expect(trapTab(2, 5, false)).toBeUndefined()
    expect(trapTab(-1, 5, false)).toBe(0)
    expect(trapTab(-1, 5, true)).toBe(4)
  })
})
