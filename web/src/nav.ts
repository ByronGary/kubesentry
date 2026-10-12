// The sidebar: which pages there are, how they group into sections, their
// badges, which page an address shows, and how the sidebar folds. Kept free of
// React so it is testable.

import { visibleNav, type NavItem } from './access'
import type { AttentionSeverity, Info, OverviewResponse } from './types'

export type NavKey =
  | 'overview'
  | 'alerts'
  | 'map'
  | 'workloads'
  | 'pods'
  | 'nodes'
  | 'agents'
  | 'findings'
  | 'memory'
  | 'storage'
  | 'security'
  | 'certificates'
  | 'activity'

export type SectionKey = 'top' | 'cluster' | 'health' | 'security'

export interface NavEntry extends NavItem {
  key: NavKey
  section: SectionKey
  /** Listed for when its server feature lands, but not shown until then (Alerts, after alerting phase B). */
  placeholder?: boolean
}

export const SECTIONS: { key: SectionKey; label: string }[] = [
  { key: 'top', label: '' },
  { key: 'cluster', label: 'Cluster' },
  { key: 'health', label: 'Health' },
  { key: 'security', label: 'Security' },
]

export const NAV: NavEntry[] = [
  { key: 'overview', section: 'top', href: '/', label: 'Overview' },
  { key: 'alerts', section: 'top', href: '/alerts', label: 'Alerts', placeholder: true },
  { key: 'map', section: 'cluster', href: '/map', label: 'Map', needs: 'inventory' },
  { key: 'workloads', section: 'cluster', href: '/workloads', label: 'Workloads', needs: 'inventory' },
  { key: 'pods', section: 'cluster', href: '/pods', label: 'Pods' },
  { key: 'nodes', section: 'cluster', href: '/nodes', label: 'Nodes', needs: 'inventory', cap: 'nodes' },
  // Agent status is a newer route: only servers that scope per user have it.
  { key: 'agents', section: 'cluster', href: '/agents', label: 'Agents', needs: 'processes', cap: 'agents', scopedOnly: true },
  { key: 'findings', section: 'health', href: '/findings', label: 'Findings' },
  { key: 'memory', section: 'health', href: '/memory', label: 'Memory' },
  { key: 'storage', section: 'health', href: '/storage', label: 'Storage' },
  { key: 'security', section: 'security', href: '/security', label: 'Security', needs: 'inventory' },
  { key: 'certificates', section: 'security', href: '/certificates', label: 'Certificates', needs: 'certs' },
  { key: 'activity', section: 'security', href: '/activity', label: 'Activity', cap: 'audit' },
]

// ---- Badges ----

export type Badges = OverviewResponse['badges']
export type BadgeKey = keyof Badges

export interface Badge {
  count: number
  severity: AttentionSeverity
  /** The page that explains the count, already filtered. */
  href: string
  /** "3 failing pods, critical", for screen readers and tooltips. */
  label: string
}

const BADGE_HREF: Record<BadgeKey, (s: AttentionSeverity) => string> = {
  workloads: () => '#/workloads?status=unhealthy',
  pods: () => '#/pods?status=failing',
  findings: () => '#/findings',
  memory: () => '#/memory',
  security: (s) => `#/security?severity=${s}`,
  certificates: () => '#/certificates?status=unhealthy',
}

const BADGE_NOUN: Record<BadgeKey, [string, string]> = {
  workloads: ['unhealthy workload', 'unhealthy workloads'],
  pods: ['failing pod', 'failing pods'],
  findings: ['finding', 'findings'],
  memory: ['memory finding', 'memory findings'],
  security: ['security finding', 'security findings'],
  certificates: ['certificate needs attention', 'certificates need attention'],
}

const SEVERITY_WORD: Record<AttentionSeverity, string> = { crit: 'critical', warn: 'warning' }

function isBadgeKey(k: string): k is BadgeKey {
  return k in BADGE_HREF
}

/** The badge for a nav item, or undefined when there is none (zero, unknown key, or no /overview). */
export function badgeFor(key: string, badges: Badges | undefined): Badge | undefined {
  if (!badges || !isBadgeKey(key)) return undefined
  const b = badges[key]
  if (!b || !(b.count > 0) || (b.severity !== 'crit' && b.severity !== 'warn')) return undefined
  const [one, many] = BADGE_NOUN[key]
  return {
    count: b.count,
    severity: b.severity,
    href: BADGE_HREF[key](b.severity),
    label: `${b.count.toLocaleString('en-US')} ${b.count === 1 ? one : many}, ${SEVERITY_WORD[b.severity]}`,
  }
}

/** A count small enough for a badge: 7, 312, 1.2k, 14k. */
export function compactCount(n: number): string {
  if (!Number.isFinite(n)) return '-'
  if (n < 1000) return String(Math.round(n))
  if (n < 9950) return `${(n / 1000).toFixed(1).replace(/\.0$/, '')}k`
  return `${Math.round(n / 1000)}k`
}

// ---- Grouping ----

export interface ShownEntry extends NavEntry {
  badge?: Badge
}

export interface NavSection {
  key: SectionKey
  label: string
  items: ShownEntry[]
  /** The worst badge severity in the section, shown on its toggle while it is folded. */
  worst?: AttentionSeverity
  /** How many of its items carry a badge. */
  flagged: number
}

export interface GroupOptions {
  /** Routes found missing at run time (an older server without /overview or /agents). */
  hidden?: ReadonlySet<string>
  badges?: Badges
  /** The server provides alerts (alerting phase B). Until then the Alerts item stays hidden. */
  alerts?: boolean
}

/**
 * The sidebar's sections with the items this server has and this user may use,
 * gated exactly as the old tabs were (access.ts `visibleNav`). A section with
 * nothing visible disappears.
 */
export function groupNav(info: Info, opts: GroupOptions = {}, items: NavEntry[] = NAV): NavSection[] {
  const shown = visibleNav(
    items.filter((i) => !i.placeholder || (i.key === 'alerts' && opts.alerts === true)),
    info,
    opts.hidden,
  )
  const out: NavSection[] = []
  for (const s of SECTIONS) {
    const list: ShownEntry[] = shown.filter((i) => i.section === s.key).map((i) => ({ ...i, badge: badgeFor(i.key, opts.badges) }))
    if (list.length === 0) continue
    const flagged = list.filter((i) => i.badge)
    const worst = flagged.some((i) => i.badge!.severity === 'crit') ? 'crit' : flagged.length ? 'warn' : undefined
    out.push({ key: s.key, label: s.label, items: list, worst, flagged: flagged.length })
  }
  return out
}

// ---- Routes ----

export type PageKey = Exclude<NavKey, 'alerts'> | 'pod'

export interface Resolved {
  page: PageKey
  /** Path segments after aliases, decoded: ["pods", "shop", "web-0"]. */
  parts: string[]
  /** An old address that now lives elsewhere: replace the address with this hash. */
  redirect?: string
}

const PAGES = new Set<string>(['map', 'workloads', 'pods', 'nodes', 'agents', 'findings', 'memory', 'storage', 'security', 'certificates', 'activity'])

/** Old paths that still work. */
const ALIAS: Record<string, string> = { volumes: 'storage' }

function decode(s: string): string {
  try {
    return decodeURIComponent(s)
  } catch {
    return s
  }
}

/**
 * Which page an address shows. `#/` is the Overview, unless the server has no
 * /overview (`overview: false`): then it is Findings, the old home page.
 * Findings itself lives at `#/findings`; it never took query parameters, so an
 * old `#/` link needs no translation. Older addresses redirect:
 * `#/map?view=nodes` to `#/nodes`, `#/volumes` to `#/storage`.
 */
export function resolveRoute(path: string, query: URLSearchParams, opts: { overview: boolean }): Resolved {
  const parts = path.split('/').filter(Boolean).map(decode)
  const home: PageKey = opts.overview ? 'overview' : 'findings'
  if (parts.length === 0) return { page: home, parts }
  const first = parts[0]
  if (ALIAS[first]) {
    const rest = path.split('/').filter(Boolean).slice(1)
    const q = query.toString()
    return { page: ALIAS[first] as PageKey, parts: [ALIAS[first], ...parts.slice(1)], redirect: `#/${[ALIAS[first], ...rest].join('/')}${q ? `?${q}` : ''}` }
  }
  if (first === 'map' && query.get('view') === 'nodes') {
    const p = new URLSearchParams()
    for (const k of ['node', 'q']) {
      const v = query.get(k)
      if (v) p.set(k, v)
    }
    const q = p.toString()
    return { page: 'nodes', parts: ['nodes'], redirect: `#/nodes${q ? `?${q}` : ''}` }
  }
  if (first === 'pods' && parts.length >= 3) return { page: 'pod', parts }
  if (PAGES.has(first)) return { page: first as PageKey, parts }
  // Unknown paths (and Alerts, until it exists) show the home page, as before.
  return { page: home, parts }
}

/** The nav item to mark as the current page. */
export function activeKey(page: PageKey): NavKey {
  return page === 'pod' ? 'pods' : page
}

// ---- Layout and folding ----

/** Wide screens get the expanded sidebar, laptops the icon rail, phones a drawer. */
export type Layout = 'expanded' | 'rail' | 'drawer'
export type Pref = 'expanded' | 'rail'

/** Below this width the sidebar is a drawer. */
export const DRAWER_BELOW = 768
/** Below this width (and above DRAWER_BELOW) it starts as the icon rail. */
export const RAIL_BELOW = 1280

export function defaultLayout(width: number): Layout {
  if (width < DRAWER_BELOW) return 'drawer'
  if (width < RAIL_BELOW) return 'rail'
  return 'expanded'
}

/** The layout for a width: always a drawer on a phone, else the remembered choice, else the default. */
export function layoutFor(width: number, pref: Pref | undefined): Layout {
  const d = defaultLayout(width)
  if (d === 'drawer') return d
  return pref ?? d
}

export interface NavState {
  /** The user's « / » choice; undefined follows the screen width. */
  pref?: Pref
  folded: SectionKey[]
  drawerOpen: boolean
}

export type NavAction =
  | { type: 'toggleRail'; layout: Layout }
  | { type: 'toggleSection'; section: SectionKey }
  | { type: 'openDrawer' }
  | { type: 'closeDrawer' }

export function navReducer(s: NavState, a: NavAction): NavState {
  switch (a.type) {
    case 'toggleRail':
      if (a.layout === 'drawer') return s
      return { ...s, pref: a.layout === 'expanded' ? 'rail' : 'expanded' }
    case 'toggleSection':
      if (a.section === 'top') return s
      return { ...s, folded: s.folded.includes(a.section) ? s.folded.filter((x) => x !== a.section) : [...s.folded, a.section] }
    case 'openDrawer':
      return s.drawerOpen ? s : { ...s, drawerOpen: true }
    case 'closeDrawer':
      return s.drawerOpen ? { ...s, drawerOpen: false } : s
  }
}

export const NAV_PREFS_KEY = 'kubesentry.sidebar'

const FOLDABLE = new Set<string>(['cluster', 'health', 'security'])

/** The remembered sidebar state from localStorage; anything unreadable is ignored. */
export function readNavPrefs(raw: string | undefined): NavState {
  const s: NavState = { folded: [], drawerOpen: false }
  if (!raw) return s
  try {
    const v = JSON.parse(raw) as { pref?: unknown; folded?: unknown }
    if (v.pref === 'expanded' || v.pref === 'rail') s.pref = v.pref
    if (Array.isArray(v.folded)) s.folded = [...new Set(v.folded.filter((f): f is SectionKey => typeof f === 'string' && FOLDABLE.has(f)))]
  } catch {
    /* not ours or corrupt: defaults */
  }
  return s
}

/** What is remembered: the « / » choice and the folded sections, never whether the drawer is open. */
export function writeNavPrefs(s: NavState): string | undefined {
  if (!s.pref && s.folded.length === 0) return undefined
  return JSON.stringify({ ...(s.pref ? { pref: s.pref } : {}), ...(s.folded.length ? { folded: s.folded } : {}) })
}

// ---- Keyboard ----

/** Arrow keys within the nav list: the index to focus next, or undefined to leave the key alone. */
export function arrowTarget(index: number, count: number, key: string): number | undefined {
  if (count <= 0) return undefined
  switch (key) {
    case 'ArrowDown':
      return index < 0 ? 0 : (index + 1) % count
    case 'ArrowUp':
      return index < 0 ? count - 1 : (index - 1 + count) % count
    case 'Home':
      return 0
    case 'End':
      return count - 1
    default:
      return undefined
  }
}

/**
 * Keeps Tab inside the open drawer: from the last element forwards goes to
 * the first, from the first backwards to the last. Undefined lets the browser
 * move focus as usual.
 */
export function trapTab(index: number, count: number, shift: boolean): number | undefined {
  if (count <= 0) return undefined
  if (index < 0) return shift ? count - 1 : 0
  if (!shift && index === count - 1) return 0
  if (shift && index === 0) return count - 1
  return undefined
}
