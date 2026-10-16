// What the signed-in user may see, from /info, kept free of React so it is testable.
//
// Namespaced data is filtered by the server; `capabilities` says which
// cluster-wide sources and optional features this user may use. A server that
// does not scope per user sends no capabilities, and then everything is allowed.

import type { Capability, Info } from './types'

/** Whether the user may use a capability. Absent `capabilities` means everything is allowed. */
export function can(info: Pick<Info, 'capabilities'> | undefined, cap: Capability): boolean {
  const caps = info?.capabilities
  if (!caps) return true
  return caps[cap] === true
}

/** The server scopes data to the caller (it sent capabilities), so emptiness may mean "no access". */
export function isScoped(info: Pick<Info, 'capabilities'> | undefined): boolean {
  return info?.capabilities !== undefined
}

export type Flag = 'inventory' | 'certs' | 'processes' | 'audit' | 'incidents'

/**
 * Whether the server offers a feature. Incidents count only when /info says
 * they are enabled: older servers leave `incidents` out, and a server could
 * send it switched off.
 */
export function hasFeature(info: Info | undefined, flag: Flag): boolean {
  if (!info) return false
  if (flag === 'incidents') return info.incidents?.enabled === true
  return info[flag] === true
}

export interface NavItem {
  href: string
  label: string
  /** A server feature the page needs. */
  needs?: Flag
  /** A capability the user needs. */
  cap?: Capability
  /** Only on servers that scope per user (newer routes). */
  scopedOnly?: boolean
}

/** Nav items this server has and this user may use. `hidden` drops routes found missing at run time. */
export function visibleNav<T extends NavItem>(items: T[], info: Info, hidden: ReadonlySet<string> = new Set()): T[] {
  return items.filter(
    (n) => !hidden.has(n.href) && (!n.needs || hasFeature(info, n.needs)) && (!n.cap || can(info, n.cap)) && (!n.scopedOnly || isScoped(info)),
  )
}

const NOUN: Record<Capability, string> = {
  nodes: 'nodes',
  pvs: 'persistent volumes',
  storageClasses: 'storage classes',
  clusterRBAC: 'cluster-wide RBAC (ClusterRoles and ClusterRoleBindings)',
  clusterIssuers: 'ClusterIssuers',
  processes: 'process data',
  audit: 'the audit log',
  clusterAudit: 'cluster-scoped audit events',
  agents: 'node agents',
  podLogs: 'pod logs',
  cloudtrail: 'AWS CloudTrail events',
}

/** Inline note where the server degrades a source to names only. */
export function namesOnlyNote(cap: Capability): string {
  return `You don't have cluster-wide access to ${NOUN[cap]}; showing names only.`
}

const HIDDEN: Record<Capability, string> = {
  nodes: 'Node details are hidden: they need cluster-wide access to nodes.',
  pvs: 'Persistent volumes are hidden: they need cluster-wide access to persistent volumes.',
  storageClasses: 'Storage classes are hidden: they need cluster-wide access to storage classes.',
  clusterRBAC: 'Findings about ClusterRoles and ClusterRoleBindings are hidden: they need cluster-wide access to RBAC.',
  clusterIssuers: 'ClusterIssuers are hidden: they need cluster-wide access to cert-manager issuers.',
  processes: 'Processes are hidden: your access does not include process data.',
  audit: 'Activity is hidden: your access does not include the audit log.',
  clusterAudit: 'Events without a namespace (cluster-scoped objects) are hidden: they need cluster-wide audit access.',
  agents: 'Agent status is hidden: it needs cluster-wide access.',
  podLogs: 'Logs are hidden: your access does not include pod logs (get pods/log) in this namespace.',
  cloudtrail: 'CloudTrail changes are hidden: they need the kubesentry CloudTrail viewer role.',
}

/** Note for a section hidden because the user lacks a capability. */
export function hiddenNote(cap: Capability): string {
  return HIDDEN[cap]
}

/** Which capabilities the user lacks, for the identity menu. */
export function missingCapabilities(info: Pick<Info, 'capabilities'> | undefined): Capability[] {
  const caps = info?.capabilities
  if (!caps) return []
  // Only what the server reports as denied: an older server that doesn't know
  // a capability (e.g. podLogs) must not make it look missing. Gating with
  // can() still treats an absent key as not allowed.
  return (Object.keys(NOUN) as Capability[]).filter((c) => c in caps && caps[c] !== true)
}

export function capabilityNoun(cap: Capability): string {
  return NOUN[cap]
}

/**
 * The user sees no namespace at all: a single sign-on user got a complete,
 * empty list. Most likely their RBAC grants nothing yet.
 */
export function seesNothing(info: Info | undefined, count: number, complete: boolean): boolean {
  if (!info || count > 0 || !complete) return false
  // The token and "none" identities are unrestricted, so empty means empty.
  return info.identity?.source === 'proxy'
}

// Map default namespace.

export const MAP_NS_KEY = 'kubesentry.mapNamespace'

/** Per-namespace numbers a server may send with the map (proposed contract). */
export interface NamespaceStat {
  name: string
  pods: number
  system?: boolean
}

/** The namespace with the most pods that is not cluster plumbing; ties go to the first by name. */
export function busiestNamespace(stats: NamespaceStat[] | undefined): string | undefined {
  let best: NamespaceStat | undefined
  for (const s of stats ?? []) {
    if (s.system || !(s.pods > 0)) continue
    if (!best || s.pods > best.pods || (s.pods === best.pods && s.name < best.name)) best = s
  }
  return best?.name
}

/**
 * Which namespace to ask the map for: the one in the address, else the one the
 * user last looked at (when it is still visible, if we know what is), else
 * the busiest visible one. Empty lets the server choose.
 */
export function chooseMapNamespace(o: { fromURL: string; remembered?: string; visible?: string[]; stats?: NamespaceStat[] }): string {
  if (o.fromURL) return o.fromURL
  if (o.remembered && (!o.visible || o.visible.includes(o.remembered))) return o.remembered
  return busiestNamespace(o.stats) ?? ''
}
