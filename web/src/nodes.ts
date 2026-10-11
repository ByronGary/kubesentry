// Grouping nodes by pool and zone for the Map's node view, kept free of React
// so it is testable. Everything here is linear in the number of nodes.

import { matches } from './inventory'
import type { NodeSummary, Status } from './types'

export type PoolKind = 'nodegroup' | 'karpenter' | 'fargate' | 'role' | 'none'

export const POOL_KIND_LABEL: Record<PoolKind, string> = {
  nodegroup: 'Node group',
  karpenter: 'Karpenter node pool',
  fargate: 'Fargate',
  role: 'Role',
  none: 'No pool label',
}

/** The group a node belongs to: its node group or Karpenter pool, else Fargate, else its roles. */
export function poolOf(n: NodeSummary): { key: string; name: string; kind: PoolKind } {
  const p = n.placement
  const kind = p?.poolKind || ''
  if (p?.pool) {
    const k: PoolKind = kind === 'karpenter' || kind === 'fargate' ? kind : 'nodegroup'
    return { key: `${k}:${p.pool}`, name: p.pool, kind: k }
  }
  if (kind === 'fargate') return { key: 'fargate:', name: 'Fargate', kind: 'fargate' }
  const roles = (n.roles ?? []).filter(Boolean)
  if (roles.length) {
    const name = [...roles].sort().join(', ')
    return { key: `role:${name}`, name, kind: 'role' }
  }
  return { key: 'none:', name: 'Nodes without a pool label', kind: 'none' }
}

/** Pods on a node: podCount from summary responses, else the length of the pod list. */
export function podCountOf(n: NodeSummary): number {
  return n.podCount ?? n.pods?.length ?? 0
}

export interface NodeAggregate {
  count: number
  ready: number
  notReady: number
  cordoned: number
  /** The worst node status. */
  status: Status
  byStatus: Record<Status, number>
  cpuRequestedMilli: number
  cpuAllocatableMilli: number
  memoryRequestedBytes: number
  memoryAllocatableBytes: number
  pods: number
  podsAllocatable: number
  /** [label, count], most common first. */
  capacityTypes: [string, number][]
  arch: [string, number][]
  instanceTypes: [string, number][]
}

const WORST: Status[] = ['crit', 'warn', 'unknown', 'ok']

function tally(m: Map<string, number>): [string, number][] {
  return [...m.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
}

const CAPACITY_LABEL: Record<string, string> = { spot: 'Spot', 'on-demand': 'On-demand' }

export function aggregateNodes(nodes: NodeSummary[]): NodeAggregate {
  const byStatus: Record<Status, number> = { ok: 0, warn: 0, crit: 0, unknown: 0 }
  const cap = new Map<string, number>()
  const arch = new Map<string, number>()
  const types = new Map<string, number>()
  const a = {
    count: nodes.length,
    ready: 0,
    notReady: 0,
    cordoned: 0,
    cpuRequestedMilli: 0,
    cpuAllocatableMilli: 0,
    memoryRequestedBytes: 0,
    memoryAllocatableBytes: 0,
    pods: 0,
    podsAllocatable: 0,
  }
  const bump = (m: Map<string, number>, k: string | undefined) => {
    if (k) m.set(k, (m.get(k) ?? 0) + 1)
  }
  for (const n of nodes) {
    if (n.ready) a.ready++
    else a.notReady++
    if (n.unschedulable) a.cordoned++
    byStatus[n.status in byStatus ? n.status : 'unknown']++
    a.cpuRequestedMilli += n.cpuRequestedMilli || 0
    a.cpuAllocatableMilli += n.cpuAllocatableMilli || 0
    a.memoryRequestedBytes += n.memoryRequestedBytes || 0
    a.memoryAllocatableBytes += n.memoryAllocatableBytes || 0
    a.pods += podCountOf(n)
    a.podsAllocatable += n.podsAllocatable || 0
    const p = n.placement
    bump(cap, p?.capacityType ? (CAPACITY_LABEL[p.capacityType] ?? p.capacityType) : p?.poolKind === 'fargate' ? 'Fargate' : undefined)
    bump(arch, p?.arch)
    bump(types, p?.instanceType)
  }
  return {
    ...a,
    status: WORST.find((s) => byStatus[s] > 0) ?? 'ok',
    byStatus,
    capacityTypes: tally(cap),
    arch: tally(arch),
    instanceTypes: tally(types),
  }
}

/** "Spot 12 · On-demand 3", or "" when nothing is known. */
export function mixText(entries: [string, number][], max = 3): string {
  const shown = entries.slice(0, max).map(([k, v]) => `${k} ${v}`)
  const rest = entries.slice(max).reduce((s, [, v]) => s + v, 0)
  if (rest > 0) shown.push(`other ${rest}`)
  return shown.join(' · ')
}

export interface ZoneGroup {
  key: string
  zone: string
  nodes: NodeSummary[]
  agg: NodeAggregate
}

export interface PoolGroup {
  key: string
  name: string
  kind: PoolKind
  zones: ZoneGroup[]
  agg: NodeAggregate
}

const STATUS_RANK: Record<Status, number> = { crit: 0, warn: 1, unknown: 2, ok: 3 }
const rankOf = (s: Status) => STATUS_RANK[s] ?? 2

export const NO_ZONE = 'No zone label'

/**
 * Pools, then zones within each pool. Pools and zones with problems come first,
 * then the bigger ones; nodes with problems come first within a zone.
 */
export function groupNodes(nodes: NodeSummary[]): PoolGroup[] {
  const pools = new Map<string, { name: string; kind: PoolKind; zones: Map<string, NodeSummary[]>; all: NodeSummary[] }>()
  for (const n of nodes) {
    const p = poolOf(n)
    let g = pools.get(p.key)
    if (!g) {
      g = { name: p.name, kind: p.kind, zones: new Map(), all: [] }
      pools.set(p.key, g)
    }
    g.all.push(n)
    const z = n.placement?.zone || NO_ZONE
    const list = g.zones.get(z)
    if (list) list.push(n)
    else g.zones.set(z, [n])
  }
  const byWorstThenSize = (a: { agg: NodeAggregate; label: string }, b: { agg: NodeAggregate; label: string }) =>
    rankOf(a.agg.status) - rankOf(b.agg.status) || b.agg.count - a.agg.count || a.label.localeCompare(b.label)
  const out: PoolGroup[] = []
  for (const [key, g] of pools) {
    const zones: ZoneGroup[] = []
    for (const [zone, list] of g.zones) {
      list.sort((a, b) => rankOf(a.status) - rankOf(b.status) || a.name.localeCompare(b.name, 'en', { numeric: true }))
      zones.push({ key: `${key}|${zone}`, zone, nodes: list, agg: aggregateNodes(list) })
    }
    zones.sort((a, b) => (a.zone === NO_ZONE ? 1 : 0) - (b.zone === NO_ZONE ? 1 : 0) || a.zone.localeCompare(b.zone))
    out.push({ key, name: g.name, kind: g.kind, zones, agg: aggregateNodes(g.all) })
  }
  return out
    .map((p) => ({ p, label: p.name, agg: p.agg }))
    .sort(byWorstThenSize)
    .map((x) => x.p)
}

/** Above this many nodes, pools start collapsed. */
export const COLLAPSE_NODES_ABOVE = 24

/** Nodes matching a search: name, pool, zone, instance type or capacity type. */
export function filterNodes(nodes: NodeSummary[], q: string): NodeSummary[] {
  if (!q.trim()) return nodes
  return nodes.filter((n) => {
    const p = n.placement
    return matches(q, n.name, p?.pool, p?.zone, p?.instanceType, p?.capacityType, p?.arch, ...(n.roles ?? []))
  })
}

/** Ready / not ready / cordoned in words: "40 nodes, 2 not ready, 1 cordoned". */
export function nodeCountText(a: NodeAggregate): string {
  const parts = [`${a.count} ${a.count === 1 ? 'node' : 'nodes'}`]
  if (a.notReady) parts.push(`${a.notReady} not ready`)
  if (a.cordoned) parts.push(`${a.cordoned} cordoned`)
  return parts.join(', ')
}
