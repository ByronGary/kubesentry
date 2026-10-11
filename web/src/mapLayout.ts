// Layered left-to-right layout for the Map page, kept free of React so it is testable.
//
// 1. Each kind has a rank (Ingress, Service, CronJob, workloads, Pod, then PVC
//    and Node); ranks with no objects are dropped, the rest become columns.
// 2. Edges spanning several columns get a waypoint in every column they cross,
//    so they run in a lane between boxes instead of through them.
// 3. Rows within a column start in name order, then a few down and up sweeps
//    sort each column by the barycenter (mean position) of its neighbours in
//    the column before or after. The ordering with the fewest crossings wins.
// 4. Vertical positions are relaxed towards the mean of each box's neighbours,
//    keeping the order and minimum gaps (isotonic regression), so a workload
//    sits beside its pods rather than at the top of its column.

import { podHref, workloadHref } from './findings'
import type { GraphEdge, GraphKind, GraphNode } from './types'

export interface LayoutOptions {
  boxW: number
  boxH: number
  colGap: number
  rowGap: number
  /** Outer padding. */
  pad: number
  /** Space above the boxes for column headings. */
  header: number
  /** Height reserved for an edge passing through a column. */
  laneH: number
  /** Down-and-up sweep pairs for crossing reduction. */
  sweeps: number
}

export const DEFAULT_LAYOUT: LayoutOptions = {
  boxW: 196,
  boxH: 46,
  colGap: 64,
  rowGap: 12,
  pad: 8,
  header: 28,
  laneH: 4,
  sweeps: 4,
}

export interface Box {
  id: string
  x: number
  y: number
  w: number
  h: number
  /** Column index after empty ranks are dropped. */
  column: number
  /** Position among the real boxes of its column, top first. */
  row: number
}

export interface EdgePath {
  from: string
  to: string
  /** SVG path: cubic curves between columns, straight runs through waypoints. */
  d: string
  x1: number
  y1: number
  x2: number
  y2: number
}

export interface Column {
  x: number
  label: string
}

export interface MapLayout {
  boxes: Box[]
  edges: EdgePath[]
  columns: Column[]
  width: number
  height: number
  /** Edge crossings between adjacent columns in the chosen ordering. */
  crossings: number
}

const RANK: Record<GraphKind, number> = {
  Ingress: 0,
  Service: 1,
  // CronJobs create Jobs, so they get their own column left of the workloads.
  CronJob: 2,
  Deployment: 3,
  StatefulSet: 3,
  // Orphaned ReplicaSets and other owners (Rollouts, operators) run pods like workloads do.
  ReplicaSet: 3,
  Controller: 3,
  DaemonSet: 3,
  Job: 3,
  Pod: 4,
  PVC: 5,
  Node: 5,
}

const RANK_LABEL = ['Ingresses', 'Services', 'CronJobs', 'Workloads', 'Pods']

/** Kinds that share a column keep separate bands: claims above nodes. */
function bandOf(kind: GraphKind | undefined): number {
  return kind === 'Node' ? 1 : 0
}

/** The column rank of a kind (before empty ranks are dropped). Unknown kinds go with the workloads. */
export function rankOf(kind: string): number {
  return RANK[kind as GraphKind] ?? 3
}

function columnLabel(rank: number, kinds: Set<string>): string {
  if (rank < RANK_LABEL.length) return RANK_LABEL[rank]
  if (kinds.has('PVC') && kinds.has('Node')) return 'Claims and nodes'
  return kinds.has('Node') ? 'Nodes' : 'Volume claims'
}

interface Item {
  id: string
  real: boolean
  column: number
  band: number
  name: string
}

const byNumber = (a: number, b: number) => (a === b ? 0 : a < b ? -1 : 1)

/**
 * Crossings between two adjacent columns: pairs of edges (a→b, c→d) with a
 * above c but b below d. O(E log V) with a Fenwick tree.
 */
export function countCrossings(top: string[], bottom: string[], edges: Iterable<[string, string]>): number {
  const tp = new Map(top.map((id, i) => [id, i]))
  const bp = new Map(bottom.map((id, i) => [id, i]))
  const pairs: [number, number][] = []
  for (const [a, b] of edges) {
    const i = tp.get(a)
    const j = bp.get(b)
    if (i !== undefined && j !== undefined) pairs.push([i, j])
  }
  pairs.sort((p, q) => p[0] - q[0] || p[1] - q[1])
  const tree = new Array<number>(bottom.length + 1).fill(0)
  let count = 0
  pairs.forEach(([, v], k) => {
    let atMost = 0
    for (let x = v + 1; x > 0; x -= x & -x) atMost += tree[x]
    count += k - atMost
    for (let x = v + 1; x <= bottom.length; x += x & -x) tree[x]++
  })
  return count
}

/**
 * Least-squares fit of `desired` top positions that keeps the given order and
 * minimum spacing (pool-adjacent-violators on the offset-adjusted values).
 */
export function placeInOrder(desired: number[], sizes: number[], gaps: number[]): number[] {
  const off: number[] = []
  let acc = 0
  for (let i = 0; i < desired.length; i++) {
    off.push(acc)
    acc += sizes[i] + (gaps[i] ?? 0)
  }
  const blocks: { sum: number; n: number }[] = []
  for (let i = 0; i < desired.length; i++) {
    blocks.push({ sum: desired[i] - off[i], n: 1 })
    while (blocks.length > 1) {
      const b = blocks[blocks.length - 1]
      const a = blocks[blocks.length - 2]
      if (a.sum / a.n <= b.sum / b.n) break
      a.sum += b.sum
      a.n += b.n
      blocks.pop()
    }
  }
  const out: number[] = []
  for (const b of blocks) for (let k = 0; k < b.n; k++) out.push(b.sum / b.n + off[out.length])
  return out
}

const f = (n: number) => (Math.round(n * 10) / 10).toString()

export function layoutGraph(nodes: GraphNode[], edges: GraphEdge[], options: Partial<LayoutOptions> = {}): MapLayout {
  const o = { ...DEFAULT_LAYOUT, ...options }

  // Real objects, deduplicated, and the columns they occupy.
  const node = new Map<string, GraphNode>()
  for (const n of nodes) if (!node.has(n.id)) node.set(n.id, n)
  const ranks = [...new Set([...node.values()].map((n) => rankOf(n.kind)))].sort(byNumber)
  const colOfRank = new Map(ranks.map((r, i) => [r, i]))
  const kindsInRank = new Map<number, Set<string>>()
  for (const n of node.values()) {
    const r = rankOf(n.kind)
    kindsInRank.set(r, (kindsInRank.get(r) ?? new Set()).add(n.kind))
  }

  const items = new Map<string, Item>()
  for (const n of node.values()) {
    items.set(n.id, { id: n.id, real: true, column: colOfRank.get(rankOf(n.kind))!, band: bandOf(n.kind), name: n.name })
  }

  // Edges: forward ones become chains through waypoints; the rest are drawn but not laid out.
  interface Chain {
    from: string
    to: string
    ids: string[]
    forward: boolean
  }
  const chains: Chain[] = []
  const seen = new Set<string>()
  const down = new Map<string, string[]>()
  const up = new Map<string, string[]>()
  const link = (a: string, b: string) => {
    down.set(a, [...(down.get(a) ?? []), b])
    up.set(b, [...(up.get(b) ?? []), a])
  }
  edges.forEach((e, k) => {
    const a = items.get(e.from)
    const b = items.get(e.to)
    const key = `${e.from}\u0000${e.to}`
    if (!a || !b || e.from === e.to || seen.has(key)) return
    seen.add(key)
    if (b.column <= a.column) {
      chains.push({ from: e.from, to: e.to, ids: [e.from, e.to], forward: false })
      return
    }
    const ids = [e.from]
    for (let c = a.column + 1; c < b.column; c++) {
      const id = `\u0000${k}:${c}`
      items.set(id, { id, real: false, column: c, band: 0, name: '' })
      ids.push(id)
    }
    ids.push(e.to)
    for (let i = 1; i < ids.length; i++) link(ids[i - 1], ids[i])
    chains.push({ from: e.from, to: e.to, ids, forward: true })
  })

  const connected = (id: string) => (down.get(id)?.length ?? 0) + (up.get(id)?.length ?? 0) > 0

  // Initial order: band, then name; waypoints after the boxes until the first sweep places them.
  let layers: string[][] = ranks.map(() => [])
  for (const it of items.values()) layers[it.column].push(it.id)
  layers = layers.map((l) =>
    [...l].sort((a, b) => {
      const x = items.get(a)!
      const y = items.get(b)!
      return Number(!x.real) - Number(!y.real) || x.band - y.band || x.name.localeCompare(y.name) || a.localeCompare(b)
    }),
  )

  const reorder = (layer: string[], ref: string[], nbrs: Map<string, string[]>): string[] => {
    const refPos = new Map(ref.map((id, i) => [id, (i + 0.5) / ref.length]))
    const keyed = layer.map((id, i) => {
      const ps = (nbrs.get(id) ?? []).map((n) => refPos.get(n)).filter((p): p is number => p !== undefined)
      // No neighbour on this side: hold position. No neighbours at all: sink to the bottom.
      const bc = ps.length ? ps.reduce((s, p) => s + p, 0) / ps.length : connected(id) ? (i + 0.5) / layer.length : Infinity
      return { id, i, band: items.get(id)!.band, bc }
    })
    keyed.sort((a, b) => a.band - b.band || byNumber(a.bc, b.bc) || a.i - b.i)
    return keyed.map((k) => k.id)
  }

  const edgesBetween = (c: number): [string, string][] =>
    layers[c].flatMap((a) => (down.get(a) ?? []).map((b) => [a, b] as [string, string]))
  const total = (ls: string[][]) => {
    let n = 0
    for (let c = 0; c + 1 < ls.length; c++) n += countCrossings(ls[c], ls[c + 1], edgesBetween(c))
    return n
  }

  // First pass places waypoints; then alternate sweeps, keeping the best ordering seen.
  for (let c = 1; c < layers.length; c++) layers[c] = reorder(layers[c], layers[c - 1], up)
  let best = layers.map((l) => [...l])
  let bestCount = total(layers)
  for (let s = 0; s < o.sweeps && bestCount > 0; s++) {
    for (let c = layers.length - 2; c >= 0; c--) layers[c] = reorder(layers[c], layers[c + 1], down)
    for (let c = 1; c < layers.length; c++) layers[c] = reorder(layers[c], layers[c - 1], up)
    const n = total(layers)
    if (n < bestCount) {
      bestCount = n
      best = layers.map((l) => [...l])
    }
  }
  layers = best

  // Vertical placement.
  const size = (id: string) => (items.get(id)!.real ? o.boxH : o.laneH)
  const gap = (a: string, b: string) => (items.get(a)!.real && items.get(b)!.real ? o.rowGap : o.rowGap / 2)
  const top = new Map<string, number>()
  for (const l of layers) {
    let y = 0
    l.forEach((id, i) => {
      top.set(id, y)
      y += size(id) + (i + 1 < l.length ? gap(id, l[i + 1]) : 0)
    })
  }
  const centre = (id: string) => top.get(id)! + size(id) / 2
  const relax = (l: string[]) => {
    const desired = l.map((id) => {
      const ns = [...(up.get(id) ?? []), ...(down.get(id) ?? [])]
      if (!ns.length) return top.get(id)!
      return ns.reduce((s, n) => s + centre(n), 0) / ns.length - size(id) / 2
    })
    const placed = placeInOrder(
      desired,
      l.map(size),
      l.map((id, i) => (i + 1 < l.length ? gap(id, l[i + 1]) : 0)),
    )
    l.forEach((id, i) => top.set(id, placed[i]))
  }
  for (let it = 0; it < 4; it++) {
    for (const l of layers) relax(l)
    for (let c = layers.length - 1; c >= 0; c--) relax(layers[c])
  }
  let minTop = Infinity
  for (const y of top.values()) minTop = Math.min(minTop, y)
  const shift = (Number.isFinite(minTop) ? -minTop : 0) + o.pad + o.header
  for (const [id, y] of top) top.set(id, Math.round((y + shift) * 10) / 10)

  const colX = (c: number) => o.pad + c * (o.boxW + o.colGap)
  const boxes: Box[] = []
  layers.forEach((l, c) => {
    let row = 0
    for (const id of l) {
      if (!items.get(id)!.real) continue
      boxes.push({ id, x: colX(c), y: top.get(id)!, w: o.boxW, h: o.boxH, column: c, row: row++ })
    }
  })

  const paths: EdgePath[] = chains.map((ch) => {
    const a = items.get(ch.from)!
    const b = items.get(ch.to)!
    if (!ch.forward) {
      // Same column or pointing left: loop out from the right side of both.
      const x1 = colX(a.column) + o.boxW
      const x2 = colX(b.column) + o.boxW
      const y1 = centre(ch.from)
      const y2 = centre(ch.to)
      const bulge = Math.max(28, (x1 - x2) / 2)
      return { from: ch.from, to: ch.to, x1, y1, x2, y2, d: `M${f(x1)} ${f(y1)}C${f(x1 + bulge)} ${f(y1)} ${f(x2 + bulge)} ${f(y2)} ${f(x2)} ${f(y2)}` }
    }
    const x1 = colX(a.column) + o.boxW
    const y1 = centre(ch.from)
    let d = `M${f(x1)} ${f(y1)}`
    let px = x1
    let py = y1
    const curveTo = (x: number, y: number) => {
      const dx = (x - px) / 2
      d += `C${f(px + dx)} ${f(py)} ${f(x - dx)} ${f(y)} ${f(x)} ${f(y)}`
      px = x
      py = y
    }
    for (const id of ch.ids.slice(1, -1)) {
      const c = items.get(id)!.column
      curveTo(colX(c), centre(id))
      px = colX(c) + o.boxW
      d += `L${f(px)} ${f(py)}`
    }
    const x2 = colX(b.column)
    const y2 = centre(ch.to)
    curveTo(x2, y2)
    return { from: ch.from, to: ch.to, d, x1, y1, x2, y2 }
  })

  let bottom = o.pad + o.header
  for (const [id, y] of top) bottom = Math.max(bottom, y + size(id))
  const nCols = layers.length
  return {
    boxes,
    edges: paths,
    columns: ranks.map((r, c) => ({ x: colX(c), label: columnLabel(r, kindsInRank.get(r) ?? new Set()) })),
    width: nCols ? o.pad * 2 + nCols * o.boxW + (nCols - 1) * o.colGap : o.pad * 2,
    height: Math.ceil(bottom + o.pad),
    crossings: bestCount,
  }
}

/** Outgoing and incoming neighbours of every object, for highlighting and the list view. */
export function linksOf(edges: GraphEdge[]): { out: Map<string, string[]>; in: Map<string, string[]> } {
  const out = new Map<string, string[]>()
  const inc = new Map<string, string[]>()
  const seen = new Set<string>()
  for (const e of edges) {
    const key = `${e.from}\u0000${e.to}`
    if (e.from === e.to || seen.has(key)) continue
    seen.add(key)
    out.set(e.from, [...(out.get(e.from) ?? []), e.to])
    inc.set(e.to, [...(inc.get(e.to) ?? []), e.from])
  }
  return { out, in: inc }
}

const WORKLOAD_KINDS = new Set<string>(['Deployment', 'StatefulSet', 'DaemonSet', 'Job', 'CronJob'])

export function isWorkloadKind(kind: string): boolean {
  return WORKLOAD_KINDS.has(kind)
}

/** Where a map object links to; undefined for kinds with no page of their own. */
export function graphHref(n: GraphNode, namespace: string): string | undefined {
  const ns = n.namespace ?? namespace
  if (n.kind === 'Pod') return podHref(ns, n.name)
  if (isWorkloadKind(n.kind)) return workloadHref(ns, n.name)
  if (n.kind === 'PVC') return `#/storage?q=${encodeURIComponent(`${ns}/${n.name}`)}`
  if (n.kind === 'Node') return `#/map?view=nodes&node=${encodeURIComponent(n.name)}`
  return undefined
}
