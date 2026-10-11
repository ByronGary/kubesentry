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
import type { GraphEdge, GraphKind, GraphNode, Status } from './types'

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
  // Push in place: a Service or Node with hundreds of neighbours must not copy its list per edge.
  const push = (m: Map<string, string[]>, k: string, v: string) => {
    const l = m.get(k)
    if (l) l.push(v)
    else m.set(k, [v])
  }
  const link = (a: string, b: string) => {
    push(down, a, b)
    push(up, b, a)
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
    const o = out.get(e.from)
    if (o) o.push(e.to)
    else out.set(e.from, [e.to])
    const i = inc.get(e.to)
    if (i) i.push(e.from)
    else inc.set(e.to, [e.from])
  }
  return { out, in: inc }
}

const WORKLOAD_KINDS = new Set<string>(['Deployment', 'StatefulSet', 'DaemonSet', 'Job', 'CronJob'])

export function isWorkloadKind(kind: string): boolean {
  return WORKLOAD_KINDS.has(kind)
}

/**
 * Where a map object links to; undefined for kinds with no page of their own.
 * `nodes: false` drops links to the node view for users who cannot see nodes.
 */
export function graphHref(n: MapNode, namespace: string, opts: { nodes?: boolean } = {}): string | undefined {
  const ns = n.namespace ?? namespace
  const canNodes = opts.nodes ?? true
  if (n.group) {
    if (n.kind === 'Pod') return `#/pods?${new URLSearchParams({ namespace: ns, ...(n.group.owner ? { q: n.group.owner } : {}) })}`
    if (n.kind === 'PVC') return `#/storage?q=${encodeURIComponent(`${ns}/`)}`
    if (n.kind === 'Node') return canNodes ? '#/map?view=nodes' : undefined
    return undefined
  }
  if (n.kind === 'Pod') return podHref(ns, n.name)
  if (isWorkloadKind(n.kind)) return workloadHref(ns, n.name)
  if (n.kind === 'PVC') return `#/storage?q=${encodeURIComponent(`${ns}/${n.name}`)}`
  if (n.kind === 'Node') return canNodes ? `#/map?view=nodes&node=${encodeURIComponent(n.name)}` : undefined
  return undefined
}

/** The kind line on a box: the real kind behind a Controller (e.g. Rollout), or the plural for a group. */
export function kindLabel(n: MapNode): string {
  if (n.group) return GROUP_LABEL[n.kind] ?? `${n.kind}s`
  if (n.kind === 'Controller') return n.ownerKind ? `${n.ownerKind} (controller)` : 'Controller'
  return n.kind
}

const GROUP_LABEL: Partial<Record<GraphKind, string>> = { Pod: 'Pods', PVC: 'Volume claims', Node: 'Nodes' }

/**
 * Endpoint states on a Service link: "3 ready, 1 not ready, 2 terminating".
 * Undefined when the link carries none (it was not found through EndpointSlices).
 */
export function endpointText(e: Pick<GraphEdge, 'how' | 'ready' | 'notReady' | 'terminating'>): string | undefined {
  const any = e.ready !== undefined || e.notReady !== undefined || e.terminating !== undefined
  if (!any && e.how !== 'endpoints') return undefined
  const parts = [`${e.ready ?? 0} ready`]
  if (e.notReady) parts.push(`${e.notReady} not ready`)
  if (e.terminating) parts.push(`${e.terminating} terminating`)
  return parts.join(', ')
}

/** How a link was found, in words, for the list view and tooltips. */
export function howText(how: GraphEdge['how']): string | undefined {
  switch (how) {
    case 'owner':
      return 'owner reference'
    case 'endpoints':
      return 'endpoints'
    case 'selector':
      return 'matched by labels'
    default:
      return undefined
  }
}

// Collapsing big namespaces.
//
// A workload with hundreds of pods would make a column thousands of pixels
// tall and the SVG slow. Pods sharing an owner collapse into one box past a
// threshold, claims used only by such a group collapse with them, and many
// nodes collapse into one box that links to the node view.

/** A graph object as drawn: a real one, or a group standing for several. */
export interface MapNode extends GraphNode {
  group?: {
    /** How many objects it stands for. */
    count: number
    /** Name of the owning workload, for pod groups. */
    owner?: string
  }
}

/** A drawn link; `merged` counts the real links it stands for. */
export interface MapEdge extends GraphEdge {
  merged?: number
}

export interface CollapseOptions {
  /** Pods per owner above which they become one box. */
  maxPods: number
  /** Pods shown one by one at most; past it the biggest remaining owners collapse too. */
  maxTotalPods: number
  /** Claims per pod group above which they become one box. */
  maxClaims: number
  /** Nodes above which they become one box. */
  maxNodes: number
}

export const DEFAULT_COLLAPSE: CollapseOptions = { maxPods: 12, maxTotalPods: 150, maxClaims: 12, maxNodes: 24 }

export interface CollapsedGraph {
  nodes: MapNode[]
  edges: MapEdge[]
  /** Group id to the ids it stands for. */
  members: Map<string, string[]>
  /** Real objects hidden inside groups. */
  hidden: number
}

const STATUS_ORDER: Status[] = ['crit', 'warn', 'unknown', 'ok']
const STATUS_WORD: Record<Status, string> = { crit: 'critical', warn: 'warning', unknown: 'unknown', ok: 'OK' }

function worstOf(ns: GraphNode[]): Status {
  const has = new Set(ns.map((n) => n.status))
  return STATUS_ORDER.find((s) => has.has(s)) ?? 'unknown'
}

/** "2 critical, 5 warning, 280 OK", worst first. */
export function statusMix(ns: GraphNode[]): string {
  const c: Record<Status, number> = { crit: 0, warn: 0, unknown: 0, ok: 0 }
  for (const n of ns) c[n.status in c ? n.status : 'unknown']++
  return STATUS_ORDER.filter((s) => c[s] > 0)
    .map((s) => `${c[s]} ${STATUS_WORD[s]}`)
    .join(', ')
}

const HOW_RANK: Record<string, number> = { endpoints: 0, owner: 1, selector: 2 }
const GROUP = '\u0001'

/** Whether an id is a group made by collapseGraph. */
export function isGroupId(id: string): boolean {
  return id.startsWith(GROUP)
}

export function collapseGraph(nodes: GraphNode[], edges: GraphEdge[], o: CollapseOptions = DEFAULT_COLLAPSE): CollapsedGraph {
  const byId = new Map<string, GraphNode>()
  for (const n of nodes) if (!byId.has(n.id)) byId.set(n.id, n)

  // Each pod's owner: an incoming link from a workload-like object (lowest id wins, for stable output).
  const ownerOf = new Map<string, string>()
  for (const e of edges) {
    const to = byId.get(e.to)
    const from = byId.get(e.from)
    if (to?.kind !== 'Pod' || !from || rankOf(from.kind) !== RANK.Deployment) continue
    const cur = ownerOf.get(e.to)
    if (cur === undefined || e.from < cur) ownerOf.set(e.to, e.from)
  }
  const podBuckets = new Map<string, string[]>()
  for (const n of byId.values()) {
    if (n.kind !== 'Pod') continue
    const k = ownerOf.get(n.id) ?? ''
    const b = podBuckets.get(k)
    if (b) b.push(n.id)
    else podBuckets.set(k, [n.id])
  }

  const rep = new Map<string, string>()
  const members = new Map<string, string[]>()
  const groups: MapNode[] = []
  const addGroup = (id: string, kind: GraphKind, ids: string[], noun: [string, string], owner?: string) => {
    const ms = ids.map((m) => byId.get(m)!)
    groups.push({
      id,
      kind,
      name: `${ids.length} ${ids.length === 1 ? noun[0] : noun[1]}`,
      namespace: ms[0]?.namespace,
      status: worstOf(ms),
      detail: statusMix(ms),
      group: owner ? { count: ids.length, owner } : { count: ids.length },
    })
    members.set(id, ids)
    for (const m of ids) rep.set(m, id)
  }

  // Big owners always fold. If too many single pods remain, fold the biggest
  // remaining owners (two pods or more) until the rest fit the budget.
  const buckets = [...podBuckets].sort((a, b) => b[1].length - a[1].length || (a[0] < b[0] ? -1 : 1))
  let single = 0
  for (const [, ids] of buckets) if (ids.length <= o.maxPods) single += ids.length
  for (const [owner, ids] of buckets) {
    const big = ids.length > o.maxPods
    const overBudget = !big && single > o.maxTotalPods && ids.length > 1 && owner !== ''
    if (!big && !overBudget) continue
    if (overBudget) single -= ids.length
    addGroup(`${GROUP}pods:${owner}`, 'Pod', ids, ['pod', 'pods'], byId.get(owner)?.name)
  }

  // Claims used by exactly one pod group collapse with it.
  if (members.size > 0) {
    const sources = new Map<string, Set<string>>()
    for (const e of edges) {
      if (byId.get(e.to)?.kind !== 'PVC' || !byId.has(e.from)) continue
      const s = sources.get(e.to)
      if (s) s.add(rep.get(e.from) ?? e.from)
      else sources.set(e.to, new Set([rep.get(e.from) ?? e.from]))
    }
    const claimBuckets = new Map<string, string[]>()
    for (const [pvc, s] of sources) {
      if (s.size !== 1) continue
      const [g] = s
      if (!members.has(g)) continue
      const b = claimBuckets.get(g)
      if (b) b.push(pvc)
      else claimBuckets.set(g, [pvc])
    }
    for (const [g, ids] of claimBuckets) {
      if (ids.length > o.maxClaims) addGroup(`${GROUP}claims:${g}`, 'PVC', ids, ['claim', 'claims'])
    }
  }

  const nodeIds: string[] = []
  for (const n of byId.values()) if (n.kind === 'Node') nodeIds.push(n.id)
  if (nodeIds.length > o.maxNodes) addGroup(`${GROUP}nodes`, 'Node', nodeIds, ['node', 'nodes'])

  const out: MapEdge[] = []
  const at = new Map<string, number>()
  for (const e of edges) {
    if (!byId.has(e.from) || !byId.has(e.to)) continue
    const from = rep.get(e.from) ?? e.from
    const to = rep.get(e.to) ?? e.to
    if (from === to) continue
    const k = `${from}\u0000${to}`
    const i = at.get(k)
    if (i === undefined) {
      at.set(k, out.length)
      out.push({ ...e, from, to, merged: 1 })
      continue
    }
    const m = out[i]
    m.merged = (m.merged ?? 1) + 1
    if (e.ready !== undefined || m.ready !== undefined) m.ready = (m.ready ?? 0) + (e.ready ?? 0)
    if (e.notReady !== undefined || m.notReady !== undefined) m.notReady = (m.notReady ?? 0) + (e.notReady ?? 0)
    if (e.terminating !== undefined || m.terminating !== undefined) m.terminating = (m.terminating ?? 0) + (e.terminating ?? 0)
    // A merged link is as solid as its strongest member.
    if (e.how && (!m.how || (HOW_RANK[e.how] ?? 3) < (HOW_RANK[m.how] ?? 3))) m.how = e.how
  }

  const kept: MapNode[] = []
  for (const n of byId.values()) if (!rep.has(n.id)) kept.push(n)
  return { nodes: [...kept, ...groups], edges: out, members, hidden: rep.size }
}

/** "316 pods of 2 workloads and 275 nodes", for the note above a collapsed map. */
export function groupedText(groups: MapNode[]): string {
  const sum = (kind: GraphKind) => groups.filter((g) => g.kind === kind && g.group).reduce((s, g) => s + (g.group?.count ?? 0), 0)
  const owners = groups.filter((g) => g.kind === 'Pod' && g.group).length
  const parts: string[] = []
  const pods = sum('Pod')
  if (pods) parts.push(`${pods} ${pods === 1 ? 'pod' : 'pods'} of ${owners} ${owners === 1 ? 'owner' : 'owners'}`)
  const claims = sum('PVC')
  if (claims) parts.push(`${claims} volume ${claims === 1 ? 'claim' : 'claims'}`)
  const nodes = sum('Node')
  if (nodes) parts.push(`${nodes} ${nodes === 1 ? 'node' : 'nodes'}`)
  return parts.length > 1 ? `${parts.slice(0, -1).join(', ')} and ${parts[parts.length - 1]}` : (parts[0] ?? '')
}
