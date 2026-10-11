import { describe, expect, it } from 'vitest'
import { countCrossings, graphHref, layoutGraph, linksOf, placeInOrder, type MapLayout } from './mapLayout'
import type { GraphEdge, GraphKind, GraphNode } from './types'

const n = (kind: GraphKind, name: string, ns = 'shop'): GraphNode =>
  kind === 'Node' ? { id: `Node/${name}`, kind, name, status: 'ok', detail: '' } : { id: `${kind}/${ns}/${name}`, kind, name, namespace: ns, status: 'ok', detail: '' }
const e = (from: GraphNode, to: GraphNode): GraphEdge => ({ from: from.id, to: to.id })

const ing = n('Ingress', 'web')
const svc = n('Service', 'web')
const dep = n('Deployment', 'web')
const pod1 = n('Pod', 'web-7d9-a')
const pod2 = n('Pod', 'web-7d9-b')
const pvc = n('PVC', 'data')
const node = n('Node', 'node-1')
const shopNodes = [ing, svc, dep, pod1, pod2, pvc, node]
const shopEdges = [e(ing, svc), e(svc, dep), e(dep, pod1), e(dep, pod2), e(pod1, node), e(pod2, node), e(pod1, pvc)]

const box = (l: MapLayout, id: string) => {
  const b = l.boxes.find((x) => x.id === id)
  if (!b) throw new Error(`no box ${id}`)
  return b
}

describe('layoutGraph columns', () => {
  it('puts each kind in its column, left to right', () => {
    const l = layoutGraph(shopNodes, shopEdges)
    expect([ing, svc, dep, pod1, pod2, pvc, node].map((x) => box(l, x.id).column)).toEqual([0, 1, 2, 3, 3, 4, 4])
    expect(l.columns.map((c) => c.label)).toEqual(['Ingresses', 'Services', 'Workloads', 'Pods', 'Claims and nodes'])
    const xs = l.columns.map((c) => c.x)
    expect(xs).toEqual([...xs].sort((a, b) => a - b))
    expect(l.width).toBeGreaterThanOrEqual(xs[4] + box(l, node.id).w)
    expect(l.height).toBeGreaterThanOrEqual(Math.max(...l.boxes.map((b) => b.y + b.h)))
  })

  it('drops empty columns and gives CronJobs their own', () => {
    const cj = n('CronJob', 'nightly')
    const job = n('Job', 'nightly-1')
    const p = n('Pod', 'nightly-1-x')
    const l = layoutGraph([p, job, cj], [e(cj, job), e(job, p)])
    expect([cj, job, p].map((x) => box(l, x.id).column)).toEqual([0, 1, 2])
    expect(l.columns.map((c) => c.label)).toEqual(['CronJobs', 'Workloads', 'Pods'])
  })

  it('keeps claims above nodes in the shared column', () => {
    const l = layoutGraph(shopNodes, shopEdges)
    expect(box(l, pvc.id).y).toBeLessThan(box(l, node.id).y)
  })

  it('handles an empty graph', () => {
    const l = layoutGraph([], [])
    expect(l.boxes).toEqual([])
    expect(l.edges).toEqual([])
    expect(l.width).toBeGreaterThan(0)
    expect(l.height).toBeGreaterThan(0)
  })
})

describe('layoutGraph ordering', () => {
  it('is deterministic whatever the input order', () => {
    const a = layoutGraph(shopNodes, shopEdges)
    const b = layoutGraph([...shopNodes].reverse(), shopEdges)
    expect(b.boxes).toEqual(a.boxes)
    expect(layoutGraph(shopNodes, shopEdges)).toEqual(a)
  })

  it('removes the crossings that name order would give', () => {
    const [sa, sb, sc] = ['a', 'b', 'c'].map((x) => n('Service', x))
    const [dx, dy, dz] = ['x', 'y', 'z'].map((x) => n('Deployment', x))
    const edges = [e(sa, dz), e(sb, dy), e(sc, dx)]
    const pairs = edges.map((x) => [x.from, x.to] as [string, string])
    expect(countCrossings([sa, sb, sc].map((x) => x.id), [dx, dy, dz].map((x) => x.id), pairs)).toBe(3)
    const l = layoutGraph([sa, sb, sc, dx, dy, dz], edges)
    expect(l.crossings).toBe(0)
    expect([dz, dy, dx].map((x) => box(l, x.id).row)).toEqual([0, 1, 2])
  })

  it('sinks unconnected objects to the bottom of their column', () => {
    const lonely = n('Service', 'aaa-unused')
    const l = layoutGraph([...shopNodes, lonely], shopEdges)
    expect(box(l, lonely.id).row).toBe(1)
    expect(box(l, svc.id).row).toBe(0)
  })

  it('never overlaps boxes in a column', () => {
    const pods = Array.from({ length: 12 }, (_, i) => n('Pod', `p${i}`))
    const deps = [n('Deployment', 'a'), n('Deployment', 'b')]
    const edges = pods.map((p, i) => e(deps[i % 2], p))
    const l = layoutGraph([...deps, ...pods], edges)
    for (const col of [0, 1]) {
      const bs = l.boxes.filter((b) => b.column === col).sort((a, b) => a.y - b.y)
      for (let i = 1; i < bs.length; i++) expect(bs[i].y).toBeGreaterThanOrEqual(bs[i - 1].y + bs[i - 1].h)
      expect(bs.map((b) => b.row)).toEqual(bs.map((_, i) => i))
    }
  })
})

describe('layoutGraph edges', () => {
  it('runs from the right edge of the source to the left edge of the target', () => {
    const l = layoutGraph(shopNodes, shopEdges)
    expect(l.edges).toHaveLength(shopEdges.length)
    for (const p of l.edges) {
      const a = box(l, p.from)
      const b = box(l, p.to)
      expect(p.x1).toBe(a.x + a.w)
      expect(p.y1).toBeCloseTo(a.y + a.h / 2, 1)
      expect(p.x2).toBe(b.x)
      expect(p.y2).toBeCloseTo(b.y + b.h / 2, 1)
      expect(p.d.startsWith('M')).toBe(true)
      expect(p.d).toContain('C')
      const nums = p.d.match(/-?\d+(\.\d+)?/g)!.map(Number)
      expect(nums.slice(0, 2)).toEqual([+p.x1.toFixed(1), +p.y1.toFixed(1)])
      expect(nums.slice(-2)).toEqual([+p.x2.toFixed(1), +p.y2.toFixed(1)])
    }
  })

  it('routes an edge that skips a column through a lane, not a box', () => {
    const bare = n('Pod', 'bare')
    const l = layoutGraph([...shopNodes, bare], [...shopEdges, e(svc, bare)])
    const p = l.edges.find((x) => x.to === bare.id)!
    expect(p.d).toContain('L')
    const lane = Number(p.d.split('L')[1].split(' ')[1].split('C')[0])
    for (const b of l.boxes.filter((x) => x.column === 2)) {
      expect(lane < b.y || lane > b.y + b.h).toBe(true)
    }
  })

  it('ignores self loops, duplicates and edges to unknown objects', () => {
    const l = layoutGraph([svc, dep], [e(svc, dep), e(svc, dep), e(svc, svc), { from: svc.id, to: 'Pod/shop/gone' }])
    expect(l.edges).toHaveLength(1)
  })
})

describe('helpers', () => {
  it('fits positions in order with minimum gaps', () => {
    expect(placeInOrder([0, 0, 0], [10, 10, 10], [2, 2, 0])).toEqual([-12, 0, 12])
    expect(placeInOrder([0, 100], [10, 10], [2, 0])).toEqual([0, 100])
  })

  it('counts crossings', () => {
    expect(countCrossings(['a', 'b'], ['x', 'y'], [['a', 'x'], ['b', 'y']])).toBe(0)
    expect(countCrossings(['a', 'b'], ['x', 'y'], [['a', 'y'], ['b', 'x']])).toBe(1)
    expect(countCrossings(['a', 'b'], ['x', 'y'], [['a', 'x'], ['a', 'y'], ['b', 'x']])).toBe(1)
  })

  it('links objects to their pages', () => {
    expect(graphHref(pod1, 'shop')).toBe('#/pods/shop/web-7d9-a')
    expect(graphHref(dep, 'shop')).toBe('#/workloads?namespace=shop&q=web')
    expect(graphHref(pvc, 'shop')).toBe('#/storage?q=shop%2Fdata')
    expect(graphHref(node, 'shop')).toBe('#/map?view=nodes&node=node-1')
    expect(graphHref(svc, 'shop')).toBeUndefined()
    expect(graphHref(ing, 'shop')).toBeUndefined()
  })

  it('collects incoming and outgoing links', () => {
    const { out, in: inc } = linksOf(shopEdges)
    expect(out.get(dep.id)).toEqual([pod1.id, pod2.id])
    expect(inc.get(node.id)).toEqual([pod1.id, pod2.id])
  })
})
