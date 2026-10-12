import { describe, expect, it } from 'vitest'
import { collapseGraph, countCrossings, endpointText, graphHref, groupedText, howText, kindLabel, layoutGraph, linksOf, placeInOrder, type MapLayout } from './mapLayout'
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
    expect(graphHref(node, 'shop')).toBe('#/nodes?node=node-1')
    expect(graphHref(svc, 'shop')).toBeUndefined()
    expect(graphHref(ing, 'shop')).toBeUndefined()
  })

  it('collects incoming and outgoing links', () => {
    const { out, in: inc } = linksOf(shopEdges)
    expect(out.get(dep.id)).toEqual([pod1.id, pod2.id])
    expect(inc.get(node.id)).toEqual([pod1.id, pod2.id])
  })

  it('drops node links for users who cannot see nodes', () => {
    expect(graphHref(node, 'shop', { nodes: false })).toBeUndefined()
    expect(graphHref(pod1, 'shop', { nodes: false })).toBe('#/pods/shop/web-7d9-a')
  })
})

describe('new kinds and links', () => {
  it('puts ReplicaSets and other controllers in the workload column', () => {
    const rs = n('ReplicaSet', 'web-7d9')
    const ctl: GraphNode = { ...n('Controller', 'canary'), ownerKind: 'Rollout' }
    const l = layoutGraph([svc, rs, ctl, pod1, pod2], [e(svc, rs), e(rs, pod1), e(ctl, pod2)])
    expect(box(l, rs.id).column).toBe(box(l, ctl.id).column)
    expect(l.columns.map((c) => c.label)).toEqual(['Services', 'Workloads', 'Pods'])
    expect(kindLabel(ctl)).toBe('Rollout (controller)')
    expect(kindLabel({ ...ctl, ownerKind: undefined })).toBe('Controller')
    expect(kindLabel(rs)).toBe('ReplicaSet')
    expect(graphHref(rs, 'shop')).toBeUndefined()
    expect(graphHref(ctl, 'shop')).toBeUndefined()
  })

  it('describes endpoint states and how a link was found', () => {
    expect(endpointText({ how: 'endpoints', ready: 3, notReady: 1, terminating: 2 })).toBe('3 ready, 1 not ready, 2 terminating')
    // The server omits zero counts.
    expect(endpointText({ how: 'endpoints', notReady: 2 })).toBe('0 ready, 2 not ready')
    expect(endpointText({ how: 'endpoints' })).toBe('0 ready')
    expect(endpointText({ how: 'owner' })).toBeUndefined()
    expect(endpointText({})).toBeUndefined()
    expect(howText('selector')).toBe('matched by labels')
    expect(howText(undefined)).toBeUndefined()
  })
})

describe('collapseGraph', () => {
  const big = (pods: number, nodes: number) => {
    const ns: GraphNode[] = [svc, dep]
    const es: GraphEdge[] = [{ from: svc.id, to: dep.id, how: 'endpoints', ready: pods - 2, notReady: 2 }]
    const nodeList = Array.from({ length: nodes }, (_, i) => n('Node', `node-${i}`))
    ns.push(...nodeList)
    for (let i = 0; i < pods; i++) {
      const p = { ...n('Pod', `web-${i}`), status: (i === 0 ? 'crit' : 'ok') as GraphNode['status'] }
      const c = n('PVC', `data-web-${i}`)
      ns.push(p, c)
      es.push({ from: dep.id, to: p.id, how: 'owner' }, e(p, nodeList[i % nodes]), e(p, c))
    }
    return { nodes: ns, edges: es }
  }

  it('leaves small namespaces alone', () => {
    const g = collapseGraph(shopNodes, shopEdges)
    expect(g.hidden).toBe(0)
    expect(g.nodes.map((x) => x.id)).toEqual(shopNodes.map((x) => x.id))
    expect(g.edges).toHaveLength(shopEdges.length)
  })

  it('folds a big workload into one pod box, its claims into one, and many nodes into one', () => {
    const { nodes, edges } = big(300, 40)
    const g = collapseGraph(nodes, edges)
    const groups = g.nodes.filter((x) => x.group)
    expect(groups.map((x) => [x.kind, x.name])).toEqual([
      ['Pod', '300 pods'],
      ['PVC', '300 claims'],
      ['Node', '40 nodes'],
    ])
    const pods = groups[0]
    expect(pods.status).toBe('crit')
    expect(pods.detail).toBe('1 critical, 299 OK')
    expect(pods.group).toEqual({ count: 300, owner: 'web' })
    expect(g.hidden).toBe(640)
    expect(g.nodes).toHaveLength(2 + 3)
    // Links are merged, keep their method, and the Service link keeps its endpoint counts.
    expect(g.edges.map((x) => [x.from, x.to, x.merged])).toEqual([
      [svc.id, dep.id, 1],
      [dep.id, pods.id, 300],
      [pods.id, groups[2].id, 300],
      [pods.id, groups[1].id, 300],
    ])
    expect(g.edges[0]).toMatchObject({ how: 'endpoints', ready: 298, notReady: 2 })
    expect(g.edges[1].how).toBe('owner')
    expect(graphHref(pods, 'shop')).toBe('#/pods?namespace=shop&q=web')
    expect(graphHref(groups[1], 'shop')).toBe('#/storage?q=shop%2F')
    expect(graphHref(groups[2], 'shop')).toBe('#/nodes')
    expect(graphHref(groups[2], 'shop', { nodes: false })).toBeUndefined()
    expect(kindLabel(pods)).toBe('Pods')
  })

  it('sums endpoint counts when Service links to pods merge', () => {
    const pods = Array.from({ length: 20 }, (_, i) => n('Pod', `p-${i}`))
    const edges: GraphEdge[] = pods.flatMap((p, i) => [
      { from: dep.id, to: p.id, how: 'owner' as const },
      { from: svc.id, to: p.id, how: 'endpoints' as const, ready: i < 15 ? 1 : undefined, terminating: i >= 18 ? 1 : undefined },
    ])
    const g = collapseGraph([svc, dep, ...pods], edges)
    const toGroup = g.edges.find((x) => x.from === svc.id)!
    expect(endpointText(toGroup)).toBe('15 ready, 2 terminating')
  })

  it('keeps pods of different owners apart and shared claims out of groups', () => {
    const other = n('StatefulSet', 'db')
    const shared = n('PVC', 'shared')
    const a = Array.from({ length: 13 }, (_, i) => n('Pod', `a-${i}`))
    const b = Array.from({ length: 3 }, (_, i) => n('Pod', `b-${i}`))
    const edges = [...a.map((p) => e(dep, p)), ...b.map((p) => e(other, p)), e(a[0], shared), e(b[0], shared)]
    const g = collapseGraph([dep, other, shared, ...a, ...b], edges)
    expect(g.nodes.filter((x) => x.group).map((x) => x.name)).toEqual(['13 pods'])
    expect(g.nodes.some((x) => x.id === shared.id)).toBe(true)
    expect(g.nodes.filter((x) => x.kind === 'Pod' && !x.group)).toHaveLength(3)
  })

  it('folds the biggest small owners too when too many single pods remain', () => {
    const owners = Array.from({ length: 100 }, (_, i) => n('Deployment', `w-${i}`))
    const nodes: GraphNode[] = [...owners]
    const edges: GraphEdge[] = []
    owners.forEach((w, i) => {
      // Owners 0-9 have 3 pods, the rest 1 or 2.
      const count = i < 10 ? 3 : 1 + (i % 2)
      for (let k = 0; k < count; k++) {
        const p = n('Pod', `${w.name}-${k}`)
        nodes.push(p)
        edges.push(e(w, p))
      }
    })
    const all = nodes.filter((x) => x.kind === 'Pod').length
    expect(all).toBe(30 + 45 * 1 + 45 * 2)
    const g = collapseGraph(nodes, edges, { maxPods: 12, maxTotalPods: 150, maxClaims: 12, maxNodes: 24 })
    const single = g.nodes.filter((x) => x.kind === 'Pod' && !x.group).length
    expect(single).toBeLessThanOrEqual(150)
    // The 3-pod owners went first.
    expect(g.nodes.filter((x) => x.group).every((x) => x.group!.count === 3)).toBe(true)
    expect(collapseGraph(nodes, edges, { maxPods: 12, maxTotalPods: 1000, maxClaims: 12, maxNodes: 24 }).hidden).toBe(0)
  })

  it('describes what was grouped', () => {
    const { nodes, edges } = big(300, 40)
    const g = collapseGraph(nodes, edges)
    expect(groupedText(g.nodes)).toBe('300 pods of 1 owner, 300 volume claims and 40 nodes')
    expect(groupedText([])).toBe('')
  })

  it('makes a 10,000-pod namespace small enough to lay out quickly', () => {
    const { nodes, edges } = big(10_000, 500)
    const t = performance.now()
    const g = collapseGraph(nodes, edges)
    const l = layoutGraph(g.nodes, g.edges)
    expect(performance.now() - t).toBeLessThan(1500)
    expect(l.boxes).toHaveLength(5)
    expect(l.height).toBeLessThan(1000)
  })
})
