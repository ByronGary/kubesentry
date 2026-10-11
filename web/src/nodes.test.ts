import { describe, expect, it } from 'vitest'
import { aggregateNodes, filterNodes, groupNodes, mixText, NO_ZONE, nodeCountText, podCountOf, poolOf } from './nodes'
import type { NodeSummary, Placement } from './types'

const node = (name: string, placement?: Placement, extra: Partial<NodeSummary> = {}): NodeSummary => ({
  name,
  roles: [],
  ready: true,
  unschedulable: false,
  status: 'ok',
  detail: '',
  kubeletVersion: 'v1.31.2',
  osImage: 'Bottlerocket',
  containerRuntime: 'containerd://1.7',
  pressure: [],
  taints: [],
  cpuAllocatableMilli: 4000,
  cpuRequestedMilli: 1000,
  memoryAllocatableBytes: 16 * 2 ** 30,
  memoryRequestedBytes: 4 * 2 ** 30,
  podsAllocatable: 58,
  pods: undefined as never,
  podCount: 10,
  placement,
  ...extra,
})

const ng = (pool: string, zone: string, extra: Partial<Placement> = {}): Placement => ({ pool, poolKind: 'nodegroup', zone, capacityType: 'on-demand', arch: 'amd64', instanceType: 'm6i.xlarge', ...extra })

describe('poolOf', () => {
  it('uses the node group or Karpenter pool', () => {
    expect(poolOf(node('a', ng('general', 'us-east-1a')))).toEqual({ key: 'nodegroup:general', name: 'general', kind: 'nodegroup' })
    expect(poolOf(node('b', { pool: 'spot-arm', poolKind: 'karpenter' })).kind).toBe('karpenter')
  })
  it('groups Fargate nodes, then falls back to roles, then to "no pool"', () => {
    expect(poolOf(node('fargate-ip-1', { poolKind: 'fargate' }))).toEqual({ key: 'fargate:', name: 'Fargate', kind: 'fargate' })
    expect(poolOf(node('cp', undefined, { roles: ['control-plane'] }))).toEqual({ key: 'role:control-plane', name: 'control-plane', kind: 'role' })
    expect(poolOf(node('w', undefined)).kind).toBe('none')
  })
})

describe('podCountOf', () => {
  it('uses podCount from summaries and the pod list from older servers', () => {
    expect(podCountOf(node('a'))).toBe(10)
    expect(podCountOf(node('a', undefined, { podCount: undefined, pods: [{ namespace: 'x', name: 'y', phase: 'Running', status: 'ok' }] }))).toBe(1)
    expect(podCountOf(node('a', undefined, { podCount: undefined }))).toBe(0)
  })
})

describe('aggregateNodes', () => {
  it('sums capacity and requests and counts states and mixes', () => {
    const a = aggregateNodes([
      node('a', ng('g', 'z1', { capacityType: 'spot', arch: 'arm64', instanceType: 'm7g.xlarge' })),
      node('b', ng('g', 'z1'), { ready: false, status: 'crit' }),
      node('c', ng('g', 'z2'), { unschedulable: true, status: 'warn' }),
    ])
    expect(a).toMatchObject({ count: 3, ready: 2, notReady: 1, cordoned: 1, status: 'crit', pods: 30, podsAllocatable: 174 })
    expect(a.cpuAllocatableMilli).toBe(12_000)
    expect(a.cpuRequestedMilli).toBe(3000)
    expect(a.memoryAllocatableBytes).toBe(48 * 2 ** 30)
    expect(a.capacityTypes).toEqual([
      ['On-demand', 2],
      ['Spot', 1],
    ])
    expect(a.arch).toEqual([
      ['amd64', 2],
      ['arm64', 1],
    ])
    expect(a.byStatus).toEqual({ ok: 1, warn: 1, crit: 1, unknown: 0 })
  })
  it('is all zeros and ok for no nodes', () => {
    expect(aggregateNodes([])).toMatchObject({ count: 0, status: 'ok', pods: 0, capacityTypes: [] })
  })
})

describe('groupNodes', () => {
  it('groups by pool, then zone; troubled and bigger pools first; troubled nodes first', () => {
    const nodes = [
      node('g-1', ng('general', 'us-east-1a')),
      node('g-2', ng('general', 'us-east-1b')),
      node('g-3', ng('general', 'us-east-1a')),
      node('g-10', ng('general', 'us-east-1a'), { status: 'warn' }),
      node('k-1', { pool: 'batch', poolKind: 'karpenter', zone: 'us-east-1a', capacityType: 'spot' }, { status: 'crit' }),
      node('loose', undefined),
    ]
    const g = groupNodes(nodes)
    expect(g.map((p) => p.name)).toEqual(['batch', 'general', 'Nodes without a pool label'])
    const general = g[1]
    expect(general.agg.count).toBe(4)
    expect(general.zones.map((z) => z.zone)).toEqual(['us-east-1a', 'us-east-1b'])
    expect(general.zones[0].nodes.map((n) => n.name)).toEqual(['g-10', 'g-1', 'g-3'])
    expect(general.zones[0].agg.count).toBe(3)
    expect(g[2].zones[0].zone).toBe(NO_ZONE)
  })
  it('groups thousands of nodes quickly', () => {
    const nodes = Array.from({ length: 5000 }, (_, i) => node(`n-${i}`, ng(`pool-${i % 12}`, `zone-${i % 3}`)))
    const t = performance.now()
    const g = groupNodes(nodes)
    expect(performance.now() - t).toBeLessThan(500)
    expect(g).toHaveLength(12)
    expect(g.reduce((s, p) => s + p.agg.count, 0)).toBe(5000)
  })
})

describe('text', () => {
  it('summarises mixes and counts', () => {
    expect(mixText([['Spot', 12], ['On-demand', 3]])).toBe('Spot 12 · On-demand 3')
    expect(mixText([['a', 5], ['b', 4], ['c', 3], ['d', 2], ['e', 1]], 2)).toBe('a 5 · b 4 · other 6')
    expect(mixText([])).toBe('')
    expect(nodeCountText(aggregateNodes([node('a'), node('b', undefined, { ready: false, unschedulable: true })]))).toBe('2 nodes, 1 not ready, 1 cordoned')
  })
  it('searches name, pool, zone and instance type', () => {
    const nodes = [node('ip-10-0-1-1', ng('general', 'us-east-1a')), node('ip-10-0-2-2', ng('gpu', 'us-east-1b', { instanceType: 'g5.2xlarge' }))]
    expect(filterNodes(nodes, 'g5').map((n) => n.name)).toEqual(['ip-10-0-2-2'])
    expect(filterNodes(nodes, 'east-1a').map((n) => n.name)).toEqual(['ip-10-0-1-1'])
    expect(filterNodes(nodes, '  ')).toBe(nodes)
  })
})
