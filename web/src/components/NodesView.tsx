import { Fragment, useEffect, useMemo, useRef, useState } from 'react'
import { ApiError } from '../api'
import { podHref, workloadHref } from '../findings'
import { formatBytes, formatCPU, percent, plural } from '../format'
import { reasonStatus, splitWorkload } from '../inventory'
import { aggregateNodes, COLLAPSE_NODES_ABOVE, filterNodes, groupNodes, mixText, nodeCountText, podCountOf, POOL_KIND_LABEL, type NodeAggregate, type PoolGroup } from '../nodes'
import type { NodePod, NodeSummary, NodesResponse } from '../types'
import { useApi, useDebounced } from '../useApi'
import { Async, Empty, slashBreaks, StatusGlyph } from './ui'

// Nodes by pool and zone, how much of them is requested, and the pods they run:
// the Nodes page, once the Map's node view.

/** `focus` opens and scrolls to one node; `q` is the search, kept in the address by the page. */
export function NodesView({ focus, q, onQuery }: { focus: string; q: string; onQuery: (q: string) => void }) {
  const state = useApi<NodesResponse>('/api/v1/nodes?summary=true', 30_000)
  const all = state.data?.items
  const large = (all?.length ?? 0) > COLLAPSE_NODES_ABOVE
  // A small cluster shows every node as a card with its pods; a server that
  // honoured summary=true left the pods out, so ask once more for them.
  const needPods = !!all && !large && all.some((n) => n.pods === undefined && podCountOf(n) > 0)
  const full = useApi<NodesResponse>(needPods ? '/api/v1/nodes' : null, 30_000)
  const nodes = useMemo(() => {
    if (!all || !full.data) return all ?? []
    const pods = new Map(full.data.items.map((n) => [n.name, n.pods]))
    // types.ts declares pods as always present, but summary responses leave it out.
    return all.map((n) => (n.pods === undefined && pods.get(n.name) ? { ...n, pods: pods.get(n.name)! } : n))
  }, [all, full.data])

  const dq = useDebounced(q)
  const shown = useMemo(() => filterNodes(nodes, dq), [nodes, dq])
  const groups = useMemo(() => groupNodes(shown), [shown])
  const total = useMemo(() => aggregateNodes(nodes), [nodes])

  // Explicit open/closed choices; otherwise small clusters start open and large ones closed.
  const [choice, setChoice] = useState<Map<string, boolean>>(new Map())
  const [openNode, setOpenNode] = useState<string>(focus)
  const toggle = (key: string, now: boolean) => setChoice((m) => new Map(m).set(key, !now))
  const isOpen = (key: string, def: boolean) => (dq ? true : (choice.get(key) ?? def))

  // Open the pool and zone of a node linked to from elsewhere, and scroll to it.
  const scrolled = useRef('')
  useEffect(() => {
    if (!focus || !all || scrolled.current === focus) return
    const g = groups.find((p) => p.zones.some((z) => z.nodes.some((n) => n.name === focus)))
    if (!g) return
    const z = g.zones.find((zz) => zz.nodes.some((n) => n.name === focus))!
    setChoice((m) => new Map(m).set(g.key, true).set(z.key, true))
    setOpenNode(focus)
    scrolled.current = focus
    requestAnimationFrame(() => document.getElementById(`node-${focus}`)?.scrollIntoView({ block: 'start' }))
  }, [focus, all, groups])

  return (
    <Async state={state} what="nodes">
      {(d) =>
        d.items.length === 0 ? (
          <Empty title="No nodes found">The cluster reported no nodes, or kubesentry may not list them.</Empty>
        ) : (
          <>
            <div className="filters">
              <label>
                Search
                <input type="search" value={q} onChange={(e) => onQuery(e.target.value)} placeholder="Node, pool, zone or instance type" />
              </label>
            </div>
            <div className="pool-total">
              <GroupFacts agg={total} />
            </div>
            {groups.length === 0 ? (
              <Empty title="No nodes match">Clear the search.</Empty>
            ) : (
              groups.map((g) => (
                <PoolSection
                  key={g.key}
                  g={g}
                  open={isOpen(g.key, !large)}
                  onToggle={() => toggle(g.key, isOpen(g.key, !large))}
                  zoneOpen={(key) => isOpen(key, !large || g.zones.length === 1)}
                  onZoneToggle={(key) => toggle(key, isOpen(key, !large || g.zones.length === 1))}
                  cards={!large}
                  openNode={openNode}
                  setOpenNode={setOpenNode}
                />
              ))
            )}
          </>
        )
      }
    </Async>
  )
}

function GroupFacts({ agg }: { agg: NodeAggregate }) {
  const facts = [
    `${agg.pods.toLocaleString('en-US')} ${plural(agg.pods, 'pod', 'pods')}`,
    mixText(agg.capacityTypes),
    mixText(agg.arch),
    mixText(agg.instanceTypes, 2),
  ].filter(Boolean)
  return (
    <div className="pool-facts">
      <p className="pool-line">
        <StatusGlyph status={agg.status} label={false} />
        <strong>{nodeCountText(agg)}</strong>
        {facts.map((f) => (
          <span key={f} className="muted">{f}</span>
        ))}
      </p>
      <div className="pool-meters">
        <Meter label="CPU requested" value={agg.cpuRequestedMilli} max={agg.cpuAllocatableMilli} fmt={formatCPU} />
        <Meter label="Memory requested" value={agg.memoryRequestedBytes} max={agg.memoryAllocatableBytes} fmt={formatBytes} />
        <Meter label="Pods" value={agg.pods} max={agg.podsAllocatable} fmt={String} />
      </div>
    </div>
  )
}

function PoolSection({
  g,
  open,
  onToggle,
  zoneOpen,
  onZoneToggle,
  cards,
  openNode,
  setOpenNode,
}: {
  g: PoolGroup
  open: boolean
  onToggle: () => void
  zoneOpen: (key: string) => boolean
  onZoneToggle: (key: string) => void
  cards: boolean
  openNode: string
  setOpenNode: (n: string) => void
}) {
  const id = `pool-${g.key.replace(/[^a-zA-Z0-9-]/g, '_')}`
  return (
    <section className="pool" aria-labelledby={id}>
      <h2 className="pool-head" id={id}>
        <button type="button" className="disclose" aria-expanded={open} onClick={onToggle}>
          <span className="disclose-mark" aria-hidden="true">{open ? '▾' : '▸'}</span>
          <span className="id">{g.name}</span>
        </button>
        <span className="tag">{POOL_KIND_LABEL[g.kind]}</span>
      </h2>
      <GroupFacts agg={g.agg} />
      {open &&
        g.zones.map((z) => {
          const zo = zoneOpen(z.key)
          return (
            <div className="zone" key={z.key}>
              <h3 className="zone-head">
                <button type="button" className="disclose" aria-expanded={zo} onClick={() => onZoneToggle(z.key)}>
                  <span className="disclose-mark" aria-hidden="true">{zo ? '▾' : '▸'}</span>
                  {z.zone}
                </button>
                <StatusGlyph status={z.agg.status} label={false} />
                <span className="muted small">{nodeCountText(z.agg)}, {z.agg.pods.toLocaleString('en-US')} pods</span>
              </h3>
              {zo &&
                (cards ? (
                  <div className="node-grid">
                    {z.nodes.map((n) => <NodeCard key={n.name} n={n} focused={n.name === openNode} />)}
                  </div>
                ) : (
                  <NodeRows nodes={z.nodes} openNode={openNode} setOpenNode={setOpenNode} />
                ))}
            </div>
          )
        })}
    </section>
  )
}

/** Compact rows for big clusters; a row opens into the node's details and pods. */
function NodeRows({ nodes, openNode, setOpenNode }: { nodes: NodeSummary[]; openNode: string; setOpenNode: (n: string) => void }) {
  return (
    <div className="table-wrap" tabIndex={0}>
      <table className="node-rows">
        <thead>
          <tr>
            <th>Node</th>
            <th>Status</th>
            <th>Instance</th>
            <th>Capacity</th>
            <th className="num">CPU req.</th>
            <th className="num">Memory req.</th>
            <th className="num">Pods</th>
          </tr>
        </thead>
        <tbody>
          {nodes.map((n) => {
            const open = openNode === n.name
            const p = n.placement
            const cpu = percent(n.cpuRequestedMilli, n.cpuAllocatableMilli)
            const mem = percent(n.memoryRequestedBytes, n.memoryAllocatableBytes)
            return (
              <Fragment key={n.name}>
                <tr id={`node-${n.name}`} className={open ? 'open' : undefined}>
                  <td className="id">
                    <button type="button" className="disclose" aria-expanded={open} onClick={() => setOpenNode(open ? '' : n.name)}>
                      <span className="disclose-mark" aria-hidden="true">{open ? '▾' : '▸'}</span>
                      {n.name}
                    </button>
                  </td>
                  <td>
                    <StatusGlyph status={n.status} />
                    {n.unschedulable && <span className="tag tag-after">cordoned</span>}
                  </td>
                  <td className="id">{p?.instanceType || '-'}{p?.arch && <span className="muted"> {p.arch}</span>}</td>
                  <td>{p?.capacityType || (p?.poolKind === 'fargate' ? 'Fargate' : '-')}</td>
                  <td className={`num${cpu !== undefined && cpu >= 90 ? ' bad' : ''}`}>{cpu !== undefined ? `${cpu}%` : '-'}</td>
                  <td className={`num${mem !== undefined && mem >= 90 ? ' bad' : ''}`}>{mem !== undefined ? `${mem}%` : '-'}</td>
                  <td className="num">{podCountOf(n)}{n.podsAllocatable ? <span className="muted">/{n.podsAllocatable}</span> : null}</td>
                </tr>
                {open && (
                  <tr className="node-open">
                    <td colSpan={7}>
                      <NodeCard n={n} focused={false} fetchPods />
                    </td>
                  </tr>
                )}
              </Fragment>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

function placementFacts(n: NodeSummary): string {
  const p = n.placement
  return [
    p?.zone,
    p?.instanceType,
    p?.capacityType,
    p?.arch,
    n.kubeletVersion && `kubelet ${n.kubeletVersion}`,
    n.containerRuntime,
    n.osImage,
  ]
    .filter(Boolean)
    .join(' · ')
}

function NodeCard({ n, focused, fetchPods = false }: { n: NodeSummary; focused: boolean; fetchPods?: boolean }) {
  const roles = n.roles ?? []
  const pressure = n.pressure ?? []
  const taints = n.taints ?? []
  const facts = placementFacts(n)
  const count = podCountOf(n)
  return (
    <article className={`node-card${focused ? ' focus' : ''}`} id={fetchPods ? undefined : `node-${n.name}`} aria-labelledby={`node-h-${n.name}`}>
      <header className="node-head">
        <h3 className="id" id={`node-h-${n.name}`}>{n.name}</h3>
        {roles.length > 0 && <span className="muted">{roles.join(', ')}</span>}
      </header>
      <p className="node-status">
        <StatusGlyph status={n.status} />
        {n.detail && <span className="muted">{n.detail}</span>}
      </p>
      {facts && <p className="node-facts muted">{facts}</p>}
      <Meter label="CPU requested" value={n.cpuRequestedMilli} max={n.cpuAllocatableMilli} fmt={formatCPU} />
      <Meter label="Memory requested" value={n.memoryRequestedBytes} max={n.memoryAllocatableBytes} fmt={formatBytes} />
      <Meter label="Pods" value={count} max={n.podsAllocatable} fmt={String} />
      {(n.unschedulable || pressure.length > 0) && (
        <div className="node-tags">
          <span className="node-tags-label">Conditions</span>
          {n.unschedulable && <span className="tag">Cordoned</span>}
          {pressure.map((p) => (
            <span key={p} className="tag tag-glyph"><StatusGlyph status="warn" decorative />{p}</span>
          ))}
        </div>
      )}
      {taints.length > 0 && (
        <div className="node-tags">
          <span className="node-tags-label">Taints</span>
          {taints.map((t) => <span key={t} className="tag id">{t}</span>)}
        </div>
      )}
      {n.pods !== undefined ? (
        n.pods.length > 0 && (
          <details className="node-pods" open={n.pods.length <= 8 || fetchPods}>
            <summary>{n.pods.length} {plural(n.pods.length, 'pod', 'pods')}</summary>
            <PodList pods={n.pods} />
          </details>
        )
      ) : count > 0 && fetchPods ? (
        <FetchedPods name={n.name} count={count} />
      ) : null}
    </article>
  )
}

/** The pods on one node, from GET /api/v1/nodes/{name}. */
function FetchedPods({ name, count }: { name: string; count: number }) {
  const state = useApi<NodeSummary>(`/api/v1/nodes/${encodeURIComponent(name)}`)
  if (state.error instanceof ApiError && state.error.status === 404) {
    return <p className="muted small">{count} {plural(count, 'pod', 'pods')}; this server cannot list them per node.</p>
  }
  return (
    <div className="node-pods">
      <p className="muted small">{count} {plural(count, 'pod', 'pods')}</p>
      <Async state={state} what="pods on this node">{(d) => <PodList pods={d.pods ?? []} />}</Async>
    </div>
  )
}

function PodList({ pods }: { pods: NodePod[] }) {
  return (
    <ul className="plain">
      {pods.map((p) => {
        const wl = splitWorkload(p.workload)
        const rs = reasonStatus(p.reason)
        return (
          <li key={`${p.namespace}/${p.name}`}>
            <StatusGlyph status={p.status} label={false} />
            <span>
              <a className="id brk" href={podHref(p.namespace, p.name)}>{slashBreaks(`${p.namespace}/${p.name}`)}</a>
              {wl && (
                <>
                  {' '}
                  <a className="muted node-wl" href={workloadHref(p.namespace, wl.name)}>{p.workload}</a>
                </>
              )}
              {p.reason ? (
                <span className={`small ${rs === 'crit' ? 'bad-text' : 'muted'}`}> {p.reason}</span>
              ) : p.ready === false && p.phase === 'Running' && p.status !== 'ok' ? (
                // ready is sent even when unknown (false), so only believe it when the status agrees.
                <span className="muted small"> not ready</span>
              ) : (
                p.phase && p.phase !== 'Running' && <span className="muted small"> {p.phase}</span>
              )}
            </span>
          </li>
        )
      })}
    </ul>
  )
}

function Meter({ label, value, max, fmt }: { label: string; value: number; max: number; fmt: (n: number) => string }) {
  const pct = percent(value, max)
  const text = pct === undefined ? `${fmt(value)}, capacity unknown` : `${fmt(value)} of ${fmt(max)} (${pct}%)`
  return (
    <div className="meter-row">
      <div className="meter-label">
        <span>{label}</span>
        <span className="num">{text}</span>
      </div>
      {pct !== undefined && (
        <div
          className={`meter${pct >= 90 ? ' high' : ''}`}
          role="meter"
          aria-label={label}
          aria-valuemin={0}
          aria-valuemax={max}
          aria-valuenow={Math.min(value, max)}
          aria-valuetext={text}
        >
          <span style={{ width: `${pct}%` }} />
        </div>
      )}
    </div>
  )
}
