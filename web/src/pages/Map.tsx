import { Fragment, useEffect, useMemo, useRef, useState } from 'react'
import { can, chooseMapNamespace, busiestNamespace, hiddenNote, MAP_NS_KEY, namesOnlyNote, seesNothing, type NamespaceStat } from '../access'
import { ApiError, qs } from '../api'
import { localStore, readString, writeString } from '../auth'
import { NoNamespaces, useInfo } from '../components/Access'
import { Async, Empty, GLYPH_LABEL, GlyphShape, PageHead, Segmented, slashBreaks, StatusGlyph } from '../components/ui'
import { podHref, workloadHref } from '../findings'
import { formatBytes, formatCPU, percent, plural, truncateMiddle } from '../format'
import { reasonStatus, splitWorkload } from '../inventory'
import {
  collapseGraph,
  DEFAULT_LAYOUT,
  endpointText,
  graphHref,
  groupedText,
  howText,
  kindLabel,
  layoutGraph,
  linksOf,
  type Box,
  type CollapsedGraph,
  type EdgePath,
  type MapEdge,
  type MapNode,
} from '../mapLayout'
import { aggregateNodes, COLLAPSE_NODES_ABOVE, filterNodes, groupNodes, mixText, nodeCountText, podCountOf, POOL_KIND_LABEL, type NodeAggregate, type PoolGroup } from '../nodes'
import { setQuery, type Route } from '../router'
import type { MapResponse, NodePod, NodeSummary, NodesResponse } from '../types'
import { useApi, useDebounced } from '../useApi'

type View = 'apps' | 'nodes'

const VIEWS: { value: View; label: string }[] = [
  { value: 'apps', label: 'Applications' },
  { value: 'nodes', label: 'Nodes' },
]

/** The map response, plus per-namespace pod counts a newer server may add (proposed contract). */
type MapData = MapResponse & { namespaceStats?: NamespaceStat[] }

/** Named MapPage so it does not shadow the global Map. */
export function MapPage({ route }: { route: Route }) {
  const info = useInfo()
  const nodesOK = can(info, 'nodes')
  const view: View = route.query.get('view') === 'nodes' ? 'nodes' : 'apps'
  const ns = route.query.get('namespace') ?? ''
  const go = (next: { view?: View; namespace?: string }) =>
    setQuery('/map', {
      view: (next.view ?? view) === 'nodes' ? 'nodes' : undefined,
      namespace: next.namespace ?? ns,
    })

  return (
    <>
      <PageHead
        title="Map"
        lede={view === 'nodes' ? 'Nodes by pool and zone, how much of them is requested, and the pods they run.' : 'How traffic reaches the pods in one namespace, and what those pods run on and use.'}
      >
        {/* The node view needs cluster-wide access to nodes. */}
        {nodesOK && <Segmented label="View" value={view} options={VIEWS} onChange={(v) => go({ view: v })} />}
      </PageHead>
      {view === 'nodes' ? (
        nodesOK ? (
          <NodesView focus={route.query.get('node') ?? ''} />
        ) : (
          <Empty title="Node details are not available to you">{hiddenNote('nodes')}</Empty>
        )
      ) : (
        <AppsView ns={ns} onNamespace={(n) => go({ namespace: n })} />
      )}
    </>
  )
}

function AppsView({ ns, onNamespace }: { ns: string; onNamespace: (ns: string) => void }) {
  const info = useInfo()
  const store = localStore()
  // Without a namespace in the address: the one last looked at, else the busiest, else the server's pick.
  const [remembered, setRemembered] = useState(() => readString(store, MAP_NS_KEY))
  const [busiest, setBusiest] = useState<string>()
  const want = chooseMapNamespace({ fromURL: ns, remembered }) || busiest || ''
  const state = useApi<MapData>(`/api/v1/map${qs({ namespace: want })}`, 30_000)

  // A remembered namespace that is gone or no longer visible: forget it and let the server choose.
  const err = state.error
  useEffect(() => {
    if (ns || !remembered || want !== remembered) return
    if (err instanceof ApiError && (err.status === 404 || err.status === 403)) {
      writeString(store, MAP_NS_KEY, undefined)
      setRemembered(undefined)
    }
  }, [err, ns, remembered, want, store])

  const current = state.data?.namespace ?? want
  // Remember a namespace the user picked.
  useEffect(() => {
    if (ns && state.data?.namespace === ns) writeString(store, MAP_NS_KEY, ns)
  }, [ns, state.data?.namespace, store])
  // First visit: switch to the busiest namespace when the server says which it is.
  useEffect(() => {
    if (ns || remembered || busiest || !state.data) return
    const b = busiestNamespace(state.data.namespaceStats)
    if (b && b !== state.data.namespace) setBusiest(b)
  }, [ns, remembered, busiest, state.data])

  // Keep the picker filled while another namespace loads.
  const [known, setKnown] = useState<string[]>([])
  useEffect(() => {
    if (state.data) setKnown(state.data.namespaces ?? [])
  }, [state.data])
  const options = known.includes(current) || !current ? known : [...known, current].sort()

  return (
    <>
      <div className="filters">
        <label>
          Namespace
          <select value={current} onChange={(e) => onNamespace(e.target.value)} disabled={options.length === 0}>
            {options.map((n) => <option key={n}>{n}</option>)}
          </select>
        </label>
      </div>
      <Async state={state} what="map">
        {(d) =>
          (d.graph?.nodes ?? []).length === 0 ? (
            seesNothing(info, (d.namespaces ?? []).length, true) ? (
              <NoNamespaces />
            ) : (
              <Empty title={d.namespace ? `Nothing to map in ${d.namespace}` : 'No namespace has pods yet'}>
                {d.namespace ? 'This namespace has no ingresses, services, workloads or pods.' : 'The map shows one namespace at a time once something runs in it.'}
              </Empty>
            )
          ) : (
            <MapGraph resp={d} />
          )
        }
      </Async>
    </>
  )
}

const NAME_CHARS = 21
/** Past this many objects, "show every object" warns that the map may be slow. */
const MANY_OBJECTS = 400

function MapGraph({ resp }: { resp: MapResponse }) {
  const info = useInfo()
  const nodesOK = can(info, 'nodes')
  const [expand, setExpand] = useState(false)
  const rawNodes = resp.graph.nodes ?? []
  const rawEdges = resp.graph.edges ?? []
  const graph: CollapsedGraph = useMemo(
    () => (expand ? { nodes: rawNodes, edges: rawEdges, members: new Map(), hidden: 0 } : collapseGraph(rawNodes, rawEdges)),
    // rawNodes and rawEdges come from resp.
    [resp, expand],
  )
  const layout = useMemo(() => layoutGraph(graph.nodes, graph.edges), [graph])
  const links = useMemo(() => linksOf(graph.edges), [graph])
  const byId = useMemo(() => new Map<string, MapNode>(graph.nodes.map((n) => [n.id, n])), [graph])
  const edgeOf = useMemo(() => new Map<string, MapEdge>(graph.edges.map((e) => [`${e.from}\u0000${e.to}`, e])), [graph])
  const [active, setActive] = useState<string | null>(null)
  const [list, setList] = useState(false)

  const near = useMemo(
    () => (active ? new Set([active, ...(links.out.get(active) ?? []), ...(links.in.get(active) ?? [])]) : null),
    [active, links],
  )
  const touches = (e: { from: string; to: string }) => active !== null && (e.from === active || e.to === active)
  // Highlighted edges last so they draw on top.
  const edges = active ? [...layout.edges.filter((e) => !touches(e)), ...layout.edges.filter(touches)] : layout.edges
  const attention = layout.boxes.filter((b) => {
    const s = byId.get(b.id)?.status
    return s === 'crit' || s === 'warn'
  }).length
  const label = (id: string) => {
    const n = byId.get(id)
    return n ? `${kindLabel(n)} ${n.name}` : id
  }
  const hasNodes = rawNodes.some((n) => n.kind === 'Node')
  const hasSelector = graph.edges.some((e) => e.how === 'selector')
  const total = rawNodes.length
  const groupedKinds = [...graph.members.keys()].map((id) => byId.get(id)).filter((n): n is MapNode => !!n)

  return (
    <div className="chart">
      {!nodesOK && hasNodes && <p className="notice small-notice">{namesOnlyNote('nodes')}</p>}
      {graph.hidden > 0 && (
        <p className="notice small-notice">
          To keep the map readable, {groupedText(groupedKinds)} are shown as groups.{' '}
          <button type="button" className="linklike" onClick={() => setExpand(true)}>
            Show every object{total > MANY_OBJECTS ? ` (${total}, may be slow)` : ''}
          </button>
        </p>
      )}
      {expand && (
        <p className="notice small-notice">
          Showing all {total} objects.{' '}
          <button type="button" className="linklike" onClick={() => setExpand(false)}>Group them again</button>
        </p>
      )}
      <div className="chart-bar">
        <span className="chart-title">
          {total} {plural(total, 'object', 'objects')} in <span className="id">{resp.namespace}</span>
          {attention > 0 && `, ${attention} ${plural(attention, 'needs', 'need')} a look`}
        </span>
        <button type="button" className="linklike" onClick={() => setList((t) => !t)} aria-pressed={list}>
          {list ? 'Show map' : 'Show as list'}
        </button>
      </div>
      {list ? (
        <div className="table-wrap scroll-y" tabIndex={0}>
          <table>
            <caption className="sr-only">Objects in namespace {resp.namespace} and how they connect</caption>
            <thead>
              <tr><th>Status</th><th>Kind</th><th>Name</th><th>Connects to</th><th>Connected from</th></tr>
            </thead>
            <tbody>
              {layout.boxes.map((b) => {
                const n = byId.get(b.id)!
                const href = graphHref(n, resp.namespace, { nodes: nodesOK })
                return (
                  <tr key={b.id}>
                    <td><StatusGlyph status={n.status} /></td>
                    <td>{kindLabel(n)}</td>
                    <td className="id brk">
                      {href ? <a href={href}>{n.name}</a> : n.name}
                      {n.detail && <div className="muted map-detail">{n.detail}</div>}
                    </td>
                    <td><RefList ids={links.out.get(b.id) ?? []} label={label} edge={(to) => edgeOf.get(`${b.id}\u0000${to}`)} /></td>
                    <td><RefList ids={links.in.get(b.id) ?? []} label={label} edge={(from) => edgeOf.get(`${from}\u0000${b.id}`)} /></td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      ) : (
        <>
          <div className="map-canvas">
            <svg
              className="map"
              width={layout.width}
              height={layout.height}
              viewBox={`0 0 ${layout.width} ${layout.height}`}
              role="group"
              aria-label={`Map of namespace ${resp.namespace}. Lines run from what routes or owns to what it runs or uses; "Show as list" gives the same as a table.`}
            >
              {layout.columns.map((c) => (
                <text key={c.x} className="map-col" x={c.x} y={DEFAULT_LAYOUT.pad + 12}>{c.label}</text>
              ))}
              <g aria-hidden="true">
                {edges.map((e) => {
                  const how = edgeOf.get(`${e.from}\u0000${e.to}`)?.how
                  return <path key={`${e.from}>${e.to}`} className={`map-edge${how === 'selector' ? ' by-labels' : ''}${touches(e) ? ' on' : ''}`} d={e.d} />
                })}
                {active && edges.filter(touches).map((e) => <EdgeLabel key={`l:${e.from}>${e.to}`} e={e} edge={edgeOf.get(`${e.from}\u0000${e.to}`)} />)}
              </g>
              {layout.boxes.map((b) => {
                const n = byId.get(b.id)!
                return (
                  <MapBox
                    key={b.id}
                    b={b}
                    n={n}
                    href={graphHref(n, resp.namespace, { nodes: nodesOK })}
                    mode={near ? (near.has(b.id) ? 'on' : 'dim') : undefined}
                    onActive={setActive}
                  />
                )
              })}
            </svg>
          </div>
          <ul className="map-legend" aria-label="Legend">
            {(['ok', 'warn', 'crit', 'unknown'] as const).map((s) => (
              <li key={s}><StatusGlyph status={s} /></li>
            ))}
            <li className="legend-line">
              <svg width="28" height="8" aria-hidden="true"><path d="M1 4H27" className="map-edge on" /></svg>
              owns or routes to
            </li>
            {hasSelector && (
              <li className="legend-line">
                <svg width="28" height="8" aria-hidden="true"><path d="M1 4H27" className="map-edge by-labels on" /></svg>
                matched by labels
              </li>
            )}
            <li className="muted">Hover or focus an object to trace its connections and endpoint states.</li>
          </ul>
        </>
      )}
    </div>
  )
}

/** Endpoint states or "matched by labels" beside a highlighted link, near its target. */
function EdgeLabel({ e, edge }: { e: EdgePath; edge: MapEdge | undefined }) {
  if (!edge) return null
  const text = endpointText(edge) ?? (edge.how === 'selector' ? 'matched by labels' : undefined)
  if (!text) return null
  return (
    <text className="map-edge-label" x={e.x2 - 6} y={e.y2 - 6} textAnchor="end">
      {text}
    </text>
  )
}

function RefList({ ids, label, edge }: { ids: string[]; label: (id: string) => string; edge: (id: string) => MapEdge | undefined }) {
  if (ids.length === 0) return <span className="muted">-</span>
  return (
    <ul className="plain">
      {ids.map((id) => {
        const e = edge(id)
        const extra = [e && endpointText(e), e?.how === 'selector' ? howText(e.how) : undefined].filter(Boolean).join(', ')
        return (
          <li key={id}>
            <span className="id">{label(id)}</span>
            {extra && <span className="muted small"> ({extra})</span>}
          </li>
        )
      })}
    </ul>
  )
}

function MapBox({
  b,
  n,
  href,
  mode,
  onActive,
}: {
  b: Box
  n: MapNode
  href: string | undefined
  mode: 'on' | 'dim' | undefined
  onActive: (id: string | null) => void
}) {
  const status = GLYPH_LABEL[n.status] ?? n.status
  const kind = kindLabel(n)
  const full = `${kind} ${n.name}, ${status}${n.detail ? `: ${n.detail}` : ''}`
  const body = (
    <>
      <title>{full}</title>
      <rect className={`map-box${n.group ? ' group' : ''}`} x={b.x} y={b.y} width={b.w} height={b.h} rx="4" />
      {n.group && <rect className="map-box-stack" x={b.x + 3} y={b.y + b.h} width={b.w - 6} height={3} rx="1" />}
      <g className={`glyph-${n.status}`} transform={`translate(${b.x + 9} ${b.y + (b.h - 16) / 2})`}>
        <GlyphShape status={n.status} />
      </g>
      <text className="map-kind" x={b.x + 32} y={b.y + 19}>{truncateMiddle(kind, 26)}</text>
      <text className="map-name" x={b.x + 32} y={b.y + 35}>{truncateMiddle(n.name, NAME_CHARS)}</text>
    </>
  )
  const props = {
    className: `map-node${mode ? ` ${mode}` : ''}`,
    'aria-label': full,
    onMouseEnter: () => onActive(n.id),
    onMouseLeave: () => onActive(null),
    onFocus: () => onActive(n.id),
    onBlur: () => onActive(null),
  }
  return href ? (
    <a href={href} {...props}>{body}</a>
  ) : (
    <g tabIndex={0} role="img" {...props}>{body}</g>
  )
}

// Node view.

function NodesView({ focus }: { focus: string }) {
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

  const [q, setQ] = useState('')
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
                <input type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Node, pool, zone or instance type" />
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
