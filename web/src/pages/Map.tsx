import { useEffect, useMemo, useState } from 'react'
import { can, chooseMapNamespace, busiestNamespace, MAP_NS_KEY, namesOnlyNote, seesNothing, type NamespaceStat } from '../access'
import { ApiError, qs } from '../api'
import { localStore, readString, writeString } from '../auth'
import { NoNamespaces, useInfo } from '../components/Access'
import { Async, Empty, GLYPH_LABEL, GlyphShape, PageHead, StatusGlyph } from '../components/ui'
import { plural, truncateMiddle } from '../format'
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
import { setQuery, type Route } from '../router'
import type { MapResponse } from '../types'
import { useApi } from '../useApi'

/** The map response, plus per-namespace pod counts a newer server may add (proposed contract). */
type MapData = MapResponse & { namespaceStats?: NamespaceStat[] }

/**
 * Named MapPage so it does not shadow the global Map. The node view that used
 * to be a toggle here is the Nodes page now (`#/map?view=nodes` redirects).
 */
export function MapPage({ route }: { route: Route }) {
  const ns = route.query.get('namespace') ?? ''
  return (
    <>
      <PageHead title="Map" lede="How traffic reaches the pods in one namespace, and what those pods run on and use." />
      <AppsView ns={ns} onNamespace={(n) => setQuery('/map', { namespace: n })} />
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
