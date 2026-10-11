import { useEffect, useMemo, useRef, useState } from 'react'
import { qs } from '../api'
import { Async, Empty, GLYPH_LABEL, GlyphShape, PageHead, Segmented, slashBreaks, StatusGlyph } from '../components/ui'
import { podHref, workloadHref } from '../findings'
import { formatBytes, formatCPU, percent, plural, truncateMiddle } from '../format'
import { splitSubject } from '../inventory'
import { DEFAULT_LAYOUT, graphHref, layoutGraph, linksOf, type Box } from '../mapLayout'
import { setQuery, type Route } from '../router'
import type { GraphNode, MapResponse, NodeSummary, NodesResponse } from '../types'
import { useApi } from '../useApi'

type View = 'apps' | 'nodes'

const VIEWS: { value: View; label: string }[] = [
  { value: 'apps', label: 'Applications' },
  { value: 'nodes', label: 'Nodes' },
]

/** Named MapPage so it does not shadow the global Map. */
export function MapPage({ route }: { route: Route }) {
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
        lede={view === 'nodes' ? 'Every node, how much of it is requested, and the pods it runs.' : 'How traffic reaches the pods in one namespace, and what those pods run on and use.'}
      >
        <Segmented label="View" value={view} options={VIEWS} onChange={(v) => go({ view: v })} />
      </PageHead>
      {view === 'nodes' ? <NodesView focus={route.query.get('node') ?? ''} /> : <AppsView ns={ns} onNamespace={(n) => go({ namespace: n })} />}
    </>
  )
}

function AppsView({ ns, onNamespace }: { ns: string; onNamespace: (ns: string) => void }) {
  const state = useApi<MapResponse>(`/api/v1/map${qs({ namespace: ns })}`, 30_000)
  // Keep the picker filled while another namespace loads.
  const [known, setKnown] = useState<string[]>([])
  useEffect(() => {
    if (state.data) setKnown(state.data.namespaces ?? [])
  }, [state.data])
  const current = state.data?.namespace ?? ns
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
            <Empty title={d.namespace ? `Nothing to map in ${d.namespace}` : 'No namespace has pods yet'}>
              {d.namespace ? 'This namespace has no ingresses, services, workloads or pods.' : 'The map shows one namespace at a time once something runs in it.'}
            </Empty>
          ) : (
            <MapGraph resp={d} />
          )
        }
      </Async>
    </>
  )
}

const NAME_CHARS = 21

function MapGraph({ resp }: { resp: MapResponse }) {
  const layout = useMemo(() => layoutGraph(resp.graph.nodes ?? [], resp.graph.edges ?? []), [resp])
  const links = useMemo(() => linksOf(resp.graph.edges ?? []), [resp])
  const byId = useMemo(() => new Map((resp.graph.nodes ?? []).map((n) => [n.id, n])), [resp])
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
    return n ? `${n.kind} ${n.name}` : id
  }

  return (
    <div className="chart">
      <div className="chart-bar">
        <span className="chart-title">
          {layout.boxes.length} {plural(layout.boxes.length, 'object', 'objects')} in <span className="id">{resp.namespace}</span>
          {attention > 0 && `, ${attention} ${plural(attention, 'needs', 'need')} a look`}
        </span>
        <button type="button" className="linklike" onClick={() => setList((t) => !t)} aria-pressed={list}>
          {list ? 'Show map' : 'Show as list'}
        </button>
      </div>
      {list ? (
        <div className="table-wrap" tabIndex={0}>
          <table>
            <caption className="sr-only">Objects in namespace {resp.namespace} and how they connect</caption>
            <thead>
              <tr><th>Status</th><th>Kind</th><th>Name</th><th>Connects to</th><th>Connected from</th></tr>
            </thead>
            <tbody>
              {layout.boxes.map((b) => {
                const n = byId.get(b.id)!
                const href = graphHref(n, resp.namespace)
                return (
                  <tr key={b.id}>
                    <td><StatusGlyph status={n.status} /></td>
                    <td>{n.kind}</td>
                    <td className="id brk">
                      {href ? <a href={href}>{n.name}</a> : n.name}
                      {n.detail && <div className="muted map-detail">{n.detail}</div>}
                    </td>
                    <td><RefList ids={links.out.get(b.id) ?? []} label={label} /></td>
                    <td><RefList ids={links.in.get(b.id) ?? []} label={label} /></td>
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
                {edges.map((e) => (
                  <path key={`${e.from}>${e.to}`} className={touches(e) ? 'map-edge on' : 'map-edge'} d={e.d} />
                ))}
              </g>
              {layout.boxes.map((b) => {
                const n = byId.get(b.id)!
                return (
                  <MapBox
                    key={b.id}
                    b={b}
                    n={n}
                    href={graphHref(n, resp.namespace)}
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
            <li className="muted">Hover or focus an object to trace its connections.</li>
          </ul>
        </>
      )}
    </div>
  )
}

function RefList({ ids, label }: { ids: string[]; label: (id: string) => string }) {
  if (ids.length === 0) return <span className="muted">-</span>
  return (
    <ul className="plain">
      {ids.map((id) => <li key={id} className="id">{label(id)}</li>)}
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
  n: GraphNode
  href: string | undefined
  mode: 'on' | 'dim' | undefined
  onActive: (id: string | null) => void
}) {
  const status = GLYPH_LABEL[n.status] ?? n.status
  const full = `${n.kind} ${n.name}, ${status}${n.detail ? `: ${n.detail}` : ''}`
  const body = (
    <>
      <title>{full}</title>
      <rect className="map-box" x={b.x} y={b.y} width={b.w} height={b.h} rx="4" />
      <g className={`glyph-${n.status}`} transform={`translate(${b.x + 9} ${b.y + (b.h - 16) / 2})`}>
        <GlyphShape status={n.status} />
      </g>
      <text className="map-kind" x={b.x + 32} y={b.y + 19}>{n.kind}</text>
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

function NodesView({ focus }: { focus: string }) {
  const state = useApi<NodesResponse>('/api/v1/nodes', 30_000)
  const scrolled = useRef('')
  useEffect(() => {
    if (!focus || !state.data || scrolled.current === focus) return
    scrolled.current = focus
    document.getElementById(`node-${focus}`)?.scrollIntoView({ block: 'start' })
  }, [focus, state.data])

  return (
    <Async state={state} what="nodes">
      {(d) =>
        d.items.length === 0 ? (
          <Empty title="No nodes found">The cluster reported no nodes, or kubesentry may not list them.</Empty>
        ) : (
          <>
            <p className="count">{d.items.length} {plural(d.items.length, 'node', 'nodes')}</p>
            <div className="node-grid">
              {d.items.map((n) => <NodeCard key={n.name} n={n} focused={n.name === focus} />)}
            </div>
          </>
        )
      }
    </Async>
  )
}

function NodeCard({ n, focused }: { n: NodeSummary; focused: boolean }) {
  const pods = n.pods ?? []
  const roles = n.roles ?? []
  const pressure = n.pressure ?? []
  const taints = n.taints ?? []
  const facts = [n.kubeletVersion && `kubelet ${n.kubeletVersion}`, n.containerRuntime, n.osImage].filter(Boolean).join(' · ')
  return (
    <article className={`node-card${focused ? ' focus' : ''}`} id={`node-${n.name}`} aria-labelledby={`node-h-${n.name}`}>
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
      <Meter label="Pods" value={pods.length} max={n.podsAllocatable} fmt={String} />
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
      {pods.length > 0 && (
        <details className="node-pods" open={pods.length <= 8}>
          <summary>{pods.length} {plural(pods.length, 'pod', 'pods')}</summary>
          <ul className="plain">
            {pods.map((p) => {
              const wl = p.workload ? splitSubject(p.workload) : undefined
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
                    {p.phase && p.phase !== 'Running' && <span className="muted small"> {p.phase}</span>}
                  </span>
                </li>
              )
            })}
          </ul>
        </details>
      )}
    </article>
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
