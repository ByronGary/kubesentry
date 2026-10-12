import { hiddenNote, seesNothing } from '../access'
import { NoNamespaces, useInfo } from '../components/Access'
import { Sparkline } from '../components/Sparkline'
import { Async, Empty, PageHead, StatusGlyph } from '../components/ui'
import {
  activityCounts,
  attentionRows,
  healthItems,
  isFiltered,
  latestRows,
  namespaceOptions,
  overviewPath,
  POOL_HIGH_PCT,
  poolRows,
  readFilter,
  scopeText,
  tiles,
  wasteLines,
  type AttentionRow,
  type OverviewFilter,
  type Tile,
} from '../overview'
import { setQuery, type Route } from '../router'
import type { MapResponse, OverviewResponse } from '../types'
import { useApi, usePolled, type ApiState } from '../useApi'

/** The overview, plus the visible namespaces a newer server may send for the scope picker (not in the contract yet). */
type OverviewData = OverviewResponse & { namespaces?: string[] }

export const OVERVIEW_POLL_MS = 30_000

/**
 * The landing page: is the cluster healthy, what needs attention now, and
 * whose is it. `shared` is the unfiltered /overview the sidebar badges come
 * from; a namespace or owner filter (kept in the address) asks for its own.
 */
export function Overview({ route, shared }: { route: Route; shared: ApiState<OverviewResponse> }) {
  const info = useInfo()
  const filter = readFilter(route.query)
  const filtered = isFiltered(filter)
  const own = usePolled<OverviewData>(filtered ? overviewPath(filter) : null, OVERVIEW_POLL_MS, { retryBusy: true })
  const state = (filtered ? own : shared) as ApiState<OverviewData>
  const data = state.data
  // Namespaces for the picker: the server's list when it sends one, else the Map's (asked once).
  const fromServer = data?.namespaces ?? (shared.data as OverviewData | undefined)?.namespaces
  const map = useApi<MapResponse>(info.inventory && !fromServer ? '/api/v1/map' : null)
  const namespaces = namespaceOptions([fromServer, map.data?.namespaces], data?.attention ?? [], filter.namespace)
  const owners = [...new Set([...(data?.owners ?? shared.data?.owners ?? []), ...(filter.owner ? [filter.owner] : [])])].sort()
  const set = (patch: Partial<OverviewFilter>) => setQuery('/', { ...filter, ...patch })

  return (
    <>
      <PageHead title="Overview" lede={data ? `${scopeText(data.scope)}.` : 'Is the cluster healthy, what needs attention now, and whose is it?'}>
        <div className="filters ov-filters">
          <label>
            Namespace
            <select value={filter.namespace} onChange={(e) => set({ namespace: e.target.value })}>
              <option value="">All namespaces</option>
              {namespaces.map((n) => (
                <option key={n}>{n}</option>
              ))}
            </select>
          </label>
          {owners.length > 0 && (
            <label>
              Owner
              <select value={filter.owner} onChange={(e) => set({ owner: e.target.value })}>
                <option value="">All teams</option>
                {owners.map((n) => (
                  <option key={n}>{n}</option>
                ))}
              </select>
            </label>
          )}
        </div>
      </PageHead>
      <Async state={state} what="the overview" busy="kubesentry is busy">
        {(o) => <Body o={o} filter={filter} />}
      </Async>
    </>
  )
}

function Body({ o, filter }: { o: OverviewResponse; filter: OverviewFilter }) {
  const info = useInfo()
  if (o.scope.namespaces === 0) {
    if (isFiltered(filter)) {
      return (
        <Empty title="Nothing here for this filter">
          No namespace you can see matches it. <a href="#/">Show everything you can see</a>.
        </Empty>
      )
    }
    if (seesNothing(info, 0, true)) return <NoNamespaces />
  }
  const now = Date.now()
  const health = healthItems(o)
  const rows = attentionRows(o.attention, now)
  return (
    <>
      <ul className="ov-health" aria-label="Data and sources">
        {health.map((h) => (
          <li key={h.key}>
            <StatusGlyph status={h.status} label={false} />
            {h.href ? <a href={h.href}>{h.text}</a> : <span>{h.text}</span>}
          </li>
        ))}
      </ul>

      <div className="ov-tiles">
        {tiles(o, filter).map((t) => (
          <TileCard key={t.key} t={t} />
        ))}
      </div>

      {/* Two columns as in the wireframe (attention and activity; capacity and cost), so a long list leaves no gap. */}
      <div className="ov-grid">
        <div className="ov-col">
          <Attention rows={rows} />
          {o.activity && <Activity a={o.activity} />}
        </div>
        <div className="ov-col">
          {o.nodes && <Capacity nodes={o.nodes} />}
          <section className="panel" aria-labelledby="h-waste">
            <div className="panel-head">
              <h2 id="h-waste">Cost and waste</h2>
            </div>
            <Waste w={o.waste} />
          </section>
        </div>
      </div>
    </>
  )
}

function Attention({ rows }: { rows: AttentionRow[] }) {
  return (
    <section className="panel ov-attention" aria-labelledby="h-attention">
      <div className="panel-head">
        <h2 id="h-attention">Needs attention</h2>
        <span className="muted small">worst first</span>
      </div>
      {rows.length === 0 ? (
        <p className="ov-calm">
          <StatusGlyph status="ok" decorative /> Nothing needs attention right now.
        </p>
      ) : (
        <ol className="ov-list">
          {rows.map((r) => {
            const body = (
              <>
                <span className="ov-row-head">
                  <StatusGlyph status={r.severity} />
                  <span className="tag">{r.kind}</span>
                  <span className="ov-subject">{r.subject}</span>
                </span>
                <span className="ov-title">{r.title}</span>
                {(r.owner || r.age) && (
                  <span className="ov-meta">
                    {r.owner && <>owner {r.owner}</>}
                    {r.owner && r.age && ' · '}
                    {r.age && <>started {r.age}</>}
                  </span>
                )}
              </>
            )
            return (
              <li key={r.key}>
                {r.href ? (
                  <a className="ov-row" href={r.href}>
                    {body}
                  </a>
                ) : (
                  <div className="ov-row">{body}</div>
                )}
              </li>
            )
          })}
        </ol>
      )}
      <p className="panel-more">
        <a href="#/findings">See everything in Findings</a>
      </p>
    </section>
  )
}

function TileCard({ t }: { t: Tile }) {
  const id = `tile-${t.key}`
  return (
    <section className="tile" aria-labelledby={id}>
      <h2 className="tile-title" id={id}>
        {t.title}
      </h2>
      {t.restricted ? (
        <>
          <p className="tile-restricted">
            <StatusGlyph status="unknown" decorative />
            Not visible to you
          </p>
          <p className="tile-foot">{hiddenNote('nodes')}</p>
        </>
      ) : (
        <>
          {t.total !== undefined && (
            <p className="tile-total">
              <a href={t.totalHref}>
                {t.total.toLocaleString('en-US')}
                <span className="sr-only"> {t.title.toLowerCase()} in total</span>
              </a>
            </p>
          )}
          <ul className="tile-lines">
            {t.lines.map((l) => (
              <li key={l.key} className={l.count === 0 ? 'zero' : undefined}>
                {l.status ? <StatusGlyph status={l.status} label={false} /> : <span className="tile-nomark" aria-hidden="true" />}
                {l.href ? (
                  <a href={l.href}>
                    <strong>{l.count.toLocaleString('en-US')}</strong> {l.text}
                  </a>
                ) : (
                  <span>
                    <strong>{l.count.toLocaleString('en-US')}</strong> {l.text}
                  </span>
                )}
              </li>
            ))}
          </ul>
          {t.extras.length > 0 && (
            <p className="tile-extras">
              {t.extras.map((e) => (
                <a key={e.key} className="tag" href={e.href} title={`${e.count} ${e.count === 1 ? 'pod' : 'pods'} in ${e.text}`}>
                  {e.text} {e.count}
                </a>
              ))}
            </p>
          )}
          {t.spark && <Sparkline values={t.spark.values} label={t.spark.label} span={t.spark.span} />}
          {t.foot && <p className="tile-foot">{t.foot}</p>}
        </>
      )}
    </section>
  )
}

function Capacity({ nodes }: { nodes: NonNullable<OverviewResponse['nodes']> }) {
  const pools = poolRows(nodes.pools)
  const zones = nodes.zones ?? []
  return (
    <section className="panel" aria-labelledby="h-capacity">
      <div className="panel-head">
        <h2 id="h-capacity">Capacity by pool</h2>
        <span className="muted small">requested of allocatable</span>
      </div>
      {pools.length === 0 ? (
        <p className="muted">No node pools reported.</p>
      ) : (
        <ul className="ov-pools">
          {pools.map((p) => (
            <li key={p.name}>
              <p className="ov-pool-head">
                <a className="id" href={p.href}>
                  {p.name}
                </a>
                <span className="muted small">
                  {p.kind} · {p.nodes.toLocaleString('en-US')} {p.nodes === 1 ? 'node' : 'nodes'}
                </span>
              </p>
              {p.metered ? (
                <>
                  <Bar label="CPU" pct={p.cpu} />
                  <Bar label="Memory" pct={p.mem} />
                </>
              ) : (
                <p className="muted small ov-unmetered">Not metered: Fargate sizes each pod on its own.</p>
              )}
            </li>
          ))}
        </ul>
      )}
      {zones.length > 0 && (
        <p className="ov-zones">
          <span className="muted">Nodes by zone</span>
          {zones.map((z) => (
            <span key={z.name}>
              <span className="id">{z.name}</span> {z.nodes.toLocaleString('en-US')}
            </span>
          ))}
        </p>
      )}
    </section>
  )
}

function Bar({ label, pct }: { label: string; pct: number | undefined }) {
  if (pct === undefined) {
    return (
      <div className="ov-bar">
        <span>{label}</span>
        <span />
        <span className="muted num">unknown</span>
      </div>
    )
  }
  const high = pct >= POOL_HIGH_PCT
  const width = Math.min(100, Math.max(0, pct))
  return (
    <div className="ov-bar">
      <span>{label}</span>
      <div
        className={`meter${high ? ' high' : ''}`}
        role="meter"
        aria-label={`${label} requested`}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={width}
        aria-valuetext={`${pct}%${high ? ', nearly full' : ''}`}
      >
        <span style={{ width: `${width}%` }} />
      </div>
      <span className="num ov-pct">
        {high && <StatusGlyph status="warn" label={false} />}
        {pct}%
      </span>
    </div>
  )
}

function Activity({ a }: { a: NonNullable<OverviewResponse['activity']> }) {
  const counts = activityCounts(a)
  const latest = latestRows(a.latest)
  return (
    <section className="panel" aria-labelledby="h-activity">
      <div className="panel-head">
        <h2 id="h-activity">Sensitive activity</h2>
        <span className="muted small">last {a.windowHours}h</span>
      </div>
      <ul className="ov-counts">
        {counts.map((c) => (
          <li key={c.key} className={c.highlight ? 'hot' : undefined}>
            <a href={c.href}>
              {c.highlight && <StatusGlyph status="warn" label={false} />}
              <strong>{c.count.toLocaleString('en-US')}</strong> {c.label}
            </a>
          </li>
        ))}
      </ul>
      {latest.length > 0 && (
        <>
          <h3 className="panel-sub">Latest</h3>
          <ul className="ov-events">
            {latest.map((e) => (
              <li key={e.key}>
                <a href={e.href}>
                  <span className="id">{e.who}</span> {e.what} <span className="id ov-target">{e.target}</span>
                </a>
                <span className="muted small"> {e.age}</span>
              </li>
            ))}
          </ul>
        </>
      )}
      <p className="panel-more">
        <a href="#/activity">All activity</a>
      </p>
    </section>
  )
}

function Waste({ w }: { w: OverviewResponse['waste'] }) {
  const lines = wasteLines(w)
  if (lines.length === 0) {
    return (
      <p className="ov-calm">
        <StatusGlyph status="ok" decorative /> Every volume claim is in use.
      </p>
    )
  }
  return (
    <ul className="ov-waste">
      {lines.map((l) => (
        <li key={l.key}>
          <a href={l.href}>{l.text}</a>
        </li>
      ))}
    </ul>
  )
}
