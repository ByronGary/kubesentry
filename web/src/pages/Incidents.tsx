import { useMemo } from 'react'
import { SignalMark } from '../components/SignalMark'
import { Async, Empty, ListStatus, PageHead, StatusGlyph, WindowSelect } from '../components/ui'
import { ago, formatDateTime } from '../format'
import {
  incidentDuration,
  incidentHref,
  incidentsPath,
  isNarrowed,
  maxRangeHours,
  patchFilter,
  readIncidentFilter,
  severityGlyph,
  signalMeta,
  SIGNAL_TYPES,
  subjectText,
  tagChips,
  toggleType,
  typeChips,
  windowChoicesFor,
  WINDOWS,
  type IncidentFilter,
} from '../incidents'
import { setQuery, type Route } from '../router'
import type { Incident, IncidentsResponse, Info } from '../types'
import { usePaged } from '../usePaged'

const items = (r: IncidentsResponse) => r.items
const merge = (r: IncidentsResponse, all: Incident[]): IncidentsResponse => ({ ...r, items: all })

/** Distinct non-empty values, sorted, keeping the current one even when no row has it. */
function options(values: (string | undefined)[], current: string): string[] {
  return [...new Set([...values.filter((v): v is string => !!v), ...(current ? [current] : [])])].sort()
}

/**
 * Incidents in a window of up to 24 hours: one per workload, opened by a
 * spike, a restart, an OOM kill or an alert, with what changed around it.
 * Every filter lives in the address.
 */
export function Incidents({ route, info }: { route: Route; info: Info }) {
  const max = maxRangeHours(info)
  const f = readIncidentFilter(route.query, max)
  const set = (patch: Partial<IncidentFilter>) => setQuery('/incidents', patchFilter(f, patch))
  const list = usePaged<IncidentsResponse, Incident>(incidentsPath(f), { items, merge, limit: 200, refreshMs: 30_000, retryBusy: true })
  const choices = useMemo(() => windowChoicesFor(max), [max])
  const rows = list.data?.items ?? []
  const counts = list.data?.counts
  const span = WINDOWS.find((w) => w.value === f.window)?.label.toLowerCase() ?? `last ${f.window}`

  const namespaces = options(rows.map((r) => r.subject.namespace), f.namespace)
  const owners = options(rows.map((r) => r.owner), f.owner)
  const apps = options(rows.flatMap((r) => tagChips(r.tags).filter((t) => t.name === 'app').map((t) => t.value)), f.app)
  const services = options(rows.flatMap((r) => tagChips(r.tags).filter((t) => t.name === 'service').map((t) => t.value)), f.service)
  const byType = counts?.byType ?? {}
  const types = SIGNAL_TYPES.filter((t) => (byType[t] ?? 0) > 0 || f.types.includes(t))
  const extraTypes = f.types.filter((t) => !SIGNAL_TYPES.includes(t as never))

  return (
    <>
      <PageHead
        title="Incidents"
        lede="Problems on each workload, with the metrics, events, changes and logs around them on one time axis. Critical and warning only; incidents never notify anyone."
      />
      <div className="filters">
        <WindowSelect label="Period" value={f.window} choices={choices} onChange={(v) => set({ window: v })} />
        <label>
          Severity
          <select value={f.severity} onChange={(e) => set({ severity: e.target.value as IncidentFilter['severity'] })}>
            <option value="">Any</option>
            <option value="critical">Reached critical</option>
            <option value="warning">Warning only</option>
          </select>
        </label>
        <label>
          State
          <select value={f.state} onChange={(e) => set({ state: e.target.value as IncidentFilter['state'] })}>
            <option value="">Open and resolved</option>
            <option value="open">Open</option>
            <option value="resolved">Resolved</option>
          </select>
        </label>
        <label>
          Namespace
          <select value={f.namespace} onChange={(e) => set({ namespace: e.target.value })}>
            <option value="">All namespaces</option>
            {namespaces.map((n) => (
              <option key={n}>{n}</option>
            ))}
          </select>
        </label>
        {(owners.length > 0 || f.owner) && (
          <label>
            Owner
            <select value={f.owner} onChange={(e) => set({ owner: e.target.value })}>
              <option value="">All teams</option>
              {owners.map((n) => (
                <option key={n}>{n}</option>
              ))}
            </select>
          </label>
        )}
        {(apps.length > 0 || f.app) && (
          <label>
            App
            <select value={f.app} onChange={(e) => set({ app: e.target.value })}>
              <option value="">All apps</option>
              {apps.map((n) => (
                <option key={n}>{n}</option>
              ))}
            </select>
          </label>
        )}
        {(services.length > 0 || f.service) && (
          <label>
            Service
            <select value={f.service} onChange={(e) => set({ service: e.target.value })}>
              <option value="">All services</option>
              {services.map((n) => (
                <option key={n}>{n}</option>
              ))}
            </select>
          </label>
        )}
      </div>
      {(types.length > 0 || extraTypes.length > 0) && (
        <div className="filter-group type-filter">
          <span className="filter-label" id="type-filter">
            Signal type <span className="muted">(incidents holding it, before filters)</span>
          </span>
          <div className="chips" role="group" aria-labelledby="type-filter">
            {[...types, ...extraTypes].map((t) => {
              const m = signalMeta(t)
              const on = f.types.includes(t)
              return (
                <button key={t} type="button" className="chip" aria-pressed={on} onClick={() => set({ types: toggleType(f.types, t) })}>
                  <SignalMark shape={m.shape} />
                  {m.label}
                  <span className="chip-count">{(byType[t as keyof typeof byType] ?? 0).toLocaleString('en-US')}</span>
                </button>
              )
            })}
          </div>
        </div>
      )}
      {counts && (
        <ul className="tally" aria-label={`Incidents in the ${span}, before filters`}>
          <li>
            <button type="button" className="linklike tally-btn" aria-pressed={f.severity === 'critical'} onClick={() => set({ severity: f.severity === 'critical' ? '' : 'critical' })}>
              <StatusGlyph status="crit" label={false} />
              <strong>{counts.critical.toLocaleString('en-US')}</strong> reached critical
            </button>
          </li>
          <li>
            <button type="button" className="linklike tally-btn" aria-pressed={f.severity === 'warning'} onClick={() => set({ severity: f.severity === 'warning' ? '' : 'warning' })}>
              <StatusGlyph status="warn" label={false} />
              <strong>{counts.warning.toLocaleString('en-US')}</strong> warning only
            </button>
          </li>
          <li>
            <button type="button" className="linklike tally-btn" aria-pressed={f.state === 'open'} onClick={() => set({ state: f.state === 'open' ? '' : 'open' })}>
              <strong>{counts.open.toLocaleString('en-US')}</strong> open
            </button>
          </li>
          <li>
            <button type="button" className="linklike tally-btn" aria-pressed={f.state === 'resolved'} onClick={() => set({ state: f.state === 'resolved' ? '' : 'resolved' })}>
              <strong>{counts.resolved.toLocaleString('en-US')}</strong> resolved
            </button>
          </li>
          <li className="tally-note muted small">{span}, before filters</li>
        </ul>
      )}
      {isNarrowed(f) && (
        <p className="small">
          <button type="button" className="linklike" onClick={() => setQuery('/incidents', { window: f.window })}>
            Clear filters
          </button>
        </p>
      )}
      <Async state={list} what="incidents" busy="kubesentry is busy">
        {() =>
          rows.length === 0 ? (
            isNarrowed(f) ? (
              <Empty title="No incidents match these filters">Widen the period or clear the filters.</Empty>
            ) : (
              <Empty title={`No incidents in the ${span}`}>
                kubesentry opens one when a workload's requests, errors or memory spike, when it restarts, crash-loops or is OOM killed, or when an alert fires.
              </Empty>
            )
          ) : (
            <>
              <ListStatus state={list} noun={['incident', 'incidents']} />
              <ol className="ledger inc-list">
                {rows.map((r) => (
                  <IncidentRow key={r.id} r={r} />
                ))}
              </ol>
            </>
          )
        }
      </Async>
    </>
  )
}

function IncidentRow({ r }: { r: Incident }) {
  const sev = severityGlyph(r.peakSeverity || r.severity)
  const tags = tagChips(r.tags).filter((t) => t.name === 'app' || t.name === 'service')
  const chips = typeChips(r)
  return (
    <li>
      <a className="ledger-row inc-row" href={incidentHref(r.id)}>
        <StatusGlyph status={sev} label={false} />
        <span className="ledger-main">
          <span className="ledger-subject">{r.title}</span>
          <span className="ledger-kind id">{subjectText(r.subject)}</span>
          {(tags.length > 0 || chips.length > 0) && (
            <span className="inc-chips">
              {tags.map((t) => (
                <span key={t.key} className="tag">
                  {t.name} {t.value}
                </span>
              ))}
              {chips.map((c) => (
                <span key={c.type} className={`tag tag-glyph${c.trigger ? ' tag-trigger' : ''}`}>
                  <SignalMark shape={c.shape} />
                  {c.label}
                  {c.count > 1 && <span className="muted"> ×{c.count}</span>}
                </span>
              ))}
            </span>
          )}
        </span>
        <span className="ledger-meta inc-meta">
          <span className={`inc-state inc-${r.state}`}>
            {r.state === 'open' ? 'Open' : 'Resolved'} · {incidentDuration(r)}
          </span>
          <span title={formatDateTime(r.start)}>started {ago(r.start)}</span>
          {r.owner && <span>owner {r.owner}</span>}
          {r.production && <span className="tag tag-crit">production</span>}
          {r.severity !== r.peakSeverity && r.state === 'open' && <span>now {r.severity}</span>}
        </span>
      </a>
    </li>
  )
}
