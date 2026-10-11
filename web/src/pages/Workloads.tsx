import { useMemo } from 'react'
import { Async, Empty, PageHead, slashBreaks, StatusGlyph } from '../components/ui'
import { formatAge, formatDateTime, plural } from '../format'
import { filterWorkloads, imageSummary, readiness, shortImage } from '../inventory'
import { setQuery, type Route } from '../router'
import type { WorkloadSummary, WorkloadsResponse } from '../types'
import { useApi } from '../useApi'

const KINDS: WorkloadSummary['kind'][] = ['Deployment', 'StatefulSet', 'DaemonSet', 'Job', 'CronJob']
const STATUSES = [
  ['crit', 'Critical'],
  ['warn', 'Warning'],
  ['ok', 'OK'],
  ['unknown', 'Unknown'],
] as const

export function Workloads({ route }: { route: Route }) {
  const p = route.query
  const filter = { q: p.get('q') ?? '', namespace: p.get('namespace') ?? '', kind: p.get('kind') ?? '', status: p.get('status') ?? '' }
  const set = (k: keyof typeof filter, v: string) => setQuery('/workloads', { ...filter, [k]: v })

  // All namespaces at once so the namespace picker always lists every one.
  const state = useApi<WorkloadsResponse>('/api/v1/workloads', 30_000)
  const items = state.data?.items
  const namespaces = useMemo(() => [...new Set([...(items ?? []).map((w) => w.namespace), ...(filter.namespace ? [filter.namespace] : [])])].sort(), [items, filter.namespace])
  const shown = useMemo(() => filterWorkloads(items ?? [], filter), [items, filter.q, filter.namespace, filter.kind, filter.status])
  const filtered = !!(filter.q || filter.namespace || filter.kind || filter.status)

  return (
    <>
      <PageHead title="Workloads" lede="Deployments, StatefulSets, DaemonSets, Jobs and CronJobs, with the ones in trouble first." />
      <div className="filters">
        <label>
          Search
          <input type="search" value={filter.q} onChange={(e) => set('q', e.target.value)} placeholder="Name or image" />
        </label>
        <label>
          Namespace
          <select value={filter.namespace} onChange={(e) => set('namespace', e.target.value)}>
            <option value="">All namespaces</option>
            {namespaces.map((n) => <option key={n}>{n}</option>)}
          </select>
        </label>
        <label>
          Kind
          <select value={filter.kind} onChange={(e) => set('kind', e.target.value)}>
            <option value="">All kinds</option>
            {KINDS.map((k) => <option key={k}>{k}</option>)}
          </select>
        </label>
        <label>
          Status
          <select value={filter.status} onChange={(e) => set('status', e.target.value)}>
            <option value="">Any status</option>
            {STATUSES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </select>
        </label>
      </div>
      <Async state={state} what="workloads">
        {(d) =>
          shown.length === 0 ? (
            d.items.length === 0 ? (
              <Empty title="No workloads found">Nothing in the cluster is managed by a Deployment, StatefulSet, DaemonSet, Job or CronJob.</Empty>
            ) : (
              <Empty title="No workloads match">Clear the search or pick other filters.</Empty>
            )
          ) : (
            <>
              <p className="count">
                {shown.length} {plural(shown.length, 'workload', 'workloads')}
                {filtered && shown.length !== d.items.length && ` of ${d.items.length}`}
              </p>
              <div className="table-wrap" tabIndex={0}>
                <table>
                  <thead>
                    <tr>
                      <th>Status</th>
                      <th>Kind</th>
                      <th>Workload</th>
                      <th>Ready</th>
                      <th className="num">Pods</th>
                      <th className="num">Restarts</th>
                      <th>Images</th>
                      <th className="num">Age</th>
                      <th>Detail</th>
                    </tr>
                  </thead>
                  <tbody>
                    {shown.map((w) => {
                      const r = readiness(w)
                      const img = imageSummary(w.images)
                      return (
                        <tr key={`${w.kind}/${w.namespace}/${w.name}`}>
                          <td><StatusGlyph status={w.status} /></td>
                          <td>{w.kind}</td>
                          <td className="id brk name">
                            <a href={`#/map?namespace=${encodeURIComponent(w.namespace)}`} title="Show on the map">{slashBreaks(`${w.namespace}/${w.name}`)}</a>
                          </td>
                          <td>
                            <span className={w.kind === 'CronJob' ? 'id nowrap' : 'num'}>{r.main}</span>
                            {r.sub && <div className="muted small" title={w.lastScheduleTime ? formatDateTime(w.lastScheduleTime) : undefined}>{r.sub}</div>}
                          </td>
                          <td className="num">{w.pods}</td>
                          <td className="num">
                            {w.restarts}
                            {w.oomKilled && <div><span className="tag">OOMKilled</span></div>}
                          </td>
                          <td className="id brk" title={(w.images ?? []).join('\n') || undefined}>
                            <span aria-hidden="true">{slashBreaks(shortImage(img.first), '/:')}</span>
                            <span className="sr-only">{img.first}</span>
                            {img.more > 0 && <span className="muted"> +{img.more}</span>}
                          </td>
                          <td className="num" title={formatDateTime(w.created)}>{formatAge(w.created)}</td>
                          <td className="msg">{w.detail || <span className="muted">-</span>}</td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            </>
          )
        }
      </Async>
    </>
  )
}
