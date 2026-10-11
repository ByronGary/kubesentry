import { useMemo } from 'react'
import { seesNothing } from '../access'
import { NoNamespaces, useInfo } from '../components/Access'
import { Async, Empty, ListStatus, PageHead, StatusGlyph } from '../components/ui'
import { Lines, VirtualTable, type Column } from '../components/VirtualTable'
import { formatAge, formatDateTime, plural } from '../format'
import { filterWorkloads, imageSummary, readiness, shortImage, waitingReasons } from '../inventory'
import { setQuery, type Route } from '../router'
import type { WorkloadSummary, WorkloadsResponse } from '../types'
import { useDebounced } from '../useApi'
import { usePaged } from '../usePaged'
import { compareNumber, compareStatus, compareText } from '../virtual'

const KINDS: WorkloadSummary['kind'][] = ['Deployment', 'StatefulSet', 'DaemonSet', 'Job', 'CronJob']
const STATUSES = [
  ['crit', 'Critical'],
  ['warn', 'Warning'],
  ['ok', 'OK'],
  ['unknown', 'Unknown'],
] as const

const items = (r: WorkloadsResponse) => r.items
const merge = (r: WorkloadsResponse, all: WorkloadSummary[]): WorkloadsResponse => ({ ...r, items: all, count: all.length })

const columns: Column<WorkloadSummary>[] = [
  { key: 'status', header: 'Status', width: 112, sort: (a, b) => compareStatus(a.status, b.status), cell: (w) => <StatusGlyph status={w.status} /> },
  { key: 'kind', header: 'Kind', width: 116, sort: (a, b) => compareText(a.kind, b.kind), cell: (w) => w.kind },
  {
    key: 'name',
    header: 'Workload',
    width: '24%',
    sort: (a, b) => compareText(`${a.namespace}/${a.name}`, `${b.namespace}/${b.name}`),
    title: (w) => `${w.namespace}/${w.name}`,
    cell: (w) => (
      <Lines
        main={<a className="id" href={`#/map?namespace=${encodeURIComponent(w.namespace)}`} title="Show on the map">{w.name}</a>}
        sub={<span className="id">{w.namespace}</span>}
      />
    ),
  },
  {
    key: 'ready',
    header: 'Ready',
    width: 128,
    sort: (a, b) => compareNumber(a.desired ? a.ready / a.desired : 1, b.desired ? b.ready / b.desired : 1),
    title: (w) => (w.lastScheduleTime ? `Last scheduled ${formatDateTime(w.lastScheduleTime)}` : undefined),
    cell: (w) => {
      const r = readiness(w)
      const sub = r.sub ?? (w.notReady ? `${w.notReady} not ready` : undefined)
      return <Lines main={<span className={w.kind === 'CronJob' ? 'id' : 'num'}>{r.main}</span>} sub={sub} />
    },
  },
  { key: 'pods', header: 'Pods', width: 72, className: 'num', firstDir: 'desc', sort: (a, b) => compareNumber(a.pods, b.pods), cell: (w) => w.pods },
  {
    key: 'restarts',
    header: 'Restarts',
    width: 96,
    className: 'num',
    firstDir: 'desc',
    sort: (a, b) => compareNumber(a.restarts, b.restarts),
    cell: (w) => <Lines main={w.restarts} sub={w.oomKilled ? <span className="tag">OOMKilled</span> : undefined} />,
  },
  {
    key: 'detail',
    header: 'Detail',
    width: '26%',
    sort: (a, b) => compareNumber(Object.values(a.waiting ?? {}).reduce((s, n) => s + n, 0), Object.values(b.waiting ?? {}).reduce((s, n) => s + n, 0)),
    firstDir: 'desc',
    title: (w) => [...waitingReasons(w.waiting), w.detail].filter(Boolean).join('\n') || undefined,
    cell: (w) => {
      const waiting = waitingReasons(w.waiting)
      if (!waiting.length) return w.detail ? <Lines main={w.detail} /> : <span className="muted">-</span>
      return (
        <Lines
          main={waiting.map((r) => (
            <span key={r} className="tag tag-glyph tag-crit">
              <StatusGlyph status="crit" label={false} />
              {r}
            </span>
          ))}
          sub={w.detail || undefined}
        />
      )
    },
  },
  {
    key: 'images',
    header: 'Images',
    width: '18%',
    sort: (a, b) => compareText(a.images?.[0], b.images?.[0]),
    title: (w) => (w.images ?? []).join('\n') || undefined,
    cell: (w) => {
      const img = imageSummary(w.images)
      return (
        <span className="id">
          {shortImage(img.first)}
          {img.more > 0 && <span className="muted"> +{img.more}</span>}
        </span>
      )
    },
  },
  {
    key: 'age',
    header: 'Age',
    width: 64,
    className: 'num',
    sort: (a, b) => compareText(b.created, a.created),
    title: (w) => formatDateTime(w.created),
    cell: (w) => formatAge(w.created),
  },
]

export function Workloads({ route }: { route: Route }) {
  const info = useInfo()
  const p = route.query
  const filter = { q: p.get('q') ?? '', namespace: p.get('namespace') ?? '', kind: p.get('kind') ?? '', status: p.get('status') ?? '' }
  const set = (k: keyof typeof filter, v: string) => setQuery('/workloads', { ...filter, [k]: v })

  // All namespaces at once so the namespace picker always lists every one; pages follow in the background.
  const state = usePaged<WorkloadsResponse, WorkloadSummary>('/api/v1/workloads', { items, merge, refreshMs: 30_000 })
  const all = state.data?.items
  const dq = useDebounced(filter.q)
  const namespaces = useMemo(() => [...new Set([...(all ?? []).map((w) => w.namespace), ...(filter.namespace ? [filter.namespace] : [])])].sort(), [all, filter.namespace])
  const shown = useMemo(
    () => filterWorkloads(all ?? [], { ...filter, q: dq }),
    // The filter object is rebuilt every render; its fields are the dependencies.
    [all, dq, filter.namespace, filter.kind, filter.status],
  )
  const troubled = useMemo(() => shown.filter((w) => w.waiting && Object.keys(w.waiting).length > 0).length, [shown])

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
          seesNothing(info, d.items.length, state.complete) ? (
            <NoNamespaces />
          ) : (
            <>
              <ListStatus state={state} noun={['workload', 'workloads']} shown={shown.length} />
              {troubled > 0 && (
                <p className="muted small">
                  {troubled} {plural(troubled, 'workload has', 'workloads have')} pods stuck waiting.
                </p>
              )}
              {shown.length === 0 ? (
                state.following ? null : d.items.length === 0 ? (
                  <Empty title="No workloads found">Nothing in the cluster is managed by a Deployment, StatefulSet, DaemonSet, Job or CronJob.</Empty>
                ) : (
                  <Empty title="No workloads match">Clear the search or pick other filters.</Empty>
                )
              ) : (
                <VirtualTable
                  rows={shown}
                  columns={columns}
                  rowKey={(w) => `${w.kind}/${w.namespace}/${w.name}`}
                  caption="Workloads, the ones in trouble first"
                  rowHeight={52}
                  minWidth={1120}
                  resetKey={`${dq}|${filter.namespace}|${filter.kind}|${filter.status}`}
                />
              )}
            </>
          )
        }
      </Async>
    </>
  )
}
