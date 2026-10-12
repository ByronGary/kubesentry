import { useEffect, useMemo, useState } from 'react'
import { can, seesNothing } from '../access'
import { qs } from '../api'
import { NoNamespaces, useInfo } from '../components/Access'
import { Async, Empty, ListStatus, PageHead, StatusGlyph } from '../components/ui'
import { VirtualTable, type Column } from '../components/VirtualTable'
import { nodeHref, podHref, workloadHref } from '../findings'
import { filterPods, podStatusFilter, reasonStatus, splitWorkload } from '../inventory'
import { setQuery, type Route } from '../router'
import type { PodSummary, PodsResponse } from '../types'
import { useDebounced } from '../useApi'
import { usePaged } from '../usePaged'
import { compareNumber, compareText } from '../virtual'

const items = (r: PodsResponse) => r.items
const merge = (r: PodsResponse, all: PodSummary[]): PodsResponse => ({ ...r, items: all, count: all.length })

function readyRank(p: PodSummary): number {
  return p.ready === undefined ? 1 : p.ready ? 2 : 0
}

export function Pods({ route }: { route: Route }) {
  const info = useInfo()
  const q = route.query.get('q') ?? ''
  const ns = route.query.get('namespace') ?? ''
  const status = podStatusFilter(route.query.get('status'))
  const set = (k: 'q' | 'namespace' | 'status', v: string) => setQuery('/pods', { q, namespace: ns, status, [k]: v })
  // The namespace filter runs on the server, so one namespace loads fast even in a huge cluster.
  const state = usePaged<PodsResponse, PodSummary>(`/api/v1/pods${qs({ namespace: ns })}`, { items, merge, refreshMs: 30_000 })
  const all = state.data?.items
  const dq = useDebounced(q)
  const shown = useMemo(() => filterPods(all ?? [], dq, status), [all, dq, status])

  // Namespaces seen so far, so the picker keeps them while one namespace is shown.
  const [known, setKnown] = useState<string[]>([])
  useEffect(() => {
    if (!all?.length) return
    setKnown((k) => {
      const s = new Set(k)
      let grew = false
      for (const p of all) {
        if (s.has(p.namespace)) continue
        s.add(p.namespace)
        grew = true
      }
      return grew ? [...s].sort() : k
    })
  }, [all])
  const options = ns && !known.includes(ns) ? [...known, ns].sort() : known
  const nodesOK = can(info, 'nodes')
  const hasReady = useMemo(() => (all ?? []).some((p) => p.ready !== undefined || p.reason !== undefined), [all])
  const hasPlace = useMemo(() => (all ?? []).some((p) => p.node || p.workload), [all])

  const columns: Column<PodSummary>[] = [
    {
      key: 'pod',
      header: 'Pod',
      width: '30%',
      sort: (a, b) => compareText(`${a.namespace}/${a.name}`, `${b.namespace}/${b.name}`),
      title: (p) => `${p.namespace}/${p.name}`,
      cell: (p) => <a className="id" href={podHref(p.namespace, p.name)}>{p.namespace}/{p.name}</a>,
    },
    ...(hasReady
      ? [
          {
            key: 'ready',
            header: 'Ready',
            width: 96,
            sort: (a: PodSummary, b: PodSummary) => readyRank(a) - readyRank(b),
            cell: (p: PodSummary) =>
              p.ready === undefined ? (
                <span className="muted">-</span>
              ) : p.ready ? (
                <StatusGlyph status="ok" decorative />
              ) : p.phase === 'Succeeded' ? (
                <span className="muted">Done</span>
              ) : (
                <span className="tag-glyph"><StatusGlyph status="warn" decorative />No</span>
              ),
          } satisfies Column<PodSummary>,
        ]
      : []),
    {
      key: 'state',
      header: hasReady ? 'Phase and reason' : 'Phase',
      width: hasReady ? 190 : 120,
      sort: (a, b) => compareText(a.reason ?? a.phase, b.reason ?? b.phase),
      title: (p) => [p.phase, p.reason].filter(Boolean).join(': '),
      // The reason says more than the phase ("Running" hides a crash loop), so it takes the cell.
      cell: (p) => {
        const s = reasonStatus(p.reason)
        if (!p.reason) return p.phase
        return (
          <span className={`tag tag-glyph${s === 'crit' ? ' tag-crit' : ''}`}>
            <StatusGlyph status={s ?? 'warn'} label={false} />
            {p.reason}
          </span>
        )
      },
    },
    { key: 'restarts', header: 'Restarts', width: 92, className: 'num', firstDir: 'desc', sort: (a, b) => compareNumber(a.restarts, b.restarts), cell: (p) => p.restarts },
    {
      key: 'oom',
      header: 'OOMKilled',
      width: 100,
      firstDir: 'desc',
      sort: (a, b) => Number(a.oomKilled) - Number(b.oomKilled),
      cell: (p) => (p.oomKilled ? <StatusGlyph status="crit" label={false} /> : <span className="muted">No</span>),
    },
    ...(hasPlace
      ? [
          {
            key: 'workload',
            header: 'Owner',
            width: '20%',
            sort: (a: PodSummary, b: PodSummary) => compareText(a.workload, b.workload),
            title: (p: PodSummary) => p.workload,
            cell: (p: PodSummary) => {
              const w = splitWorkload(p.workload)
              if (!w) return <span className="muted">-</span>
              return (
                <a className="id" href={workloadHref(p.namespace, w.name)} title={`${p.workload} on the Workloads page`}>
                  <span className="muted">{w.kind}/</span>
                  {w.name}
                </a>
              )
            },
          } satisfies Column<PodSummary>,
          {
            key: 'node',
            header: 'Node',
            width: '16%',
            sort: (a: PodSummary, b: PodSummary) => compareText(a.node, b.node),
            title: (p: PodSummary) => p.node,
            cell: (p: PodSummary) =>
              !p.node ? (
                <span className="muted">-</span>
              ) : nodesOK && info.inventory ? (
                <a className="id" href={nodeHref(p.node)}>{p.node}</a>
              ) : (
                <span className="id">{p.node}</span>
              ),
          } satisfies Column<PodSummary>,
        ]
      : []),
    { key: 'containers', header: 'Containers', width: 106, className: 'num', firstDir: 'desc', sort: (a, b) => compareNumber(a.containers, b.containers), cell: (p) => p.containers },
  ]

  return (
    <>
      <PageHead title="Pods" lede="Pick a pod to see its memory, volumes and recent activity on one page." />
      <div className="filters">
        <label>
          Search
          <input type="search" value={q} onChange={(e) => set('q', e.target.value)} placeholder="Name, node, owner or reason" />
        </label>
        <label>
          Namespace
          <select value={ns} onChange={(e) => set('namespace', e.target.value)}>
            <option value="">All namespaces</option>
            {options.map((n) => <option key={n}>{n}</option>)}
          </select>
        </label>
        <label>
          Status
          <select value={status} onChange={(e) => set('status', e.target.value)}>
            <option value="">Any status</option>
            <option value="failing">Failing</option>
            <option value="pending">Pending</option>
          </select>
        </label>
      </div>
      <Async state={state} what="pods">
        {(d) =>
          seesNothing(info, d.items.length, state.complete) && !ns ? (
            <NoNamespaces />
          ) : (
            <>
              <ListStatus state={state} noun={['pod', 'pods']} shown={shown.length} />
              {shown.length === 0 ? (
                state.following ? null : d.items.length === 0 ? (
                  <Empty title={ns ? `No pods in ${ns}` : 'No pods found'}>{ns ? 'Choose another namespace.' : 'The cluster reported no pods.'}</Empty>
                ) : (
                  <Empty title="No pods match">{status ? 'Clear the search, pick any status or choose another namespace.' : 'Clear the search or choose another namespace.'}</Empty>
                )
              ) : (
                <VirtualTable
                  rows={shown}
                  columns={columns}
                  rowKey={(p) => `${p.namespace}/${p.name}`}
                  caption="Pods, most troubled first"
                  minWidth={hasPlace ? 1040 : 640}
                  resetKey={`${dq}|${ns}|${status}`}
                />
              )}
            </>
          )
        }
      </Async>
    </>
  )
}
