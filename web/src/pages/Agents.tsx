import { useEffect, useMemo } from 'react'
import { can } from '../access'
import { ApiError } from '../api'
import { useInfo } from '../components/Access'
import { nodeHref } from '../findings'
import { Async, Empty, PageHead, StatusGlyph } from '../components/ui'
import { VirtualTable, type Column } from '../components/VirtualTable'
import { ago, formatBytes, formatDateTime, plural } from '../format'
import type { AgentStatus } from '../types'
import { useApi } from '../useApi'
import { compareNumber, compareText } from '../virtual'

const columns = (nodesOK: boolean): Column<AgentStatus>[] => [
  {
    key: 'state',
    header: 'State',
    width: 120,
    sort: (a, b) => Number(b.stale) - Number(a.stale),
    cell: (a) => (
      <span className="tag-glyph">
        <StatusGlyph status={a.stale ? 'warn' : 'ok'} decorative />
        {a.stale ? 'Stale' : 'Reporting'}
      </span>
    ),
  },
  {
    key: 'node',
    header: 'Node',
    width: '36%',
    sort: (a, b) => compareText(a.node, b.node),
    title: (a) => a.node,
    cell: (a) =>
      nodesOK ? <a className="id" href={nodeHref(a.node)}>{a.node}</a> : <span className="id">{a.node}</span>,
  },
  {
    key: 'last',
    header: 'Last report',
    width: '20%',
    sort: (a, b) => compareText(a.lastReport, b.lastReport),
    title: (a) => formatDateTime(a.lastReport),
    cell: (a) => <span className={a.stale ? 'bad-text' : undefined}>{ago(a.lastReport)}</span>,
  },
  { key: 'procs', header: 'Processes', width: 120, className: 'num', firstDir: 'desc', sort: (a, b) => compareNumber(a.processes, b.processes), cell: (a) => a.processes.toLocaleString('en-US') },
  { key: 'bytes', header: 'Report size', width: 130, className: 'num', firstDir: 'desc', sort: (a, b) => compareNumber(a.bytes, b.bytes), cell: (a) => formatBytes(a.bytes) },
]

/** Stale first, then by node name. */
function order(items: AgentStatus[]): AgentStatus[] {
  return [...items].sort((a, b) => Number(b.stale) - Number(a.stale) || compareText(a.node, b.node))
}

/** Node agents and when each last reported. Hides its nav tab when the server has no such route. */
export function Agents({ onMissing }: { onMissing: () => void }) {
  const info = useInfo()
  // The contract is a bare array; a wrapped {items} is accepted too.
  const state = useApi<AgentStatus[] | { items?: AgentStatus[] }>('/api/v1/agents', 30_000)
  const missing = state.error instanceof ApiError && state.error.status === 404
  useEffect(() => {
    if (missing) onMissing()
  }, [missing, onMissing])
  const items = useMemo(() => {
    const d = state.data
    return order(Array.isArray(d) ? d : (d?.items ?? []))
  }, [state.data])
  const stale = items.filter((a) => a.stale).length

  if (missing) {
    return (
      <>
        <PageHead title="Agents" />
        <Empty title="This server does not report agents">Agent status needs a newer kubesentry server with process monitoring turned on.</Empty>
      </>
    )
  }
  return (
    <>
      <PageHead title="Agents" lede="The process agent on each node, and when it last reported. A stale agent means process data for that node is out of date." />
      <Async state={state} what="agents">
        {() =>
          items.length === 0 ? (
            <Empty title="No agent has reported yet">Check that the agent DaemonSet runs and can reach the server's ingest address.</Empty>
          ) : (
            <>
              <p className="count">
                {items.length - stale} of {items.length} {plural(items.length, 'agent', 'agents')} reporting
                {stale > 0 && (
                  <>
                    , <span className="bad-text">{stale} stale</span>
                  </>
                )}
              </p>
              <VirtualTable
                rows={items}
                columns={columns(can(info, 'nodes') && info.inventory)}
                rowKey={(a) => a.node}
                caption="Node agents, stale first"
                rowClass={(a) => (a.stale ? 'row-warn' : undefined)}
                minWidth={640}
              />
            </>
          )
        }
      </Async>
    </>
  )
}
