import { useMemo, useState } from 'react'
import { podHref } from '../findings'
import { Async, Empty, PageHead, StatusGlyph } from '../components/ui'
import type { PodsResponse } from '../types'
import { useApi } from '../useApi'

export function Pods() {
  const state = useApi<PodsResponse>('/api/v1/pods', 30_000)
  const [q, setQ] = useState('')
  const [ns, setNs] = useState('')
  const items = state.data?.items
  const namespaces = useMemo(() => [...new Set((items ?? []).map((p) => p.namespace))].sort(), [items])
  const shown = useMemo(() => {
    const needle = q.trim().toLowerCase()
    return (items ?? []).filter((p) => (!ns || p.namespace === ns) && (!needle || `${p.namespace}/${p.name}`.toLowerCase().includes(needle)))
  }, [items, q, ns])

  return (
    <>
      <PageHead title="Pods" lede="Pick a pod to see its memory, volumes and recent activity on one page." />
      <div className="filters">
        <label>
          Search
          <input type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Name or namespace" />
        </label>
        <label>
          Namespace
          <select value={ns} onChange={(e) => setNs(e.target.value)}>
            <option value="">All namespaces</option>
            {namespaces.map((n) => <option key={n}>{n}</option>)}
          </select>
        </label>
      </div>
      <Async state={state} what="pods">
        {() =>
          shown.length === 0 ? (
            <Empty title="No pods match">Clear the search or choose another namespace.</Empty>
          ) : (
            <div className="table-wrap" tabIndex={0}>
              <table>
                <thead>
                  <tr><th>Pod</th><th>Phase</th><th className="num">Containers</th><th className="num">Restarts</th><th>OOMKilled</th></tr>
                </thead>
                <tbody>
                  {shown.map((p) => (
                    <tr key={p.namespace + '/' + p.name}>
                      <td className="id wrap"><a href={podHref(p.namespace, p.name)}>{p.namespace}/{p.name}</a></td>
                      <td>{p.phase}</td>
                      <td className="num">{p.containers}</td>
                      <td className="num">{p.restarts}</td>
                      <td>{p.oomKilled ? <StatusGlyph status="crit" label={false} /> : <span className="muted">No</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )
        }
      </Async>
    </>
  )
}
