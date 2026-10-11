import { qs } from '../api'
import { ActivityTable } from '../components/ActivityTable'
import { Async, Empty, PageHead } from '../components/ui'
import { setQuery, type Route } from '../router'
import type { AuditEventsResponse, AuditSummary } from '../types'
import { useApi } from '../useApi'

const SINCE = [
  ['1h', 'Last hour'],
  ['24h', 'Last 24 hours'],
  ['168h', 'Last 7 days'],
  ['720h', 'Last 30 days'],
] as const

export function Activity({ route }: { route: Route }) {
  const p = route.query
  const since = p.get('since') ?? '24h'
  const tag = p.get('tag') ?? ''
  const user = p.get('user') ?? ''
  const set = (k: string, v: string) => setQuery('/activity', { since, tag, user, [k]: v })

  const summary = useApi<AuditSummary>(`/api/v1/audit/summary${qs({ since })}`, 60_000)
  const events = useApi<AuditEventsResponse>(`/api/v1/audit/events${qs({ since, tag, user, limit: 200 })}`, 60_000)
  const tags = Object.keys(summary.data?.byTag ?? {}).sort()
  const users = (summary.data?.users ?? []).map((u) => u.username)

  return (
    <>
      <PageHead title="Activity" lede="Who did what in the cluster, from the API server audit log. System components and plain reads are hidden." />
      <div className="filters">
        <label>
          Period
          <select value={since} onChange={(e) => set('since', e.target.value)}>
            {SINCE.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </select>
        </label>
        <label>
          Flag
          <select value={tag} onChange={(e) => set('tag', e.target.value)}>
            <option value="">Any</option>
            {[...new Set([...tags, ...(tag ? [tag] : [])])].map((t) => <option key={t} value={t}>{t} ({summary.data?.byTag[t] ?? 0})</option>)}
          </select>
        </label>
        <label>
          User
          <select value={user} onChange={(e) => set('user', e.target.value)}>
            <option value="">Everyone</option>
            {[...new Set([...users, ...(user ? [user] : [])])].map((u) => <option key={u}>{u}</option>)}
          </select>
        </label>
      </div>

      <Async state={events} what="activity">
        {(d) => (
          <>
            {summary.data && summary.data.users.length > 0 && !user && !tag && (
              <section aria-labelledby="h-users">
                <h2 id="h-users">By user</h2>
                <div className="table-wrap" tabIndex={0}>
                  <table>
                    <thead>
                      <tr><th>User</th><th className="num">Requests</th><th className="num">Changes</th><th className="num">Exec</th><th className="num">Secret reads</th><th className="num">Denied</th></tr>
                    </thead>
                    <tbody>
                      {summary.data.users.slice(0, 10).map((u) => (
                        <tr key={u.username}>
                          <td className="id"><button className="linklike" onClick={() => set('user', u.username)}>{u.username}</button></td>
                          <td className="num">{u.total}</td>
                          <td className="num">{u.writes}</td>
                          <td className="num">{u.execs}</td>
                          <td className="num">{u.secretAccess}</td>
                          <td className="num">{u.denied}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
            )}
            <section aria-labelledby="h-events">
              <h2 id="h-events">Events</h2>
              {d.items.length === 0 ? <Empty title="No events match">Widen the period or clear the filters.</Empty> : <ActivityTable events={d.items} />}
            </section>
          </>
        )}
      </Async>
    </>
  )
}
