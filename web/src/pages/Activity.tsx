import { useMemo } from 'react'
import { can, hiddenNote } from '../access'
import { qs } from '../api'
import { auditTarget } from '../components/ActivityTable'
import { Async, Empty, PageHead, WindowSelect } from '../components/ui'
import { Lines, VirtualTable, type Column } from '../components/VirtualTable'
import { ago, formatDateTime } from '../format'
import { auditHistoryHours, auditWhy, windowChoices, type WindowOption } from '../retention'
import { setQuery, type Route } from '../router'
import type { AuditEvent, AuditEventsResponse, AuditSummary, Info } from '../types'
import { useApi } from '../useApi'
import { usePaged } from '../usePaged'
import { compareNumber, compareText } from '../virtual'

const SINCE: WindowOption[] = [
  { value: '1h', label: 'Last hour', hours: 1 },
  { value: '24h', label: 'Last 24 hours', hours: 24 },
  { value: '168h', label: 'Last 7 days', hours: 168 },
  { value: '720h', label: 'Last 30 days', hours: 720 },
]

const PAGE = 200

const eventItems = (r: AuditEventsResponse) => r.items
const mergeEvents = (r: AuditEventsResponse, items: AuditEvent[]): AuditEventsResponse => ({ ...r, items, count: items.length })

const columns: Column<AuditEvent>[] = [
  { key: 'when', header: 'When', width: 132, sort: (a, b) => compareText(a.time, b.time), firstDir: 'desc', title: (e) => formatDateTime(e.time), cell: (e) => ago(e.time) },
  {
    key: 'who',
    header: 'Who',
    width: '22%',
    sort: (a, b) => compareText(a.username, b.username),
    title: (e) => [e.username, e.arn, e.impersonatedUser && `as ${e.impersonatedUser}`].filter(Boolean).join('\n'),
    cell: (e) => <Lines main={<span className="id">{e.arn ? e.sessionName || e.arn : e.username}</span>} sub={e.impersonatedUser ? `as ${e.impersonatedUser}` : undefined} />,
  },
  { key: 'verb', header: 'Action', width: 96, sort: (a, b) => compareText(a.verb, b.verb), cell: (e) => e.verb },
  { key: 'target', header: 'Target', width: '34%', sort: (a, b) => compareText(auditTarget(a), auditTarget(b)), title: (e) => e.requestURI || auditTarget(e), cell: (e) => <span className="id">{auditTarget(e)}</span> },
  {
    key: 'result',
    header: 'Result',
    width: 76,
    sort: (a, b) => compareNumber(a.statusCode, b.statusCode),
    firstDir: 'desc',
    cell: (e) => <span className={e.statusCode >= 400 ? 'bad-text' : undefined}>{e.statusCode || '-'}</span>,
  },
  {
    key: 'flags',
    header: 'Flags',
    width: '18%',
    title: (e) => (e.tags ?? []).join(', ') || undefined,
    cell: (e) => (e.tags ?? []).map((t) => <span key={t} className="tag">{t}</span>),
  },
]

export function Activity({ route, info }: { route: Route; info: Info }) {
  const p = route.query
  const since = p.get('since') ?? '24h'
  const tag = p.get('tag') ?? ''
  const user = p.get('user') ?? ''
  const set = (k: string, v: string) => setQuery('/activity', { since, tag, user, [k]: v })

  const summary = useApi<AuditSummary>(info.audit ? `/api/v1/audit/summary${qs({ since })}` : null, 60_000)
  // Newest first, one page at a time: "Load older" follows the cursor.
  const events = usePaged<AuditEventsResponse, AuditEvent>(info.audit ? `/api/v1/audit/events${qs({ since, tag, user })}` : null, {
    items: eventItems,
    merge: mergeEvents,
    limit: PAGE,
    mode: 'manual',
    refreshMs: 60_000,
  })
  const tags = Object.keys(summary.data?.byTag ?? {}).sort()
  const users = (summary.data?.users ?? []).map((u) => u.username)
  const choices = useMemo(() => windowChoices(SINCE, auditHistoryHours(info.auditStore), auditWhy(info.auditStore)), [info.auditStore])

  if (!info.audit) {
    return (
      <>
        <PageHead title="Activity" />
        <Empty title="Activity needs audit ingestion">This server does not receive the API server audit log. The README shows how to turn it on.</Empty>
      </>
    )
  }

  return (
    <>
      <PageHead title="Activity" lede="Who did what in the cluster, from the API server audit log. System components and plain reads are hidden." />
      <div className="filters">
        <WindowSelect label="Period" value={since} choices={choices} onChange={(v) => set('since', v)} />
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
      {!can(info, 'clusterAudit') && <p className="notice">{hiddenNote('clusterAudit')}</p>}

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
              {d.items.length === 0 ? (
                <Empty title="No events match">Widen the period or clear the filters.</Empty>
              ) : (
                <>
                  <p className="count" aria-live="polite">
                    {d.items.length.toLocaleString('en-US')} {d.items.length === 1 ? 'event' : 'events'}, newest first
                    {events.hasMore ? '; older ones follow' : ''}
                  </p>
                  <VirtualTable rows={d.items} columns={columns} rowKey={(e) => e.auditID + e.stage} caption="Audit events, newest first" rowHeight={44} minWidth={900} />
                  {events.hasMore && (
                    <p className="load-more">
                      <button type="button" className="btn" onClick={events.loadMore} disabled={events.loadingMore}>
                        {events.loadingMore ? 'Loading…' : 'Load older events'}
                      </button>
                    </p>
                  )}
                </>
              )}
            </section>
          </>
        )}
      </Async>
    </>
  )
}
