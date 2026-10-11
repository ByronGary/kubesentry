import { ago, formatDateTime } from '../format'
import type { AuditEvent } from '../types'

/** What an audit event acted on: "shop: pods/exec/web-0", or the request URI. */
export function auditTarget(e: AuditEvent): string {
  const r = [e.resource, e.subresource].filter(Boolean).join('/')
  const n = e.name ? `${r}/${e.name}` : r
  return e.namespace ? `${e.namespace}: ${n || e.requestURI || ''}` : n || e.requestURI || ''
}

export function ActivityTable({ events }: { events: AuditEvent[] }) {
  return (
    <div className="table-wrap" tabIndex={0}>
      <table>
        <thead>
          <tr>
            <th>When</th>
            <th>Who</th>
            <th>Action</th>
            <th>Target</th>
            <th>Result</th>
            <th>Flags</th>
          </tr>
        </thead>
        <tbody>
          {events.map((e) => (
            <tr key={e.auditID + e.stage}>
              <td title={formatDateTime(e.time)}>{ago(e.time)}</td>
              <td>
                <span className="id">{e.arn ? e.sessionName || e.arn : e.username}</span>
                {e.impersonatedUser && <span className="muted"> as {e.impersonatedUser}</span>}
              </td>
              <td>{e.verb}</td>
              <td className="id wrap">{auditTarget(e)}</td>
              <td className={e.statusCode >= 400 ? 'bad' : undefined}>{e.statusCode || '-'}</td>
              <td>
                {(e.tags ?? []).map((t) => (
                  <span key={t} className="tag">{t}</span>
                ))}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
