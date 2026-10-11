import { ago, formatDateTime } from '../format'
import type { AuditEvent } from '../types'

function target(e: AuditEvent): string {
  const r = [e.resource, e.subresource].filter(Boolean).join('/')
  const n = e.name ? `${r}/${e.name}` : r
  return e.namespace ? `${e.namespace}: ${n || e.requestURI || ''}` : n || e.requestURI || ''
}

export function ActivityTable({ events, showNamespace = true }: { events: AuditEvent[]; showNamespace?: boolean }) {
  void showNamespace
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
              <td className="id wrap">{target(e)}</td>
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
