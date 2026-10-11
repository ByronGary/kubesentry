import { useMemo } from 'react'
import { activityFindings, certFindings, memoryFindings, oomFindings, rank, securityFindings, volumeFindings } from '../findings'
import { plural } from '../format'
import { Async, Empty, PageHead, StatusGlyph } from '../components/ui'
import type { AuditEventsResponse, CertificatesResponse, Info, OOMResponse, SecurityResponse, UnusedPVCResponse } from '../types'
import { useApi } from '../useApi'

export function Findings({ info }: { info: Info }) {
  const oom = useApi<OOMResponse>('/api/v1/oom?window=24h', 60_000)
  const pvcs = useApi<UnusedPVCResponse>('/api/v1/pvcs/unused', 60_000)
  const events = useApi<AuditEventsResponse>(info.audit ? '/api/v1/audit/events?since=24h&limit=500' : null, 60_000)
  const security = useApi<SecurityResponse>(info.inventory ? '/api/v1/security' : null, 60_000)
  const certs = useApi<CertificatesResponse>(info.certs ? '/api/v1/certificates' : null, 60_000)

  const findings = useMemo(
    () =>
      rank([
        ...oomFindings(oom.data),
        ...memoryFindings(oom.data),
        ...securityFindings(security.data),
        ...certFindings(certs.data),
        ...volumeFindings(pvcs.data),
        ...activityFindings(events.data?.items),
      ]),
    [oom.data, pvcs.data, events.data, security.data, certs.data],
  )

  // Show the page as soon as the cheapest sources answer; auth errors surface through Async.
  const primary = oom.data ? oom : pvcs.data ? pvcs : oom
  return (
    <>
      <PageHead title="Findings" lede="What needs a look, most urgent first. Each line opens the place to dig in." />
      <Async state={primary as never} what="findings">
        {() => (
          <>
            {oom.data && !oom.data.metricsAvailable && (
              <div className="notice warn">
                No Prometheus connection, so memory leaks and trends are not checked. Start the server with <code>-prometheus-url</code>.
              </div>
            )}
            {!info.audit && (
              <div className="notice">User activity is off. Enable audit ingestion to see who did what; the README shows how.</div>
            )}
            {findings.length === 0 ? (
              <Empty title="Nothing needs attention">
                No OOM kills, leaking containers{info.inventory ? ', security risks' : ''}{info.certs ? ', failing certificates' : ''}, unused volumes or notable activity in the last 24 hours.
              </Empty>
            ) : (
              <>
                <p className="count">{findings.length} {plural(findings.length, 'finding', 'findings')}</p>
                <ul className="ledger">
                  {findings.map((f) => (
                    <li key={f.id}>
                      <a href={f.href} className="ledger-row">
                        <StatusGlyph status={f.severity} label={false} />
                        <span className="ledger-main">
                          <span className="ledger-kind">{f.category}</span>
                          <span className={f.subjectIsId ? 'id' : 'ledger-subject'}>{f.subject}</span>
                          <span className="ledger-sentence">{f.sentence}</span>
                        </span>
                        <span className="ledger-meta">{f.meta}</span>
                      </a>
                    </li>
                  ))}
                </ul>
              </>
            )}
          </>
        )}
      </Async>
    </>
  )
}
