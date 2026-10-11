import { useMemo } from 'react'
import { can } from '../access'
import { activityFindings, certFindings, memoryFindings, oomFindings, rank, securityFindings, volumeFindings } from '../findings'
import { plural } from '../format'
import { securityPartial } from '../inventory'
import { Async, Empty, PageHead, StatusGlyph } from '../components/ui'
import { auditHistoryHours, lookbackText, metricsHistoryHours } from '../retention'
import type { AuditEventsResponse, CertificatesResponse, Info, OOMResponse, SecurityResponse, UnusedPVCResponse } from '../types'
import { useApi } from '../useApi'

/** The lookback of this page's queries. */
const WINDOW_HOURS = 24

/** "in the last 24 hours", or less when Prometheus or the audit log holds less. */
function windowText(info: Info, audit: boolean): string {
  const metrics = info.metrics ? metricsHistoryHours(info.prometheus) : undefined
  const events = audit ? auditHistoryHours(info.auditStore) : undefined
  if (events !== undefined && (metrics === undefined || events < metrics)) return lookbackText(WINDOW_HOURS, events, 'the audit log')
  return lookbackText(WINDOW_HOURS, metrics, 'Prometheus')
}

export function Findings({ info }: { info: Info }) {
  const auditOK = info.audit && can(info, 'audit')
  const oom = useApi<OOMResponse>(`/api/v1/oom?window=${WINDOW_HOURS}h`, 60_000)
  const pvcs = useApi<UnusedPVCResponse>('/api/v1/pvcs/unused', 60_000)
  const events = useApi<AuditEventsResponse>(auditOK ? `/api/v1/audit/events?since=${WINDOW_HOURS}h&limit=500` : null, 60_000)
  // The summary carries the counts and the most severe findings, which is all this page needs.
  const security = useApi<SecurityResponse>(info.inventory ? '/api/v1/security?view=summary' : null, 60_000)
  const certs = useApi<CertificatesResponse>(info.certs ? '/api/v1/certificates' : null, 60_000)

  const findings = useMemo(
    () =>
      rank([
        ...oomFindings(oom.data),
        ...memoryFindings(oom.data),
        ...securityFindings(security.data, !!security.data && securityPartial(security.data)),
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
                No OOM kills, leaking containers{info.inventory ? ', security risks' : ''}{info.certs ? ', failing certificates' : ''}, unused volumes
                {auditOK ? ' or notable activity' : ''} {windowText(info, auditOK)}.
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
