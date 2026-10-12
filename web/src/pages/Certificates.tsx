import { can, hiddenNote } from '../access'
import { useInfo } from '../components/Access'
import { Async, Empty, PageHead, slashBreaks, StatusGlyph } from '../components/ui'
import { ago, formatDateTime, formatExpiry, formatHours, hoursUntil, plural } from '../format'
import { matches, statusMatches } from '../inventory'
import { setQuery, type Route } from '../router'
import type { CertificatesResponse, CertSummary, RequestSummary } from '../types'
import { useApi } from '../useApi'

/** Server detail, plus the raw condition message when the detail does not already include it. */
function Message({ detail, message }: { detail?: string; message?: string }) {
  if (!detail && !message) return <span className="muted">-</span>
  const extra = message && !(detail ?? '').includes(message.replace(/[.\s]+$/, '')) ? message : undefined
  return (
    <>
      {detail && <div>{detail}</div>}
      {extra && <div className="muted small">{extra}</div>}
    </>
  )
}

function Expiry({ c }: { c: CertSummary }) {
  const h = c.expiresInHours ?? hoursUntil(c.notAfter)
  const renew = hoursUntil(c.renewalTime)
  const title = [c.notAfter && `Not after ${formatDateTime(c.notAfter)}`, c.renewalTime && `Renewal ${formatDateTime(c.renewalTime)}`].filter(Boolean).join('\n')
  return (
    <span title={title || undefined}>
      <span className={h !== undefined && h < 0 ? 'bad-text' : undefined}>{formatExpiry(h)}</span>
      {renew !== undefined && (
        <div className="muted small">{renew >= 0 ? `renews in ${formatHours(renew)}` : `renewal due ${formatHours(-renew)} ago`}</div>
      )}
    </span>
  )
}

function requestState(r: RequestSummary): string {
  const s = r.denied ? 'Denied' : r.approved ? 'Approved' : 'Awaiting approval'
  return r.reason ? `${s}, ${r.reason}` : s
}

export function Certificates({ route }: { route: Route }) {
  const q = route.query.get('q') ?? ''
  // "unhealthy" (critical or warning) is what the Overview and the sidebar badge count.
  const status = route.query.get('status') === 'unhealthy' ? 'unhealthy' : ''
  const set = (k: 'q' | 'status', v: string) => setQuery('/certificates', { q, status, [k]: v })
  const state = useApi<CertificatesResponse>('/api/v1/certificates', 60_000)
  // ClusterIssuers need cluster-wide access; without it the server sends names only, which this page hides.
  const clusterIssuersOK = can(useInfo(), 'clusterIssuers')

  return (
    <>
      <PageHead title="Certificates" lede="cert-manager certificates, when they expire, and whether their issuers can renew them." />
      <Async state={state} what="certificates">
        {(d) => {
          if (!d.installed) {
            return (
              <Empty title="cert-manager is not installed">
                Install cert-manager in the cluster and its certificates, issuers and failing requests appear here.
              </Empty>
            )
          }
          const certs = (d.certificates ?? []).filter(
            (c) => statusMatches(status, c.status) && matches(q, `${c.namespace}/${c.name}`, c.secretName, `${c.issuerKind}/${c.issuerName}`, ...(c.dnsNames ?? [])),
          )
          const issuers = (d.issuers ?? []).filter(
            (i) =>
              (clusterIssuersOK || i.kind !== 'ClusterIssuer') &&
              statusMatches(status, i.status) &&
              matches(q, i.namespace ? `${i.namespace}/${i.name}` : i.name, i.kind, i.type, i.server),
          )
          const requests = (d.requests ?? []).filter((r) => matches(q, `${r.namespace}/${r.name}`, r.certificate, r.issuerName))
          const none = q || status ? 'Nothing matches the filters' : undefined
          return (
            <>
              <div className="filters">
                <label>
                  Search
                  <input type="search" value={q} onChange={(e) => set('q', e.target.value)} placeholder="Name, DNS name or issuer" />
                </label>
                <label>
                  Status
                  <select value={status} onChange={(e) => set('status', e.target.value)}>
                    <option value="">Any status</option>
                    <option value="unhealthy">Critical or warning</option>
                  </select>
                </label>
              </div>

              <section aria-labelledby="h-certs" className="first">
                <h2 id="h-certs">Certificates</h2>
                {certs.length === 0 ? (
                  <Empty title={none ?? 'No certificates'}>{none ? undefined : 'cert-manager is installed but manages no Certificate objects.'}</Empty>
                ) : (
                  <>
                    <p className="count">{certs.length} {plural(certs.length, 'certificate', 'certificates')}</p>
                    <div className="table-wrap" tabIndex={0}>
                      <table>
                        <thead>
                          <tr><th>Status</th><th>Certificate</th><th>DNS names</th><th>Issuer</th><th>Expires</th><th>Detail</th></tr>
                        </thead>
                        <tbody>
                          {certs.map((c) => (
                            <tr key={`${c.namespace}/${c.name}`}>
                              <td><StatusGlyph status={c.status} /></td>
                              <td className="id brk name">
                                {slashBreaks(`${c.namespace}/${c.name}`)}
                                {c.secretName && <div className="muted small">secret {c.secretName}</div>}
                              </td>
                              <td>
                                {(c.dnsNames ?? []).length === 0 ? (
                                  <span className="muted">-</span>
                                ) : (
                                  <ul className="plain">{c.dnsNames.map((n) => <li key={n} className="id brk">{n}</li>)}</ul>
                                )}
                              </td>
                              <td>
                                <span className="muted small">{c.issuerKind}</span>
                                <div className="id">{c.issuerName}</div>
                              </td>
                              <td><Expiry c={c} /></td>
                              <td className="msg"><Message detail={c.detail} message={c.message} /></td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </>
                )}
              </section>

              <section aria-labelledby="h-issuers">
                <h2 id="h-issuers">Issuers</h2>
                {!clusterIssuersOK && <p className="notice">{hiddenNote('clusterIssuers')}</p>}
                {issuers.length === 0 ? (
                  <Empty title={none ?? 'No issuers'}>{none ? undefined : 'Certificates need an Issuer or ClusterIssuer before cert-manager can sign them.'}</Empty>
                ) : (
                  <div className="table-wrap" tabIndex={0}>
                    <table>
                      <thead>
                        <tr><th>Status</th><th>Kind</th><th>Issuer</th><th>Type</th><th>Server</th><th className="num">Certificates</th><th>Message</th></tr>
                      </thead>
                      <tbody>
                        {issuers.map((i) => (
                          <tr key={`${i.kind}/${i.namespace ?? ''}/${i.name}`}>
                            <td><StatusGlyph status={i.status} /></td>
                            <td>{i.kind}</td>
                            <td className="id brk">{slashBreaks(i.namespace ? `${i.namespace}/${i.name}` : i.name)}</td>
                            <td>{i.type || '-'}</td>
                            <td className="id brk">{i.server ? slashBreaks(i.server) : <span className="muted">-</span>}</td>
                            <td className="num">{i.certificates}</td>
                            <td className="msg"><Message detail={i.detail} message={i.message} /></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </section>

              {requests.length > 0 && (
                <section aria-labelledby="h-requests">
                  <h2 id="h-requests">Failing requests</h2>
                  <p className="count">Certificate requests that are pending, failed or denied.</p>
                  <div className="table-wrap" tabIndex={0}>
                    <table>
                      <thead>
                        <tr><th>Status</th><th>Request</th><th>Certificate</th><th>Issuer</th><th>State</th><th className="num">Created</th><th>Message</th></tr>
                      </thead>
                      <tbody>
                        {requests.map((r) => (
                          <tr key={`${r.namespace}/${r.name}`}>
                            <td><StatusGlyph status={r.status} /></td>
                            <td className="id brk">{slashBreaks(`${r.namespace}/${r.name}`)}</td>
                            <td className="id brk">{r.certificate || '-'}</td>
                            <td>
                              <span className="muted small">{r.issuerKind}</span>
                              <div className="id">{r.issuerName}</div>
                            </td>
                            <td>{requestState(r)}</td>
                            <td className="num" title={formatDateTime(r.created)}>{ago(r.created)}</td>
                            <td className="msg"><Message message={r.message} /></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </section>
              )}
            </>
          )
        }}
      </Async>
    </>
  )
}
