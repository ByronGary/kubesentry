import { useMemo, useState } from 'react'
import { can } from '../access'
import { qs } from '../api'
import { PrometheusNotice } from '../components/Access'
import { ActivityTable } from '../components/ActivityTable'
import { MemoryChart } from '../components/MemoryChart'
import { Async, BusyNotice, PageHead, Segmented, StatusGlyph } from '../components/ui'
import { ago, formatBytes, formatCPU, formatDateTime, plural } from '../format'
import { incidentHref, severityGlyph } from '../incidents'
import { activityEmptyText, metricsHistoryHours, metricsWhy, windowChoices, type WindowOption } from '../retention'
import { podActivity, prometheusOutage, unexplainedWarnings } from '../sources'
import type { IncidentRef, Info, PodDiagnostics, ProcessesResponse, Status } from '../types'
import { useApi } from '../useApi'

/** The server's memory windows (it accepts up to 7 days); longer than Prometheus keeps are disabled. */
const WINDOWS: WindowOption[] = [
  { value: '1h', label: '1 hour', hours: 1 },
  { value: '6h', label: '6 hours', hours: 6 },
  { value: '24h', label: '24 hours', hours: 24 },
  { value: '168h', label: '7 days', hours: 168 },
]

/** Diagnostics plus the lookback of its activity list, which a newer server may send (proposed contract). */
type Diagnostics = PodDiagnostics & { activityWindow?: string }

function verdict(d: PodDiagnostics): { status: Status; text: string } {
  const bad = d.checks.filter((c) => c.status === 'crit')
  const warn = d.checks.filter((c) => c.status === 'warn')
  if (bad.length) return { status: 'crit', text: `${bad.length} ${plural(bad.length, 'problem needs', 'problems need')} attention: ${bad[0].detail}` }
  if (warn.length) return { status: 'warn', text: `${warn.length} ${plural(warn.length, 'thing is', 'things are')} worth checking: ${warn[0].detail}` }
  return { status: 'ok', text: 'No problems found in the checks below.' }
}

export function PodDetail({ ns, name, info }: { ns: string; name: string; info: Info }) {
  const [win, setWin] = useState('6h')
  const procsOK = info.processes && can(info, 'processes')
  const auditOK = can(info, 'audit')
  const down = prometheusOutage(info)
  // The diagnostics answer 200 with a warning when the audit store did not answer:
  // keep the rest and ask again sooner, backing off like the audit routes.
  const state = useApi<Diagnostics>(
    `/api/v1/pods/${encodeURIComponent(ns)}/${encodeURIComponent(name)}/diagnostics${qs({ window: win })}`,
    30_000,
    { busyIn: (d) => auditOK && podActivity(d) === 'unavailable' },
  )
  const procs = useApi<ProcessesResponse>(
    procsOK ? `/api/v1/pods/${encodeURIComponent(ns)}/${encodeURIComponent(name)}/processes` : null,
    15_000,
  )
  const windows = useMemo(() => windowChoices(WINDOWS, metricsHistoryHours(info.prometheus), metricsWhy), [info.prometheus])

  return (
    <>
      <nav className="crumbs" aria-label="Breadcrumb"><a href="#/pods">Pods</a></nav>
      <Async state={state} what="pod">
        {(d) => {
          const v = verdict(d)
          const activity = podActivity(d)
          // The memory and activity sections explain these failures themselves.
          const warnings = unexplainedWarnings(d.warnings, { prometheus: !!down && !d.metricsAvailable, audit: auditOK && activity === 'unavailable' })
          return (
            <>
              <PageHead title={d.name} lede={<span className="id">{d.namespace}</span>}>
                <span className="phase">{d.phase}</span>
              </PageHead>
              <p className={`verdict verdict-${v.status}`}>
                <StatusGlyph status={v.status} label={false} />
                <span>{v.text}</span>
              </p>
              {warnings.map((w) => <div className="notice warn" key={w}>{w}</div>)}
              {d.incidents && d.incidents.length > 0 && <IncidentBanner refs={d.incidents} />}

              <section aria-labelledby="h-checks">
                <h2 id="h-checks">Diagnosis</h2>
                <ul className="checks">
                  {d.checks.map((c) => (
                    <li key={c.id}>
                      <StatusGlyph status={c.status} />
                      <strong>{c.title}</strong>
                      <span>{c.detail}</span>
                    </li>
                  ))}
                </ul>
              </section>

              <section aria-labelledby="h-mem">
                <div className="section-head">
                  <h2 id="h-mem">Memory</h2>
                  <Segmented label="Time window" value={win} options={windows} onChange={setWin} />
                </div>
                {!d.metricsAvailable && down ? (
                  <PrometheusNotice reason={down} fallback={<p className="muted">Memory history is paused while Prometheus is unavailable.</p>} />
                ) : !d.metricsAvailable ? (
                  <div className="notice">Memory history needs Prometheus. Start the server with <code>-prometheus-url</code>.</div>
                ) : (
                  d.containers.map((c) => (
                    <div className="container-block" key={c.name}>
                      <h3>
                        <span className="id">{c.name}</span>
                        <span className="muted">
                          {c.currentBytes !== undefined && `${formatBytes(c.currentBytes)} now`}
                          {c.limitBytes ? ` of ${formatBytes(c.limitBytes)}` : ' (no limit)'}
                          {c.restartCount > 0 && `, ${c.restartCount} ${plural(c.restartCount, 'restart', 'restarts')}`}
                          {c.lastTerminatedReason && `, last ended ${c.lastTerminatedReason}${c.lastTerminatedAt ? ' ' + ago(c.lastTerminatedAt) : ''}`}
                        </span>
                      </h3>
                      <MemoryChart container={c} />
                    </div>
                  ))
                )}
              </section>

              {procsOK && (
                <section aria-labelledby="h-proc">
                  <h2 id="h-proc">Processes</h2>
                  {!procs.data ? (
                    <p className="muted">{procs.error ? `Could not load processes: ${procs.error.message}` : 'Loading processes…'}</p>
                  ) : !procs.data.available ? (
                    <p className="muted">No node agent has reported this pod yet. Check that the agent runs on the node where it is scheduled.</p>
                  ) : (
                    <>
                      <p className="muted proc-meta">
                        {procs.data.processes.length} {plural(procs.data.processes.length, 'process', 'processes')} on <span className="id">{procs.data.node}</span>, seen {procs.data.observedAt ? ago(procs.data.observedAt) : ''}.
                        {procs.data.stale && ' This data is stale: the agent has stopped reporting.'}
                      </p>
                      <div className="table-wrap" tabIndex={0}>
                        <table>
                          <thead>
                            <tr><th>Process</th><th>Container</th><th className="num">PID</th><th className="num">CPU</th><th className="num">Memory</th><th className="num">Threads</th><th>Command</th></tr>
                          </thead>
                          <tbody>
                            {procs.data.processes.map((p) => (
                              <tr key={p.pid}>
                                <td className="id">{p.name}</td>
                                <td className="id">{p.container}</td>
                                <td className="num">{p.pid}</td>
                                <td className="num">{formatCPU(p.cpuMillicores)}</td>
                                <td className="num">{formatBytes(p.rssBytes)}</td>
                                <td className="num">{p.threads}</td>
                                <td className="id wrap cmd">{p.cmdline || '-'}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </>
                  )}
                </section>
              )}

              <section aria-labelledby="h-vol">
                <h2 id="h-vol">Volumes</h2>
                {d.volumes.length === 0 ? (
                  <p className="muted">This pod mounts no persistent volumes.</p>
                ) : (
                  <div className="table-wrap" tabIndex={0}>
                    <table>
                      <thead><tr><th>Claim</th><th>Status</th><th>Class</th><th className="num">Size</th></tr></thead>
                      <tbody>
                        {d.volumes.map((v2) => (
                          <tr key={v2.claim}>
                            <td className="id">{v2.claim}</td>
                            <td>{v2.found ? v2.phase : 'Claim not found'}</td>
                            <td>{v2.storageClass ?? '-'}</td>
                            <td className="num">{v2.capacityBytes ? formatBytes(v2.capacityBytes) : '-'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </section>

              {auditOK && (
                <section aria-labelledby="h-act">
                  <h2 id="h-act">Recent activity</h2>
                  {activity === 'unavailable' ? (
                    <BusyNotice retry={state.retry} text="Audit store is not answering" note="The rest of this page is current." />
                  ) : activity === 'hidden' ? (
                    <p className="muted">You may not read audit events in this namespace.</p>
                  ) : activity === 'off' ? (
                    <div className="notice">Activity needs audit ingestion. The README shows how to turn it on.</div>
                  ) : d.activity.length === 0 ? (
                    <p className="muted">{activityEmptyText(d.activityWindow, info.auditStore)}</p>
                  ) : (
                    <ActivityTable events={d.activity} />
                  )}
                </section>
              )}
            </>
          )
        }}
      </Async>
    </>
  )
}

/** The incidents this pod is part of (open, or resolved within a day), newest first. */
function IncidentBanner({ refs }: { refs: IncidentRef[] }) {
  const open = refs.filter((r) => r.state === 'open')
  const worst = open.some((r) => r.severity === 'critical') ? 'crit' : open.length ? 'warn' : ''
  return (
    <section className={`notice inc-banner ${worst}`} aria-labelledby="h-pod-inc">
      <h2 id="h-pod-inc" className="inc-banner-title">
        {open.length > 0
          ? `${open.length} open ${plural(open.length, 'incident involves', 'incidents involve')} this pod`
          : `${refs.length} recent ${plural(refs.length, 'incident involved', 'incidents involved')} this pod`}
      </h2>
      <ul className="plain">
        {refs.slice(0, 5).map((r) => (
          <li key={r.id}>
            <StatusGlyph status={severityGlyph(r.severity)} label={false} /> <a href={incidentHref(r.id)}>{r.title}</a>{' '}
            <span className="muted small" title={formatDateTime(r.start)}>
              {r.state}, started {ago(r.start)}
            </span>
          </li>
        ))}
      </ul>
      {refs.length > 5 && (
        <p className="small">
          <a href="#/incidents">All incidents</a>
        </p>
      )}
    </section>
  )
}
