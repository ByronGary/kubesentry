import { Async, Empty, PageHead } from '../components/ui'
import { podHref } from '../findings'
import { ago, formatBytes, formatHours } from '../format'
import type { OOMResponse } from '../types'
import { useApi } from '../useApi'

export function Memory() {
  const state = useApi<OOMResponse>('/api/v1/oom?window=24h', 60_000)
  return (
    <>
      <PageHead title="Memory" lede="Containers killed for running out of memory, and containers whose memory only climbs." />
      <Async state={state} what="memory findings">
        {(d) => (
          <>
            {d.warnings?.map((w) => <div className="notice warn" key={w}>{w}</div>)}
            {!d.metricsAvailable && <div className="notice warn">No Prometheus connection, so leak detection is off. OOM kills below still come from the cluster.</div>}
            <section aria-labelledby="h-oom">
              <h2 id="h-oom">OOMKilled</h2>
              {d.events.length === 0 ? (
                <Empty title="No containers were OOMKilled" />
              ) : (
                <div className="table-wrap" tabIndex={0}>
                  <table>
                    <thead><tr><th>Pod</th><th>Container</th><th>Last killed</th><th className="num">Restarts</th></tr></thead>
                    <tbody>
                      {d.events.map((e) => (
                        <tr key={`${e.namespace}/${e.pod}/${e.container}`}>
                          <td className="id wrap"><a href={podHref(e.namespace, e.pod)}>{e.namespace}/{e.pod}</a></td>
                          <td className="id">{e.container}</td>
                          <td>{ago(e.lastOOMAt)}</td>
                          <td className="num">{e.restartCount}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>
            <section aria-labelledby="h-leak">
              <h2 id="h-leak">Likely leaks</h2>
              {d.leaks.length === 0 ? (
                <Empty title="No steady memory growth found" />
              ) : (
                <div className="table-wrap" tabIndex={0}>
                  <table>
                    <thead>
                      <tr><th>Pod</th><th>Container</th><th className="num">Growth</th><th className="num">Now</th><th className="num">Full in</th><th>Confidence</th></tr>
                    </thead>
                    <tbody>
                      {d.leaks.map((l) => (
                        <tr key={`${l.namespace}/${l.pod}/${l.container}`}>
                          <td className="id wrap"><a href={podHref(l.namespace, l.pod)}>{l.namespace}/{l.pod}</a></td>
                          <td className="id">{l.container}</td>
                          <td className="num">{formatBytes(l.slopeBytesPerHour)}/h</td>
                          <td className="num">{formatBytes(l.currentBytes)}</td>
                          <td className="num">{l.timeToLimitHours !== undefined ? formatHours(l.timeToLimitHours) : 'No limit'}</td>
                          <td>{l.confidence}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>
          </>
        )}
      </Async>
    </>
  )
}
