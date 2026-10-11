import { Async, Empty, PageHead, slashBreaks, StatusGlyph } from '../components/ui'
import { podHref } from '../findings'
import { formatBytes, formatUSD, plural } from '../format'
import { matches } from '../inventory'
import { setQuery, type Route } from '../router'
import type { StorageResponse, UnusedPVC, UnusedPVCResponse } from '../types'
import { useApi } from '../useApi'

const COST_LEDE = 'Costs are estimates from the per-class prices you configure.'

/** Inventory servers get the full picture; others only the unused-claims check. */
export function Storage({ route, inventory }: { route: Route; inventory: boolean }) {
  return inventory ? <FullStorage route={route} /> : <UnusedOnly />
}

const size = (b: number) => (b > 0 ? formatBytes(b) : '-')

function UnusedTable({ items }: { items: UnusedPVC[] }) {
  return (
    <div className="table-wrap" tabIndex={0}>
      <table>
        <thead>
          <tr><th>Claim</th><th>Class</th><th className="num">Size</th><th className="num">Age</th><th className="num">Est. per month</th></tr>
        </thead>
        <tbody>
          {items.map((p) => (
            <tr key={p.namespace + '/' + p.name}>
              <td className="id brk">{slashBreaks(`${p.namespace}/${p.name}`)}</td>
              <td>{p.storageClass || '-'}</td>
              <td className="num">{formatBytes(p.capacityBytes)}</td>
              <td className="num">{Math.round(p.ageHours / 24)} days</td>
              <td className="num">{formatUSD(p.estMonthlyCostUSD)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function UnusedCount({ count, cost }: { count: number; cost: number }) {
  return (
    <p className="count">
      {count} unused {plural(count, 'claim', 'claims')}, about {formatUSD(cost)} a month
    </p>
  )
}

function UnusedOnly() {
  const state = useApi<UnusedPVCResponse>('/api/v1/pvcs/unused', 60_000)
  return (
    <>
      <PageHead title="Storage" lede={`Persistent volume claims that no pod mounts. ${COST_LEDE}`} />
      <Async state={state} what="volume claims">
        {(d) =>
          d.count === 0 ? (
            <Empty title="Every volume claim is in use" />
          ) : (
            <>
              <UnusedCount count={d.count} cost={d.totalEstMonthlyCostUSD} />
              <UnusedTable items={d.items ?? []} />
            </>
          )
        }
      </Async>
    </>
  )
}

function FullStorage({ route }: { route: Route }) {
  const q = route.query.get('q') ?? ''
  const state = useApi<StorageResponse>('/api/v1/storage', 60_000)
  return (
    <>
      <PageHead title="Storage" lede={`Volume claims, the volumes behind them and their storage classes, starting with claims no pod mounts. ${COST_LEDE}`} />
      <div className="filters">
        <label>
          Search
          <input type="search" value={q} onChange={(e) => setQuery('/storage', { q: e.target.value })} placeholder="Claim, volume or class" />
        </label>
      </div>
      <Async state={state} what="storage">
        {(d) => {
          const unused = (d.unused ?? []).filter((u) => matches(q, `${u.namespace}/${u.name}`, u.storageClass))
          const unusedCost = q ? unused.reduce((s, u) => s + u.estMonthlyCostUSD, 0) : d.unusedMonthlyCostUSD
          const claims = (d.claims ?? []).filter((c) => matches(q, `${c.namespace}/${c.name}`, c.storageClass, c.volumeName))
          const volumes = (d.volumes ?? []).filter((v) => matches(q, v.name, v.claim, v.storageClass))
          const classes = (d.classes ?? []).filter((c) => matches(q, c.name, c.provisioner))
          const none = q ? 'Nothing matches the search' : undefined
          return (
            <>
              <section aria-labelledby="h-unused" className="first">
                <h2 id="h-unused">Unused claims</h2>
                {unused.length === 0 ? (
                  <Empty title={none ?? 'Every volume claim is in use'} />
                ) : (
                  <>
                    <UnusedCount count={unused.length} cost={unusedCost} />
                    <UnusedTable items={unused} />
                  </>
                )}
              </section>

              <section aria-labelledby="h-claims">
                <h2 id="h-claims">Claims</h2>
                {claims.length === 0 ? (
                  <Empty title={none ?? 'No persistent volume claims'} />
                ) : (
                  <div className="table-wrap" tabIndex={0}>
                    <table>
                      <thead>
                        <tr><th>Status</th><th>Claim</th><th>Phase</th><th>Class</th><th className="num">Size</th><th>Used by</th><th>Detail</th></tr>
                      </thead>
                      <tbody>
                        {claims.map((c) => (
                          <tr key={`${c.namespace}/${c.name}`}>
                            <td><StatusGlyph status={c.status} /></td>
                            <td className="id brk name">{slashBreaks(`${c.namespace}/${c.name}`)}</td>
                            <td>{c.phase || '-'}</td>
                            <td>{c.storageClass || '-'}</td>
                            <td className="num">{size(c.capacityBytes)}</td>
                            <td>
                              {(c.usedBy ?? []).length === 0 ? (
                                <span className="muted">No pod</span>
                              ) : (
                                <ul className="plain">
                                  {c.usedBy.map((p) => (
                                    <li key={p}><a className="id" href={podHref(c.namespace, p)}>{p}</a></li>
                                  ))}
                                </ul>
                              )}
                            </td>
                            <td className="msg">{c.detail || <span className="muted">-</span>}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </section>

              <section aria-labelledby="h-pv">
                <h2 id="h-pv">Persistent volumes</h2>
                {volumes.length === 0 ? (
                  <Empty title={none ?? 'No persistent volumes'} />
                ) : (
                  <div className="table-wrap" tabIndex={0}>
                    <table>
                      <thead>
                        <tr><th>Status</th><th>Volume</th><th>Phase</th><th>Class</th><th>Claim</th><th className="num">Size</th><th>Reclaim</th><th>Source</th><th>Detail</th></tr>
                      </thead>
                      <tbody>
                        {volumes.map((v) => (
                          <tr key={v.name}>
                            <td><StatusGlyph status={v.status} /></td>
                            <td className="id brk name">{v.name}</td>
                            <td>{v.phase || '-'}</td>
                            <td>{v.storageClass || '-'}</td>
                            <td className="id brk">{v.claim ? slashBreaks(v.claim) : <span className="muted">-</span>}</td>
                            <td className="num">{size(v.capacityBytes)}</td>
                            <td>{v.reclaimPolicy || '-'}</td>
                            <td>{v.source || '-'}</td>
                            <td className="msg">{v.detail || <span className="muted">-</span>}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </section>

              <section aria-labelledby="h-sc">
                <h2 id="h-sc">Storage classes</h2>
                {classes.length === 0 ? (
                  <Empty title={none ?? 'No storage classes'} />
                ) : (
                  <div className="table-wrap" tabIndex={0}>
                    <table>
                      <thead>
                        <tr><th>Class</th><th>Provisioner</th><th>Reclaim</th><th>Binding</th><th>Expansion</th><th className="num">Claims</th><th className="num">Capacity</th></tr>
                      </thead>
                      <tbody>
                        {classes.map((c) => (
                          <tr key={c.name}>
                            <td>
                              <span className="id">{c.name}</span>
                              {c.default && <span className="tag tag-after">default</span>}
                            </td>
                            <td className="id brk">{slashBreaks(c.provisioner)}</td>
                            <td>{c.reclaimPolicy || '-'}</td>
                            <td>{c.bindingMode || '-'}</td>
                            <td>{c.allowExpansion ? 'Allowed' : 'No'}</td>
                            <td className="num">{c.claims}</td>
                            <td className="num">{size(c.capacityBytes)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </section>
            </>
          )
        }}
      </Async>
    </>
  )
}
