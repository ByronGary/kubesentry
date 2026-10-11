import { useMemo } from 'react'
import { can, hiddenNote } from '../access'
import { useInfo } from '../components/Access'
import { Async, Empty, ListStatus, PageHead, slashBreaks, StatusGlyph } from '../components/ui'
import { Lines, VirtualTable, type Column } from '../components/VirtualTable'
import { anyCost, claimCost, claimIndex, classPrice, PRICE_ANNOTATION, unusedCost, unusedTotal, type CostDisplay } from '../cost'
import { podHref } from '../findings'
import { formatBytes, formatUSD, plural } from '../format'
import { matches } from '../inventory'
import { setQuery, type Route } from '../router'
import type { ClaimSummary, StorageResponse, UnusedPVC, UnusedPVCResponse, VolumeSummary } from '../types'
import { useApi, useDebounced } from '../useApi'
import { usePaged } from '../usePaged'
import { compareNumber, compareStatus, compareText } from '../virtual'

const COST_LEDE = 'Monthly costs are estimates from each storage class’s price; hover a cost to see where the price comes from.'

/** Inventory servers get the full picture; others only the unused-claims check. */
export function Storage({ route, inventory }: { route: Route; inventory: boolean }) {
  return inventory ? <FullStorage route={route} /> : <UnusedOnly />
}

const size = (b: number) => (b > 0 ? formatBytes(b) : '-')

function Cost({ c }: { c: CostDisplay }) {
  return (
    <span className={c.kind === 'known' ? undefined : 'muted'} title={c.title}>
      {c.text}
      {c.kind === 'unknown' && <span className="sr-only">: {c.title}</span>}
    </span>
  )
}

function UnusedTable({ items, claims }: { items: UnusedPVC[]; claims: Map<string, ClaimSummary> }) {
  const columns: Column<UnusedPVC>[] = [
    {
      key: 'claim',
      header: 'Claim',
      width: '40%',
      sort: (a, b) => compareText(`${a.namespace}/${a.name}`, `${b.namespace}/${b.name}`),
      title: (p) => `${p.namespace}/${p.name}`,
      cell: (p) => <span className="id">{p.namespace}/{p.name}</span>,
    },
    { key: 'class', header: 'Class', width: '18%', sort: (a, b) => compareText(a.storageClass, b.storageClass), cell: (p) => p.storageClass || '-' },
    { key: 'size', header: 'Size', width: 96, className: 'num', firstDir: 'desc', sort: (a, b) => compareNumber(a.capacityBytes, b.capacityBytes), cell: (p) => formatBytes(p.capacityBytes) },
    { key: 'age', header: 'Age', width: 96, className: 'num', firstDir: 'desc', sort: (a, b) => compareNumber(a.ageHours, b.ageHours), cell: (p) => `${Math.round(p.ageHours / 24)} days` },
    {
      key: 'cost',
      header: 'Est. per month',
      width: 140,
      className: 'num',
      firstDir: 'desc',
      sort: (a, b) => compareNumber(unusedCost(a, claims).kind === 'known' ? a.estMonthlyCostUSD : -1, unusedCost(b, claims).kind === 'known' ? b.estMonthlyCostUSD : -1),
      cell: (p) => <Cost c={unusedCost(p, claims)} />,
    },
  ]
  return <VirtualTable rows={items} columns={columns} rowKey={(p) => `${p.namespace}/${p.name}`} caption="Unused volume claims" minWidth={680} />
}

function UnusedCount({ count, cost, unpriced }: { count: number; cost: number; unpriced: number }) {
  return (
    <p className="count">
      {count} unused {plural(count, 'claim', 'claims')}
      {count > unpriced && `, about ${formatUSD(cost)} a month`}
      {unpriced > 0 && ` (${unpriced} without a price)`}
    </p>
  )
}

const NO_CLAIMS = new Map<string, ClaimSummary>()

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
              <UnusedCount count={d.count} cost={d.totalEstMonthlyCostUSD} unpriced={0} />
              <UnusedTable items={d.items ?? []} claims={NO_CLAIMS} />
            </>
          )
        }
      </Async>
    </>
  )
}

const claimItems = (r: StorageResponse) => r.claims
const mergeClaims = (r: StorageResponse, claims: ClaimSummary[]): StorageResponse => ({ ...r, claims })

function claimColumns(withCost: boolean): Column<ClaimSummary>[] {
  return [
    { key: 'status', header: 'Status', width: 112, sort: (a, b) => compareStatus(a.status, b.status), cell: (c) => <StatusGlyph status={c.status} /> },
    {
      key: 'claim',
      header: 'Claim',
      width: '26%',
      sort: (a, b) => compareText(`${a.namespace}/${a.name}`, `${b.namespace}/${b.name}`),
      title: (c) => `${c.namespace}/${c.name}${c.volumeName ? `\nvolume ${c.volumeName}` : ''}`,
      cell: (c) => <Lines main={<span className="id">{c.name}</span>} sub={<span className="id">{c.namespace}</span>} />,
    },
    { key: 'phase', header: 'Phase', width: 92, sort: (a, b) => compareText(a.phase, b.phase), cell: (c) => c.phase || '-' },
    { key: 'class', header: 'Class', width: '14%', sort: (a, b) => compareText(a.storageClass, b.storageClass), title: (c) => c.storageClass, cell: (c) => c.storageClass || '-' },
    { key: 'size', header: 'Size', width: 88, className: 'num', firstDir: 'desc', sort: (a, b) => compareNumber(a.capacityBytes, b.capacityBytes), cell: (c) => size(c.capacityBytes) },
    ...(withCost
      ? [
          {
            key: 'cost',
            header: 'Est. per month',
            width: 132,
            className: 'num',
            firstDir: 'desc' as const,
            sort: (a: ClaimSummary, b: ClaimSummary) =>
              compareNumber(claimCost(a)?.kind === 'known' ? a.estMonthlyCostUSD : -1, claimCost(b)?.kind === 'known' ? b.estMonthlyCostUSD : -1),
            cell: (c: ClaimSummary) => {
              const cost = claimCost(c)
              return cost ? <Cost c={cost} /> : <span className="muted">-</span>
            },
          },
        ]
      : []),
    {
      key: 'used',
      header: 'Used by',
      width: '18%',
      sort: (a, b) => compareNumber(a.usedBy?.length ?? 0, b.usedBy?.length ?? 0),
      title: (c) => (c.usedBy ?? []).join('\n') || undefined,
      cell: (c) => {
        const used = c.usedBy ?? []
        if (used.length === 0) return <span className="muted">No pod</span>
        return (
          <Lines
            main={<a className="id" href={podHref(c.namespace, used[0])}>{used[0]}</a>}
            sub={used.length > 1 ? `and ${used.length - 1} more` : undefined}
          />
        )
      },
    },
    { key: 'detail', header: 'Detail', width: '20%', title: (c) => c.detail || undefined, cell: (c) => (c.detail ? <Lines main={c.detail} /> : <span className="muted">-</span>) },
  ]
}

const volumeColumns: Column<VolumeSummary>[] = [
  { key: 'status', header: 'Status', width: 112, sort: (a, b) => compareStatus(a.status, b.status), cell: (v) => <StatusGlyph status={v.status} /> },
  { key: 'name', header: 'Volume', width: '22%', sort: (a, b) => compareText(a.name, b.name), title: (v) => v.name, cell: (v) => <span className="id">{v.name}</span> },
  { key: 'phase', header: 'Phase', width: 92, sort: (a, b) => compareText(a.phase, b.phase), cell: (v) => v.phase || '-' },
  { key: 'class', header: 'Class', width: '12%', sort: (a, b) => compareText(a.storageClass, b.storageClass), cell: (v) => v.storageClass || '-' },
  { key: 'claim', header: 'Claim', width: '20%', sort: (a, b) => compareText(a.claim, b.claim), title: (v) => v.claim, cell: (v) => (v.claim ? <span className="id">{v.claim}</span> : <span className="muted">-</span>) },
  { key: 'size', header: 'Size', width: 88, className: 'num', firstDir: 'desc', sort: (a, b) => compareNumber(a.capacityBytes, b.capacityBytes), cell: (v) => size(v.capacityBytes) },
  { key: 'reclaim', header: 'Reclaim', width: 92, sort: (a, b) => compareText(a.reclaimPolicy, b.reclaimPolicy), cell: (v) => v.reclaimPolicy || '-' },
  { key: 'source', header: 'Source', width: '10%', sort: (a, b) => compareText(a.source, b.source), title: (v) => [v.source, v.driver, v.volumeHandle].filter(Boolean).join('\n'), cell: (v) => v.source || '-' },
  { key: 'detail', header: 'Detail', width: '16%', title: (v) => v.detail || undefined, cell: (v) => v.detail || <span className="muted">-</span> },
]

function FullStorage({ route }: { route: Route }) {
  const info = useInfo()
  const q = route.query.get('q') ?? ''
  const dq = useDebounced(q)
  const state = usePaged<StorageResponse, ClaimSummary>('/api/v1/storage', { items: claimItems, merge: mergeClaims, refreshMs: 60_000 })
  const d = state.data
  const pvsOK = can(info, 'pvs')
  const classesOK = can(info, 'storageClasses')

  const index = useMemo(() => claimIndex(d?.claims ?? []), [d?.claims])
  const withCost = useMemo(() => anyCost(d?.claims ?? []), [d?.claims])
  const unused = useMemo(() => (d?.unused ?? []).filter((u) => matches(dq, `${u.namespace}/${u.name}`, u.storageClass)), [d?.unused, dq])
  const unusedSum = useMemo(() => {
    if (!d) return { total: 0, unpriced: 0 }
    const t = unusedTotal(unused, index)
    // Without a search and with every claim priced, the server's own total is exact.
    return !dq && t.unpriced === 0 ? { total: d.unusedMonthlyCostUSD, unpriced: 0 } : t
  }, [d, unused, index, dq])
  const claims = useMemo(() => (d?.claims ?? []).filter((c) => matches(dq, `${c.namespace}/${c.name}`, c.storageClass, c.volumeName)), [d?.claims, dq])
  const volumes = useMemo(() => (d?.volumes ?? []).filter((v) => matches(dq, v.name, v.claim, v.storageClass)), [d?.volumes, dq])
  const classes = useMemo(() => (d?.classes ?? []).filter((c) => matches(dq, c.name, c.provisioner)), [d?.classes, dq])
  const cols = useMemo(() => claimColumns(withCost), [withCost])
  const none = dq ? 'Nothing matches the search' : undefined
  const anyPrice = (d?.classes ?? []).some((c) => classPrice(c) !== undefined)

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
        {() => (
          <>
            <section aria-labelledby="h-unused" className="first">
              <h2 id="h-unused">Unused claims</h2>
              {unused.length === 0 ? (
                <Empty title={none ?? 'Every volume claim is in use'} />
              ) : (
                <>
                  <UnusedCount count={unused.length} cost={unusedSum.total} unpriced={unusedSum.unpriced} />
                  <UnusedTable items={unused} claims={index} />
                </>
              )}
            </section>

            <section aria-labelledby="h-claims">
              <h2 id="h-claims">Claims</h2>
              <ListStatus state={state} noun={['claim', 'claims']} shown={claims.length} />
              {claims.length === 0 ? (
                state.following ? null : <Empty title={none ?? 'No persistent volume claims'} />
              ) : (
                <VirtualTable rows={claims} columns={cols} rowKey={(c) => `${c.namespace}/${c.name}`} caption="Persistent volume claims" rowHeight={52} minWidth={withCost ? 1080 : 960} resetKey={dq} />
              )}
              {withCost && (
                <p className="field-hint">
                  “—” means no price is known for the class: set the StorageClass annotation <code>{PRICE_ANNOTATION}</code>. EFS and FSx are billed by
                  usage, so they have no estimate.
                </p>
              )}
            </section>

            <section aria-labelledby="h-pv">
              <h2 id="h-pv">Persistent volumes</h2>
              {!pvsOK ? (
                <p className="notice">{hiddenNote('pvs')}</p>
              ) : volumes.length === 0 ? (
                <Empty title={none ?? 'No persistent volumes'} />
              ) : (
                <VirtualTable rows={volumes} columns={volumeColumns} rowKey={(v) => v.name} caption="Persistent volumes" minWidth={1080} resetKey={dq} />
              )}
            </section>

            <section aria-labelledby="h-sc">
              <h2 id="h-sc">Storage classes</h2>
              {!classesOK ? (
                <p className="notice">{hiddenNote('storageClasses')}</p>
              ) : classes.length === 0 ? (
                <Empty title={none ?? 'No storage classes'} />
              ) : (
                <div className="table-wrap" tabIndex={0}>
                  <table>
                    <thead>
                      <tr>
                        <th>Class</th>
                        <th>Provisioner</th>
                        <th>Reclaim</th>
                        <th>Binding</th>
                        <th>Expansion</th>
                        <th className="num">Claims</th>
                        <th className="num">Capacity</th>
                        {anyPrice && <th className="num">Price</th>}
                      </tr>
                    </thead>
                    <tbody>
                      {classes.map((c) => {
                        const price = classPrice(c)
                        return (
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
                            {anyPrice && <td className="num">{price ? <Cost c={price} /> : <span className="muted">-</span>}</td>}
                          </tr>
                        )
                      })}
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
