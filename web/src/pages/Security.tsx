import { useMemo, useState } from 'react'
import { can, hiddenNote } from '../access'
import { useInfo } from '../components/Access'
import { Async, Empty, ListStatus, PageHead, Segmented, StatusGlyph } from '../components/ui'
import { VirtualTable, type Column } from '../components/VirtualTable'
import { plural } from '../format'
import { groupSecurity, securityPartial, securitySubjectHref } from '../inventory'
import { setQuery, type Route } from '../router'
import type { SecurityFinding, SecurityResponse, SecuritySeverity } from '../types'
import { useApi, useDebounced, type ApiState } from '../useApi'
import { usePaged } from '../usePaged'
import { compareStatus, compareText } from '../virtual'

type CategoryOption = 'all' | 'pod' | 'rbac' | 'namespace' | 'exposure'

const CATEGORIES: { value: CategoryOption; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'pod', label: 'Pods' },
  { value: 'rbac', label: 'RBAC' },
  { value: 'namespace', label: 'Namespaces' },
  { value: 'exposure', label: 'Exposure' },
]

const SEVERITIES: { value: SecuritySeverity; label: string; count: (n: number) => string }[] = [
  { value: 'crit', label: 'Critical', count: () => 'critical' },
  { value: 'warn', label: 'Warning', count: (n) => plural(n, 'warning', 'warnings') },
  { value: 'info', label: 'Info', count: () => 'info' },
]

/** Groups bigger than this show a few findings and a link to all of them. */
const GROUP_PREVIEW_ABOVE = 12
const GROUP_PREVIEW = 8

const findingItems = (r: SecurityResponse) => r.findings
const mergeFindings = (r: SecurityResponse, findings: SecurityFinding[]): SecurityResponse => ({ ...r, findings })

const findingColumns: Column<SecurityFinding>[] = [
  { key: 'sev', header: 'Severity', width: 112, sort: (a, b) => compareStatus(a.severity, b.severity), cell: (x) => <StatusGlyph status={x.severity} /> },
  { key: 'kind', header: 'Kind', width: 150, sort: (a, b) => compareText(a.subjectKind, b.subjectKind), cell: (x) => (
    <>
      {x.subjectKind}
      {x.system && <span className="tag tag-after">system</span>}
    </>
  ) },
  {
    key: 'subject',
    header: 'Subject',
    width: '34%',
    sort: (a, b) => compareText(a.subject, b.subject),
    title: (x) => x.subject,
    cell: (x) => {
      const href = securitySubjectHref(x)
      return href ? <a className="id" href={href}>{x.subject}</a> : <span className="id">{x.subject}</span>
    },
  },
  { key: 'detail', header: 'Detail', width: '46%', title: (x) => x.detail || undefined, cell: (x) => x.detail || <span className="muted">-</span> },
]

export function Security({ route }: { route: Route }) {
  const info = useInfo()
  const p = route.query
  const f = {
    category: p.get('category') ?? '',
    severity: p.get('severity') ?? '',
    q: p.get('q') ?? '',
    system: p.get('system') === '1',
    check: p.get('check') ?? '',
  }
  const set = (patch: Partial<Record<'category' | 'severity' | 'q' | 'system' | 'check', string | undefined>>) =>
    setQuery('/security', { category: f.category, severity: f.severity, q: f.q, system: f.system ? '1' : undefined, check: f.check, ...patch })

  // The summary (counts and the most severe findings) is quick at any size; the rest loads on demand.
  const [full, setFull] = useState(false)
  const summary = useApi<SecurityResponse>(full ? null : '/api/v1/security?view=summary', 60_000)
  const all = usePaged<SecurityResponse, SecurityFinding>(full ? '/api/v1/security' : null, { items: findingItems, merge: mergeFindings, refreshMs: 60_000 })
  const data = full ? (all.data ?? summary.data) : summary.data
  const state: ApiState<SecurityResponse> = full
    ? { data, error: all.error, loading: all.loading && !!all.data, reload: all.reload }
    : summary

  const dq = useDebounced(f.q)
  const findings = useMemo(() => data?.findings ?? [], [data])
  const groups = useMemo(
    () => groupSecurity(findings, { ...f, q: dq }),
    // The filter object is rebuilt every render; its fields are the dependencies.
    [findings, dq, f.category, f.severity, f.system, f.check],
  )
  const partial = !full && !!data && securityPartial(data)
  const rbacHidden = !can(info, 'clusterRBAC') && (!f.category || f.category === 'rbac')

  return (
    <>
      <PageHead
        title="Security"
        lede="Risky pod settings, broad RBAC grants, namespaces without Pod Security, and services reachable from outside the cluster."
      />
      <Async state={state} what="security findings">
        {(d) => {
          const total = Object.values(d.counts ?? {}).reduce((s: number, n) => s + (n ?? 0), 0)
          const namespaces = (d.namespaces ?? []).filter((n) => f.system || !n.system)
          const checkTitle = f.check ? (findings.find((x) => x.check === f.check)?.title ?? f.check) : ''
          return (
            <>
              {d.warnings?.map((w) => <div className="notice warn" key={w}>{w}</div>)}
              <ul className="tally" aria-label="Findings by severity, not counting system components">
                {SEVERITIES.map((s) => {
                  const n = d.counts?.[s.value] ?? 0
                  return (
                    <li key={s.value}>
                      <StatusGlyph status={s.value} decorative />
                      <strong>{n.toLocaleString('en-US')}</strong> {s.count(n)}
                    </li>
                  )
                })}
                <li className="muted tally-note">not counting system components</li>
              </ul>

              {partial && (
                <div className="notice" role="status">
                  <p>
                    Showing the {findings.length.toLocaleString('en-US')} most severe of {total.toLocaleString('en-US')} findings. Filters and search apply to these only.
                  </p>
                  <button type="button" className="btn" onClick={() => setFull(true)}>Load all findings</button>
                </div>
              )}
              {full && (all.following || all.stopped || all.truncated) && <ListStatus state={all} noun={['finding', 'findings']} />}

              <div className="filters">
                <div className="filter-group">
                  <span className="filter-label" aria-hidden="true">Category</span>
                  <Segmented
                    label="Category"
                    value={(f.category || 'all') as CategoryOption}
                    options={CATEGORIES}
                    onChange={(v) => set({ category: v === 'all' ? undefined : v })}
                  />
                </div>
                <label>
                  Severity
                  <select value={f.severity} onChange={(e) => set({ severity: e.target.value })}>
                    <option value="">Critical and warnings</option>
                    <option value="all">Any severity</option>
                    {SEVERITIES.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
                  </select>
                </label>
                <label>
                  Search
                  <input type="search" value={f.q} onChange={(e) => set({ q: e.target.value })} placeholder="Subject, check or detail" />
                </label>
                <label className="checkbox">
                  <input type="checkbox" checked={f.system} onChange={(e) => set({ system: e.target.checked ? '1' : undefined })} />
                  Show system components
                </label>
              </div>

              {rbacHidden && <p className="notice">{hiddenNote('clusterRBAC')}</p>}
              {f.check && (
                <p className="notice">
                  Showing one check: <strong>{checkTitle}</strong>.{' '}
                  <button type="button" className="linklike" onClick={() => set({ check: undefined })}>Show all checks</button>
                </p>
              )}

              <section aria-labelledby="h-findings" className="first">
                <h2 id="h-findings">Findings</h2>
                {findings.length === 0 ? (
                  <Empty title="No security risks found" />
                ) : groups.length === 0 ? (
                  <Empty title="No findings match">
                    {f.system ? 'Clear the search or pick another category or severity.' : 'Clear the filters, or show system components.'}
                  </Empty>
                ) : f.check && groups.length === 1 && groups[0].findings.length > GROUP_PREVIEW_ABOVE ? (
                  <>
                    <p className="count">{groups[0].findings.length.toLocaleString('en-US')} {plural(groups[0].findings.length, 'finding', 'findings')}</p>
                    <VirtualTable rows={groups[0].findings} columns={findingColumns} rowKey={(x) => x.id} caption={groups[0].title} minWidth={820} resetKey={dq} />
                  </>
                ) : (
                  groups.map((g) => {
                    const preview = !f.check && g.findings.length > GROUP_PREVIEW_ABOVE
                    const list = preview ? g.findings.slice(0, GROUP_PREVIEW) : g.findings
                    return (
                      <div className="group" key={g.check}>
                        <h3 className="group-head" id={`g-${g.check}`}>
                          <StatusGlyph status={g.severity} label={false} />
                          <span>{g.title}</span>
                          <span className="group-count">{g.findings.length.toLocaleString('en-US')}</span>
                        </h3>
                        <ul className="ledger" aria-labelledby={`g-${g.check}`}>
                          {list.map((x) => {
                            const href = securitySubjectHref(x)
                            return (
                              <li key={x.id}>
                                <div className="ledger-row static">
                                  <StatusGlyph status={x.severity} label={false} />
                                  <span className="ledger-main">
                                    <span className="ledger-kind">
                                      {x.subjectKind}
                                      {x.system && <span className="tag tag-after">system</span>}
                                    </span>
                                    {href ? <a className="id" href={href}>{x.subject}</a> : <span className="id">{x.subject}</span>}
                                    {x.detail && <span className="ledger-sentence">{x.detail}</span>}
                                  </span>
                                </div>
                              </li>
                            )
                          })}
                        </ul>
                        {preview && (
                          <p className="group-more">
                            <button type="button" className="linklike" onClick={() => set({ check: g.check })}>
                              Show all {g.findings.length.toLocaleString('en-US')}
                            </button>
                          </p>
                        )}
                      </div>
                    )
                  })
                )}
              </section>

              <section aria-labelledby="h-psa">
                <h2 id="h-psa">Namespace Pod Security</h2>
                {namespaces.length === 0 ? (
                  <Empty title="No namespaces to show" />
                ) : (
                  <div className="table-wrap scroll-y" tabIndex={0}>
                    <table>
                      <thead>
                        <tr><th>Namespace</th><th>Enforce</th><th>Audit</th><th>Warn</th><th>Status</th></tr>
                      </thead>
                      <tbody>
                        {namespaces.map((n) => (
                          <tr key={n.name}>
                            <td>
                              <span className="id">{n.name}</span>
                              {n.system && <span className="tag tag-after">system</span>}
                            </td>
                            {[n.enforce, n.audit, n.warn].map((v, i) => (
                              <td key={i}>{v || <span className="muted">not set</span>}</td>
                            ))}
                            <td><StatusGlyph status={n.status} /></td>
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
