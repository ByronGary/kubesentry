import { Async, Empty, PageHead, Segmented, StatusGlyph } from '../components/ui'
import { plural } from '../format'
import { groupSecurity, securitySubjectHref } from '../inventory'
import { setQuery, type Route } from '../router'
import type { SecurityResponse, SecuritySeverity } from '../types'
import { useApi } from '../useApi'

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

export function Security({ route }: { route: Route }) {
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
  const state = useApi<SecurityResponse>('/api/v1/security', 60_000)

  return (
    <>
      <PageHead
        title="Security"
        lede="Risky pod settings, broad RBAC grants, namespaces without Pod Security, and services reachable from outside the cluster."
      />
      <Async state={state} what="security findings">
        {(d) => {
          const findings = d.findings ?? []
          const groups = groupSecurity(findings, f)
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
                      <strong>{n}</strong> {s.count(n)}
                    </li>
                  )
                })}
                <li className="muted tally-note">not counting system components</li>
              </ul>

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
                ) : (
                  groups.map((g) => (
                    <div className="group" key={g.check}>
                      <h3 className="group-head" id={`g-${g.check}`}>
                        <StatusGlyph status={g.severity} label={false} />
                        <span>{g.title}</span>
                        <span className="group-count">{g.findings.length}</span>
                      </h3>
                      <ul className="ledger" aria-labelledby={`g-${g.check}`}>
                        {g.findings.map((x) => {
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
                    </div>
                  ))
                )}
              </section>

              <section aria-labelledby="h-psa">
                <h2 id="h-psa">Namespace Pod Security</h2>
                {namespaces.length === 0 ? (
                  <Empty title="No namespaces to show" />
                ) : (
                  <div className="table-wrap" tabIndex={0}>
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
