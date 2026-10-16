import { useEffect, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from 'react'
import { can, hiddenNote } from '../access'
import {
  ackText,
  alertsPath,
  annotationRows,
  bulkPlan,
  canSelect,
  checkDuration,
  checkLabel,
  checkReason,
  chunks,
  filterAlerts,
  historyRows,
  isNarrowed,
  keyMissing,
  linkLabel,
  MAX_QUERY,
  MAX_REASON,
  maxSilenceMs,
  objectText,
  optionsOf,
  outcomeOf,
  patchAlertFilter,
  presetAllowed,
  readAlertFilter,
  requestErrorText,
  rowActions,
  rowId,
  selectionOf,
  severityStatus,
  silenceText,
  SILENCE_PRESETS,
  STATE_TABS,
  STATE_WORD,
  tabCounts,
  toggleAll,
  toggleKey,
  durationText,
  type AlertFilter,
  type Outcome,
} from '../alerts'
import { ApiError, apiPost } from '../api'
import { Async, Empty, ListStatus, PageHead, StatusGlyph } from '../components/ui'
import { ago, formatDateTime } from '../format'
import { incidentHref } from '../incidents'
import { trapTab } from '../nav'
import { setQuery, type Route } from '../router'
import type { AlertActionKind, AlertActionResponse, AlertActionResult, AlertActionsResponse, AlertFinding, AlertsResponse, AlertState, Info } from '../types'
import { useApi } from '../useApi'
import { usePaged } from '../usePaged'

const items = (r: AlertsResponse) => r.items
const merge = (r: AlertsResponse, all: AlertFinding[]): AlertsResponse => ({ ...r, items: all })

/** A pending silence: the findings it covers and how many selected rows it left out. */
interface SilenceRequest {
  rows: AlertFinding[]
  skipped: number
}

/**
 * The findings kubesentry alerts on, by state, with who acknowledged or
 * silenced them. Acting on them changes kubesentry's notifications only;
 * nothing is written to the cluster or to Alertmanager's silences. Every
 * filter lives in the address.
 */
export function Alerts({ route, info }: { route: Route; info: Info }) {
  const f = readAlertFilter(route.query)
  const set = (patch: Partial<AlertFilter>) => setQuery('/alerts', patchAlertFilter(f, patch))
  const list = usePaged<AlertsResponse, AlertFinding>(alertsPath(f), { items, merge, limit: 500, refreshMs: 30_000, retryBusy: true })
  const rows = useMemo(() => list.data?.items ?? [], [list.data])
  const shown = filterAlerts(rows, f)
  const counts = tabCounts(rows, f, list.data?.counts)
  const mayAct = can(info, 'alertsUpdate')
  const maxMs = maxSilenceMs(info)

  const [selected, setSelected] = useState<ReadonlySet<string>>(new Set())
  const [open, setOpen] = useState<ReadonlySet<string>>(() => new Set(f.key ? [f.key] : []))
  const [outcome, setOutcome] = useState<Outcome>()
  const [busy, setBusy] = useState(false)
  const [silence, setSilence] = useState<SilenceRequest | null>(null)
  const [historyTick, setHistoryTick] = useState(0)

  // A finding named in the address opens, and scrolls into view once it is listed.
  const scrolled = useRef('')
  useEffect(() => {
    if (!f.key) return
    setOpen((o) => (o.has(f.key) ? o : new Set([...o, f.key])))
  }, [f.key])
  const keyed = f.key && shown.some((a) => a.key === f.key)
  useEffect(() => {
    if (!keyed || scrolled.current === f.key) return
    scrolled.current = f.key
    document.getElementById(rowId(f.key))?.scrollIntoView({ block: 'start' })
  }, [keyed, f.key])

  const titles = useMemo(() => new Map(rows.map((a) => [a.key, a.title])), [rows])
  const sel = selectionOf(shown, selected)
  const plan = bulkPlan(shown, sel.keys)

  /** Runs one action on keys; the outcome shows above the list. A failed request throws for the silence dialog to show. */
  async function act(action: AlertActionKind, keys: string[], extra: { for?: string; reason?: string; forText?: string; skipped?: number } = {}) {
    if (keys.length === 0) return
    setBusy(true)
    try {
      const results: AlertActionResult[] = []
      for (const part of chunks(keys)) {
        const body = action === 'silence' ? { keys: part, action, for: extra.for, reason: extra.reason } : { keys: part, action }
        const r = await apiPost<AlertActionResponse>('/api/v1/alerts/actions', body)
        results.push(...r.results)
      }
      setOutcome(outcomeOf(action, results, titles, { forText: extra.forText, skipped: extra.skipped }))
      const done = new Set(results.filter((r) => r.ok).map((r) => r.key))
      setSelected((s) => new Set([...s].filter((k) => !done.has(k))))
      list.reload()
      setHistoryTick((t) => t + 1)
    } catch (e) {
      const msg = e instanceof ApiError ? requestErrorText(e.status, e.message) : e instanceof Error ? e.message : String(e)
      if (action === 'silence') throw new Error(msg)
      setOutcome({ tone: 'crit', text: msg, details: [] })
    } finally {
      setBusy(false)
    }
  }

  const askSilence = (targets: AlertFinding[], skipped = 0) => setSilence({ rows: targets, skipped })
  const namespaces = optionsOf(rows.map((r) => r.namespace), f.namespace)
  const owners = optionsOf(rows.map((r) => r.owner), f.owner)
  const checks = optionsOf(rows.map((r) => r.check), f.check)
  const narrowed = isNarrowed(f)
  const a = info.alerts
  const missing = keyMissing(f, rows, list.complete)

  return (
    <>
      <PageHead
        title="Alerts"
        lede="What kubesentry notifies about, and who is handling it. Acknowledging and silencing change only kubesentry's own notifications; nothing is written to the cluster or to Alertmanager."
      />
      {a?.sink === 'none' && (
        <p className="muted small al-note">This server sends no notifications (no Alertmanager is configured); the list shows what it would send.</p>
      )}
      {a?.lastError && (
        <div className="notice warn" role="status">
          Sending to Alertmanager fails: {a.lastError}
        </div>
      )}
      {!mayAct && <p className="muted small al-note">{hiddenNote('alertsUpdate')}</p>}

      <div className="filters">
        <label>
          Severity
          <select value={f.severity} onChange={(e) => set({ severity: e.target.value as AlertFilter['severity'] })}>
            <option value="">Any</option>
            <option value="critical">Critical</option>
            <option value="warning">Warning</option>
          </select>
        </label>
        <label>
          Check
          <select value={f.check} onChange={(e) => set({ check: e.target.value })}>
            <option value="">All checks</option>
            {checks.map((c) => (
              <option key={c} value={c}>
                {checkLabel(c)}
              </option>
            ))}
          </select>
        </label>
        <label>
          Namespace
          <select value={f.namespace} onChange={(e) => set({ namespace: e.target.value })}>
            <option value="">All namespaces</option>
            {namespaces.map((n) => (
              <option key={n}>{n}</option>
            ))}
          </select>
        </label>
        {(owners.length > 0 || f.owner) && (
          <label>
            Owner
            <select value={f.owner} onChange={(e) => set({ owner: e.target.value })}>
              <option value="">All teams</option>
              {owners.map((n) => (
                <option key={n}>{n}</option>
              ))}
            </select>
          </label>
        )}
        <label className="al-search">
          Search
          <input type="search" value={f.q} maxLength={MAX_QUERY} placeholder="Title, object, owner or check" onChange={(e) => set({ q: e.target.value })} />
        </label>
      </div>

      <div className="al-tabs" role="group" aria-label="State">
        {STATE_TABS.map((t) => (
          <button key={t.value} type="button" aria-pressed={f.state === t.value} onClick={() => set({ state: t.value })}>
            {t.label} <span className="al-tab-count">{counts[t.value].toLocaleString('en-US')}</span>
          </button>
        ))}
      </div>
      {(narrowed || f.key) && (
        <p className="small al-clear">
          {narrowed && <span className="muted">Counts follow the filters. </span>}
          <button type="button" className="linklike" onClick={() => set({ namespace: '', owner: '', severity: '', check: '', q: '', key: '' })}>
            Clear filters
          </button>
        </p>
      )}

      {outcome && (
        <div className={`notice ${outcome.tone} al-outcome`} role="status">
          <div className="banner-head">
            <p>{outcome.text}</p>
            <button type="button" className="btn quiet" onClick={() => setOutcome(undefined)}>
              Dismiss
            </button>
          </div>
          {outcome.details.length > 0 && (
            <ul className="plain small">
              {outcome.details.slice(0, 10).map((d, i) => (
                <li key={i}>{d}</li>
              ))}
              {outcome.details.length > 10 && <li className="muted">and {outcome.details.length - 10} more</li>}
            </ul>
          )}
        </div>
      )}
      {missing && (
        <div className="notice" role="status">
          <p>
            The alert <code className="brk">{f.key}</code> is not in the list: it resolved more than a day ago, or you may not see it.
          </p>
        </div>
      )}

      <Async state={list} what="alerts" busy="kubesentry is busy">
        {() =>
          shown.length === 0 ? (
            <Empty title={emptyTitle(f, rows.length)}>
              {rows.length === 0
                ? 'kubesentry alerts on unhealthy workloads, memory leaks, certificates, RBAC and exposure changes, privileged workloads, sensitive audit activity and silent agents.'
                : 'Try another tab, or clear the filters.'}
            </Empty>
          ) : (
            <>
              <ListStatus state={list} noun={['alert', 'alerts']} shown={shown.length} />
              {mayAct && sel.selectable.length > 0 && (
                <div className="al-toolbar" role="group" aria-label="Selected alerts">
                  <label className="al-selectall">
                    <SelectAll checked={sel.all} mixed={sel.some} onChange={() => setSelected((s) => toggleAll(shown, s))} />
                    {sel.keys.length > 0 ? `${sel.keys.length} selected` : `Select all ${sel.selectable.length}`}
                  </label>
                  {plan.ack.length > 0 && (
                    <button type="button" className="btn" disabled={busy} onClick={() => act('ack', plan.ack, { skipped: sel.keys.length - plan.ack.length })}>
                      Acknowledge {plan.ack.length}
                    </button>
                  )}
                  {plan.unack.length > 0 && (
                    <button type="button" className="btn" disabled={busy} onClick={() => act('unack', plan.unack, { skipped: sel.keys.length - plan.unack.length })}>
                      Unacknowledge {plan.unack.length}
                    </button>
                  )}
                  {plan.silence.length > 0 && (
                    <button
                      type="button"
                      className="btn"
                      disabled={busy}
                      onClick={() => askSilence(shown.filter((r) => plan.silence.includes(r.key)), sel.keys.length - plan.silence.length)}
                    >
                      Silence {plan.silence.length}…
                    </button>
                  )}
                  {plan.unsilence.length > 0 && (
                    <button type="button" className="btn" disabled={busy} onClick={() => act('unsilence', plan.unsilence, { skipped: sel.keys.length - plan.unsilence.length })}>
                      Unsilence {plan.unsilence.length}
                    </button>
                  )}
                  {sel.keys.length > 0 && (
                    <button type="button" className="linklike" onClick={() => setSelected(new Set())}>
                      Clear selection
                    </button>
                  )}
                </div>
              )}
              <ol className="al-list">
                {shown.map((r) => (
                  <AlertRow
                    key={r.key}
                    a={r}
                    mayAct={mayAct}
                    busy={busy}
                    highlight={r.key === f.key}
                    selected={selected.has(r.key)}
                    onSelect={() => setSelected((s) => toggleKey(s, r.key))}
                    expanded={open.has(r.key)}
                    onToggle={() => setOpen((o) => toggleKey(o, r.key))}
                    onAct={(action) => act(action, [r.key])}
                    onSilence={() => askSilence([r])}
                    historyTick={historyTick}
                  />
                ))}
              </ol>
            </>
          )
        }
      </Async>
      {list.data?.updatedAt && <p className="muted small al-updated">Evaluated {ago(list.data.updatedAt)}.</p>}

      {silence && (
        <SilenceDialog
          rows={silence.rows}
          maxMs={maxMs}
          onCancel={() => setSilence(null)}
          onSubmit={async (forGo, reason, forText) => {
            await act(
              'silence',
              silence.rows.map((r) => r.key),
              { for: forGo, reason, forText, skipped: silence.skipped },
            )
            setSilence(null)
          }}
        />
      )}
    </>
  )
}

function emptyTitle(f: AlertFilter, total: number): string {
  if (total === 0) return isNarrowed(f) ? 'No alerts match these filters' : 'No alerts'
  const tab = f.state === 'all' ? 'alerts' : `${STATE_WORD[f.state as AlertState].toLowerCase()} alerts`
  return isNarrowed(f) ? `No ${tab} match these filters` : `No ${tab}`
}

/** A checkbox that can show "some selected". */
function SelectAll({ checked, mixed, onChange }: { checked: boolean; mixed: boolean; onChange: () => void }) {
  const ref = useRef<HTMLInputElement>(null)
  useEffect(() => {
    if (ref.current) ref.current.indeterminate = mixed
  }, [mixed])
  return <input ref={ref} type="checkbox" checked={checked} onChange={onChange} />
}

/** The state as a shape plus its word, so it never relies on colour. */
export function AlertStateBadge({ state }: { state: AlertState }) {
  return (
    <span className={`al-state al-state-${state}`}>
      <StateIcon state={state} />
      {STATE_WORD[state]}
    </span>
  )
}

/** The state's shape alone, beside text that already says it. */
function StateIcon({ state }: { state: AlertState }) {
  return (
    <svg className="al-state-icon" viewBox="0 0 16 16" width="13" height="13" aria-hidden="true">
      <StateShape state={state} />
    </svg>
  )
}

function StateShape({ state }: { state: AlertState }) {
  switch (state) {
    case 'acknowledged':
      // A check mark: someone has it.
      return <path d="M3 8.5 6.5 12 13 4.5" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    case 'silenced':
      // A bell, struck through.
      return (
        <>
          <path d="M8 2.5a3.6 3.6 0 0 0-3.6 3.6v3L3 11.2h10l-1.4-2.1v-3A3.6 3.6 0 0 0 8 2.5ZM6.6 13.2a1.5 1.5 0 0 0 2.8 0" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round" />
          <path d="M2.5 2.5 13.5 13.5" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
        </>
      )
    case 'resolved':
      // A ring: closed.
      return <circle cx="8" cy="8" r="5" fill="none" stroke="currentColor" strokeWidth="1.8" />
    default:
      // A bell: it notifies.
      return (
        <path d="M8 2a3.8 3.8 0 0 0-3.8 3.8v3.1L2.7 11.4h10.6l-1.5-2.5V5.8A3.8 3.8 0 0 0 8 2ZM6.5 13.1a1.6 1.6 0 0 0 3 0" fill="currentColor" stroke="currentColor" strokeWidth="0.6" strokeLinejoin="round" />
      )
  }
}

function AlertRow({
  a,
  mayAct,
  busy,
  highlight,
  selected,
  onSelect,
  expanded,
  onToggle,
  onAct,
  onSilence,
  historyTick,
}: {
  a: AlertFinding
  mayAct: boolean
  busy: boolean
  highlight: boolean
  selected: boolean
  onSelect: () => void
  expanded: boolean
  onToggle: () => void
  onAct: (action: AlertActionKind) => void
  onSilence: () => void
  historyTick: number
}) {
  const id = rowId(a.key)
  const acts = rowActions(a)
  const ack = ackText(a)
  const silenced = silenceText(a)
  const linkText = linkLabel(a.link)
  return (
    <li id={id} className={`al-item${highlight ? ' al-highlight' : ''}${mayAct ? ' al-selectable' : ''}`} aria-current={highlight || undefined}>
      {mayAct && (
        <span className="al-check">
          {canSelect(a) && <input type="checkbox" checked={selected} onChange={onSelect} aria-label={`Select: ${a.title}`} />}
        </span>
      )}
      <div className="al-body">
        <p className="al-head">
          <StatusGlyph status={severityStatus(a.severity)} />
          <AlertStateBadge state={a.state} />
          {a.production && <span className="tag tag-crit">production</span>}
          {a.quiet && <span className="tag" title="Listed in the owner's standing digest; never notified on its own until it crosses the threshold">quiet: reported in the digest</span>}
          {a.digest && !a.quiet && <span className="tag" title="Storm protection: announced in the owner's digest rather than on its own">in the owner's digest</span>}
          <span className="al-age" title={`First seen ${formatDateTime(a.firstSeen)}`}>
            {a.state === 'resolved' && a.resolvedAt ? `resolved ${ago(a.resolvedAt)}` : `first seen ${ago(a.firstSeen)}`}
          </span>
        </p>
        <h2 className="al-title">{a.title}</h2>
        <p className="al-sub">
          <span className="id brk">{objectText(a)}</span>
          <span>{checkLabel(a.check)}</span>
          {a.owner && <span>owner {a.owner}</span>}
        </p>
        {(ack || silenced) && (
          <ul className="plain al-marks">
            {ack && (
              <li>
                <StateIcon state="acknowledged" />
                {ack}
              </li>
            )}
            {silenced && (
              <li>
                <StateIcon state="silenced" />
                {silenced}
                {a.silenceReason && <q className="al-reason">{a.silenceReason}</q>}
              </li>
            )}
          </ul>
        )}
        <div className="al-actions">
          {a.incidentId && (
            <a className="btn al-link" href={incidentHref(a.incidentId)}>
              View incident
            </a>
          )}
          {linkText && a.link && (
            <a className="btn al-link" href={a.link}>
              {linkText}
            </a>
          )}
          {acts.ack && (
            <button type="button" className="btn" disabled={busy} onClick={() => onAct('ack')} aria-label={`Acknowledge: ${a.title}`}>
              Acknowledge
            </button>
          )}
          {acts.unack && (
            <button type="button" className="btn" disabled={busy} onClick={() => onAct('unack')} aria-label={`Unacknowledge: ${a.title}`}>
              Unacknowledge
            </button>
          )}
          {acts.silence && (
            <button type="button" className="btn" disabled={busy} onClick={onSilence} aria-label={`Silence…: ${a.title}`}>
              Silence…
            </button>
          )}
          {acts.unsilence && (
            <button type="button" className="btn" disabled={busy} onClick={() => onAct('unsilence')} aria-label={`Unsilence: ${a.title}`}>
              Unsilence
            </button>
          )}
          <button type="button" className="disclose al-more" aria-expanded={expanded} aria-controls={`${id}-details`} onClick={onToggle}>
            <span className="disclose-mark" aria-hidden="true">
              {expanded ? '▾' : '▸'}
            </span>
            Details and history
          </button>
        </div>
        {expanded && <AlertDetails id={`${id}-details`} a={a} mayAct={mayAct} tick={historyTick} />}
      </div>
    </li>
  )
}

function AlertDetails({ id, a, mayAct, tick }: { id: string; a: AlertFinding; mayAct: boolean; tick: number }) {
  const notes = annotationRows(a.annotations)
  const description = a.annotations?.description
  const labels = Object.entries(a.labels ?? {}).sort(([x], [y]) => x.localeCompare(y))
  return (
    <div className="al-details" id={id}>
      {description && <p className="al-desc">{description}</p>}
      <dl className="al-facts">
        <Fact label="First seen">
          {formatDateTime(a.firstSeen)} <span className="muted">({ago(a.firstSeen)})</span>
        </Fact>
        <Fact label="Last seen">{formatDateTime(a.lastSeen)}</Fact>
        {a.lastNotified && <Fact label="Last notified">{formatDateTime(a.lastNotified)}</Fact>}
        {a.resolvedAt && <Fact label="Resolved">{formatDateTime(a.resolvedAt)}</Fact>}
        <Fact label="Alert">
          <span className="id">{a.alert}</span>
        </Fact>
        <Fact label="Key" wide>
          <code className="brk">{a.key}</code>
        </Fact>
        {notes.map((n) => (
          <Fact key={n.key} label={n.label} wide={n.value.length > 60 || n.value.includes('\n')}>
            {n.href ? (
              <a href={n.href} target="_blank" rel="noreferrer noopener">
                {n.key === 'runbook_url' ? 'Open the runbook' : n.value}
              </a>
            ) : (
              <span className="al-value">{n.value}</span>
            )}
          </Fact>
        ))}
        {labels.length > 0 && (
          <Fact label="Labels sent" wide>
            <span className="al-labels">
              {labels.map(([k, v]) => (
                <span key={k} className="tag">
                  {k}={v}
                </span>
              ))}
            </span>
          </Fact>
        )}
      </dl>
      {mayAct && !a.actionable && <p className="muted small">Acknowledging and silencing this one needs the alerts responder role in its namespace.</p>}
      <History alertKey={a.key} firstSeen={a.firstSeen} tick={tick} />
    </div>
  )
}

function Fact({ label, wide, children }: { label: string; wide?: boolean; children: ReactNode }) {
  return (
    <div className={wide ? 'wide' : undefined}>
      <dt>{label}</dt>
      <dd>{children}</dd>
    </div>
  )
}

function History({ alertKey, firstSeen, tick }: { alertKey: string; firstSeen: string; tick: number }) {
  const h = useApi<AlertActionsResponse>(`/api/v1/alerts/actions?${new URLSearchParams({ key: alertKey, limit: '50' })}`)
  const { reload } = h
  const first = useRef(tick)
  useEffect(() => {
    if (tick !== first.current) reload()
  }, [tick, reload])
  return (
    <section className="al-history" aria-label="History">
      <h3>History</h3>
      <Async state={h} what="the history">
        {(d) => {
          const rows = historyRows(d.items, firstSeen)
          if (rows.length === 0) return <p className="muted small">Nobody has acknowledged or silenced it yet.</p>
          return (
            <ol className="plain al-history-list">
              {rows.map((r) => (
                <li key={r.id}>
                  <time dateTime={r.at} title={formatDateTime(r.at)}>
                    {ago(r.at)}
                  </time>
                  <span>
                    <strong>{r.actor}</strong> {r.what}
                    {r.earlier && <span className="muted"> (an earlier episode)</span>}
                    {r.reason && <q className="al-reason">{r.reason}</q>}
                  </span>
                </li>
              ))}
            </ol>
          )
        }}
      </Async>
    </section>
  )
}

const FOCUSABLE = 'button:not([disabled]), input:not([disabled]), textarea:not([disabled]), select:not([disabled]), a[href]'

/**
 * Asks how long and why. A modal dialog: the page behind is inert, Tab
 * stays inside, Esc cancels, and focus goes back where it was.
 */
function SilenceDialog({
  rows,
  maxMs,
  onCancel,
  onSubmit,
}: {
  rows: AlertFinding[]
  maxMs: number
  onCancel: () => void
  onSubmit: (forGo: string, reason: string, forText: string) => Promise<void>
}) {
  const ref = useRef<HTMLDialogElement>(null)
  const firstAllowed = SILENCE_PRESETS.find((p) => p.value === '4h' && presetAllowed(p.value, maxMs)) ?? SILENCE_PRESETS.find((p) => presetAllowed(p.value, maxMs))
  const [choice, setChoice] = useState(firstAllowed?.value ?? 'custom')
  const [custom, setCustom] = useState('')
  const [reason, setReason] = useState('')
  const [tried, setTried] = useState(false)
  const [sending, setSending] = useState(false)
  const [error, setError] = useState<string>()
  const dur = checkDuration(choice, custom, maxMs)
  const why = checkReason(reason)
  const n = rows.length

  useEffect(() => {
    const d = ref.current
    const back = document.activeElement as HTMLElement | null
    if (d && !d.open) d.showModal()
    // Start on the chosen length.
    d?.querySelector<HTMLInputElement>('input[name="silence-for"]:checked')?.focus()
    return () => {
      d?.close()
      back?.focus?.()
    }
  }, [])

  const onKeyDown = (e: KeyboardEvent<HTMLDialogElement>) => {
    if (e.key !== 'Tab' || !ref.current) return
    const els = [...ref.current.querySelectorAll<HTMLElement>(FOCUSABLE)].filter((el) => el.offsetParent !== null || el === document.activeElement)
    const i = els.indexOf(document.activeElement as HTMLElement)
    const next = trapTab(i, els.length, e.shiftKey)
    if (next !== undefined) {
      e.preventDefault()
      els[next]?.focus()
    }
  }

  const submit = async () => {
    setTried(true)
    setError(undefined)
    if (!dur.ok || !why.ok || sending) return
    setSending(true)
    try {
      await onSubmit(dur.go, reason.trim(), dur.text)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
      setSending(false)
    }
  }

  const showDur = !dur.ok && (tried || (choice === 'custom' && custom.trim() !== ''))
  const showWhy = !why.ok && tried
  return (
    <dialog
      ref={ref}
      className="al-dialog"
      aria-labelledby="silence-title"
      aria-describedby="silence-what"
      onCancel={(e) => {
        e.preventDefault()
        if (!sending) onCancel()
      }}
      onKeyDown={onKeyDown}
    >
      <form
        method="dialog"
        onSubmit={(e) => {
          e.preventDefault()
          void submit()
        }}
      >
        <h2 id="silence-title">
          Silence {n} {n === 1 ? 'alert' : 'alerts'}
        </h2>
        <div id="silence-what">
          <p className="muted small">
            kubesentry stops notifying about {n === 1 ? 'it' : 'them'} until the silence ends or is lifted, also if {n === 1 ? 'it resolves and fires' : 'they resolve and fire'} again. Alertmanager's own silences are not touched.
          </p>
          <ul className="plain al-dialog-list">
            {rows.slice(0, 5).map((r) => (
              <li key={r.key}>
                <StatusGlyph status={severityStatus(r.severity)} label={false} /> {r.title}
              </li>
            ))}
            {n > 5 && <li className="muted">and {n - 5} more</li>}
          </ul>
        </div>
        <fieldset className="al-durations" aria-describedby="silence-dur-hint silence-dur-error">
          <legend>For how long</legend>
          {SILENCE_PRESETS.map((p) => {
            const allowed = presetAllowed(p.value, maxMs)
            return (
              <label key={p.value} className={allowed ? undefined : 'off'}>
                <input type="radio" name="silence-for" value={p.value} checked={choice === p.value} disabled={!allowed} onChange={() => setChoice(p.value)} />
                {p.label}
              </label>
            )
          })}
          <label>
            <input type="radio" name="silence-for" value="custom" checked={choice === 'custom'} onChange={() => setChoice('custom')} />
            Other
          </label>
          <input
            type="text"
            className="al-custom"
            aria-label="Other duration"
            placeholder="e.g. 90m, 6h, 2d"
            value={custom}
            inputMode="text"
            autoComplete="off"
            aria-invalid={showDur || undefined}
            onFocus={() => setChoice('custom')}
            onChange={(e) => {
              setChoice('custom')
              setCustom(e.target.value)
            }}
          />
          <p id="silence-dur-hint" className="field-hint">
            Between 5 minutes and {durationText(maxMs)}.{dur.ok && ` Until ${formatDateTime(Date.now() + dur.ms)}.`}
          </p>
          {showDur && (
            <p id="silence-dur-error" className="al-error">
              {!dur.ok && dur.error}
            </p>
          )}
        </fieldset>
        <label className="al-reason-field">
          <span>
            Reason <span className="muted">(required)</span>
          </span>
          <textarea
            value={reason}
            rows={3}
            maxLength={MAX_REASON}
            aria-invalid={showWhy || undefined}
            aria-describedby="silence-reason-hint"
            placeholder="Why, and what happens next: a ticket, a fix, a planned change"
            onChange={(e) => setReason(e.target.value)}
          />
          <span id="silence-reason-hint" className={showWhy ? 'al-error' : 'field-hint'}>
            {showWhy ? why.error : 'Shown to everyone who sees the alert, and sent to Alertmanager.'}{' '}
            <span className="muted">
              {why.length}/{MAX_REASON}
            </span>
          </span>
        </label>
        {error && (
          <p className="notice crit" role="alert">
            {error}
          </p>
        )}
        <div className="al-dialog-buttons">
          <button type="button" className="btn" onClick={onCancel} disabled={sending}>
            Cancel
          </button>
          <button type="submit" className="btn primary" disabled={sending}>
            {sending ? 'Silencing…' : `Silence ${n === 1 ? 'alert' : `${n} alerts`}`}
          </button>
        </div>
      </form>
    </dialog>
  )
}

