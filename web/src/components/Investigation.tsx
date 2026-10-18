import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { ApiError, apiPost } from '../api'
import type { Range } from '../chartMath'
import { formatClock, formatDateTime } from '../format'
import {
  announceText,
  cachedText,
  canCancel,
  cancelErrorText,
  cancelPath,
  checkView,
  chosenRun,
  confidence,
  egressNotice,
  failedText,
  hiddenRunsText,
  investigationPath,
  investigationsPath,
  investigatorOn,
  isTerminal,
  modelText,
  omittedRows,
  outcome,
  outcomeText,
  pollMs,
  providerName,
  refAction,
  refLabel,
  runByline,
  runStatus,
  startErrorText,
  stepView,
  timelineRange,
  usageText,
  type LogFocus,
  type RefContext,
} from '../investigation'
import type { Info, Investigation as Run, InvestigationEvidence, InvestigationsResponse, InvestigationStartResponse, InvestigationSummary } from '../types'
import { useApi, useNow } from '../useApi'
import { StatusGlyph } from './ui'

// The AI investigator on the incident page: the Investigate button (by the
// bundle download), and the panel with a run's progress, its report and the
// incident's earlier runs. Everything the model wrote is rendered as React
// text: no markdown, no HTML, no links. Refs become buttons that move the
// page to the evidence; commands are shown, never run. Logic lives in
// investigation.ts.

export interface InvestigationsState {
  enabled: boolean
  info: Info
  incidentId: string
  runs: InvestigationSummary[]
  hidden: number
  listLoaded: boolean
  /** The run shown, and its full record once loaded. */
  selected?: string
  run?: Run
  runError?: Error
  select: (id: string) => void
  start: (fresh: boolean) => void
  starting: boolean
  /** Why the last start failed, in words. */
  error?: string
  /** The last start was answered from an earlier run. */
  cached: boolean
  cancel: () => void
  cancelling: boolean
  cancelError?: string
  /** This tab started the shown run. */
  startedHere: boolean
  /** What the live region says. */
  announce: string
  setAnnounce: (s: string) => void
}

/** The incident's runs, the one shown (polled every 2s while it runs), and starting and cancelling. */
export function useInvestigations(incidentId: string, info: Info): InvestigationsState {
  const enabled = investigatorOn(info)
  const list = useApi<InvestigationsResponse>(enabled ? investigationsPath(incidentId) : null)
  const [asked, setAsked] = useState<string>()
  const [started, setStarted] = useState<Run>()
  const [startedIds, setStartedIds] = useState<Set<string>>(() => new Set())
  const [starting, setStarting] = useState(false)
  const [error, setError] = useState<string>()
  const [cached, setCached] = useState(false)
  const [cancelling, setCancelling] = useState(false)
  const [cancelError, setCancelError] = useState<string>()
  const [announce, setAnnounce] = useState('')

  const runs = useMemo(() => list.data?.items ?? [], [list.data])
  const selected = chosenRun(runs, asked, started?.id)
  // Poll the shown run while it runs: the interval follows the last answer.
  const [interval, setIntervalMs] = useState<number>()
  const detail = useApi<Run>(enabled && selected ? investigationPath(incidentId, selected) : null, interval)
  let run = detail.data?.id === selected ? detail.data : undefined
  if (started && started.id === selected && (!run || (run.status === 'running' && started.status !== 'running'))) run = started
  useEffect(() => setIntervalMs(pollMs(run)), [run?.status])

  // When the shown run ends, say so and refresh the list's summaries.
  const lastStatus = useRef<string | undefined>(undefined)
  const reloadList = list.reload
  useEffect(() => {
    if (!run) return
    const prev = lastStatus.current
    lastStatus.current = `${run.id}:${run.status}`
    if (prev === undefined || prev === lastStatus.current) return
    if (prev.startsWith(`${run.id}:`) || startedIds.has(run.id)) setAnnounce(announceText(run))
    if (isTerminal(run.status)) reloadList()
  }, [run?.id, run?.status])

  const select = useCallback((id: string) => {
    setAsked(id)
    setCached(false)
    setError(undefined)
    setCancelError(undefined)
  }, [])

  const start = useCallback(
    async (fresh: boolean) => {
      setStarting(true)
      setError(undefined)
      setCancelError(undefined)
      try {
        const r = await apiPost<InvestigationStartResponse>(investigationsPath(incidentId), fresh ? { fresh: true } : undefined)
        setStarted(r.investigation)
        setStartedIds((s) => new Set(s).add(r.investigation.id))
        setAsked(r.investigation.id)
        setCached(r.cached === true)
        setAnnounce(r.cached ? announceText(r.investigation) : 'Investigation started.')
        reloadList()
      } catch (e) {
        if (e instanceof ApiError && e.status === 409 && typeof e.body?.runningId === 'string') {
          setAsked(e.body.runningId)
          setCached(false)
          setError(`${startErrorText(e)} It is shown below.`)
          reloadList()
        } else {
          setError(e instanceof ApiError ? startErrorText(e) : e instanceof Error ? e.message : String(e))
        }
      } finally {
        setStarting(false)
      }
    },
    [incidentId, reloadList],
  )

  const reloadDetail = detail.reload
  const cancel = useCallback(async () => {
    if (!selected) return
    setCancelling(true)
    setCancelError(undefined)
    try {
      const r = await apiPost<InvestigationStartResponse>(cancelPath(incidentId, selected))
      setStarted(r.investigation)
      reloadDetail()
      reloadList()
    } catch (e) {
      setCancelError(e instanceof ApiError ? cancelErrorText(e) : e instanceof Error ? e.message : String(e))
      reloadDetail()
    } finally {
      setCancelling(false)
    }
  }, [incidentId, selected, reloadDetail, reloadList])

  return {
    enabled,
    info,
    incidentId,
    runs,
    hidden: list.data?.hidden ?? 0,
    listLoaded: list.data !== undefined,
    selected,
    run,
    runError: run ? undefined : detail.error,
    select,
    start: (fresh) => void start(fresh),
    starting,
    error,
    cached: cached && run?.id === started?.id && run?.cachedFrom !== undefined,
    cancel: () => void cancel(),
    cancelling,
    cancelError,
    startedHere: run !== undefined && startedIds.has(run.id),
    announce,
    setAnnounce,
  }
}

/** The Investigate button and the data notice, beside Download in the page head. */
export function InvestigateButton({ s, onStarted }: { s: InvestigationsState; onStarted?: () => void }) {
  if (!s.enabled) return null
  const running = s.run?.status === 'running'
  const first = s.listLoaded && s.runs.length === 0 && !s.run
  const inv = s.info.investigator!
  const note = s.error ?? (first ? egressNotice(inv) : `${providerName(inv.provider)}, ${inv.model}. Suggested commands are never run.`)
  return (
    <div className="inc-download inv-start">
      <button
        type="button"
        className="btn primary"
        onClick={() => {
          s.start(false)
          onStarted?.()
        }}
        disabled={s.starting || running}
        aria-describedby="inv-start-note"
      >
        {s.starting ? 'Starting…' : running ? 'Investigating…' : s.runs.length > 0 || s.run ? 'Investigate again' : 'Investigate'}
      </button>
      <span id="inv-start-note" className={`small ${s.error ? 'inv-error' : 'muted'}`} aria-live="polite">
        {note}
      </span>
    </div>
  )
}

/** What the page does for an evidence ref or a timeline entry. */
export interface EvidenceActions {
  /** Highlight a lane item and move the crosshair to t. */
  lane: (key: string, t?: number) => void
  /** Narrow the log panel, select range when given, and scroll to it. */
  logs: (focus: LogFocus, range: Range | null) => void
  /** Select range on the charts and scroll to them. */
  charts: (range: Range) => void
}

export interface PanelProps {
  s: InvestigationsState
  /** The keys of the lane items on the page (mergeTimeline). */
  laneKeys: ReadonlySet<string>
  domain: Range
  actions: EvidenceActions
}

/** The investigation panel: progress while it runs, then the report; the incident's earlier runs below. */
export function InvestigationPanel({ s, laneKeys, domain, actions }: PanelProps) {
  if (!s.enabled) return null
  const hiddenText = hiddenRunsText(s.hidden)
  if (!s.run && !s.selected && !hiddenText && !s.error) return null
  return (
    <section className="inv" aria-labelledby="h-inv" id="investigation">
      <h2 id="h-inv">AI investigation</h2>
      <p className="sr-only" aria-live="polite" aria-atomic="true">
        {s.announce}
      </p>
      {s.run ? (
        <RunView s={s} run={s.run} laneKeys={laneKeys} domain={domain} actions={actions} />
      ) : s.selected ? (
        s.runError ? (
          <div className="notice crit" role="alert">
            <p>Could not load the investigation: {s.runError.message}</p>
          </div>
        ) : (
          <p className="muted">Loading the investigation…</p>
        )
      ) : null}
      <PastRuns s={s} hiddenText={hiddenText} />
    </section>
  )
}

function RunHead({ run, s }: { run: Run; s: InvestigationsState }) {
  const st = runStatus(run.status)
  const running = run.status === 'running'
  const now = useNow(1000, running)
  const elapsed = Math.max(0, Math.round((now - Date.parse(run.createdAt)) / 1000))
  return (
    <div className="inv-head">
      <span className={`al-state inv-state inv-state-${run.status}`}>
        <StatusGlyph status={st.glyph} decorative />
        {st.word}
      </span>
      <span className="muted small">
        {running ? `for ${elapsed < 120 ? `${elapsed} s` : `${Math.round(elapsed / 60)} min`} · ` : ''}
        started by {run.requestedBy} at {formatDateTime(run.createdAt)}
        {run.finishedAt && !running ? `, finished ${formatClock(Date.parse(run.finishedAt))}` : ''}
      </span>
      {canCancel(run, s.info.identity?.user, s.startedHere) && (
        <button type="button" className="btn inv-cancel" onClick={s.cancel} disabled={s.cancelling}>
          {s.cancelling ? 'Cancelling…' : 'Cancel investigation'}
        </button>
      )}
    </div>
  )
}

function RunView({ s, run, laneKeys, domain, actions }: { s: InvestigationsState; run: Run; laneKeys: ReadonlySet<string>; domain: Range; actions: EvidenceActions }) {
  const cached = run.cachedFrom ? cachedText(run, s.runs) : undefined
  const mayRunAgain = run.status !== 'running' && !s.starting
  const omitted = omittedRows(run.omitted)
  return (
    <div className="inv-run">
      <RunHead run={run} s={s} />
      {s.cancelError && (
        <p className="notice warn" role="status">
          {s.cancelError}
        </p>
      )}
      {cached && (
        <div className="notice inv-cached" role="status">
          <p>{cached}</p>
          {mayRunAgain && (
            <button type="button" className="btn" onClick={() => s.start(true)}>
              Run again
            </button>
          )}
          {mayRunAgain && <span className="muted small"> A new run calls the model and counts against your hourly limit.</span>}
        </div>
      )}
      {run.status === 'running' && <Steps run={run} live />}
      {run.status === 'refused' && (
        <div className="notice warn">
          <p>
            <strong>The model declined to investigate this incident</strong>
            {run.refusal?.category ? ` (category: ${run.refusal.category})` : ''}.
          </p>
          {run.refusal?.explanation && <p className="inv-text">{run.refusal.explanation}</p>}
          <p className="muted small">Claude's safety classifiers can decline content that resembles misuse, for example attack text quoted in a log line. The steps it took are below.</p>
        </div>
      )}
      {run.status === 'failed' && (
        <div className="notice crit">
          <p>
            <strong>The investigation failed.</strong> {failedText(run.error)}
          </p>
          {run.error && <p className="muted small">Reason recorded: {run.error}</p>}
        </div>
      )}
      {run.status === 'cancelled' && (
        <div className="notice">
          <p>
            Cancelled by {run.requestedBy} after {run.turns} {run.turns === 1 ? 'turn' : 'turns'}.
          </p>
        </div>
      )}
      {run.report && <Report run={run} laneKeys={laneKeys} domain={domain} actions={actions} setAnnounce={s.setAnnounce} />}
      {omitted.length > 0 && (
        <div className="inv-omitted small">
          <span className="muted">Left out of this investigation:</span>
          <ul className="plain">
            {omitted.map((o) => (
              <li key={o}>{o}</li>
            ))}
          </ul>
        </div>
      )}
      {run.status !== 'running' && (
        <details className="inv-steps-box">
          <summary>Steps ({run.steps.length})</summary>
          <Steps run={run} />
        </details>
      )}
      <p className="muted small inv-usage">
        {usageText(run)}. Model: {modelText(run)}.
      </p>
    </div>
  )
}

function Steps({ run, live = false }: { run: Run; live?: boolean }) {
  const steps = run.steps.map(stepView)
  return (
    <div className="inv-progress">
      {live && <p className="inv-working">{steps.length === 0 ? 'Reading the incident digest and asking the model…' : 'Working…'}</p>}
      {steps.length > 0 && (
        <ol className="inv-steps" aria-label="Investigation steps">
          {steps.map((st) => (
            <li key={st.key} className={`inv-step inv-step-${st.kind}`}>
              <StatusGlyph status={st.glyph} decorative />
              {!st.loud && <span className="sr-only">{st.word}: </span>}
              <span className="inv-step-text">{st.text}</span>
              {st.loud && <span className="tag">{st.word}</span>}
            </li>
          ))}
        </ol>
      )}
    </div>
  )
}

function ConfidenceMeter({ value }: { value: string }) {
  const c = confidence(value)
  if (!c) return null
  return (
    <span className="inv-conf">
      <svg viewBox="0 0 34 10" width="34" height="10" aria-hidden="true">
        {[0, 1, 2].map((i) => (
          <circle key={i} cx={5 + i * 12} cy="5" r="4" fill={i < c.dots ? 'currentColor' : 'none'} stroke="currentColor" strokeWidth="1.5" />
        ))}
      </svg>
      {c.word}
    </span>
  )
}

function Report({
  run,
  laneKeys,
  domain,
  actions,
  setAnnounce,
}: {
  run: Run
  laneKeys: ReadonlySet<string>
  domain: Range
  actions: EvidenceActions
  setAnnounce: (s: string) => void
}) {
  const r = run.report!
  const o = outcome(r.status)
  const ctx = useMemo<RefContext>(
    () => ({
      evidence: new Map((run.evidence ?? []).map((e) => [e.ref, e])),
      unverified: new Set(r.unverified ?? []),
      laneKeys,
      domain,
    }),
    [run.evidence, r.unverified, laneKeys, domain],
  )
  const [record, setRecord] = useState<InvestigationEvidence>()
  const refs = (list: string[]) => <Refs refs={list} ctx={ctx} actions={actions} openRecord={setRecord} setAnnounce={setAnnounce} />
  return (
    <div className="inv-report">
      <p className="inv-verdict">
        {o && (
          <span className="tag-glyph inv-outcome">
            <StatusGlyph status={o.glyph} decorative />
            <strong>{o.word}</strong>
          </span>
        )}
        <ConfidenceMeter value={r.root_cause.confidence} />
      </p>
      <p className="inv-summary inv-text">{r.summary}</p>
      {record && <RecordBox ev={record} onClose={() => setRecord(undefined)} />}

      <h3>Root cause</h3>
      <p className="inv-text">{r.root_cause.statement}</p>
      {refs(r.root_cause.evidence)}

      {r.contributing_factors.length > 0 && (
        <>
          <h3>Contributing factors</h3>
          <ul className="inv-list">
            {r.contributing_factors.map((f, i) => (
              <li key={i}>
                <span className="inv-text">{f.statement}</span>
                {refs(f.evidence)}
              </li>
            ))}
          </ul>
        </>
      )}

      {r.timeline.length > 0 && (
        <>
          <h3>Timeline</h3>
          <p className="muted small inv-hint">Choose a time to select two minutes either side of it on the charts, lanes and logs.</p>
          <ol className="inv-timeline">
            {r.timeline.map((e, i) => {
              const range = timelineRange(e.time, domain)
              const t = Date.parse(e.time)
              return (
                <li key={i}>
                  <button
                    type="button"
                    className="inv-when"
                    disabled={!range}
                    onClick={() => {
                      if (!range) return
                      actions.charts(range)
                      setAnnounce(`Selected ${formatDateTime(range[0])} to ${formatDateTime(range[1])} on the charts.`)
                    }}
                    title={Number.isFinite(t) ? formatDateTime(t) : e.time}
                  >
                    <time dateTime={e.time}>{Number.isFinite(t) ? formatClock(t) : e.time}</time>
                  </button>
                  <div className="inv-entry">
                    <span className="inv-text">{e.event}</span>
                    {refs(e.evidence)}
                  </div>
                </li>
              )
            })}
          </ol>
        </>
      )}

      {r.impact && (
        <>
          <h3>Impact</h3>
          <p className="inv-text">{r.impact}</p>
        </>
      )}

      {r.suggested_checks.length > 0 && (
        <>
          <h3>Suggested checks</h3>
          <ul className="inv-list inv-checks">
            {r.suggested_checks.map((c, i) => {
              const v = checkView(c)
              return (
                <li key={i}>
                  <span className="inv-text">{v.description}</span>
                  {v.command ? (
                    <>
                      <Command text={v.command} />
                      <span className="muted small">kubesentry does not run this; review before running.</span>
                    </>
                  ) : v.removed ? (
                    <span className="inv-removed small">
                      <StatusGlyph status="warn" decorative /> Command removed: it was not read-only.
                    </span>
                  ) : null}
                </li>
              )
            })}
          </ul>
        </>
      )}

      {r.remediation_ideas.length > 0 && (
        <>
          <h3>Remediation ideas</h3>
          <ul className="inv-list">
            {r.remediation_ideas.map((m, i) => (
              <li key={i}>
                <span className="inv-text">{m.description}</span>
                {m.risk && <span className="inv-risk small">Risk: {m.risk}</span>}
              </li>
            ))}
          </ul>
        </>
      )}

      <TextList title="Open questions" items={r.open_questions} />
      <TextList title="Data gaps" items={r.data_gaps} />

      {(r.unverified?.length ?? 0) > 0 && (
        <div className="notice warn inv-unverified">
          <p>
            The model cited {r.unverified!.length === 1 ? 'a ref it was never shown' : `${r.unverified!.length} refs it was never shown`}; claims resting on{' '}
            {r.unverified!.length === 1 ? 'it' : 'them'} are marked "not verified":
          </p>
          <ul className="plain">
            {r.unverified!.map((u) => (
              <li key={u} className="id">
                {u}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

function TextList({ title, items }: { title: string; items: string[] }) {
  if (items.length === 0) return null
  return (
    <>
      <h3>{title}</h3>
      <ul className="inv-list">
        {items.map((q, i) => (
          <li key={i} className="inv-text">
            {q}
          </li>
        ))}
      </ul>
    </>
  )
}

function Refs({
  refs,
  ctx,
  actions,
  openRecord,
  setAnnounce,
}: {
  refs: string[]
  ctx: RefContext
  actions: EvidenceActions
  openRecord: (e: InvestigationEvidence) => void
  setAnnounce: (s: string) => void
}) {
  if (refs.length === 0) return <p className="muted small inv-refs">No evidence cited.</p>
  return (
    <ul className="inv-refs" aria-label="Evidence">
      {refs.map((ref) => {
        const a = refAction(ref, ctx)
        const l = refLabel(ref, ctx.evidence.get(ref))
        if (a.kind === 'text') {
          return (
            <li key={ref}>
              <span className={`inv-ref inv-ref-${a.reason}`} title={l.title}>
                <span className="inv-ref-kind">{l.kind}</span> {l.text}
                {a.reason === 'unverified' && (
                  <span className="inv-nv">
                    <StatusGlyph status="warn" decorative /> not verified
                  </span>
                )}
              </span>
            </li>
          )
        }
        const go = () => {
          switch (a.kind) {
            case 'lane':
              actions.lane(a.key, a.t)
              setAnnounce(`Showing ${l.kind.toLowerCase()} ${l.text} in What happened.`)
              break
            case 'logs':
              actions.logs(a.focus, a.range)
              setAnnounce(`Showing the logs${a.focus.pod ? ` of ${a.focus.pod}` : ''}${a.range ? ` from ${formatClock(a.range[0])} to ${formatClock(a.range[1])}` : ''}.`)
              break
            case 'charts':
              actions.charts(a.range)
              setAnnounce(`Selected ${formatClock(a.range[0])} to ${formatClock(a.range[1])} on the charts.`)
              break
            case 'record':
              openRecord(a.evidence)
              if (a.key) actions.lane(a.key, a.t)
              setAnnounce(`Opened the ${l.kind} record.`)
              break
          }
        }
        return (
          <li key={ref}>
            <button type="button" className="inv-ref" onClick={go} title={l.title}>
              <span className="inv-ref-kind">{l.kind}</span> {l.text}
            </button>
          </li>
        )
      })}
    </ul>
  )
}

function RecordBox({ ev, onClose }: { ev: InvestigationEvidence; onClose: () => void }) {
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => ref.current?.focus(), [ev.ref])
  return (
    <div className="log-open inv-record" role="region" aria-label="Evidence record" tabIndex={-1} ref={ref}>
      <div className="log-open-head">
        <span className="id">
          {ev.kind}
          {ev.time ? ` · ${formatDateTime(ev.time)}` : ''}
          {ev.object ? ` · ${ev.object}` : ''}
        </span>
        <button type="button" className="linklike" onClick={onClose}>
          Close
        </button>
      </div>
      {ev.snippet && <pre>{ev.snippet}</pre>}
      <p className="muted small">As the investigator saw it: redacted, at most 300 characters.</p>
    </div>
  )
}

/** A command in a code box with Copy. Never run. */
function Command({ text }: { text: string }) {
  const [copied, setCopied] = useState<'yes' | 'no'>()
  useEffect(() => {
    if (!copied) return
    const id = setTimeout(() => setCopied(undefined), 2500)
    return () => clearTimeout(id)
  }, [copied])
  const copy = async () => {
    try {
      if (navigator.clipboard && window.isSecureContext) await navigator.clipboard.writeText(text)
      else {
        const ta = document.createElement('textarea')
        ta.value = text
        ta.setAttribute('readonly', '')
        ta.style.position = 'fixed'
        ta.style.opacity = '0'
        document.body.appendChild(ta)
        ta.select()
        const ok = document.execCommand('copy')
        ta.remove()
        if (!ok) throw new Error('copy refused')
      }
      setCopied('yes')
    } catch {
      setCopied('no')
    }
  }
  return (
    <div className="inv-cmd">
      <code>{text}</code>
      <button type="button" className="btn inv-copy" onClick={copy} aria-label={`Copy the command: ${text}`}>
        {copied === 'yes' ? 'Copied' : 'Copy'}
      </button>
      <span className="sr-only" aria-live="polite">
        {copied === 'yes' ? 'Copied.' : copied === 'no' ? 'Could not copy; select the command instead.' : ''}
      </span>
    </div>
  )
}

function PastRuns({ s, hiddenText }: { s: InvestigationsState; hiddenText?: string }): ReactNode {
  const others = s.runs.length > 1 || (s.runs.length === 1 && s.runs[0].id !== s.selected)
  if (!others && !hiddenText) return null
  return (
    <div className="inv-runs">
      <h3>Runs of this incident</h3>
      {s.runs.length > 0 && (
        <ul className="inv-run-list">
          {s.runs.map((r) => {
            const st = runStatus(r.status)
            const o = outcomeText(r)
            const on = r.id === s.selected
            return (
              <li key={r.id}>
                <button type="button" className={`inv-run-item${on ? ' on' : ''}`} aria-pressed={on} onClick={() => s.select(r.id)}>
                  <StatusGlyph status={st.glyph} decorative />
                  <span>
                    <strong>{st.word}</strong>
                    {o ? ` · ${o}` : ''}
                  </span>
                  <span className="muted small">{runByline(r)}</span>
                </button>
              </li>
            )
          })}
        </ul>
      )}
      {hiddenText && <p className="muted small">{hiddenText}</p>}
    </div>
  )
}
