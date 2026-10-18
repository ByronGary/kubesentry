import { useEffect, useMemo, useState } from 'react'
import { can, hiddenNote } from '../access'
import { ApiError, apiBlob } from '../api'
import { byteTicks, extent, rateTicks, sharedDomain, type Range } from '../chartMath'
import { EventLanes } from '../components/EventLane'
import { InvestigateButton, InvestigationPanel, useInvestigations, type EvidenceActions } from '../components/Investigation'
import { LogPanel } from '../components/LogPanel'
import { SignalMark } from '../components/SignalMark'
import { TimeChart } from '../components/TimeChart'
import { Async, Empty, PageHead, StatusGlyph } from '../components/ui'
import { ago, formatBytes, formatDateTime, formatPercent, formatRate, plural } from '../format'
import {
  alertLinks,
  bundlePath,
  chartLines,
  chartMarks,
  chartThresholds,
  incidentDomain,
  incidentDuration,
  incidentHref,
  incidentPath,
  logSources,
  mergeTimeline,
  paddingText,
  rangeQuery,
  readRange,
  sectionAccess,
  severityGlyph,
  SEVERITY_WORD,
  shortSpan,
  sourceRows,
  sourceUp,
  spikeSpans,
  subjectText,
  tagChips,
  typeChips,
  windowRange,
  type Lane,
} from '../incidents'
import { setQuery, type Route } from '../router'
import type { IncidentBundleHeader, IncidentDetail as Detail, IncidentSeries, Info } from '../types'
import { useApi } from '../useApi'

const byteAxis = (m: number) => byteTicks(m, 4)
const rateAxis = (m: number) => rateTicks(m, 4)

/** One incident: what happened, on one time axis, with the logs written around it. */
export function IncidentDetail({ id, route, info }: { id: string; route: Route; info: Info }) {
  const [resolved, setResolved] = useState(false)
  // Open incidents keep changing: refresh them; resolved ones do not.
  const state = useApi<Detail>(incidentPath(id), resolved ? undefined : 30_000, { retryBusy: true })
  const st = state.data?.incident.state
  useEffect(() => setResolved(st === 'resolved'), [st])
  const notFound = state.error instanceof ApiError && state.error.status === 404

  return (
    <>
      <nav className="crumbs" aria-label="Breadcrumb">
        <a href="#/incidents">Incidents</a>
      </nav>
      {notFound ? (
        <>
          <PageHead title="Incident not found" />
          <Empty title="No incident with this ID that you can see">
            It may be older than the server keeps incidents, or about a namespace you cannot see. <a href="#/incidents">See the incidents list</a>.
          </Empty>
        </>
      ) : (
        <Async state={state} what="the incident" busy="kubesentry is busy">
          {(d) => <Body d={d} id={id} route={route} info={info} />}
        </Async>
      )}
    </>
  )
}

function Body({ d, id, route, info }: { d: Detail; id: string; route: Route; info: Info }) {
  const inc = d.incident
  const [hoverT, setHoverT] = useState<number | null>(null)
  const win = windowRange(d.window)
  const items = useMemo(() => mergeTimeline(d), [d])
  // The padded window, reaching back to a deploy or change the lookbehind attached; else the data's extent.
  const domain = useMemo<Range>(
    () =>
      incidentDomain(windowRange(d.window), items) ??
      sharedDomain(undefined, (d.series ?? []).map((s) => extent(s.points))) ?? [Date.parse(inc.start) - 300_000, Date.now()],
    [d.window, d.series, inc.start, items],
  )
  const brush = readRange(route.query, domain)
  const setBrush = (r: Range | null) => setQuery(`/incidents/${encodeURIComponent(id)}`, rangeQuery(r))
  const marks = useMemo(() => chartMarks(items), [items])
  const inv = useInvestigations(id, info)
  const laneKeys = useMemo(() => new Set(items.map((i) => i.key)), [items])
  // Evidence the investigation points at: a lane item, the logs or the charts.
  const [laneFocus, setLaneFocus] = useState<{ key: string; n: number }>()
  const [logFocus, setLogFocus] = useState<{ pod?: string; container?: string; q?: string; n: number }>()
  const scrollTo = (elId: string) => requestAnimationFrame(() => document.getElementById(elId)?.scrollIntoView({ behavior: 'smooth', block: 'start' }))
  const actions: EvidenceActions = {
    lane: (key, t) => {
      setLaneFocus((f) => ({ key, n: (f?.n ?? 0) + 1 }))
      if (t !== undefined) setHoverT(t)
    },
    logs: (focus, range) => {
      setLogFocus((f) => ({ ...focus, n: (f?.n ?? 0) + 1 }))
      setBrush(range)
      scrollTo('h-logs')
    },
    charts: (range) => {
      setBrush(range)
      setHoverT((range[0] + range[1]) / 2)
      scrollTo('h-metrics')
    },
  }
  const access = sectionAccess(d.sources, { audit: can(info, 'audit'), cloudtrail: can(info, 'cloudtrail'), podLogs: can(info, 'podLogs') })
  const sev = severityGlyph(inc.severity)
  const peak = severityGlyph(inc.peakSeverity)
  const tags = tagChips(inc.tags)
  const chips = typeChips(inc)
  const alerts = alertLinks(d.signals)
  const pad = paddingText(inc, win, info.incidents)
  const sources = sourceRows(d.sources)

  const hidden: Partial<Record<Lane, string>> = {}
  if (access.audit === 'forbidden') hidden.audit = 'Changes people made are hidden: your access does not include the audit log for this incident.'
  if (access.cloudtrail === 'forbidden') hidden.cloudtrail = hiddenNote('cloudtrail')
  const absent: Partial<Record<Lane, string>> = {}
  if (access.audit === 'absent') absent.audit = 'This server does not receive the API server audit log.'
  if (access.cloudtrail === 'absent') absent.cloudtrail = 'CloudTrail is not read on this server (-cloudtrail).'

  const chart = (metric: IncidentSeries['metric']) => ({
    lines: chartLines(d.series, metric),
    spans: spikeSpans(d.signals, metric, domain[1]),
    thresholds: chartThresholds(d.thresholds, metric).map((t) => ({ label: 'threshold', value: t.value, title: `${t.label}: spike threshold` })),
  })
  const mem = chart('memory')
  const req = chart('requests')
  const errs = chart('errors')
  const noCharts = mem.lines.length + req.lines.length + errs.lines.length === 0
  const seriesState = d.sources?.series

  const shared = { domain, markers: marks, hoverT, onHover: setHoverT, brush, onBrush: setBrush, breakGaps: true }

  return (
    <>
      <PageHead title={inc.title} lede={<span className="id">{subjectText(inc.subject)}</span>}>
        <div className="inc-actions">
          <InvestigateButton s={inv} onStarted={() => scrollTo('investigation')} />
          <Download id={id} />
        </div>
      </PageHead>
      <p className={`verdict verdict-${sev}`}>
        <StatusGlyph status={sev} label={false} />
        <span>
          <strong>{SEVERITY_WORD[inc.severity] ?? inc.severity}</strong>
          {inc.peakSeverity !== inc.severity && <> (reached {SEVERITY_WORD[inc.peakSeverity]?.toLowerCase() ?? inc.peakSeverity})</>},{' '}
          {inc.state === 'open' ? `open for ${incidentDuration(inc)}` : `resolved after ${incidentDuration(inc)}`}. Started {formatDateTime(inc.start)} ({ago(inc.start)})
          {inc.end ? `, ended ${formatDateTime(inc.end)}` : `, latest signal ${ago(inc.lastSignal)}`}.
        </span>
      </p>
      {(d.warnings ?? []).map((w) => (
        <div className="notice warn" key={w}>
          {w}
        </div>
      ))}

      <dl className="inc-facts">
        <div>
          <dt>Severity</dt>
          <dd>
            <StatusGlyph status={sev} />
            {peak !== sev && (
              <span className="muted">
                {' '}
                · peak <StatusGlyph status={peak} />
              </span>
            )}
          </dd>
        </div>
        <div>
          <dt>State</dt>
          <dd>
            {inc.state === 'open' ? 'Open' : 'Resolved'}
            {inc.capped && <span className="muted"> · closed at the 24-hour cap; it continues in a newer incident</span>}
            {inc.previous && (
              <>
                {' '}
                · continues <a href={incidentHref(inc.previous)}>an earlier incident</a>
              </>
            )}
          </dd>
        </div>
        {inc.owner && (
          <div>
            <dt>Owner</dt>
            <dd>
              <a href={`#/incidents?${new URLSearchParams({ owner: inc.owner })}`}>{inc.owner}</a>
              {inc.production && <span className="tag tag-crit tag-after">production</span>}
            </dd>
          </div>
        )}
        {!inc.owner && inc.production && (
          <div>
            <dt>Environment</dt>
            <dd>
              <span className="tag tag-crit">production</span>
            </dd>
          </div>
        )}
        {tags.length > 0 && (
          <div className="wide">
            <dt>Tags</dt>
            <dd className="inc-chips">
              {tags.map((t) =>
                t.filter ? (
                  <a key={t.key} className="tag" href={`#/incidents?${new URLSearchParams(Object.entries(t.filter) as [string, string][])}`} title={`Incidents with ${t.name} ${t.value}`}>
                    {t.name} {t.value}
                  </a>
                ) : (
                  <span key={t.key} className="tag">
                    {t.name} {t.value}
                  </span>
                ),
              )}
            </dd>
          </div>
        )}
        <div className="wide">
          <dt>Signals</dt>
          <dd className="inc-chips">
            {chips.map((c) => (
              <span key={c.type} className={`tag tag-glyph${c.trigger ? ' tag-trigger' : ''}`}>
                <SignalMark shape={c.shape} />
                {c.label}
                {c.count > 1 && <span className="muted"> ×{c.count}</span>}
              </span>
            ))}
          </dd>
        </div>
        {(inc.pods?.length ?? 0) > 0 && (
          <div className="wide">
            <dt>Pods</dt>
            <dd className="inc-chips">
              {inc.pods!.slice(0, 12).map((p) =>
                inc.subject.namespace ? (
                  <a key={p} className="id inc-link" href={`#/pods/${encodeURIComponent(inc.subject.namespace)}/${encodeURIComponent(p)}`}>
                    {p}
                  </a>
                ) : (
                  <span key={p} className="id">
                    {p}
                  </span>
                ),
              )}
              {inc.pods!.length > 12 && <span className="muted">and {inc.pods!.length - 12} more</span>}
            </dd>
          </div>
        )}
        {((inc.services?.length ?? 0) > 0 || (inc.nodes?.length ?? 0) > 0) && (
          <div className="wide">
            <dt>Services and nodes</dt>
            <dd className="inc-chips">
              {(inc.services ?? []).map((s) => (
                <span key={`s:${s}`} className="id">
                  {s}
                </span>
              ))}
              {(inc.nodes ?? []).map((n) => (
                <a key={`n:${n}`} className="id inc-link" href={`#/nodes?${new URLSearchParams({ node: n })}`}>
                  {n}
                </a>
              ))}
            </dd>
          </div>
        )}
        {alerts.length > 0 && (
          <div className="wide">
            <dt>Alerts</dt>
            <dd>
              <ul className="plain inc-related">
                {alerts.map((l) => (
                  <li key={l.key}>
                    <StatusGlyph status={l.severity} label={false} /> <a href={l.href}>{l.title}</a>{' '}
                    <span className="muted small">{l.ongoing ? 'still open' : 'ended'}</span>
                  </li>
                ))}
              </ul>
            </dd>
          </div>
        )}
        {d.related.length > 0 && (
          <div className="wide">
            <dt>Related</dt>
            <dd>
              <ul className="plain inc-related">
                {d.related.map((r) => (
                  <li key={r.id}>
                    <StatusGlyph status={severityGlyph(r.severity)} label={false} /> <a href={incidentHref(r.id)}>{r.title}</a>{' '}
                    <span className="muted small">
                      {r.state}, started {ago(r.start)}
                    </span>
                  </li>
                ))}
              </ul>
            </dd>
          </div>
        )}
      </dl>
      {sources.length > 0 && (
        <details className="inc-sources">
          <summary>
            Sources: {sources.filter((s) => s.status === 'ok').length} of {sources.length} answering
            {sources.some((s) => s.status === 'warn') && ', some with errors'}
          </summary>
          <ul className="plain">
            {sources.map((s) => (
              <li key={s.key}>
                <StatusGlyph status={s.status} label={false} /> {s.label}: <span className="muted">{s.text}</span>
              </li>
            ))}
          </ul>
        </details>
      )}

      <InvestigationPanel s={inv} laneKeys={laneKeys} domain={domain} actions={actions} />

      <div className="inc-window" role="status">
        <p>
          {win ? (
            <>
              Logs and events are read from {formatDateTime(win[0])} to {formatDateTime(win[1])}. {pad}
              {domain[0] < win[0] && ` The time axis starts at ${formatDateTime(domain[0])} to show changes attached from before.`}
            </>
          ) : (
            <>
              Time axis {formatDateTime(domain[0])} to {formatDateTime(domain[1])}. {pad}
            </>
          )}
        </p>
        {brush ? (
          <p>
            <strong>
              Selected {formatDateTime(brush[0])} to {formatDateTime(brush[1])}
            </strong>{' '}
            ({shortSpan(brush[1] - brush[0])}): the logs show this range and the lanes list what falls in it.{' '}
            <button type="button" className="linklike" onClick={() => setBrush(null)}>
              Clear the selection
            </button>
          </p>
        ) : (
          <p className="muted small">Drag across a chart, a lane or the log strip to narrow the logs to a time; or focus one and press Shift with an arrow key, then Enter.</p>
        )}
      </div>

      <section aria-labelledby="h-metrics">
        <h2 id="h-metrics">Metrics</h2>
        {noCharts ? (
          <p className="muted">
            {seriesState === 'absent'
              ? 'No metrics source is set up, so there are no charts: kubesentry draws memory and request rates from Prometheus.'
              : seriesState?.startsWith('error')
                ? `The metric series could not be read: ${seriesState.replace(/^error:?\s*/, '')}.`
                : 'No metric samples for this workload in the window.'}
          </p>
        ) : (
          <div className="inc-charts">
            {mem.lines.length > 0 && (
              <TimeChart
                title={mem.lines.length === 1 ? `Memory (working set) of ${mem.lines[0].label}` : 'Memory (working set)'}
                summary={`Working-set memory of ${plural(mem.lines.length, 'one container', `${mem.lines.length} containers`)} around the incident.`}
                lines={mem.lines}
                format={formatBytes}
                ticks={byteAxis}
                thresholds={mem.thresholds}
                spans={mem.spans}
                {...shared}
              />
            )}
            {req.lines.length > 0 && (
              <TimeChart
                title={req.lines.length === 1 ? `Requests to ${req.lines[0].label}` : 'Requests'}
                summary="Request rate around the incident." lines={req.lines} format={formatRate} ticks={rateAxis} thresholds={req.thresholds} spans={req.spans} height={170} {...shared} />
            )}
            {errs.lines.length > 0 && (
              <TimeChart
                title={errs.lines.length === 1 ? `Error rate (5xx share) of ${errs.lines[0].label}` : 'Error rate (5xx share)'}
                summary="Share of requests that failed around the incident." lines={errs.lines} format={formatPercent} ticks={rateAxis} thresholds={errs.thresholds} spans={errs.spans} height={150} {...shared} />
            )}
            {req.lines.length === 0 && (
              <p className="muted small">
                {sourceUp(d.sources, 'requests') === false || sourceUp(d.sources, 'requests') === undefined
                  ? 'No request-rate source answers (ingress-nginx, app metrics or the ALB), so there is no request chart.'
                  : 'No request samples for this workload in the window.'}
              </p>
            )}
            <p className="chart-note">Markers above the charts: ✕ OOM kill, ↻ restart, ◆ deploy or scale, ▲ Kubernetes event. Shaded bands are the spikes.</p>
          </div>
        )}
      </section>

      <section aria-labelledby="h-lanes">
        <h2 id="h-lanes">What happened</h2>
        <EventLanes items={items} domain={domain} hoverT={hoverT} onHover={setHoverT} brush={brush} onBrush={setBrush} hidden={hidden} absent={absent} focus={laneFocus} />
      </section>

      <section aria-labelledby="h-logs">
        <h2 id="h-logs">Logs</h2>
        <LogPanel id={id} domain={domain} range={brush} pods={inc.pods ?? []} access={access.logs} sources={logSources(d.sources)} hoverT={hoverT} onHover={setHoverT} onBrush={setBrush} focus={logFocus} />
      </section>
    </>
  )
}

/** Download the incident bundle (NDJSON) with the user's credentials, then say what it left out. */
function Download({ id }: { id: string }) {
  const [s, setS] = useState<{ busy?: boolean; error?: string; note?: string }>({})
  const run = async () => {
    setS({ busy: true })
    try {
      const { blob, filename } = await apiBlob(bundlePath(id))
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = filename ?? `incident-${id}.ndjson`
      document.body.appendChild(a)
      a.click()
      a.remove()
      setTimeout(() => URL.revokeObjectURL(url), 2000)
      let note = 'Downloaded.'
      try {
        const head = JSON.parse((await blob.slice(0, 256 * 1024).text()).split('\n')[0]) as IncidentBundleHeader
        const left = Object.entries(head.omitted ?? {}).map(([k, v]) => `${k} (${v})`)
        const cut = Object.entries(head.truncated ?? {})
          .filter(([, v]) => v)
          .map(([k]) => k)
        if (left.length) note += ` Left out: ${left.join(', ')}.`
        if (cut.length) note += ` Cut short at the size caps: ${cut.join(', ')}.`
      } catch {
        /* not NDJSON with a header: say nothing more */
      }
      setS({ note })
    } catch (e) {
      setS({ error: e instanceof Error ? e.message : String(e) })
    }
  }
  return (
    <div className="inc-download">
      <button type="button" className="btn" onClick={run} disabled={s.busy}>
        {s.busy ? 'Preparing…' : 'Download bundle'}
      </button>
      <span className="muted small" aria-live="polite">
        {s.error ? `Could not download: ${s.error}` : (s.note ?? 'NDJSON, for tools and agents')}
      </span>
    </div>
  )
}
