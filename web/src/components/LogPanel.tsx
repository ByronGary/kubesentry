import { useId, useMemo, useState } from 'react'
import { hiddenNote } from '../access'
import { ApiError } from '../api'
import type { Range } from '../chartMath'
import { formatDateTime } from '../format'
import { levelGlyph, LEVELS, logsPath, logVolume, normalLevel, type Access, type LogLevel, type LogSource } from '../incidents'
import type { IncidentLogLine, IncidentLogsResponse } from '../types'
import { useApi, useDebounced } from '../useApi'
import { Segmented, StatusGlyph, Unauthorized } from './ui'
import { useWidth } from './TimeChart'
import { TimeStrip } from './TimeStrip'
import { Lines, VirtualTable, type Column } from './VirtualTable'

const clockSeconds = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' })

interface Row extends IncidentLogLine {
  i: number
  t: number
}

const SOURCE_LABEL: Record<LogSource, string> = { auto: 'Auto', kubernetes: 'Kubernetes', cloudwatch: 'CloudWatch' }

export interface LogPanelProps {
  id: string
  domain: Range
  /** The brushed range; the whole padded window without one. */
  range: Range | null
  pods: string[]
  /** This caller's access to this incident's logs. */
  access: Access
  /** Which named sources the switch may ask for. */
  sources: { kubernetes: boolean; cloudwatch: boolean }
  hoverT: number | null
  onHover: (t: number | null) => void
  onBrush?: (r: Range | null) => void
}

/**
 * The incident's logs, fetched when viewed and never stored: a volume strip
 * on the shared time axis, then the lines. Level, search, pod, container and
 * source narrow them; the brush narrows the time.
 */
export function LogPanel(p: LogPanelProps) {
  const [level, setLevel] = useState<LogLevel>('')
  const [text, setText] = useState('')
  const q = useDebounced(text.trim(), 350)
  const [pod, setPod] = useState('')
  const [container, setContainer] = useState('')
  const [source, setSource] = useState<LogSource>('auto')
  const [open, setOpen] = useState<Row | null>(null)
  const [wrap, w] = useWidth()
  const hatch = `hatch-${useId().replace(/[^a-zA-Z0-9_-]/g, '')}`

  const path = p.access === 'ok' ? logsPath(p.id, { from: p.range?.[0], to: p.range?.[1], pod, container, level, q, source }) : null
  const state = useApi<IncidentLogsResponse>(path)
  const data = state.data
  // Sources interleave pods; oldest first reads as one story.
  const rows = useMemo<Row[]>(
    () =>
      (data?.lines ?? [])
        .map((l, i) => ({ ...l, i, t: Date.parse(l.time) }))
        .sort((a, b) => (Number.isFinite(a.t) && Number.isFinite(b.t) ? a.t - b.t : 0) || a.i - b.i),
    [data],
  )
  const containers = useMemo(() => [...new Set([...rows.map((r) => r.container).filter(Boolean), ...(container ? [container] : [])])].sort(), [rows, container])
  const span = p.range ?? p.domain
  const volume = useMemo(() => logVolume(rows, p.domain, Math.max(12, Math.min(120, Math.floor(w / 9)))), [rows, p.domain, w])
  const keys = useMemo(() => [...new Set(rows.map((r) => r.t).filter(Number.isFinite))].sort((a, b) => a - b), [rows])

  if (p.access === 'forbidden') return <p className="notice">{hiddenNote('podLogs')}</p>
  if (p.access === 'absent') {
    return <p className="muted">No log source is set up on this server: kubesentry reads pod logs or CloudWatch Logs when they are.</p>
  }

  const err = state.error
  const columns: Column<Row>[] = [
    { key: 'time', header: 'Time', width: 116, title: (r) => formatDateTime(r.time), cell: (r) => (Number.isFinite(r.t) ? clockSeconds.format(r.t) : '-') },
    {
      key: 'level',
      header: 'Level',
      width: 86,
      cell: (r) => {
        const g = levelGlyph(r.level)
        const word = normalLevel(r.level) || r.level || '-'
        return g ? (
          <span className="tag-glyph">
            <StatusGlyph status={g} decorative />
            {word}
          </span>
        ) : (
          <span className="muted">{word}</span>
        )
      },
    },
    {
      key: 'text',
      header: 'Line',
      width: 'auto',
      title: (r) => r.text,
      cell: (r) => (
        <Lines
          main={
            <button type="button" className="linklike log-text" onClick={() => setOpen(r)} onFocus={() => Number.isFinite(r.t) && p.onHover(r.t)} onMouseEnter={() => Number.isFinite(r.t) && p.onHover(r.t)}>
              {r.text}
            </button>
          }
          sub={
            <span className="id">
              {r.pod}
              {r.container ? ` · ${r.container}` : ''}
              {r.source ? ` · ${r.source}` : ''}
            </span>
          }
        />
      ),
    },
  ]

  return (
    <div className="logs" ref={wrap}>
      <div className="filters log-filters">
        <div className="filter-group">
          <span className="filter-label">Level</span>
          <Segmented label="Lowest level" value={level} options={LEVELS} onChange={setLevel} />
        </div>
        <label>
          Search
          <input type="search" value={text} onChange={(e) => setText(e.target.value)} placeholder="text in the line" maxLength={256} />
        </label>
        {p.pods.length > 0 && (
          <label>
            Pod
            <select value={pod} onChange={(e) => setPod(e.target.value)}>
              <option value="">All pods</option>
              {[...new Set([...p.pods, ...(pod ? [pod] : [])])].map((n) => (
                <option key={n}>{n}</option>
              ))}
            </select>
          </label>
        )}
        <label>
          Container
          <select value={container} onChange={(e) => setContainer(e.target.value)}>
            <option value="">All containers</option>
            {containers.map((n) => (
              <option key={n}>{n}</option>
            ))}
          </select>
        </label>
        <div className="filter-group">
          <span className="filter-label">Source</span>
          <Segmented
            label="Log source"
            value={source}
            onChange={setSource}
            options={(['auto', 'kubernetes', 'cloudwatch'] as LogSource[]).map((s) => ({
              value: s,
              label: SOURCE_LABEL[s],
              disabled: s !== 'auto' && !p.sources[s],
              reason: s === 'kubernetes' ? 'Pod logs are not read on this server.' : s === 'cloudwatch' ? 'CloudWatch Logs are not set up on this server.' : undefined,
            }))}
          />
        </div>
      </div>

      {err instanceof ApiError && err.status === 401 ? (
        <Unauthorized error={err} />
      ) : err instanceof ApiError && err.status === 403 ? (
        <p className="notice">{hiddenNote('podLogs')}</p>
      ) : err instanceof ApiError && err.status === 404 ? (
        <div className="notice warn">
          <p>These logs are gone from the cluster: {err.message || 'the pod no longer exists'}.</p>
          {p.sources.cloudwatch && source !== 'cloudwatch' ? (
            <button type="button" className="btn" onClick={() => setSource('cloudwatch')}>
              Read them from CloudWatch
            </button>
          ) : (
            <p className="muted small">A deleted pod's lines are kept only where a log shipper sent them, such as CloudWatch Logs.</p>
          )}
        </div>
      ) : err && !data ? (
        <div className="notice crit" role="alert">
          <p>Could not load logs: {err.message}</p>
          {err instanceof ApiError && err.status === 400 && source !== 'auto' ? (
            <button type="button" className="btn" onClick={() => setSource('auto')}>
              Use the default source
            </button>
          ) : (
            <button type="button" className="btn" onClick={state.reload}>
              Try again
            </button>
          )}
        </div>
      ) : !data ? (
        <p className="muted" aria-live="polite">
          Loading logs…
        </p>
      ) : (
        <div className={state.loading ? 'refetching' : undefined} aria-busy={state.loading}>
          <p className="list-status">
            <span aria-live="polite">
              {rows.length.toLocaleString('en-US')} {rows.length === 1 ? 'line' : 'lines'}
              {data.source ? ` from ${SOURCE_LABEL[data.source as LogSource] ?? data.source}` : ''}, {formatDateTime(span[0])} to {formatDateTime(span[1])}
              {p.range ? ' (the selection)' : ''}
            </span>
            <button type="button" className="linklike" onClick={state.reload} disabled={state.loading}>
              {state.loading ? 'Refreshing…' : 'Refresh'}
            </button>
          </p>
          {data.truncated && (
            <p className="notice warn small-notice">Only the first {rows.length.toLocaleString('en-US')} lines are shown. Select a shorter time on a chart, or narrow the level or search, to see the rest.</p>
          )}
          {(data.warnings ?? []).map((m) => (
            <p className="notice warn small-notice" key={m}>
              {m}
            </p>
          ))}
          {rows.length > 0 && (
            <>
              <TimeStrip
                width={w}
                height={34}
                domain={p.domain}
                label={`Log lines over time: ${rows.length} lines, ${volume.errors.reduce((a, b) => a + b, 0)} errors`}
                keys={keys}
                hoverT={p.hoverT}
                onHover={p.onHover}
                brush={p.range}
                onBrush={p.onBrush}
              >
                {(s) => {
                  const n = volume.all.length
                  const bw = (s.right - s.left) / n
                  const h = s.height - 2
                  return (
                    <g>
                      <defs>
                        <pattern id={hatch} width="4" height="4" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
                          <rect className="vol-hatch-bg" width="4" height="4" />
                          <line className="vol-hatch" x1="0" y1="0" x2="0" y2="4" />
                        </pattern>
                      </defs>
                      {volume.all.map((c, i) => {
                        if (!c) return null
                        const e = volume.errors[i]
                        const hAll = Math.max(2, (c / volume.max) * h)
                        const hErr = e ? Math.max(2, (e / volume.max) * h) : 0
                        const x = s.left + i * bw + 0.5
                        return (
                          <g key={i}>
                            <rect className="vol" x={x} y={s.height - 1 - hAll} width={Math.max(1, bw - 1)} height={hAll} />
                            {hErr > 0 && <rect className="vol-err" fill={`url(#${hatch})`} x={x} y={s.height - 1 - hErr} width={Math.max(1, bw - 1)} height={hErr} />}
                          </g>
                        )
                      })}
                    </g>
                  )
                }}
              </TimeStrip>
              <p className="vol-legend muted small">
                <span className="vol-key" aria-hidden="true" /> lines <span className="vol-key err" aria-hidden="true" /> errors (hatched), on the charts' time axis
              </p>
            </>
          )}
          {rows.length === 0 ? (
            <p className="muted">No log lines match{q || level || pod || container ? ' these filters' : ' in this window'}.</p>
          ) : (
            <VirtualTable rows={rows} columns={columns} rowKey={(r) => String(r.i)} caption="Log lines, oldest first" rowHeight={46} minWidth={560} rowClass={(r) => (normalLevel(r.level) === 'error' ? 'row-err' : normalLevel(r.level) === 'warn' ? 'row-warn' : undefined)} resetKey={path ?? ''} />
          )}
          {open && (
            <div className="log-open" role="region" aria-label="Selected log line">
              <div className="log-open-head">
                <span className="id">
                  {formatDateTime(open.time)} · {open.pod}
                  {open.container ? ` · ${open.container}` : ''}
                </span>
                <button type="button" className="linklike" onClick={() => setOpen(null)}>
                  Close
                </button>
              </div>
              <pre>{open.text}</pre>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
