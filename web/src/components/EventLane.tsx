import { useEffect, useRef, useState, type KeyboardEvent } from 'react'
import type { Range } from '../chartMath'
import { formatClock, formatDateTime } from '../format'
import { inRange, laneItems, LANES, type Lane, type TimelineItem } from '../incidents'
import { ShapePath, SignalMark } from './SignalMark'
import { useWidth } from './TimeChart'
import { TimeStrip } from './TimeStrip'

/** Items listed per lane before "Show all". */
const FIRST = 5

export interface LaneProps {
  items: TimelineItem[]
  domain: Range
  hoverT: number | null
  onHover: (t: number | null) => void
  brush: Range | null
  onBrush?: (r: Range | null) => void
  /** Lanes this caller may not see for this incident, with the reason. */
  hidden?: Partial<Record<Lane, string>>
  /** Lanes whose source is not set up, with a note. */
  absent?: Partial<Record<Lane, string>>
  /** An item to list, highlight, scroll to and focus (an investigation's evidence); n changes on every request. */
  focus?: { key: string; n: number }
}

/**
 * What happened around the incident, one lane per kind (spikes, restarts,
 * Kubernetes events, deploys, alerts, audit, CloudTrail) on the charts' time
 * axis. Each lane is a strip of shapes and a list of the same items, which
 * the keyboard reaches; focusing an item moves the shared crosshair to it.
 * With a brush, items inside it are listed and the rest are dimmed.
 */
export function EventLanes(p: LaneProps) {
  const [wrap, w] = useWidth()
  const lanes = LANES.filter((l) => p.hidden?.[l.key] || p.absent?.[l.key] || laneItems(p.items, l.key).length > 0)
  return (
    <div className="lanes" ref={wrap}>
      {lanes.length === 0 ? (
        <p className="muted">No events, changes or alerts in this window.</p>
      ) : (
        lanes.map((l) => {
          const note = p.hidden?.[l.key] ?? (laneItems(p.items, l.key).length === 0 ? p.absent?.[l.key] : undefined)
          if (note) {
            return (
              <section className="lane" key={l.key} aria-label={l.label}>
                <div className="lane-head">
                  <h3>{l.label}</h3>
                </div>
                <p className="muted small lane-note">{note}</p>
              </section>
            )
          }
          return <LaneRow key={l.key} lane={l.key} label={l.label} width={w} {...p} />
        })
      )}
    </div>
  )
}

function LaneRow({ lane, label, width, items: all, domain, hoverT, onHover, brush, onBrush, focus }: LaneProps & { lane: Lane; label: string; width: number }) {
  const [showAll, setShowAll] = useState(false)
  const [showOutside, setShowOutside] = useState(false)
  const items = laneItems(all, lane)
  const listRef = useRef<HTMLOListElement>(null)
  const target = focus ? items.find((i) => i.key === focus.key) : undefined
  const [jump, setJump] = useState(0)
  // List the item (all of the lane, and outside the selection), then scroll to it and focus it.
  useEffect(() => {
    if (!target) return
    setShowAll(true)
    if (brush && !inRange(target, brush)) setShowOutside(true)
    setJump((n) => n + 1)
  }, [focus?.n])
  useEffect(() => {
    if (!jump || !target) return
    const b = [...(listRef.current?.querySelectorAll<HTMLButtonElement>('button.lane-item') ?? [])].find((x) => x.dataset.key === target.key)
    b?.scrollIntoView({ block: 'center', behavior: 'smooth' })
    b?.focus({ preventScroll: true })
  }, [jump])
  const inside = brush ? items.filter((i) => inRange(i, brush)) : items
  const listed = brush && !showOutside ? inside : items
  const shown = showAll ? listed : listed.slice(0, FIRST)
  const id = `lane-${lane}`
  const keys = [...new Set(items.map((i) => i.t))].sort((a, b) => a - b)

  const move = (e: KeyboardEvent<HTMLButtonElement>) => {
    const list = e.currentTarget.closest('ol')
    if (!list) return
    const buttons = [...list.querySelectorAll<HTMLButtonElement>('button.lane-item')]
    const i = buttons.indexOf(e.currentTarget)
    const next = e.key === 'ArrowDown' ? i + 1 : e.key === 'ArrowUp' ? i - 1 : e.key === 'Home' ? 0 : e.key === 'End' ? buttons.length - 1 : undefined
    if (next === undefined) return
    e.preventDefault()
    buttons[Math.max(0, Math.min(buttons.length - 1, next))]?.focus()
  }

  return (
    <section className="lane" aria-labelledby={id}>
      <div className="lane-head">
        <h3 id={id}>{label}</h3>
        <span className="muted small">
          {items.length.toLocaleString('en-US')}
          {brush ? `, ${inside.length.toLocaleString('en-US')} in the selection` : ''}
        </span>
      </div>
      <TimeStrip
        width={width}
        domain={domain}
        label={`${label}: ${items.length} on the time axis`}
        keys={keys}
        hoverT={hoverT}
        onHover={onHover}
        brush={brush}
        onBrush={onBrush}
      >
        {(s) => (
          <g>
            {items.map((i) => {
              const dim = brush && !inRange(i, brush)
              const x0 = Math.max(s.left, Math.min(s.right, s.x(i.t)))
              const end = i.ongoing ? domain[1] : i.end
              const x1 = end !== undefined ? Math.max(x0, Math.min(s.right, s.x(end))) : undefined
              return (
                <g key={i.key} className={`lane-mark sev-${i.severity ?? 'none'}${dim ? ' dim' : ''}`}>
                  {x1 !== undefined && x1 - x0 > 1 && <rect className="lane-span" x={x0} y={s.height / 2 - 2} width={x1 - x0} height={4} rx={2} />}
                  <g transform={`translate(${x0.toFixed(1)},${s.height / 2})`}>
                    <ShapePath shape={i.shape} r={5} />
                  </g>
                  <title>{`${formatClock(i.t)} ${i.title}${i.detail ? ` (${i.detail})` : ''}`}</title>
                </g>
              )
            })}
          </g>
        )}
      </TimeStrip>
      {shown.length > 0 ? (
        <ol className="lane-items" ref={listRef}>
          {shown.map((i) => (
            <li key={i.key} className={i.href ? 'lane-linked' : undefined}>
              <button
                type="button"
                className={`lane-item${hoverT === i.t ? ' on' : ''}${focus?.key === i.key ? ' hl' : ''}`}
                data-key={i.key}
                onFocus={() => onHover(i.t)}
                onMouseEnter={() => onHover(i.t)}
                onClick={() => onHover(i.t)}
                onKeyDown={move}
                title={formatDateTime(i.t)}
              >
                <SignalMark shape={i.shape} severity={i.severity} />
                <time dateTime={new Date(i.t).toISOString()}>{formatClock(i.t)}</time>
                <span className="lane-text">
                  {i.title}
                  {i.detail && <span className="muted"> · {i.detail}</span>}
                  {i.ongoing && <span className="muted"> · still going</span>}
                </span>
                {i.role === 'trigger' && <span className="tag">trigger</span>}
              </button>
              {i.href && (
                <a className="lane-link" href={i.href} aria-label={`Open the alert in Alerts: ${i.title}`}>
                  Open alert
                </a>
              )}
            </li>
          ))}
        </ol>
      ) : (
        <p className="muted small lane-note">Nothing in the selection.</p>
      )}
      <p className="lane-more">
        {listed.length > FIRST && (
          <button type="button" className="linklike" onClick={() => setShowAll((v) => !v)}>
            {showAll ? 'Show fewer' : `Show all ${listed.length.toLocaleString('en-US')}`}
          </button>
        )}
        {brush && inside.length < items.length && (
          <button type="button" className="linklike" onClick={() => setShowOutside((v) => !v)}>
            {showOutside ? 'Only the selection' : `Also ${(items.length - inside.length).toLocaleString('en-US')} outside the selection`}
          </button>
        )}
      </p>
    </section>
  )
}
