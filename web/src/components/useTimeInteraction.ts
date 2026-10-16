import { useRef, useState, type KeyboardEvent, type PointerEvent } from 'react'
import { brushRange, timeAt, type Range } from '../chartMath'

/** Pixels a pointer must travel before a press becomes a brush rather than a click. */
const DRAG_PX = 5

export interface TimeInteraction {
  domain: Range
  /** The plot's left edge and width, in the SVG's own units (its viewBox matches its pixel width). */
  left: number
  width: number
  /** The SVG's width in its own units, to turn client pixels into SVG ones. */
  svgWidth: number
  /** Times the arrow keys step through (the samples); sorted. Empty steps by 1/60 of the domain. */
  keys: readonly number[]
  hoverT: number | null
  onHover: (t: number | null) => void
  /** The committed brush, shown by the caller. */
  brush?: Range | null
  /** Without it there is no brush: dragging only moves the crosshair. */
  onBrush?: (r: Range | null) => void
  /** Snap the crosshair to the nearest key while the pointer moves (charts); strips follow the pointer. */
  snap?: boolean
}

export interface KeyState {
  hoverT: number | null
  /** The brush being drawn with Shift+Arrow. */
  pending: Range | null
  /** Where the keyboard brush started. */
  anchor: number | null
}

export interface KeyResult extends KeyState {
  /** Apply this brush (Enter). */
  commit?: Range
  /** Clear the committed brush (Escape with nothing pending). */
  clear?: boolean
}

/**
 * What a key does on the time axis, free of React: arrows (and Home/End) move
 * the crosshair through `keys`; with Shift they draw a brush from where they
 * started; Enter applies it; Escape drops what is pending, else the committed
 * brush, and the crosshair. Undefined for keys it leaves alone.
 */
export function timeKey(
  s: KeyState,
  key: string,
  shift: boolean,
  ctx: { keys: readonly number[]; domain: Range; canBrush: boolean; hasBrush: boolean },
): KeyResult | undefined {
  const last = ctx.keys.length ? ctx.keys[ctx.keys.length - 1] : ctx.domain[1]
  const cur = s.hoverT ?? last
  const dir = key === 'ArrowLeft' ? -1 : key === 'ArrowRight' ? 1 : key === 'Home' ? 'home' : key === 'End' ? 'end' : undefined
  if (dir !== undefined) {
    // The first plain press shows where the crosshair is; later ones move it.
    const next = s.hoverT === null && !shift ? cur : stepTime(cur, dir, ctx.keys, ctx.domain)
    if (shift && ctx.canBrush) {
      const anchor = s.anchor ?? cur
      return { hoverT: next, anchor, pending: anchor === next ? null : anchor < next ? [anchor, next] : [next, anchor] }
    }
    return { ...s, hoverT: next }
  }
  if (key === 'Enter' && s.pending && ctx.canBrush) {
    const r = brushRange(s.pending[0], s.pending[1], ctx.domain)
    return { hoverT: s.hoverT, pending: null, anchor: null, commit: r ?? undefined }
  }
  if (key === 'Escape') {
    return { hoverT: null, pending: null, anchor: null, clear: !s.pending && ctx.hasBrush && ctx.canBrush }
  }
  return undefined
}

/** The next time the arrow keys reach: the neighbouring key, or 1/60 of the domain without keys. */
export function stepTime(from: number, dir: -1 | 1 | 'home' | 'end', keys: readonly number[], domain: Range): number {
  if (keys.length === 0) {
    const s = (domain[1] - domain[0]) / 60
    if (dir === 'home') return domain[0]
    if (dir === 'end') return domain[1]
    return Math.min(domain[1], Math.max(domain[0], from + dir * s))
  }
  if (dir === 'home') return keys[0]
  if (dir === 'end') return keys[keys.length - 1]
  const i = nearest(keys, from)
  return keys[Math.min(keys.length - 1, Math.max(0, i + dir))]
}

function nearest(keys: readonly number[], t: number): number {
  if (keys.length === 0) return -1
  let lo = 0
  let hi = keys.length - 1
  while (lo < hi) {
    const mid = (lo + hi) >> 1
    if (keys[mid] < t) lo = mid + 1
    else hi = mid
  }
  if (lo > 0 && Math.abs(keys[lo - 1] - t) <= Math.abs(keys[lo] - t)) return lo - 1
  return lo
}

/**
 * Pointer and keyboard handling for anything drawn on the shared time axis:
 * the crosshair follows the pointer or the arrow keys; dragging (or
 * Shift+Arrow, then Enter) brushes a range; Escape clears the selection and
 * the crosshair. Returns the brush being drawn, for the caller to show.
 */
export function useTimeInteraction(o: TimeInteraction) {
  const [pending, setPending] = useState<Range | null>(null)
  const anchor = useRef<{ t: number; px: number } | null>(null)
  const kbAnchor = useRef<number | null>(null)

  const toSvg = (e: PointerEvent<Element>) => {
    const r = e.currentTarget.getBoundingClientRect()
    return r.width > 0 ? ((e.clientX - r.left) / r.width) * o.svgWidth : 0
  }
  const snapT = (t: number) => {
    if (!o.snap || o.keys.length === 0) return t
    return o.keys[nearest(o.keys, t)]
  }
  const inPlot = (px: number) => px >= o.left - 2 && px <= o.left + o.width + 2

  const onPointerDown = (e: PointerEvent<SVGSVGElement>) => {
    if (e.button !== 0) return
    const px = toSvg(e)
    if (!inPlot(px)) return
    const t = timeAt(px, o.domain, o.left, o.width)
    o.onHover(snapT(t))
    if (!o.onBrush) return
    anchor.current = { t, px }
    try {
      e.currentTarget.setPointerCapture(e.pointerId)
    } catch {
      /* not capturable (synthetic event) */
    }
  }
  const onPointerMove = (e: PointerEvent<SVGSVGElement>) => {
    const px = toSvg(e)
    const a = anchor.current
    if (!a && !inPlot(px)) {
      o.onHover(null)
      return
    }
    const t = timeAt(px, o.domain, o.left, o.width)
    o.onHover(snapT(t))
    if (a && Math.abs(px - a.px) >= DRAG_PX) setPending(a.t < t ? [a.t, t] : [t, a.t])
  }
  // The drag is read from the anchor and the release point, not from `pending`:
  // React renders pointermove updates later, so the handler may not have seen the latest yet.
  const finish = (e: PointerEvent<SVGSVGElement> | null) => {
    const a = anchor.current
    anchor.current = null
    setPending(null)
    if (!e || !a || !o.onBrush) return
    const px = toSvg(e)
    if (Math.abs(px - a.px) < DRAG_PX) return
    const r = brushRange(a.t, timeAt(px, o.domain, o.left, o.width), o.domain)
    if (r) o.onBrush(r)
  }
  const onPointerUp = (e: PointerEvent<SVGSVGElement>) => finish(e)
  const onPointerCancel = () => finish(null)
  const onPointerLeave = () => {
    if (!anchor.current) o.onHover(null)
  }

  const onKeyDown = (e: KeyboardEvent<Element>) => {
    const r = timeKey({ hoverT: o.hoverT, pending, anchor: kbAnchor.current }, e.key, e.shiftKey, {
      keys: o.keys,
      domain: o.domain,
      canBrush: !!o.onBrush,
      hasBrush: !!o.brush,
    })
    if (!r) return
    e.preventDefault()
    kbAnchor.current = r.anchor
    setPending(r.pending)
    if (r.hoverT !== o.hoverT) o.onHover(r.hoverT)
    if (r.commit) o.onBrush?.(r.commit)
    if (r.clear) o.onBrush?.(null)
  }
  const onBlur = () => {
    kbAnchor.current = null
    if (!anchor.current) setPending(null)
  }

  return {
    pending,
    handlers: { onPointerDown, onPointerMove, onPointerUp, onPointerCancel, onPointerLeave, onKeyDown, onBlur },
  }
}

/** What the arrow keys do, for screen readers; one copy per page is enough. */
export const TIME_KEYS_HINT = 'Left and Right arrows move through time. Shift with an arrow selects a range; Enter applies it; Escape clears it.'
