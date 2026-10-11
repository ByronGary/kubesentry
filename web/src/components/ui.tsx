import { Fragment, useState, type ReactNode } from 'react'
import { ApiError, setToken } from '../api'
import { loadedText } from '../paging'
import type { WindowChoice } from '../retention'
import { retryText, type Retry } from '../retry'
import type { Status } from '../types'
import type { PagedState } from '../usePaged'
import { bumpAuth, useNow, type ApiState } from '../useApi'
import { SignInStuck } from './Access'

/** Status plus a neutral "info" level used for security findings. UI-only. */
export type GlyphKind = Status | 'info'

export const GLYPH_LABEL: Record<GlyphKind, string> = { ok: 'OK', warn: 'Warning', crit: 'Critical', unknown: 'Unknown', info: 'Info' }

/**
 * The shape for a status, drawn in a 16x16 box with currentColor. Shared by
 * StatusGlyph and the map so a status always has the same shape everywhere.
 */
export function GlyphShape({ status }: { status: GlyphKind }) {
  switch (status) {
    case 'ok':
      return <circle cx="8" cy="8" r="5.5" fill="currentColor" />
    case 'warn':
      return <path d="M8 2 14.5 13.5H1.5Z" fill="currentColor" strokeLinejoin="round" />
    case 'crit':
      return <path d="M8 1.5 14.5 8 8 14.5 1.5 8Z" fill="currentColor" />
    case 'info':
      return (
        <>
          <circle cx="8" cy="8" r="5.3" fill="none" stroke="currentColor" strokeWidth="1.8" />
          <circle cx="8" cy="8" r="2" fill="currentColor" />
        </>
      )
    default:
      return <circle cx="8" cy="8" r="5" fill="none" stroke="currentColor" strokeWidth="1.8" strokeDasharray="2.6 2.2" />
  }
}

/**
 * Status mark. Shape differs per status so colour is never the only signal.
 * `label={false}` keeps the word for screen readers only; `decorative` drops it
 * entirely, for when the surrounding text already says it.
 */
export function StatusGlyph({ status, label = true, decorative = false }: { status: GlyphKind; label?: boolean; decorative?: boolean }) {
  return (
    <span className={`glyph glyph-${status}`}>
      <svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true">
        <GlyphShape status={status} />
      </svg>
      {decorative ? null : label ? <span>{GLYPH_LABEL[status]}</span> : <span className="sr-only">{GLYPH_LABEL[status]}</span>}
    </span>
  )
}

/**
 * Text for an identifier such as "namespace/name" or an image reference, with
 * line-break chances after each separator (by default "/") so it wraps between
 * parts, not mid-word. Pair with the `brk` class.
 */
export function slashBreaks(text: string, separators = '/'): ReactNode {
  const parts: string[] = []
  let start = 0
  for (let i = 0; i < text.length; i++) {
    if (separators.includes(text[i])) {
      parts.push(text.slice(start, i + 1))
      start = i + 1
    }
  }
  if (parts.length === 0) return text
  parts.push(text.slice(start))
  return parts.map((p, i) => (
    <Fragment key={i}>
      {p}
      {i < parts.length - 1 && <wbr />}
    </Fragment>
  ))
}

export function Logo() {
  return (
    <svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true" className="logo">
      <path d="M3 18 11 6v12L19 4" fill="none" stroke="currentColor" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

export function TokenForm() {
  const [v, setV] = useState('')
  return (
    <form
      className="token-form"
      onSubmit={(e) => {
        e.preventDefault()
        setToken(v.trim())
        bumpAuth()
      }}
    >
      <h2>This server needs an API token</h2>
      <p>Enter the value passed to <code>-api-token</code>. It is kept for this browser tab only.</p>
      <label>
        API token
        <input type="password" value={v} onChange={(e) => setV(e.target.value)} autoFocus autoComplete="off" />
      </label>
      <button type="submit" className="btn primary" disabled={!v.trim()}>Use token</button>
    </form>
  )
}

/**
 * A calm note while a busy store is waited out: "Audit store is busy, retrying
 * in 5 s…". The countdown is hidden from screen readers so it is not read out
 * every second.
 */
export function BusyNotice({ retry, text = 'Audit store is busy', note }: { retry?: Retry; text?: string; note?: ReactNode }) {
  const now = useNow(1000, retry !== undefined)
  return (
    <div className="notice busy" role="status">
      <p>
        {text}
        {retry ? (
          <>
            , <span aria-hidden="true" className="countdown">{retryText(retry, now)}</span>
            <span className="sr-only">retrying shortly.</span>
          </>
        ) : (
          '; it will be asked again shortly.'
        )}
      </p>
      {note && <p className="muted small">{note}</p>}
    </div>
  )
}

/**
 * Renders loading / error / content for an API state. A 503 that the hook is
 * retrying (`retryBusy`) shows as a calm BusyNotice saying `busy`, not as an error.
 */
export function Async<T>({
  state,
  children,
  what,
  busy,
}: {
  state: ApiState<T>
  what: string
  children: (data: T) => ReactNode
  /** What is busy when a 503 is being retried, e.g. "Audit store is busy". */
  busy?: string
}) {
  const { data, error, loading, reload, retry } = state
  if (error instanceof ApiError && error.status === 401) return <Unauthorized error={error} />
  const waiting = error !== undefined && retry !== undefined
  if (!data) {
    if (waiting) return <BusyNotice retry={retry} text={busy} />
    if (error) {
      return (
        <div className="notice crit" role="alert">
          <p>Could not load {what}: {error.message}</p>
          <button className="btn" onClick={reload}>Try again</button>
        </div>
      )
    }
    return <p className="muted" aria-live="polite">Loading {what}…</p>
  }
  return (
    <div className={loading ? 'refetching' : undefined} aria-busy={loading}>
      {waiting ? (
        <BusyNotice retry={retry} text={busy} note="Showing the last result meanwhile." />
      ) : (
        error && (
          <div className="notice warn" role="status">
            Showing the last result. Refreshing failed: {error.message}
          </div>
        )
      )}
      {children(data)}
    </div>
  )
}

export function PageHead({ title, lede, children }: { title: string; lede?: ReactNode; children?: ReactNode }) {
  return (
    <header className="page-head">
      <div>
        <h1>{title}</h1>
        {lede && <p className="lede">{lede}</p>}
      </div>
      {children}
    </header>
  )
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <h2>{title}</h2>
      {children && <p>{children}</p>}
    </div>
  )
}

export function Segmented<T extends string>({
  label,
  value,
  options,
  onChange,
}: {
  label: string
  value: T
  options: { value: T; label: string; disabled?: boolean; reason?: string }[]
  onChange: (v: T) => void
}) {
  return (
    <div className="segmented" role="group" aria-label={label}>
      {options.map((o) => (
        // aria-disabled rather than disabled, so the tooltip saying why still shows.
        <button
          key={o.value}
          type="button"
          aria-pressed={o.value === value}
          aria-disabled={o.disabled || undefined}
          title={o.disabled ? o.reason : undefined}
          onClick={() => {
            if (!o.disabled) onChange(o.value)
          }}
        >
          {o.label}
        </button>
      ))}
    </div>
  )
}

/** A 401: the token prompt, a note while single sign-on renews, or help when renewing failed. */
export function Unauthorized({ error }: { error: ApiError }) {
  if (error.reauth === 'reload') return <p className="muted" aria-live="polite">Your sign-in expired. Signing you in again…</p>
  if (error.reauth === 'stuck') return <SignInStuck message={error.message} />
  return <TokenForm />
}

/** A period picker whose options with no data behind them are disabled, with the reason underneath. */
export function WindowSelect<V extends string>({
  label,
  value,
  choices,
  onChange,
}: {
  label: string
  value: V
  choices: WindowChoice<V>[]
  onChange: (v: V) => void
}) {
  const off = choices.find((c) => c.disabled)
  return (
    <label>
      {label}
      <select value={value} onChange={(e) => onChange(e.target.value as V)} aria-describedby={off ? 'window-why' : undefined}>
        {choices.map((c) => (
          <option key={c.value} value={c.value} disabled={c.disabled} title={c.reason}>
            {c.label}
            {c.disabled ? ' (no data)' : ''}
          </option>
        ))}
      </select>
      {off && <span id="window-why" className="field-hint">{off.reason}</span>}
    </label>
  )
}

/**
 * The line above a paged list: progress while pages arrive (with Stop), how
 * many rows match, and Refresh when the list is too big to refresh on its own.
 */
export function ListStatus({ state, noun, shown }: { state: PagedState<unknown>; noun: [string, string]; shown?: number }) {
  const { loaded, following, truncated, stopped, pages, loading, data } = state
  const filtered = shown !== undefined && shown !== loaded && !following
  let text: string
  if (stopped) text = `Stopped after ${loaded.toLocaleString('en-US')} ${loaded === 1 ? noun[0] : noun[1]}`
  else if (filtered) text = `${shown.toLocaleString('en-US')} of ${loaded.toLocaleString('en-US')} ${loaded === 1 ? noun[0] : noun[1]}`
  else text = loadedText(loaded, noun, { following, truncated, complete: true })
  return (
    <div className="list-status">
      <span aria-live="polite">{text}</span>
      {following && (
        <button type="button" className="linklike" onClick={state.stop}>Stop loading</button>
      )}
      {stopped && (
        <button type="button" className="linklike" onClick={state.reload}>Load all</button>
      )}
      {truncated && <span className="muted">Narrow the list with a namespace to see the rest.</span>}
      {!following && !stopped && pages > 1 && data !== undefined && (
        <button type="button" className="linklike" onClick={state.reload} disabled={loading}>
          {loading ? 'Refreshing…' : 'Refresh'}
        </button>
      )}
    </div>
  )
}
