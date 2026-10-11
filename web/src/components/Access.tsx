import { createContext, useContext, useEffect, useRef, useState } from 'react'
import { capabilityNoun, missingCapabilities } from '../access'
import { apiPost, ApiError, reloadForSignIn } from '../api'
import { cooldownLeft, readNumber, readString, RECHECK_COOLDOWN_MS, RECHECK_KEY, sessionStore, sortGroups, sourceText, writeNumber, writeString } from '../auth'
import { plural } from '../format'
import { clusterFacts, stalenessText } from '../retention'
import type { Info, RecheckResponse } from '../types'
import { bumpAuth, useNow } from '../useApi'

export const NO_INFO: Info = { demo: false, metrics: false, audit: false, processes: false, inventory: false, certs: false }

/** /api/v1/info for every page, so pages can check capabilities without prop drilling. */
export const InfoContext = createContext<Info>(NO_INFO)

export function useInfo(): Info {
  return useContext(InfoContext)
}

type RecheckState = { kind: 'idle' } | { kind: 'busy' } | { kind: 'done'; text: string } | { kind: 'error'; text: string }

/**
 * Asks the server to forget this user's cached access decisions, then reloads
 * /info and the page. The server allows one recheck a minute, so the button
 * waits that long after each use.
 */
export function RecheckButton({ className = 'btn' }: { className?: string }) {
  const store = sessionStore()
  const [until, setUntil] = useState<number | undefined>(() => readNumber(store, RECHECK_KEY))
  const [state, setState] = useState<RecheckState>({ kind: 'idle' })
  const now = useNow(1000, cooldownLeft(until, Date.now()) > 0)
  const left = cooldownLeft(until, now)

  const wait = (ms: number) => {
    const t = Date.now() + ms
    setUntil(t)
    writeNumber(store, RECHECK_KEY, t)
  }

  const run = async () => {
    setState({ kind: 'busy' })
    try {
      const r = await apiPost<RecheckResponse>('/api/v1/auth/recheck')
      wait(RECHECK_COOLDOWN_MS)
      const lacking = missingCapabilities({ capabilities: r?.capabilities })
      setState({
        kind: 'done',
        text: lacking.length === 0 ? 'Access rechecked. You can see everything kubesentry offers.' : 'Access rechecked. Pages now show what your current access allows.',
      })
      bumpAuth()
    } catch (e) {
      if (e instanceof ApiError && e.status === 429) {
        wait(e.retryAfterMs ?? RECHECK_COOLDOWN_MS)
        setState({ kind: 'error', text: 'Access was rechecked less than a minute ago. Try again when the button is available.' })
      } else if (e instanceof ApiError && e.status === 404) {
        setState({ kind: 'error', text: 'This kubesentry server cannot recheck access. Changes still show within a few minutes.' })
      } else if (e instanceof ApiError && e.reauth === 'reload') {
        setState({ kind: 'busy' })
      } else {
        setState({ kind: 'error', text: `Could not recheck access: ${e instanceof Error ? e.message : String(e)}` })
      }
    }
  }

  const secs = Math.ceil(left / 1000)
  return (
    <div className="recheck">
      <button type="button" className={className} onClick={run} disabled={state.kind === 'busy' || left > 0} aria-describedby="recheck-help">
        {state.kind === 'busy' ? 'Rechecking…' : left > 0 ? `Recheck access (${secs} s)` : 'Recheck access'}
      </button>
      <p id="recheck-help" className="muted small" role="status">
        {state.kind === 'done' || state.kind === 'error'
          ? state.text
          : 'Access comes from Kubernetes RBAC and is cached for a few minutes. Recheck after it changes.'}
      </p>
    </div>
  )
}

/** The signed-in user in the header, with groups and sign-out in a menu. */
export function IdentityMenu({ info }: { info: Info }) {
  const id = info.identity
  const ref = useRef<HTMLDetailsElement>(null)
  // Close on Escape or a click elsewhere, like other menus.
  useEffect(() => {
    const el = ref.current
    if (!el) return
    const onDoc = (e: MouseEvent) => {
      if (el.open && !el.contains(e.target as Node)) el.open = false
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && el.open) {
        el.open = false
        el.querySelector('summary')?.focus()
      }
    }
    document.addEventListener('click', onDoc)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('click', onDoc)
      document.removeEventListener('keydown', onKey)
    }
  }, [])
  if (!id) return null
  const groups = sortGroups(id.groups)
  const lacking = missingCapabilities(info)
  const user = id.user || (id.source === 'none' ? 'anonymous' : 'unknown user')
  // The bar has little room: the part before "@" is enough to recognise yourself.
  const short = user.includes('@') ? user.slice(0, user.indexOf('@')) : user
  return (
    <details className="menu" ref={ref}>
      <summary title={`${user}\n${groups.length} ${plural(groups.length, 'group', 'groups')}`}>
        <svg viewBox="0 0 16 16" width="16" height="16" aria-hidden="true">
          <circle cx="8" cy="5.5" r="3" fill="none" stroke="currentColor" strokeWidth="1.6" />
          <path d="M2.5 14.5c.6-3 2.8-4.5 5.5-4.5s4.9 1.5 5.5 4.5" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
        </svg>
        <span className="menu-user">{short}</span>
        <span className="sr-only">: account menu</span>
      </summary>
      <div className="menu-panel">
        <p className="menu-name id">{user}</p>
        <p className="muted small">{sourceText(id.source)}</p>
        {groups.length > 0 && (
          <div>
            <h3 className="menu-h">{groups.length} {plural(groups.length, 'group', 'groups')}</h3>
            <ul className="plain menu-groups">
              {groups.map((g) => <li key={g} className="id">{g}</li>)}
            </ul>
          </div>
        )}
        {lacking.length > 0 && (
          <div>
            <h3 className="menu-h">Not available to you</h3>
            <ul className="plain small">
              {lacking.map((c) => <li key={c}>{capabilityNoun(c)}</li>)}
            </ul>
          </div>
        )}
        {id.source === 'proxy' && <RecheckButton />}
        {id.source === 'proxy' && info.signOutURL && (
          <a className="btn menu-signout" href={info.signOutURL}>Sign out</a>
        )}
      </div>
    </details>
  )
}

/** Cluster name and version under the top bar, when the server says. */
export function ClusterBar({ info }: { info: Info }) {
  const c = clusterFacts(info.cluster)
  if (!c.name && c.facts.length === 0) return null
  return (
    <div className="cluster-bar">
      <span className="cluster-name">{c.name ?? 'Cluster'}</span>
      {c.facts.map((f) => (
        <span key={f} className="muted">{f}</span>
      ))}
    </div>
  )
}

const DISMISS_KEY = 'kubesentry.dismissedUnavailable'

/** Staleness and unreadable-source notices, above every page. */
export function StatusBanners({ info }: { info: Info }) {
  const stale = stalenessText(info.snapshot)
  const unavailable = Object.entries(info.unavailable ?? {}).sort(([a], [b]) => a.localeCompare(b))
  const sig = unavailable.map(([k, v]) => `${k}=${v}`).join('\n')
  // Dismissed per tab, and only for this exact set of sources: a new failure shows again.
  const [dismissed, setDismissed] = useState(() => readString(sessionStore(), DISMISS_KEY) ?? '')
  const dismiss = () => {
    setDismissed(sig)
    writeString(sessionStore(), DISMISS_KEY, sig)
  }
  return (
    <>
      {stale && (
        <div className="notice warn banner" role="status">
          <p>
            <strong>{stale}</strong> Pages show the last data kubesentry read.
          </p>
          {info.snapshot?.error && <p className="muted small">{info.snapshot.error}</p>}
        </div>
      )}
      {unavailable.length > 0 && dismissed !== sig && (
        <div className="notice banner" role="status">
          <div className="banner-head">
            <p>
              <strong>Some sources could not be read,</strong> so parts of the pages below may be missing.
            </p>
            <button type="button" className="btn quiet" onClick={dismiss}>Dismiss</button>
          </div>
          <ul className="plain small">
            {unavailable.map(([k, v]) => (
              <li key={k}><span className="id">{k}</span>: {v}</li>
            ))}
          </ul>
        </div>
      )}
    </>
  )
}

/** Shown when a scoped user sees no namespace at all. */
export function NoNamespaces() {
  const info = useInfo()
  return (
    <div className="empty">
      <h2>You can't see any namespaces yet</h2>
      <p>
        kubesentry shows you what your Kubernetes access allows: a namespace appears once RBAC lets{' '}
        <span className="id">{info.identity?.user ?? 'you'}</span> <code>list pods</code> in it. Ask a cluster admin for a
        RoleBinding in the namespaces you work in, then recheck.
      </p>
      {info.identity?.source === 'proxy' && <RecheckButton className="btn primary" />}
    </div>
  )
}

/** The single sign-on session could not be renewed by reloading. */
export function SignInStuck({ message }: { message?: string }) {
  const info = useInfo()
  return (
    <div className="notice crit" role="alert">
      <p>
        <strong>Your sign-in could not be renewed.</strong> The page reloaded to sign you in again, but the server still does not
        accept the session{message ? `: ${message}` : '.'}
      </p>
      <p className="muted small">If this keeps happening, sign out and in again, or ask whoever runs kubesentry to check the sign-in proxy.</p>
      <p className="actions">
        <button type="button" className="btn primary" onClick={() => reloadForSignIn()}>Sign in again</button>
        {info.signOutURL && <a className="btn" href={info.signOutURL}>Sign out</a>}
      </p>
    </div>
  )
}
