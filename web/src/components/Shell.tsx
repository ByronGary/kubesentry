import { useEffect, useReducer, useRef, useState, type KeyboardEvent as ReactKeyboardEvent, type MouseEvent as ReactMouseEvent, type RefObject } from 'react'
import { localStore, readString, writeString } from '../auth'
import { plural } from '../format'
import {
  arrowTarget,
  compactCount,
  DRAWER_BELOW,
  layoutFor,
  NAV_PREFS_KEY,
  navReducer,
  RAIL_BELOW,
  readNavPrefs,
  trapTab,
  writeNavPrefs,
  type Layout,
  type NavAction,
  type NavKey,
  type NavSection,
  type NavState,
  type ShownEntry,
} from '../nav'
import { clusterFacts } from '../retention'
import type { AttentionSeverity, Info } from '../types'
import { IdentityMenu } from './Access'
import { Icon } from './Icons'
import { GlyphShape, Logo } from './ui'

/** /info, plus the kubesentry version a newer server may send (not in the contract yet). */
type ServerInfo = Info & { version?: string }

export type Theme = 'light' | 'dark' | 'auto'

export function useTheme(): [Theme, () => void] {
  const [theme, setTheme] = useState<Theme>(() => {
    const t = readString(localStore(), 'kubesentry.theme')
    return t === 'light' || t === 'dark' ? t : 'auto'
  })
  useEffect(() => {
    const el = document.documentElement
    if (theme === 'auto') el.removeAttribute('data-theme')
    else el.setAttribute('data-theme', theme)
    writeString(localStore(), 'kubesentry.theme', theme)
  }, [theme])
  const next = () => setTheme((t) => (t === 'auto' ? 'dark' : t === 'dark' ? 'light' : 'auto'))
  return [theme, next]
}

/** The window width, updated when it crosses a sidebar breakpoint (all the layout needs). */
function useLayoutWidth(): number {
  const [w, setW] = useState(() => (typeof window === 'undefined' ? RAIL_BELOW : window.innerWidth))
  useEffect(() => {
    const queries = [window.matchMedia(`(min-width: ${DRAWER_BELOW}px)`), window.matchMedia(`(min-width: ${RAIL_BELOW}px)`)]
    const on = () => setW(window.innerWidth)
    queries.forEach((q) => q.addEventListener('change', on))
    on()
    return () => queries.forEach((q) => q.removeEventListener('change', on))
  }, [])
  return w
}

export interface SidebarControl {
  layout: Layout
  state: NavState
  dispatch: (a: NavAction) => void
}

/**
 * The sidebar's layout (expanded, icon rail, or a drawer on a phone) and its
 * folded sections. The « / » choice and the folds are remembered in
 * localStorage; every access is guarded, so blocked storage just forgets.
 */
export function useSidebar(): SidebarControl {
  const width = useLayoutWidth()
  const [state, dispatch] = useReducer(navReducer, undefined, () => readNavPrefs(readString(localStore(), NAV_PREFS_KEY)))
  const layout = layoutFor(width, state.pref)
  const saved = writeNavPrefs(state)
  useEffect(() => {
    writeString(localStore(), NAV_PREFS_KEY, saved)
  }, [saved])
  // Growing out of phone width closes the drawer, so it does not reappear open later.
  useEffect(() => {
    if (layout !== 'drawer' && state.drawerOpen) dispatch({ type: 'closeDrawer' })
  }, [layout, state.drawerOpen])
  const locked = layout === 'drawer' && state.drawerOpen
  useEffect(() => {
    document.documentElement.classList.toggle('drawer-open', locked)
  }, [locked])
  return { layout, state, dispatch }
}

const FOCUSABLE = 'a[href], button:not([disabled]), summary, input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])'

/** Elements that can take focus inside `root`, in order, skipping hidden ones. */
function focusables(root: HTMLElement): HTMLElement[] {
  return [...root.querySelectorAll<HTMLElement>(FOCUSABLE)].filter((el) => el.getClientRects().length > 0 && !el.closest('[hidden]'))
}

const SEVERITY_WORD: Record<AttentionSeverity, string> = { crit: 'Critical', warn: 'Warning' }

/** A severity shape: ◆ critical, ▲ warning. Its words go in the surrounding label. */
function SevShape({ severity, size = 10 }: { severity: AttentionSeverity; size?: number }) {
  return (
    <svg className={`glyph-${severity}`} viewBox="0 0 16 16" width={size} height={size} aria-hidden="true" focusable="false">
      <GlyphShape status={severity} />
    </svg>
  )
}

const THEME_NAME: Record<Theme, string> = { auto: 'system', dark: 'dark', light: 'light' }

export function Sidebar({
  sections,
  active,
  control,
  info,
  theme,
  onTheme,
  menuButton,
}: {
  sections: NavSection[]
  active: NavKey
  control: SidebarControl
  info: ServerInfo
  theme: Theme
  onTheme: () => void
  menuButton: RefObject<HTMLButtonElement | null>
}) {
  const { layout, state, dispatch } = control
  const ref = useRef<HTMLDivElement>(null)
  const drawer = layout === 'drawer'
  const rail = layout === 'rail'
  const open = drawer && state.drawerOpen
  // Where focus goes when the drawer closes: back to ☰, or to the page after following a link.
  const toPage = useRef(false)

  // While the drawer is open: focus starts inside it, Escape closes it, and Tab stays inside.
  useEffect(() => {
    if (!open) return
    const root = ref.current
    root?.querySelector<HTMLElement>('[data-autofocus]')?.focus()
    const onKey = (e: KeyboardEvent) => {
      if (!root) return
      if (e.key === 'Escape') {
        // An open identity menu closes first.
        if ((document.activeElement as HTMLElement | null)?.closest('details[open]')) return
        e.preventDefault()
        dispatch({ type: 'closeDrawer' })
      } else if (e.key === 'Tab') {
        const list = focusables(root)
        const t = trapTab(list.indexOf(document.activeElement as HTMLElement), list.length, e.shiftKey)
        if (t !== undefined) {
          e.preventDefault()
          list[t].focus()
        }
      }
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [open, dispatch])

  const wasOpen = useRef(open)
  useEffect(() => {
    if (wasOpen.current && !open) {
      if (toPage.current) document.getElementById('main')?.focus({ preventScroll: true })
      else menuButton.current?.focus()
    }
    wasOpen.current = open
    toPage.current = false
  }, [open, menuButton])

  // Following any in-app link closes the drawer (also when it points at the page already shown).
  const onClick = (e: ReactMouseEvent<HTMLDivElement>) => {
    if (!open) return
    if ((e.target as HTMLElement).closest('a[href^="#"]')) {
      toPage.current = true
      dispatch({ type: 'closeDrawer' })
    }
  }

  // Up and Down move through the list, Home and End jump to its ends.
  const onNavKey = (e: ReactKeyboardEvent<HTMLElement>) => {
    if (e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return
    const list = focusables(e.currentTarget)
    const t = arrowTarget(list.indexOf(document.activeElement as HTMLElement), list.length, e.key)
    if (t !== undefined) {
      e.preventDefault()
      list[t].focus()
    }
  }

  const item = (n: ShownEntry) => {
    const current = active === n.key
    const tip = n.badge ? `${n.label}: ${n.badge.label}` : n.label
    return (
      <li className="nav-item" key={n.key}>
        <a className="nav-link" href={`#${n.href}`} aria-current={current ? 'page' : undefined} title={rail ? tip : undefined}>
          <span className="nav-icon">
            <Icon name={n.key} />
            {rail && n.badge && (
              <span className="rail-mark">
                <SevShape severity={n.badge.severity} size={9} />
              </span>
            )}
          </span>
          <span className={rail ? 'sr-only' : 'nav-label'}>{rail && n.badge ? tip : n.label}</span>
        </a>
        {!rail && n.badge && (
          <a className="nav-badge" href={n.badge.href} title={n.badge.label} aria-label={`Show ${n.badge.label}`}>
            <SevShape severity={n.badge.severity} />
            <span>{compactCount(n.badge.count)}</span>
          </a>
        )}
      </li>
    )
  }

  const version = info.version
  const themeText = `Theme: ${THEME_NAME[theme]}`
  return (
    <div
      ref={ref}
      id="sidebar"
      className={`sidebar${open ? ' open' : ''}`}
      role={open ? 'dialog' : undefined}
      aria-modal={open ? true : undefined}
      aria-label={open ? 'Menu' : undefined}
      onClick={onClick}
    >
      <div className="side-head">
        <a className="brand" href="#/" title={rail ? 'kubesentry' : undefined}>
          <Logo />
          <span className={rail ? 'sr-only' : 'brand-name'}>kubesentry</span>
        </a>
        {drawer ? (
          <button type="button" className="icon-btn" data-autofocus aria-label="Close menu" onClick={() => dispatch({ type: 'closeDrawer' })}>
            <Icon name="close" />
          </button>
        ) : (
          <button
            type="button"
            className="icon-btn"
            aria-label={rail ? 'Expand the sidebar' : 'Collapse the sidebar to icons'}
            title={rail ? 'Expand the sidebar' : 'Collapse the sidebar to icons'}
            onClick={() => dispatch({ type: 'toggleRail', layout })}
          >
            <Icon name={rail ? 'expand' : 'collapse'} />
          </button>
        )}
      </div>
      <div className="side-scroll">
        <nav aria-label="Main" onKeyDown={onNavKey}>
          {sections.map((s) => {
            if (s.key === 'top' || s.key === 'bottom') {
              return (
                <ul className={s.key === 'bottom' ? 'nav-list nav-bottom' : 'nav-list'} key={s.key}>
                  {s.items.map(item)}
                </ul>
              )
            }
            const folded = !rail && state.folded.includes(s.key)
            const listId = `nav-list-${s.key}`
            return (
              <div className="nav-section" key={s.key}>
                {!rail && (
                  <button
                    type="button"
                    className="nav-section-toggle"
                    aria-expanded={!folded}
                    aria-controls={listId}
                    onClick={() => dispatch({ type: 'toggleSection', section: s.key })}
                  >
                    <span>{s.label}</span>
                    {folded && s.worst && (
                      <span className="nav-section-flag" title={`${s.flagged} ${plural(s.flagged, 'page needs', 'pages need')} attention`}>
                        <SevShape severity={s.worst} />
                        <span className="sr-only">
                          {SEVERITY_WORD[s.worst]}: {s.flagged} {plural(s.flagged, 'page needs', 'pages need')} attention
                        </span>
                      </span>
                    )}
                    <Icon name="caret" className={folded ? 'caret folded' : 'caret'} />
                  </button>
                )}
                <ul className="nav-list" id={listId} aria-label={s.label} hidden={folded}>
                  {s.items.map(item)}
                </ul>
              </div>
            )
          })}
        </nav>
      </div>
      <div className="side-foot">
        <IdentityMenu info={info} />
        <button type="button" className="side-btn" onClick={onTheme} title="Change colour theme" aria-label={rail ? `${themeText}. Change colour theme` : undefined}>
          <Icon name="theme" />
          <span className={rail ? 'sr-only' : undefined}>{themeText}</span>
        </button>
        {version && !rail && <p className="side-version">kubesentry {version}</p>}
      </div>
    </div>
  )
}

/**
 * The slim bar above every page: the cluster's name and version, and on a
 * phone the ☰ button that opens the menu.
 */
export function AppHeader({
  info,
  layout,
  drawerOpen,
  onMenu,
  menuButton,
}: {
  info: Info
  layout: Layout
  drawerOpen: boolean
  onMenu: () => void
  menuButton: RefObject<HTMLButtonElement | null>
}) {
  const c = clusterFacts(info.cluster)
  return (
    <header className="appbar">
      {layout === 'drawer' && (
        <>
          <button
            ref={menuButton}
            type="button"
            className="icon-btn"
            aria-label="Open the menu"
            aria-haspopup="dialog"
            aria-expanded={drawerOpen}
            aria-controls="sidebar"
            onClick={onMenu}
          >
            <Icon name="menu" />
          </button>
          <a className="brand" href="#/" title="kubesentry">
            <Logo />
            <span className="sr-only">kubesentry</span>
          </a>
        </>
      )}
      {(c.name || c.facts.length > 0) && (
        <p className="cluster-facts">
          <span className="cluster-name">{c.name ?? 'Cluster'}</span>
          {c.facts.map((f) => (
            <span key={f} className="muted cluster-fact">{f}</span>
          ))}
        </p>
      )}
      {info.demo && (
        <span className="badge appbar-end" title="Synthetic data, not a real cluster">
          Demo data
        </span>
      )}
    </header>
  )
}
