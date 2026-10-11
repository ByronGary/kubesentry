import { useEffect, useRef, useState, type ReactNode } from 'react'
import { Async, Empty, Logo, PageHead } from './components/ui'
import { Activity } from './pages/Activity'
import { Certificates } from './pages/Certificates'
import { Findings } from './pages/Findings'
import { MapPage } from './pages/Map'
import { Memory } from './pages/Memory'
import { PodDetail } from './pages/PodDetail'
import { Pods } from './pages/Pods'
import { Security } from './pages/Security'
import { Storage } from './pages/Storage'
import { Workloads } from './pages/Workloads'
import { useRoute } from './router'
import type { Info } from './types'
import { useApi, type ApiState } from './useApi'

type Flag = 'inventory' | 'certs'

const NAV: { href: string; label: string; needs?: Flag }[] = [
  { href: '/', label: 'Findings' },
  { href: '/map', label: 'Map', needs: 'inventory' },
  { href: '/workloads', label: 'Workloads', needs: 'inventory' },
  { href: '/pods', label: 'Pods' },
  { href: '/memory', label: 'Memory' },
  { href: '/storage', label: 'Storage' },
  { href: '/security', label: 'Security', needs: 'inventory' },
  { href: '/certificates', label: 'Certificates', needs: 'certs' },
  { href: '/activity', label: 'Activity' },
]

/** Old paths that still work. */
const ALIAS: Record<string, string> = { volumes: 'storage' }

const NO_INFO: Info = { demo: false, metrics: false, audit: false, processes: false, inventory: false, certs: false }

type Theme = 'light' | 'dark' | 'auto'

function useTheme(): [Theme, () => void] {
  const [theme, setTheme] = useState<Theme>(() => {
    try {
      return (localStorage.getItem('kubesentry.theme') as Theme) || 'auto'
    } catch {
      return 'auto'
    }
  })
  useEffect(() => {
    const el = document.documentElement
    if (theme === 'auto') el.removeAttribute('data-theme')
    else el.setAttribute('data-theme', theme)
    try {
      localStorage.setItem('kubesentry.theme', theme)
    } catch {
      /* ignore */
    }
  }, [theme])
  const next = () => setTheme((t) => (t === 'auto' ? 'dark' : t === 'dark' ? 'light' : 'auto'))
  return [theme, next]
}

/**
 * Waits for /api/v1/info before rendering a page that depends on it, and
 * explains when this server does not offer the page at all.
 */
function Gate({ state, title, needs, children }: { state: ApiState<Info>; title: string; needs?: Flag; children: (info: Info) => ReactNode }) {
  if (!state.data) {
    return (
      <>
        <PageHead title={title} />
        <Async state={state} what="server features">{() => null}</Async>
      </>
    )
  }
  if (needs && !state.data[needs]) {
    return (
      <>
        <PageHead title={title} />
        <Empty title={`${title} is not available on this server`}>
          {needs === 'certs'
            ? 'This kubesentry server does not read cert-manager objects.'
            : 'This kubesentry server does not list workloads, services and nodes, so this page has nothing to show.'}
        </Empty>
      </>
    )
  }
  return <>{children(state.data)}</>
}

export function App() {
  const route = useRoute()
  // Through useApi so it is fetched again once a token is entered.
  const infoState = useApi<Info>('/api/v1/info')
  const info = infoState.data ?? NO_INFO
  const [theme, cycleTheme] = useTheme()

  const parts = route.path.split('/').filter(Boolean).map(decodeURIComponent)
  if (parts[0] && ALIAS[parts[0]]) parts[0] = ALIAS[parts[0]]
  let page
  if (parts[0] === 'pods' && parts.length >= 3) page = <PodDetail key={parts[1] + '/' + parts[2]} ns={parts[1]} name={parts[2]} info={info} />
  else if (parts[0] === 'pods') page = <Pods />
  else if (parts[0] === 'memory') page = <Memory />
  else if (parts[0] === 'map') page = <Gate state={infoState} title="Map" needs="inventory">{() => <MapPage route={route} />}</Gate>
  else if (parts[0] === 'workloads') page = <Gate state={infoState} title="Workloads" needs="inventory">{() => <Workloads route={route} />}</Gate>
  else if (parts[0] === 'storage') page = <Gate state={infoState} title="Storage">{(i) => <Storage route={route} inventory={i.inventory} />}</Gate>
  else if (parts[0] === 'security') page = <Gate state={infoState} title="Security" needs="inventory">{() => <Security route={route} />}</Gate>
  else if (parts[0] === 'certificates') page = <Gate state={infoState} title="Certificates" needs="certs">{() => <Certificates route={route} />}</Gate>
  else if (parts[0] === 'activity') page = <Activity route={route} />
  else page = <Findings info={info} />

  const section = parts[0] ? '/' + parts[0] : '/'
  // Gated tabs appear once the server says it has them, so there are no dead links.
  const nav = NAV.filter((n) => !n.needs || info[n.needs])

  // On a phone the nav scrolls sideways; keep the current tab in view.
  const navRef = useRef<HTMLElement>(null)
  const navCount = nav.length
  useEffect(() => {
    const el = navRef.current?.querySelector<HTMLElement>('a[aria-current="page"]')
    const bar = navRef.current
    if (!el || !bar || bar.scrollWidth <= bar.clientWidth) return
    const r = el.getBoundingClientRect()
    const b = bar.getBoundingClientRect()
    if (r.left < b.left || r.right > b.right) bar.scrollLeft += r.left - b.left - 12
  }, [section, navCount])
  return (
    <>
      <a className="skip" href="#main">Skip to content</a>
      <header className="top">
        <a className="brand" href="#/"><Logo /><span>kubesentry</span></a>
        <nav aria-label="Main" ref={navRef}>
          {nav.map(({ href, label }) => (
            <a key={href} href={`#${href}`} aria-current={section === href ? 'page' : undefined}>{label}</a>
          ))}
        </nav>
        <div className="top-end">
          {info.demo && <span className="badge" title="Synthetic data, not a real cluster">Demo data</span>}
          <button className="btn quiet" onClick={cycleTheme} title="Change colour theme">
            Theme: {theme === 'auto' ? 'system' : theme}
          </button>
        </div>
      </header>
      <main id="main" className={parts[0] === 'map' ? 'wide' : undefined}>{page}</main>
    </>
  )
}
