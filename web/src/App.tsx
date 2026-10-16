import { useCallback, useEffect, useRef, useState, type ReactElement, type ReactNode } from 'react'
import { can, hasFeature, hiddenNote } from './access'
import { ApiError, setAuthSource } from './api'
import { InfoContext, NO_INFO, PrometheusNotice, StatusBanners } from './components/Access'
import { AppHeader, Sidebar, useSidebar, useTheme } from './components/Shell'
import { Async, Empty, PageHead } from './components/ui'
import { activeKey, groupNav, resolveRoute, type PageKey } from './nav'
import { Activity } from './pages/Activity'
import { Agents } from './pages/Agents'
import { Certificates } from './pages/Certificates'
import { Findings } from './pages/Findings'
import { IncidentDetail } from './pages/IncidentDetail'
import { Incidents } from './pages/Incidents'
import { MapPage } from './pages/Map'
import { Memory } from './pages/Memory'
import { Nodes } from './pages/Nodes'
import { Overview, OVERVIEW_POLL_MS } from './pages/Overview'
import { PodDetail } from './pages/PodDetail'
import { Pods } from './pages/Pods'
import { Security } from './pages/Security'
import { Storage } from './pages/Storage'
import { Workloads } from './pages/Workloads'
import { useRoute } from './router'
import { prometheusOutage } from './sources'
import type { Capability, Info, OverviewResponse } from './types'
import { useApi, usePolled, type ApiState } from './useApi'

type Flag = 'inventory' | 'certs' | 'incidents'

/** Pages built around wide tables (and the Overview's tiles) get more room; the map and node pages get the most. */
const TABLE_PAGES = new Set<PageKey>(['overview', 'pods', 'workloads', 'storage', 'activity', 'agents', 'incidents', 'incident'])
const WIDE_PAGES = new Set<PageKey>(['map', 'nodes'])

/** Pages that read metrics: the Prometheus notice above them replaces the generic banner's line. */
const METRICS_PAGES = new Set<PageKey>(['findings', 'memory', 'pod'])
const METRICS_SOURCES = ['prometheus']

/**
 * Waits for /api/v1/info before rendering a page that depends on it, and
 * explains when this server does not offer the page or this user may not use it.
 */
function Gate({ state, title, needs, cap, children }: { state: ApiState<Info>; title: string; needs?: Flag; cap?: Capability; children: (info: Info) => ReactNode }) {
  if (!state.data) {
    return (
      <>
        <PageHead title={title} />
        <Async state={state} what="server features">{() => null}</Async>
      </>
    )
  }
  if (needs && !hasFeature(state.data, needs)) {
    return (
      <>
        <PageHead title={title} />
        <Empty title={`${title} is not available on this server`}>
          {needs === 'certs'
            ? 'This kubesentry server does not read cert-manager objects.'
            : needs === 'incidents'
              ? 'This kubesentry server does not track incidents: it is older than incidents, or runs without -incidents.'
              : 'This kubesentry server does not list workloads, services and nodes, so this page has nothing to show.'}
        </Empty>
      </>
    )
  }
  if (cap && !can(state.data, cap)) {
    return (
      <>
        <PageHead title={title} />
        <Empty title={`${title} is not available to you`}>{hiddenNote(cap)}</Empty>
      </>
    )
  }
  return <>{children(state.data)}</>
}

export function App() {
  const route = useRoute()
  // Through useApi so it is fetched again once a token is entered or access is rechecked.
  // Refreshed so the staleness banner and capabilities stay current.
  const infoState = useApi<Info>('/api/v1/info', 30_000)
  const info = infoState.data ?? NO_INFO
  const [theme, cycleTheme] = useTheme()
  const [missing, setMissing] = useState<ReadonlySet<string>>(new Set())
  const hideRoute = useCallback((href: string) => setMissing((m) => (m.has(href) ? m : new Set([...m, href]))), [])

  const source = infoState.data?.identity?.source
  useEffect(() => {
    if (source) setAuthSource(source)
  }, [source])

  // The Overview page and the sidebar badges share one /overview, polled while
  // the tab is visible. An older server answers 404: then there are no badges,
  // Findings is the home page again, and /overview is not asked for again.
  const overviewGone = missing.has('/')
  const overview = usePolled<OverviewResponse>(overviewGone ? null : '/api/v1/overview', OVERVIEW_POLL_MS, { retryBusy: true })
  const notFound = overview.error instanceof ApiError && overview.error.status === 404
  useEffect(() => {
    if (notFound) hideRoute('/')
  }, [notFound, hideRoute])

  const resolved = resolveRoute(route.path, route.query, { overview: !overviewGone && !notFound })
  useEffect(() => {
    if (!resolved.redirect) return
    window.history.replaceState(null, '', resolved.redirect)
    window.dispatchEvent(new HashChangeEvent('hashchange'))
  }, [resolved.redirect])

  const { parts } = resolved
  let page: ReactElement
  switch (resolved.page) {
    case 'overview':
      page = <Overview route={route} shared={overview} />
      break
    case 'pod':
      page = <PodDetail key={parts[1] + '/' + parts[2]} ns={parts[1]} name={parts[2]} info={info} />
      break
    case 'pods':
      page = <Pods route={route} />
      break
    case 'memory':
      page = <Memory />
      break
    case 'map':
      page = <Gate state={infoState} title="Map" needs="inventory">{() => <MapPage route={route} />}</Gate>
      break
    case 'nodes':
      page = <Gate state={infoState} title="Nodes" needs="inventory" cap="nodes">{() => <Nodes route={route} />}</Gate>
      break
    case 'workloads':
      page = <Gate state={infoState} title="Workloads" needs="inventory">{() => <Workloads route={route} />}</Gate>
      break
    case 'storage':
      page = <Gate state={infoState} title="Storage">{(i) => <Storage route={route} inventory={i.inventory} />}</Gate>
      break
    case 'security':
      page = <Gate state={infoState} title="Security" needs="inventory">{() => <Security route={route} />}</Gate>
      break
    case 'certificates':
      page = <Gate state={infoState} title="Certificates" needs="certs">{() => <Certificates route={route} />}</Gate>
      break
    case 'activity':
      page = <Gate state={infoState} title="Activity" cap="audit">{(i) => <Activity route={route} info={i} />}</Gate>
      break
    case 'incidents':
      page = <Gate state={infoState} title="Incidents" needs="incidents">{(i) => <Incidents route={route} info={i} />}</Gate>
      break
    case 'incident':
      page = (
        <Gate state={infoState} title="Incident" needs="incidents">
          {(i) => <IncidentDetail key={parts[1]} id={parts[1]} route={route} info={i} />}
        </Gate>
      )
      break
    case 'agents':
      page = <Gate state={infoState} title="Agents" cap="agents">{() => <Agents onMissing={() => hideRoute('/agents')} />}</Gate>
      break
    default:
      page = <Findings info={info} />
  }
  // Pages that read metrics get the Prometheus notice; the generic banner leaves Prometheus out there.
  const metricsPage = METRICS_PAGES.has(resolved.page)
  const down = prometheusOutage(info)

  // Gated items appear once the server says it has them and the user may use them, so there are no dead links.
  const sections = groupNav(info, { hidden: missing, badges: overviewGone ? undefined : overview.data?.badges })
  const control = useSidebar()
  const { layout, state, dispatch } = control
  const drawerOpen = layout === 'drawer' && state.drawerOpen
  const menuButton = useRef<HTMLButtonElement>(null)

  // Back and forward close the drawer too.
  const hash = `${route.path}?${route.query}`
  useEffect(() => {
    dispatch({ type: 'closeDrawer' })
  }, [hash, dispatch])

  const frame = WIDE_PAGES.has(resolved.page) ? 'wide' : TABLE_PAGES.has(resolved.page) ? 'tables' : ''
  return (
    <InfoContext.Provider value={info}>
      {/* Hash routing: following "#main" would change the page, so move focus instead. */}
      <a
        className="skip"
        href="#main"
        onClick={(e) => {
          e.preventDefault()
          document.getElementById('main')?.focus()
        }}
      >
        Skip to content
      </a>
      <div className="shell" data-layout={layout}>
        <Sidebar sections={sections} active={activeKey(resolved.page)} control={control} info={info} theme={theme} onTheme={cycleTheme} menuButton={menuButton} />
        {drawerOpen && <div className="scrim" aria-hidden="true" onClick={() => dispatch({ type: 'closeDrawer' })} />}
        <div className="content" inert={drawerOpen || undefined}>
          <AppHeader info={info} layout={layout} drawerOpen={drawerOpen} onMenu={() => dispatch({ type: 'openDrawer' })} menuButton={menuButton} />
          <div className={`notices ${frame}`}>
            <StatusBanners info={info} explained={metricsPage ? METRICS_SOURCES : undefined} />
            {down && (resolved.page === 'findings' || resolved.page === 'memory') && <PrometheusNotice reason={down} />}
          </div>
          <main id="main" tabIndex={-1} className={frame || undefined}>
            {page}
          </main>
        </div>
      </div>
    </InfoContext.Provider>
  )
}
