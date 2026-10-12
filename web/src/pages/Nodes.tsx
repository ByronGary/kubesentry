import { NodesView } from '../components/NodesView'
import { PageHead } from '../components/ui'
import { setQuery, type Route } from '../router'

/** Nodes by pool and zone. `?node=` opens one node, `?q=` searches (e.g. a pool from the Overview). */
export function Nodes({ route }: { route: Route }) {
  const q = route.query.get('q') ?? ''
  const node = route.query.get('node') ?? ''
  return (
    <>
      <PageHead title="Nodes" lede="Nodes by pool and zone, how much of them is requested, and the pods they run." />
      <NodesView focus={node} q={q} onQuery={(v) => setQuery('/nodes', { q: v, node })} />
    </>
  )
}
