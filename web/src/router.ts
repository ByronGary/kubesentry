import { useEffect, useState } from 'react'

export interface Route {
  path: string
  query: URLSearchParams
}

export function parseHash(hash: string): Route {
  const raw = hash.replace(/^#/, '') || '/'
  const i = raw.indexOf('?')
  const path = i === -1 ? raw : raw.slice(0, i)
  const query = new URLSearchParams(i === -1 ? '' : raw.slice(i + 1))
  return { path: path || '/', query }
}

export function useRoute(): Route {
  const [hash, setHash] = useState(window.location.hash)
  useEffect(() => {
    const on = () => setHash(window.location.hash)
    window.addEventListener('hashchange', on)
    return () => window.removeEventListener('hashchange', on)
  }, [])
  return parseHash(hash)
}

/** Replace the query string of the current route without adding history entries. */
export function setQuery(path: string, params: Record<string, string | undefined>): void {
  const p = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) if (v) p.set(k, v)
  const s = p.toString()
  window.history.replaceState(null, '', `#${path}${s ? `?${s}` : ''}`)
  window.dispatchEvent(new HashChangeEvent('hashchange'))
}
