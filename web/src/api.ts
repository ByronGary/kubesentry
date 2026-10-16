import {
  AUTH_SOURCE_KEY,
  readNumber,
  readString,
  REAUTH_KEY,
  reauthDecision,
  retryAfterMs,
  sessionStore,
  writeNumber,
  writeString,
  type AuthSource,
} from './auth'

const TOKEN_KEY = 'kubesentry.token'

/**
 * What a 401 means for the screen: `token` shows the token prompt; `reload`
 * means the page is reloading to renew a single sign-on session; `stuck` means
 * it reloaded moments ago and the session still is not valid.
 */
export type Reauth = 'token' | 'reload' | 'stuck'

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    /** Set on 401s. */
    public reauth?: Reauth,
    /** From Retry-After on 429 and 503. */
    public retryAfterMs?: number,
  ) {
    super(message)
  }
}

export function getToken(): string {
  return readString(sessionStore(), TOKEN_KEY) ?? ''
}

export function setToken(t: string): void {
  writeString(sessionStore(), TOKEN_KEY, t)
}

let authSource: AuthSource | undefined = readString(sessionStore(), AUTH_SOURCE_KEY) as AuthSource | undefined

/** Remember how this server identifies users, from /info. */
export function setAuthSource(s: AuthSource | undefined): void {
  if (s === authSource) return
  authSource = s
  writeString(sessionStore(), AUTH_SOURCE_KEY, s)
}

export function getAuthSource(): AuthSource | undefined {
  return authSource
}

let reloading = false

/** Reload the page so oauth2-proxy can sign the user in again. */
export function reloadForSignIn(): void {
  writeNumber(sessionStore(), REAUTH_KEY, Date.now())
  if (reloading) return
  reloading = true
  window.location.reload()
}

function unauthorized(message: string): ApiError {
  if (authSource !== 'proxy') return new ApiError(401, message, 'token')
  // Other requests failing while the reload is under way are part of the same expiry.
  if (reloading) return new ApiError(401, 'Your sign-in expired. Signing you in again…', 'reload')
  const decision = reauthDecision(readNumber(sessionStore(), REAUTH_KEY), Date.now())
  if (decision === 'reload') {
    reloadForSignIn()
    return new ApiError(401, 'Your sign-in expired. Signing you in again…', 'reload')
  }
  return new ApiError(401, message || 'Your sign-in could not be renewed.', 'stuck')
}

/** Build a query string, skipping empty values. */
export function qs(params: Record<string, string | number | undefined>): string {
  const p = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== '') p.set(k, String(v))
  }
  const s = p.toString()
  return s ? `?${s}` : ''
}

async function request<T>(method: 'GET' | 'POST', path: string, body: unknown, signal?: AbortSignal): Promise<T> {
  const token = getToken()
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (token) headers.Authorization = `Bearer ${token}`
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  const res = await fetch(path, {
    method,
    signal,
    headers,
    credentials: 'same-origin',
    // An expired oauth2-proxy session answers API calls with a redirect to the
    // identity provider, which fetch cannot follow across origins. Seeing the
    // redirect lets us treat it like the 401 it is.
    redirect: 'manual',
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  if (res.type === 'opaqueredirect') {
    if (authSource === 'proxy') throw unauthorized('Your sign-in expired.')
    throw new ApiError(0, 'The server redirected the request; a proxy in front of kubesentry may need you to sign in.')
  }
  if (!res.ok) {
    let msg = res.statusText
    try {
      const b = await res.json()
      if (b?.error) msg = b.error
    } catch {
      /* not JSON */
    }
    if (res.status === 401) throw unauthorized(msg)
    throw new ApiError(res.status, msg, undefined, retryAfterMs(res.headers.get('Retry-After'), Date.now()))
  }
  return (await res.json()) as T
}

export function apiGet<T>(path: string, signal?: AbortSignal): Promise<T> {
  return request<T>('GET', path, undefined, signal)
}

/**
 * GET a file with the user's credentials (the token or the sign-in cookie),
 * for a download: the body as a Blob, and the file name from
 * Content-Disposition when the server gives one.
 */
export async function apiBlob(path: string, signal?: AbortSignal): Promise<{ blob: Blob; filename?: string }> {
  const token = getToken()
  const headers: Record<string, string> = {}
  if (token) headers.Authorization = `Bearer ${token}`
  const res = await fetch(path, { method: 'GET', signal, headers, credentials: 'same-origin', redirect: 'manual' })
  if (res.type === 'opaqueredirect') {
    if (authSource === 'proxy') throw unauthorized('Your sign-in expired.')
    throw new ApiError(0, 'The server redirected the request; a proxy in front of kubesentry may need you to sign in.')
  }
  if (!res.ok) {
    let msg = res.statusText
    try {
      const b = await res.json()
      if (b?.error) msg = b.error
    } catch {
      /* not JSON */
    }
    if (res.status === 401) throw unauthorized(msg)
    throw new ApiError(res.status, msg, undefined, retryAfterMs(res.headers.get('Retry-After'), Date.now()))
  }
  const cd = res.headers.get('Content-Disposition') ?? ''
  const m = /filename\*?=(?:UTF-8'')?"?([^";]+)"?/i.exec(cd)
  let filename: string | undefined
  if (m) {
    try {
      filename = decodeURIComponent(m[1])
    } catch {
      filename = m[1]
    }
  }
  return { blob: await res.blob(), filename }
}

/** POST with an optional JSON body. */
export function apiPost<T>(path: string, body?: unknown, signal?: AbortSignal): Promise<T> {
  return request<T>('POST', path, body, signal)
}
